import { db, scanFingerprintProfilesTable, scanRequestTelemetryTable, orchestratorConfigTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { selectHealthiestProxy, recordProxyOutcome, type ProxyOutcome } from "./proxyManager.js";
import { waitForRateLimitToken, recordRateLimitSuccess, recordRateLimitFailure } from "./adaptiveRateLimiter.js";
import { getCircuitState, isCircuitOpen, recordCircuitResult } from "./circuitBreaker.js";
import { getDelay, sleep, type ScanIntensity } from "./delayEngine.js";
import { storeCookies, getCookieHeader } from "./cookieJar.js";
import { analyzeResponse, type ResponseClassification } from "./responseAnalyzer.js";
import { resolveWithRotation } from "./dnsResolverPool.js";
import { pushWaterfallEvent } from "./sseManager.js";
import { logger } from "./logger.js";
import { fetch as undiciFetch, ProxyAgent } from "undici";

export interface OrchestratorContext {
  tenantId?: number;
  scanId?: number;
  assetId?: number;
  target?: string;
  intensity?: ScanIntensity;
}

interface OrchConfig {
  enabled: boolean;
  useProxies: boolean;
  rotateFingerprints: boolean;
  maxRetries: number;
  backoffBaseMs: number;
  maxBackoffMs: number;
  logAllRequests: boolean;
  wafBypassEnabled: boolean;
  adaptiveRateLimitEnabled: boolean;
  circuitBreakerEnabled: boolean;
}

let _config: OrchConfig | null = null;
let _configLoadedAt = 0;
const CONFIG_TTL_MS = 60_000;

async function loadConfig(): Promise<OrchConfig> {
  if (_config && Date.now() - _configLoadedAt < CONFIG_TTL_MS) return _config;
  try {
    const rows = await db.select().from(orchestratorConfigTable);
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    _config = {
      enabled:                  map["enabled"]               !== "false",
      useProxies:               map["use_proxies"]            !== "false",
      rotateFingerprints:       map["rotate_fingerprints"]    !== "false",
      maxRetries:               parseInt(map["max_retries"]        ?? "4",    10),
      backoffBaseMs:            parseInt(map["retry_base_delay_ms"] ?? "1000", 10),
      maxBackoffMs:             parseInt(map["max_backoff_ms"]      ?? "30000", 10),
      logAllRequests:           map["log_all_requests"]       !== "false",
      wafBypassEnabled:         map["waf_bypass_strategy"]    !== "none" && !!map["waf_bypass_strategy"],
      adaptiveRateLimitEnabled: map["adaptive_rate_limit"]    !== "false",
      circuitBreakerEnabled:    map["circuit_breaker_enabled"] !== "false",
    };
    _configLoadedAt = Date.now();
    return _config;
  } catch {
    return {
      enabled: true, useProxies: false, rotateFingerprints: true,
      maxRetries: 4, backoffBaseMs: 1000, maxBackoffMs: 30_000,
      logAllRequests: true, wafBypassEnabled: false,
      adaptiveRateLimitEnabled: true, circuitBreakerEnabled: true,
    };
  }
}

let _profiles: Array<{ id: number; headers: Record<string, string> }> = [];
let _profilesLoadedAt = 0;
const PROFILES_TTL_MS = 5 * 60_000;

async function loadProfiles(): Promise<Array<{ id: number; headers: Record<string, string> }>> {
  if (_profiles.length > 0 && Date.now() - _profilesLoadedAt < PROFILES_TTL_MS) return _profiles;
  try {
    const rows = await db
      .select({ id: scanFingerprintProfilesTable.id, headers: scanFingerprintProfilesTable.headers })
      .from(scanFingerprintProfilesTable)
      .where(eq(scanFingerprintProfilesTable.isActive, true));
    if (rows.length > 0) {
      _profiles = rows.map(r => ({ id: r.id, headers: sanitizeHeaders(r.headers) }));
      _profilesLoadedAt = Date.now();
    }
    return _profiles;
  } catch {
    return [];
  }
}

// ── Issue 4b: WAF-protected host registry ────────────────────────────────────
// When all retries consistently return WAF responses, the hostname is persisted
// in orchestrator_config (key "waf_host:{hostname}") with a 24h TTL. On the
// next request to that host, WAF-bypass mode is pre-activated from attempt 1
// (instead of waiting for the first detection), and the state survives restarts.

const wafHostCache = new Map<string, number>(); // hostname → markedAt epoch ms
const WAF_HOST_TTL_MS      = 24 * 60 * 60_000; // 24 h
const WAF_CACHE_REFRESH_MS =  5 * 60_000;       // re-read DB every 5 min
let _wafCacheLoadedAt      = 0;

async function refreshWafHostCache(): Promise<void> {
  try {
    const rows = await db.select({ key: orchestratorConfigTable.key, updatedAt: orchestratorConfigTable.updatedAt })
      .from(orchestratorConfigTable);
    const now = Date.now();
    wafHostCache.clear();
    for (const row of rows) {
      if (!row.key.startsWith("waf_host:")) continue;
      const markedAt = row.updatedAt.getTime();
      if (now - markedAt < WAF_HOST_TTL_MS) wafHostCache.set(row.key.slice(9), markedAt);
    }
    _wafCacheLoadedAt = now;
  } catch { /* non-fatal */ }
}

async function isHostWafProtected(hostname: string): Promise<boolean> {
  if (Date.now() - _wafCacheLoadedAt > WAF_CACHE_REFRESH_MS) {
    await refreshWafHostCache();
  }
  const markedAt = wafHostCache.get(hostname);
  return !!markedAt && (Date.now() - markedAt < WAF_HOST_TTL_MS);
}

export async function markHostWafProtected(hostname: string): Promise<void> {
  const key   = `waf_host:${hostname}`;
  const value = JSON.stringify({ hostname, markedAt: new Date().toISOString(), source: "auto_detection" });
  try {
    await db.insert(orchestratorConfigTable)
      .values({ key, value, description: `Auto-detected WAF for ${hostname}` })
      .onConflictDoUpdate({ target: orchestratorConfigTable.key, set: { value, updatedAt: new Date() } });
    wafHostCache.set(hostname, Date.now());
    logger.warn({ hostname }, "Orchestrator: host marked as WAF-protected in DB (24h TTL)");
  } catch (err) {
    logger.warn({ err, hostname }, "Orchestrator: failed to persist WAF host flag");
  }
}

export function getWafProtectedHosts(): Array<{ hostname: string; markedAt: number }> {
  const now = Date.now();
  return [...wafHostCache.entries()]
    .filter(([, t]) => now - t < WAF_HOST_TTL_MS)
    .map(([hostname, markedAt]) => ({ hostname, markedAt }));
}

// ── Issue 6: Fingerprint crash guard ─────────────────────────────────────────
// Validate that headers from the DB jsonb column are a flat Record<string, string>.
// Handles null, non-object, nested objects, numeric values, etc.
function sanitizeHeaders(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof k === "string" && k.trim().length > 0 && v != null) {
      // Coerce to string — headers must be strings for undici
      const str = typeof v === "string" ? v : String(v);
      if (str.length > 0) out[k] = str;
    }
  }
  return out;
}

function pickRandomProfile(
  profiles: Array<{ id: number; headers: Record<string, string> }>,
  excludeId?: number,
): { id: number; headers: Record<string, string> } | null {
  if (profiles.length === 0) return null;
  const candidates = excludeId != null ? profiles.filter(p => p.id !== excludeId) : profiles;
  const pool = candidates.length > 0 ? candidates : profiles;
  return pool[Math.floor(Math.random() * pool.length)]!;
}

function extractHostname(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

// ── Issue 4: Telemetry write + SSE waterfall push ────────────────────────────
async function writeTelemetry(data: {
  tenantId?: number;
  scanId?: number;
  assetId?: number;
  target?: string;
  method: string;
  url: string;
  proxyId?: number;
  fingerprintProfileId?: number;
  statusCode?: number;
  latencyMs?: number;
  retries: number;
  delayAppliedMs?: number;
  backoffAppliedMs?: number;
  healthScoreAtDispatch?: number;
  circuitBreakerState?: string;
  wafDetected: boolean;
  captchaDetected: boolean;
  bytesDownloaded?: number;
}): Promise<void> {
  try {
    await db.insert(scanRequestTelemetryTable).values(data as any);
    // Push to real-time waterfall SSE stream for any connected admins
    if (data.tenantId) {
      pushWaterfallEvent(data.tenantId, {
        ...data,
        ts: Date.now(),
      });
    }
  } catch {
    // Telemetry write failure is non-fatal
  }
}

// Classifications that warrant tripping the circuit breaker (rate-limit or active block).
const CIRCUIT_TRIP_CLASSES: Set<ResponseClassification> = new Set([
  "RateLimited", "Forbidden", "CloudflareChallenge", "AkamaiChallenge", "ImpervaBlock",
]);

// Only these transient classes are worth retrying — 403/WAF blocks and permanent errors are not.
const RETRYABLE_CLASSES: Set<ResponseClassification> = new Set([
  "RateLimited", "TemporaryError", "Timeout", "ConnectionReset",
]);

// ── Issue 2: Build proxy URL with credentials ─────────────────────────────────
// Explicit interface so TypeScript can resolve this through async closures without
// reducing to `never` via Awaited<ReturnType<...>> inference.
interface ActiveProxy {
  id: number;
  ip: string;
  port: number;
  healthScore: number;
  username: string | null;
  password: string | null;
}

function buildProxyUrl(proxy: ActiveProxy): string {
  if (proxy.username) {
    const user = encodeURIComponent(proxy.username);
    const pass = encodeURIComponent(proxy.password ?? "");
    return `http://${user}:${pass}@${proxy.ip}:${proxy.port}`;
  }
  return `http://${proxy.ip}:${proxy.port}`;
}

export async function orchestratedFetch(
  url: string,
  init: RequestInit = {},
  ctx: OrchestratorContext = {},
): Promise<Response> {
  let config: OrchConfig;
  let profiles: Array<{ id: number; headers: Record<string, string> }>;

  // Bootstrap with safe fallbacks so orchestration errors never kill the scan
  try {
    config = await loadConfig();
  } catch {
    config = {
      enabled: true, useProxies: false, rotateFingerprints: false,
      maxRetries: 4, backoffBaseMs: 1000, maxBackoffMs: 30_000,
      logAllRequests: false, wafBypassEnabled: false,
      adaptiveRateLimitEnabled: true, circuitBreakerEnabled: true,
    };
  }
  try {
    profiles = config.rotateFingerprints ? await loadProfiles() : [];
  } catch {
    profiles = [];
  }

  const hostname = extractHostname(url);
  const intensity = ctx.intensity ?? "endpoint-discovery";
  const method = (init.method ?? "GET").toUpperCase();

  if (config.circuitBreakerEnabled && isCircuitOpen(hostname)) {
    throw new Error(`Circuit breaker OPEN for ${hostname} (state: ${getCircuitState(hostname)})`);
  }

  // Select proxy — only when orchestrator is enabled and use_proxies is true.
  // Returns a value instead of mutating outer vars so TypeScript can track the type.
  const pickProxy = async (excludeProxyId?: number): Promise<{ proxy: ActiveProxy | null; proxyAgent: ProxyAgent | undefined }> => {
    if (!config.useProxies || !config.enabled) return { proxy: null, proxyAgent: undefined };
    try {
      const p = await selectHealthiestProxy(excludeProxyId);
      if (p) {
        return { proxy: p, proxyAgent: new ProxyAgent(buildProxyUrl(p)) };
      }
    } catch { /* fall through */ }
    return { proxy: null, proxyAgent: undefined };
  };

  let { proxy, proxyAgent } = await pickProxy();

  let profile = pickRandomProfile(profiles);
  const baseDelay = getDelay(intensity);

  if (config.adaptiveRateLimitEnabled) {
    await waitForRateLimitToken(url);
  }
  await sleep(baseDelay);

  const existingCookies = getCookieHeader(url);

  let lastError: Error | undefined;
  let attemptNumber = 0;
  let backoffMs = 0;
  let statusCode: number | undefined;
  const maxRetries = config.maxRetries;

  // ── Issue 4: WAF bypass state — pre-activate if host is known WAF-protected ──
  // If a previous scan already exhausted all retries with WAF detections, we skip
  // the "cold" first attempt and go straight to bypass mode on retry 1.
  let lastWafDetected = await isHostWafProtected(hostname);
  let wafHitCount     = 0; // tracks how many attempts triggered WAF in this call

  while (attemptNumber <= maxRetries) {
    // ── Issue 7: WAF bypass — on next retry after WAF, rotate profile + proxy ──
    if (lastWafDetected && config.wafBypassEnabled && attemptNumber > 0) {
      const prevProfileId = profile?.id;
      profile = pickRandomProfile(profiles, prevProfileId);
      const prevProxyId = proxy?.id;
      ({ proxy, proxyAgent } = await pickProxy(prevProxyId));
      // Double the delay for WAF bypass — makes the request look less robotic
      backoffMs = Math.min(backoffMs * 2 || baseDelay * 2, config.maxBackoffMs);
      logger.debug({ url, prevProfileId, newProfileId: profile?.id, prevProxyId, newProxyId: proxy?.id }, "WAF bypass: rotated fingerprint + proxy");
    }

    // ── Issue 6: Fingerprint crash guard — sanitizeHeaders already called at load,
    //    but guard here too in case profile was somehow set externally.
    const fingerprintHeaders: Record<string, string> = profile ? sanitizeHeaders(profile.headers) : {};
    const mergedHeaders: Record<string, string> = {
      ...fingerprintHeaders,
      ...(existingCookies ? { "Cookie": existingCookies } : {}),
      ...(init.headers as Record<string, string> ?? {}),
    };

    const requestStart = Date.now();
    let wafDetected = false;
    let captchaDetected = false;
    let bytesDownloaded: number | undefined;
    let latencyMs = 0;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);

      // Use undici fetch with ProxyAgent when proxy is configured — this actually routes
      // the TCP connection through the proxy, changing the outbound IP seen by the target.
      const response = await (undiciFetch as any)(url, {
        ...init,
        headers: mergedHeaders,
        signal: controller.signal,
        ...(proxyAgent ? { dispatcher: proxyAgent } : {}),
      }) as Response;

      clearTimeout(timeoutId);

      latencyMs = Date.now() - requestStart;
      statusCode = response.status;

      const bodyText = await response.clone().text().catch(() => "");
      bytesDownloaded = bodyText.length;

      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });

      const analysis = analyzeResponse(statusCode, bodyText, responseHeaders);
      wafDetected     = analysis.wafDetected;
      captchaDetected = analysis.captchaDetected;
      lastWafDetected = wafDetected;
      if (wafDetected) wafHitCount++;

      const setCookieHeader = response.headers.get("set-cookie");
      if (setCookieHeader) storeCookies(url, [setCookieHeader]);

      // Record proxy outcome on every attempt
      if (proxy) {
        const outcome: ProxyOutcome = analysis.classification === "RateLimited" ? "rate_limited"
          : analysis.classification === "Forbidden"
            || analysis.classification === "CloudflareChallenge"
            || analysis.classification === "AkamaiChallenge"
            || analysis.classification === "ImpervaBlock" ? "forbidden"
          : analysis.classification === "Timeout" ? "timeout"
          : analysis.isSuccess ? "success"
          : "connection_error";
        recordProxyOutcome(proxy.id, outcome, latencyMs).catch(() => {});
      }

      // Write per-attempt telemetry
      if (config.logAllRequests) {
        writeTelemetry({
          tenantId: ctx.tenantId,
          scanId: ctx.scanId,
          assetId: ctx.assetId,
          target: ctx.target ?? hostname,
          method,
          url,
          proxyId: proxy?.id,
          fingerprintProfileId: profile?.id,
          statusCode,
          latencyMs,
          retries: attemptNumber,
          delayAppliedMs: baseDelay,
          backoffAppliedMs: backoffMs,
          healthScoreAtDispatch: proxy?.healthScore,
          circuitBreakerState: getCircuitState(hostname),
          wafDetected,
          captchaDetected,
          bytesDownloaded,
        }).catch(() => {});
      }

      if (analysis.isSuccess) {
        if (config.adaptiveRateLimitEnabled) recordRateLimitSuccess(url);
        if (config.circuitBreakerEnabled) recordCircuitResult(hostname, true);
        return response;
      }

      // Only trip circuit breaker for rate-limit or active block responses
      if (config.circuitBreakerEnabled && CIRCUIT_TRIP_CLASSES.has(analysis.classification)) {
        recordCircuitResult(hostname, false);
      }

      // Only retry for explicitly transient, recoverable classes (not 403/WAF/permanent)
      if (!RETRYABLE_CLASSES.has(analysis.classification)) {
        return response;
      }

      if (config.adaptiveRateLimitEnabled) {
        recordRateLimitFailure(url, analysis.retryAfterMs);
      }

      attemptNumber++;
      if (attemptNumber > maxRetries) break;

      const jitter = Math.random() * config.backoffBaseMs;
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, attemptNumber - 1) + jitter, config.maxBackoffMs);
      if (analysis.retryAfterMs) backoffMs = Math.max(backoffMs, analysis.retryAfterMs);
      logger.debug({ url, attemptNumber, backoffMs, classification: analysis.classification }, "Orchestrator retrying");
      await sleep(backoffMs);

    } catch (err: any) {
      latencyMs = Date.now() - requestStart;
      lastError = err;
      lastWafDetected = false;

      if (config.circuitBreakerEnabled) recordCircuitResult(hostname, false);
      if (proxy) {
        const outcome: ProxyOutcome = err?.name === "AbortError" ? "timeout" : "connection_error";
        recordProxyOutcome(proxy.id, outcome, latencyMs).catch(() => {});
      }

      // Write per-attempt telemetry for errors too
      if (config.logAllRequests) {
        writeTelemetry({
          tenantId: ctx.tenantId,
          scanId: ctx.scanId,
          assetId: ctx.assetId,
          target: ctx.target ?? hostname,
          method,
          url,
          proxyId: proxy?.id,
          fingerprintProfileId: profile?.id,
          latencyMs,
          retries: attemptNumber,
          delayAppliedMs: baseDelay,
          backoffAppliedMs: backoffMs,
          healthScoreAtDispatch: proxy?.healthScore,
          circuitBreakerState: getCircuitState(hostname),
          wafDetected: false,
          captchaDetected: false,
        }).catch(() => {});
      }

      attemptNumber++;
      if (attemptNumber > maxRetries) break;

      const jitter = Math.random() * config.backoffBaseMs;
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, attemptNumber - 1) + jitter, config.maxBackoffMs);
      logger.debug({ url, attemptNumber, backoffMs, err: err?.message }, "Orchestrator retrying after error");
      await sleep(backoffMs);
    }
  }

  // ── Issue 4: Mark host as WAF-protected when all retries consistently hit WAF ──
  // Threshold: WAF detected on ≥ 2 attempts AND > half of total attempts.
  // Stored in orchestrator_config with 24h TTL so bypass pre-activates next time.
  if (wafHitCount >= 2 && wafHitCount > attemptNumber / 2 && config.wafBypassEnabled) {
    markHostWafProtected(hostname).catch(() => {});
  }

  throw lastError ?? new Error(`orchestratedFetch exhausted ${maxRetries + 1} attempts: ${url}`);
}

export { resolveWithRotation as orchestratedDnsResolve };

export function invalidateConfigCache(): void {
  _config = null;
  _profiles = [];
}
