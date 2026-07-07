import { db, scanFingerprintProfilesTable, scanRequestTelemetryTable, orchestratorConfigTable } from "@workspace/db";
import { and, eq } from "drizzle-orm";
import { getCurrentTenantId } from "./tenantContext.js";
import { selectHealthiestProxy, recordProxyOutcome, type ProxyOutcome } from "./proxyManager.js";
import { waitForRateLimitToken, recordRateLimitSuccess, recordRateLimitFailure } from "./adaptiveRateLimiter.js";
import { getCircuitState, isCircuitOpen, recordCircuitResult } from "./circuitBreaker.js";
import { getDelay, sleep, setDelayMultiplier, type ScanIntensity } from "./delayEngine.js";
import { storeCookies, getCookieHeader } from "./cookieJar.js";
import { analyzeResponse, type ResponseClassification } from "./responseAnalyzer.js";
import { resolveWithRotation } from "./dnsResolverPool.js";
import { pushWaterfallEvent } from "./sseManager.js";
import { logger } from "./logger.js";
import { fetch as undiciFetch, ProxyAgent, Agent, buildConnector } from "undici";
import { dispatchNotifications } from "./notifier.js";

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
  proxyHealthScoringEnabled: boolean;
  delayMultiplier: number;
  defaultIntensity: ScanIntensity;
}

// Per-tenant config cache: key = tenantId
const _configCache = new Map<number, { config: OrchConfig; loadedAt: number }>();
const CONFIG_TTL_MS = 60_000;

// ── Issue 7: per-module alert debounce state ───────────────────────────────────
// Proxy pool exhausted alert — debounced to 30 min to avoid flooding operators.
let _lastLowProxyAlertAt = 0;
const LOW_PROXY_ALERT_COOLDOWN_MS = 30 * 60_000;

// WAF rate rolling-window alert — fires when >50% of the last WAF_RATE_WINDOW
// requests to a hostname were WAF-blocked, debounced per-host at 30 min.
interface WafRateEntry { outcomes: boolean[]; lastAlertAt: number; }
const _hostWafRates          = new Map<string, WafRateEntry>();
const WAF_RATE_WINDOW            = 20;
const WAF_RATE_ALERT_COOLDOWN_MS = 30 * 60_000;

async function loadConfig(tenantId: number): Promise<OrchConfig> {
  const cached = _configCache.get(tenantId);
  if (cached && Date.now() - cached.loadedAt < CONFIG_TTL_MS) return cached.config;
  try {
    const rows = await db.select().from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.tenantId, tenantId));
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    const config: OrchConfig = {
      enabled:                  map["enabled"]               !== "false",
      useProxies:               map["use_proxies"]            !== "false",
      rotateFingerprints:       map["rotate_fingerprints"]    !== "false",
      maxRetries:               parseInt(map["max_retries"]        ?? "4",    10),
      backoffBaseMs:            parseInt(map["retry_base_delay_ms"] ?? "1000", 10),
      maxBackoffMs:             parseInt(map["max_backoff_ms"]      ?? "30000", 10),
      logAllRequests:           map["log_all_requests"]       !== "false",
      wafBypassEnabled:          (map["waf_bypass_strategy"] ?? "rotate") !== "none",
      adaptiveRateLimitEnabled:  map["adaptive_rate_limit"]    !== "false",
      circuitBreakerEnabled:     map["circuit_breaker_enabled"] !== "false",
      proxyHealthScoringEnabled: map["proxy_health_scoring"]   !== "false",
      delayMultiplier:           parseFloat(map["scan_delay_multiplier"] ?? "1.0"),
      defaultIntensity:          toScanIntensity(map["scan_delay_intensity"]),
    };
    // propagate multiplier to delayEngine immediately after each config load
    setDelayMultiplier(config.delayMultiplier);
    _configCache.set(tenantId, { config, loadedAt: Date.now() });
    return config;
  } catch {
    return {
      enabled: true, useProxies: false, rotateFingerprints: true,
      maxRetries: 4, backoffBaseMs: 1000, maxBackoffMs: 30_000,
      logAllRequests: true, wafBypassEnabled: false,
      adaptiveRateLimitEnabled: true, circuitBreakerEnabled: true,
      proxyHealthScoringEnabled: true, delayMultiplier: 1.0,
      defaultIntensity: "endpoint-discovery",
    };
  }
}

const VALID_INTENSITIES: ReadonlyArray<ScanIntensity> = [
  "passive", "endpoint-discovery", "dir-fuzzing", "heavy-enumeration", "vuln-scan",
];
function toScanIntensity(raw: string | undefined): ScanIntensity {
  if (raw && VALID_INTENSITIES.includes(raw as ScanIntensity)) return raw as ScanIntensity;
  return "endpoint-discovery";
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

// Key format: "{tenantId}:{hostname}" — WAF detections are per-tenant
const wafHostCache = new Map<string, number>();
const WAF_HOST_TTL_MS      = 24 * 60 * 60_000; // 24 h
const WAF_CACHE_REFRESH_MS =  5 * 60_000;       // re-read DB every 5 min
// Per-tenant refresh timestamps
const _wafCacheLoadedAt = new Map<number, number>();

async function refreshWafHostCache(tenantId: number): Promise<void> {
  try {
    const rows = await db.select({ key: orchestratorConfigTable.key, updatedAt: orchestratorConfigTable.updatedAt })
      .from(orchestratorConfigTable)
      .where(and(eq(orchestratorConfigTable.tenantId, tenantId)));
    const now = Date.now();
    // Clear existing entries for this tenant
    for (const k of [...wafHostCache.keys()]) {
      if (k.startsWith(`${tenantId}:`)) wafHostCache.delete(k);
    }
    for (const row of rows) {
      if (!row.key.startsWith("waf_host:")) continue;
      const markedAt = row.updatedAt.getTime();
      if (now - markedAt < WAF_HOST_TTL_MS) {
        wafHostCache.set(`${tenantId}:${row.key.slice(9)}`, markedAt);
      }
    }
    _wafCacheLoadedAt.set(tenantId, now);
  } catch { /* non-fatal */ }
}

async function isHostWafProtected(tenantId: number, hostname: string): Promise<boolean> {
  const loadedAt = _wafCacheLoadedAt.get(tenantId) ?? 0;
  if (Date.now() - loadedAt > WAF_CACHE_REFRESH_MS) {
    await refreshWafHostCache(tenantId);
  }
  const markedAt = wafHostCache.get(`${tenantId}:${hostname}`);
  return !!markedAt && (Date.now() - markedAt < WAF_HOST_TTL_MS);
}

export async function markHostWafProtected(hostname: string, tenantId: number): Promise<void> {
  const key   = `waf_host:${hostname}`;
  const value = JSON.stringify({ hostname, markedAt: new Date().toISOString(), source: "auto_detection" });
  try {
    await db.insert(orchestratorConfigTable)
      .values({ tenantId, key, value, description: `Auto-detected WAF for ${hostname}` } as any)
      .onConflictDoUpdate({
        target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
        set:    { value, updatedAt: new Date() },
      });
    wafHostCache.set(`${tenantId}:${hostname}`, Date.now());
    logger.warn({ tenantId, hostname }, "Orchestrator: host marked as WAF-protected in DB (24h TTL)");
  } catch (err) {
    logger.warn({ err, tenantId, hostname }, "Orchestrator: failed to persist WAF host flag");
  }
}

export function getWafProtectedHosts(tenantId: number): Array<{ hostname: string; markedAt: number }> {
  const prefix = `${tenantId}:`;
  const now = Date.now();
  return [...wafHostCache.entries()]
    .filter(([k, t]) => k.startsWith(prefix) && now - t < WAF_HOST_TTL_MS)
    .map(([k, markedAt]) => ({ hostname: k.slice(prefix.length), markedAt }));
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

// ── Issue 10: DNS rotation via custom undici Agent ────────────────────────────
// Resolves hostnames through the rotating DNS pool (8.8.8.8/1.1.1.1/9.9.9.9/…)
// instead of the Replit system resolver. Original hostname kept in opts.servername
// so TLS SNI works correctly. Used as the default dispatcher when no proxy is set.
const _defaultConnector = buildConnector({});
const _dnsRotationAgent = new Agent({
  connect: (opts: any, callback: any) => {
    const originalHostname: string = opts.hostname ?? "";
    if (!originalHostname || /^\d{1,3}(\.\d{1,3}){3}$/.test(originalHostname)) {
      _defaultConnector(opts, callback);
      return;
    }
    resolveWithRotation(originalHostname)
      .then(ips => {
        if (ips.length > 0) {
          opts.servername = opts.servername || originalHostname;
          opts.hostname   = ips[Math.floor(Math.random() * ips.length)];
        }
        _defaultConnector(opts, callback);
      })
      .catch(() => _defaultConnector(opts, callback));
  },
});

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
  const tenantId = ctx.tenantId ?? getCurrentTenantId() ?? 0;
  try {
    config = await loadConfig(tenantId);
  } catch {
    config = {
      enabled: true, useProxies: false, rotateFingerprints: false,
      maxRetries: 4, backoffBaseMs: 1000, maxBackoffMs: 30_000,
      logAllRequests: false, wafBypassEnabled: false,
      adaptiveRateLimitEnabled: true, circuitBreakerEnabled: true,
      proxyHealthScoringEnabled: true, delayMultiplier: 1.0,
      defaultIntensity: "endpoint-discovery" as const,
    };
  }
  try {
    profiles = config.rotateFingerprints ? await loadProfiles() : [];
  } catch {
    profiles = [];
  }

  const hostname = extractHostname(url);
  const intensity = ctx.intensity ?? config.defaultIntensity;
  const method = (init.method ?? "GET").toUpperCase();

  if (config.circuitBreakerEnabled && isCircuitOpen(tenantId, hostname)) {
    throw new Error(`Circuit breaker OPEN for ${hostname} (state: ${getCircuitState(tenantId, hostname)})`);
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

  // Issue 7: alert when proxy pool is exhausted (operator has proxies enabled but
  // none are healthy/active).  Debounced per-process to 30 min.
  if (config.useProxies && config.enabled && !proxy) {
    const now = Date.now();
    if (ctx.tenantId && now - _lastLowProxyAlertAt > LOW_PROXY_ALERT_COOLDOWN_MS) {
      _lastLowProxyAlertAt = now;
      dispatchNotifications({
        tenantId:       ctx.tenantId,
        eventType:      "orchestrator_event",
        title:          "Proxy Pool Exhausted",
        message:        "No healthy proxies are available for scan traffic. All proxies may be in cooldown or unreachable — requests will proceed without a proxy until the pool recovers.",
        severity:       "high",
        relatedAssetId: ctx.assetId,
        scanId:         ctx.scanId,
        assetName:      ctx.target ?? hostname,
        domain:         hostname,
      }).catch(() => {});
    }
  }

  let profile = pickRandomProfile(profiles);
  const baseDelay = getDelay(intensity);

  if (config.adaptiveRateLimitEnabled) {
    await waitForRateLimitToken(tenantId, url);
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
  let lastWafDetected = await isHostWafProtected(tenantId, hostname);
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
      // Issue 10: always set dispatcher — proxy when available, DNS-rotation agent otherwise
      const response = await (undiciFetch as any)(url, {
        ...init,
        headers: mergedHeaders,
        signal: controller.signal,
        dispatcher: proxyAgent ?? _dnsRotationAgent,
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
      if (wafDetected) {
        wafHitCount++;
        // Issue 8: fire WAF alert on the very first detection for this request
        if (wafHitCount === 1 && ctx.tenantId) {
          dispatchNotifications({
            tenantId: ctx.tenantId,
            eventType: "orchestrator_event",
            title: `WAF Detected: ${hostname}`,
            message: `A Web Application Firewall was detected at ${hostname}. Activating bypass strategy: rotating request fingerprint and proxy.`,
            severity: "medium",
            relatedAssetId: ctx.assetId,
            scanId: ctx.scanId,
            assetName: ctx.target ?? hostname,
            domain: hostname,
          }).catch(() => {});
        }
      }

      // Issue 7: rolling WAF-rate alert — fire when >50% of the last WAF_RATE_WINDOW
      // requests to this hostname were WAF-blocked (debounced 30 min per host).
      {
        const rateEntry = _hostWafRates.get(hostname) ?? { outcomes: [], lastAlertAt: 0 };
        rateEntry.outcomes.push(wafDetected);
        if (rateEntry.outcomes.length > WAF_RATE_WINDOW) rateEntry.outcomes.shift();
        _hostWafRates.set(hostname, rateEntry);

        if (rateEntry.outcomes.length >= 10 && ctx.tenantId) {
          const wafHits = rateEntry.outcomes.filter(Boolean).length;
          const wafRate = wafHits / rateEntry.outcomes.length;
          const now = Date.now();
          if (wafRate > 0.5 && now - rateEntry.lastAlertAt > WAF_RATE_ALERT_COOLDOWN_MS) {
            rateEntry.lastAlertAt = now;
            dispatchNotifications({
              tenantId:       ctx.tenantId,
              eventType:      "orchestrator_event",
              title:          `High WAF Rate: ${hostname}`,
              message:        `${Math.round(wafRate * 100)}% of recent requests to ${hostname} triggered WAF detection (${wafHits}/${rateEntry.outcomes.length}). Consider pausing scans or rotating source IPs.`,
              severity:       "high",
              relatedAssetId: ctx.assetId,
              scanId:         ctx.scanId,
              assetName:      ctx.target ?? hostname,
              domain:         hostname,
            }).catch(() => {});
          }
        }
      }

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
        // Issue 7: gate proxy health scoring behind config flag; fire cooldown alert
        if (config.proxyHealthScoringEnabled) {
          const capturedProxy = proxy;
          recordProxyOutcome(capturedProxy.id, outcome, latencyMs)
            .then(r => {
              if (r.enteredCooldown && ctx.tenantId) {
                dispatchNotifications({
                  tenantId: ctx.tenantId!,
                  eventType: "orchestrator_event",
                  title: `Proxy Entered Cooldown`,
                  message: `Proxy ${capturedProxy.ip}:${capturedProxy.port} entered cooldown after repeated failures. Scan traffic will route via remaining healthy proxies.`,
                  severity: "medium",
                  relatedAssetId: ctx.assetId,
                  scanId: ctx.scanId,
                  assetName: ctx.target ?? hostname,
                  domain: hostname,
                }).catch(() => {});
              }
            })
            .catch(() => {});
        }
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
          circuitBreakerState: getCircuitState(tenantId, hostname),
          wafDetected,
          captchaDetected,
          bytesDownloaded,
        }).catch(() => {});
      }

      if (analysis.isSuccess) {
        if (config.adaptiveRateLimitEnabled) recordRateLimitSuccess(tenantId, url);
        if (config.circuitBreakerEnabled) await recordCircuitResult(tenantId, hostname, true);
        return response;
      }

      // Issue 9: trip circuit breaker and alert when it just opened
      if (config.circuitBreakerEnabled && CIRCUIT_TRIP_CLASSES.has(analysis.classification)) {
        const cbResult = await recordCircuitResult(tenantId, hostname, false);
        if (cbResult.justTripped && ctx.tenantId) {
          dispatchNotifications({
            tenantId: ctx.tenantId,
            eventType: "orchestrator_event",
            title: `Circuit Breaker Opened: ${hostname}`,
            message: `The circuit breaker for ${hostname} tripped after repeated ${analysis.classification} responses. Requests to this host are paused until it recovers.`,
            severity: "high",
            relatedAssetId: ctx.assetId,
            scanId: ctx.scanId,
            assetName: ctx.target ?? hostname,
            domain: hostname,
          }).catch(() => {});
        }
      }

      // Only retry for explicitly transient, recoverable classes (not 403/WAF/permanent)
      if (!RETRYABLE_CLASSES.has(analysis.classification)) {
        return response;
      }

      if (config.adaptiveRateLimitEnabled) {
        recordRateLimitFailure(tenantId, url, analysis.retryAfterMs);
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

      // Issue 9: catch-path circuit breaker trip alert
      if (config.circuitBreakerEnabled) {
        const cbResult = await recordCircuitResult(tenantId, hostname, false);
        if (cbResult.justTripped && ctx.tenantId) {
          dispatchNotifications({
            tenantId: ctx.tenantId,
            eventType: "orchestrator_event",
            title: `Circuit Breaker Opened: ${hostname}`,
            message: `The circuit breaker for ${hostname} tripped after a connection error. Requests to this host are paused until it recovers.`,
            severity: "high",
            relatedAssetId: ctx.assetId,
            scanId: ctx.scanId,
            assetName: ctx.target ?? hostname,
            domain: hostname,
          }).catch(() => {});
        }
      }
      // Issue 7: gate proxy health scoring behind config flag; fire cooldown alert
      if (proxy && config.proxyHealthScoringEnabled) {
        const capturedProxy = proxy;
        const errOutcome: ProxyOutcome = err?.name === "AbortError" ? "timeout" : "connection_error";
        recordProxyOutcome(capturedProxy.id, errOutcome, latencyMs)
          .then(r => {
            if (r.enteredCooldown && ctx.tenantId) {
              dispatchNotifications({
                tenantId: ctx.tenantId!,
                eventType: "orchestrator_event",
                title: `Proxy Entered Cooldown`,
                message: `Proxy ${capturedProxy.ip}:${capturedProxy.port} entered cooldown after repeated failures. Scan traffic will route via remaining healthy proxies.`,
                severity: "medium",
                relatedAssetId: ctx.assetId,
                scanId: ctx.scanId,
                assetName: ctx.target ?? hostname,
                domain: hostname,
              }).catch(() => {});
            }
          })
          .catch(() => {});
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
          circuitBreakerState: getCircuitState(tenantId, hostname),
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

  // ── Mark host as WAF-protected when retries consistently hit WAF ──────────────
  // Threshold: WAF detected on ≥ 2 attempts AND > half of total attempts.
  // Stored in orchestrator_config with 24h TTL so bypass pre-activates next time.
  // Note: host marking happens regardless of wafBypassEnabled so the DB record
  //       is always current — bypass reads it on the NEXT request.
  if (wafHitCount >= 2 && wafHitCount > attemptNumber / 2) {
    markHostWafProtected(hostname, tenantId).catch(() => {});
  }

  throw lastError ?? new Error(`orchestratedFetch exhausted ${maxRetries + 1} attempts: ${url}`);
}

export { resolveWithRotation as orchestratedDnsResolve };

export function invalidateConfigCache(tenantId?: number): void {
  if (tenantId != null) {
    _configCache.delete(tenantId);
  } else {
    _configCache.clear();
  }
  _profiles = [];
}
