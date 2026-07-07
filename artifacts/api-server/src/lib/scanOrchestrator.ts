import { db, scanFingerprintProfilesTable, scanRequestTelemetryTable, orchestratorConfigTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import { selectHealthiestProxy, recordProxyOutcome, type ProxyOutcome } from "./proxyManager.js";
import { waitForRateLimitToken, recordRateLimitSuccess, recordRateLimitFailure } from "./adaptiveRateLimiter.js";
import { getCircuitState, isCircuitOpen, recordCircuitResult } from "./circuitBreaker.js";
import { getDelay, sleep, type ScanIntensity } from "./delayEngine.js";
import { storeCookies, getCookieHeader } from "./cookieJar.js";
import { analyzeResponse, type ResponseClassification } from "./responseAnalyzer.js";
import { resolveWithRotation } from "./dnsResolverPool.js";
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
  logAllRequests: boolean;
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
      enabled:            map["enabled"]             !== "false",
      useProxies:         map["use_proxies"]          !== "false",
      rotateFingerprints: map["rotate_fingerprints"]  !== "false",
      maxRetries:         parseInt(map["max_retries"] ?? "3", 10),
      backoffBaseMs:      parseInt(map["backoff_base_ms"] ?? "1000", 10),
      logAllRequests:     map["log_all_requests"]     !== "false",
    };
    _configLoadedAt = Date.now();
    return _config;
  } catch {
    return { enabled: true, useProxies: false, rotateFingerprints: true, maxRetries: 3, backoffBaseMs: 1000, logAllRequests: true };
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
      _profiles = rows as Array<{ id: number; headers: Record<string, string> }>;
      _profilesLoadedAt = Date.now();
    }
    return _profiles;
  } catch {
    return [];
  }
}

function pickRandomProfile(profiles: Array<{ id: number; headers: Record<string, string> }>): { id: number; headers: Record<string, string> } | null {
  if (profiles.length === 0) return null;
  return profiles[Math.floor(Math.random() * profiles.length)]!;
}

function extractHostname(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}

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
    config = { enabled: true, useProxies: false, rotateFingerprints: false, maxRetries: 3, backoffBaseMs: 1000, logAllRequests: false };
  }
  try {
    profiles = config.rotateFingerprints ? await loadProfiles() : [];
  } catch {
    profiles = [];
  }

  const hostname = extractHostname(url);
  const intensity = ctx.intensity ?? "endpoint-discovery";
  const method = (init.method ?? "GET").toUpperCase();

  if (isCircuitOpen(hostname)) {
    throw new Error(`Circuit breaker OPEN for ${hostname} (state: ${getCircuitState(hostname)})`);
  }

  // Select proxy — always attempt selection but only use when enabled
  let proxy: Awaited<ReturnType<typeof selectHealthiestProxy>> = null;
  let proxyAgent: ProxyAgent | undefined;
  if (config.useProxies && config.enabled) {
    try {
      proxy = await selectHealthiestProxy();
      if (proxy) {
        proxyAgent = new ProxyAgent(`http://${proxy.ip}:${proxy.port}`);
      }
    } catch {
      proxy = null;
      proxyAgent = undefined;
    }
  }

  const profile = pickRandomProfile(profiles);
  const delay = getDelay(intensity);

  await waitForRateLimitToken(url);
  await sleep(delay);

  const existingCookies = getCookieHeader(url);
  const fingerprintHeaders: Record<string, string> = profile?.headers ?? {};

  const mergedHeaders: Record<string, string> = {
    ...fingerprintHeaders,
    ...(existingCookies ? { "Cookie": existingCookies } : {}),
    ...(init.headers as Record<string, string> ?? {}),
  };

  let lastError: Error | undefined;
  let attemptNumber = 0;
  let backoffMs = 0;
  let statusCode: number | undefined;
  const maxRetries = config.maxRetries;

  while (attemptNumber <= maxRetries) {
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
          delayAppliedMs: delay,
          backoffAppliedMs: backoffMs,
          healthScoreAtDispatch: proxy?.healthScore,
          circuitBreakerState: getCircuitState(hostname),
          wafDetected,
          captchaDetected,
          bytesDownloaded,
        }).catch(() => {});
      }

      if (analysis.isSuccess) {
        recordRateLimitSuccess(url);
        recordCircuitResult(hostname, true);
        return response;
      }

      // Only trip circuit breaker for rate-limit or active block responses
      if (CIRCUIT_TRIP_CLASSES.has(analysis.classification)) {
        recordCircuitResult(hostname, false);
      }

      // Only retry for explicitly transient, recoverable classes (not 403/WAF/permanent)
      if (!RETRYABLE_CLASSES.has(analysis.classification)) {
        return response;
      }

      recordRateLimitFailure(url, analysis.retryAfterMs);

      attemptNumber++;
      if (attemptNumber > maxRetries) break;

      const jitter = Math.random() * config.backoffBaseMs;
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, attemptNumber - 1) + jitter, 30_000);
      if (analysis.retryAfterMs) backoffMs = Math.max(backoffMs, analysis.retryAfterMs);
      logger.debug({ url, attemptNumber, backoffMs, classification: analysis.classification }, "Orchestrator retrying");
      await sleep(backoffMs);

    } catch (err: any) {
      latencyMs = Date.now() - requestStart;
      lastError = err;

      recordCircuitResult(hostname, false);
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
          delayAppliedMs: delay,
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
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, attemptNumber - 1) + jitter, 30_000);
      logger.debug({ url, attemptNumber, backoffMs, err: err?.message }, "Orchestrator retrying after error");
      await sleep(backoffMs);
    }
  }

  throw lastError ?? new Error(`orchestratedFetch exhausted ${maxRetries + 1} attempts: ${url}`);
}

export { resolveWithRotation as orchestratedDnsResolve };

export function invalidateConfigCache(): void {
  _config = null;
  _profiles = [];
}
