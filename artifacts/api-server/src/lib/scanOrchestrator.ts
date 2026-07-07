import { db, scanFingerprintProfilesTable, scanRequestTelemetryTable, orchestratorConfigTable } from "@workspace/db";
import { eq, desc } from "drizzle-orm";
import { selectHealthiestProxy, recordProxyOutcome, type ProxyOutcome } from "./proxyManager.js";
import { waitForRateLimitToken, recordRateLimitSuccess, recordRateLimitFailure } from "./adaptiveRateLimiter.js";
import { getCircuitState, isCircuitOpen, recordCircuitResult } from "./circuitBreaker.js";
import { getDelay, sleep, type ScanIntensity } from "./delayEngine.js";
import { storeCookies, getCookieHeader } from "./cookieJar.js";
import { analyzeResponse } from "./responseAnalyzer.js";
import { resolveWithRotation } from "./dnsResolverPool.js";
import { logger } from "./logger.js";

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
      maxRetries:         parseInt(map["max_retries"] ?? "4", 10),
      backoffBaseMs:      parseInt(map["backoff_base_ms"] ?? "1000", 10),
      logAllRequests:     map["log_all_requests"]     !== "false",
    };
    _configLoadedAt = Date.now();
    return _config;
  } catch {
    return { enabled: true, useProxies: false, rotateFingerprints: true, maxRetries: 4, backoffBaseMs: 1000, logAllRequests: true };
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

export async function orchestratedFetch(
  url: string,
  init: RequestInit = {},
  ctx: OrchestratorContext = {},
): Promise<Response> {
  const config = await loadConfig();
  const profiles = config.rotateFingerprints ? await loadProfiles() : [];
  const hostname = extractHostname(url);
  const intensity = ctx.intensity ?? "endpoint-discovery";
  const method = (init.method ?? "GET").toUpperCase();

  if (isCircuitOpen(hostname)) {
    const circuitState = getCircuitState(hostname);
    throw new Error(`Circuit breaker OPEN for ${hostname} (state: ${circuitState})`);
  }

  let proxy: Awaited<ReturnType<typeof selectHealthiestProxy>> = null;
  if (config.useProxies && config.enabled) {
    proxy = await selectHealthiestProxy();
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
  let retries = 0;
  let backoffMs = 0;
  let statusCode: number | undefined;
  const maxRetries = config.maxRetries;

  while (retries <= maxRetries) {
    const requestStart = Date.now();
    let wafDetected = false;
    let captchaDetected = false;
    let bytesDownloaded: number | undefined;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30_000);

      const fetchOpts: RequestInit = {
        ...init,
        headers: mergedHeaders,
        signal: controller.signal,
      };

      const response = await fetch(url, fetchOpts);
      clearTimeout(timeoutId);

      const latencyMs = Date.now() - requestStart;
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

      if (proxy) {
        const outcome: ProxyOutcome = analysis.classification === "RateLimited" ? "rate_limited"
          : analysis.classification === "Forbidden" ? "forbidden"
          : analysis.classification === "Timeout" ? "timeout"
          : analysis.isSuccess ? "success"
          : "connection_error";
        recordProxyOutcome(proxy.id, outcome, latencyMs).catch(() => {});
      }

      if (analysis.isSuccess || !analysis.isTransient) {
        if (analysis.isSuccess) {
          recordRateLimitSuccess(url);
          recordCircuitResult(hostname, true);
        } else {
          recordCircuitResult(hostname, false);
        }

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
            retries,
            delayAppliedMs: delay,
            backoffAppliedMs: backoffMs,
            healthScoreAtDispatch: proxy?.healthScore,
            circuitBreakerState: getCircuitState(hostname),
            wafDetected,
            captchaDetected,
            bytesDownloaded,
          }).catch(() => {});
        }

        return response;
      }

      recordRateLimitFailure(url, analysis.retryAfterMs);
      recordCircuitResult(hostname, false);

      retries++;
      if (retries > maxRetries) break;

      const jitter = Math.random() * config.backoffBaseMs;
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, retries - 1) + jitter, 30_000);

      if (analysis.retryAfterMs) backoffMs = Math.max(backoffMs, analysis.retryAfterMs);
      logger.debug({ url, retries, backoffMs, classification: analysis.classification }, "Orchestrator retrying");
      await sleep(backoffMs);

    } catch (err: any) {
      const latencyMs = Date.now() - requestStart;
      lastError = err;

      recordCircuitResult(hostname, false);
      if (proxy) {
        const outcome: ProxyOutcome = err?.name === "AbortError" ? "timeout" : "connection_error";
        recordProxyOutcome(proxy.id, outcome, latencyMs).catch(() => {});
      }

      retries++;
      if (retries > maxRetries) break;

      const jitter = Math.random() * config.backoffBaseMs;
      backoffMs = Math.min(config.backoffBaseMs * Math.pow(2, retries - 1) + jitter, 30_000);
      logger.debug({ url, retries, backoffMs, err: err?.message }, "Orchestrator retrying after error");
      await sleep(backoffMs);
    }
  }

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
      retries,
      delayAppliedMs: delay,
      backoffAppliedMs: backoffMs,
      healthScoreAtDispatch: proxy?.healthScore,
      circuitBreakerState: getCircuitState(hostname),
      wafDetected: false,
      captchaDetected: false,
    }).catch(() => {});
  }

  throw lastError ?? new Error(`orchestratedFetch failed after ${retries} attempts: ${url}`);
}

export { resolveWithRotation as orchestratedDnsResolve };

export function invalidateConfigCache(): void {
  _config = null;
  _profiles = [];
}
