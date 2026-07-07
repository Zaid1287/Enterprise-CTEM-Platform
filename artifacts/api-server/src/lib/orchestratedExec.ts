import { exec } from "child_process";
import { promisify } from "util";
import type { ExecOptions } from "child_process";
import { db, orchestratorConfigTable } from "@workspace/db";
import { isCircuitOpen, getCircuitState, recordCircuitResult } from "./circuitBreaker.js";
import { waitForRateLimitToken, recordRateLimitSuccess, recordRateLimitFailure } from "./adaptiveRateLimiter.js";
import { selectHealthiestProxy } from "./proxyManager.js";
import { logger } from "./logger.js";

const execAsync = promisify(exec);

interface ExecOrchConfig {
  enabled: boolean;
  circuitBreakerEnabled: boolean;
  adaptiveRateLimitEnabled: boolean;
  useProxies: boolean;
}

let _execConfig: ExecOrchConfig | null = null;
let _execConfigLoadedAt = 0;
const EXEC_CONFIG_TTL_MS = 60_000;

async function getExecConfig(): Promise<ExecOrchConfig> {
  if (_execConfig && Date.now() - _execConfigLoadedAt < EXEC_CONFIG_TTL_MS) return _execConfig;
  try {
    const rows = await db.select().from(orchestratorConfigTable);
    const map: Record<string, string> = {};
    for (const r of rows) map[r.key] = r.value;
    _execConfig = {
      enabled:                  map["enabled"]                !== "false",
      circuitBreakerEnabled:    map["circuit_breaker_enabled"] !== "false",
      adaptiveRateLimitEnabled: map["adaptive_rate_limit"]     !== "false",
      useProxies:               map["use_proxies"]             !== "false",
    };
    _execConfigLoadedAt = Date.now();
    return _execConfig;
  } catch {
    return { enabled: true, circuitBreakerEnabled: true, adaptiveRateLimitEnabled: true, useProxies: false };
  }
}

export interface OrchestratedExecOptions extends ExecOptions {
  timeout?: number;
  targetHost?: string;
}

export interface OrchestratedExecResult {
  stdout: string;
  stderr: string;
  proxyUrl: string | null;
}

/**
 * Gate a child_process exec call through the orchestrator control plane:
 *   1. Circuit breaker — aborts if the target host is known open/unreachable
 *   2. Adaptive rate limiter — spaces out calls to the same target
 *   3. Proxy selection — returns `proxyUrl` so callers can inject it into
 *      tool CLI flags (e.g. ffuf -replay-proxy, gobuster --proxy)
 *
 * TCP-level tools (nmap, naabu, masscan) cannot route through HTTP proxies
 * but still benefit from circuit-breaking and rate-limiting gating.
 *
 * `cmd` can be a plain string OR a builder function `(proxyUrl) => string`
 * so callers can embed the proxy URL inside the tool command when needed.
 */
export async function orchestratedExec(
  cmd: string | ((proxyUrl: string | null) => string),
  options: OrchestratedExecOptions = {},
): Promise<OrchestratedExecResult> {
  const config = await getExecConfig();
  const { targetHost, timeout = 120_000, ...execOpts } = options;

  // ── Circuit breaker check ────────────────────────────────────────────────────
  if (config.circuitBreakerEnabled && targetHost) {
    if (isCircuitOpen(targetHost)) {
      const state = getCircuitState(targetHost);
      throw new Error(`orchestratedExec: circuit breaker OPEN for ${targetHost} (${state}) — skipping`);
    }
  }

  // ── Rate limiter ─────────────────────────────────────────────────────────────
  if (config.adaptiveRateLimitEnabled && targetHost) {
    await waitForRateLimitToken(`https://${targetHost}`);
  }

  // ── Proxy selection (returned for callers to inject into tool flags) ─────────
  let proxyUrl: string | null = null;
  if (config.useProxies && config.enabled) {
    try {
      const proxy = await selectHealthiestProxy();
      if (proxy) {
        const creds = proxy.username
          ? `${encodeURIComponent(proxy.username)}:${encodeURIComponent((proxy as any).password ?? "")}@`
          : "";
        proxyUrl = `http://${creds}${proxy.ip}:${proxy.port}`;
      }
    } catch { /* non-fatal — continue without proxy */ }
  }

  const finalCmd = typeof cmd === "function" ? cmd(proxyUrl) : cmd;

  const start = Date.now();
  try {
    const { stdout, stderr } = await execAsync(finalCmd, { ...execOpts, timeout });
    const latencyMs = Date.now() - start;

    if (config.circuitBreakerEnabled && targetHost) recordCircuitResult(targetHost, true);
    if (config.adaptiveRateLimitEnabled && targetHost) recordRateLimitSuccess(`https://${targetHost}`);

    logger.debug({ cmd: finalCmd.slice(0, 100), targetHost, latencyMs }, "orchestratedExec success");
    return { stdout, stderr, proxyUrl };
  } catch (err: any) {
    const latencyMs = Date.now() - start;

    if (config.circuitBreakerEnabled && targetHost) recordCircuitResult(targetHost, false);
    if (config.adaptiveRateLimitEnabled && targetHost) recordRateLimitFailure(`https://${targetHost}`);

    logger.debug({ cmd: finalCmd.slice(0, 100), targetHost, latencyMs, err: err?.message }, "orchestratedExec failed");
    throw err;
  }
}
