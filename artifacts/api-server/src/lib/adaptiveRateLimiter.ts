import { logger } from "./logger.js";
import { db, orchestratorConfigTable } from "@workspace/db";
import { eq } from "drizzle-orm";

interface TargetState {
  intervalMs: number;
  lastRequestAt: number;
  consecutiveSuccesses: number;
  retryAfterUntil: number;
  recentRequests: number[];
}

const MIN_INTERVAL_MS     =   200;
const MAX_INTERVAL_MS     = 10_000;
const INITIAL_INTERVAL_MS =  2_000;
const SUCCESS_THRESHOLD   = 5;
const WINDOW_MS           = 60_000;

// Key format: "{tenantId}:{hostname}" — rate-limit state is fully per-tenant.
// Tenant A hitting a 429 on api.github.com does not slow Tenant B.
const states = new Map<string, TargetState>();

const STATE_KEY         = "rate_limiter_state";
const FLUSH_INTERVAL_MS = 30_000;
const STATE_TTL_MS      = 4 * 60 * 60_000; // 4 h — rate-limit state is transient

// ── Persistence ───────────────────────────────────────────────────────────────

interface PersistedState {
  intervalMs: number;
  retryAfterUntil: number;
  savedAt: string;
}

async function saveRateLimiterStates(): Promise<void> {
  try {
    const byTenant = new Map<number, Record<string, PersistedState>>();
    const now = new Date().toISOString();

    for (const [compoundKey, state] of states) {
      // Only persist if non-default or active Retry-After
      if (state.intervalMs === INITIAL_INTERVAL_MS && state.retryAfterUntil <= Date.now()) continue;

      const colonIdx = compoundKey.indexOf(":");
      if (colonIdx < 0) continue;
      const tenantId = parseInt(compoundKey.slice(0, colonIdx), 10);
      const target   = compoundKey.slice(colonIdx + 1);
      if (isNaN(tenantId)) continue;

      if (!byTenant.has(tenantId)) byTenant.set(tenantId, {});
      byTenant.get(tenantId)![target] = {
        intervalMs:      state.intervalMs,
        retryAfterUntil: state.retryAfterUntil,
        savedAt:         now,
      };
    }

    for (const [tenantId, payload] of byTenant) {
      if (Object.keys(payload).length === 0) continue;
      const value = JSON.stringify(payload);
      await db.insert(orchestratorConfigTable)
        .values({ tenantId, key: STATE_KEY, value, description: "Adaptive rate limiter per-host state" } as any)
        .onConflictDoUpdate({
          target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
          set:    { value, updatedAt: new Date() },
        });
    }
  } catch (err) {
    logger.warn({ err }, "Rate limiter: failed to persist state (non-fatal)");
  }
}

export async function initRateLimiter(): Promise<void> {
  try {
    const rows = await db
      .select({ tenantId: orchestratorConfigTable.tenantId, value: orchestratorConfigTable.value })
      .from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.key, STATE_KEY));

    let count = 0;
    for (const row of rows) {
      if (!row.tenantId) continue;
      const cutoff = Date.now() - STATE_TTL_MS;
      try {
        const payload: Record<string, PersistedState> = JSON.parse(row.value);
        for (const [target, entry] of Object.entries(payload)) {
          if (new Date(entry.savedAt).getTime() < cutoff) continue;
          states.set(`${row.tenantId}:${target}`, {
            intervalMs:           entry.intervalMs,
            lastRequestAt:        0,
            consecutiveSuccesses: 0,
            retryAfterUntil:      entry.retryAfterUntil,
            recentRequests:       [],
          });
          count++;
        }
      } catch { /* skip malformed row */ }
    }
    logger.info({ count }, "Rate limiter: state restored from DB");
  } catch (err) {
    logger.warn({ err }, "Rate limiter: failed to load state from DB (non-fatal, starting fresh)");
  }

  setInterval(() => { saveRateLimiterStates().catch(() => {}); }, FLUSH_INTERVAL_MS);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeKey(tenantId: number, url: string): string {
  try {
    return `${tenantId}:${new URL(url).hostname}`;
  } catch {
    return `${tenantId}:${url}`;
  }
}

function getState(tenantId: number, url: string): TargetState {
  const key = makeKey(tenantId, url);
  if (!states.has(key)) {
    states.set(key, {
      intervalMs: INITIAL_INTERVAL_MS, lastRequestAt: 0,
      consecutiveSuccesses: 0, retryAfterUntil: 0, recentRequests: [],
    });
  }
  return states.get(key)!;
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function waitForRateLimitToken(tenantId: number, url: string): Promise<void> {
  const state = getState(tenantId, url);
  const now = Date.now();

  if (now < state.retryAfterUntil) {
    const wait = state.retryAfterUntil - now;
    logger.debug({ tenantId, url, waitMs: wait }, "Rate limiter honoring Retry-After");
    await new Promise(r => setTimeout(r, wait));
  }

  const elapsed = Date.now() - state.lastRequestAt;
  if (elapsed < state.intervalMs) {
    await new Promise(r => setTimeout(r, state.intervalMs - elapsed));
  }

  state.lastRequestAt = Date.now();
  state.recentRequests = state.recentRequests.filter(t => Date.now() - t < WINDOW_MS);
  state.recentRequests.push(Date.now());
}

export function recordRateLimitSuccess(tenantId: number, url: string): void {
  const state = getState(tenantId, url);
  state.consecutiveSuccesses++;
  if (state.consecutiveSuccesses >= SUCCESS_THRESHOLD) {
    state.intervalMs = Math.max(MIN_INTERVAL_MS, Math.round(state.intervalMs * 0.9));
    state.consecutiveSuccesses = 0;
  }
}

export function recordRateLimitFailure(tenantId: number, url: string, retryAfterMs?: number): void {
  const state = getState(tenantId, url);
  state.consecutiveSuccesses = 0;
  state.intervalMs = Math.min(MAX_INTERVAL_MS, state.intervalMs * 2);

  if (retryAfterMs != null && retryAfterMs > 0) {
    state.retryAfterUntil = Date.now() + retryAfterMs;
    logger.debug({ tenantId, url, retryAfterMs }, "Rate limiter: Retry-After set");
  }

  logger.debug({ tenantId, url, newIntervalMs: state.intervalMs }, "Rate limiter: interval doubled after 429");
  saveRateLimiterStates().catch(() => {});
}

export function getRecentRequestCount(tenantId: number, url: string): number {
  const state = getState(tenantId, url);
  state.recentRequests = state.recentRequests.filter(t => Date.now() - t < WINDOW_MS);
  return state.recentRequests.length;
}

export function getAllRateLimiterStats(tenantId: number): Array<{
  target: string; intervalMs: number; recentRequestsPerMinute: number; retryAfterUntil: number;
}> {
  const prefix = `${tenantId}:`;
  const now = Date.now();
  const result = [];
  for (const [compoundKey, state] of states) {
    if (!compoundKey.startsWith(prefix)) continue;
    const target = compoundKey.slice(prefix.length);
    result.push({
      target,
      intervalMs:               state.intervalMs,
      recentRequestsPerMinute:  state.recentRequests.filter(t => now - t < WINDOW_MS).length,
      retryAfterUntil:          state.retryAfterUntil,
    });
  }
  return result;
}
