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

const MIN_INTERVAL_MS =  200;
const MAX_INTERVAL_MS = 10_000;
const INITIAL_INTERVAL_MS = 2_000;
const SUCCESS_THRESHOLD  = 5;
const WINDOW_MS = 60_000;

const states = new Map<string, TargetState>();

const STATE_KEY         = "rate_limiter_state";
const FLUSH_INTERVAL_MS = 30_000;
const STATE_TTL_MS      = 4 * 60 * 60_000; // 4 h — rate-limit state is transient

// ── Persistence helpers ───────────────────────────────────────────────────────

interface PersistedState {
  intervalMs: number;
  retryAfterUntil: number;
  savedAt: string;
}

async function saveRateLimiterStates(): Promise<void> {
  try {
    const payload: Record<string, PersistedState> = {};
    const now = new Date().toISOString();
    for (const [target, state] of states) {
      // Only persist if interval differs from default or there's an active Retry-After
      if (state.intervalMs === INITIAL_INTERVAL_MS && state.retryAfterUntil <= Date.now()) continue;
      payload[target] = {
        intervalMs:      state.intervalMs,
        retryAfterUntil: state.retryAfterUntil,
        savedAt:         now,
      };
    }
    if (Object.keys(payload).length === 0) return; // nothing worth persisting
    const value = JSON.stringify(payload);
    await db.insert(orchestratorConfigTable)
      .values({ key: STATE_KEY, value, description: "Adaptive rate limiter per-host state" })
      .onConflictDoUpdate({
        target: orchestratorConfigTable.key,
        set: { value, updatedAt: new Date() },
      });
  } catch (err) {
    logger.warn({ err }, "Rate limiter: failed to persist state (non-fatal)");
  }
}

export async function initRateLimiter(): Promise<void> {
  try {
    const [row] = await db
      .select({ value: orchestratorConfigTable.value })
      .from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.key, STATE_KEY));

    if (row) {
      const cutoff = Date.now() - STATE_TTL_MS;
      const payload: Record<string, PersistedState> = JSON.parse(row.value);
      for (const [target, entry] of Object.entries(payload)) {
        if (new Date(entry.savedAt).getTime() < cutoff) continue; // skip stale
        states.set(target, {
          intervalMs:           entry.intervalMs,
          lastRequestAt:        0,
          consecutiveSuccesses: 0,
          retryAfterUntil:      entry.retryAfterUntil,
          recentRequests:       [],
        });
      }
      logger.info({ count: states.size }, "Rate limiter: state restored from DB");
    }
  } catch (err) {
    logger.warn({ err }, "Rate limiter: failed to load state from DB (non-fatal, starting fresh)");
  }

  // Periodic flush every 30 s
  setInterval(() => { saveRateLimiterStates().catch(() => {}); }, FLUSH_INTERVAL_MS);
}

// ── Core logic ────────────────────────────────────────────────────────────────

function normalizeTarget(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname;
  } catch {
    return url;
  }
}

function getState(target: string): TargetState {
  const key = normalizeTarget(target);
  if (!states.has(key)) {
    states.set(key, {
      intervalMs: INITIAL_INTERVAL_MS,
      lastRequestAt: 0,
      consecutiveSuccesses: 0,
      retryAfterUntil: 0,
      recentRequests: [],
    });
  }
  return states.get(key)!;
}

export async function waitForRateLimitToken(url: string): Promise<void> {
  const state = getState(url);
  const now = Date.now();

  if (now < state.retryAfterUntil) {
    const wait = state.retryAfterUntil - now;
    logger.debug({ url, waitMs: wait }, "Rate limiter honoring Retry-After");
    await new Promise(r => setTimeout(r, wait));
  }

  const elapsed = Date.now() - state.lastRequestAt;
  if (elapsed < state.intervalMs) {
    const delay = state.intervalMs - elapsed;
    await new Promise(r => setTimeout(r, delay));
  }

  state.lastRequestAt = Date.now();

  state.recentRequests = state.recentRequests.filter(t => Date.now() - t < WINDOW_MS);
  state.recentRequests.push(Date.now());
}

export function recordRateLimitSuccess(url: string): void {
  const state = getState(url);
  state.consecutiveSuccesses++;
  if (state.consecutiveSuccesses >= SUCCESS_THRESHOLD) {
    state.intervalMs = Math.max(MIN_INTERVAL_MS, Math.round(state.intervalMs * 0.9));
    state.consecutiveSuccesses = 0;
  }
}

export function recordRateLimitFailure(url: string, retryAfterMs?: number): void {
  const state = getState(url);
  state.consecutiveSuccesses = 0;
  state.intervalMs = Math.min(MAX_INTERVAL_MS, state.intervalMs * 2);

  if (retryAfterMs != null && retryAfterMs > 0) {
    state.retryAfterUntil = Date.now() + retryAfterMs;
    logger.debug({ url, retryAfterMs }, "Rate limiter: Retry-After set");
  }

  logger.debug({ url, newIntervalMs: state.intervalMs }, "Rate limiter: interval doubled after 429");
  // Persist immediately when a 429 is recorded — restart should honour it
  saveRateLimiterStates().catch(() => {});
}

export function getRecentRequestCount(url: string): number {
  const state = getState(url);
  state.recentRequests = state.recentRequests.filter(t => Date.now() - t < WINDOW_MS);
  return state.recentRequests.length;
}

export function getAllRateLimiterStats(): Array<{ target: string; intervalMs: number; recentRequestsPerMinute: number; retryAfterUntil: number }> {
  const now = Date.now();
  return [...states.entries()].map(([target, state]) => ({
    target,
    intervalMs: state.intervalMs,
    recentRequestsPerMinute: state.recentRequests.filter(t => now - t < WINDOW_MS).length,
    retryAfterUntil: state.retryAfterUntil,
  }));
}
