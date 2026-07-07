import { logger } from "./logger.js";

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
