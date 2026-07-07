import { logger } from "./logger.js";

export type CircuitState = "closed" | "open" | "half-open";

interface CircuitEntry {
  state: CircuitState;
  consecutiveFailures: number;
  openedAt?: Date;
  cooldownMs: number;
  tripCount: number;
}

const circuits = new Map<string, CircuitEntry>();

const FAILURE_THRESHOLD = 5;
const INITIAL_COOLDOWN_MS  = 15 * 60 * 1_000;
const ESCALATED_COOLDOWN_MS = 60 * 60 * 1_000;

function getEntry(target: string): CircuitEntry {
  if (!circuits.has(target)) {
    circuits.set(target, {
      state: "closed",
      consecutiveFailures: 0,
      cooldownMs: INITIAL_COOLDOWN_MS,
      tripCount: 0,
    });
  }
  return circuits.get(target)!;
}

export function getCircuitState(target: string): CircuitState {
  const entry = getEntry(target);
  if (entry.state === "open" && entry.openedAt) {
    const elapsed = Date.now() - entry.openedAt.getTime();
    if (elapsed >= entry.cooldownMs) {
      entry.state = "half-open";
      logger.info({ target }, "Circuit breaker transitioning to half-open");
    }
  }
  return entry.state;
}

export function isCircuitOpen(target: string): boolean {
  return getCircuitState(target) === "open";
}

export function recordCircuitResult(target: string, success: boolean): void {
  const entry = getEntry(target);

  if (success) {
    entry.consecutiveFailures = 0;
    if (entry.state === "half-open") {
      entry.state = "closed";
      entry.cooldownMs = INITIAL_COOLDOWN_MS;
      logger.info({ target }, "Circuit breaker closed after successful probe");
    }
    return;
  }

  entry.consecutiveFailures++;

  if (entry.state === "half-open") {
    entry.tripCount++;
    entry.cooldownMs = entry.tripCount >= 2 ? ESCALATED_COOLDOWN_MS : INITIAL_COOLDOWN_MS;
    entry.state = "open";
    entry.openedAt = new Date();
    logger.warn({ target, cooldownMs: entry.cooldownMs }, "Circuit breaker re-opened after failed half-open probe");
    return;
  }

  if (entry.consecutiveFailures >= FAILURE_THRESHOLD && entry.state === "closed") {
    entry.tripCount++;
    entry.cooldownMs = entry.tripCount >= 2 ? ESCALATED_COOLDOWN_MS : INITIAL_COOLDOWN_MS;
    entry.state = "open";
    entry.openedAt = new Date();
    logger.warn({ target, trips: entry.tripCount, cooldownMs: entry.cooldownMs }, "Circuit breaker opened");
  }
}

export function getAllCircuits(): Array<{ target: string; state: CircuitState; consecutiveFailures: number; openedAt?: Date; cooldownMs: number; tripCount: number }> {
  const result = [];
  for (const [target, entry] of circuits) {
    getCircuitState(target);
    result.push({ target, ...entry });
  }
  return result;
}
