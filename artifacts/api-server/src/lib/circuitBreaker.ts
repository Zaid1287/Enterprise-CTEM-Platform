import { logger } from "./logger.js";
import { db, orchestratorConfigTable } from "@workspace/db";
import { eq } from "drizzle-orm";

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

const STATE_KEY   = "circuit_breaker_state";
const FLUSH_INTERVAL_MS = 30_000;
const STATE_TTL_MS      = 24 * 60 * 60_000; // 24 h — stale after this

// ── Persistence helpers ───────────────────────────────────────────────────────

interface PersistedEntry {
  state: CircuitState;
  consecutiveFailures: number;
  openedAt?: string;
  cooldownMs: number;
  tripCount: number;
  savedAt: string;
}

async function saveCircuitStates(): Promise<void> {
  try {
    const payload: Record<string, PersistedEntry> = {};
    const now = new Date().toISOString();
    for (const [target, entry] of circuits) {
      payload[target] = {
        state: entry.state,
        consecutiveFailures: entry.consecutiveFailures,
        openedAt: entry.openedAt?.toISOString(),
        cooldownMs: entry.cooldownMs,
        tripCount: entry.tripCount,
        savedAt: now,
      };
    }
    const value = JSON.stringify(payload);
    await db.insert(orchestratorConfigTable)
      .values({ key: STATE_KEY, value, description: "Circuit breaker per-host state" })
      .onConflictDoUpdate({
        target: orchestratorConfigTable.key,
        set: { value, updatedAt: new Date() },
      });
  } catch (err) {
    logger.warn({ err }, "Circuit breaker: failed to persist state (non-fatal)");
  }
}

export async function initCircuitBreaker(): Promise<void> {
  try {
    const [row] = await db
      .select({ value: orchestratorConfigTable.value, updatedAt: orchestratorConfigTable.updatedAt })
      .from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.key, STATE_KEY));

    if (row) {
      const cutoff = Date.now() - STATE_TTL_MS;
      const payload: Record<string, PersistedEntry> = JSON.parse(row.value);
      for (const [target, entry] of Object.entries(payload)) {
        if (new Date(entry.savedAt).getTime() < cutoff) continue; // skip stale
        circuits.set(target, {
          state:               entry.state,
          consecutiveFailures: entry.consecutiveFailures,
          openedAt:            entry.openedAt ? new Date(entry.openedAt) : undefined,
          cooldownMs:          entry.cooldownMs,
          tripCount:           entry.tripCount,
        });
      }
      logger.info({ count: circuits.size }, "Circuit breaker: state restored from DB");
    }
  } catch (err) {
    logger.warn({ err }, "Circuit breaker: failed to load state from DB (non-fatal, starting fresh)");
  }

  // Periodic flush — captures all incremental changes every 30 s
  setInterval(() => { saveCircuitStates().catch(() => {}); }, FLUSH_INTERVAL_MS);
}

// ── Core logic ────────────────────────────────────────────────────────────────

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
      saveCircuitStates().catch(() => {}); // persist on close
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
    saveCircuitStates().catch(() => {}); // persist on trip
    return;
  }

  if (entry.consecutiveFailures >= FAILURE_THRESHOLD && entry.state === "closed") {
    entry.tripCount++;
    entry.cooldownMs = entry.tripCount >= 2 ? ESCALATED_COOLDOWN_MS : INITIAL_COOLDOWN_MS;
    entry.state = "open";
    entry.openedAt = new Date();
    logger.warn({ target, trips: entry.tripCount, cooldownMs: entry.cooldownMs }, "Circuit breaker opened");
    saveCircuitStates().catch(() => {}); // persist on trip
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
