import { logger } from "./logger.js";
import { db, orchestratorConfigTable } from "@workspace/db";
import { and, eq } from "drizzle-orm";

export type CircuitState = "closed" | "open" | "half-open";

interface CircuitEntry {
  state: CircuitState;
  consecutiveFailures: number;
  openedAt?: Date;
  cooldownMs: number;
  tripCount: number;
}

// Key format: "{tenantId}:{hostname}" — fully isolates CB state per tenant.
// Tenant A tripping a breaker on github.com has zero effect on Tenant B.
const circuits = new Map<string, CircuitEntry>();

const FAILURE_THRESHOLD          = 5;
const DEFAULT_INITIAL_MS         = 15 * 60 * 1_000;   // 15 min
const DEFAULT_ESCALATED_MS       = 60 * 60 * 1_000;   // 60 min

// Per-tenant cooldown cache — refreshed from orchestrator_config (proxy_cooldown_minutes)
// on every trip so changes propagate without a server restart.
interface CooldownConfig { initialMs: number; escalatedMs: number; loadedAt: number; }
const _cooldownCache = new Map<number, CooldownConfig>();
const COOLDOWN_TTL_MS = 60_000;

async function getTenantCooldown(tenantId: number): Promise<{ initialMs: number; escalatedMs: number }> {
  const cached = _cooldownCache.get(tenantId);
  if (cached && Date.now() - cached.loadedAt < COOLDOWN_TTL_MS) {
    return { initialMs: cached.initialMs, escalatedMs: cached.escalatedMs };
  }
  try {
    const [row] = await db
      .select({ value: orchestratorConfigTable.value })
      .from(orchestratorConfigTable)
      .where(and(
        eq(orchestratorConfigTable.tenantId, tenantId),
        eq(orchestratorConfigTable.key, "proxy_cooldown_minutes"),
      ));
    if (row) {
      const minutes = parseInt(row.value, 10);
      if (!isNaN(minutes) && minutes > 0) {
        const cfg: CooldownConfig = {
          initialMs:   minutes * 60_000,
          escalatedMs: minutes * 4 * 60_000,
          loadedAt:    Date.now(),
        };
        _cooldownCache.set(tenantId, cfg);
        logger.info({ tenantId, initialMs: cfg.initialMs, escalatedMs: cfg.escalatedMs },
          "Circuit breaker: cooldown config refreshed from proxy_cooldown_minutes");
        return cfg;
      }
    }
  } catch { /* non-fatal — keep defaults */ }
  const fallback: CooldownConfig = {
    initialMs: DEFAULT_INITIAL_MS, escalatedMs: DEFAULT_ESCALATED_MS, loadedAt: Date.now(),
  };
  _cooldownCache.set(tenantId, fallback);
  return fallback;
}

// ── Persistence ───────────────────────────────────────────────────────────────

const STATE_KEY         = "circuit_breaker_state";
const FLUSH_INTERVAL_MS = 30_000;
const STATE_TTL_MS      = 24 * 60 * 60_000; // 24 h

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
    const byTenant = new Map<number, Record<string, PersistedEntry>>();
    const now = new Date().toISOString();

    for (const [compoundKey, entry] of circuits) {
      const colonIdx = compoundKey.indexOf(":");
      if (colonIdx < 0) continue;
      const tenantId = parseInt(compoundKey.slice(0, colonIdx), 10);
      const target   = compoundKey.slice(colonIdx + 1);
      if (isNaN(tenantId)) continue;
      if (!byTenant.has(tenantId)) byTenant.set(tenantId, {});
      byTenant.get(tenantId)![target] = {
        state:               entry.state,
        consecutiveFailures: entry.consecutiveFailures,
        openedAt:            entry.openedAt?.toISOString(),
        cooldownMs:          entry.cooldownMs,
        tripCount:           entry.tripCount,
        savedAt:             now,
      };
    }

    for (const [tenantId, payload] of byTenant) {
      const value = JSON.stringify(payload);
      await db.insert(orchestratorConfigTable)
        .values({ tenantId, key: STATE_KEY, value, description: "Circuit breaker per-host state" } as any)
        .onConflictDoUpdate({
          target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
          set:    { value, updatedAt: new Date() },
        });
    }
  } catch (err) {
    logger.warn({ err }, "Circuit breaker: failed to persist state (non-fatal)");
  }
}

export async function initCircuitBreaker(): Promise<void> {
  try {
    const rows = await db
      .select({
        tenantId:  orchestratorConfigTable.tenantId,
        value:     orchestratorConfigTable.value,
        updatedAt: orchestratorConfigTable.updatedAt,
      })
      .from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.key, STATE_KEY));

    let count = 0;
    for (const row of rows) {
      if (!row.tenantId) continue;
      const cutoff = Date.now() - STATE_TTL_MS;
      try {
        const payload: Record<string, PersistedEntry> = JSON.parse(row.value);
        for (const [target, entry] of Object.entries(payload)) {
          if (new Date(entry.savedAt).getTime() < cutoff) continue;
          circuits.set(`${row.tenantId}:${target}`, {
            state:               entry.state,
            consecutiveFailures: entry.consecutiveFailures,
            openedAt:            entry.openedAt ? new Date(entry.openedAt) : undefined,
            cooldownMs:          entry.cooldownMs,
            tripCount:           entry.tripCount,
          });
          count++;
        }
      } catch { /* skip malformed row */ }
    }
    logger.info({ count }, "Circuit breaker: state restored from DB");
  } catch (err) {
    logger.warn({ err }, "Circuit breaker: failed to load state from DB (non-fatal, starting fresh)");
  }

  // Periodic flush captures all incremental changes every 30 s
  setInterval(() => { saveCircuitStates().catch(() => {}); }, FLUSH_INTERVAL_MS);
}

// ── Core logic ────────────────────────────────────────────────────────────────

function getEntry(tenantId: number, target: string): CircuitEntry {
  const key = `${tenantId}:${target}`;
  if (!circuits.has(key)) {
    circuits.set(key, {
      state: "closed", consecutiveFailures: 0,
      cooldownMs: DEFAULT_INITIAL_MS, tripCount: 0,
    });
  }
  return circuits.get(key)!;
}

export function getCircuitState(tenantId: number, target: string): CircuitState {
  const entry = getEntry(tenantId, target);
  if (entry.state === "open" && entry.openedAt) {
    if (Date.now() - entry.openedAt.getTime() >= entry.cooldownMs) {
      entry.state = "half-open";
      logger.info({ tenantId, target }, "Circuit breaker transitioning to half-open");
    }
  }
  return entry.state;
}

export function isCircuitOpen(tenantId: number, target: string): boolean {
  return getCircuitState(tenantId, target) === "open";
}

/**
 * Record the outcome of a request to `target` for `tenantId`.
 * Async because it reads the per-tenant cooldown config from DB on circuit trips.
 */
export async function recordCircuitResult(
  tenantId: number, target: string, success: boolean,
): Promise<{ justTripped: boolean }> {
  const entry = getEntry(tenantId, target);

  if (success) {
    entry.consecutiveFailures = 0;
    if (entry.state === "half-open") {
      const { initialMs } = await getTenantCooldown(tenantId);
      entry.state = "closed";
      entry.cooldownMs = initialMs;
      logger.info({ tenantId, target }, "Circuit breaker closed after successful probe");
      saveCircuitStates().catch(() => {});
    }
    return { justTripped: false };
  }

  entry.consecutiveFailures++;

  if (entry.state === "half-open") {
    entry.tripCount++;
    const { initialMs, escalatedMs } = await getTenantCooldown(tenantId);
    entry.cooldownMs = entry.tripCount >= 2 ? escalatedMs : initialMs;
    entry.state      = "open";
    entry.openedAt   = new Date();
    logger.warn({ tenantId, target, cooldownMs: entry.cooldownMs },
      "Circuit breaker re-opened after failed half-open probe");
    saveCircuitStates().catch(() => {});
    return { justTripped: true };
  }

  if (entry.consecutiveFailures >= FAILURE_THRESHOLD && entry.state === "closed") {
    entry.tripCount++;
    const { initialMs, escalatedMs } = await getTenantCooldown(tenantId);
    entry.cooldownMs = entry.tripCount >= 2 ? escalatedMs : initialMs;
    entry.state      = "open";
    entry.openedAt   = new Date();
    logger.warn({ tenantId, target, trips: entry.tripCount, cooldownMs: entry.cooldownMs },
      "Circuit breaker opened");
    saveCircuitStates().catch(() => {});
    return { justTripped: true };
  }

  return { justTripped: false };
}

export function getAllCircuits(tenantId: number): Array<{
  target: string; state: CircuitState;
  consecutiveFailures: number; openedAt?: Date;
  cooldownMs: number; tripCount: number;
}> {
  const prefix = `${tenantId}:`;
  const result = [];
  for (const [compoundKey, entry] of circuits) {
    if (!compoundKey.startsWith(prefix)) continue;
    const target = compoundKey.slice(prefix.length);
    getCircuitState(tenantId, target); // update half-open state
    result.push({ target, ...entry });
  }
  return result;
}
