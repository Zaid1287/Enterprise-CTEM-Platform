import { db, scanProxiesTable } from "@workspace/db";
import { eq, isNull, or, lt, and, sql } from "drizzle-orm";
import { healthCheckProxy } from "./proxyHealthCheck.js";
import { logger } from "./logger.js";

export type ProxyOutcome = "success" | "rate_limited" | "forbidden" | "timeout" | "connection_error";

const SCORE_DELTAS: Record<ProxyOutcome, number> = {
  success:          +2,
  rate_limited:     -10,
  forbidden:        -8,
  timeout:          -6,
  connection_error: -5,
};

const LATENCY_BONUS = +1;
const COOLDOWN_FAILURES = 5;
const COOLDOWN_DURATION_MS = 30 * 60 * 1_000;

// ── Issue 2: Select proxy returning credentials too ───────────────────────────
export async function selectHealthiestProxy(
  excludeProxyId?: number,
): Promise<{ id: number; ip: string; port: number; healthScore: number; username: string | null; password: string | null } | null> {
  try {
    const now = new Date();
    const proxies = await db
      .select({
        id:          scanProxiesTable.id,
        ip:          scanProxiesTable.ip,
        port:        scanProxiesTable.port,
        healthScore: scanProxiesTable.healthScore,
        username:    scanProxiesTable.username,
        password:    scanProxiesTable.password,
      })
      .from(scanProxiesTable)
      .where(
        or(
          isNull(scanProxiesTable.cooldownUntil),
          lt(scanProxiesTable.cooldownUntil, now),
        ) as any
      )
      .orderBy(scanProxiesTable.healthScore);

    const active = proxies.filter(p => p.healthScore > 0 && p.id !== excludeProxyId);
    if (active.length === 0) {
      // Fall back to any active proxy if exclusion leaves nothing
      const fallback = proxies.filter(p => p.healthScore > 0);
      if (fallback.length === 0) return null;
      fallback.sort((a, b) => (b.healthScore ?? 0) - (a.healthScore ?? 0));
      return fallback[0] ?? null;
    }

    active.sort((a, b) => (b.healthScore ?? 0) - (a.healthScore ?? 0));
    return active[0] ?? null;
  } catch (err) {
    logger.warn({ err }, "proxyManager: selectHealthiestProxy failed");
    return null;
  }
}

export async function recordProxyOutcome(
  proxyId: number,
  outcome: ProxyOutcome,
  latencyMs?: number,
): Promise<void> {
  try {
    const [current] = await db
      .select({
        healthScore:         scanProxiesTable.healthScore,
        consecutiveFailures: scanProxiesTable.consecutiveFailures,
        successCount:        scanProxiesTable.successCount,
        failCount:           scanProxiesTable.failCount,
        count429:            scanProxiesTable.count429,
        count403:            scanProxiesTable.count403,
        timeoutCount:        scanProxiesTable.timeoutCount,
        avgLatencyMs:        scanProxiesTable.avgLatencyMs,
      })
      .from(scanProxiesTable)
      .where(eq(scanProxiesTable.id, proxyId));

    if (!current) return;

    let delta = SCORE_DELTAS[outcome];
    if (outcome === "success" && latencyMs != null && latencyMs < 300) delta += LATENCY_BONUS;

    const newScore = Math.max(0, Math.min(100, (current.healthScore ?? 100) + delta));
    const isFailure = outcome !== "success";
    const newConsecutive = isFailure ? (current.consecutiveFailures ?? 0) + 1 : 0;

    const newAvgLatency = latencyMs != null
      ? (current.avgLatencyMs != null
          ? Math.round((current.avgLatencyMs * 0.8 + latencyMs * 0.2))
          : latencyMs)
      : current.avgLatencyMs;

    const updates: Partial<typeof scanProxiesTable.$inferInsert> = {
      healthScore:         newScore,
      consecutiveFailures: newConsecutive,
      avgLatencyMs:        newAvgLatency ?? undefined,
      lastTestedAt:        new Date(),
      successCount:        outcome === "success" ? (current.successCount ?? 0) + 1 : current.successCount ?? 0,
      failCount:           isFailure           ? (current.failCount    ?? 0) + 1 : current.failCount    ?? 0,
      count429:            outcome === "rate_limited" ? (current.count429 ?? 0) + 1 : current.count429 ?? 0,
      count403:            outcome === "forbidden"    ? (current.count403 ?? 0) + 1 : current.count403 ?? 0,
      timeoutCount:        outcome === "timeout"      ? (current.timeoutCount ?? 0) + 1 : current.timeoutCount ?? 0,
    };

    if (newConsecutive >= COOLDOWN_FAILURES) {
      updates.cooldownUntil = new Date(Date.now() + COOLDOWN_DURATION_MS);
      updates.status = "cooldown";
      logger.warn({ proxyId, newConsecutive }, "Proxy entering cooldown after repeated failures");
    }

    await db.update(scanProxiesTable)
      .set(updates as any)
      .where(eq(scanProxiesTable.id, proxyId));
  } catch (err) {
    logger.warn({ err, proxyId }, "proxyManager: recordProxyOutcome failed");
  }
}

export async function scheduleRetestCoolingProxies(): Promise<void> {
  const INTERVAL_MS = 5 * 60_000;

  const retest = async () => {
    try {
      const now = new Date();
      const cooling = await db
        .select({ id: scanProxiesTable.id, ip: scanProxiesTable.ip, port: scanProxiesTable.port })
        .from(scanProxiesTable)
        .where(
          or(
            eq(scanProxiesTable.status, "cooldown"),
            lt(scanProxiesTable.cooldownUntil, now) as any,
          )
        );

      for (const proxy of cooling) {
        const result = await healthCheckProxy(proxy.ip, proxy.port ?? 8080);
        if (result.reachable) {
          await db.update(scanProxiesTable)
            .set({
              status:             "active",
              cooldownUntil:      null,
              consecutiveFailures: 0,
              healthScore:        50,
              lastTestedAt:       new Date(),
              avgLatencyMs:       result.latencyMs,
            })
            .where(eq(scanProxiesTable.id, proxy.id));
          logger.info({ ip: proxy.ip, latencyMs: result.latencyMs }, "Cooled proxy re-activated after retest");
        } else {
          await db.update(scanProxiesTable)
            .set({ lastTestedAt: new Date(), cooldownUntil: new Date(Date.now() + COOLDOWN_DURATION_MS) })
            .where(eq(scanProxiesTable.id, proxy.id));
          logger.debug({ ip: proxy.ip }, "Cooled proxy still unreachable — extending cooldown");
        }
      }
    } catch (err) {
      logger.warn({ err }, "proxyManager: retest cycle failed");
    }

    setTimeout(retest, INTERVAL_MS);
  };

  setTimeout(retest, INTERVAL_MS);
  logger.info("Proxy retest scheduler started (interval: 5 min)");
}

// ── Issue 5: Proxy score decay on idle ────────────────────────────────────────
// Active proxies that haven't been used in 6+ hours have their health scores
// decayed by DECAY_AMOUNT per cycle. This ensures stale proxies don't remain
// at artificially high scores without being validated.
export async function decayIdleProxyScores(): Promise<void> {
  const IDLE_THRESHOLD_MS = 6 * 60 * 60_000; // 6 hours
  const DECAY_AMOUNT = 5; // points per 6h cycle

  try {
    const idleThreshold = new Date(Date.now() - IDLE_THRESHOLD_MS);

    const idleProxies = await db
      .select({ id: scanProxiesTable.id, healthScore: scanProxiesTable.healthScore })
      .from(scanProxiesTable)
      .where(
        and(
          eq(scanProxiesTable.status, "active"),
          // Use last_tested_at if available, otherwise fall back to created_at
          sql`coalesce(last_tested_at, created_at) < ${idleThreshold}`,
        )
      );

    if (idleProxies.length === 0) return;

    for (const proxy of idleProxies) {
      const newScore = Math.max(0, (proxy.healthScore ?? 100) - DECAY_AMOUNT);
      const updates: Partial<typeof scanProxiesTable.$inferInsert> = { healthScore: newScore };
      if (newScore <= 0) {
        updates.status = "inactive";
      }
      await db.update(scanProxiesTable)
        .set(updates as any)
        .where(eq(scanProxiesTable.id, proxy.id));
    }

    logger.info({ count: idleProxies.length, decayAmount: DECAY_AMOUNT }, "Proxy decay: applied idle health score decay");
  } catch (err) {
    logger.warn({ err }, "proxyManager: decayIdleProxyScores failed");
  }
}
