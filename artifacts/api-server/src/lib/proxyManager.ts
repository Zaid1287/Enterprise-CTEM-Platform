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

// Re-ping a proxy if it hasn't been tested in the last hour before trusting its score
const STALE_TEST_THRESHOLD_MS = 60 * 60 * 1_000; // 1 hour

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
        lastTestedAt: scanProxiesTable.lastTestedAt,
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
    let candidates = active.length > 0 ? active : proxies.filter(p => p.healthScore > 0);
    if (candidates.length === 0) return null;

    candidates.sort((a, b) => (b.healthScore ?? 0) - (a.healthScore ?? 0));
    let best = candidates[0]!;

    // ── Issue 3: Force re-ping before trusting a stale score ─────────────────
    // If the proxy hasn't been tested in the last hour, ping it now before
    // returning it so callers don't get handed a dead proxy with an old high score.
    const lastTested = best.lastTestedAt ? best.lastTestedAt.getTime() : 0;
    const isStale = Date.now() - lastTested > STALE_TEST_THRESHOLD_MS;

    if (isStale) {
      logger.debug({ ip: best.ip, lastTestedAt: best.lastTestedAt }, "Proxy: stale score — re-pinging before selection");
      const result = await healthCheckProxy(best.ip, best.port ?? 8080);

      if (result.reachable) {
        // Reward the re-ping with a small score bump toward 100
        const reboundScore = Math.min(100, (best.healthScore ?? 50) + 3);
        await db.update(scanProxiesTable)
          .set({ healthScore: reboundScore, lastTestedAt: new Date(), avgLatencyMs: result.latencyMs })
          .where(eq(scanProxiesTable.id, best.id));
        best = { ...best, healthScore: reboundScore };
        logger.debug({ ip: best.ip, reboundScore }, "Proxy re-ping passed — score updated");
      } else {
        // Re-ping failed — decay immediately and try the next candidate
        const decayedScore = Math.max(0, (best.healthScore ?? 50) - 15);
        const updates: Partial<typeof scanProxiesTable.$inferInsert> = {
          healthScore: decayedScore,
          lastTestedAt: new Date(),
        };
        if (decayedScore <= 0) {
          updates.status = "inactive";
          updates.cooldownUntil = new Date(Date.now() + COOLDOWN_DURATION_MS);
        }
        await db.update(scanProxiesTable).set(updates as any).where(eq(scanProxiesTable.id, best.id));
        logger.warn({ ip: best.ip, decayedScore }, "Proxy re-ping failed — score decayed, trying next");

        // Fall back to next candidate
        const fallback = candidates.find(p => p.id !== best.id);
        if (!fallback) return null;
        return { id: fallback.id, ip: fallback.ip, port: fallback.port, healthScore: fallback.healthScore, username: fallback.username, password: fallback.password };
      }
    }

    return { id: best.id, ip: best.ip, port: best.port, healthScore: best.healthScore, username: best.username, password: best.password };
  } catch (err) {
    logger.warn({ err }, "proxyManager: selectHealthiestProxy failed");
    return null;
  }
}

export async function recordProxyOutcome(
  proxyId: number,
  outcome: ProxyOutcome,
  latencyMs?: number,
): Promise<{ enteredCooldown: boolean }> {
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

    if (!current) return { enteredCooldown: false };

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

    const enteredCooldown = newConsecutive >= COOLDOWN_FAILURES;

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

    if (enteredCooldown) {
      updates.cooldownUntil = new Date(Date.now() + COOLDOWN_DURATION_MS);
      updates.status = "cooldown";
      logger.warn({ proxyId, newConsecutive }, "Proxy entering cooldown after repeated failures");
    }

    await db.update(scanProxiesTable)
      .set(updates as any)
      .where(eq(scanProxiesTable.id, proxyId));

    return { enteredCooldown };
  } catch (err) {
    logger.warn({ err, proxyId }, "proxyManager: recordProxyOutcome failed");
    return { enteredCooldown: false };
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

// ── Issue 3: Proxy score decay on idle ─────────────────────────────────────────
// Every 6h: subtract (100 − currentScore) * 0.1 from active proxies not recently
// used. This converges idle scores toward zero asymptotically — low-scored proxies
// die fast, high-scored ones persist longer (giving them a chance to be re-pinged
// by selectHealthiestProxy before they finally vanish).
export async function decayIdleProxyScores(): Promise<void> {
  const IDLE_THRESHOLD_MS = 6 * 60 * 60_000; // 6 hours

  try {
    const idleThreshold = new Date(Date.now() - IDLE_THRESHOLD_MS);

    const idleProxies = await db
      .select({ id: scanProxiesTable.id, healthScore: scanProxiesTable.healthScore })
      .from(scanProxiesTable)
      .where(
        and(
          eq(scanProxiesTable.status, "active"),
          sql`coalesce(last_tested_at, created_at) < ${idleThreshold}`,
        )
      );

    if (idleProxies.length === 0) return;

    let decayed = 0;
    for (const proxy of idleProxies) {
      const current = proxy.healthScore ?? 100;
      // Issue 3 formula: (100 − currentScore) × 0.1 — low-scored proxies decay faster
      const decayAmount = Math.max(1, (100 - current) * 0.1);
      const newScore = Math.max(0, current - decayAmount);

      const updates: Partial<typeof scanProxiesTable.$inferInsert> = { healthScore: newScore };
      if (newScore <= 0) updates.status = "inactive";

      await db.update(scanProxiesTable)
        .set(updates as any)
        .where(eq(scanProxiesTable.id, proxy.id));
      decayed++;
    }

    logger.info({ count: decayed }, "Proxy decay: applied idle health score decay (formula: (100-score)*0.1)");
  } catch (err) {
    logger.warn({ err }, "proxyManager: decayIdleProxyScores failed");
  }
}
