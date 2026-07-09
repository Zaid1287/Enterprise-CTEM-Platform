/**
 * Auto-Tuner
 *
 * Self-optimization loop that reads real observed WAF hit rates from the
 * orchestrator_waf_stats table and automatically adjusts per-tenant scan
 * configuration in orchestrator_config:
 *
 *   • scan_delay_multiplier  — scales every request delay up/down (0.1–5.0×)
 *   • waf_bypass_strategy    — enables/disables fingerprint+proxy rotation
 *
 * Decision logic (per-tenant, last 24 h of data):
 *   WAF hit rate > 60% → multiply delay by 1.5 (cap 5.0), enable bypass
 *   WAF hit rate 30–60% → enable bypass if not already; no delay change
 *   WAF hit rate < 15% and multiplier > 1.5 → multiply delay by 0.85 (floor 1.0)
 *   WAF hit rate < 5%  and bypass still on after 48+ quiet hours → disable bypass
 *
 * Every action is logged to orchestrator_tuning_log for operator visibility.
 * The tuner runs every 10 minutes via the beat scheduler.
 */

import { db, orchestratorConfigTable, orchestratorWafStatsTable, orchestratorTuningLogTable } from "@workspace/db";
import { and, eq, gte, sql } from "drizzle-orm";
import { logger } from "./logger.js";

// ── Tuning thresholds ──────────────────────────────────────────────────────────
const HIGH_WAF_RATE      = 0.60;   // above → increase delay + enable bypass
const MEDIUM_WAF_RATE    = 0.30;   // above → enable bypass (no delay change)
const LOW_WAF_RATE       = 0.15;   // below this + multiplier > 1.5 → reduce delay
const VERY_LOW_WAF_RATE  = 0.05;   // below this → consider disabling bypass

const DELAY_UP_FACTOR    = 1.5;    // multiply delay by this on high WAF
const DELAY_DOWN_FACTOR  = 0.85;   // multiply delay by this on low WAF
const MAX_MULTIPLIER     = 5.0;
const MIN_MULTIPLIER     = 1.0;
const MIN_REQUESTS_NEEDED = 20;    // need at least N requests to make a decision

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getConfigValue(tenantId: number, key: string): Promise<string | null> {
  const [row] = await db
    .select({ value: orchestratorConfigTable.value })
    .from(orchestratorConfigTable)
    .where(and(eq(orchestratorConfigTable.tenantId, tenantId), eq(orchestratorConfigTable.key, key)));
  return row?.value ?? null;
}

async function setConfigValue(tenantId: number, key: string, value: string, description?: string): Promise<void> {
  await db
    .insert(orchestratorConfigTable)
    .values({ tenantId, key, value, description: description ?? null, updatedAt: new Date() } as any)
    .onConflictDoUpdate({
      target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
      set:    { value, updatedAt: new Date() },
    });
}

async function logTuningAction(
  tenantId: number,
  action:   string,
  oldValue: string | null,
  newValue: string | null,
  reason:   string,
  hostname?: string,
): Promise<void> {
  try {
    await db.insert(orchestratorTuningLogTable).values({
      tenantId,
      hostname: hostname ?? null,
      action,
      oldValue,
      newValue,
      reason,
      createdAt: new Date(),
    } as any);
  } catch (err) {
    logger.warn({ err }, "autoTuner: failed to log action (non-fatal)");
  }
}

// ── Per-tenant tuning cycle ───────────────────────────────────────────────────

async function tuneTenant(tenantId: number): Promise<void> {
  const since24h = new Date(Date.now() - 24 * 60 * 60_000);
  const since24hDate = since24h.toISOString().slice(0, 10);

  // Aggregate WAF stats across all hostnames for this tenant over last 24 h
  const [agg] = await db
    .select({
      totalRequests:   sql<number>`sum(total_requests)::int`,
      wafHits:         sql<number>`sum(waf_hits)::int`,
      bypassSuccesses: sql<number>`sum(bypass_successes)::int`,
      captchaHits:     sql<number>`sum(captcha_hits)::int`,
    })
    .from(orchestratorWafStatsTable)
    .where(
      and(
        eq(orchestratorWafStatsTable.tenantId, tenantId),
        gte(orchestratorWafStatsTable.statDate, since24hDate),
      )
    );

  const total   = agg?.totalRequests  ?? 0;
  const wafHits = agg?.wafHits        ?? 0;

  // Not enough traffic to make a reliable decision
  if (total < MIN_REQUESTS_NEEDED) {
    logger.debug({ tenantId, total }, "autoTuner: insufficient traffic for tuning decision");
    return;
  }

  const wafRate = wafHits / total;

  // Read current config
  const currentMultiplierStr = await getConfigValue(tenantId, "scan_delay_multiplier");
  const currentBypass        = await getConfigValue(tenantId, "waf_bypass_strategy");
  const currentMultiplier    = parseFloat(currentMultiplierStr ?? "1.0");

  logger.info({ tenantId, total, wafHits, wafRate: Math.round(wafRate * 100) + "%" }, "autoTuner: running tuning cycle");

  // ── Rule 1: High WAF rate → increase delay + enable bypass ────────────────
  if (wafRate > HIGH_WAF_RATE) {
    const newMult = Math.min(MAX_MULTIPLIER, parseFloat((currentMultiplier * DELAY_UP_FACTOR).toFixed(2)));
    if (newMult !== currentMultiplier) {
      await setConfigValue(tenantId, "scan_delay_multiplier", String(newMult), "Auto-tuned: high WAF rate");
      await logTuningAction(
        tenantId,
        "increase_delay_multiplier",
        String(currentMultiplier),
        String(newMult),
        `WAF hit rate ${Math.round(wafRate * 100)}% exceeded ${Math.round(HIGH_WAF_RATE * 100)}% threshold over ${total} requests in last 24h`,
      );
      logger.info({ tenantId, oldMult: currentMultiplier, newMult }, "autoTuner: increased delay multiplier");
    }

    if (currentBypass !== "rotate") {
      await setConfigValue(tenantId, "waf_bypass_strategy", "rotate", "Auto-tuned: high WAF rate");
      await logTuningAction(
        tenantId,
        "enable_waf_bypass",
        currentBypass ?? "none",
        "rotate",
        `WAF hit rate ${Math.round(wafRate * 100)}% — enabling fingerprint+proxy rotation bypass`,
      );
      logger.info({ tenantId }, "autoTuner: enabled WAF bypass (rotate)");
    }
    return;
  }

  // ── Rule 2: Medium WAF rate → enable bypass, no delay change ──────────────
  if (wafRate > MEDIUM_WAF_RATE) {
    if (currentBypass !== "rotate") {
      await setConfigValue(tenantId, "waf_bypass_strategy", "rotate", "Auto-tuned: medium WAF rate");
      await logTuningAction(
        tenantId,
        "enable_waf_bypass",
        currentBypass ?? "none",
        "rotate",
        `WAF hit rate ${Math.round(wafRate * 100)}% exceeded ${Math.round(MEDIUM_WAF_RATE * 100)}% — enabling bypass without delay increase`,
      );
      logger.info({ tenantId }, "autoTuner: enabled WAF bypass at medium rate (no delay change)");
    }
    return;
  }

  // ── Rule 3: Low WAF rate + elevated delay → reduce delay ──────────────────
  if (wafRate < LOW_WAF_RATE && currentMultiplier > MIN_MULTIPLIER) {
    const newMult = Math.max(MIN_MULTIPLIER, parseFloat((currentMultiplier * DELAY_DOWN_FACTOR).toFixed(2)));
    if (newMult !== currentMultiplier) {
      await setConfigValue(tenantId, "scan_delay_multiplier", String(newMult), "Auto-tuned: low WAF rate");
      await logTuningAction(
        tenantId,
        "decrease_delay_multiplier",
        String(currentMultiplier),
        String(newMult),
        `WAF hit rate ${Math.round(wafRate * 100)}% below ${Math.round(LOW_WAF_RATE * 100)}% threshold — reducing scan delay`,
      );
      logger.info({ tenantId, oldMult: currentMultiplier, newMult }, "autoTuner: decreased delay multiplier");
    }
  }

  // ── Rule 4: Very low WAF rate → disable bypass if it's been quiet ─────────
  if (wafRate < VERY_LOW_WAF_RATE && currentBypass === "rotate") {
    // Check 48h stats too — only disable bypass if it's been quiet for 2 days
    const since48hDate = new Date(Date.now() - 48 * 60 * 60_000).toISOString().slice(0, 10);
    const [agg48] = await db
      .select({ total: sql<number>`sum(total_requests)::int`, waf: sql<number>`sum(waf_hits)::int` })
      .from(orchestratorWafStatsTable)
      .where(and(
        eq(orchestratorWafStatsTable.tenantId, tenantId),
        gte(orchestratorWafStatsTable.statDate, since48hDate),
      ));
    const rate48 = (agg48?.total ?? 0) > 0 ? (agg48?.waf ?? 0) / (agg48?.total ?? 1) : 0;
    if (rate48 < VERY_LOW_WAF_RATE && (agg48?.total ?? 0) >= MIN_REQUESTS_NEEDED) {
      await setConfigValue(tenantId, "waf_bypass_strategy", "none", "Auto-tuned: very low WAF rate");
      await logTuningAction(
        tenantId,
        "disable_waf_bypass",
        "rotate",
        "none",
        `WAF hit rate ${Math.round(rate48 * 100)}% (48h) below ${Math.round(VERY_LOW_WAF_RATE * 100)}% — disabling bypass to reduce overhead`,
      );
      logger.info({ tenantId }, "autoTuner: disabled WAF bypass (very low rate over 48h)");
    }
  }
}

// ── Main cycle — iterate all tenants that have recent WAF stats ───────────────

export async function runAutoTunerCycle(): Promise<void> {
  try {
    const since24hDate = new Date(Date.now() - 24 * 60 * 60_000).toISOString().slice(0, 10);

    // Find tenants with enough recent traffic to tune
    const tenants = await db
      .selectDistinct({ tenantId: orchestratorWafStatsTable.tenantId })
      .from(orchestratorWafStatsTable)
      .where(gte(orchestratorWafStatsTable.statDate, since24hDate));

    if (tenants.length === 0) {
      logger.debug("autoTuner: no recent WAF stats — skipping cycle");
      return;
    }

    logger.info({ count: tenants.length }, "autoTuner: starting tuning cycle");
    for (const { tenantId } of tenants) {
      if (!tenantId) continue;
      await tuneTenant(tenantId).catch(err =>
        logger.warn({ err, tenantId }, "autoTuner: tuneTenant failed (non-fatal, skipping tenant)")
      );
    }
    logger.info({ count: tenants.length }, "autoTuner: tuning cycle complete");
  } catch (err) {
    logger.error({ err }, "autoTuner: runAutoTunerCycle error");
  }
}
