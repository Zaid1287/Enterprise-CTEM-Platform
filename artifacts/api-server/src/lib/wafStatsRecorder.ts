/**
 * WAF Stats Recorder
 *
 * Buffers per-tenant/hostname WAF outcome counts in memory and flushes them
 * to the database every 30 seconds via atomic increment upserts.  This keeps
 * the hot request path free of synchronous DB writes.
 *
 * Also tracks per-fingerprint-profile A/B performance (successes vs WAF blocks)
 * using the same buffer + flush pattern.  The UCB1 profile selector in
 * scanOrchestrator.ts reads profile stats from the DB (5-min TTL) to pick the
 * statistically best-performing profile while still exploring less-tested ones.
 */

import { db, orchestratorWafStatsTable, orchestratorProfileStatsTable } from "@workspace/db";
import { sql } from "drizzle-orm";
import { logger } from "./logger.js";

// ── WAF outcome type ───────────────────────────────────────────────────────────
export type WafOutcome =
  | "success"         // request succeeded with no prior WAF detection on this call
  | "waf_hit"         // WAF blocked this attempt
  | "bypass_success"  // WAF was detected on a prior attempt; this attempt succeeded
  | "captcha";        // CAPTCHA gate encountered (whether solved or not)

// ── In-memory accumulation buffers ────────────────────────────────────────────
// Key format for WAF buffer:  "{tenantId}::{hostname}::{YYYY-MM-DD}"
// Key format for profile buf: "{profileId}::{tenantId}"
interface WafBucket {
  totalRequests:   number;
  wafHits:         number;
  bypassSuccesses: number;
  captchaHits:     number;
  directSuccesses: number;
}
interface ProfileBucket {
  totalUses:  number;
  successes:  number;
  wafBlocked: number;
}

const _wafBuf    = new Map<string, WafBucket>();
const _profBuf   = new Map<string, ProfileBucket>();

function utcDateString(): string {
  return new Date().toISOString().slice(0, 10);
}

// ── Public recording functions (synchronous — zero latency on hot path) ────────

export function recordWafOutcome(
  tenantId: number,
  hostname: string,
  outcome:  WafOutcome,
): void {
  if (!tenantId || !hostname) return;
  const key = `${tenantId}::${hostname}::${utcDateString()}`;
  let b = _wafBuf.get(key);
  if (!b) { b = { totalRequests: 0, wafHits: 0, bypassSuccesses: 0, captchaHits: 0, directSuccesses: 0 }; _wafBuf.set(key, b); }
  b.totalRequests++;
  if (outcome === "waf_hit")         b.wafHits++;
  else if (outcome === "bypass_success") b.bypassSuccesses++;
  else if (outcome === "captcha")    b.captchaHits++;
  else if (outcome === "success")    b.directSuccesses++;
}

export function recordProfileOutcome(
  profileId: number,
  tenantId:  number,
  success:   boolean,
  wafBlock:  boolean,
): void {
  if (!profileId || !tenantId) return;
  const key = `${profileId}::${tenantId}`;
  let b = _profBuf.get(key);
  if (!b) { b = { totalUses: 0, successes: 0, wafBlocked: 0 }; _profBuf.set(key, b); }
  b.totalUses++;
  if (success)  b.successes++;
  if (wafBlock) b.wafBlocked++;
}

// ── Flush to DB ───────────────────────────────────────────────────────────────

async function flushWafStats(): Promise<void> {
  if (_wafBuf.size === 0) return;
  const snapshot = new Map(_wafBuf);
  _wafBuf.clear();

  for (const [key, b] of snapshot) {
    const parts     = key.split("::");
    const tenantId  = parseInt(parts[0]!, 10);
    const hostname  = parts[1];
    const statDate  = parts[2];
    if (!tenantId || !hostname || !statDate) continue;
    try {
      await db
        .insert(orchestratorWafStatsTable)
        .values({
          tenantId, hostname, statDate,
          totalRequests:   b.totalRequests,
          wafHits:         b.wafHits,
          bypassSuccesses: b.bypassSuccesses,
          captchaHits:     b.captchaHits,
          directSuccesses: b.directSuccesses,
          updatedAt:       new Date(),
        } as any)
        .onConflictDoUpdate({
          target: [
            orchestratorWafStatsTable.tenantId,
            orchestratorWafStatsTable.hostname,
            orchestratorWafStatsTable.statDate,
          ],
          set: {
            totalRequests:   sql`orchestrator_waf_stats.total_requests   + ${b.totalRequests}`,
            wafHits:         sql`orchestrator_waf_stats.waf_hits         + ${b.wafHits}`,
            bypassSuccesses: sql`orchestrator_waf_stats.bypass_successes + ${b.bypassSuccesses}`,
            captchaHits:     sql`orchestrator_waf_stats.captcha_hits     + ${b.captchaHits}`,
            directSuccesses: sql`orchestrator_waf_stats.direct_successes + ${b.directSuccesses}`,
            updatedAt:       new Date(),
          },
        });
    } catch (err) {
      logger.warn({ err, key }, "wafStatsRecorder: WAF stats flush failed (non-fatal)");
      // Put back so next flush retries
      const existing = _wafBuf.get(key);
      if (existing) {
        existing.totalRequests   += b.totalRequests;
        existing.wafHits         += b.wafHits;
        existing.bypassSuccesses += b.bypassSuccesses;
        existing.captchaHits     += b.captchaHits;
        existing.directSuccesses += b.directSuccesses;
      } else {
        _wafBuf.set(key, b);
      }
    }
  }
}

async function flushProfileStats(): Promise<void> {
  if (_profBuf.size === 0) return;
  const snapshot = new Map(_profBuf);
  _profBuf.clear();

  for (const [key, b] of snapshot) {
    const parts     = key.split("::");
    const profileId = parseInt(parts[0]!, 10);
    const tenantId  = parseInt(parts[1]!, 10);
    if (!profileId || !tenantId) continue;
    try {
      await db
        .insert(orchestratorProfileStatsTable)
        .values({
          profileId, tenantId,
          totalUses:  b.totalUses,
          successes:  b.successes,
          wafBlocked: b.wafBlocked,
          lastUsedAt: new Date(),
          updatedAt:  new Date(),
        } as any)
        .onConflictDoUpdate({
          target: [
            orchestratorProfileStatsTable.profileId,
            orchestratorProfileStatsTable.tenantId,
          ],
          set: {
            totalUses:  sql`orchestrator_profile_stats.total_uses  + ${b.totalUses}`,
            successes:  sql`orchestrator_profile_stats.successes   + ${b.successes}`,
            wafBlocked: sql`orchestrator_profile_stats.waf_blocked + ${b.wafBlocked}`,
            lastUsedAt: new Date(),
            updatedAt:  new Date(),
          },
        });
    } catch (err) {
      logger.warn({ err, key }, "wafStatsRecorder: profile stats flush failed (non-fatal)");
      const existing = _profBuf.get(key);
      if (existing) {
        existing.totalUses  += b.totalUses;
        existing.successes  += b.successes;
        existing.wafBlocked += b.wafBlocked;
      } else {
        _profBuf.set(key, b);
      }
    }
  }
}

// ── Init — call once at server startup ────────────────────────────────────────
export function initWafStatsRecorder(): void {
  setInterval(() => {
    flushWafStats().catch(() => {});
    flushProfileStats().catch(() => {});
  }, 30_000);
  logger.info("WAF stats recorder: 30 s flush interval started");
}
