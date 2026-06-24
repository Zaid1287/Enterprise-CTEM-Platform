/**
 * Beat scheduler — polls both asset-level scan frequencies and the
 * scan_schedules table (nextRunAt-based).
 *
 * When Redis is available → enqueues to BullMQ (worker handles execution).
 * When Redis is absent   → calls POST /api/scans/pipeline-run via internal
 *                          HTTP using the platform tenant's super_admin token.
 *
 * Key design decisions:
 *
 * 1. Platform tenant token: client tenants don't configure pipeline tools —
 *    the platform tenant does. Using the platform super_admin token lets
 *    pipeline-run load tools from the correct tenant while still attributing
 *    results to the right client tenant via effectiveTenantId (derived from
 *    each asset's own tenantId).
 *
 * 2. No pre-scan creation: pipeline-run is the single source of truth for
 *    scan records. Creating one here causes duplicate records.
 *
 * 3. Loop-break on failure: after all retry attempts are exhausted, each
 *    affected asset's lastScannedAt is stamped to now so isDue() returns
 *    false for the next interval — preventing the "never scanned → always
 *    due → always failing" infinite dispatch loop.
 */
import { logger } from "../lib/logger";
import { db, assetsTable, scanSchedulesTable, tenantsTable } from "@workspace/db";
import { and, eq, sql, lte, isNotNull, inArray } from "drizzle-orm";
import { getScanQueue } from "../queues/scanQueue";

let _port = 8080;
let _platformTenantId = 5; // resolved at startup
let _intervalHandle: ReturnType<typeof setInterval> | null = null;

function isDue(asset: { scanFrequency: string; lastScannedAt: Date | null }): boolean {
  if (asset.scanFrequency === "manual" || asset.scanFrequency === "once") return false;
  if (!asset.lastScannedAt) return true;
  const elapsed = Date.now() - asset.lastScannedAt.getTime();
  const intervals: Record<string, number> = {
    hourly:  3_600_000,
    daily:   86_400_000,
    weekly:  604_800_000,
    monthly: 2_592_000_000,
  };
  const interval = intervals[asset.scanFrequency];
  return !!interval && elapsed >= interval;
}

function computeNextRunAt(
  frequency: string,
  runTime: string,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
): Date {
  const [h, m] = (runTime ?? "09:00").split(":").map(Number);
  const now = new Date();
  const next = new Date();
  next.setSeconds(0, 0);
  next.setHours(h ?? 9, m ?? 0, 0, 0);

  if (frequency === "hourly") {
    if (next <= now) next.setHours(next.getHours() + 1);
  } else if (frequency === "daily") {
    if (next <= now) next.setDate(next.getDate() + 1);
  } else if (frequency === "weekly") {
    const dow = dayOfWeek ?? 1;
    let diff = (dow - now.getDay() + 7) % 7;
    if (diff === 0 && next <= now) diff = 7;
    next.setDate(now.getDate() + diff);
    next.setHours(h ?? 9, m ?? 0, 0, 0);
  } else if (frequency === "monthly") {
    const dom = dayOfMonth ?? 1;
    next.setDate(dom);
    if (next <= now) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(dom);
    }
  } else {
    next.setDate(next.getDate() + 1);
  }
  return next;
}

/**
 * Call POST /api/scans/pipeline-run with the platform tenant's credentials.
 *
 * On permanent failure (all attempts exhausted), stamps lastScannedAt on every
 * affected asset so isDue() returns false for the full scan interval — this
 * breaks the infinite "never scanned → always due → always failing" loop.
 */
async function runWithRetry(
  assetIds: number[],
  maxAttempts = 3,
): Promise<void> {
  const { signAccessToken } = await import("../lib/auth");
  const token = signAccessToken({ userId: 0, tenantId: _platformTenantId, role: "super_admin", email: "beat-scheduler@system" });
  const origin = `http://127.0.0.1:${_port}`;
  const body = JSON.stringify({ assetIds });

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const resp = await fetch(`${origin}/api/scans/pipeline-run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body,
      });

      if (!resp.ok) {
        const text = await resp.text().catch(() => "");
        throw new Error(`Pipeline HTTP ${resp.status}: ${text.slice(0, 300)}`);
      }
      logger.info({ assetIds, attempt }, "Beat: inline scan started");
      return;
    } catch (err) {
      if (attempt === maxAttempts) {
        logger.error({ err, assetIds }, "Beat: inline scan failed after retries");
        // Stamp lastScannedAt so these assets won't be considered "due" again
        // until their next full scan interval has elapsed.
        await db
          .update(assetsTable)
          .set({ lastScannedAt: new Date() })
          .where(inArray(assetsTable.id, assetIds))
          .catch(() => {});
      } else {
        const delay = 5_000 * Math.pow(2, attempt - 1);
        logger.warn({ err, attempt, assetIds, delay }, "Beat: retrying inline scan");
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
}

async function enqueueOrRun(assetIds: number[]): Promise<void> {
  const queue = getScanQueue();
  if (queue) {
    await queue.add(
      `scheduled:${assetIds.join("-")}`,
      { scanId: 0, assetIds, tenantId: _platformTenantId, userId: 0 },
      { delay: 0, attempts: 3, backoff: { type: "exponential", delay: 5_000 } },
    );
    logger.info({ assetIds }, "Beat: scan enqueued to BullMQ");
  } else {
    setImmediate(() => runWithRetry(assetIds).catch(() => {}));
    logger.info({ assetIds }, "Beat: inline scan triggered");
  }
}

async function dispatchDueAssets(): Promise<void> {
  const assets = await db
    .select({
      id:            assetsTable.id,
      tenantId:      assetsTable.tenantId,
      scanFrequency: assetsTable.scanFrequency,
      lastScannedAt: assetsTable.lastScannedAt,
    })
    .from(assetsTable)
    .where(
      and(
        eq(assetsTable.isActive, true),
        eq(assetsTable.verificationStatus, "verified"),
        sql`${assetsTable.scanFrequency} != 'manual'`,
      ),
    );

  const dueAssets = assets.filter(isDue);
  if (dueAssets.length === 0) return;

  const assetIds = dueAssets.map((a) => a.id);
  await enqueueOrRun(assetIds);
  logger.info({ count: dueAssets.length, assetIds }, "Beat: asset-frequency scan dispatched");
}

async function dispatchDueSchedules(): Promise<void> {
  const now = new Date();
  const dueSchedules = await db
    .select()
    .from(scanSchedulesTable)
    .where(
      and(
        eq(scanSchedulesTable.status, "active"),
        isNotNull(scanSchedulesTable.nextRunAt),
        lte(scanSchedulesTable.nextRunAt, now),
      ),
    );

  for (const schedule of dueSchedules) {
    try {
      const config = schedule.assetToolConfig as { assetId: number }[] | null;
      if (!config || !Array.isArray(config) || config.length === 0) continue;
      const rawIds = config.map((c) => c.assetId).filter(Boolean);
      if (rawIds.length === 0) continue;

      // Only scan verified assets
      const verifiedRows = await db
        .select({ id: assetsTable.id })
        .from(assetsTable)
        .where(eq(assetsTable.verificationStatus, "verified"));
      const verifiedSet = new Set(verifiedRows.map((r) => r.id));
      const assetIds = rawIds.filter((id) => verifiedSet.has(id));
      if (assetIds.length === 0) {
        logger.warn({ scheduleId: schedule.id }, "Beat: schedule skipped — no verified assets");
        continue;
      }

      const nextRunAt = computeNextRunAt(
        schedule.frequency ?? "daily",
        schedule.runTime ?? "09:00",
        schedule.dayOfWeek,
        schedule.dayOfMonth,
      );

      // Advance nextRunAt BEFORE dispatching so the next poll doesn't re-fire
      await db
        .update(scanSchedulesTable)
        .set({ lastRunAt: now, nextRunAt })
        .where(eq(scanSchedulesTable.id, schedule.id));

      await enqueueOrRun(assetIds);
      logger.info({ scheduleId: schedule.id, nextRunAt, assetIds }, "Beat: schedule dispatched");
    } catch (err) {
      logger.error({ err, scheduleId: schedule.id }, "Beat: failed to dispatch schedule");
    }
  }
}

async function dispatchDueScans(): Promise<void> {
  try {
    await Promise.all([dispatchDueAssets(), dispatchDueSchedules()]);
  } catch (err) {
    logger.error({ err }, "Beat scheduler error");
  }
}

export async function startBeatScheduler(port = 8080): Promise<void> {
  _port = port;

  // Resolve platform tenant ID once so inline scans use the correct credentials
  try {
    const [row] = await db
      .select({ id: tenantsTable.id })
      .from(tenantsTable)
      .where(eq(tenantsTable.isPlatform, true));
    if (row) _platformTenantId = row.id;
  } catch {
    logger.warn("Beat: could not resolve platform tenant ID, defaulting to 5");
  }

  logger.info(
    process.env.REDIS_URL
      ? "Beat scheduler active (BullMQ mode)"
      : "Beat scheduler active (inline-execution mode with retry)",
  );

  setTimeout(async () => {
    await dispatchDueScans();
    _intervalHandle = setInterval(dispatchDueScans, 60 * 1_000);
    logger.info("Beat scheduler polling started (60 s interval)");
  }, 30_000);
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
