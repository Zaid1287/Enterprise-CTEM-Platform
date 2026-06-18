/**
 * Beat scheduler — polls both asset-level scan frequencies and the
 * scan_schedules table (nextRunAt-based).
 *
 * When Redis is available → enqueues to BullMQ (worker handles execution).
 * When Redis is absent   → runs inline via internal HTTP with exponential
 *                          back-off retry (up to 3 attempts per scan).
 */
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import { db, assetsTable, scansTable, scanJobsTable, scanSchedulesTable } from "@workspace/db";
import { and, eq, sql, lte, isNotNull } from "drizzle-orm";
import { getScanQueue } from "../queues/scanQueue";

let _port = 8080;
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

async function runWithRetry(
  scanId: number,
  tenantId: number,
  assetIds: number[],
  maxAttempts = 3,
): Promise<void> {
  const { signAccessToken } = await import("../lib/auth");
  const token = signAccessToken({ userId: 0, tenantId, role: "admin" });
  const origin = `http://127.0.0.1:${_port}`;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await db
        .update(scansTable)
        .set({ status: "running", startedAt: new Date() })
        .where(eq(scansTable.id, scanId));

      const resp = await fetch(`${origin}/api/scans/pipeline-run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scanId, assetIds }),
      });

      if (!resp.ok) throw new Error(`Pipeline HTTP ${resp.status}`);
      logger.info({ scanId, attempt }, "Beat: inline scan started");
      return;
    } catch (err) {
      if (attempt === maxAttempts) {
        logger.error({ err, scanId }, "Beat: inline scan failed after retries");
        await db
          .update(scansTable)
          .set({ status: "failed" })
          .where(eq(scansTable.id, scanId))
          .catch(() => {});
      } else {
        const delay = 5_000 * Math.pow(2, attempt - 1);
        logger.warn({ err, attempt, scanId, delay }, "Beat: retrying inline scan");
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }
}

async function enqueueOrRun(
  scanId: number,
  tenantId: number,
  assetIds: number[],
): Promise<void> {
  const queue = getScanQueue();
  if (queue) {
    await queue.add(
      `scheduled:${scanId}`,
      { scanId, tenantId, userId: 0, assetIds },
      { delay: 0 },
    );
    logger.info({ tenantId, scanId }, "Beat: scan enqueued to BullMQ");
  } else {
    setImmediate(() => runWithRetry(scanId, tenantId, assetIds).catch(() => {}));
    logger.info({ tenantId, scanId }, "Beat: inline scan triggered");
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
        sql`${assetsTable.scanFrequency} != 'manual'`,
      ),
    );

  const dueAssets = assets.filter(isDue);
  if (dueAssets.length === 0) return;

  const byTenant = new Map<number, typeof dueAssets>();
  for (const a of dueAssets) {
    if (!byTenant.has(a.tenantId)) byTenant.set(a.tenantId, []);
    byTenant.get(a.tenantId)!.push(a);
  }

  for (const [tenantId, tenantAssets] of byTenant) {
    const assetIds = tenantAssets.map((a) => a.id);

    const [scan] = await db
      .insert(scansTable)
      .values({
        tenantId,
        name: `Scheduled Scan — ${new Date().toLocaleDateString()}`,
        type: "scheduled",
        status: "pending",
        assetIds,
        startedAt: new Date(),
      })
      .returning();

    await db.insert(scanJobsTable).values(
      assetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
    );

    await enqueueOrRun(scan.id, tenantId, assetIds);
    logger.info({ tenantId, scanId: scan.id, count: assetIds.length }, "Beat: asset-frequency scan dispatched");
  }
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
      const assetIds = config.map((c) => c.assetId).filter(Boolean);
      if (assetIds.length === 0) continue;

      const [scan] = await db
        .insert(scansTable)
        .values({
          tenantId: schedule.tenantId,
          name: `${schedule.name} — ${now.toLocaleDateString()}`,
          type: "scheduled",
          status: "pending",
          assetIds,
          startedAt: now,
        })
        .returning();

      await db.insert(scanJobsTable).values(
        assetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
      );

      const nextRunAt = computeNextRunAt(
        schedule.frequency ?? "daily",
        schedule.runTime ?? "09:00",
        schedule.dayOfWeek,
        schedule.dayOfMonth,
      );

      await db
        .update(scanSchedulesTable)
        .set({ lastRunAt: now, lastScanId: scan.id, nextRunAt })
        .where(eq(scanSchedulesTable.id, schedule.id));

      await enqueueOrRun(scan.id, schedule.tenantId, assetIds);
      logger.info(
        { scheduleId: schedule.id, scanId: scan.id, nextRunAt },
        "Beat: schedule dispatched",
      );
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
  logger.info(
    process.env.REDIS_URL
      ? "Beat scheduler active (BullMQ mode)"
      : "Beat scheduler active (inline-execution mode with retry)",
  );

  setTimeout(async () => {
    await dispatchDueScans();
    _intervalHandle = setInterval(dispatchDueScans, 60 * 60 * 1_000);
    logger.info("Beat scheduler polling started (1 h interval)");
  }, 30_000);
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
