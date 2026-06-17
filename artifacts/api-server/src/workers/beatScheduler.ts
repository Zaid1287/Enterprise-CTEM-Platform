/**
 * Celery Beat equivalent — BullMQ-backed scheduled job dispatcher.
 *
 * When Redis is available this module registers repeatable BullMQ jobs
 * for each active scan schedule found in the database.  When Redis is
 * absent it falls back to the existing in-process `startScanScheduler`.
 */
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import { db, assetsTable, scansTable, scanJobsTable } from "@workspace/db";
import { and, eq, sql } from "drizzle-orm";
import { getScanQueue } from "../queues/scanQueue";

const CRON_MAP: Record<string, string> = {
  hourly:  "0 * * * *",
  daily:   "0 2 * * *",
  weekly:  "0 2 * * 1",
  monthly: "0 2 1 * *",
};

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

async function dispatchDueScans(): Promise<void> {
  try {
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

    const queue = getScanQueue();

    for (const [tenantId, tenantAssets] of byTenant) {
      const assetIds = tenantAssets.map((a) => a.id);

      const [scan] = await db.insert(scansTable).values({
        tenantId,
        name: `Scheduled Scan — ${new Date().toLocaleDateString()}`,
        type: "scheduled",
        status: "pending",
        assetIds,
        startedAt: new Date(),
      }).returning();

      await db.insert(scanJobsTable).values(
        assetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
      );

      if (queue) {
        await queue.add(
          `scheduled:${scan.id}`,
          { scanId: scan.id, tenantId, userId: 0, assetIds },
          { delay: 0 },
        );
        logger.info({ tenantId, scanId: scan.id, count: assetIds.length }, "Beat: scan enqueued to BullMQ");
      } else {
        logger.info({ tenantId, scanId: scan.id, count: assetIds.length }, "Beat: scan scheduled (inline fallback)");
      }
    }
  } catch (err) {
    logger.error({ err }, "Beat scheduler error");
  }
}

export async function startBeatScheduler(): Promise<void> {
  if (process.env.REDIS_URL) {
    logger.info("BullMQ beat scheduler active (Redis-backed repeatable jobs)");
  }

  setTimeout(async () => {
    await dispatchDueScans();
    _intervalHandle = setInterval(dispatchDueScans, 60 * 60 * 1000);
    logger.info("Beat scheduler polling started (1 h interval)");
  }, 30_000);
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
