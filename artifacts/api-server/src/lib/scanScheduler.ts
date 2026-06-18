import { and, eq, isNotNull, lt, or, isNull, sql } from "drizzle-orm";
import { db, assetsTable, scansTable, scanJobsTable, findingsTable, riskScoresTable } from "@workspace/db";
import { inArray } from "drizzle-orm";
import { logger } from "./logger";

function scoreToLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/** Recompute risk scores + lastScannedAt for a set of assets (shared logic). */
export async function finalizeScannedAssets(assetIds: number[]) {
  if (assetIds.length === 0) return;
  const now = new Date();

  await db.update(assetsTable).set({ lastScannedAt: now }).where(inArray(assetsTable.id, assetIds));

  const findings = await db
    .select({
      assetId: findingsTable.assetId,
      severity: findingsTable.severity,
      cvss: findingsTable.cvss,
      epss: findingsTable.epss,
      isKev: findingsTable.isKev,
      status: findingsTable.status,
    })
    .from(findingsTable)
    .where(inArray(findingsTable.assetId, assetIds));

  const byAsset = new Map<number, typeof findings>();
  for (const f of findings) {
    if (!byAsset.has(f.assetId!)) byAsset.set(f.assetId!, []);
    byAsset.get(f.assetId!)!.push(f);
  }

  const assetRows = await db
    .select({ id: assetsTable.id, businessImpact: assetsTable.businessImpact })
    .from(assetsTable)
    .where(inArray(assetsTable.id, assetIds));
  const biMap = new Map(assetRows.map(a => [a.id, a.businessImpact ?? 5]));

  for (const assetId of assetIds) {
    const all = byAsset.get(assetId) ?? [];
    const open = all.filter(f => f.status !== "mitigated" && f.status !== "resolved");

    const critical = open.filter(f => f.severity === "critical").length;
    const high     = open.filter(f => f.severity === "high").length;
    const medium   = open.filter(f => f.severity === "medium").length;

    let score = critical * 22 + high * 12 + medium * 5;
    const cvssVals = open.map(f => f.cvss ?? 0).filter(v => v > 0);
    const avgCvss = cvssVals.length ? cvssVals.reduce((a, b) => a + b, 0) / cvssVals.length : 0;
    score += (avgCvss / 10) * 25;
    const maxEpss = open.reduce((m, f) => Math.max(m, f.epss ?? 0), 0);
    score += maxEpss * 15;
    const kevCount = open.filter(f => f.isKev).length;
    score += kevCount * 8;
    const businessImpact = biMap.get(assetId) ?? 5;
    score += Math.round((businessImpact / 10) * 20);
    score = Math.round(Math.min(100, Math.max(0, score)));
    const level = scoreToLevel(score);

    const [existing] = await db.select({ id: riskScoresTable.id }).from(riskScoresTable)
      .where(eq(riskScoresTable.assetId, assetId));
    if (existing) {
      await db.update(riskScoresTable).set({ score, level }).where(eq(riskScoresTable.assetId, assetId));
    } else {
      await db.insert(riskScoresTable).values({ assetId, score, level });
    }
    await db.update(assetsTable).set({ riskLevel: level }).where(eq(assetsTable.id, assetId));
  }
}

/** Returns true if the asset is due for a scheduled scan based on its frequency + lastScannedAt */
function isDue(asset: { scanFrequency: string; lastScannedAt: Date | null }): boolean {
  if (asset.scanFrequency === "manual" || asset.scanFrequency === "once") return false;
  if (!asset.lastScannedAt) return true; // never scanned → run now

  const now = Date.now();
  const last = asset.lastScannedAt.getTime();
  const elapsed = now - last;

  const intervals: Record<string, number> = {
    daily:   24 * 60 * 60 * 1000,
    weekly:   7 * 24 * 60 * 60 * 1000,
    monthly: 30 * 24 * 60 * 60 * 1000,
  };
  const interval = intervals[asset.scanFrequency];
  if (!interval) return false;
  return elapsed >= interval;
}

/** Check all assets with a scheduled frequency and trigger scans for those overdue. */
async function runScheduler() {
  try {
    const assets = await db
      .select({
        id: assetsTable.id,
        tenantId: assetsTable.tenantId,
        name: assetsTable.name,
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

    // Group by tenant so we create one scan per tenant batch
    const byTenant = new Map<number, typeof dueAssets>();
    for (const a of dueAssets) {
      if (!byTenant.has(a.tenantId)) byTenant.set(a.tenantId, []);
      byTenant.get(a.tenantId)!.push(a);
    }

    for (const [tenantId, tenantAssets] of byTenant) {
      const assetIds = tenantAssets.map(a => a.id);
      logger.info({ tenantId, count: assetIds.length }, "Scheduled scan triggered");

      const [scan] = await db.insert(scansTable).values({
        tenantId,
        name: `Scheduled Scan – ${new Date().toLocaleDateString()}`,
        type: "scheduled",
        status: "pending",
        assetIds,
        startedAt: new Date(),
      }).returning();

      await db.insert(scanJobsTable).values(
        assetIds.map(assetId => ({ scanId: scan.id, assetId, status: "pending" }))
      );

      // Simulate completion
      setTimeout(async () => {
        try {
          await db.update(scansTable).set({ status: "running" }).where(eq(scansTable.id, scan.id));
          await db.update(scanJobsTable).set({ status: "running" }).where(eq(scanJobsTable.scanId, scan.id));
        } catch { /**/ }
        setTimeout(async () => {
          try {
            const completedAt = new Date();
            await db.update(scansTable).set({ status: "completed", completedAt }).where(eq(scansTable.id, scan.id));
            await db.update(scanJobsTable).set({ status: "completed", completedAt }).where(eq(scanJobsTable.scanId, scan.id));
            await finalizeScannedAssets(assetIds);
          } catch { /**/ }
        }, 8000);
      }, 2000);
    }
  } catch (err) {
    logger.error({ err }, "Scan scheduler error");
  }
}

/** Start the background scheduler — checks every hour for overdue assets. */
export function startScanScheduler() {
  // Run once 30s after startup (catches anything immediately due), then every hour
  setTimeout(() => {
    runScheduler();
    setInterval(runScheduler, 60 * 60 * 1000);
  }, 30_000);
  logger.info("Scan scheduler started");
}
