import { eq } from "drizzle-orm";
import { db, assetsTable, findingsTable, riskScoresTable } from "@workspace/db";
import { inArray } from "drizzle-orm";

function scoreToLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/**
 * Recompute risk scores + lastScannedAt for a set of assets after a real pipeline scan.
 * This is the single source of truth for post-scan risk calculation.
 * Imported by pipelineScans.ts — do not remove.
 */
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

    const cvssComponent = Math.round((avgCvss / 10) * 25 * 10) / 10;
    const epssComponent = Math.round(maxEpss * 15 * 10) / 10;
    const kevBonus      = kevCount * 8;

    const [existing] = await db.select({ id: riskScoresTable.id }).from(riskScoresTable)
      .where(eq(riskScoresTable.assetId, assetId));
    if (existing) {
      await db.update(riskScoresTable)
        .set({ score, level, cvssComponent, epssComponent, kevBonus })
        .where(eq(riskScoresTable.assetId, assetId));
    } else {
      await db.insert(riskScoresTable).values({ assetId, score, level, cvssComponent, epssComponent, kevBonus });
    }
    await db.update(assetsTable).set({ riskLevel: level }).where(eq(assetsTable.id, assetId));
  }
}
