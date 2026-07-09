import { Router } from "express";
import { eq, and, inArray, desc, gte, sql } from "drizzle-orm";
import { db, riskScoresTable, assetsTable, riskScoreHistoryTable } from "@workspace/db";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter, getEffectiveAssetIdsForTenant } from "../lib/tenantScoping";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { finalizeScannedAssets } from "../lib/scanScheduler";
import { logger } from "../lib/logger";

const router = Router();
router.use(denyExternalMembers);

// ── Helper: build asset WHERE clause based on role ───────────────────────────
async function buildAssetFilter(req: AuthenticatedRequest) {
  const role = req.user!.role;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) return null;
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;

    if (!isNaN(qTenantId) && privIds.includes(qTenantId)) {
      // Specific client: resolve effective asset IDs (direct + assigned)
      const effectiveAssetIds = await getEffectiveAssetIdsForTenant(qTenantId);
      if (effectiveAssetIds.length === 0) return null;
      return inArray(assetsTable.id, effectiveAssetIds) as any;
    }
    // "All Clients": show assets from all accessible tenants
    const filtered = resolvePrivilegedTenantFilter(privIds, null);
    return inArray(assetsTable.tenantId, filtered) as any;
  }
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) return null;
    return inArray(assetsTable.tenantId, ids) as any;
  }
  if (role === "client") {
    return eq(assetsTable.assignedClientId, req.user!.userId) as any;
  }
  return eq(assetsTable.tenantId, req.user!.tenantId) as any;
}

// ── GET /risk/scores ─────────────────────────────────────────────────────────
router.get("/risk/scores", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const whereClause = await buildAssetFilter(req);
  if (whereClause === null) { res.json([]); return; }

  const scores = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
    assetType: assetsTable.type,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(whereClause);

  res.json(scores.map(({ score, assetName, assetType }) => ({
    id: score.id, assetId: score.assetId, assetName: assetName ?? "Unknown",
    assetType: assetType ?? null,
    score: score.score, level: score.level,
    cvssComponent: score.cvssComponent,
    epssComponent: score.epssComponent,
    kevBonus: score.kevBonus,
    criticalityBonus: score.criticalityBonus,
    exposureBonus: score.exposureBonus,
    businessImpactComponent: score.businessImpactComponent,
    updatedAt: score.updatedAt.toISOString(),
  })));
});

// ── GET /risk/scores/:assetId ────────────────────────────────────────────────
router.get("/risk/scores/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(String(req.params.assetId), 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid asset ID" }); return; }

  const role = req.user!.role;
  let assetFilter;
  if (role === "super_admin" || role === "admin") {
    assetFilter = eq(riskScoresTable.assetId, assetId);
  } else if (role === "client") {
    assetFilter = and(eq(riskScoresTable.assetId, assetId), eq(assetsTable.assignedClientId, req.user!.userId));
  } else {
    assetFilter = and(eq(riskScoresTable.assetId, assetId), eq(assetsTable.tenantId, req.user!.tenantId));
  }

  const [row] = await db.select({ score: riskScoresTable, assetName: assetsTable.name })
    .from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(assetFilter);

  if (!row) { res.status(404).json({ error: "Risk score not found" }); return; }
  const { score, assetName } = row;
  res.json({
    id: score.id, assetId: score.assetId, assetName: assetName ?? "Unknown",
    score: score.score, level: score.level,
    cvssComponent: score.cvssComponent,
    epssComponent: score.epssComponent,
    kevBonus: score.kevBonus,
    criticalityBonus: score.criticalityBonus,
    exposureBonus: score.exposureBonus,
    businessImpactComponent: score.businessImpactComponent,
    updatedAt: score.updatedAt.toISOString(),
  });
});

// ── GET /risk/scores/:assetId/history ────────────────────────────────────────
router.get("/risk/scores/:assetId/history", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(String(req.params.assetId), 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid asset ID" }); return; }

  const role = req.user!.role;
  let allowed = false;
  if (role === "super_admin" || role === "admin") {
    allowed = true;
  } else {
    const [asset] = await db.select({ tenantId: assetsTable.tenantId, assignedClientId: assetsTable.assignedClientId })
      .from(assetsTable).where(eq(assetsTable.id, assetId));
    if (asset) {
      if (role === "client") allowed = asset.assignedClientId === req.user!.userId;
      else allowed = asset.tenantId === req.user!.tenantId;
    }
  }
  if (!allowed) { res.status(404).json({ error: "Asset not found" }); return; }

  const days = Math.min(90, parseInt(String(req.query.days ?? "30"), 10) || 30);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  const rows = await db.select()
    .from(riskScoreHistoryTable)
    .where(and(eq(riskScoreHistoryTable.assetId, assetId), gte(riskScoreHistoryTable.calculatedAt, since)))
    .orderBy(desc(riskScoreHistoryTable.calculatedAt))
    .limit(500);

  res.json(rows.map(r => ({
    id: r.id, assetId: r.assetId, score: r.score, level: r.level,
    cvssComponent: r.cvssComponent, epssComponent: r.epssComponent,
    kevBonus: r.kevBonus, criticalityBonus: r.criticalityBonus,
    exposureBonus: r.exposureBonus, businessImpactComponent: r.businessImpactComponent,
    calculatedAt: r.calculatedAt.toISOString(),
  })));
});

// ── GET /risk/history ─────────────────────────────────────────────────────────
// Aggregate daily history for all assets the user can see — powers the trend chart.
router.get("/risk/history", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const whereClause = await buildAssetFilter(req);
  if (whereClause === null) { res.json([]); return; }

  // First: get the asset IDs in scope
  const assetRows = await db.select({ id: assetsTable.id }).from(assetsTable).where(whereClause);
  if (assetRows.length === 0) { res.json([]); return; }
  const assetIds = assetRows.map(a => a.id);

  const days = Math.min(90, parseInt(String(req.query.days ?? "30"), 10) || 30);
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

  // Aggregate by day: average score + count per level
  const rows = await db.select({
    day: sql<string>`DATE_TRUNC('day', ${riskScoreHistoryTable.calculatedAt})::date`.as("day"),
    avgScore: sql<number>`ROUND(AVG(${riskScoreHistoryTable.score})::numeric, 1)`.as("avg_score"),
    critical: sql<number>`COUNT(CASE WHEN ${riskScoreHistoryTable.level} = 'critical' THEN 1 END)`.as("critical"),
    high: sql<number>`COUNT(CASE WHEN ${riskScoreHistoryTable.level} = 'high' THEN 1 END)`.as("high"),
    medium: sql<number>`COUNT(CASE WHEN ${riskScoreHistoryTable.level} = 'medium' THEN 1 END)`.as("medium"),
    low: sql<number>`COUNT(CASE WHEN ${riskScoreHistoryTable.level} = 'low' THEN 1 END)`.as("low"),
  })
    .from(riskScoreHistoryTable)
    .where(and(
      inArray(riskScoreHistoryTable.assetId, assetIds),
      gte(riskScoreHistoryTable.calculatedAt, since),
    ))
    .groupBy(sql`DATE_TRUNC('day', ${riskScoreHistoryTable.calculatedAt})::date`)
    .orderBy(sql`DATE_TRUNC('day', ${riskScoreHistoryTable.calculatedAt})::date`);

  res.json(rows.map(r => ({
    day: r.day,
    avgScore: Number(r.avgScore),
    critical: Number(r.critical),
    high: Number(r.high),
    medium: Number(r.medium),
    low: Number(r.low),
  })));
});

// ── POST /risk/recalculate ────────────────────────────────────────────────────
// Issue 1: now uses the SAME unified formula as post-scan via finalizeScannedAssets
router.post("/risk/recalculate", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;

  let assets: { id: number }[];
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json({ recalculated: 0 }); return; }
    assets = await db.select({ id: assetsTable.id }).from(assetsTable).where(inArray(assetsTable.tenantId, privIds));
  } else {
    assets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.tenantId, req.user!.tenantId));
  }
  if (assets.length === 0) { res.json({ recalculated: 0 }); return; }

  const assetIds = assets.map(a => a.id);
  // Do NOT update lastScannedAt — this is a manual recalculate, not a real scan
  await finalizeScannedAssets(assetIds, { updateLastScannedAt: false });
  logger.info({ assetCount: assetIds.length, role }, "Manual risk recalculate completed");

  res.json({ recalculated: assetIds.length });
});

export default router;
