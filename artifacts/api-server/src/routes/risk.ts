import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, riskScoresTable, assetsTable, findingsTable } from "@workspace/db";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter } from "../lib/tenantScoping";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";

const router = Router();
router.use(denyExternalMembers);

router.get("/risk/scores", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  let whereClause: ReturnType<typeof eq> | ReturnType<typeof inArray> | undefined;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    whereClause = inArray(assetsTable.tenantId, filtered) as any;
  } else if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    whereClause = inArray(assetsTable.tenantId, ids) as any;
  } else if (role === "client") {
    // Client sees risk scores only for assets explicitly assigned to them (cross-tenant)
    whereClause = eq(assetsTable.assignedClientId, req.user!.userId) as any;
  } else {
    whereClause = eq(assetsTable.tenantId, req.user!.tenantId) as any;
  }
  const scores = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
    assetType: assetsTable.type,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(whereClause as any);

  res.json(scores.map(({ score, assetName, assetType }) => ({
    id: score.id, assetId: score.assetId, assetName: assetName ?? "Unknown",
    score: score.score, level: score.level, cvssComponent: score.cvssComponent,
    epssComponent: score.epssComponent, kevBonus: score.kevBonus,
    criticalityBonus: score.criticalityBonus, exposureBonus: score.exposureBonus,
    updatedAt: score.updatedAt.toISOString(),
  })));
});

router.get("/risk/scores/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId = parseInt(String(req.params.assetId), 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid asset ID" }); return; }

  const role = req.user!.role;
  let assetFilter;
  if (role === "super_admin" || role === "admin") {
    assetFilter = eq(riskScoresTable.assetId, assetId);
  } else if (role === "client") {
    // Client: only if the asset is explicitly assigned to them
    assetFilter = and(
      eq(riskScoresTable.assetId, assetId),
      eq(assetsTable.assignedClientId, req.user!.userId),
    );
  } else {
    assetFilter = and(eq(riskScoresTable.assetId, assetId), eq(assetsTable.tenantId, req.user!.tenantId));
  }
  const [row] = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(assetFilter);

  if (!row) { res.status(404).json({ error: "Risk score not found" }); return; }
  const { score, assetName } = row;
  res.json({
    id: score.id, assetId: score.assetId, assetName: assetName ?? "Unknown",
    score: score.score, level: score.level, cvssComponent: score.cvssComponent,
    epssComponent: score.epssComponent, kevBonus: score.kevBonus,
    criticalityBonus: score.criticalityBonus, exposureBonus: score.exposureBonus,
    updatedAt: score.updatedAt.toISOString(),
  });
});

router.post("/risk/recalculate", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const recalcRole = req.user!.role;

  let assets: (typeof assetsTable.$inferSelect)[];
  if (recalcRole === "super_admin" || recalcRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json({ recalculated: 0 }); return; }
    assets = await db.select().from(assetsTable).where(inArray(assetsTable.tenantId, privIds));
  } else {
    assets = await db.select().from(assetsTable).where(eq(assetsTable.tenantId, tenantId));
  }
  if (assets.length === 0) { res.json({ recalculated: 0 }); return; }

  const assetIds = assets.map(a => a.id);
  const allFindings = await db.select().from(findingsTable).where(
    and(
      inArray(findingsTable.assetId, assetIds),
      inArray(findingsTable.status, ["open", "in_progress"]),
    ),
  );

  const byAsset = new Map<number, typeof allFindings>();
  for (const f of allFindings) {
    if (!byAsset.has(f.assetId)) byAsset.set(f.assetId, []);
    byAsset.get(f.assetId)!.push(f);
  }

  let recalculated = 0;
  for (const asset of assets) {
    const af = byAsset.get(asset.id) ?? [];

    const maxCvss = af.reduce((m, f) => Math.max(m, f.cvss ?? 0), 0);
    const cvssComponent = (maxCvss / 10) * 40;

    const maxEpss = af.reduce((m, f) => Math.max(m, f.epss ?? 0), 0);
    const epssComponent = maxEpss * 20;

    const kevBonus = af.some(f => f.isKev) ? 15 : 0;

    const critMap: Record<string, number> = { critical: 20, high: 15, medium: 10, low: 5 };
    const criticalityBonus = critMap[asset.riskLevel ?? "low"] ?? 5;

    const portCount = af.filter(f => (f.cve ?? "").startsWith("EXP-PORT-")).length;
    const exposureBonus = Math.min(5, portCount * 1.5);

    const score = Math.min(100, cvssComponent + epssComponent + kevBonus + criticalityBonus + exposureBonus);
    const level = score >= 70 ? "critical" : score >= 40 ? "high" : score >= 20 ? "medium" : "low";

    await db.insert(riskScoresTable).values({
      assetId: asset.id,
      score,
      level,
      cvssComponent,
      epssComponent,
      kevBonus,
      criticalityBonus,
      exposureBonus,
    }).onConflictDoUpdate({
      target: riskScoresTable.assetId,
      set: { score, level, cvssComponent, epssComponent, kevBonus, criticalityBonus, exposureBonus },
    });
    recalculated++;
  }

  res.json({ recalculated });
});

export default router;
