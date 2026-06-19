import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, riskScoresTable, assetsTable } from "@workspace/db";
import { getAmClientTenantIds } from "../lib/amScoping";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/risk/scores", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  let whereClause;
  if (req.user!.role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    whereClause = inArray(assetsTable.tenantId, ids);
  } else {
    whereClause = eq(assetsTable.tenantId, req.user!.tenantId);
  }
  const scores = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
    assetType: assetsTable.type,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(whereClause);

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

  const [row] = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(and(eq(riskScoresTable.assetId, assetId), eq(assetsTable.tenantId, req.user!.tenantId)));

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

export default router;
