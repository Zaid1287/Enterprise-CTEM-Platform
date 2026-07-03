import { Router } from "express";
import { eq, and, count, inArray, avg, max } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { db, assetGroupsTable, assetGroupMembersTable, assetsTable, riskScoresTable } from "@workspace/db";
import {
  CreateAssetGroupBody, GetAssetGroupParams, UpdateAssetGroupParams,
  UpdateAssetGroupBody, DeleteAssetGroupParams,
} from "@workspace/api-zod";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";

const router = Router();
router.use(denyExternalMembers);

function toAssetResponse(a: typeof assetsTable.$inferSelect) {
  return {
    id: a.id, tenantId: a.tenantId, name: a.name, type: a.type, value: a.value,
    status: a.status, riskScore: a.riskScore, ipAddress: a.ipAddress,
    verificationStatus: a.verificationStatus,
    createdAt: a.createdAt.toISOString(),
    lastScannedAt: a.lastScannedAt?.toISOString() ?? null,
  };
}

router.get("/asset-groups", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  let groupWhere;
  if (req.user!.role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    groupWhere = inArray(assetGroupsTable.tenantId, ids);
  } else {
    groupWhere = eq(assetGroupsTable.tenantId, req.user!.tenantId);
  }
  const groups = await db.select().from(assetGroupsTable).where(groupWhere);
  const memberCounts = await db.select({
    groupId: assetGroupMembersTable.groupId,
    cnt: count(),
  }).from(assetGroupMembersTable).groupBy(assetGroupMembersTable.groupId);
  const countMap = Object.fromEntries(memberCounts.map(m => [m.groupId, Number(m.cnt)]));

  // Aggregate risk scores per group via member assets
  const allMembers = await db.select({
    groupId: assetGroupMembersTable.groupId,
    assetId: assetGroupMembersTable.assetId,
  }).from(assetGroupMembersTable);
  const memberAssetIds = [...new Set(allMembers.map(m => m.assetId))];
  const riskRows = memberAssetIds.length > 0
    ? await db.select({ assetId: riskScoresTable.assetId, score: riskScoresTable.score, level: riskScoresTable.level })
        .from(riskScoresTable).where(inArray(riskScoresTable.assetId, memberAssetIds))
    : [];
  const riskByAsset = new Map(riskRows.map(r => [r.assetId, r]));

  // Build per-group risk stats
  const groupRiskMap = new Map<number, { scores: number[]; levels: string[] }>();
  for (const m of allMembers) {
    const r = riskByAsset.get(m.assetId);
    if (!r) continue;
    const existing = groupRiskMap.get(m.groupId) ?? { scores: [], levels: [] };
    existing.scores.push(r.score);
    existing.levels.push(r.level);
    groupRiskMap.set(m.groupId, existing);
  }

  res.json(groups.map(g => {
    const riskInfo = groupRiskMap.get(g.id);
    const avgRisk = riskInfo && riskInfo.scores.length > 0
      ? Math.round(riskInfo.scores.reduce((a, b) => a + b, 0) / riskInfo.scores.length)
      : null;
    const maxRisk = riskInfo && riskInfo.scores.length > 0
      ? Math.max(...riskInfo.scores)
      : null;
    // Highest severity level in group
    const LEVEL_ORDER = ["critical", "high", "medium", "low", "none"];
    const worstLevel = riskInfo ? LEVEL_ORDER.find(l => riskInfo.levels.includes(l)) ?? null : null;
    return {
      id: g.id, tenantId: g.tenantId, name: g.name, description: g.description,
      color: g.color ?? "slate",
      assetCount: countMap[g.id] ?? 0,
      avgRisk, maxRisk, worstLevel,
      createdAt: g.createdAt.toISOString(),
    };
  }));
});

router.post("/asset-groups", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAssetGroupBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const { assetIds, color, ...groupData } = parsed.data as any;
  const [group] = await db.insert(assetGroupsTable).values({
    ...groupData, color: color ?? "slate", tenantId: req.user!.tenantId,
  }).returning();
  if (assetIds?.length) {
    await db.insert(assetGroupMembersTable).values(assetIds.map((id: number) => ({ groupId: group.id, assetId: id })));
  }
  res.status(201).json({ ...group, color: group.color ?? "slate", assetCount: assetIds?.length ?? 0, createdAt: group.createdAt.toISOString() });
});

router.get("/asset-groups/:groupId/members", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const groupId = parseInt(req.params.groupId, 10);
  if (isNaN(groupId)) { res.status(400).json({ error: "Invalid groupId" }); return; }
  const [group] = await db.select().from(assetGroupsTable)
    .where(and(eq(assetGroupsTable.id, groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)));
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }

  const members = await db.select({ assetId: assetGroupMembersTable.assetId })
    .from(assetGroupMembersTable).where(eq(assetGroupMembersTable.groupId, groupId));

  if (members.length === 0) { res.json([]); return; }

  const assetIds = members.map(m => m.assetId);
  const assets = await db.select().from(assetsTable)
    .where(and(inArray(assetsTable.id, assetIds), eq(assetsTable.tenantId, req.user!.tenantId)));
  res.json(assets.map(toAssetResponse));
});

router.put("/asset-groups/:groupId/members", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const groupId = parseInt(req.params.groupId, 10);
  if (isNaN(groupId)) { res.status(400).json({ error: "Invalid groupId" }); return; }
  const [group] = await db.select().from(assetGroupsTable)
    .where(and(eq(assetGroupsTable.id, groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)));
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }

  const assetIds: number[] = Array.isArray(req.body.assetIds) ? req.body.assetIds.map(Number).filter((n: number) => !isNaN(n)) : [];

  await db.delete(assetGroupMembersTable).where(eq(assetGroupMembersTable.groupId, groupId));
  if (assetIds.length > 0) {
    await db.insert(assetGroupMembersTable).values(assetIds.map(id => ({ groupId, assetId: id })));
  }

  res.json({ ...group, assetCount: assetIds.length, createdAt: group.createdAt.toISOString() });
});

router.get("/asset-groups/:groupId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAssetGroupParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [group] = await db.select().from(assetGroupsTable)
    .where(and(eq(assetGroupsTable.id, params.data.groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)));
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }
  const [{ cnt }] = await db.select({ cnt: count() }).from(assetGroupMembersTable)
    .where(eq(assetGroupMembersTable.groupId, group.id));
  // Compute aggregate risk for this group
  const members = await db.select({ assetId: assetGroupMembersTable.assetId })
    .from(assetGroupMembersTable).where(eq(assetGroupMembersTable.groupId, group.id));
  const memberIds = members.map(m => m.assetId);
  const riskRows = memberIds.length > 0
    ? await db.select({ score: riskScoresTable.score, level: riskScoresTable.level })
        .from(riskScoresTable).where(inArray(riskScoresTable.assetId, memberIds))
    : [];
  const scores = riskRows.map(r => r.score);
  const avgRisk = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const maxRisk = scores.length > 0 ? Math.max(...scores) : null;
  const LEVEL_ORDER = ["critical", "high", "medium", "low", "none"];
  const levels = riskRows.map(r => r.level);
  const worstLevel = levels.length > 0 ? LEVEL_ORDER.find(l => levels.includes(l)) ?? null : null;
  res.json({ ...group, color: group.color ?? "slate", assetCount: Number(cnt), avgRisk, maxRisk, worstLevel, createdAt: group.createdAt.toISOString() });
});

router.patch("/asset-groups/:groupId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAssetGroupParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAssetGroupBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const { assetIds, color, ...updates } = parsed.data as any;
  if (color !== undefined) (updates as any).color = color;
  const [group] = await db.update(assetGroupsTable).set(updates)
    .where(and(eq(assetGroupsTable.id, params.data.groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }

  if (Array.isArray(assetIds)) {
    await db.delete(assetGroupMembersTable).where(eq(assetGroupMembersTable.groupId, group.id));
    if (assetIds.length > 0) {
      await db.insert(assetGroupMembersTable).values(assetIds.map((id: number) => ({ groupId: group.id, assetId: id })));
    }
  }

  const [{ cnt }] = await db.select({ cnt: count() }).from(assetGroupMembersTable)
    .where(eq(assetGroupMembersTable.groupId, group.id));
  res.json({ ...group, color: group.color ?? "slate", assetCount: Number(cnt), createdAt: group.createdAt.toISOString() });
});

router.delete("/asset-groups/:groupId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteAssetGroupParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  await db.delete(assetGroupMembersTable).where(eq(assetGroupMembersTable.groupId, params.data.groupId));
  const [group] = await db.delete(assetGroupsTable)
    .where(and(eq(assetGroupsTable.id, params.data.groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }
  res.sendStatus(204);
});

export default router;
