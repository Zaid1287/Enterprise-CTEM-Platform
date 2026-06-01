import { Router } from "express";
import { eq, and, count } from "drizzle-orm";
import { db, assetGroupsTable, assetGroupMembersTable } from "@workspace/db";
import {
  CreateAssetGroupBody, GetAssetGroupParams, UpdateAssetGroupParams,
  UpdateAssetGroupBody, DeleteAssetGroupParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/asset-groups", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const groups = await db.select().from(assetGroupsTable)
    .where(eq(assetGroupsTable.tenantId, req.user!.tenantId));
  const memberCounts = await db.select({
    groupId: assetGroupMembersTable.groupId,
    cnt: count(),
  }).from(assetGroupMembersTable).groupBy(assetGroupMembersTable.groupId);
  const countMap = Object.fromEntries(memberCounts.map(m => [m.groupId, Number(m.cnt)]));
  res.json(groups.map(g => ({
    id: g.id, tenantId: g.tenantId, name: g.name, description: g.description,
    assetCount: countMap[g.id] ?? 0, createdAt: g.createdAt.toISOString(),
  })));
});

router.post("/asset-groups", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAssetGroupBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const { assetIds, ...groupData } = parsed.data as any;
  const [group] = await db.insert(assetGroupsTable).values({
    ...groupData, tenantId: req.user!.tenantId,
  }).returning();
  if (assetIds?.length) {
    await db.insert(assetGroupMembersTable).values(assetIds.map((id: number) => ({ groupId: group.id, assetId: id })));
  }
  res.status(201).json({ ...group, assetCount: assetIds?.length ?? 0, createdAt: group.createdAt.toISOString() });
});

router.get("/asset-groups/:groupId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAssetGroupParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [group] = await db.select().from(assetGroupsTable)
    .where(and(eq(assetGroupsTable.id, params.data.groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)));
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }
  const [{ cnt }] = await db.select({ cnt: count() }).from(assetGroupMembersTable)
    .where(eq(assetGroupMembersTable.groupId, group.id));
  res.json({ ...group, assetCount: Number(cnt), createdAt: group.createdAt.toISOString() });
});

router.patch("/asset-groups/:groupId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAssetGroupParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAssetGroupBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [group] = await db.update(assetGroupsTable).set(parsed.data)
    .where(and(eq(assetGroupsTable.id, params.data.groupId), eq(assetGroupsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!group) { res.status(404).json({ error: "Asset group not found" }); return; }
  res.json({ ...group, assetCount: 0, createdAt: group.createdAt.toISOString() });
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
