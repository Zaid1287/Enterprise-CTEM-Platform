import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, packagesTable, tenantPackagesTable } from "@workspace/db";
import { requireAuth, requireRole, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";

const router = Router();
router.use(denyExternalMembers);

function toPackageResponse(pkg: typeof packagesTable.$inferSelect) {
  return {
    id: pkg.id,
    name: pkg.name,
    description: pkg.description,
    price: Number(pkg.price),
    features: (pkg.features as string[]) ?? [],
    maxAssets: pkg.maxAssets,
    maxUsers: pkg.maxUsers,
    toolIds: (pkg.toolIds as number[]) ?? [],
    isActive: pkg.isActive,
    createdAt: pkg.createdAt.toISOString(),
  };
}

router.get("/packages", requireAuth, async (_req, res): Promise<void> => {
  const packages = await db.select().from(packagesTable).orderBy(packagesTable.createdAt);
  res.json(packages.map(toPackageResponse));
});

router.post("/packages", requireAuth, requireRole("super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { name, description, price, features, maxAssets, maxUsers, toolIds } = req.body;
  if (!name) { res.status(400).json({ error: "name is required" }); return; }
  const [pkg] = await db.insert(packagesTable).values({
    name,
    description: description ?? null,
    price: String(price ?? 0),
    features: Array.isArray(features) ? features : [],
    maxAssets: maxAssets ?? null,
    maxUsers: maxUsers ?? null,
    toolIds: Array.isArray(toolIds) ? toolIds : [],
  }).returning();
  res.status(201).json(toPackageResponse(pkg));
});

router.patch("/packages/:packageId", requireAuth, requireRole("super_admin"), async (req, res): Promise<void> => {
  const packageId = Number(req.params.packageId);
  if (!packageId) { res.status(400).json({ error: "Invalid ID" }); return; }
  const { name, description, price, features, maxAssets, maxUsers, toolIds, isActive } = req.body;
  const updates: Record<string, unknown> = {};
  if (name !== undefined) updates.name = name;
  if (description !== undefined) updates.description = description;
  if (price !== undefined) updates.price = String(price);
  if (features !== undefined) updates.features = features;
  if (maxAssets !== undefined) updates.maxAssets = maxAssets;
  if (maxUsers !== undefined) updates.maxUsers = maxUsers;
  if (toolIds !== undefined) updates.toolIds = toolIds;
  if (isActive !== undefined) updates.isActive = isActive;
  const [pkg] = await db.update(packagesTable).set(updates as any).where(eq(packagesTable.id, packageId)).returning();
  if (!pkg) { res.status(404).json({ error: "Package not found" }); return; }
  res.json(toPackageResponse(pkg));
});

router.delete("/packages/:packageId", requireAuth, requireRole("super_admin"), async (req, res): Promise<void> => {
  const packageId = Number(req.params.packageId);
  if (!packageId) { res.status(400).json({ error: "Invalid ID" }); return; }
  await db.delete(packagesTable).where(eq(packagesTable.id, packageId));
  res.sendStatus(204);
});

router.post("/packages/:packageId/assign", requireAuth, requireRole("super_admin"), async (req, res): Promise<void> => {
  const packageId = Number(req.params.packageId);
  const { tenantId, expiresAt } = req.body;
  if (!tenantId) { res.status(400).json({ error: "tenantId is required" }); return; }
  await db.delete(tenantPackagesTable).where(eq(tenantPackagesTable.tenantId, Number(tenantId)));
  const [tp] = await db.insert(tenantPackagesTable).values({
    tenantId: Number(tenantId),
    packageId,
    expiresAt: expiresAt ? new Date(expiresAt) : undefined,
  }).returning();
  res.status(201).json(tp);
});

router.get("/tenants/:tenantId/package", requireAuth, async (req, res): Promise<void> => {
  const tenantId = Number(req.params.tenantId);
  const rows = await db.select({ tp: tenantPackagesTable, pkg: packagesTable })
    .from(tenantPackagesTable)
    .leftJoin(packagesTable, eq(tenantPackagesTable.packageId, packagesTable.id))
    .where(eq(tenantPackagesTable.tenantId, tenantId));
  const row = rows[0];
  if (!row?.pkg) { res.json(null); return; }
  res.json({
    ...toPackageResponse(row.pkg),
    assignedAt: row.tp.assignedAt?.toISOString() ?? null,
    expiresAt: row.tp.expiresAt?.toISOString() ?? null,
  });
});

export default router;
