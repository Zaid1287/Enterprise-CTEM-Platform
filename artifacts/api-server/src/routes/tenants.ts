import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, tenantsTable } from "@workspace/db";
import { CreateTenantBody, UpdateTenantBody, GetTenantParams, UpdateTenantParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/tenants", requireAuth, async (_req, res): Promise<void> => {
  const tenants = await db.select().from(tenantsTable).orderBy(tenantsTable.createdAt);
  res.json(tenants.map(t => ({
    id: t.id, name: t.name, slug: t.slug, plan: t.plan, isActive: t.isActive,
    maxAssets: t.maxAssets, maxUsers: t.maxUsers, createdAt: t.createdAt.toISOString(),
  })));
});

router.post("/tenants", requireAuth, async (req, res): Promise<void> => {
  const parsed = CreateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [tenant] = await db.insert(tenantsTable).values(parsed.data).returning();
  res.status(201).json({ ...tenant, createdAt: tenant.createdAt.toISOString() });
});

router.get("/tenants/:tenantId", requireAuth, async (req, res): Promise<void> => {
  const params = GetTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, params.data.tenantId));
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  res.json({ ...tenant, createdAt: tenant.createdAt.toISOString() });
});

router.patch("/tenants/:tenantId", requireAuth, async (req, res): Promise<void> => {
  const params = UpdateTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [tenant] = await db.update(tenantsTable).set(parsed.data).where(eq(tenantsTable.id, params.data.tenantId)).returning();
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  res.json({ ...tenant, createdAt: tenant.createdAt.toISOString() });
});

export default router;
