import { Router } from "express";
import { eq, inArray, and } from "drizzle-orm";
import { db, tenantsTable, usersTable, assetsTable, findingsTable, accountManagerClientsTable } from "@workspace/db";
import { CreateTenantBody, UpdateTenantBody, GetTenantParams, UpdateTenantParams } from "@workspace/api-zod";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

function toTenantResponse(t: typeof tenantsTable.$inferSelect) {
  return {
    id: t.id, name: t.name, slug: t.slug, plan: t.plan, isActive: t.isActive,
    isPlatform: t.isPlatform, maxAssets: t.maxAssets, maxUsers: t.maxUsers,
    createdAt: t.createdAt.toISOString(),
  };
}

router.get("/tenants", requireAuth, requireRole("super_admin"), async (_req, res): Promise<void> => {
  const tenants = await db.select().from(tenantsTable)
    .where(eq(tenantsTable.isPlatform, false))
    .orderBy(tenantsTable.createdAt);

  const tenantIds = tenants.map(t => t.id);
  if (tenantIds.length === 0) { res.json([]); return; }

  const [allUsers, allAssets, allFindings, allAssignments] = await Promise.all([
    db.select().from(usersTable).where(inArray(usersTable.tenantId, tenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, tenantIds)),
    db.select().from(findingsTable).where(inArray(findingsTable.tenantId, tenantIds)),
    db.select().from(accountManagerClientsTable).where(inArray(accountManagerClientsTable.clientTenantId, tenantIds)),
  ]);

  const amUserIds = [...new Set(allAssignments.map(a => a.accountManagerUserId))];
  const amUsers = amUserIds.length > 0
    ? await db.select({ id: usersTable.id, email: usersTable.email, firstName: usersTable.firstName, lastName: usersTable.lastName })
        .from(usersTable).where(inArray(usersTable.id, amUserIds))
    : [];

  res.json(tenants.map(t => ({
    ...toTenantResponse(t),
    userCount: allUsers.filter(u => u.tenantId === t.id).length,
    assetCount: allAssets.filter(a => a.tenantId === t.id).length,
    findingCount: allFindings.filter(f => f.tenantId === t.id).length,
    criticalCount: allFindings.filter(f => f.tenantId === t.id && f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.tenantId === t.id && f.status === "open").length,
    assignedManagers: allAssignments
      .filter(a => a.clientTenantId === t.id)
      .map(a => {
        const u = amUsers.find(m => m.id === a.accountManagerUserId);
        return u ? { id: u.id, name: `${u.firstName} ${u.lastName}`, email: u.email } : null;
      }).filter(Boolean),
  })));
});

router.post("/tenants", requireAuth, requireRole("super_admin"), async (req, res): Promise<void> => {
  const parsed = CreateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [tenant] = await db.insert(tenantsTable).values({ ...parsed.data, isPlatform: false }).returning();
  res.status(201).json(toTenantResponse(tenant));
});

router.get("/tenants/:tenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;
  if (role !== "super_admin" && req.user!.tenantId !== params.data.tenantId) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, params.data.tenantId));
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  res.json(toTenantResponse(tenant));
});

// ── Assign an account manager to a tenant ────────────────────────────────────
router.post("/tenants/:tenantId/managers", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = Number(req.params.tenantId);
  const amUserId = Number(req.body?.accountManagerUserId);
  if (isNaN(tenantId) || isNaN(amUserId)) { res.status(400).json({ error: "tenantId and accountManagerUserId required" }); return; }

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tenantId));
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }

  const [amUser] = await db.select().from(usersTable)
    .where(and(eq(usersTable.id, amUserId), eq(usersTable.role, "account_manager")));
  if (!amUser) { res.status(404).json({ error: "Account manager not found" }); return; }

  const existing = await db.select().from(accountManagerClientsTable)
    .where(and(eq(accountManagerClientsTable.accountManagerUserId, amUserId), eq(accountManagerClientsTable.clientTenantId, tenantId)));
  if (existing.length > 0) { res.status(409).json({ error: "Already assigned" }); return; }

  const [row] = await db.insert(accountManagerClientsTable)
    .values({ accountManagerUserId: amUserId, clientTenantId: tenantId }).returning();
  res.status(201).json(row);
});

// ── Unassign an account manager from a tenant ─────────────────────────────────
router.delete("/tenants/:tenantId/managers/:amUserId", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = Number(req.params.tenantId);
  const amUserId = Number(req.params.amUserId);
  if (isNaN(tenantId) || isNaN(amUserId)) { res.status(400).json({ error: "Invalid IDs" }); return; }
  await db.delete(accountManagerClientsTable)
    .where(and(eq(accountManagerClientsTable.accountManagerUserId, amUserId), eq(accountManagerClientsTable.clientTenantId, tenantId)));
  res.sendStatus(204);
});

router.patch("/tenants/:tenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const role = req.user!.role;
  if (role !== "super_admin" && req.user!.tenantId !== params.data.tenantId) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const [tenant] = await db.update(tenantsTable).set(parsed.data)
    .where(eq(tenantsTable.id, params.data.tenantId)).returning();
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  res.json(toTenantResponse(tenant));
});

export default router;
