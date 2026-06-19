import { Router } from "express";
import { eq, inArray, and, or } from "drizzle-orm";
import { db, tenantsTable, usersTable, assetsTable, findingsTable, accountManagerClientsTable } from "@workspace/db";
import { CreateTenantBody, UpdateTenantBody, GetTenantParams, UpdateTenantParams } from "@workspace/api-zod";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

function toTenantResponse(t: typeof tenantsTable.$inferSelect) {
  return {
    id: t.id, name: t.name, slug: t.slug, plan: t.plan, isActive: t.isActive,
    isPlatform: t.isPlatform, parentTenantId: t.parentTenantId,
    maxAssets: t.maxAssets, maxUsers: t.maxUsers,
    createdAt: t.createdAt.toISOString(),
  };
}

async function buildRichTenantList(tenantIds: number[]) {
  if (tenantIds.length === 0) return [];
  const [allTenants, allUsers, allAssets, allFindings, allAssignments] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, tenantIds)),
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
  return allTenants.map(t => ({
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
        return u ? { id: u.id, name: `${u.firstName ?? ""} ${u.lastName ?? ""}`.trim() || u.email, email: u.email } : null;
      }).filter(Boolean),
  }));
}

/**
 * Check whether an admin can access a given target tenant.
 * Admins can access: (1) their own tenant, (2) any tenant they created (parentTenantId = admin's tenantId).
 */
async function adminCanAccessTenant(adminTenantId: number, targetTenantId: number): Promise<boolean> {
  if (adminTenantId === targetTenantId) return true;
  const [row] = await db.select({ id: tenantsTable.id })
    .from(tenantsTable)
    .where(and(eq(tenantsTable.id, targetTenantId), eq(tenantsTable.parentTenantId, adminTenantId)));
  return !!row;
}

// ── List tenants ──────────────────────────────────────────────────────────────
// Super admin: all client tenants. Admin: own tenant + all child tenants they created.
router.get("/tenants", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  const myTenantId = req.user!.tenantId;

  if (role === "super_admin") {
    const tenants = await db.select().from(tenantsTable)
      .where(eq(tenantsTable.isPlatform, false))
      .orderBy(tenantsTable.createdAt);
    const result = await buildRichTenantList(tenants.map(t => t.id));
    res.json(result); return;
  }

  // Admin: own tenant + any tenant with parentTenantId = myTenantId
  const tenants = await db.select().from(tenantsTable)
    .where(
      and(
        eq(tenantsTable.isPlatform, false),
        or(eq(tenantsTable.id, myTenantId), eq(tenantsTable.parentTenantId, myTenantId)),
      ),
    )
    .orderBy(tenantsTable.createdAt);
  const result = await buildRichTenantList(tenants.map(t => t.id));
  res.json(result);
});

// ── Create tenant ─────────────────────────────────────────────────────────────
router.post("/tenants", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  // Admins automatically become the parent of tenants they create
  const parentTenantId = req.user!.role === "admin" ? req.user!.tenantId : undefined;

  const [tenant] = await db.insert(tenantsTable)
    .values({ ...parsed.data, isPlatform: false, parentTenantId: parentTenantId ?? null })
    .returning();
  res.status(201).json(toTenantResponse(tenant));
});

// ── Get single tenant ─────────────────────────────────────────────────────────
router.get("/tenants/:tenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;
  if (role !== "super_admin" && !(await adminCanAccessTenant(req.user!.tenantId, params.data.tenantId))) {
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

  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tenantId))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }

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
  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tenantId))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  await db.delete(accountManagerClientsTable)
    .where(and(eq(accountManagerClientsTable.accountManagerUserId, amUserId), eq(accountManagerClientsTable.clientTenantId, tenantId)));
  res.sendStatus(204);
});

// ── Assets for a specific tenant (cross-tenant management) ───────────────────
router.get("/tenants/:tenantId/assets", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  if (isNaN(tid)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tid))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const assets = await db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid));
  res.json(assets.map(a => ({
    id: a.id, name: a.name, type: a.type, value: a.value,
    verificationStatus: a.verificationStatus, isActive: a.isActive,
    scanFrequency: a.scanFrequency, businessImpact: a.businessImpact,
    riskLevel: a.riskLevel, lastScannedAt: a.lastScannedAt,
  })));
});

router.post("/tenants/:tenantId/assets", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  if (isNaN(tid)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tid))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const { name, type, value, scanFrequency, businessImpact, description } = req.body ?? {};
  if (!name || !type || !value) { res.status(400).json({ error: "name, type and value are required" }); return; }

  const [asset] = await db.insert(assetsTable).values({
    tenantId: tid,
    name: String(name),
    type: String(type),
    value: String(value).trim().toLowerCase(),
    verificationStatus: "unverified",
    isActive: true,
    scanFrequency: scanFrequency ?? "manual",
    businessImpact: businessImpact ?? 5,
    description: description ?? null,
    riskLevel: "info",
  }).returning();
  res.status(201).json(asset);
});

router.delete("/tenants/:tenantId/assets/:assetId", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  const aid = Number(req.params.assetId);
  if (isNaN(tid) || isNaN(aid)) { res.status(400).json({ error: "Invalid IDs" }); return; }
  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tid))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  await db.delete(assetsTable).where(and(eq(assetsTable.id, aid), eq(assetsTable.tenantId, tid)));
  res.sendStatus(204);
});

// ── Delete tenant ─────────────────────────────────────────────────────────────
// Super admin: any non-platform tenant. Admin: only their child tenants (not their own).
router.delete("/tenants/:tenantId", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  if (isNaN(tid)) { res.status(400).json({ error: "Invalid tenantId" }); return; }

  if (req.user!.role === "admin") {
    if (tid === req.user!.tenantId) { res.status(403).json({ error: "Cannot delete your own tenant" }); return; }
    if (!(await adminCanAccessTenant(req.user!.tenantId, tid))) {
      res.status(403).json({ error: "Forbidden" }); return;
    }
  }

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tid));
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  if (tenant.isPlatform) { res.status(403).json({ error: "Cannot delete platform tenant" }); return; }

  // Cascade: delete assets, users, findings, etc. belonging to this tenant
  await db.delete(assetsTable).where(eq(assetsTable.tenantId, tid));
  await db.delete(usersTable).where(eq(usersTable.tenantId, tid));
  await db.delete(tenantsTable).where(eq(tenantsTable.id, tid));
  res.sendStatus(204);
});

// ── Update tenant ─────────────────────────────────────────────────────────────
router.patch("/tenants/:tenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateTenantParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateTenantBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const role = req.user!.role;
  if (role !== "super_admin" && !(await adminCanAccessTenant(req.user!.tenantId, params.data.tenantId))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const [tenant] = await db.update(tenantsTable).set(parsed.data)
    .where(eq(tenantsTable.id, params.data.tenantId)).returning();
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }
  res.json(toTenantResponse(tenant));
});

export default router;
