import { Router } from "express";
import { eq, inArray, and, or, isNull } from "drizzle-orm";
import {
  db, tenantsTable, usersTable, assetsTable, findingsTable, findingCommentsTable,
  accountManagerClientsTable, scanAssetResultsTable, assetGroupMembersTable,
  riskScoresTable, discoveryResultsTable,
} from "@workspace/db";
import { CreateTenantBody, UpdateTenantBody, GetTenantParams, UpdateTenantParams } from "@workspace/api-zod";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";

/** Cascade-delete an asset and all child records that would violate FK constraints. */
async function cascadeDeleteAsset(assetId: number, tenantId: number) {
  // 1. Delete finding comments for findings on this asset
  const assetFindings = await db.select({ id: findingsTable.id })
    .from(findingsTable)
    .where(and(eq(findingsTable.assetId, assetId), eq(findingsTable.tenantId, tenantId)));
  if (assetFindings.length > 0) {
    const fids = assetFindings.map(f => f.id);
    await db.delete(findingCommentsTable).where(inArray(findingCommentsTable.findingId, fids));
    await db.delete(findingsTable).where(inArray(findingsTable.id, fids));
  }
  // 2. Delete scan asset results
  await db.delete(scanAssetResultsTable).where(eq(scanAssetResultsTable.assetId, assetId));
  // 3. Remove from asset groups
  await db.delete(assetGroupMembersTable).where(eq(assetGroupMembersTable.assetId, assetId));
  // 4. Delete risk score
  await db.delete(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
  // 5. Delete discovery results
  await db.delete(discoveryResultsTable).where(eq(discoveryResultsTable.assetId, assetId));
  // 6. Delete asset (screenshots + technology_detections cascade automatically via DB)
  await db.delete(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId)));
}

/** Same but for a whole tenant — called during tenant deletion. */
async function cascadeDeleteTenantAssets(tenantId: number) {
  const tenantAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
    .where(eq(assetsTable.tenantId, tenantId));
  if (tenantAssets.length === 0) return;
  const aids = tenantAssets.map(a => a.id);
  const tenantFindings = await db.select({ id: findingsTable.id }).from(findingsTable)
    .where(eq(findingsTable.tenantId, tenantId));
  if (tenantFindings.length > 0) {
    const fids = tenantFindings.map(f => f.id);
    await db.delete(findingCommentsTable).where(inArray(findingCommentsTable.findingId, fids));
    await db.delete(findingsTable).where(eq(findingsTable.tenantId, tenantId));
  }
  await db.delete(scanAssetResultsTable).where(inArray(scanAssetResultsTable.assetId, aids));
  await db.delete(assetGroupMembersTable).where(inArray(assetGroupMembersTable.assetId, aids));
  await db.delete(riskScoresTable).where(inArray(riskScoresTable.assetId, aids));
  await db.delete(discoveryResultsTable).where(inArray(discoveryResultsTable.assetId, aids));
  await db.delete(assetsTable).where(eq(assetsTable.tenantId, tenantId));
}

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

// ── Pool: all assets across every tenant the caller manages + unassigned ones ─
// MUST be registered before /tenants/:tenantId to avoid the param shadowing "assets".
router.get("/tenants/assets/pool", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  const myTenantId = req.user!.tenantId;

  let tenantIds: number[];
  if (role === "super_admin") {
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
    tenantIds = rows.map(r => r.id);
  } else {
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable)
      .where(and(eq(tenantsTable.isPlatform, false),
        or(eq(tenantsTable.id, myTenantId), eq(tenantsTable.parentTenantId, myTenantId))));
    tenantIds = rows.map(r => r.id);
  }

  // Fetch assigned assets (belonging to managed tenants) AND unassigned assets (tenantId IS NULL)
  const assetWhere = tenantIds.length > 0
    ? or(inArray(assetsTable.tenantId, tenantIds), isNull(assetsTable.tenantId))
    : isNull(assetsTable.tenantId);

  const [assets, tenants] = await Promise.all([
    db.select().from(assetsTable).where(assetWhere),
    tenantIds.length > 0
      ? db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable)
          .where(inArray(tenantsTable.id, tenantIds))
      : Promise.resolve([] as { id: number; name: string }[]),
  ]);

  const nameMap = new Map(tenants.map(t => [t.id, t.name]));
  res.json(assets.map(a => ({
    id: a.id, name: a.name, type: a.type, value: a.value,
    tenantId: a.tenantId ?? null,
    tenantName: a.tenantId != null ? (nameMap.get(a.tenantId) ?? "Unknown") : null,
    verificationStatus: a.verificationStatus, riskLevel: a.riskLevel,
    businessImpact: a.businessImpact, scanFrequency: a.scanFrequency,
    lastScannedAt: a.lastScannedAt?.toISOString() ?? null, isActive: a.isActive,
  })));
});

// ── Bulk-move (reassign) assets to a target tenant ────────────────────────────
router.post("/tenants/:tenantId/assets/assign", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const targetTenantId = Number(req.params.tenantId);
  if (isNaN(targetTenantId)) { res.status(400).json({ error: "Invalid tenantId" }); return; }

  const { assetIds } = req.body ?? {};
  if (!Array.isArray(assetIds) || assetIds.length === 0) {
    res.status(400).json({ error: "assetIds must be a non-empty array" }); return;
  }
  const ids = (assetIds as unknown[]).map(Number).filter(n => !isNaN(n));
  if (ids.length === 0) { res.status(400).json({ error: "No valid asset IDs" }); return; }

  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, targetTenantId))) {
    res.status(403).json({ error: "Forbidden: cannot access target tenant" }); return;
  }

  const [targetTenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, targetTenantId));
  if (!targetTenant) { res.status(404).json({ error: "Target tenant not found" }); return; }

  // For admin: verify they own the source tenant of every asset that has one.
  // Unassigned assets (tenantId IS NULL) can be assigned by any admin.
  if (req.user!.role === "admin") {
    const sourceAssets = await db.select({ id: assetsTable.id, tenantId: assetsTable.tenantId })
      .from(assetsTable).where(inArray(assetsTable.id, ids));
    const sourceTenantIds = [...new Set(sourceAssets.map(a => a.tenantId).filter((t): t is number => t != null))];
    for (const srcTid of sourceTenantIds) {
      if (!(await adminCanAccessTenant(req.user!.tenantId, srcTid))) {
        res.status(403).json({ error: `Forbidden: cannot move assets from tenant ${srcTid}` }); return;
      }
    }
  }

  const updated = await db.update(assetsTable)
    .set({ tenantId: targetTenantId })
    .where(inArray(assetsTable.id, ids))
    .returning({ id: assetsTable.id, tenantId: assetsTable.tenantId });

  res.json({ moved: updated.length, targetTenantId, assetIds: updated.map(a => a.id) });
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

// ── Remove asset from tenant (unassign only — asset is NOT deleted) ───────────
// Moves the asset back to the caller's own tenant so it can be re-assigned later.
router.post("/tenants/:tenantId/assets/:assetId/unassign", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  const aid = Number(req.params.assetId);
  if (isNaN(tid) || isNaN(aid)) { res.status(400).json({ error: "Invalid IDs" }); return; }

  // Admins can only manage their own child tenants
  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tid))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  // Verify asset belongs to the target tenant
  const [asset] = await db.select({ id: assetsTable.id, tenantId: assetsTable.tenantId })
    .from(assetsTable).where(and(eq(assetsTable.id, aid), eq(assetsTable.tenantId, tid)));
  if (!asset) { res.status(404).json({ error: "Asset not found in this tenant" }); return; }

  // Set tenantId = null — asset is now free/unassigned until explicitly re-assigned
  await db.update(assetsTable)
    .set({ tenantId: null })
    .where(eq(assetsTable.id, aid));

  res.json({ id: aid, unassigned: true });
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

  // Cascade: delete all asset child records, then assets, users, tenant
  await cascadeDeleteTenantAssets(tid);
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
