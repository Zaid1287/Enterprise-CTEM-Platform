import { Router } from "express";
import { eq, inArray, and } from "drizzle-orm";
import { db, accountManagerClientsTable, tenantsTable, assetsTable, findingsTable, scansTable, usersTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

// Returns the account manager(s) assigned to the caller's tenant.
// Merges two sources:
//   1. account_manager_clients — tenant-level AM assignments
//   2. assets.assigned_account_manager_id — asset-level AM assignments
router.get("/account-manager/my-manager", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;

  // Source 1: tenant-level assignments
  const tenantAssignments = await db
    .select({ accountManagerUserId: accountManagerClientsTable.accountManagerUserId, assignedAt: accountManagerClientsTable.assignedAt })
    .from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.clientTenantId, tenantId));

  // Source 2: asset-level assignments — distinct AM user IDs from assets in this tenant
  const assetAssignments = await db
    .selectDistinct({ accountManagerUserId: assetsTable.assignedAccountManagerId })
    .from(assetsTable)
    .where(eq(assetsTable.tenantId, tenantId));

  // Merge and deduplicate AM user IDs
  const amUserIdSet = new Set<number>();
  for (const a of tenantAssignments) amUserIdSet.add(a.accountManagerUserId);
  for (const a of assetAssignments) {
    if (a.accountManagerUserId != null) amUserIdSet.add(a.accountManagerUserId);
  }

  if (amUserIdSet.size === 0) {
    res.json([]);
    return;
  }

  const amUserIds = Array.from(amUserIdSet);
  const amUsers = await db
    .select({
      id: usersTable.id,
      firstName: usersTable.firstName,
      lastName: usersTable.lastName,
      email: usersTable.email,
      role: usersTable.role,
      avatarUrl: usersTable.avatarUrl,
      isActive: usersTable.isActive,
    })
    .from(usersTable)
    .where(inArray(usersTable.id, amUserIds));

  // Attach earliest assignedAt from tenant-level assignments when available
  const result = amUsers.map(u => ({
    ...u,
    assignedAt: tenantAssignments.find(a => a.accountManagerUserId === u.id)?.assignedAt?.toISOString() ?? null,
  }));

  res.json(result);
});

// Returns tenants that CAN be assigned to this AM — not already assigned + not the AM's own tenant
router.get("/account-manager/available-tenants", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId, tenantId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin" && role !== "admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const targetUserId = (role === "super_admin" || role === "admin") && req.query.userId
    ? Number(req.query.userId)
    : userId;
  const existing = await db.select({ clientTenantId: accountManagerClientsTable.clientTenantId })
    .from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.accountManagerUserId, targetUserId));
  const existingIds = existing.map(e => e.clientTenantId);
  const allTenants = await db.select({ id: tenantsTable.id, name: tenantsTable.name, plan: tenantsTable.plan, isActive: tenantsTable.isActive })
    .from(tenantsTable);
  const available = allTenants.filter(t =>
    t.id !== tenantId &&
    !existingIds.includes(t.id)
  );
  res.json(available);
});

router.get("/account-manager/clients", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const targetUserId = role === "super_admin" && req.query.userId
    ? Number(req.query.userId)
    : userId;

  const assignments = await db.select().from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.accountManagerUserId, targetUserId));

  if (assignments.length === 0) { res.json([]); return; }

  const clientTenantIds = assignments.map(a => a.clientTenantId);

  // Step 1: fetch clients + assets (needed to resolve asset IDs before querying findings/scans)
  const [clients, allAssets] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, clientTenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, clientTenantIds)),
  ]);

  const allAssetIds = allAssets.map(a => a.id);
  const assetIdSet = new Set(allAssetIds);

  // Step 2: fetch findings by assetId; scans scoped to client tenantIds (no full-table scan)
  const [allFindings, allScans] = await (allAssetIds.length > 0
    ? Promise.all([
        db.select().from(findingsTable).where(inArray(findingsTable.assetId, allAssetIds)),
        db.select().from(scansTable).where(inArray(scansTable.tenantId, clientTenantIds)),
      ])
    : Promise.resolve([[], []] as [typeof findingsTable.$inferSelect[], typeof scansTable.$inferSelect[]]));

  const result = clients.map(t => {
    const clientAssets = allAssets.filter(a => a.tenantId === t.id);
    const clientAssetIds = clientAssets.map(a => a.id);
    const clientFindings = allFindings.filter(f => clientAssetIds.includes(f.assetId));
    return {
      tenantId: t.id,
      tenantName: t.name,
      plan: t.plan,
      isActive: t.isActive,
      assetCount: clientAssets.length,
      findingCount: clientFindings.length,
      criticalCount: clientFindings.filter(f => f.severity === "critical").length,
      openFindingCount: clientFindings.filter(f => f.status === "open").length,
      activeScans: allScans.filter(s =>
        (s.status === "running" || s.status === "pending") &&
        Array.isArray(s.assetIds) && (s.assetIds as number[]).some(id => clientAssetIds.includes(id))
      ).length,
      assignedAt: assignments.find(a => a.clientTenantId === t.id)?.assignedAt?.toISOString() ?? null,
      createdAt: t.createdAt.toISOString(),
    };
  });

  res.json(result);
});

router.post("/account-manager/clients", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const { clientTenantId, accountManagerUserId } = req.body;
  const amUserId = (role === "super_admin" && accountManagerUserId) ? Number(accountManagerUserId) : userId;
  if (!clientTenantId) { res.status(400).json({ error: "clientTenantId is required" }); return; }

  const existing = await db.select().from(accountManagerClientsTable)
    .where(and(
      eq(accountManagerClientsTable.accountManagerUserId, amUserId),
      eq(accountManagerClientsTable.clientTenantId, Number(clientTenantId))
    ));
  if (existing.length > 0) { res.status(409).json({ error: "Already assigned" }); return; }

  const [assignment] = await db.insert(accountManagerClientsTable).values({
    accountManagerUserId: amUserId,
    clientTenantId: Number(clientTenantId),
  }).returning();
  res.status(201).json(assignment);
});

router.delete("/account-manager/clients/:clientTenantId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "account_manager" && role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  const clientTenantId = Number(req.params.clientTenantId);
  const amUserId = role === "super_admin" && req.query.amUserId
    ? Number(req.query.amUserId)
    : userId;
  await db.delete(accountManagerClientsTable)
    .where(and(
      eq(accountManagerClientsTable.accountManagerUserId, amUserId),
      eq(accountManagerClientsTable.clientTenantId, clientTenantId)
    ));
  res.sendStatus(204);
});

export default router;
