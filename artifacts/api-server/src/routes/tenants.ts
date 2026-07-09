import { Router } from "express";
import { eq, inArray, and, or, isNull } from "drizzle-orm";
import {
  db, tenantsTable, usersTable, assetsTable, findingsTable, findingCommentsTable,
  accountManagerClientsTable, scanAssetResultsTable, assetGroupMembersTable, assetGroupsTable,
  riskScoresTable, discoveryResultsTable, scansTable, scanJobsTable, scanSchedulesTable,
  alertsTable, alertRulesTable, brandThreatScansTable, brandThreatResultsTable,
  brandWatchlistItemsTable, takedownRequestsTable, securityToolsTable, toolPipelineStepsTable,
  toolRunsTable, complianceControlsTable, complianceFrameworksTable, platformSettingsTable,
  invitationsTable, sessionsTable, screenshotsTable, technologyDetectionsTable,
  auditLogsTable, reportsTable, userAiSettingsTable,
  dataLeakResultsTable, phishingDetectionsTable, brandAbuseResultsTable, adMonitoringResultsTable,
  aiMapperModuleAssignmentsTable, scanSuppressionsTable, packagesTable, tenantPackagesTable,
  orchestratorConfigTable, scanRequestTelemetryTable,
} from "@workspace/db";
import { CreateTenantBody, UpdateTenantBody, GetTenantParams, UpdateTenantParams } from "@workspace/api-zod";
import { requireAuth, requireRole, hashPassword, type AuthenticatedRequest } from "../lib/auth";
import { getAmClientTenantIds } from "../lib/amScoping";
import { seedNewTenantData } from "./auth";
import crypto from "crypto";

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

/** Complete cascade delete for an entire tenant — deletes ALL related records in FK-safe order. */
export async function cascadeDeleteTenant(tenantId: number) {
  // 1. Tool runs (reference scans, assets, security_tools)
  await db.delete(toolRunsTable).where(eq(toolRunsTable.tenantId, tenantId));

  // 2. Scan children — scan_jobs has no tenantId, delete via scanId
  const tenantScans = await db.select({ id: scansTable.id })
    .from(scansTable).where(eq(scansTable.tenantId, tenantId));
  if (tenantScans.length > 0) {
    const scanIds = tenantScans.map(s => s.id);
    await db.delete(scanJobsTable).where(inArray(scanJobsTable.scanId, scanIds));
  }
  await db.delete(scanAssetResultsTable).where(eq(scanAssetResultsTable.tenantId, tenantId));
  await db.delete(scanSchedulesTable).where(eq(scanSchedulesTable.tenantId, tenantId));

  // 3. Finding comments, then findings
  const tenantFindings = await db.select({ id: findingsTable.id })
    .from(findingsTable).where(eq(findingsTable.tenantId, tenantId));
  if (tenantFindings.length > 0) {
    const fids = tenantFindings.map(f => f.id);
    await db.delete(findingCommentsTable).where(inArray(findingCommentsTable.findingId, fids));
  }
  await db.delete(findingsTable).where(eq(findingsTable.tenantId, tenantId));

  // 4. Scans
  await db.delete(scansTable).where(eq(scansTable.tenantId, tenantId));

  // 5. Takedown requests (reference brand_threat_results)
  await db.delete(takedownRequestsTable).where(eq(takedownRequestsTable.tenantId, tenantId));

  // 6. Brand threat child records, then scans and watchlist
  const btScans = await db.select({ id: brandThreatScansTable.id })
    .from(brandThreatScansTable).where(eq(brandThreatScansTable.tenantId, tenantId));
  if (btScans.length > 0) {
    const btIds = btScans.map(s => s.id);
    await db.delete(brandThreatResultsTable).where(inArray(brandThreatResultsTable.scanId, btIds));
  }
  await db.delete(brandThreatScansTable).where(eq(brandThreatScansTable.tenantId, tenantId));
  await db.delete(brandWatchlistItemsTable).where(eq(brandWatchlistItemsTable.tenantId, tenantId));

  // 6b. Other brand-threat derivative tables (all tenant-scoped)
  await db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.tenantId, tenantId));
  await db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.tenantId, tenantId));
  await db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.tenantId, tenantId));
  await db.delete(adMonitoringResultsTable).where(eq(adMonitoringResultsTable.tenantId, tenantId));

  // 7. Asset-level child records
  const tenantAssets = await db.select({ id: assetsTable.id })
    .from(assetsTable).where(eq(assetsTable.tenantId, tenantId));
  if (tenantAssets.length > 0) {
    const aids = tenantAssets.map(a => a.id);
    await db.delete(screenshotsTable).where(inArray(screenshotsTable.assetId, aids));
    await db.delete(technologyDetectionsTable).where(inArray(technologyDetectionsTable.assetId, aids));
    await db.delete(riskScoresTable).where(inArray(riskScoresTable.assetId, aids));
    await db.delete(discoveryResultsTable).where(inArray(discoveryResultsTable.assetId, aids));
    await db.delete(assetGroupMembersTable).where(inArray(assetGroupMembersTable.assetId, aids));
    await db.delete(scanAssetResultsTable).where(inArray(scanAssetResultsTable.assetId, aids));
  }
  await db.delete(assetsTable).where(eq(assetsTable.tenantId, tenantId));

  // 7b. Asset groups (members deleted above; groups themselves have tenantId FK without cascade)
  await db.delete(assetGroupsTable).where(eq(assetGroupsTable.tenantId, tenantId));

  // 8. Alerts and alert rules
  await db.delete(alertsTable).where(eq(alertsTable.tenantId, tenantId));
  await db.delete(alertRulesTable).where(eq(alertRulesTable.tenantId, tenantId));

  // 9. Compliance controls (frameworks are shared, not tenant-scoped — skip)
  await db.delete(complianceControlsTable).where(eq(complianceControlsTable.tenantId, tenantId));

  // 10. Reports
  await db.delete(reportsTable).where(eq(reportsTable.tenantId, tenantId));

  // 11. Security tools and pipeline
  await db.delete(toolPipelineStepsTable).where(eq(toolPipelineStepsTable.tenantId, tenantId));
  await db.delete(securityToolsTable).where(eq(securityToolsTable.tenantId, tenantId));

  // 11b. Orchestrator config (seeded by seedNewTenantData; has tenantId FK without cascade)
  await db.delete(orchestratorConfigTable).where(eq(orchestratorConfigTable.tenantId, tenantId));

  // 11c. Scan suppressions and tenant package assignments (tenant-scoped; no DB cascade)
  // Note: packagesTable is a global catalog (no tenantId) — not deleted here.
  await db.delete(scanSuppressionsTable).where(eq(scanSuppressionsTable.tenantId, tenantId));
  await db.delete(tenantPackagesTable).where(eq(tenantPackagesTable.tenantId, tenantId));

  // 11d. Scan request telemetry (optional tenantId; clean up to avoid stale references)
  await db.delete(scanRequestTelemetryTable).where(eq(scanRequestTelemetryTable.tenantId, tenantId));

  // 11e. AI Mapper module assignment — FK has onDelete:cascade but that fires only when the
  //      tenant row is deleted. Delete explicitly so cascadeDeleteTenant is fully self-contained.
  await db.delete(aiMapperModuleAssignmentsTable).where(eq(aiMapperModuleAssignmentsTable.tenantId, tenantId));

  // 12. User AI settings — keyed by userId (no tenantId column)
  // platformSettingsTable is global (no tenantId column) — skip
  // userAiSettings are cleaned up when users are deleted below via cascade or here:
  const tenantUserIds = await db.select({ id: usersTable.id })
    .from(usersTable).where(eq(usersTable.tenantId, tenantId));
  if (tenantUserIds.length > 0) {
    await db.delete(userAiSettingsTable)
      .where(inArray(userAiSettingsTable.userId, tenantUserIds.map(u => u.id)));
  }

  // 13. Invitations
  await db.delete(invitationsTable).where(eq(invitationsTable.tenantId, tenantId));

  // 14. Account manager assignments (as client or as manager of this tenant's users)
  await db.delete(accountManagerClientsTable).where(eq(accountManagerClientsTable.clientTenantId, tenantId));

  // 15. Sessions and users
  const tenantUsers = await db.select({ id: usersTable.id })
    .from(usersTable).where(eq(usersTable.tenantId, tenantId));
  if (tenantUsers.length > 0) {
    const uids = tenantUsers.map(u => u.id);
    await db.delete(sessionsTable).where(inArray(sessionsTable.userId, uids));
    await db.delete(accountManagerClientsTable)
      .where(inArray(accountManagerClientsTable.accountManagerUserId, uids));
  }
  await db.delete(usersTable).where(eq(usersTable.tenantId, tenantId));

  // 16. Audit logs (last — immutability trigger only blocks UPDATE/DELETE by non-superuser at DB level)
  await db.delete(auditLogsTable).where(eq(auditLogsTable.tenantId, tenantId));
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
  const [allTenants, allUsers, allAssets, allAssignments] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, tenantIds)),
    db.select().from(usersTable).where(inArray(usersTable.tenantId, tenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, tenantIds)),
    db.select().from(accountManagerClientsTable).where(inArray(accountManagerClientsTable.clientTenantId, tenantIds)),
  ]);
  // Fetch findings by asset ID so scans run by the platform admin are correctly attributed
  // to the asset's owner tenant (not the scanner's tenantId)
  const allAssetIds = allAssets.map(a => a.id);
  const allFindings = allAssetIds.length > 0
    ? await db.select({ assetId: findingsTable.assetId, severity: findingsTable.severity, status: findingsTable.status })
        .from(findingsTable).where(inArray(findingsTable.assetId, allAssetIds))
    : [];
  const amUserIds = [...new Set(allAssignments.map(a => a.accountManagerUserId))];
  const amUsers = amUserIds.length > 0
    ? await db.select({ id: usersTable.id, email: usersTable.email, firstName: usersTable.firstName, lastName: usersTable.lastName })
        .from(usersTable).where(inArray(usersTable.id, amUserIds))
    : [];
  // assigned_client_id stores a USER ID (not a tenant ID). Build userId → tenantId map so
  // platform-owned assets (e.g. SA-scanned assets) are correctly attributed to their client tenant.
  const userTenantMap = new Map(allUsers.map(u => [u.id, u.tenantId]));
  return allTenants.map(t => {
    const tenantAssets = allAssets.filter(a =>
      a.tenantId === t.id ||
      (a.assignedClientId != null && userTenantMap.get(a.assignedClientId) === t.id)
    );
    const tenantAssetIdSet = new Set(tenantAssets.map(a => a.id));
    const tenantFindings = allFindings.filter(f => f.assetId != null && tenantAssetIdSet.has(f.assetId));
    return {
      ...toTenantResponse(t),
      userCount: allUsers.filter(u => u.tenantId === t.id).length,
      assetCount: tenantAssetIdSet.size,
      findingCount: tenantFindings.length,
      criticalCount: tenantFindings.filter(f => f.severity === "critical").length,
      openFindingCount: tenantFindings.filter(f => f.status === "open").length,
      assignedManagers: allAssignments
        .filter(a => a.clientTenantId === t.id)
        .map(a => {
          const u = amUsers.find(m => m.id === a.accountManagerUserId);
          return u ? { id: u.id, name: `${u.firstName ?? ""} ${u.lastName ?? ""}`.trim() || u.email, email: u.email } : null;
        }).filter(Boolean),
    };
  });
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
      .orderBy(tenantsTable.createdAt);
    const result = await buildRichTenantList(tenants.map(t => t.id));
    res.json(result); return;
  }

  // Admin: check if they belong to the platform tenant — if so, full SA-level view
  const [myTenantRow] = await db.select({ isPlatform: tenantsTable.isPlatform })
    .from(tenantsTable).where(eq(tenantsTable.id, myTenantId));

  if (myTenantRow?.isPlatform) {
    // Platform admins see ALL tenants exactly like super_admin
    const tenants = await db.select().from(tenantsTable).orderBy(tenantsTable.createdAt);
    const result = await buildRichTenantList(tenants.map(t => t.id));
    res.json(result); return;
  }

  // Non-platform admin: own tenant + any tenant with parentTenantId = myTenantId
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

  const { adminFirstName, adminLastName, adminEmail: adminEmailOverride } = req.body ?? {};

  const temporaryPassword = crypto.randomBytes(10).toString("base64url").slice(0, 14);
  const passwordHash = await hashPassword(temporaryPassword);

  // Validate required admin user fields
  const firstName = typeof adminFirstName === "string" && adminFirstName.trim() ? adminFirstName.trim() : null;
  const lastName  = typeof adminLastName  === "string" && adminLastName.trim()  ? adminLastName.trim()  : null;
  const adminEmail = typeof adminEmailOverride === "string" && adminEmailOverride.trim()
    ? adminEmailOverride.trim().toLowerCase()
    : null;

  if (!adminEmail) { res.status(400).json({ error: "adminEmail is required" }); return; }
  if (!firstName)  { res.status(400).json({ error: "adminFirstName is required" }); return; }
  if (!lastName)   { res.status(400).json({ error: "adminLastName is required" }); return; }

  // Check email uniqueness before starting transaction
  const [existingUser] = await db.select({ id: usersTable.id }).from(usersTable).where(eq(usersTable.email, adminEmail));
  if (existingUser) { res.status(409).json({ error: "A user with this email already exists" }); return; }

  // Step 1: Create the tenant + client user atomically.
  // Seeding is intentionally done AFTER commit so the tenant FK is visible
  // on the global connection pool used by seedNewTenantData.
  const { tenant, clientUser } = await db.transaction(async (tx) => {
    const [t] = await tx.insert(tenantsTable)
      .values({ ...parsed.data, isPlatform: false, parentTenantId: parentTenantId ?? null })
      .returning();

    const [u] = await tx.insert(usersTable).values({
      tenantId: t.id,
      email: adminEmail,
      passwordHash,
      firstName,
      lastName,
      role: "client",
      requiresPasswordReset: true,
    }).returning();

    return { tenant: t, clientUser: u };
  });

  // Step 2: Seed tools and frameworks now that the tenant row is committed and
  // visible to the global connection pool. Failure here rolls up to the caller.
  await seedNewTenantData(tenant.id);

  // Step 3: Explicitly set AI Mapper as disabled for this tenant (ensures a clear audit record).
  await db.insert(aiMapperModuleAssignmentsTable)
    .values({ tenantId: tenant.id, isEnabled: false, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoNothing();

  res.status(201).json({
    ...toTenantResponse(tenant),
    adminUser: {
      id: clientUser.id,
      email: clientUser.email,
      temporaryPassword,
      note: "Share these credentials with the tenant client. They will be required to set a new password on first login.",
    },
  });
});

// ── Pool: all assets across every tenant the caller manages + unassigned ones ─
// MUST be registered before /tenants/:tenantId to avoid the param shadowing "assets".
router.get("/tenants/assets/pool", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  const myTenantId = req.user!.tenantId;

  let tenantIds: number[];
  if (role === "super_admin") {
    // Super admin sees ALL tenants (platform + client) so every asset appears in the picker
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable);
    tenantIds = rows.map(r => r.id);
  } else {
    // Admin sees their own tenant + direct child tenants (no isPlatform filter — admins can
    // live on any tenant type and should see all assets they legitimately manage)
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable)
      .where(or(eq(tenantsTable.id, myTenantId), eq(tenantsTable.parentTenantId, myTenantId)));
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
    description: a.description ?? null,
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

// ── Reassign a client tenant to a different account manager (atomic replace) ──
// Removes ALL existing AM assignments for the tenant and adds the new one.
// If accountManagerUserId is null / omitted, all AMs are cleared (unassign all).
router.post("/tenants/:tenantId/assign-manager", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = Number(req.params.tenantId);
  if (isNaN(tenantId)) { res.status(400).json({ error: "Invalid tenantId" }); return; }

  if (req.user!.role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tenantId))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const [tenant] = await db.select().from(tenantsTable).where(eq(tenantsTable.id, tenantId));
  if (!tenant) { res.status(404).json({ error: "Tenant not found" }); return; }

  const rawAmUserId = req.body?.accountManagerUserId;
  const amUserId = rawAmUserId != null ? Number(rawAmUserId) : null;

  if (amUserId !== null) {
    const [amUser] = await db.select().from(usersTable)
      .where(and(eq(usersTable.id, amUserId), eq(usersTable.role, "account_manager")));
    if (!amUser) { res.status(404).json({ error: "Account manager not found" }); return; }
  }

  // Atomically: delete all existing assignments for this client tenant, then insert the new one.
  await db.delete(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.clientTenantId, tenantId));

  if (amUserId !== null) {
    await db.insert(accountManagerClientsTable)
      .values({ accountManagerUserId: amUserId, clientTenantId: tenantId });
    res.json({ tenantId, accountManagerUserId: amUserId, reassigned: true });
  } else {
    res.json({ tenantId, accountManagerUserId: null, reassigned: true, cleared: true });
  }
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
router.get("/tenants/:tenantId/assets", requireAuth, requireRole("super_admin", "admin", "account_manager"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = Number(req.params.tenantId);
  if (isNaN(tid)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  const role = req.user!.role;
  if (role === "admin" && !(await adminCanAccessTenant(req.user!.tenantId, tid))) {
    res.status(403).json({ error: "Forbidden" }); return;
  }
  if (role === "account_manager") {
    const clientIds = await getAmClientTenantIds(req.user!.userId);
    if (!clientIds.includes(tid)) { res.status(403).json({ error: "Forbidden" }); return; }
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

  // Full cascade: delete all related records across every table, then the tenant itself
  await cascadeDeleteTenant(tid);
  await db.delete(tenantsTable).where(eq(tenantsTable.id, tid));
  res.sendStatus(204);
});

// ── Update tenant ─────────────────────────────────────────────────────────────
router.patch("/tenants/:tenantId", requireAuth, requireRole("super_admin", "admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
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
