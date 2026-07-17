import { Router } from "express";
import multer from "multer";
import { db } from "@workspace/db";
import {
  tprmModuleAssignmentsTable,
  tprmVendorsTable,
  tprmVendorRiskScoresTable,
  tprmVendorAssetsTable,
  tprmVendorFindingsTable,
  tprmFourthPartyVendorsTable,
  tprmVendorSecurityAnalysisTable,
  tprmVendorBreachEventsTable,
  tprmSupplyChainNodesTable,
  tprmVendorContactsTable,
  tprmQuestionnaireTemplatesTable,
  tprmVendorQuestionnairesTable,
  tprmComplianceDocumentsTable,
  tprmComplianceRequirementsTable,
  tprmVendorComplianceControlsTable,
  tprmComplianceRemindersTable,
  tprmQuestionLibraryTable,
  tprmSbomUploadsTable,
  tenantsTable,
  platformSettingsTable,
  alertsTable,
  assetsTable,
} from "@workspace/db";
import { eq, and, desc, asc, or, ilike, sql, ne, lte, inArray, isNull } from "drizzle-orm";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { logger } from "../lib/logger";
import { enrichCompanyByDomain, runFullVendorScan } from "../lib/tprmEnrichment";
import { parseSbom, detectSbomFormat, enrichSbomWithVulnerabilities } from "../lib/tprmSbom";
import { enrichFindingsWithEpssKev } from "../lib/epssKev";
import { getAmClientTenantIds } from "../lib/amScoping";

const router = Router();
const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });

// ── requireTprm middleware ─────────────────────────────────────────────────────
async function requireTprm(req: AuthenticatedRequest, res: any, next: Function) {
  const tenantId = req.user?.tenantId;
  const role     = req.user?.role;
  if (!tenantId) { res.status(401).json({ error: "Unauthorized" }); return; }
  // Admin, super_admin, and account_manager always have TPRM access
  if (role === "admin" || role === "super_admin" || role === "account_manager") { next(); return; }
  try {
    const [row] = await db.select().from(tprmModuleAssignmentsTable).where(eq(tprmModuleAssignmentsTable.tenantId, tenantId));
    if (!row?.isEnabled) { res.status(403).json({ error: "TPRM module is not enabled for this tenant" }); return; }
    next();
  } catch { res.status(500).json({ error: "Module check failed" }); }
}

/**
 * Returns the list of tenant IDs the calling user can access for TPRM vendor queries.
 * - super_admin / admin: all tenants (platform + client)
 * - account_manager: only their assigned client tenants
 * - client / others: only their own tenant
 */
async function getVendorScopeTenantIds(req: AuthenticatedRequest): Promise<number[]> {
  const { role, tenantId, userId } = req.user!;
  if (role === "super_admin" || role === "admin") {
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable);
    return rows.map(r => r.id);
  }
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(userId);
    return [...new Set([tenantId, ...ids])]; // own platform tenant + all assigned client tenants
  }
  return [tenantId];
}

/**
 * Resolves a vendor by ID for any role — cross-tenant for admin/SA, assigned-tenants for AM.
 */
async function resolveVendorForRole(vendorId: number, req: AuthenticatedRequest) {
  const { role, tenantId, userId } = req.user!;
  if (role === "super_admin" || role === "admin") {
    const [v] = await db.select().from(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    return v ?? null;
  }
  if (role === "account_manager") {
    const clientIds = await getAmClientTenantIds(userId);
    const allTenantIds = [...new Set([tenantId, ...clientIds])];
    const [v] = await db.select().from(tprmVendorsTable).where(
      and(eq(tprmVendorsTable.id, vendorId), inArray(tprmVendorsTable.tenantId, allTenantIds))
    );
    return v ?? null;
  }
  return resolveVendor(vendorId, tenantId);
}

/**
 * Resolve a vendor by ID while enforcing tenant ownership (client-only path).
 * Returns the vendor row if the caller's tenant owns it (tenantId match) OR it is a global vendor.
 * Returns null if the vendor doesn't exist or belongs to a different tenant.
 */
async function resolveVendor(vendorId: number, tenantId: number) {
  const [vendor] = await db.select().from(tprmVendorsTable).where(
    and(eq(tprmVendorsTable.id, vendorId), or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!)
  );
  return vendor ?? null;
}

// ── Module management ─────────────────────────────────────────────────────────

router.get("/tprm/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  // Admin, super_admin, and account_manager always have TPRM active — bypass the per-tenant flag
  if (role === "admin" || role === "super_admin" || role === "account_manager") {
    const [tenant] = await db.select({ plan: tenantsTable.plan }).from(tenantsTable).where(eq(tenantsTable.id, tenantId));
    res.json({ isEnabled: true, updatedAt: null, plan: tenant?.plan ?? null });
    return;
  }
  const [[row], [tenant]] = await Promise.all([
    db.select().from(tprmModuleAssignmentsTable).where(eq(tprmModuleAssignmentsTable.tenantId, tenantId)),
    db.select({ plan: tenantsTable.plan }).from(tenantsTable).where(eq(tenantsTable.id, tenantId)),
  ]);
  res.json({ isEnabled: row?.isEnabled ?? false, updatedAt: row?.updatedAt ?? null, plan: tenant?.plan ?? null });
});

router.get("/tprm/module/all", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const rows = await db.select({ tenantId: tprmModuleAssignmentsTable.tenantId, isEnabled: tprmModuleAssignmentsTable.isEnabled }).from(tprmModuleAssignmentsTable);
  const map: Record<number, boolean> = {};
  for (const r of rows) map[r.tenantId] = r.isEnabled ?? false;
  res.json(map);
});

router.patch("/tprm/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role, tenantId: callerTenantId } = req.user!;
  if (role !== "admin" && role !== "super_admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const requestedTenantId = req.body.tenantId ? Number(req.body.tenantId) : callerTenantId;
  const targetTenantId = requestedTenantId; // both admin and super_admin can toggle any tenant
  const isEnabled = !!req.body.isEnabled;
  await db.insert(tprmModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: tprmModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "tprm_enabled" : "tprm_disabled", "tenant", targetTenantId, JSON.stringify({ targetTenantId, isEnabled }), req);
  res.json({ isEnabled });
});

// Explicit per-tenant toggle for super_admin (canonical URL expected by frontend/code review)
router.patch("/tprm/client/:tenantId/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const targetTenantId = parseInt(req.params.tenantId as string);
  if (isNaN(targetTenantId)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  const isEnabled = !!req.body.isEnabled;
  await db.insert(tprmModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: tprmModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "tprm_enabled" : "tprm_disabled", "tenant", targetTenantId, JSON.stringify({ targetTenantId, isEnabled }), req);
  res.json({ isEnabled, tenantId: targetTenantId });
});

// ── Admin: global vendor library ───────────────────────────────────────────────

router.get("/tprm/admin/global-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const { page = "1", limit = "20", search = "" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const searchCond = search
      ? and(eq(tprmVendorsTable.isGlobal, true), or(ilike(tprmVendorsTable.companyName, `%${search}%`), ilike(tprmVendorsTable.domain, `%${search}%`)))
      : eq(tprmVendorsTable.isGlobal, true);
    const [vendors, [countRow]] = await Promise.all([
      db.select().from(tprmVendorsTable).where(searchCond).orderBy(asc(tprmVendorsTable.companyName)).limit(parseInt(limit)).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmVendorsTable).where(searchCond),
    ]);
    res.json({ vendors, total: countRow?.count ?? 0 });
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendors GET error");
    res.status(500).json({ error: "Failed to fetch global vendors" });
  }
});

router.post("/tprm/admin/global-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role, tenantId, userId } = req.user!;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const { companyName, domain, type, industry, description } = req.body;
  if (!companyName || !domain) { res.status(400).json({ error: "companyName and domain are required" }); return; }
  try {
    const cleanDomain = domain.replace(/^www\./, "").split("/")[0].toLowerCase();
    const slug = companyName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    const [vendor] = await db.insert(tprmVendorsTable).values({
      tenantId,
      companyName,
      domain:   cleanDomain,
      slug:     `${slug}-${Date.now()}`,
      type:     type ?? "service_provider",
      industry: industry ?? null,
      description: description ?? null,
      isGlobal: true,
      status:   "pending",
    }).returning();
    await logAudit(req.user!, "tprm_global_vendor_created", "vendor", vendor.id, JSON.stringify({ companyName, domain: cleanDomain }), req);
    setImmediate(() => {
      runFullVendorScan(vendor.id, tenantId).catch(err => logger.error({ err, vendorId: vendor.id }, "TPRM global vendor scan failed"));
    });
    res.status(201).json(vendor);
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendor POST error");
    res.status(500).json({ error: "Failed to create global vendor" });
  }
});

router.patch("/tprm/admin/global-vendors/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const vendorId = parseInt(req.params.id as string);
  const { companyName, type, industry, description, status } = req.body;
  try {
    const [existing] = await db.select().from(tprmVendorsTable).where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.isGlobal, true)));
    if (!existing) { res.status(404).json({ error: "Global vendor not found" }); return; }
    const [updated] = await db.update(tprmVendorsTable).set({
      ...(companyName && { companyName }),
      ...(type        && { type }),
      ...(industry    && { industry }),
      ...(description !== undefined && { description }),
      ...(status      && { status }),
      updatedAt: new Date(),
    }).where(eq(tprmVendorsTable.id, vendorId)).returning();
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendor PATCH error");
    res.status(500).json({ error: "Failed to update global vendor" });
  }
});

router.delete("/tprm/admin/global-vendors/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const vendorId = parseInt(req.params.id as string);
  try {
    const [existing] = await db.select().from(tprmVendorsTable).where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.isGlobal, true)));
    if (!existing) { res.status(404).json({ error: "Global vendor not found" }); return; }
    await db.delete(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    await logAudit(req.user!, "tprm_global_vendor_deleted", "vendor", vendorId, JSON.stringify({ companyName: existing.companyName }), req);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendor DELETE error");
    res.status(500).json({ error: "Failed to delete global vendor" });
  }
});

// ── Admin: cross-tenant all vendors (admin / super_admin) — paginated ──────────

router.get("/tprm/admin/all-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const { page = "1", limit = "20", search = "" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const searchCond = search
      ? or(ilike(tprmVendorsTable.companyName, `%${search}%`), ilike(tprmVendorsTable.domain, `%${search}%`))
      : undefined;
    const [vendors, [countRow]] = await Promise.all([
      db.select({
          id:          tprmVendorsTable.id,
          companyName: tprmVendorsTable.companyName,
          domain:      tprmVendorsTable.domain,
          type:        tprmVendorsTable.type,
          status:      tprmVendorsTable.status,
          riskScore:   tprmVendorsTable.riskScore,
          riskGrade:   tprmVendorsTable.riskGrade,
          isGlobal:    tprmVendorsTable.isGlobal,
          tenantId:    tprmVendorsTable.tenantId,
          tenantName:  tenantsTable.name,
          lastScannedAt: tprmVendorsTable.lastScannedAt,
        })
        .from(tprmVendorsTable)
        .leftJoin(tenantsTable, eq(tprmVendorsTable.tenantId, tenantsTable.id))
        .where(searchCond)
        .orderBy(desc(tprmVendorsTable.updatedAt))
        .limit(parseInt(limit))
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmVendorsTable).where(searchCond),
    ]);
    res.json({ vendors, total: countRow?.count ?? 0 });
  } catch (err) {
    logger.error({ err }, "TPRM admin all-vendors error");
    res.status(500).json({ error: "Failed to fetch vendors" });
  }
});

// ── Admin: global vendor library — paginated ───────────────────────────────────
// NOTE: the existing GET /tprm/admin/global-vendors is replaced by adding pagination

// ── Admin: asset inventory with TPRM status ────────────────────────────────────

router.get("/tprm/admin/assets", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role, tenantId: callerTenantId } = req.user!;
  if (role !== "admin" && role !== "super_admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const { page = "1", limit = "20", search = "", verified = "" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const conds: any[] = [];
    if (search) conds.push(or(ilike(assetsTable.name, `%${search}%`), ilike(assetsTable.value, `%${search}%`)));
    if (verified === "true")  conds.push(eq(assetsTable.verificationStatus, "verified"));
    if (verified === "false") conds.push(ne(assetsTable.verificationStatus, "verified"));

    const whereClause = conds.length > 0 ? and(...conds) : undefined;

    const [rows, [countRow]] = await Promise.all([
      db.select({
          id:                 assetsTable.id,
          tenantId:           assetsTable.tenantId,
          tenantName:         tenantsTable.name,
          name:               assetsTable.name,
          type:               assetsTable.type,
          value:              assetsTable.value,
          verificationStatus: assetsTable.verificationStatus,
          isTprmEnabled:      assetsTable.isTprmEnabled,
          riskLevel:          assetsTable.riskLevel,
          isActive:           assetsTable.isActive,
          createdAt:          assetsTable.createdAt,
        })
        .from(assetsTable)
        .leftJoin(tenantsTable, eq(assetsTable.tenantId, tenantsTable.id))
        .where(whereClause)
        .orderBy(desc(assetsTable.createdAt))
        .limit(parseInt(limit))
        .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(assetsTable).where(whereClause),
    ]);
    res.json({ assets: rows, total: countRow?.count ?? 0 });
  } catch (err) {
    logger.error({ err }, "TPRM admin assets error");
    res.status(500).json({ error: "Failed to fetch assets" });
  }
});

router.patch("/tprm/admin/assets/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "admin" && role !== "super_admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  const assetId = parseInt(req.params.id as string);
  const { isTprmEnabled } = req.body as { isTprmEnabled: boolean };
  if (typeof isTprmEnabled !== "boolean") { res.status(400).json({ error: "isTprmEnabled (boolean) is required" }); return; }

  const [asset] = await db.select({ id: assetsTable.id, verificationStatus: assetsTable.verificationStatus })
    .from(assetsTable).where(eq(assetsTable.id, assetId));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  if (isTprmEnabled && asset.verificationStatus !== "verified") {
    res.status(400).json({ error: "TPRM can only be enabled for verified assets" }); return;
  }

  const [updated] = await db.update(assetsTable)
    .set({ isTprmEnabled, updatedAt: new Date() })
    .where(eq(assetsTable.id, assetId))
    .returning({ id: assetsTable.id, isTprmEnabled: assetsTable.isTprmEnabled, verificationStatus: assetsTable.verificationStatus });
  res.json(updated);
});

// ── Admin overview ─────────────────────────────────────────────────────────────

router.get("/tprm/admin/overview", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "admin" && role !== "super_admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  try {
    const tenants = await db.select().from(tenantsTable); // both admin and super_admin see all tenants
    const moduleRows = await db.select().from(tprmModuleAssignmentsTable);
    const moduleMap: Record<number, boolean> = {};
    for (const r of moduleRows) moduleMap[r.tenantId] = r.isEnabled ?? false;

    const vendorCounts = await db
      .select({ tenantId: tprmVendorsTable.tenantId, count: sql<number>`count(*)::int` })
      .from(tprmVendorsTable)
      .groupBy(tprmVendorsTable.tenantId);
    const vendorMap: Record<number, number> = {};
    for (const r of vendorCounts) vendorMap[r.tenantId] = r.count;

    const avgScores = await db
      .select({ tenantId: tprmVendorsTable.tenantId, avg: sql<number>`round(avg(risk_score))::int` })
      .from(tprmVendorsTable)
      .groupBy(tprmVendorsTable.tenantId);
    const avgMap: Record<number, number> = {};
    for (const r of avgScores) avgMap[r.tenantId] = r.avg;

    const result = tenants.map(t => ({
      tenantId:        t.id,
      tenantName:      t.name,
      plan:            t.plan,
      isEnabled:       moduleMap[t.id] ?? false,
      vendorCount:     vendorMap[t.id] ?? 0,
      avgRiskScore:    avgMap[t.id] ?? 0,
    }));

    res.json({
      tenants: result,
      stats: {
        total:   result.length,
        enabled: result.filter(r => r.isEnabled).length,
        disabled: result.filter(r => !r.isEnabled).length,
      },
    });
  } catch (err) {
    logger.error({ err }, "TPRM admin overview error");
    res.status(500).json({ error: "Failed to load overview" });
  }
});

// ── Company enrichment ────────────────────────────────────────────────────────

router.post("/tprm/enrich", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { domain } = req.body;
  if (!domain) { res.status(400).json({ error: "domain is required" }); return; }
  try {
    const enrichment = await enrichCompanyByDomain(domain);
    const cleanDomain = domain.replace(/^www\./, "").split("/")[0].toLowerCase();
    const { tenantId } = req.user!;
    const [existing] = await db.select({ id: tprmVendorsTable.id, companyName: tprmVendorsTable.companyName })
      .from(tprmVendorsTable)
      .where(and(
        eq(tprmVendorsTable.domain, cleanDomain),
        or(eq(tprmVendorsTable.isGlobal, true), eq(tprmVendorsTable.tenantId, tenantId)),
      ));
    res.json({ ...enrichment, existingVendor: existing ?? null });
  } catch (err) {
    logger.error({ err }, "TPRM enrich error");
    res.status(500).json({ error: "Enrichment failed" });
  }
});

// ── Vendors CRUD ──────────────────────────────────────────────────────────────

router.get("/tprm/vendors", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role, userId } = req.user!;
  const { type, status, riskGrade, industry, search, page = "1", limit = "50" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  try {
    // Build tenant scope condition
    let tenantCond: any;
    let tprmStatusMap: Record<number, boolean> = {};

    if (role === "super_admin" || role === "admin") {
      // All vendors across all tenants — no tenant filter
      tenantCond = undefined;
    } else if (role === "account_manager") {
      const clientIds = await getAmClientTenantIds(userId);
      if (clientIds.length === 0) {
        res.json({ vendors: [], total: 0, page: parseInt(page), limit: parseInt(limit) });
        return;
      }
      tenantCond = inArray(tprmVendorsTable.tenantId, clientIds);
      // Fetch per-client TPRM enabled status for AM visibility of disabled clients
      const assignments = await db.select({ tenantId: tprmModuleAssignmentsTable.tenantId, isEnabled: tprmModuleAssignmentsTable.isEnabled })
        .from(tprmModuleAssignmentsTable)
        .where(inArray(tprmModuleAssignmentsTable.tenantId, clientIds));
      for (const a of assignments) tprmStatusMap[a.tenantId] = a.isEnabled ?? false;
    } else {
      tenantCond = or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!;
    }

    const conds: any[] = [];
    if (tenantCond) conds.push(tenantCond);
    if (type)      conds.push(eq(tprmVendorsTable.type, type));
    if (status)    conds.push(eq(tprmVendorsTable.status, status));
    if (riskGrade) conds.push(eq(tprmVendorsTable.riskGrade, riskGrade));
    if (industry)  conds.push(eq(tprmVendorsTable.industry, industry));
    if (search)    conds.push(or(ilike(tprmVendorsTable.companyName, `%${search}%`), ilike(tprmVendorsTable.domain, `%${search}%`))!);

    const whereClause = conds.length > 0 ? and(...conds) : undefined;

    const [vendors, [countRow]] = await Promise.all([
      db.select().from(tprmVendorsTable).where(whereClause).orderBy(desc(tprmVendorsTable.createdAt)).limit(parseInt(limit)).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmVendorsTable).where(whereClause),
    ]);

    const vendorIds = vendors.map(v => v.id);
    let assetCounts: Record<number, number> = {};
    if (vendorIds.length > 0) {
      const counts = await db.select({ vendorId: tprmVendorAssetsTable.vendorId, count: sql<number>`count(*)::int` })
        .from(tprmVendorAssetsTable)
        .where(inArray(tprmVendorAssetsTable.vendorId, vendorIds))
        .groupBy(tprmVendorAssetsTable.vendorId);
      for (const c of counts) assetCounts[c.vendorId] = c.count;
    }

    // For AM: add tprmEnabled flag per vendor's tenant so frontend can show disabled state
    res.json({
      vendors: vendors.map(v => ({
        ...v,
        assetCount: assetCounts[v.id] ?? 0,
        tprmEnabled: role === "account_manager" ? (tprmStatusMap[v.tenantId] ?? false) : true,
      })),
      total: countRow?.count ?? 0,
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    logger.error({ err }, "TPRM vendors list error");
    res.status(500).json({ error: "Failed to list vendors" });
  }
});

router.post("/tprm/vendors", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role, userId } = req.user!;
  const { companyName, domain, type, industry, description, logoUrl, website, employeeCount, companySize, founded, location, marketCap, companyType, isGlobal, inherentRisk, businessImpact, scanFrequency, source, assessmentType } = req.body;

  if (!companyName || !domain) { res.status(400).json({ error: "companyName and domain are required" }); return; }
  if (isGlobal && role !== "super_admin") { res.status(403).json({ error: "Only super_admin can create global vendors" }); return; }

  const cleanDomain = domain.replace(/^www\./, "").split("/")[0].toLowerCase();
  const slug = companyName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");

  try {
    const [vendor] = await db.insert(tprmVendorsTable).values({
      tenantId:       isGlobal ? tenantId : tenantId,
      companyName,
      slug,
      domain:         cleanDomain,
      type:           type ?? "service_provider",
      industry:       industry ?? null,
      description:    description ?? null,
      logoUrl:        logoUrl ?? null,
      website:        website ?? `https://${cleanDomain}`,
      employeeCount:  employeeCount ? parseInt(employeeCount) : null,
      companySize:    companySize ?? null,
      founded:        founded ?? null,
      location:       location ?? null,
      marketCap:      marketCap ?? null,
      companyType:    companyType ?? "private",
      isGlobal:       !!isGlobal,
      inherentRisk:   inherentRisk ?? "medium",
      riskScore:      0,
      riskGrade:      "F",
      businessImpact: businessImpact ? parseInt(businessImpact) : 5,
      scanFrequency:  scanFrequency ?? "weekly",
      status:         "pending",
      source:         source ?? "manual",
      assessmentType: assessmentType ?? "continuous",
      createdBy:      userId as any,
    }).returning();

    await logAudit(req.user!, "tprm_vendor_created", "vendor", vendor.id, JSON.stringify({ companyName, domain: cleanDomain }), req);

    // Trigger background scan
    setImmediate(() => {
      runFullVendorScan(vendor.id, tenantId).catch(err => logger.error({ err, vendorId: vendor.id }, "TPRM background scan failed"));
    });

    res.status(201).json(vendor);
  } catch (err) {
    logger.error({ err }, "TPRM create vendor error");
    res.status(500).json({ error: "Failed to create vendor" });
  }
});

// Static sub-paths MUST come before /tprm/vendors/:id to avoid param shadowing

router.get("/tprm/vendors/assets-summary", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const vendorCond = scopeTenantIds.length === 0
      ? sql`false`
      : inArray(tprmVendorsTable.tenantId, scopeTenantIds);
    const vendorIds = (await db.select({ id: tprmVendorsTable.id }).from(tprmVendorsTable).where(vendorCond)).map(v => v.id);

    if (vendorIds.length === 0) { res.json({ domains: 0, subdomains: 0, ipAddresses: 0, webApps: 0, mobileApps: 0 }); return; }

    const rows = await db.select({ assetType: tprmVendorAssetsTable.assetType, count: sql<number>`count(*)::int` })
      .from(tprmVendorAssetsTable).where(inArray(tprmVendorAssetsTable.vendorId, vendorIds)).groupBy(tprmVendorAssetsTable.assetType);

    const out = { domains: 0, subdomains: 0, ipAddresses: 0, webApps: 0, mobileApps: 0 };
    for (const r of rows) {
      if (r.assetType === "domain")          out.domains     += r.count;
      else if (r.assetType === "subdomain")  out.subdomains  += r.count;
      else if (r.assetType === "ip")         out.ipAddresses += r.count;
      else if (r.assetType === "web_app")    out.webApps     += r.count;
      else if (r.assetType === "mobile_app") out.mobileApps  += r.count;
    }
    if (out.domains === 0) out.domains = vendorIds.length;
    res.json(out);
  } catch (err) {
    logger.error({ err }, "TPRM assets-summary error");
    res.status(500).json({ error: "Failed to load assets summary" });
  }
});

router.get("/tprm/vendors/timeline", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const vendorCond = scopeTenantIds.length === 0 ? sql`false` : inArray(tprmVendorsTable.tenantId, scopeTenantIds);
    const vendorIds = (await db.select({ id: tprmVendorsTable.id }).from(tprmVendorsTable).where(vendorCond)).map(v => v.id);

    if (vendorIds.length === 0) { res.json({ weeks: [], topAssetTypes: [] }); return; }

    const weeks: { label: string; assetCount: number; issueCount: number; vendorCount: number }[] = [];
    const now = new Date();
    for (let w = 7; w >= 0; w--) {
      const weekEnd = new Date(now.getTime() - w * 7 * 86400000);
      const label   = weekEnd.toLocaleDateString("en-US", { month: "short", day: "numeric" });
      const vidArr = sql`ARRAY[${sql.join(vendorIds.map(id => sql`${id}`), sql`, `)}]::int[]`;
      const [assetRow, issueRow, vendorRow] = await Promise.all([
        db.execute(sql`SELECT count(*)::int AS c FROM tprm_vendor_assets WHERE vendor_id = ANY(${vidArr}) AND discovered_at <= ${weekEnd}`),
        db.execute(sql`SELECT count(*)::int AS c FROM tprm_vendor_findings WHERE vendor_id = ANY(${vidArr}) AND created_at <= ${weekEnd} AND status = 'open'`),
        db.execute(sql`SELECT count(*)::int AS c FROM tprm_vendors WHERE id = ANY(${vidArr}) AND created_at <= ${weekEnd}`),
      ]);
      weeks.push({
        label,
        assetCount:  Number((assetRow.rows[0] as any)?.c ?? 0),
        issueCount:  Number((issueRow.rows[0] as any)?.c ?? 0),
        vendorCount: Number((vendorRow.rows[0] as any)?.c ?? 0),
      });
    }

    const vidArrTop = sql`ARRAY[${sql.join(vendorIds.map(id => sql`${id}`), sql`, `)}]::int[]`;
    const topTypeRows = await db.execute(sql`
      SELECT asset_type, count(*)::int AS c FROM tprm_vendor_assets
      WHERE vendor_id = ANY(${vidArrTop})
      GROUP BY asset_type ORDER BY c DESC LIMIT 5
    `);
    const topAssetTypes = (topTypeRows.rows as any[]).map(r => ({ type: r.asset_type, count: Number(r.c) }));

    res.json({ weeks, topAssetTypes });
  } catch (err) {
    logger.error({ err }, "TPRM vendors timeline error");
    res.status(500).json({ error: "Failed to load timeline" });
  }
});

// ── Risk comparison — static sub-path, must be before /:id ───────────────────
router.get("/tprm/vendors/compare", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const { ids } = req.query as { ids?: string };
    const scopeIds = await getVendorScopeTenantIds(req);
    let vendorIds: number[] = [];
    if (ids) {
      vendorIds = ids.split(",").map(s => parseInt(s.trim())).filter(n => !isNaN(n)).slice(0, 5);
    } else {
      // Default: top 5 by risk score
      const top = await db.select({ id: tprmVendorsTable.id })
        .from(tprmVendorsTable)
        .where(scopeIds.length === 0 ? sql`false` : inArray(tprmVendorsTable.tenantId, scopeIds))
        .orderBy(desc(tprmVendorsTable.riskScore))
        .limit(5);
      vendorIds = top.map(v => v.id);
    }
    if (vendorIds.length === 0) { res.json([]); return; }
    const vendors = await db.select().from(tprmVendorsTable).where(inArray(tprmVendorsTable.id, vendorIds));
    const result = await Promise.all(vendors.map(async v => {
      const [scores, findingCounts, openFindingCounts, fourthPartyRows] = await Promise.all([
        db.select({ overallScore: tprmVendorRiskScoresTable.overallScore, calculatedAt: tprmVendorRiskScoresTable.calculatedAt })
          .from(tprmVendorRiskScoresTable)
          .where(and(eq(tprmVendorRiskScoresTable.vendorId, v.id), eq(tprmVendorRiskScoresTable.tenantId, v.tenantId)))
          .orderBy(asc(tprmVendorRiskScoresTable.calculatedAt))
          .limit(30),
        db.select({
          critical: sql<number>`count(*) filter (where severity='critical')::int`,
          high:     sql<number>`count(*) filter (where severity='high')::int`,
          medium:   sql<number>`count(*) filter (where severity='medium')::int`,
          low:      sql<number>`count(*) filter (where severity='low')::int`,
        }).from(tprmVendorFindingsTable)
          .where(and(eq(tprmVendorFindingsTable.vendorId, v.id), eq(tprmVendorFindingsTable.tenantId, v.tenantId))),
        db.select({ count: sql<number>`count(*)::int` })
          .from(tprmVendorFindingsTable)
          .where(and(
            eq(tprmVendorFindingsTable.vendorId, v.id),
            eq(tprmVendorFindingsTable.tenantId, v.tenantId),
            eq(tprmVendorFindingsTable.status, "open"),
          )),
        db.select({ count: sql<number>`count(*)::int` })
          .from(tprmFourthPartyVendorsTable)
          .where(and(
            eq(tprmFourthPartyVendorsTable.parentVendorId, v.id),
            eq(tprmFourthPartyVendorsTable.tenantId, v.tenantId),
          )),
      ]);
      const fc = findingCounts[0] ?? { critical: 0, high: 0, medium: 0, low: 0 };
      return {
        id:               v.id,
        companyName:      v.companyName,
        riskScore:        v.riskScore,
        riskGrade:        v.riskGrade,
        domain:           v.domain,
        logoUrl:          v.logoUrl,
        industry:         v.industry,
        inherentRisk:     v.inherentRisk,
        criticalFindings: fc.critical,
        highFindings:     fc.high,
        mediumFindings:   fc.medium,
        lowFindings:      fc.low,
        openFindings:     openFindingCounts[0]?.count ?? 0,
        fourthPartyCount: fourthPartyRows[0]?.count ?? 0,
        complianceScore:  null as number | null,
        riskHistory:      scores.map(s => ({ score: s.overallScore, date: s.calculatedAt })),
      };
    }));
    res.json(result);
  } catch (err) {
    logger.error({ err }, "TPRM compare error");
    res.status(500).json({ error: "Failed to compare vendors" });
  }
});

// ── Bulk Scan — must be before /:id to avoid param shadowing ──────────────────
router.post("/tprm/vendors/bulk-scan", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const vendorCond = scopeTenantIds.length === 0
      ? sql`false`
      : inArray(tprmVendorsTable.tenantId, scopeTenantIds);

    const vendors = await db
      .select({ id: tprmVendorsTable.id, tenantId: tprmVendorsTable.tenantId, status: tprmVendorsTable.status })
      .from(tprmVendorsTable)
      .where(and(vendorCond, ne(tprmVendorsTable.status, "scanning")));

    if (vendors.length === 0) {
      res.json({ ok: true, queued: 0, message: "No vendors to scan" });
      return;
    }

    // Mark all as pending immediately so the frontend can show progress
    const vendorIds = vendors.map(v => v.id);
    await db.update(tprmVendorsTable)
      .set({ status: "pending", updatedAt: new Date() })
      .where(inArray(tprmVendorsTable.id, vendorIds));

    // Queue each scan in background — stagger by 3s to avoid OOM
    vendors.forEach((vendor, idx) => {
      setTimeout(() => {
        runFullVendorScan(vendor.id, vendor.tenantId).catch(err =>
          logger.error({ err, vendorId: vendor.id }, "TPRM bulk-scan failed for vendor")
        );
      }, idx * 3000);
    });

    logger.info({ queued: vendors.length, userId: req.user!.userId }, "TPRM bulk-scan triggered");
    res.json({ ok: true, queued: vendors.length, message: `Started scanning ${vendors.length} vendor${vendors.length !== 1 ? "s" : ""}` });
  } catch (err) {
    logger.error({ err }, "TPRM bulk-scan error");
    res.status(500).json({ error: "Failed to start bulk scan" });
  }
});

router.get("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);

  try {
    const vendor = await resolveVendorForRole(vendorId, req);
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }

    // ownerTenantId is always the vendor's actual tenant (for cross-tenant access)
    const ownerTenantId = vendor.tenantId;

    const [riskScores, assets, findings, fourthParties, supplyChain, contacts, questionnaires, complianceDocs] = await Promise.all([
      db.select().from(tprmVendorRiskScoresTable).where(and(eq(tprmVendorRiskScoresTable.vendorId, vendorId), eq(tprmVendorRiskScoresTable.tenantId, ownerTenantId))).orderBy(desc(tprmVendorRiskScoresTable.calculatedAt)).limit(30),
      db.select().from(tprmVendorAssetsTable).where(and(eq(tprmVendorAssetsTable.vendorId, vendorId), eq(tprmVendorAssetsTable.tenantId, ownerTenantId))).limit(200),
      db.select().from(tprmVendorFindingsTable).where(and(eq(tprmVendorFindingsTable.vendorId, vendorId), eq(tprmVendorFindingsTable.tenantId, ownerTenantId))).orderBy(desc(tprmVendorFindingsTable.createdAt)).limit(100),
      db.select().from(tprmFourthPartyVendorsTable).where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, ownerTenantId))),
      db.select().from(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.vendorId, vendorId), eq(tprmSupplyChainNodesTable.tenantId, ownerTenantId))).limit(200),
      db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.vendorId, vendorId), eq(tprmVendorContactsTable.tenantId, tenantId))),
      db.select().from(tprmVendorQuestionnairesTable).where(and(eq(tprmVendorQuestionnairesTable.vendorId, vendorId), eq(tprmVendorQuestionnairesTable.tenantId, tenantId))).orderBy(desc(tprmVendorQuestionnairesTable.createdAt)),
      db.select().from(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.vendorId, vendorId), eq(tprmComplianceDocumentsTable.tenantId, tenantId))).orderBy(desc(tprmComplianceDocumentsTable.createdAt)),
    ]);

    // Attach template names to questionnaires (batch fetch)
    const tplIds = [...new Set(questionnaires.filter(q => q.templateId).map(q => q.templateId!))];
    const tplRows = tplIds.length > 0
      ? await db.select({ id: tprmQuestionnaireTemplatesTable.id, name: tprmQuestionnaireTemplatesTable.name })
          .from(tprmQuestionnaireTemplatesTable).where(inArray(tprmQuestionnaireTemplatesTable.id, tplIds))
      : [];
    const tplNameMap = new Map(tplRows.map(t => [t.id, t.name]));

    res.json({ ...vendor, riskScores, assets, findings, fourthParties, supplyChain, contacts, questionnaires: questionnaires.map(q => ({ ...q, responses: undefined, templateName: q.templateId ? (tplNameMap.get(q.templateId) ?? null) : null })), complianceDocs });
  } catch (err) {
    logger.error({ err }, "TPRM vendor detail error");
    res.status(500).json({ error: "Failed to load vendor" });
  }
});

router.patch("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  const allowed = ["companyName", "domain", "type", "industry", "description", "logoUrl", "website", "employeeCount", "companySize", "founded", "location", "marketCap", "companyType", "inherentRisk", "businessImpact", "scanFrequency", "status", "source", "assessmentType", "slaUptimePercent", "slaResponseTimeHours", "slaReviewDate", "slaNotes", "slaBreachCount"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }

  // Clean domain: strip protocol, www prefix handling, trailing slashes and paths
  if (updates.domain) {
    let d: string = String(updates.domain).trim().toLowerCase();
    d = d.replace(/^https?:\/\//i, "");   // strip http:// or https://
    d = d.replace(/^www\./i, "");          // strip leading www.
    d = d.split("/")[0];                   // strip any path after the domain
    d = d.split("?")[0];                   // strip query strings
    d = d.split("#")[0];                   // strip hash fragments
    updates.domain = d;
    // Regenerate slug from cleaned domain + company name
    const companyName: string = updates.companyName ?? "";
    const base = (companyName || d).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    updates.slug = `${base}-${d.replace(/[^a-z0-9]+/g, "-")}`;
  }

  try {
    const existing = await resolveVendorForRole(vendorId, req);
    if (!existing) { res.status(404).json({ error: "Vendor not found" }); return; }

    // If inherentRisk is changing, recalculate the risk score immediately.
    // Use the vendor's last technical score as the base, then apply an
    // inherent-risk adjustment: critical=−15, high=−8, medium=0, low=+5.
    const changingInherentRisk = req.body.inherentRisk !== undefined && req.body.inherentRisk !== existing.inherentRisk;
    if (changingInherentRisk) {
      const newInherentRisk: string = req.body.inherentRisk;
      const adjustment: Record<string, number> = { critical: -15, high: -8, medium: 0, low: 5 };
      const delta = adjustment[newInherentRisk] ?? 0;

      // Fetch last saved technical score (from risk score history if available)
      const [lastScore] = await db
        .select({ overallScore: tprmVendorRiskScoresTable.overallScore })
        .from(tprmVendorRiskScoresTable)
        .where(and(eq(tprmVendorRiskScoresTable.vendorId, vendorId), eq(tprmVendorRiskScoresTable.tenantId, existing.tenantId)))
        .orderBy(desc(tprmVendorRiskScoresTable.calculatedAt))
        .limit(1);

      // Base = last technical score or current riskScore (default 50 for never-scanned vendors)
      const baseScore = lastScore?.overallScore ?? existing.riskScore ?? 50;
      const newScore  = Math.max(0, Math.min(100, baseScore + delta));

      let newGrade = "F";
      if      (newScore >= 90) newGrade = "A+";
      else if (newScore >= 80) newGrade = "A";
      else if (newScore >= 70) newGrade = "B";
      else if (newScore >= 60) newGrade = "C";
      else if (newScore >= 50) newGrade = "D";

      updates.riskScore = newScore;
      updates.riskGrade = newGrade;

      // Persist a new risk-score history entry so the timeline chart reflects the change
      await db.insert(tprmVendorRiskScoresTable).values({
        vendorId,
        tenantId:        existing.tenantId,
        overallScore:    newScore,
        networkScore:    lastScore?.overallScore ?? 50,
        dnsScore:        0,
        webAppScore:     0,
        emailScore:      0,
        tlsScore:        0,
        endpointScore:   0,
        cloudScore:      0,
        appSecScore:     0,
        reputationScore: 0,
        infoLeakScore:   0,
        darkWebMentions: 0,
        calculatedAt:    new Date(),
      });
    }

    const [vendor] = await db.update(tprmVendorsTable).set(updates)
      .where(eq(tprmVendorsTable.id, vendorId))
      .returning();
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
    await logAudit(req.user!, "tprm_vendor_updated", "vendor", vendorId, JSON.stringify({ companyName: vendor.companyName, domain: vendor.domain, inherentRisk: vendor.inherentRisk }), req);
    res.json(vendor);
  } catch (err) {
    logger.error({ err }, "TPRM update vendor error");
    res.status(500).json({ error: "Failed to update vendor" });
  }
});

router.delete("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  try {
    const vendor = await resolveVendorForRole(vendorId, req);
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
    if (vendor.isGlobal && role !== "super_admin" && role !== "admin") {
      res.status(403).json({ error: "Only super_admin or admin can delete global vendors" }); return;
    }
    await db.delete(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    await logAudit(req.user!, "tprm_vendor_deleted", "vendor", vendorId, JSON.stringify({ companyName: vendor.companyName }), req);
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "TPRM delete vendor error");
    res.status(500).json({ error: "Failed to delete vendor" });
  }
});

router.post("/tprm/vendors/:id/scan", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  try {
    const vendor = await resolveVendorForRole(vendorId, req);
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
    await db.update(tprmVendorsTable).set({ status: "pending", updatedAt: new Date() }).where(eq(tprmVendorsTable.id, vendorId));
    setImmediate(() => {
      runFullVendorScan(vendorId, vendor.tenantId).catch(err => logger.error({ err }, "TPRM manual scan failed"));
    });
    res.json({ ok: true, message: "Scan started" });
  } catch (err) {
    logger.error({ err }, "TPRM trigger scan error");
    res.status(500).json({ error: "Failed to start scan" });
  }
});

// ── 4th Party ─────────────────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/fourth-party", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const rows = await db.select().from(tprmFourthPartyVendorsTable).where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, ownerTenantId))).orderBy(desc(tprmFourthPartyVendorsTable.discoveredAt));
  res.json(rows);
});

router.post("/tprm/vendors/:id/fourth-party", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const parentVendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(parentVendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { name, domain, discoveryMethod, riskContribution, details } = req.body;
  if (!name) { res.status(400).json({ error: "name is required" }); return; }
  const [row] = await db.insert(tprmFourthPartyVendorsTable).values({ parentVendorId, tenantId, name, domain: domain ?? null, discoveryMethod: discoveryMethod ?? "manual", riskContribution: riskContribution ?? 0, details: details ?? null }).returning();
  res.status(201).json(row);
});

// ── 4th Party Advanced: Rescan, Security Analysis, Breach Intel ───────────────

router.post("/tprm/vendors/:id/rescan-fourth-parties", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  res.json({ message: "Fourth party rescan triggered", vendorId });
  setImmediate(async () => {
    try {
      await runFullVendorScan(vendorId, vendor.tenantId);
    } catch (e) {
      logger.error({ e, vendorId }, "TPRM rescan-fourth-parties failed");
    }
  });
});

router.get("/tprm/vendors/:id/security-analysis", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const [row] = await db.select().from(tprmVendorSecurityAnalysisTable)
    .where(and(eq(tprmVendorSecurityAnalysisTable.vendorId, vendorId), eq(tprmVendorSecurityAnalysisTable.tenantId, ownerTenantId)))
    .orderBy(desc(tprmVendorSecurityAnalysisTable.scannedAt))
    .limit(1);
  if (!row) { res.json(null); return; }
  // Also include findings from the security analysis engine
  try {
    const { runVendorSecurityAnalysis } = await import("../lib/tprmSecurityAnalysis.js");
    const live = await runVendorSecurityAnalysis(vendor.domain);
    res.json({ ...row, live });
  } catch {
    res.json({ ...row, live: null });
  }
});

router.get("/tprm/vendors/:id/breach-intel", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const breachEvents = await db.select().from(tprmVendorBreachEventsTable)
    .where(and(eq(tprmVendorBreachEventsTable.vendorId, vendorId), eq(tprmVendorBreachEventsTable.tenantId, ownerTenantId)))
    .orderBy(desc(tprmVendorBreachEventsTable.discoveredAt));
  // Also run live lookalike detection
  let lookalikes: unknown[] = [];
  try {
    const { detectLookalikeDomains } = await import("../lib/tprmBreachIntel.js");
    lookalikes = await detectLookalikeDomains(vendor.domain);
  } catch { /* non-fatal */ }
  res.json({ breachEvents, lookalikes, domain: vendor.domain });
});

// ── 4th Party Cross-Vendor Intelligence ───────────────────────────────────────

router.get("/tprm/fourth-parties/concentration-risk", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const scopeTenantIds = await getVendorScopeTenantIds(req);
  const tenantCond = scopeTenantIds.length > 0
    ? inArray(tprmFourthPartyVendorsTable.tenantId, scopeTenantIds)
    : sql`false`;
  // Get all 4th party records for accessible tenants, joining vendor info
  const rows = await db.select({
    id:              tprmFourthPartyVendorsTable.id,
    name:            tprmFourthPartyVendorsTable.name,
    domain:          tprmFourthPartyVendorsTable.domain,
    category:        tprmFourthPartyVendorsTable.category,
    riskLevel:       tprmFourthPartyVendorsTable.riskLevel,
    confidence:      tprmFourthPartyVendorsTable.confidence,
    riskContribution:tprmFourthPartyVendorsTable.riskContribution,
    parentVendorId:  tprmFourthPartyVendorsTable.parentVendorId,
    vendorName:      tprmVendorsTable.companyName,
    vendorRiskGrade: tprmVendorsTable.riskGrade,
    vendorRiskScore: tprmVendorsTable.riskScore,
  })
  .from(tprmFourthPartyVendorsTable)
  .innerJoin(tprmVendorsTable, eq(tprmFourthPartyVendorsTable.parentVendorId, tprmVendorsTable.id))
  .where(tenantCond)
  .orderBy(desc(tprmFourthPartyVendorsTable.riskContribution));

  // Group by 4th party domain to find shared dependencies
  const grouped = new Map<string, {
    name: string; domain: string; category: string; riskLevel: string;
    vendors: Array<{ id: number; name: string; grade: string; score: number }>;
    maxRiskContribution: number;
  }>();

  for (const row of rows) {
    const key = row.domain ?? row.name;
    if (!grouped.has(key)) {
      grouped.set(key, { name: row.name, domain: row.domain ?? "", category: row.category, riskLevel: row.riskLevel, vendors: [], maxRiskContribution: 0 });
    }
    const entry = grouped.get(key)!;
    if (!entry.vendors.some(v => v.id === row.parentVendorId)) {
      entry.vendors.push({ id: row.parentVendorId, name: row.vendorName, grade: row.vendorRiskGrade, score: row.vendorRiskScore });
    }
    if (row.riskContribution > entry.maxRiskContribution) entry.maxRiskContribution = row.riskContribution;
  }

  const concentrationRisk = [...grouped.values()]
    .map(e => ({
      ...e,
      vendorCount: e.vendors.length,
      concentrationScore: e.vendors.length * e.maxRiskContribution,
    }))
    .sort((a, b) => b.concentrationScore - a.concentrationScore);

  res.json({
    concentrationRisk,
    totalFourthParties: grouped.size,
    sharedFourthParties: concentrationRisk.filter(e => e.vendorCount > 1).length,
    highRiskFourthParties: concentrationRisk.filter(e => e.riskLevel === "high" || e.riskLevel === "critical").length,
  });
});

// ── Update 4th party risk level (all rows sharing that domain/name) ───────────
router.patch("/tprm/fourth-parties/risk-level", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const scopeTenantIds = await getVendorScopeTenantIds(req);
  const { domain, name, riskLevel } = req.body as { domain?: string; name?: string; riskLevel: string };

  if (!riskLevel || !["critical", "high", "medium", "low"].includes(riskLevel)) {
    res.status(400).json({ error: "riskLevel must be critical, high, medium or low" }); return;
  }
  if (!domain && !name) {
    res.status(400).json({ error: "domain or name is required" }); return;
  }

  const tenantCond = scopeTenantIds.length > 0
    ? inArray(tprmFourthPartyVendorsTable.tenantId, scopeTenantIds)
    : sql`false`;

  const keyCond = domain
    ? eq(tprmFourthPartyVendorsTable.domain, domain)
    : eq(tprmFourthPartyVendorsTable.name, name!);

  // Fetch existing rows so we know old riskLevels before update
  const existing = await db.select({
    id:            tprmFourthPartyVendorsTable.id,
    parentVendorId:tprmFourthPartyVendorsTable.parentVendorId,
    tenantId:      tprmFourthPartyVendorsTable.tenantId,
    riskLevel:     tprmFourthPartyVendorsTable.riskLevel,
  }).from(tprmFourthPartyVendorsTable).where(and(tenantCond, keyCond));

  if (existing.length === 0) {
    res.status(404).json({ error: "No matching 4th party entries found" }); return;
  }

  await db.update(tprmFourthPartyVendorsTable)
    .set({ riskLevel })
    .where(and(tenantCond, keyCond));

  // Recalculate each unique parent vendor's risk score
  const riskOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const uniqueVendors = [...new Map(existing.map(r => [`${r.parentVendorId}-${r.tenantId}`, r])).values()];

  await Promise.all(uniqueVendors.map(async ({ parentVendorId, tenantId: vTenantId, riskLevel: oldRiskLevel }) => {
    try {
      const [vendor] = await db
        .select({ riskScore: tprmVendorsTable.riskScore, riskGrade: tprmVendorsTable.riskGrade })
        .from(tprmVendorsTable)
        .where(eq(tprmVendorsTable.id, parentVendorId));
      if (!vendor) return;

      // Delta per risk level change: each level step = 4 points
      const oldOrder = riskOrder[oldRiskLevel] ?? 2;
      const newOrder = riskOrder[riskLevel] ?? 2;
      const delta = (oldOrder - newOrder) * 4; // positive = risk went DOWN = score improves

      const newScore = Math.max(0, Math.min(100, (vendor.riskScore ?? 50) + delta));
      let newGrade = "F";
      if      (newScore >= 90) newGrade = "A+";
      else if (newScore >= 80) newGrade = "A";
      else if (newScore >= 70) newGrade = "B";
      else if (newScore >= 60) newGrade = "C";
      else if (newScore >= 50) newGrade = "D";

      await db.update(tprmVendorsTable)
        .set({ riskScore: newScore, riskGrade: newGrade, updatedAt: new Date() })
        .where(eq(tprmVendorsTable.id, parentVendorId));

      // Persist new risk score history row
      const [lastScore] = await db.select({ overallScore: tprmVendorRiskScoresTable.overallScore })
        .from(tprmVendorRiskScoresTable)
        .where(and(eq(tprmVendorRiskScoresTable.vendorId, parentVendorId), eq(tprmVendorRiskScoresTable.tenantId, vTenantId)))
        .orderBy(desc(tprmVendorRiskScoresTable.calculatedAt)).limit(1);

      await db.insert(tprmVendorRiskScoresTable).values({
        vendorId: parentVendorId, tenantId: vTenantId,
        overallScore:    newScore,
        networkScore:    lastScore?.overallScore ?? 50,
        dnsScore: 0, webAppScore: 0, emailScore: 0, tlsScore: 0,
        endpointScore: 0, cloudScore: 0, appSecScore: 0, reputationScore: 0,
        infoLeakScore: 0, darkWebMentions: 0,
        calculatedAt: new Date(),
      });
    } catch (err) {
      logger.warn({ err, parentVendorId }, "TPRM: vendor risk recalc failed (non-fatal)");
    }
  }));

  res.json({ ok: true, updated: existing.length });
});

router.get("/tprm/fourth-parties/graph", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const scopeTenantIds = await getVendorScopeTenantIds(req);
  const vendorTenantCond = scopeTenantIds.length > 0
    ? inArray(tprmVendorsTable.tenantId, scopeTenantIds)
    : sql`false`;
  const fpTenantCond = scopeTenantIds.length > 0
    ? inArray(tprmFourthPartyVendorsTable.tenantId, scopeTenantIds)
    : sql`false`;

  // Get all vendors + their 4th parties
  const vendors = await db.select({
    id: tprmVendorsTable.id,
    name: tprmVendorsTable.companyName,
    domain: tprmVendorsTable.domain,
    riskGrade: tprmVendorsTable.riskGrade,
    riskScore: tprmVendorsTable.riskScore,
    logoUrl: tprmVendorsTable.logoUrl,
  }).from(tprmVendorsTable)
    .where(and(vendorTenantCond, ne(tprmVendorsTable.status, "archived" as any)))
    .limit(50);

  const fourthParties = await db.select().from(tprmFourthPartyVendorsTable)
    .where(fpTenantCond);

  // Build graph: nodes + edges
  const nodes: Array<{ id: string; label: string; type: "org" | "vendor" | "fourth_party"; riskGrade?: string; category?: string; riskLevel?: string; domain?: string }> = [];
  const edges: Array<{ source: string; target: string; label: string }> = [];

  // Org node (the platform user's organisation)
  nodes.push({ id: "org-0", label: "Your Organization", type: "org" });

  // Vendor nodes + org→vendor edges
  for (const v of vendors) {
    const vId = `vendor-${v.id}`;
    nodes.push({ id: vId, label: v.name, type: "vendor", riskGrade: v.riskGrade, domain: v.domain ?? undefined });
    edges.push({ source: "org-0", target: vId, label: "USES" });
  }

  // 4th party nodes + vendor→4th edges (deduplicate 4th party nodes by domain)
  const fpNodeMap = new Map<string, string>();
  for (const fp of fourthParties) {
    const key = fp.domain ?? fp.name;
    if (!fpNodeMap.has(key)) {
      const fpId = `fp-${fpNodeMap.size}`;
      fpNodeMap.set(key, fpId);
      nodes.push({ id: fpId, label: fp.name, type: "fourth_party", category: fp.category, riskLevel: fp.riskLevel, domain: fp.domain ?? undefined });
    }
    const fpId = fpNodeMap.get(key)!;
    const vId = `vendor-${fp.parentVendorId}`;
    edges.push({ source: vId, target: fpId, label: fp.discoveryMethod.replace(/_/g, " ") });
  }

  res.json({ nodes, edges, meta: { vendorCount: vendors.length, fourthPartyCount: fpNodeMap.size, edgeCount: edges.length } });
});

// ── Risk & Findings ───────────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/risk-history", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendorForRole(vendorId, req);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmVendorRiskScoresTable).where(and(eq(tprmVendorRiskScoresTable.vendorId, vendorId), eq(tprmVendorRiskScoresTable.tenantId, vendor.tenantId))).orderBy(asc(tprmVendorRiskScoresTable.calculatedAt)).limit(90);
  res.json(rows);
});

router.get("/tprm/vendors/:id/findings", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendorForRole(vendorId, req);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { severity, status, page = "1", limit = "50" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const conds: any[] = [eq(tprmVendorFindingsTable.vendorId, vendorId), eq(tprmVendorFindingsTable.tenantId, vendor.tenantId)];
  if (severity) conds.push(eq(tprmVendorFindingsTable.severity, severity));
  if (status)   conds.push(eq(tprmVendorFindingsTable.status, status));
  const [rows, [countRow]] = await Promise.all([
    db.select().from(tprmVendorFindingsTable).where(and(...conds)).orderBy(desc(tprmVendorFindingsTable.createdAt)).limit(parseInt(limit)).offset(offset),
    db.select({ count: sql<number>`count(*)::int` }).from(tprmVendorFindingsTable).where(and(...conds)),
  ]);
  res.json({ findings: rows, total: countRow?.count ?? 0 });
});

router.patch("/tprm/vendors/:id/findings/:fid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const findingId = parseInt(req.params.fid as string);
  const { status } = req.body;
  const [row] = await db.update(tprmVendorFindingsTable).set({ status }).where(and(eq(tprmVendorFindingsTable.id, findingId), eq(tprmVendorFindingsTable.tenantId, tenantId))).returning();
  if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
  res.json(row);
});

router.get("/tprm/vendors/:id/assets", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendorForRole(vendorId, req);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmVendorAssetsTable).where(and(eq(tprmVendorAssetsTable.vendorId, vendorId), eq(tprmVendorAssetsTable.tenantId, vendor.tenantId))).orderBy(asc(tprmVendorAssetsTable.assetType)).limit(500);
  res.json(rows);
});

// ── Supply Chain ──────────────────────────────────────────────────────────────

router.get("/tprm/supply-chain", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { nodeType, riskLevel, vendorId, page = "1", limit = "20" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const tenantCond = scopeTenantIds.length > 0 ? inArray(tprmSupplyChainNodesTable.tenantId, scopeTenantIds) : sql`false`;
    const conds: any[] = [tenantCond];
    if (nodeType)  conds.push(eq(tprmSupplyChainNodesTable.nodeType, nodeType));
    if (riskLevel) conds.push(eq(tprmSupplyChainNodesTable.riskLevel, riskLevel));
    if (vendorId)  conds.push(eq(tprmSupplyChainNodesTable.vendorId, parseInt(vendorId)));
    const [rows, [countRow]] = await Promise.all([
      db.select({
        id:            tprmSupplyChainNodesTable.id,
        name:          tprmSupplyChainNodesTable.name,
        version:       tprmSupplyChainNodesTable.version,
        nodeType:      tprmSupplyChainNodesTable.nodeType,
        cpe:           tprmSupplyChainNodesTable.cpe,
        purl:          tprmSupplyChainNodesTable.purl,
        license:       tprmSupplyChainNodesTable.license,
        supplier:      tprmSupplyChainNodesTable.supplier,
        riskLevel:     tprmSupplyChainNodesTable.riskLevel,
        vulnerabilities: tprmSupplyChainNodesTable.vulnerabilities,
        parentNodeId:  tprmSupplyChainNodesTable.parentNodeId,
        depth:         tprmSupplyChainNodesTable.depth,
        sbomUploadId:  tprmSupplyChainNodesTable.sbomUploadId,
        vendorId:      tprmSupplyChainNodesTable.vendorId,
        tenantId:      tprmSupplyChainNodesTable.tenantId,
        discoveredAt:  tprmSupplyChainNodesTable.discoveredAt,
        // Fallback: if component has no explicit supplier, show the parent vendor name
        vendorName:    tprmVendorsTable.companyName,
      })
      .from(tprmSupplyChainNodesTable)
      .leftJoin(tprmVendorsTable, eq(tprmSupplyChainNodesTable.vendorId, tprmVendorsTable.id))
      .where(and(...conds))
      .orderBy(desc(tprmSupplyChainNodesTable.discoveredAt))
      .limit(parseInt(limit))
      .offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(...conds)),
    ]);
    res.json({ nodes: rows, total: countRow?.count ?? 0 });
  } catch (err) {
    logger.error({ err }, "TPRM supply-chain list error");
    res.status(500).json({ error: "Failed to list supply chain" });
  }
});

// ── Update supply-chain node risk level ───────────────────────────────────────
router.patch("/tprm/supply-chain/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const nodeId = parseInt(req.params.id as string);
  const { riskLevel } = req.body as { riskLevel: string };

  if (!riskLevel || !["critical", "high", "medium", "low"].includes(riskLevel)) {
    res.status(400).json({ error: "riskLevel must be critical, high, medium or low" }); return;
  }

  const scopeTenantIds = await getVendorScopeTenantIds(req);
  const tenantCond = scopeTenantIds.length > 0
    ? inArray(tprmSupplyChainNodesTable.tenantId, scopeTenantIds)
    : sql`false`;

  const [updated] = await db.update(tprmSupplyChainNodesTable)
    .set({ riskLevel })
    .where(and(eq(tprmSupplyChainNodesTable.id, nodeId), tenantCond))
    .returning({ id: tprmSupplyChainNodesTable.id, riskLevel: tprmSupplyChainNodesTable.riskLevel });

  if (!updated) { res.status(404).json({ error: "Node not found" }); return; }
  res.json({ ok: true, id: updated.id, riskLevel: updated.riskLevel });
});

router.get("/tprm/supply-chain/stats", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const tenantCond = scopeTenantIds.length > 0 ? inArray(tprmSupplyChainNodesTable.tenantId, scopeTenantIds) : sql`false`;
    const findingTenantCond = scopeTenantIds.length > 0 ? inArray(tprmVendorFindingsTable.tenantId, scopeTenantIds) : sql`false`;

    const [totalNodes, criticalNodes, highNodes] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(tenantCond),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(tenantCond, eq(tprmSupplyChainNodesTable.riskLevel, "critical"))),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(tenantCond, eq(tprmSupplyChainNodesTable.riskLevel, "high"))),
    ]);

    const byType = await db.select({ nodeType: tprmSupplyChainNodesTable.nodeType, count: sql<number>`count(*)::int` })
      .from(tprmSupplyChainNodesTable).where(tenantCond).groupBy(tprmSupplyChainNodesTable.nodeType);

    const vendorsWithCritical = await db.selectDistinct({ vendorId: tprmVendorFindingsTable.vendorId })
      .from(tprmVendorFindingsTable)
      .where(and(findingTenantCond, eq(tprmVendorFindingsTable.severity, "critical"), eq(tprmVendorFindingsTable.status, "open")));

    res.json({
      totalNodes:     totalNodes[0]?.count ?? 0,
      criticalNodes:  criticalNodes[0]?.count ?? 0,
      highNodes:      highNodes[0]?.count ?? 0,
      vendorsWithCriticalFindings: vendorsWithCritical.length,
      byType,
    });
  } catch (err) {
    logger.error({ err }, "TPRM supply chain stats error");
    res.status(500).json({ error: "Failed to load stats" });
  }
});

router.get("/tprm/vendors/:id/supply-chain", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendorForRole(vendorId, req);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.vendorId, vendorId), eq(tprmSupplyChainNodesTable.tenantId, vendor.tenantId))).limit(500);
  res.json(rows);
});

// ── Dashboard ─────────────────────────────────────────────────────────────────

router.get("/tprm/dashboard", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  try {
    const scopeTenantIds = await getVendorScopeTenantIds(req);
    const vendorWhereClause = scopeTenantIds.length > 0 ? inArray(tprmVendorsTable.tenantId, scopeTenantIds) : undefined;
    const allVendors = await db.select().from(tprmVendorsTable).where(vendorWhereClause);

    const totalVendors      = allVendors.length;
    const serviceProviders  = allVendors.filter(v => v.type === "service_provider").length;
    const prospecting       = allVendors.filter(v => v.type === "prospecting").length;
    const subsidiaries      = allVendors.filter(v => v.type === "subsidiary").length;
    const avgRiskScore      = totalVendors > 0 ? Math.round(allVendors.reduce((s, v) => s + v.riskScore, 0) / totalVendors) : 0;

    const gradeMap: Record<string, number> = {};
    for (const v of allVendors) gradeMap[v.riskGrade] = (gradeMap[v.riskGrade] ?? 0) + 1;

    const poor    = allVendors.filter(v => v.riskScore < 50).length;
    const average = allVendors.filter(v => v.riskScore >= 50 && v.riskScore < 70).length;
    const good    = allVendors.filter(v => v.riskScore >= 70).length;

    // Assessment type breakdown
    const contVendors = allVendors.filter(v => v.assessmentType === "continuous");
    const oneTimeVendors = allVendors.filter(v => v.assessmentType === "one_time" || !v.assessmentType);
    const continuousBreakdown = { poor: contVendors.filter(v => v.riskScore < 50).length, average: contVendors.filter(v => v.riskScore >= 50 && v.riskScore < 70).length, good: contVendors.filter(v => v.riskScore >= 70).length };
    const oneTimeBreakdown    = { poor: oneTimeVendors.filter(v => v.riskScore < 50).length, average: oneTimeVendors.filter(v => v.riskScore >= 50 && v.riskScore < 70).length, good: oneTimeVendors.filter(v => v.riskScore >= 70).length };

    const topCritical = allVendors.filter(v => v.riskGrade === "D" || v.riskGrade === "F").sort((a, b) => a.riskScore - b.riskScore).slice(0, 5);

    const vendorIds = allVendors.map(v => v.id);
    let digitalExposure = { credentialLeaks: 0, docsExposed: 0, darkWebMentions: 0, brandMentions: 0, employeeDataExposed: 0, credentialOnForum: 0 };
    let infraCoverage = { misconfiguredCloud: 0, subdomains: 0, mobileApps: 0, webApps: 0, misconfiguredDns: 0, sslIssues: 0 };
    let assetCounts = { domains: 0, subdomains: 0, ipAddresses: 0, webApps: 0, mobileApps: 0 };
    let activeDataLeaks = 0;
    let activeSecurityRisks = 0;
    const vendorSummaryData: any[] = [];

    if (vendorIds.length > 0) {
      const sevenDaysAgo = new Date(Date.now() - 7 * 86400000);
      const [assets, findings, allFindings, recentFindings, assetTypeCounts, latestRiskScores, prevRiskScores] = await Promise.all([
        db.select({ assetType: tprmVendorAssetsTable.assetType, count: sql<number>`count(*)::int` })
          .from(tprmVendorAssetsTable).where(inArray(tprmVendorAssetsTable.vendorId, vendorIds)).groupBy(tprmVendorAssetsTable.assetType),
        db.select().from(tprmVendorFindingsTable).where(and(inArray(tprmVendorFindingsTable.vendorId, vendorIds), eq(tprmVendorFindingsTable.status, "open"))),
        db.select().from(tprmVendorFindingsTable).where(inArray(tprmVendorFindingsTable.vendorId, vendorIds)),
        db.select().from(tprmVendorFindingsTable).where(and(inArray(tprmVendorFindingsTable.vendorId, vendorIds), sql`${tprmVendorFindingsTable.createdAt} >= ${sevenDaysAgo}`)),
        db.select({ vendorId: tprmVendorAssetsTable.vendorId, count: sql<number>`count(*)::int` })
          .from(tprmVendorAssetsTable).where(inArray(tprmVendorAssetsTable.vendorId, vendorIds)).groupBy(tprmVendorAssetsTable.vendorId),
        // Latest risk score per vendor (rank=1)
        db.execute(sql`
          SELECT DISTINCT ON (vendor_id) vendor_id, overall_score, network_score, dns_score, web_app_score,
            email_score, cloud_score, tls_score, info_leak_score, reputation_score, dark_web_mentions, calculated_at
          FROM tprm_vendor_risk_scores
          WHERE vendor_id = ANY(ARRAY[${sql.join(vendorIds.map(id => sql`${id}`), sql`, `)}]::int[])
          ORDER BY vendor_id, calculated_at DESC
        `),
        // 2nd latest score per vendor for score delta
        db.execute(sql`
          SELECT vendor_id, overall_score FROM (
            SELECT vendor_id, overall_score, calculated_at,
              ROW_NUMBER() OVER (PARTITION BY vendor_id ORDER BY calculated_at DESC) AS rn
            FROM tprm_vendor_risk_scores
            WHERE vendor_id = ANY(ARRAY[${sql.join(vendorIds.map(id => sql`${id}`), sql`, `)}]::int[])
          ) t WHERE rn = 2
        `),
      ]);

      for (const a of assets) {
        if (a.assetType === "subdomain")   assetCounts.subdomains  += a.count;
        else if (a.assetType === "ip")     assetCounts.ipAddresses += a.count;
        else if (a.assetType === "domain") assetCounts.domains     += a.count;
        else if (a.assetType === "web_app")assetCounts.webApps     += a.count;
        else if (a.assetType === "mobile_app") assetCounts.mobileApps += a.count;
      }
      if (assetCounts.domains === 0) assetCounts.domains = totalVendors;

      infraCoverage.misconfiguredCloud = findings.filter(f => f.category === "cloud").length;
      infraCoverage.subdomains         = assetCounts.subdomains;
      infraCoverage.mobileApps         = assetCounts.mobileApps;
      infraCoverage.webApps            = assetCounts.webApps;
      infraCoverage.misconfiguredDns   = findings.filter(f => f.category === "email" || f.category === "dns").length;
      infraCoverage.sslIssues          = findings.filter(f => f.category === "tls").length;

      digitalExposure.credentialLeaks    = findings.filter(f => f.category === "info_leak" && (f.title?.includes(".env") || f.title?.includes("credential") || f.title?.includes("secret"))).length;
      digitalExposure.docsExposed        = findings.filter(f => f.category === "info_leak" && (f.title?.includes(".git") || f.title?.includes("config"))).length;
      digitalExposure.brandMentions      = findings.filter(f => f.category === "brand_threat" || f.title?.toLowerCase().includes("brand")).length;
      digitalExposure.employeeDataExposed= findings.filter(f => f.title?.toLowerCase().includes("employee") || f.title?.toLowerCase().includes("personnel") || f.title?.toLowerCase().includes("pii")).length;
      digitalExposure.credentialOnForum  = findings.filter(f => f.title?.toLowerCase().includes("leak") || f.title?.toLowerCase().includes("forum") || f.title?.toLowerCase().includes("dark web")).length;

      activeDataLeaks    = recentFindings.filter(f => f.severity === "critical" || f.severity === "high").length;
      activeSecurityRisks= findings.length;

      // Build per-vendor risk score maps
      const latestScoreMap: Record<number, any> = {};
      for (const r of (latestRiskScores.rows as any[])) latestScoreMap[Number(r.vendor_id)] = r;
      const prevScoreMap: Record<number, number> = {};
      for (const r of (prevRiskScores.rows as any[])) prevScoreMap[Number(r.vendor_id)] = Number(r.overall_score);

      // Per-vendor summary with incident/status counts + security ratings
      const assetCountMap = Object.fromEntries(assetTypeCounts.map(a => [a.vendorId, a.count]));
      for (const v of allVendors) {
        const vFindings     = findings.filter(f => f.vendorId === v.id);
        const vAllFindings  = allFindings.filter(f => f.vendorId === v.id);
        const vNewFindings  = recentFindings.filter(f => f.vendorId === v.id);
        const rs            = latestScoreMap[v.id];
        const prevScore     = prevScoreMap[v.id] ?? null;
        const statusBreakup = {
          open:      vFindings.filter(f => f.status === "open").length,
          mitigated: vAllFindings.filter(f => f.status === "mitigated").length,
          in_progress: vAllFindings.filter(f => f.status === "in_progress").length,
          accepted:  vAllFindings.filter(f => f.status === "accepted_risk").length,
        };
        // Security ratings per vendor
        const externalAssets = assetCountMap[v.id] ?? 0;
        const brandThreat    = rs ? Number(rs.reputation_score ?? 0) : vFindings.filter(f => f.category === "brand_threat").length;
        const dataBreach     = rs ? Number(rs.info_leak_score ?? 0) : vFindings.filter(f => f.category === "info_leak").length;
        const darkwebMentions= rs ? Number(rs.dark_web_mentions ?? 0) : ((v as any).darkWebMentions ?? 0);
        const socialMedia    = vFindings.filter(f => f.title?.toLowerCase().includes("social") || f.category === "social_media").length;
        const fakeAds        = vFindings.filter(f => f.title?.toLowerCase().includes("fake") || f.title?.toLowerCase().includes("phish") || f.title?.toLowerCase().includes("typosquat")).length;
        const scoreIncrease  = prevScore !== null ? v.riskScore - prevScore : 0;
        vendorSummaryData.push({
          id: v.id, companyName: v.companyName, riskGrade: v.riskGrade, riskScore: v.riskScore,
          assessmentType: v.assessmentType, status: v.status, domain: v.domain, logoUrl: v.logoUrl,
          incidents: vFindings.filter(f => f.severity === "critical" || f.severity === "high").length,
          newIssues: vNewFindings.length,
          issuesSolved: vAllFindings.filter(f => f.status === "mitigated").length,
          totalIssues: vAllFindings.length,
          totalAssets: externalAssets,
          statusBreakup,
          // Security ratings columns
          externalAssets,
          brandThreat,
          dataBreach,
          darkwebMentions,
          socialMedia,
          fakeAds,
          scoreIncrease,
        });
      }
    }

    const recentScans = allVendors.filter(v => v.lastScannedAt).sort((a, b) => (b.lastScannedAt?.getTime() ?? 0) - (a.lastScannedAt?.getTime() ?? 0)).slice(0, 10);

    res.json({
      totalVendors, serviceProviders, prospecting, subsidiaries,
      avgRiskScore, gradeMap, poor, average, good,
      continuousBreakdown, oneTimeBreakdown,
      topCritical,
      digitalExposure, infraCoverage, assetCounts,
      activeDataLeaks, activeSecurityRisks,
      recentScans,
      vendorSummary: vendorSummaryData,
    });
  } catch (err) {
    logger.error({ err }, "TPRM dashboard error");
    res.status(500).json({ error: "Failed to load dashboard" });
  }
});

// ── Questionnaire Templates ────────────────────────────────────────────────────

router.get("/tprm/questionnaire-templates", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const rows = await db.select().from(tprmQuestionnaireTemplatesTable)
    .where(or(eq(tprmQuestionnaireTemplatesTable.tenantId, tenantId), eq(tprmQuestionnaireTemplatesTable.isGlobal, true))!)
    .orderBy(desc(tprmQuestionnaireTemplatesTable.createdAt));
  res.json(rows);
});

router.post("/tprm/questionnaire-templates", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId, role } = req.user!;
  const { name, description, category, questions, isGlobal } = req.body;
  if (!name) { res.status(400).json({ error: "name is required" }); return; }
  if (isGlobal && role !== "super_admin") { res.status(403).json({ error: "Only super_admin can create global templates" }); return; }
  const [row] = await db.insert(tprmQuestionnaireTemplatesTable).values({ tenantId, name, description: description ?? null, category: category ?? "security", questions: questions ?? [], isGlobal: !!isGlobal, createdBy: userId as any }).returning();
  res.status(201).json(row);
});

router.patch("/tprm/questionnaire-templates/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const id = parseInt(req.params.id as string);
  const { name, description, category, questions, isActive } = req.body;

  // super_admin can edit global templates; regular users can only edit their own
  const [existing] = await db.select({ id: tprmQuestionnaireTemplatesTable.id, isGlobal: tprmQuestionnaireTemplatesTable.isGlobal, tenantId: tprmQuestionnaireTemplatesTable.tenantId })
    .from(tprmQuestionnaireTemplatesTable)
    .where(eq(tprmQuestionnaireTemplatesTable.id, id));

  if (!existing) { res.status(404).json({ error: "Template not found" }); return; }
  if (existing.isGlobal && role !== "super_admin") { res.status(403).json({ error: "Only super_admin can edit global templates" }); return; }
  if (!existing.isGlobal && existing.tenantId !== tenantId) { res.status(404).json({ error: "Template not found" }); return; }

  const updates: Record<string, any> = { updatedAt: new Date() };
  if (name        !== undefined) updates.name        = name;
  if (description !== undefined) updates.description = description;
  if (category    !== undefined) updates.category    = category;
  if (questions   !== undefined) updates.questions   = questions;
  if (isActive    !== undefined) updates.isActive    = isActive;

  const [row] = await db.update(tprmQuestionnaireTemplatesTable)
    .set(updates)
    .where(eq(tprmQuestionnaireTemplatesTable.id, id))
    .returning();
  res.json(row);
});

router.delete("/tprm/questionnaire-templates/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id as string);
  await db.delete(tprmQuestionnaireTemplatesTable).where(and(eq(tprmQuestionnaireTemplatesTable.id, id), eq(tprmQuestionnaireTemplatesTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// ── Vendor Questionnaires ──────────────────────────────────────────────────────

router.post("/tprm/vendors/:id/questionnaires", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { templateId, dueDate, recipientEmail, notes } = req.body;
  if (!templateId) { res.status(400).json({ error: "templateId is required" }); return; }

  try {
    const [template] = await db.select().from(tprmQuestionnaireTemplatesTable)
      .where(and(
        eq(tprmQuestionnaireTemplatesTable.id, parseInt(templateId)),
        or(eq(tprmQuestionnaireTemplatesTable.tenantId, tenantId), eq(tprmQuestionnaireTemplatesTable.isGlobal, true))!
      ));
    if (!template) { res.status(404).json({ error: "Template not found" }); return; }

    const [q] = await db.insert(tprmVendorQuestionnairesTable).values({
      vendorId, tenantId,
      templateId: parseInt(templateId),
      status:      "sent",
      sentAt:      new Date(),
      dueDate:     dueDate ? new Date(dueDate) : null,
      respondedBy: recipientEmail ?? null,
      notes:       notes ?? null,
    }).returning();

    const platformDomain = process.env.REPLIT_DOMAINS?.split(",")[0];
    const baseUrl = platformDomain ? `https://${platformDomain}` : "https://your-platform.com";
    const portalLink = `${baseUrl}/tprm/respond/${q.accessToken}`;

    if (recipientEmail) {
      try {
        const { sendEmail } = await import("../lib/email");
        const dueDateStr = dueDate ? new Date(dueDate).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : "at your earliest convenience";
        await sendEmail({
          to: recipientEmail,
          subject: `[Sentinelware] Security Questionnaire — ${vendor.companyName}`,
          html: `<p>You have been asked to complete a security questionnaire by <strong>${vendor.companyName}</strong>.</p>
<p>Please complete the questionnaire by <strong>${dueDateStr}</strong>.</p>
${notes ? `<p>Notes: ${notes}</p>` : ""}
<p><a href="${portalLink}" style="display:inline-block;background:#3b82f6;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Complete Questionnaire</a></p>
<p>Or copy this link: ${portalLink}</p>`,
        });
      } catch (emailErr) {
        logger.warn({ emailErr, recipientEmail }, "TPRM: questionnaire email dispatch failed (non-fatal)");
      }
    }

    logger.info({ questionnaireId: q.id, portalLink, recipientEmail }, "TPRM: questionnaire sent");
    res.status(201).json({ ...q, portalLink });
  } catch (err) {
    logger.error({ err }, "TPRM send questionnaire error");
    res.status(500).json({ error: "Failed to send questionnaire" });
  }
});

router.get("/tprm/vendors/:id/questionnaires", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmVendorQuestionnairesTable).where(and(eq(tprmVendorQuestionnairesTable.vendorId, vendorId), eq(tprmVendorQuestionnairesTable.tenantId, tenantId))).orderBy(desc(tprmVendorQuestionnairesTable.createdAt));
  const tplIds = [...new Set(rows.filter(q => q.templateId).map(q => q.templateId!))];
  const tplRows = tplIds.length > 0 ? await db.select({ id: tprmQuestionnaireTemplatesTable.id, name: tprmQuestionnaireTemplatesTable.name }).from(tprmQuestionnaireTemplatesTable).where(inArray(tprmQuestionnaireTemplatesTable.id, tplIds)) : [];
  const tplMap = new Map(tplRows.map(t => [t.id, t.name]));
  res.json(rows.map(q => ({ ...q, responses: undefined, templateName: q.templateId ? (tplMap.get(q.templateId) ?? null) : null })));
});

router.patch("/tprm/vendors/:id/questionnaires/:qid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const qid = parseInt(req.params.qid as string);
  const [existing] = await db.select().from(tprmVendorQuestionnairesTable)
    .where(and(eq(tprmVendorQuestionnairesTable.id, qid), eq(tprmVendorQuestionnairesTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Questionnaire not found" }); return; }
  const { status, dueDate, respondedBy, notes, score } = req.body;
  const updates: Record<string, any> = {};
  if (status     !== undefined) updates.status      = status;
  if (respondedBy !== undefined) updates.respondedBy = respondedBy;
  if (notes      !== undefined) updates.notes       = notes;
  if (score      !== undefined) updates.score       = score !== null ? parseInt(score) : null;
  if (dueDate    !== undefined) updates.dueDate     = dueDate === "" || dueDate === null ? null : new Date(dueDate);
  if (status === "completed" && !existing.completedAt) updates.completedAt = new Date();
  const [updated] = await db.update(tprmVendorQuestionnairesTable).set(updates)
    .where(and(eq(tprmVendorQuestionnairesTable.id, qid), eq(tprmVendorQuestionnairesTable.tenantId, tenantId))).returning();
  res.json({ ...updated, responses: undefined });
});

router.delete("/tprm/vendors/:id/questionnaires/:qid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const qid = parseInt(req.params.qid as string);
  const [existing] = await db.select().from(tprmVendorQuestionnairesTable)
    .where(and(eq(tprmVendorQuestionnairesTable.id, qid), eq(tprmVendorQuestionnairesTable.tenantId, tenantId)));
  if (!existing) { res.status(404).json({ error: "Questionnaire not found" }); return; }
  await db.delete(tprmVendorQuestionnairesTable)
    .where(and(eq(tprmVendorQuestionnairesTable.id, qid), eq(tprmVendorQuestionnairesTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// Apply questionnaire score to vendor risk — triggers a full vendor rescan in background
router.post("/tprm/vendors/:id/questionnaires/:qid/apply-risk", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const qid = parseInt(req.params.qid as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const [q] = await db.select().from(tprmVendorQuestionnairesTable)
    .where(and(eq(tprmVendorQuestionnairesTable.id, qid), eq(tprmVendorQuestionnairesTable.tenantId, tenantId)));
  if (!q) { res.status(404).json({ error: "Questionnaire not found" }); return; }
  // Mark completed if not already
  if (q.status !== "completed") {
    await db.update(tprmVendorQuestionnairesTable)
      .set({ status: "completed", completedAt: new Date() })
      .where(eq(tprmVendorQuestionnairesTable.id, qid));
  }
  // Trigger background rescan to blend questionnaire score into overall vendor risk
  setImmediate(() => {
    runFullVendorScan(vendorId, tenantId).catch(err =>
      logger.warn({ err, vendorId }, "TPRM: apply-risk rescan failed")
    );
  });
  res.json({ ok: true, message: "Risk recalculation triggered. Vendor risk score will update shortly." });
});

router.get("/tprm/questionnaires/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id as string);
  const [q] = await db.select().from(tprmVendorQuestionnairesTable).where(and(eq(tprmVendorQuestionnairesTable.id, id), eq(tprmVendorQuestionnairesTable.tenantId, tenantId)));
  if (!q) { res.status(404).json({ error: "Questionnaire not found" }); return; }
  const [template] = q.templateId ? await db.select().from(tprmQuestionnaireTemplatesTable).where(eq(tprmQuestionnaireTemplatesTable.id, q.templateId)) : [null];
  res.json({ ...q, template });
});

// ── Public vendor respond routes (no requireAuth) ─────────────────────────────

router.get("/tprm/respond/:token", async (req, res) => {
  const { token } = req.params;
  try {
    const [q] = await db.select().from(tprmVendorQuestionnairesTable).where(eq(tprmVendorQuestionnairesTable.accessToken, token as any));
    if (!q) { res.status(404).json({ error: "Questionnaire not found or expired" }); return; }
    if (q.status === "expired") { res.status(410).json({ error: "This questionnaire link has expired" }); return; }
    // Enforce due-date expiry: auto-expire and reject if past due and not yet completed
    if (q.dueDate && new Date(q.dueDate) < new Date() && q.status !== "completed") {
      await db.update(tprmVendorQuestionnairesTable).set({ status: "expired" }).where(eq(tprmVendorQuestionnairesTable.id, q.id));
      res.status(410).json({ error: "This questionnaire link has expired (past due date)" }); return;
    }
    const [template] = q.templateId ? await db.select().from(tprmQuestionnaireTemplatesTable).where(eq(tprmQuestionnaireTemplatesTable.id, q.templateId)) : [null];
    const [vendor] = await db.select({ id: tprmVendorsTable.id, companyName: tprmVendorsTable.companyName }).from(tprmVendorsTable).where(eq(tprmVendorsTable.id, q.vendorId));
    const rawQuestions: any[] = (template?.questions as any[]) ?? [];
    const publicQuestions = rawQuestions.map(({ weight: _w, ...q }) => q);
    res.json({
      id:          q.id,
      status:      q.status,
      dueDate:     q.dueDate,
      vendorName:  vendor?.companyName ?? "Unknown",
      templateName: template?.name ?? "Security Questionnaire",
      questions:   publicQuestions,
      alreadyCompleted: q.status === "completed",
    });
  } catch (err) {
    logger.error({ err }, "TPRM respond GET error");
    res.status(500).json({ error: "Failed to load questionnaire" });
  }
});

router.post("/tprm/respond/:token", async (req, res) => {
  const { token } = req.params;
  const { responses, respondedBy } = req.body;
  try {
    const [q] = await db.select().from(tprmVendorQuestionnairesTable).where(eq(tprmVendorQuestionnairesTable.accessToken, token as any));
    if (!q) { res.status(404).json({ error: "Questionnaire not found" }); return; }
    if (q.status === "completed") { res.status(409).json({ error: "Questionnaire already completed" }); return; }
    if (q.status === "expired") { res.status(410).json({ error: "Questionnaire link has expired" }); return; }
    // Enforce due-date: reject submission if past due
    if (q.dueDate && new Date(q.dueDate) < new Date()) {
      await db.update(tprmVendorQuestionnairesTable).set({ status: "expired" }).where(eq(tprmVendorQuestionnairesTable.id, q.id));
      res.status(410).json({ error: "Questionnaire link has expired (past due date)" }); return;
    }

    // Weighted scoring: each question may carry a weight (default 1); sum(score*weight)/sum(weight)
    const [template] = q.templateId ? await db.select().from(tprmQuestionnaireTemplatesTable).where(eq(tprmQuestionnaireTemplatesTable.id, q.templateId)) : [null];
    const questions = (template?.questions as any[]) ?? [];
    let totalWeighted = 0, totalWeight = 0;
    for (const ans of (responses as any[]) ?? []) {
      const q_def = questions.find((qd: any) => qd.id === ans.questionId);
      if (!q_def) continue;
      const w = typeof q_def.weight === "number" && q_def.weight > 0 ? q_def.weight : 1;
      if (q_def.type === "boolean") {
        totalWeighted += (ans.answer === true || ans.answer === "yes" ? 100 : 0) * w;
        totalWeight += w;
      } else if (q_def.type === "rating") {
        const rating = parseInt(String(ans.answer), 10);
        if (!isNaN(rating)) { totalWeighted += (rating / 5) * 100 * w; totalWeight += w; }
      }
    }
    // When no weighted (boolean/rating) questions answered, score is indeterminate
    const score: number | null = totalWeight > 0 ? Math.round(totalWeighted / totalWeight) : null;
    const riskLevel: string | null = score === null ? null : score >= 80 ? "low" : score >= 60 ? "medium" : score >= 40 ? "high" : "critical";

    await db.update(tprmVendorQuestionnairesTable).set({
      status:      "completed",
      completedAt: new Date(),
      respondedBy: respondedBy ?? q.respondedBy,
      responses,
      score,
      riskLevel,
    }).where(eq(tprmVendorQuestionnairesTable.id, q.id));

    // Dispatch questionnaire completion notification through the full notification pipeline
    // (inserts DB alert + fires tenant alert rules + platform fallbacks)
    try {
      const { dispatchNotifications } = await import("../lib/notifier");
      const [v] = await db.select({ companyName: tprmVendorsTable.companyName }).from(tprmVendorsTable).where(eq(tprmVendorsTable.id, q.vendorId));
      await dispatchNotifications({
        tenantId: q.tenantId,
        eventType: "tprm_questionnaire_completed",
        title: `Questionnaire completed — ${v?.companyName ?? `vendor #${q.vendorId}`}`,
        message: `Security questionnaire completed${respondedBy ? ` by ${respondedBy}` : ""}. Score: ${score}/100 (${riskLevel} risk).`,
        severity: riskLevel === "critical" ? "critical" : riskLevel === "high" ? "high" : "medium",
      });
    } catch { /* non-fatal */ }

    // Trigger background rescan so latest questionnaire score is blended into risk score
    setImmediate(() => {
      runFullVendorScan(q.vendorId, q.tenantId).catch(err =>
        logger.warn({ err, vendorId: q.vendorId }, "TPRM: rescan after questionnaire completion failed")
      );
    });

    res.json({ ok: true, score, riskLevel, message: "Your response has been recorded. Thank you." });
  } catch (err) {
    logger.error({ err }, "TPRM respond POST error");
    res.status(500).json({ error: "Failed to submit response" });
  }
});

// ── Compliance Documents ───────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/compliance", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const [docs, reqs] = await Promise.all([
    db.select().from(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.vendorId, vendorId), eq(tprmComplianceDocumentsTable.tenantId, tenantId))).orderBy(desc(tprmComplianceDocumentsTable.createdAt)),
    db.select().from(tprmComplianceRequirementsTable).where(and(eq(tprmComplianceRequirementsTable.vendorId, vendorId), eq(tprmComplianceRequirementsTable.tenantId, tenantId))),
  ]);
  const safeDoc = (d: any) => ({ ...d, fileData: undefined });
  const today = new Date();
  const gaps = reqs.filter(r => r.required && !docs.find(d => d.documentType === r.documentType && d.status !== "expired")).map(r => r.documentType);
  res.json({ documents: docs.map(safeDoc), requirements: reqs, gaps });
});

router.post("/tprm/vendors/:id/compliance", requireAuth, requireTprm, upload.single("file"), async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { documentType, title, auditor, auditPeriodStart, auditPeriodEnd, expiresAt, coverageScope } = req.body;
  if (!documentType || !title) { res.status(400).json({ error: "documentType and title are required" }); return; }

  let fileData: string | null = null, fileName: string | null = null, fileSize: number | null = null;
  if (req.file) {
    fileData = req.file.buffer.toString("base64");
    fileName = req.file.originalname;
    fileSize = req.file.size;
  }

  const today = new Date();
  const expDate = expiresAt ? new Date(expiresAt) : null;
  const status = !expDate ? "pending_review" : expDate < today ? "expired" : (expDate.getTime() - today.getTime() < 30 * 86400000 ? "expiring_soon" : "valid");

  const [doc] = await db.insert(tprmComplianceDocumentsTable).values({
    vendorId, tenantId, documentType, title, auditor: auditor ?? null,
    auditPeriodStart: auditPeriodStart ?? null, auditPeriodEnd: auditPeriodEnd ?? null,
    expiresAt: expiresAt ?? null, status, coverageScope: coverageScope ?? null,
    fileData, fileName, fileSize, uploadedBy: userId as any,
  }).returning();
  res.status(201).json({ ...doc, fileData: undefined });
});

router.patch("/tprm/vendors/:id/compliance/:docId", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId as string);
  const allowed = ["auditor", "auditPeriodStart", "auditPeriodEnd", "expiresAt", "coverageScope", "title", "status"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }

  // Auto-recalculate status from expiry date when expiresAt changes (unless caller explicitly sets status)
  if (updates.expiresAt !== undefined && updates.status === undefined) {
    const today = new Date();
    const expDate = updates.expiresAt ? new Date(updates.expiresAt) : null;
    if (!expDate) {
      updates.status = "pending_review";
    } else if (expDate < today) {
      updates.status = "expired";
    } else if (expDate.getTime() - today.getTime() < 30 * 86400000) {
      updates.status = "expiring_soon";
    } else {
      updates.status = "valid";
    }
  }

  const [doc] = await db.update(tprmComplianceDocumentsTable).set(updates).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId))).returning();
  if (!doc) { res.status(404).json({ error: "Document not found" }); return; }
  res.json({ ...doc, fileData: undefined });
});

// Bulk auto-verify: set docs with future expiry to "valid"
router.post("/tprm/vendors/:id/compliance/auto-verify", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const today = new Date();
  const docs = await db.select().from(tprmComplianceDocumentsTable)
    .where(and(eq(tprmComplianceDocumentsTable.vendorId, vendorId), eq(tprmComplianceDocumentsTable.tenantId, tenantId)));
  let verified = 0;
  for (const doc of docs) {
    if (doc.status === "pending_review" && doc.expiresAt) {
      const exp = new Date(doc.expiresAt);
      if (exp > today) {
        const newStatus = exp.getTime() - today.getTime() < 30 * 86400000 ? "expiring_soon" : "valid";
        await db.update(tprmComplianceDocumentsTable).set({ status: newStatus, updatedAt: new Date() }).where(eq(tprmComplianceDocumentsTable.id, doc.id));
        verified++;
      }
    }
  }
  res.json({ ok: true, verified, message: `Auto-verified ${verified} document${verified !== 1 ? "s" : ""}` });
});

router.delete("/tprm/vendors/:id/compliance/:docId", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId as string);
  await db.delete(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId)));
  res.json({ ok: true });
});

router.get("/tprm/vendors/:id/compliance/:docId/download", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId as string);
  const [doc] = await db.select().from(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId)));
  if (!doc?.fileData) { res.status(404).json({ error: "File not found" }); return; }
  const buf = Buffer.from(doc.fileData, "base64");
  res.setHeader("Content-Disposition", `attachment; filename="${doc.fileName ?? "document"}"`);
  res.setHeader("Content-Type", "application/octet-stream");
  res.send(buf);
});

router.get("/tprm/compliance/expiring", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const sixtyDaysOut = new Date(Date.now() + 60 * 86400000).toISOString().split("T")[0];
  const today = new Date().toISOString().split("T")[0];
  const docs = await db.select().from(tprmComplianceDocumentsTable)
    .where(and(
      eq(tprmComplianceDocumentsTable.tenantId, tenantId),
      sql`expires_at IS NOT NULL AND expires_at >= ${today} AND expires_at <= ${sixtyDaysOut}`
    ))
    .orderBy(asc(tprmComplianceDocumentsTable.expiresAt));
  res.json(docs.map(d => ({
    ...d,
    fileData: undefined,
    daysRemaining: d.expiresAt ? Math.ceil((new Date(d.expiresAt).getTime() - Date.now()) / 86400000) : null,
  })));
});

// ── SBOM ──────────────────────────────────────────────────────────────────────

router.post("/tprm/vendors/:id/sbom", requireAuth, requireTprm, upload.single("file"), async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  if (!req.file) { res.status(400).json({ error: "SBOM file is required" }); return; }

  try {
    const content   = req.file.buffer.toString("utf-8");
    const fileName  = req.file.originalname;
    const format    = detectSbomFormat(content, fileName);
    const parsed    = parseSbom(content, format);

    const [upload] = await db.insert(tprmSbomUploadsTable).values({
      vendorId, tenantId,
      fileName, format,
      specVersion:              parsed.specVersion ?? null,
      toolName:                 parsed.toolName ?? null,
      componentCount:           parsed.components.length,
      vulnerableComponentCount: 0,
      fileData:                 req.file.buffer.toString("base64"),
      uploadedBy:               userId as any,
    }).returning();

    // Background enrichment
    setImmediate(async () => {
      try {
        const enriched = await enrichSbomWithVulnerabilities(parsed.components);
        let vulnCount = 0;

        if (enriched.length > 0) {
          const nodes = enriched.map(e => ({
            vendorId, tenantId,
            name:            e.component.name,
            version:         e.component.version ?? null,
            nodeType:        "software" as const,
            cpe:             e.component.cpe ?? null,
            purl:            e.component.purl ?? null,
            license:         e.component.licenses[0] ?? null,
            supplier:        e.component.supplier ?? null,
            riskLevel:       e.riskLevel === "none" ? "low" : e.riskLevel,
            vulnerabilities: e.vulns as any,
            sbomUploadId:    upload.id,
          }));
          await db.insert(tprmSupplyChainNodesTable).values(nodes);
          vulnCount = enriched.filter(e => e.vulns.length > 0).length;
        }

        await db.update(tprmSbomUploadsTable).set({ vulnerableComponentCount: vulnCount }).where(eq(tprmSbomUploadsTable.id, upload.id));
      } catch (err) {
        logger.error({ err, uploadId: upload.id }, "TPRM SBOM enrichment failed");
      }
    });

    res.status(201).json({
      uploadId:        upload.id,
      format,
      specVersion:     parsed.specVersion,
      toolName:        parsed.toolName,
      componentCount:  parsed.components.length,
      vulnerableCount: 0,
      criticalCount:   0,
      message:         "SBOM uploaded. Vulnerability enrichment is running in the background.",
    });
  } catch (err) {
    logger.error({ err }, "TPRM SBOM upload error");
    res.status(500).json({ error: "Failed to process SBOM file" });
  }
});

router.get("/tprm/vendors/:id/sbom", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmSbomUploadsTable).where(and(eq(tprmSbomUploadsTable.vendorId, vendorId), eq(tprmSbomUploadsTable.tenantId, tenantId))).orderBy(desc(tprmSbomUploadsTable.createdAt));
  res.json(rows.map(r => ({ ...r, fileData: undefined })));
});

router.get("/tprm/sbom/:uploadId/components", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const uploadId = parseInt(req.params.uploadId as string);
  const { riskLevel, page = "1", limit = "100" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const conds: any[] = [eq(tprmSupplyChainNodesTable.sbomUploadId, uploadId), eq(tprmSupplyChainNodesTable.tenantId, tenantId)];
  if (riskLevel) conds.push(eq(tprmSupplyChainNodesTable.riskLevel, riskLevel));
  const [nodes, [countRow]] = await Promise.all([
    db.select().from(tprmSupplyChainNodesTable).where(and(...conds)).limit(parseInt(limit)).offset(offset),
    db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(...conds)),
  ]);
  res.json({ components: nodes, total: countRow?.count ?? 0 });
});

router.get("/tprm/sbom/:uploadId/vulnerabilities", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const uploadId = parseInt(req.params.uploadId as string);
  const nodes = await db.select().from(tprmSupplyChainNodesTable)
    .where(and(eq(tprmSupplyChainNodesTable.sbomUploadId, uploadId), eq(tprmSupplyChainNodesTable.tenantId, tenantId), sql`jsonb_array_length(vulnerabilities) > 0`));
  const vulns: any[] = [];
  for (const node of nodes) {
    for (const v of (node.vulnerabilities as any[]) ?? []) {
      vulns.push({ ...v, component: node.name, version: node.version, purl: node.purl });
    }
  }

  // Enrich CVE aliases with EPSS + KEV data
  try {
    const cveEntries = vulns.filter(v => {
      const id: string = v.id ?? "";
      return id.startsWith("CVE-") || (v.aliases ?? []).some((a: string) => a.startsWith("CVE-"));
    });
    if (cveEntries.length > 0) {
      const mapped = cveEntries.map(v => ({
        cve:      (v.aliases ?? []).find((a: string) => a.startsWith("CVE-")) ?? v.id,
        severity: v.severity ?? "medium",
        title:    v.summary ?? v.id,
        cvss:     v.cvss ?? null,
      }));
      const enriched = await enrichFindingsWithEpssKev(mapped as any[]);
      for (const ev of enriched as any[]) {
        const match = vulns.find(v =>
          v.id === ev.cve || (v.aliases ?? []).includes(ev.cve)
        );
        if (match) {
          match.epss  = ev.epss  ?? null;
          match.isKev = ev.isKev ?? false;
        }
      }
    }
  } catch { /* non-fatal — return unenriched vulns */ }

  res.json(vulns);
});

// ── Vendor contacts ────────────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/contacts", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  res.json(await db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.vendorId, vendorId), eq(tprmVendorContactsTable.tenantId, tenantId))));
});

router.post("/tprm/vendors/:id/contacts", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { name, email, role: contactRole, isPrimary } = req.body;
  if (!name || !email) { res.status(400).json({ error: "name and email are required" }); return; }
  const [row] = await db.insert(tprmVendorContactsTable).values({ vendorId, tenantId, name, email, role: contactRole ?? null, isPrimary: !!isPrimary }).returning();
  res.status(201).json(row);
});

router.delete("/tprm/vendors/:id/contacts/:cid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const contactId = parseInt(req.params.cid as string);
  await db.delete(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.id, contactId), eq(tprmVendorContactsTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// #14: Send email to vendor contact
router.post("/tprm/vendors/:id/contacts/:cid/send-email", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const contactId = parseInt(req.params.cid as string);
  const { subject, message } = req.body;
  if (!subject || !message) { res.status(400).json({ error: "subject and message are required" }); return; }
  const [contact] = await db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.id, contactId), eq(tprmVendorContactsTable.tenantId, tenantId)));
  if (!contact) { res.status(404).json({ error: "Contact not found" }); return; }
  try {
    const { sendEmail } = await import("../lib/email");
    await sendEmail({ to: contact.email, subject, html: `<p>${message.replace(/\n/g, "<br>")}</p>` });
    res.json({ ok: true, message: `Email sent to ${contact.email}` });
  } catch (err) {
    logger.warn({ err, contactId }, "TPRM: contact send-email failed");
    res.status(500).json({ error: "Failed to send email — check email provider configuration" });
  }
});

// #11: Send verification email to contact
router.post("/tprm/vendors/:id/contacts/:cid/send-verification", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const contactId = parseInt(req.params.cid as string);
  const [contact] = await db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.id, contactId), eq(tprmVendorContactsTable.tenantId, tenantId)));
  if (!contact) { res.status(404).json({ error: "Contact not found" }); return; }
  if (contact.isEmailVerified) { res.json({ ok: true, message: "Contact already verified" }); return; }
  const { randomBytes } = await import("node:crypto");
  const token = randomBytes(32).toString("hex");
  await db.update(tprmVendorContactsTable).set({ emailVerificationToken: token }).where(eq(tprmVendorContactsTable.id, contactId));
  const platformDomain = process.env.REPLIT_DOMAINS?.split(",")[0];
  const baseUrl = platformDomain ? `https://${platformDomain}` : "https://your-platform.com";
  const verifyLink = `${baseUrl}/api/tprm/contacts/verify/${token}`;
  try {
    const { sendEmail } = await import("../lib/email");
    await sendEmail({
      to: contact.email,
      subject: "[Sentinelware] Please verify your email address",
      html: `<p>Hi ${contact.name},</p><p>Please verify your email address by clicking the link below:</p><p><a href="${verifyLink}" style="display:inline-block;background:#3b82f6;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none">Verify Email</a></p><p>Or copy: ${verifyLink}</p>`,
    });
    res.json({ ok: true, message: `Verification email sent to ${contact.email}` });
  } catch (err) {
    logger.warn({ err }, "TPRM: send-verification email failed");
    res.status(500).json({ error: "Failed to send verification email — check email provider configuration" });
  }
});

// #11: Public email verification callback
router.get("/tprm/contacts/verify/:token", async (req, res: any) => {
  const { token } = req.params as { token: string };
  const [contact] = await db.select().from(tprmVendorContactsTable).where(eq(tprmVendorContactsTable.emailVerificationToken, token));
  if (!contact) { res.status(400).send("<h2>Invalid or expired verification link.</h2>"); return; }
  await db.update(tprmVendorContactsTable).set({ isEmailVerified: true, emailVerifiedAt: new Date(), emailVerificationToken: null }).where(eq(tprmVendorContactsTable.id, contact.id));
  res.send("<h2 style='font-family:sans-serif;color:#22c55e'>✓ Email verified successfully. You may close this tab.</h2>");
});

// ── Compliance Requirements Management ────────────────────────────────────────

router.post("/tprm/vendors/:id/compliance-requirements", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { documentType, required, dueDate, reminderDays, notes } = req.body;
  if (!documentType) { res.status(400).json({ error: "documentType is required" }); return; }
  const [row] = await db.insert(tprmComplianceRequirementsTable).values({
    vendorId, tenantId, documentType, required: required !== false, dueDate: dueDate ?? null, reminderDays: reminderDays ?? 30, notes: notes ?? null,
  }).returning();
  res.status(201).json(row);
});

router.delete("/tprm/vendors/:id/compliance-requirements/:reqId", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const reqId = parseInt(req.params.reqId as string);
  await db.delete(tprmComplianceRequirementsTable).where(and(eq(tprmComplianceRequirementsTable.id, reqId), eq(tprmComplianceRequirementsTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// #15: Notify vendors about compliance requirements (send email)
router.post("/tprm/vendors/:id/compliance-requirements/:reqId/notify", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const reqId = parseInt(req.params.reqId as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const [req_] = await db.select().from(tprmComplianceRequirementsTable).where(and(eq(tprmComplianceRequirementsTable.id, reqId), eq(tprmComplianceRequirementsTable.tenantId, tenantId)));
  if (!req_) { res.status(404).json({ error: "Requirement not found" }); return; }
  const contacts = await db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.vendorId, vendorId), eq(tprmVendorContactsTable.tenantId, tenantId)));
  const targets = contacts.filter(c => c.isPrimary || contacts.length === 1);
  if (targets.length === 0) { res.status(400).json({ error: "No primary contacts to notify" }); return; }
  try {
    const { sendEmail } = await import("../lib/email");
    const due = req_.dueDate ? new Date(req_.dueDate).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }) : "as soon as possible";
    for (const contact of targets) {
      await sendEmail({
        to: contact.email,
        subject: `[Sentinelware] Compliance Document Required: ${req_.documentType}`,
        html: `<p>Hi ${contact.name},</p><p>A compliance document is required from <strong>${vendor.companyName}</strong>:</p><ul><li><strong>Document type:</strong> ${req_.documentType}</li><li><strong>Required by:</strong> ${due}</li>${req_.notes ? `<li><strong>Notes:</strong> ${req_.notes}</li>` : ""}</ul><p>Please submit the document to your account manager at your earliest convenience.</p>`,
      });
    }
    res.json({ ok: true, notified: targets.length });
  } catch (err) {
    logger.warn({ err }, "TPRM: compliance requirement notify failed");
    res.status(500).json({ error: "Failed to send notification — check email provider configuration" });
  }
});

// ── AI Compliance Document Parsing ────────────────────────────────────────────
// #8: Use AI to extract key fields from uploaded compliance documents

router.post("/tprm/vendors/:id/compliance/:docId/ai-parse", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId as string);
  const [doc] = await db.select().from(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId)));
  if (!doc) { res.status(404).json({ error: "Document not found" }); return; }
  if (!doc.fileData) { res.status(400).json({ error: "Document has no file attached" }); return; }

  try {
    const { llmComplete, isLLMAvailable } = await import("../lib/llm.js");
    if (!isLLMAvailable()) { res.status(503).json({ error: "AI not configured — set OPENAI_API_KEY to enable" }); return; }

    // Decode base64 → text (handle PDF/text; truncate to 8000 chars for context)
    const rawText = Buffer.from(doc.fileData, "base64").toString("utf-8", 0, 16000).slice(0, 8000);
    const prompt = `You are a compliance analyst. Extract key information from this document text and return ONLY a JSON object with these fields: { "documentType": string, "auditor": string|null, "auditPeriodStart": "YYYY-MM-DD"|null, "auditPeriodEnd": "YYYY-MM-DD"|null, "expiresAt": "YYYY-MM-DD"|null, "coverageScope": string|null, "summary": string }. Document text:\n\n${rawText}`;

    const result = await llmComplete([{ role: "user", content: prompt }], { maxTokens: 500 });
    const jsonMatch = result?.text?.match(/\{[\s\S]+\}/);
    if (!jsonMatch) { res.status(500).json({ error: "AI could not parse document" }); return; }
    const parsed = JSON.parse(jsonMatch[0]);

    // Auto-apply extracted fields to the document
    const updates: Record<string, any> = { updatedAt: new Date() };
    if (parsed.auditor)          updates.auditor          = parsed.auditor;
    if (parsed.auditPeriodStart) updates.auditPeriodStart = parsed.auditPeriodStart;
    if (parsed.auditPeriodEnd)   updates.auditPeriodEnd   = parsed.auditPeriodEnd;
    if (parsed.expiresAt) {
      updates.expiresAt = parsed.expiresAt;
      const today = new Date(); const exp = new Date(parsed.expiresAt);
      updates.status = exp < today ? "expired" : exp.getTime() - today.getTime() < 30 * 86400000 ? "expiring_soon" : "valid";
    }
    if (parsed.coverageScope) updates.coverageScope = parsed.coverageScope;
    await db.update(tprmComplianceDocumentsTable).set(updates).where(eq(tprmComplianceDocumentsTable.id, docId));
    res.json({ ok: true, parsed, applied: Object.keys(updates).filter(k => k !== "updatedAt") });
  } catch (err) {
    logger.warn({ err, docId }, "TPRM: AI compliance parse failed");
    res.status(500).json({ error: "AI parsing failed" });
  }
});

// ── SBOM Automated Discovery ──────────────────────────────────────────────────
// #7: Crawl vendor domain for SBOM files at well-known paths

router.post("/tprm/vendors/:id/sbom/discover", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }

  const WELL_KNOWN_PATHS = [
    "/.well-known/sbom", "/.well-known/sbom.json", "/sbom.json", "/sbom.xml",
    "/bom.json", "/bom.xml", "/.well-known/security.json",
    "/security/sbom.json", "/docs/sbom.json",
  ];

  res.json({ ok: true, message: "SBOM discovery started — check SBOM tab in a moment", vendorId });

  setImmediate(async () => {
    try {
      const baseUrls = [`https://${vendor.domain}`, `https://www.${vendor.domain}`];
      for (const base of baseUrls) {
        for (const path of WELL_KNOWN_PATHS) {
          try {
            const ctrl = new AbortController();
            const t = setTimeout(() => ctrl.abort(), 8000);
            const r = await fetch(`${base}${path}`, { signal: ctrl.signal, headers: { "User-Agent": "Sentinelware-TPRM/1.0" } });
            clearTimeout(t);
            if (!r.ok) continue;
            const ct = r.headers.get("content-type") ?? "";
            if (!ct.includes("json") && !ct.includes("xml") && !ct.includes("text")) continue;
            const content = await r.text();
            if (content.length < 50) continue;
            const fileName = path.split("/").pop() ?? "sbom.json";
            const format = detectSbomFormat(content, fileName);
            const parsed = parseSbom(content, format);
            if (parsed.components.length === 0) continue;

            // Save upload record
            const [upload] = await db.insert(tprmSbomUploadsTable).values({
              vendorId, tenantId,
              fileName: `discovered-${fileName}`,
              format,
              specVersion: parsed.specVersion ?? null,
              toolName: parsed.toolName ?? null,
              componentCount: parsed.components.length,
              fileData: Buffer.from(content).toString("base64"),
              uploadedBy: userId as any,
            }).returning();

            // Enrich with vulnerabilities in background
            const enriched = await enrichSbomWithVulnerabilities(parsed.components);
            const vulnCount = enriched.filter(e => e.vulns.length > 0).length;
            await db.update(tprmSbomUploadsTable).set({ vulnerableComponentCount: vulnCount }).where(eq(tprmSbomUploadsTable.id, upload.id));
            if (enriched.length > 0) {
              await db.insert(tprmSupplyChainNodesTable).values(
                enriched.map(e => ({
                  vendorId, tenantId,
                  name: e.component.name, version: e.component.version ?? null,
                  nodeType: "software" as const, cpe: e.component.cpe ?? null, purl: e.component.purl ?? null,
                  license: e.component.licenses[0] ?? null, supplier: e.component.supplier ?? null,
                  riskLevel: e.riskLevel === "none" ? "low" : e.riskLevel,
                  vulnerabilities: e.vulns, sbomUploadId: upload.id,
                }))
              );
            }
            logger.info({ vendorId, path, components: parsed.components.length }, "TPRM: auto-discovered SBOM");
            return; // Stop after first successful SBOM
          } catch { /* try next path */ }
        }
      }
      logger.info({ vendorId }, "TPRM: no SBOM found at well-known paths");
    } catch (err) {
      logger.warn({ err, vendorId }, "TPRM: SBOM discovery failed");
    }
  });
});

// ── 4th Party → Platform Asset Findings ──────────────────────────────────────
// #16: Propagate critical/high 4th party risks as platform asset findings

router.post("/tprm/vendors/:id/propagate-findings", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }

  const criticalFindings = await db.select().from(tprmVendorFindingsTable)
    .where(and(
      eq(tprmVendorFindingsTable.vendorId, vendorId),
      eq(tprmVendorFindingsTable.tenantId, tenantId),
      or(eq(tprmVendorFindingsTable.severity, "critical"), eq(tprmVendorFindingsTable.severity, "high"))!,
      eq(tprmVendorFindingsTable.status, "open"),
    )).limit(20);

  if (criticalFindings.length === 0) { res.json({ ok: true, propagated: 0, message: "No critical/high findings to propagate" }); return; }

  // Create platform alerts for each finding
  let propagated = 0;
  for (const f of criticalFindings) {
    try {
      await db.insert(alertsTable).values({
        tenantId,
        title: `[TPRM] ${vendor.companyName}: ${f.title}`,
        message: `Third-party risk finding from vendor ${vendor.companyName} (${vendor.domain}): ${f.description ?? f.title}. Severity: ${f.severity}. ${f.cve ? `CVE: ${f.cve}.` : ""}`,
        type: "tprm_vendor_finding_propagated" as any,
        severity: f.severity,
      });
      propagated++;
    } catch { /* non-fatal per finding */ }
  }
  res.json({ ok: true, propagated, message: `Propagated ${propagated} finding${propagated !== 1 ? "s" : ""} to platform alerts` });
});

// ── Recursive 4th Party Security Scanning ────────────────────────────────────
// #9: For each discovered 4th party, run a lightweight security probe on their domain

router.post("/tprm/vendors/:id/fourth-party/deep-scan", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }

  const fourthParties = await db.select().from(tprmFourthPartyVendorsTable)
    .where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, tenantId)))
    .limit(10);

  if (fourthParties.length === 0) { res.json({ ok: true, scanned: 0, message: "No 4th parties to scan — run a vendor scan first" }); return; }

  res.json({ ok: true, scanned: fourthParties.length, message: `Deep scanning ${fourthParties.length} 4th party vendor${fourthParties.length !== 1 ? "s" : ""}` });

  setImmediate(async () => {
    for (const fp of fourthParties) {
      if (!fp.domain) continue;
      try {
        const dns_ = await import("node:dns/promises");
        const ips = await dns_.resolve4(fp.domain).catch(() => [] as string[]);

        // Check Shodan InternetDB for each IP
        const shodanResults: { ip: string; vulns: string[]; ports: number[] }[] = [];
        for (const ip of ips.slice(0, 3)) {
          try {
            const r = await fetch(`https://internetdb.shodan.io/${ip}`, { headers: { "User-Agent": "Sentinelware-TPRM/1.0" }, signal: AbortSignal.timeout(8000) });
            if (r.ok) {
              const data: any = await r.json().catch(() => null);
              if (data) shodanResults.push({ ip, vulns: data.vulns ?? [], ports: data.ports ?? [] });
            }
          } catch { /* ignore per-IP */ }
        }

        const totalVulns = shodanResults.reduce((n, s) => n + s.vulns.length, 0);
        const dangerousPorts = [22, 23, 3389, 21, 25, 110, 143, 3306, 5432, 6379, 27017].filter(p => shodanResults.some(s => s.ports.includes(p)));
        const newRisk = totalVulns > 5 || dangerousPorts.length > 0 ? "high" : totalVulns > 0 ? "medium" : "low";

        await db.update(tprmFourthPartyVendorsTable)
          .set({ riskLevel: newRisk, details: { shodanResults: shodanResults.slice(0, 3), dangerousPorts, scannedAt: new Date().toISOString() } })
          .where(eq(tprmFourthPartyVendorsTable.id, fp.id));

        // If high risk, create a finding on the parent vendor
        if (newRisk === "high") {
          const cves = [...new Set(shodanResults.flatMap(s => s.vulns))].slice(0, 3);
          await db.insert(tprmVendorFindingsTable).values({
            vendorId, tenantId,
            title: `4th party risk: ${fp.name} (${fp.domain}) has critical exposure`,
            severity: "high",
            category: "fourth_party",
            description: `Shodan found ${totalVulns} known CVE${totalVulns !== 1 ? "s" : ""} on ${fp.domain} IPs. ${dangerousPorts.length > 0 ? `Dangerous ports open: ${dangerousPorts.join(", ")}.` : ""} ${cves.length > 0 ? `CVEs: ${cves.join(", ")}.` : ""}`,
            remediation: `Review and remediate exposure on ${fp.domain} or switch to a less exposed ${fp.category} provider.`,
            cve: cves[0] ?? null,
          }).onConflictDoNothing();
        }
      } catch (e) {
        logger.warn({ e, fpDomain: fp.domain }, "TPRM: 4th party deep scan failed (non-fatal)");
      }
      // Small delay between 4th party probes
      await new Promise(r => setTimeout(r, 2000));
    }
  });
});

// ── Questionnaire file-upload answer handling ─────────────────────────────────
// #17: Allow file-type answers to be uploaded separately and stored as base64

router.post("/tprm/questionnaire-respond-file/:token/:questionId", upload.single("file"), async (req: any, res: any) => {
  const { token, questionId } = req.params as { token: string; questionId: string };
  if (!req.file) { res.status(400).json({ error: "file is required" }); return; }
  try {
    const [q] = await db.select().from(tprmVendorQuestionnairesTable).where(eq(tprmVendorQuestionnairesTable.accessToken, token as any));
    if (!q || q.status === "completed") { res.status(404).json({ error: "Questionnaire not found or already submitted" }); return; }
    const existing = (q.responses as any[]) ?? [];
    const fileRef = { type: "file", fileName: req.file.originalname, fileSize: req.file.size, mimeType: req.file.mimetype, data: req.file.buffer.toString("base64") };
    const updated = existing.filter((r: any) => r.questionId !== questionId);
    updated.push({ questionId, answer: fileRef });
    await db.update(tprmVendorQuestionnairesTable).set({ responses: updated }).where(eq(tprmVendorQuestionnairesTable.id, q.id));
    res.json({ ok: true, questionId, fileName: req.file.originalname });
  } catch (err) {
    logger.error({ err }, "TPRM: questionnaire file upload failed");
    res.status(500).json({ error: "Failed to upload file answer" });
  }
});

// ── Framework control seed data ───────────────────────────────────────────────
const FRAMEWORK_CONTROLS: Record<string, { controlId: string; controlTitle: string; category: string }[]> = {
  iso27001: [
    { controlId: "A.5.1",  controlTitle: "Policies for information security",                        category: "Organizational" },
    { controlId: "A.5.2",  controlTitle: "Information security roles & responsibilities",            category: "Organizational" },
    { controlId: "A.5.9",  controlTitle: "Inventory of information & assets",                       category: "Organizational" },
    { controlId: "A.5.15", controlTitle: "Access control",                                          category: "Organizational" },
    { controlId: "A.5.23", controlTitle: "Information security for use of cloud services",          category: "Organizational" },
    { controlId: "A.6.1",  controlTitle: "Screening",                                               category: "People"         },
    { controlId: "A.6.3",  controlTitle: "Information security awareness, education & training",    category: "People"         },
    { controlId: "A.6.8",  controlTitle: "Information security event reporting",                    category: "People"         },
    { controlId: "A.7.1",  controlTitle: "Physical security perimeters",                            category: "Physical"       },
    { controlId: "A.7.6",  controlTitle: "Working in secure areas",                                 category: "Physical"       },
    { controlId: "A.8.2",  controlTitle: "Privileged access rights",                                category: "Technological"  },
    { controlId: "A.8.5",  controlTitle: "Secure authentication",                                   category: "Technological"  },
    { controlId: "A.8.7",  controlTitle: "Protection against malware",                              category: "Technological"  },
    { controlId: "A.8.13", controlTitle: "Information backup",                                      category: "Technological"  },
    { controlId: "A.8.16", controlTitle: "Monitoring activities",                                   category: "Technological"  },
    { controlId: "A.8.24", controlTitle: "Use of cryptography",                                     category: "Technological"  },
    { controlId: "A.8.25", controlTitle: "Secure development life cycle",                           category: "Technological"  },
    { controlId: "A.8.28", controlTitle: "Secure coding",                                           category: "Technological"  },
  ],
  soc2: [
    { controlId: "CC1.1", controlTitle: "Control environment — COSO principles",                    category: "Control Environment" },
    { controlId: "CC1.4", controlTitle: "Commitment to competence",                                 category: "Control Environment" },
    { controlId: "CC2.1", controlTitle: "Information & communication (internal)",                   category: "Communication"       },
    { controlId: "CC2.2", controlTitle: "External communication of information",                    category: "Communication"       },
    { controlId: "CC3.1", controlTitle: "Risk assessment process",                                  category: "Risk Assessment"     },
    { controlId: "CC3.3", controlTitle: "Fraud risk assessment",                                    category: "Risk Assessment"     },
    { controlId: "CC4.1", controlTitle: "Ongoing and/or separate evaluations",                      category: "Monitoring"          },
    { controlId: "CC5.1", controlTitle: "Control activities — COSO principles",                     category: "Control Activities"  },
    { controlId: "CC6.1", controlTitle: "Logical access security measures",                         category: "Logical Access"      },
    { controlId: "CC6.2", controlTitle: "Prior to issuing system credentials",                      category: "Logical Access"      },
    { controlId: "CC6.6", controlTitle: "Logical access to the organization's network",             category: "Logical Access"      },
    { controlId: "CC6.7", controlTitle: "Transmission, movement & removal of information",          category: "Logical Access"      },
    { controlId: "CC7.1", controlTitle: "System monitoring for anomalies & incidents",              category: "System Operations"   },
    { controlId: "CC7.2", controlTitle: "Security incidents identified & responded to",             category: "System Operations"   },
    { controlId: "CC8.1", controlTitle: "Change management processes",                              category: "Change Management"   },
    { controlId: "CC9.1", controlTitle: "Risk mitigation activities",                               category: "Risk Mitigation"     },
    { controlId: "A1.1",  controlTitle: "Availability — capacity & performance monitoring",         category: "Availability"        },
    { controlId: "C1.1",  controlTitle: "Confidential information protection & disposal",           category: "Confidentiality"     },
  ],
  pcidss: [
    { controlId: "Req-1",  controlTitle: "Install & maintain network security controls",              category: "Network Security"    },
    { controlId: "Req-2",  controlTitle: "Apply secure configurations to all system components",      category: "Configuration"       },
    { controlId: "Req-3",  controlTitle: "Protect stored account data",                               category: "Data Protection"     },
    { controlId: "Req-4",  controlTitle: "Protect cardholder data in transit with strong cryptography", category: "Encryption"        },
    { controlId: "Req-5",  controlTitle: "Protect all systems & networks against malicious software",  category: "Malware Protection"  },
    { controlId: "Req-6",  controlTitle: "Develop & maintain secure systems & software",              category: "Secure Development"  },
    { controlId: "Req-7",  controlTitle: "Restrict access to system components & cardholder data",    category: "Access Control"      },
    { controlId: "Req-8",  controlTitle: "Identify users & authenticate access to system components", category: "Identity"            },
    { controlId: "Req-9",  controlTitle: "Restrict physical access to cardholder data",               category: "Physical Security"   },
    { controlId: "Req-10", controlTitle: "Log & monitor all access to system components",             category: "Logging & Monitoring"},
    { controlId: "Req-11", controlTitle: "Test security of systems & networks regularly",             category: "Security Testing"    },
    { controlId: "Req-12", controlTitle: "Support information security with organizational policies", category: "Policy"              },
  ],
  hipaa: [
    { controlId: "164.308(a)(1)", controlTitle: "Security management process — risk analysis & management",  category: "Administrative" },
    { controlId: "164.308(a)(2)", controlTitle: "Assigned security responsibility",                          category: "Administrative" },
    { controlId: "164.308(a)(3)", controlTitle: "Workforce security — authorization, supervision",           category: "Administrative" },
    { controlId: "164.308(a)(4)", controlTitle: "Information access management",                             category: "Administrative" },
    { controlId: "164.308(a)(5)", controlTitle: "Security awareness & training",                             category: "Administrative" },
    { controlId: "164.308(a)(6)", controlTitle: "Security incident procedures",                              category: "Administrative" },
    { controlId: "164.308(a)(7)", controlTitle: "Contingency plan — backup, recovery, testing",              category: "Administrative" },
    { controlId: "164.308(a)(8)", controlTitle: "Evaluation — periodic technical & non-technical review",    category: "Administrative" },
    { controlId: "164.310(a)",    controlTitle: "Facility access controls",                                  category: "Physical"       },
    { controlId: "164.310(c)",    controlTitle: "Workstation use & security",                                category: "Physical"       },
    { controlId: "164.310(d)",    controlTitle: "Device & media controls",                                   category: "Physical"       },
    { controlId: "164.312(a)",    controlTitle: "Access control — unique user IDs, emergency access, encryption", category: "Technical" },
    { controlId: "164.312(b)",    controlTitle: "Audit controls — hardware, software, procedural",           category: "Technical"      },
    { controlId: "164.312(c)",    controlTitle: "Integrity — authenticate & protect ePHI",                   category: "Technical"      },
    { controlId: "164.312(e)",    controlTitle: "Transmission security — encryption & network controls",     category: "Technical"      },
  ],
  nist_csf: [
    { controlId: "GV.OC-01", controlTitle: "Org mission & objectives aligned to cybersecurity risk strategy",      category: "Govern"   },
    { controlId: "GV.RM-01", controlTitle: "Risk management objectives established & agreed upon",                 category: "Govern"   },
    { controlId: "ID.AM-01", controlTitle: "Asset inventory of hardware & software maintained",                    category: "Identify" },
    { controlId: "ID.AM-05", controlTitle: "Assets prioritized based on classification, criticality & resources",  category: "Identify" },
    { controlId: "ID.RA-01", controlTitle: "Vulnerabilities in assets identified & documented",                    category: "Identify" },
    { controlId: "ID.RA-05", controlTitle: "Threats, vulnerabilities, likelihoods & impacts used to prioritize",  category: "Identify" },
    { controlId: "PR.AA-01", controlTitle: "Identities & credentials issued, managed, verified & revoked",        category: "Protect"  },
    { controlId: "PR.AA-05", controlTitle: "Access permissions & authorizations managed",                         category: "Protect"  },
    { controlId: "PR.DS-01", controlTitle: "Data-at-rest protected",                                              category: "Protect"  },
    { controlId: "PR.DS-02", controlTitle: "Data-in-transit protected",                                           category: "Protect"  },
    { controlId: "PR.PS-01", controlTitle: "Configs of hardware & software managed & maintained",                 category: "Protect"  },
    { controlId: "DE.AE-02", controlTitle: "Potentially adverse events analyzed to characterize incidents",       category: "Detect"   },
    { controlId: "DE.CM-01", controlTitle: "Networks & network services monitored for anomalous activity",        category: "Detect"   },
    { controlId: "RS.MA-01", controlTitle: "Incidents reported and triaged by response personnel",                category: "Respond"  },
    { controlId: "RS.CO-02", controlTitle: "Internal & external stakeholders notified of incidents",              category: "Respond"  },
    { controlId: "RC.RP-01", controlTitle: "Recovery plan executed during or after incidents",                    category: "Recover"  },
    { controlId: "RC.CO-03", controlTitle: "Recovery activities communicated to internal & external stakeholders", category: "Recover" },
  ],
};

// ── Compliance Controls ───────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/compliance-controls", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const framework = req.query.framework as string | undefined;
  const conds = [eq(tprmVendorComplianceControlsTable.vendorId, vendorId), eq(tprmVendorComplianceControlsTable.tenantId, tenantId)];
  if (framework) conds.push(eq(tprmVendorComplianceControlsTable.framework, framework));
  const controls = await db.select().from(tprmVendorComplianceControlsTable).where(and(...conds)).orderBy(asc(tprmVendorComplianceControlsTable.controlId));
  res.json(controls);
});

// MUST be before /:cid to avoid seed being treated as a control ID
router.post("/tprm/vendors/:id/compliance-controls/seed", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { framework } = req.body;
  const controls = FRAMEWORK_CONTROLS[framework];
  if (!controls) { res.status(400).json({ error: `Unknown framework. Valid: ${Object.keys(FRAMEWORK_CONTROLS).join(", ")}` }); return; }
  // Only insert controls not already present for this vendor+framework
  const existing = await db.select({ controlId: tprmVendorComplianceControlsTable.controlId })
    .from(tprmVendorComplianceControlsTable)
    .where(and(eq(tprmVendorComplianceControlsTable.vendorId, vendorId), eq(tprmVendorComplianceControlsTable.tenantId, tenantId), eq(tprmVendorComplianceControlsTable.framework, framework)));
  const existingIds = new Set(existing.map(e => e.controlId));
  const toInsert = controls.filter(c => !existingIds.has(c.controlId));
  if (toInsert.length === 0) { res.json({ inserted: 0, message: "All controls already exist for this framework" }); return; }
  const rows = toInsert.map(c => ({ vendorId, tenantId, framework, controlId: c.controlId, controlTitle: c.controlTitle, category: c.category, status: "pending_review", createdBy: userId as any }));
  await db.insert(tprmVendorComplianceControlsTable).values(rows);
  res.status(201).json({ inserted: toInsert.length, message: `Seeded ${toInsert.length} controls for ${framework}` });
});

router.post("/tprm/vendors/:id/compliance-controls", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { framework, controlId, controlTitle, category, status, evidence, notes, assignedTo, nextReviewAt } = req.body;
  if (!framework || !controlId || !controlTitle) { res.status(400).json({ error: "framework, controlId, controlTitle are required" }); return; }
  const [ctrl] = await db.insert(tprmVendorComplianceControlsTable).values({
    vendorId, tenantId, framework, controlId, controlTitle, category: category ?? null,
    status: status ?? "pending_review", evidence: evidence ?? null, notes: notes ?? null,
    assignedTo: assignedTo ?? null, nextReviewAt: nextReviewAt ? new Date(nextReviewAt) : null,
    createdBy: userId as any,
  }).returning();
  res.status(201).json(ctrl);
});

router.patch("/tprm/vendors/:id/compliance-controls/:cid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const cid = parseInt(req.params.cid as string);
  const allowed = ["status", "evidence", "notes", "assignedTo", "nextReviewAt", "controlTitle", "category", "isActive"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) {
    if (req.body[k] !== undefined) {
      if (k === "nextReviewAt") {
        updates[k] = req.body[k] === "" || req.body[k] === null ? null : new Date(req.body[k]);
      } else if (k === "isActive") {
        updates[k] = Boolean(req.body[k]);
      } else {
        updates[k] = req.body[k];
      }
    }
  }
  if (updates.status && ["compliant", "partial", "non_compliant"].includes(updates.status)) {
    updates.reviewedAt = new Date();
  }
  const [ctrl] = await db.update(tprmVendorComplianceControlsTable).set(updates)
    .where(and(eq(tprmVendorComplianceControlsTable.id, cid), eq(tprmVendorComplianceControlsTable.tenantId, tenantId))).returning();
  if (!ctrl) { res.status(404).json({ error: "Control not found" }); return; }
  res.json(ctrl);
});

router.delete("/tprm/vendors/:id/compliance-controls/:cid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const cid = parseInt(req.params.cid as string);
  await db.delete(tprmVendorComplianceControlsTable).where(and(eq(tprmVendorComplianceControlsTable.id, cid), eq(tprmVendorComplianceControlsTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// ── Compliance Reminders ──────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/reminders", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const showAll = req.query.all === "true";
  const conds = [eq(tprmComplianceRemindersTable.vendorId, vendorId), eq(tprmComplianceRemindersTable.tenantId, tenantId)];
  if (!showAll) conds.push(eq(tprmComplianceRemindersTable.isDismissed, false));
  const reminders = await db.select().from(tprmComplianceRemindersTable).where(and(...conds)).orderBy(asc(tprmComplianceRemindersTable.dueDate));
  res.json(reminders);
});

router.post("/tprm/vendors/:id/reminders", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId } = req.user!;
  const vendorId = parseInt(req.params.id as string);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { title, type, referenceId, referenceType, dueDate, notes } = req.body;
  if (!title || !dueDate) { res.status(400).json({ error: "title and dueDate are required" }); return; }
  const [reminder] = await db.insert(tprmComplianceRemindersTable).values({
    vendorId, tenantId, title, type: type ?? "custom",
    referenceId: referenceId ?? null, referenceType: referenceType ?? null,
    dueDate, notes: notes ?? null, createdBy: userId as any,
  }).returning();
  res.status(201).json(reminder);
});

router.patch("/tprm/vendors/:id/reminders/:rid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const rid = parseInt(req.params.rid as string);
  const allowed = ["title", "dueDate", "notes", "isDismissed", "type"];
  const updates: Record<string, any> = {};
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }
  const [reminder] = await db.update(tprmComplianceRemindersTable).set(updates)
    .where(and(eq(tprmComplianceRemindersTable.id, rid), eq(tprmComplianceRemindersTable.tenantId, tenantId))).returning();
  if (!reminder) { res.status(404).json({ error: "Reminder not found" }); return; }
  res.json(reminder);
});

router.delete("/tprm/vendors/:id/reminders/:rid", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const rid = parseInt(req.params.rid as string);
  await db.delete(tprmComplianceRemindersTable).where(and(eq(tprmComplianceRemindersTable.id, rid), eq(tprmComplianceRemindersTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// ── Question Library ─────────────────────────────────────────────────────────

router.get("/tprm/question-library", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const isSA = role === "super_admin";
  const rows = await db
    .select()
    .from(tprmQuestionLibraryTable)
    .where(
      isSA
        ? undefined
        : or(eq(tprmQuestionLibraryTable.tenantId, tenantId), eq(tprmQuestionLibraryTable.isGlobal, true))
    )
    .orderBy(tprmQuestionLibraryTable.category, tprmQuestionLibraryTable.id);
  res.json(rows);
});

router.post("/tprm/question-library", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, userId, role } = req.user!;
  const { text, type, category, required, weight, options, isGlobal } = req.body as any;
  if (!text?.trim()) { res.status(400).json({ error: "text required" }); return; }
  const isG = isGlobal && role === "super_admin";
  const [row] = await db
    .insert(tprmQuestionLibraryTable)
    .values({ tenantId: isG ? null : tenantId, text: text.trim(), type: type ?? "boolean", category: category ?? "general", required: !!required, weight: weight ?? 1, options: options ?? null, isGlobal: isG, isActive: true, createdBy: userId as any })
    .returning();
  res.status(201).json(row);
});

router.post("/tprm/question-library/seed-defaults", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const existing = await db.select({ id: tprmQuestionLibraryTable.id })
    .from(tprmQuestionLibraryTable)
    .where(eq(tprmQuestionLibraryTable.isGlobal, true))
    .limit(1);
  if (existing.length > 0) {
    res.json({ seeded: 0, message: "Default questions already exist" });
    return;
  }
  const defaults = [
    { text: "Does the vendor have an information security policy?",            type: "boolean",      category: "Governance",         required: true,  weight: 2, options: null },
    { text: "Is the vendor ISO 27001 certified?",                              type: "boolean",      category: "Compliance",         required: true,  weight: 2, options: null },
    { text: "Does the vendor perform annual penetration testing?",             type: "boolean",      category: "Testing",            required: true,  weight: 2, options: null },
    { text: "Does the vendor encrypt data at rest?",                           type: "boolean",      category: "Data Protection",    required: true,  weight: 2, options: null },
    { text: "Does the vendor encrypt data in transit?",                        type: "boolean",      category: "Data Protection",    required: true,  weight: 2, options: null },
    { text: "Does the vendor have a formal incident response plan?",           type: "boolean",      category: "Incident Response",  required: true,  weight: 2, options: null },
    { text: "Does the vendor perform background checks on employees?",         type: "boolean",      category: "HR Security",        required: false, weight: 1, options: null },
    { text: "Does the vendor use multi-factor authentication?",                type: "boolean",      category: "Access Control",     required: true,  weight: 2, options: null },
    { text: "Rate the vendor's overall security maturity level (1-5)",         type: "rating",       category: "Maturity",           required: false, weight: 3, options: null },
    { text: "Does the vendor have SOC 2 Type II certification?",               type: "boolean",      category: "Compliance",         required: false, weight: 2, options: null },
    { text: "What is the vendor's SLA for critical security incidents (hrs)?", type: "text",         category: "Incident Response",  required: false, weight: 1, options: null },
    { text: "Does the vendor maintain a vulnerability disclosure program?",    type: "boolean",      category: "Vulnerability Mgmt", required: false, weight: 1, options: null },
    { text: "Which compliance frameworks does the vendor adhere to?",          type: "multi_choice", category: "Compliance",         required: false, weight: 1, options: ["ISO 27001","SOC 2","PCI DSS","HIPAA","GDPR","NIST CSF","CIS Controls"] },
    { text: "Please upload the latest third-party audit report",               type: "file_upload",  category: "Compliance",         required: false, weight: 2, options: null },
  ];
  const rows = await db.insert(tprmQuestionLibraryTable)
    .values(defaults.map(d => ({ tenantId: null, text: d.text, type: d.type, category: d.category, required: d.required, weight: d.weight, options: d.options, isGlobal: true, isActive: true, createdBy: null as any })))
    .returning();
  res.status(201).json({ seeded: rows.length });
});

router.patch("/tprm/question-library/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const qid = parseInt(req.params.id as string);
  const existing = await db.select().from(tprmQuestionLibraryTable).where(eq(tprmQuestionLibraryTable.id, qid)).limit(1);
  if (!existing.length) { res.status(404).json({ error: "Not found" }); return; }
  const q = existing[0];
  if (q.isGlobal && role !== "super_admin") { res.status(403).json({ error: "Only super_admin can edit global questions" }); return; }
  if (!q.isGlobal && q.tenantId !== tenantId) { res.status(403).json({ error: "Forbidden" }); return; }
  const { text, type, category, required, weight, options, isActive } = req.body as any;
  const [updated] = await db
    .update(tprmQuestionLibraryTable)
    .set({ ...(text !== undefined && { text }), ...(type !== undefined && { type }), ...(category !== undefined && { category }), ...(required !== undefined && { required: !!required }), ...(weight !== undefined && { weight }), ...(options !== undefined && { options }), ...(isActive !== undefined && { isActive: !!isActive }), updatedAt: new Date() })
    .where(eq(tprmQuestionLibraryTable.id, qid))
    .returning();
  res.json(updated);
});

router.delete("/tprm/question-library/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const qid = parseInt(req.params.id as string);
  const existing = await db.select().from(tprmQuestionLibraryTable).where(eq(tprmQuestionLibraryTable.id, qid)).limit(1);
  if (!existing.length) { res.status(404).json({ error: "Not found" }); return; }
  const q = existing[0];
  if (q.isGlobal && role !== "super_admin") { res.status(403).json({ error: "Forbidden" }); return; }
  if (!q.isGlobal && q.tenantId !== tenantId) { res.status(403).json({ error: "Forbidden" }); return; }
  await db.delete(tprmQuestionLibraryTable).where(eq(tprmQuestionLibraryTable.id, qid));
  res.json({ ok: true });
});

export default router;
