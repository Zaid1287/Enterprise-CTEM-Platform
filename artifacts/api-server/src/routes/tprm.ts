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
  tprmSupplyChainNodesTable,
  tprmVendorContactsTable,
  tprmQuestionnaireTemplatesTable,
  tprmVendorQuestionnairesTable,
  tprmComplianceDocumentsTable,
  tprmComplianceRequirementsTable,
  tprmSbomUploadsTable,
  tenantsTable,
  platformSettingsTable,
  alertsTable,
} from "@workspace/db";
import { eq, and, desc, asc, or, ilike, sql, ne, lte, inArray, isNull } from "drizzle-orm";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { logger } from "../lib/logger";
import { enrichCompanyByDomain, runFullVendorScan } from "../lib/tprmEnrichment";
import { parseSbom, detectSbomFormat, enrichSbomWithVulnerabilities } from "../lib/tprmSbom";
import { enrichFindingsWithEpssKev } from "../lib/epssKev";

const router = Router();
const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } });

// ── requireTprm middleware ─────────────────────────────────────────────────────
async function requireTprm(req: AuthenticatedRequest, res: any, next: Function) {
  const tenantId = req.user?.tenantId;
  const role     = req.user?.role;
  if (!tenantId) { res.status(401).json({ error: "Unauthorized" }); return; }
  if (role === "admin" || role === "super_admin") { next(); return; }
  try {
    const [row] = await db.select().from(tprmModuleAssignmentsTable).where(eq(tprmModuleAssignmentsTable.tenantId, tenantId));
    if (!row?.isEnabled) { res.status(403).json({ error: "TPRM module is not enabled for this tenant" }); return; }
    next();
  } catch { res.status(500).json({ error: "Module check failed" }); }
}

/**
 * Resolve a vendor by ID while enforcing tenant ownership.
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
  const tenantId = req.user!.tenantId;
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
  const targetTenantId = role === "super_admin" ? requestedTenantId : callerTenantId;
  if (role === "admin" && requestedTenantId !== callerTenantId) { res.status(403).json({ error: "Admins can only toggle their own tenant" }); return; }
  const isEnabled = !!req.body.isEnabled;
  await db.insert(tprmModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: tprmModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "tprm_enabled" : "tprm_disabled", "tenant", targetTenantId, JSON.stringify({ targetTenantId, isEnabled }), req.ip ?? "");
  res.json({ isEnabled });
});

// Explicit per-tenant toggle for super_admin (canonical URL expected by frontend/code review)
router.patch("/tprm/client/:tenantId/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const targetTenantId = parseInt(req.params.tenantId);
  if (isNaN(targetTenantId)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  const isEnabled = !!req.body.isEnabled;
  await db.insert(tprmModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: tprmModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "tprm_enabled" : "tprm_disabled", "tenant", targetTenantId, JSON.stringify({ targetTenantId, isEnabled }), req.ip ?? "");
  res.json({ isEnabled, tenantId: targetTenantId });
});

// ── Admin: global vendor library ───────────────────────────────────────────────

router.get("/tprm/admin/global-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  try {
    const vendors = await db.select().from(tprmVendorsTable)
      .where(eq(tprmVendorsTable.isGlobal, true))
      .orderBy(asc(tprmVendorsTable.companyName));
    res.json(vendors);
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendors GET error");
    res.status(500).json({ error: "Failed to fetch global vendors" });
  }
});

router.post("/tprm/admin/global-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role, tenantId, userId } = req.user!;
  if (role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
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
    await logAudit(req.user!, "tprm_global_vendor_created", "vendor", vendor.id, JSON.stringify({ companyName, domain: cleanDomain }), req.ip ?? "");
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
  if (role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const vendorId = parseInt(req.params.id);
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
  if (role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const vendorId = parseInt(req.params.id);
  try {
    const [existing] = await db.select().from(tprmVendorsTable).where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.isGlobal, true)));
    if (!existing) { res.status(404).json({ error: "Global vendor not found" }); return; }
    await db.delete(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    await logAudit(req.user!, "tprm_global_vendor_deleted", "vendor", vendorId, JSON.stringify({ companyName: existing.companyName }), req.ip ?? "");
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "TPRM admin global-vendor DELETE error");
    res.status(500).json({ error: "Failed to delete global vendor" });
  }
});

// ── Admin: cross-tenant all vendors (super_admin only) ─────────────────────────

router.get("/tprm/admin/all-vendors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role } = req.user!;
  if (role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  try {
    const vendors = await db
      .select({
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
      .orderBy(desc(tprmVendorsTable.updatedAt));
    res.json(vendors);
  } catch (err) {
    logger.error({ err }, "TPRM admin all-vendors error");
    res.status(500).json({ error: "Failed to fetch vendors" });
  }
});

// ── Admin overview ─────────────────────────────────────────────────────────────

router.get("/tprm/admin/overview", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { role, tenantId: callerTenantId } = req.user!;
  if (role !== "admin" && role !== "super_admin") { res.status(403).json({ error: "Insufficient permissions" }); return; }
  try {
    const tenants = role === "super_admin"
      ? await db.select().from(tenantsTable)
      : await db.select().from(tenantsTable).where(eq(tenantsTable.id, callerTenantId));
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
  const { tenantId, role } = req.user!;
  const { type, status, riskGrade, industry, search, page = "1", limit = "50" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  try {
    const conds: any[] = [
      or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!,
    ];
    if (type)      conds.push(eq(tprmVendorsTable.type, type));
    if (status)    conds.push(eq(tprmVendorsTable.status, status));
    if (riskGrade) conds.push(eq(tprmVendorsTable.riskGrade, riskGrade));
    if (industry)  conds.push(eq(tprmVendorsTable.industry, industry));
    if (search)    conds.push(or(ilike(tprmVendorsTable.companyName, `%${search}%`), ilike(tprmVendorsTable.domain, `%${search}%`))!);

    const [vendors, [countRow]] = await Promise.all([
      db.select().from(tprmVendorsTable).where(and(...conds)).orderBy(desc(tprmVendorsTable.createdAt)).limit(parseInt(limit)).offset(offset),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmVendorsTable).where(and(...conds)),
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

    res.json({
      vendors: vendors.map(v => ({ ...v, assetCount: assetCounts[v.id] ?? 0 })),
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

    await logAudit(req.user!, "tprm_vendor_created", "vendor", vendor.id, JSON.stringify({ companyName, domain: cleanDomain }), req.ip ?? "");

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

router.get("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);

  try {
    const [vendor] = await db.select().from(tprmVendorsTable).where(
      and(eq(tprmVendorsTable.id, vendorId), or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!)
    );
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }

    // For global vendors, scan data is stored under the owner tenant — use ownerTenantId for all child queries
    const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;

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

    res.json({ ...vendor, riskScores, assets, findings, fourthParties, supplyChain, contacts, questionnaires: questionnaires.map(q => ({ ...q, responses: undefined })), complianceDocs });
  } catch (err) {
    logger.error({ err }, "TPRM vendor detail error");
    res.status(500).json({ error: "Failed to load vendor" });
  }
});

router.patch("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  const allowed = ["companyName", "type", "industry", "description", "logoUrl", "website", "employeeCount", "companySize", "founded", "location", "marketCap", "companyType", "inherentRisk", "businessImpact", "scanFrequency", "status", "source", "assessmentType"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }

  try {
    const [vendor] = await db.update(tprmVendorsTable).set(updates)
      .where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.tenantId, tenantId)))
      .returning();
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
    res.json(vendor);
  } catch (err) {
    logger.error({ err }, "TPRM update vendor error");
    res.status(500).json({ error: "Failed to update vendor" });
  }
});

router.delete("/tprm/vendors/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const vendorId = parseInt(req.params.id);
  try {
    const [vendor] = await db.select().from(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
    if (vendor.isGlobal && role !== "super_admin") { res.status(403).json({ error: "Only super_admin can delete global vendors" }); return; }
    if (!vendor.isGlobal && vendor.tenantId !== tenantId) { res.status(403).json({ error: "Not your vendor" }); return; }
    await db.delete(tprmVendorsTable).where(eq(tprmVendorsTable.id, vendorId));
    await logAudit(req.user!, "tprm_vendor_deleted", "vendor", vendorId, JSON.stringify({ companyName: vendor.companyName }), req.ip ?? "");
    res.json({ ok: true });
  } catch (err) {
    logger.error({ err }, "TPRM delete vendor error");
    res.status(500).json({ error: "Failed to delete vendor" });
  }
});

router.post("/tprm/vendors/:id/scan", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  try {
    const [vendor] = await db.select().from(tprmVendorsTable).where(
      and(eq(tprmVendorsTable.id, vendorId), or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!)
    );
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
  const vendorId = parseInt(req.params.id);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const rows = await db.select().from(tprmFourthPartyVendorsTable).where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, ownerTenantId))).orderBy(desc(tprmFourthPartyVendorsTable.discoveredAt));
  res.json(rows);
});

router.post("/tprm/vendors/:id/fourth-party", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const parentVendorId = parseInt(req.params.id);
  if (!await resolveVendor(parentVendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { name, domain, discoveryMethod, riskContribution, details } = req.body;
  if (!name) { res.status(400).json({ error: "name is required" }); return; }
  const [row] = await db.insert(tprmFourthPartyVendorsTable).values({ parentVendorId, tenantId, name, domain: domain ?? null, discoveryMethod: discoveryMethod ?? "manual", riskContribution: riskContribution ?? 0, details: details ?? null }).returning();
  res.status(201).json(row);
});

// ── Risk & Findings ───────────────────────────────────────────────────────────

router.get("/tprm/vendors/:id/risk-history", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const rows = await db.select().from(tprmVendorRiskScoresTable).where(and(eq(tprmVendorRiskScoresTable.vendorId, vendorId), eq(tprmVendorRiskScoresTable.tenantId, ownerTenantId))).orderBy(asc(tprmVendorRiskScoresTable.calculatedAt)).limit(90);
  res.json(rows);
});

router.get("/tprm/vendors/:id/findings", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const { severity, status, page = "1", limit = "50" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const conds: any[] = [eq(tprmVendorFindingsTable.vendorId, vendorId), eq(tprmVendorFindingsTable.tenantId, ownerTenantId)];
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
  const findingId = parseInt(req.params.fid);
  const { status } = req.body;
  const [row] = await db.update(tprmVendorFindingsTable).set({ status }).where(and(eq(tprmVendorFindingsTable.id, findingId), eq(tprmVendorFindingsTable.tenantId, tenantId))).returning();
  if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
  res.json(row);
});

router.get("/tprm/vendors/:id/assets", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const rows = await db.select().from(tprmVendorAssetsTable).where(and(eq(tprmVendorAssetsTable.vendorId, vendorId), eq(tprmVendorAssetsTable.tenantId, ownerTenantId))).orderBy(asc(tprmVendorAssetsTable.assetType)).limit(500);
  res.json(rows);
});

// ── Supply Chain ──────────────────────────────────────────────────────────────

router.get("/tprm/supply-chain", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const { nodeType, riskLevel, vendorId, page = "1", limit = "100" } = req.query as Record<string, string>;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  const conds: any[] = [eq(tprmSupplyChainNodesTable.tenantId, tenantId)];
  if (nodeType)  conds.push(eq(tprmSupplyChainNodesTable.nodeType, nodeType));
  if (riskLevel) conds.push(eq(tprmSupplyChainNodesTable.riskLevel, riskLevel));
  if (vendorId)  conds.push(eq(tprmSupplyChainNodesTable.vendorId, parseInt(vendorId)));
  const [rows, [countRow]] = await Promise.all([
    db.select().from(tprmSupplyChainNodesTable).where(and(...conds)).orderBy(desc(tprmSupplyChainNodesTable.discoveredAt)).limit(parseInt(limit)).offset(offset),
    db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(...conds)),
  ]);
  res.json({ nodes: rows, total: countRow?.count ?? 0 });
});

router.get("/tprm/supply-chain/stats", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  try {
    const [totalNodes, criticalNodes, highNodes] = await Promise.all([
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(eq(tprmSupplyChainNodesTable.tenantId, tenantId)),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.tenantId, tenantId), eq(tprmSupplyChainNodesTable.riskLevel, "critical"))),
      db.select({ count: sql<number>`count(*)::int` }).from(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.tenantId, tenantId), eq(tprmSupplyChainNodesTable.riskLevel, "high"))),
    ]);

    const byType = await db.select({ nodeType: tprmSupplyChainNodesTable.nodeType, count: sql<number>`count(*)::int` })
      .from(tprmSupplyChainNodesTable).where(eq(tprmSupplyChainNodesTable.tenantId, tenantId)).groupBy(tprmSupplyChainNodesTable.nodeType);

    const vendorsWithCritical = await db.selectDistinct({ vendorId: tprmVendorFindingsTable.vendorId })
      .from(tprmVendorFindingsTable)
      .where(and(eq(tprmVendorFindingsTable.tenantId, tenantId), eq(tprmVendorFindingsTable.severity, "critical"), eq(tprmVendorFindingsTable.status, "open")));

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
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  const vendor = await resolveVendor(vendorId, tenantId);
  if (!vendor) { res.status(404).json({ error: "Vendor not found" }); return; }
  const ownerTenantId = vendor.isGlobal ? vendor.tenantId : tenantId;
  const rows = await db.select().from(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.vendorId, vendorId), eq(tprmSupplyChainNodesTable.tenantId, ownerTenantId))).limit(500);
  res.json(rows);
});

// ── Dashboard ─────────────────────────────────────────────────────────────────

router.get("/tprm/dashboard", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  try {
    const allVendors = await db.select().from(tprmVendorsTable).where(
      or(eq(tprmVendorsTable.tenantId, tenantId), eq(tprmVendorsTable.isGlobal, true))!
    );

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

    const topCritical = allVendors.filter(v => v.riskGrade === "D" || v.riskGrade === "F").sort((a, b) => a.riskScore - b.riskScore).slice(0, 5);

    const vendorIds = allVendors.map(v => v.id);
    let digitalExposure = { credentialLeaks: 0, docsExposed: 0, darkWebMentions: 0 };
    let infraCoverage = { misconfiguredCloud: 0, secretsInApps: 0, misconfiguredDns: 0, sslIssues: 0, exposedServices: 0 };
    let assetCounts = { domains: 0, subdomains: 0, ipAddresses: 0, webApps: 0 };

    if (vendorIds.length > 0) {
      const [assets, findings] = await Promise.all([
        db.select({ assetType: tprmVendorAssetsTable.assetType, count: sql<number>`count(*)::int` })
          .from(tprmVendorAssetsTable).where(inArray(tprmVendorAssetsTable.vendorId, vendorIds)).groupBy(tprmVendorAssetsTable.assetType),
        db.select().from(tprmVendorFindingsTable).where(and(inArray(tprmVendorFindingsTable.vendorId, vendorIds), eq(tprmVendorFindingsTable.status, "open"))),
      ]);

      for (const a of assets) {
        if (a.assetType === "subdomain") assetCounts.subdomains += a.count;
        else if (a.assetType === "ip") assetCounts.ipAddresses += a.count;
        else if (a.assetType === "domain") assetCounts.domains += a.count;
        else if (a.assetType === "web_app") assetCounts.webApps += a.count;
      }
      assetCounts.domains = totalVendors;

      infraCoverage.sslIssues = findings.filter(f => f.category === "tls").length;
      infraCoverage.misconfiguredDns = findings.filter(f => f.category === "email" || f.category === "dns").length;
      infraCoverage.exposedServices = findings.filter(f => f.category === "network").length;
      infraCoverage.secretsInApps = findings.filter(f => f.category === "info_leak" || f.category === "sensitive-file").length;
      infraCoverage.misconfiguredCloud = findings.filter(f => f.category === "cloud").length;
      digitalExposure.credentialLeaks = findings.filter(f => f.category === "info_leak" && (f.title?.includes(".env") || f.title?.includes("credential") || f.title?.includes("secret"))).length;
      digitalExposure.docsExposed = findings.filter(f => f.category === "info_leak" && (f.title?.includes(".git") || f.title?.includes("config"))).length;
    }

    const recentScans = allVendors.filter(v => v.lastScannedAt).sort((a, b) => (b.lastScannedAt?.getTime() ?? 0) - (a.lastScannedAt?.getTime() ?? 0)).slice(0, 10);

    res.json({
      totalVendors, serviceProviders, prospecting, subsidiaries,
      avgRiskScore, gradeMap, poor, average, good,
      topCritical,
      digitalExposure, infraCoverage, assetCounts, recentScans,
      vendorSummary: allVendors.map(v => ({ id: v.id, companyName: v.companyName, riskGrade: v.riskGrade, riskScore: v.riskScore, assessmentType: v.assessmentType, status: v.status, domain: v.domain, logoUrl: v.logoUrl })),
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
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id);
  const { name, description, category, questions } = req.body;
  const [row] = await db.update(tprmQuestionnaireTemplatesTable)
    .set({ name, description, category, questions, updatedAt: new Date() })
    .where(and(eq(tprmQuestionnaireTemplatesTable.id, id), eq(tprmQuestionnaireTemplatesTable.tenantId, tenantId)))
    .returning();
  if (!row) { res.status(404).json({ error: "Template not found" }); return; }
  res.json(row);
});

router.delete("/tprm/questionnaire-templates/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id);
  await db.delete(tprmQuestionnaireTemplatesTable).where(and(eq(tprmQuestionnaireTemplatesTable.id, id), eq(tprmQuestionnaireTemplatesTable.tenantId, tenantId)));
  res.json({ ok: true });
});

// ── Vendor Questionnaires ──────────────────────────────────────────────────────

router.post("/tprm/vendors/:id/questionnaires", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
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
  const vendorId = parseInt(req.params.id);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmVendorQuestionnairesTable).where(and(eq(tprmVendorQuestionnairesTable.vendorId, vendorId), eq(tprmVendorQuestionnairesTable.tenantId, tenantId))).orderBy(desc(tprmVendorQuestionnairesTable.createdAt));
  res.json(rows.map(q => ({ ...q, responses: undefined })));
});

router.get("/tprm/questionnaires/:id", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const id = parseInt(req.params.id);
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
    const score = totalWeight > 0 ? Math.round(totalWeighted / totalWeight) : 50;
    const riskLevel = score >= 80 ? "low" : score >= 60 ? "medium" : score >= 40 ? "high" : "critical";

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
  const vendorId = parseInt(req.params.id);
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
  const vendorId = parseInt(req.params.id);
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
  const docId = parseInt(req.params.docId);
  const allowed = ["auditor", "auditPeriodStart", "auditPeriodEnd", "expiresAt", "coverageScope", "title"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) { if (req.body[k] !== undefined) updates[k] = req.body[k]; }
  const [doc] = await db.update(tprmComplianceDocumentsTable).set(updates).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId))).returning();
  if (!doc) { res.status(404).json({ error: "Document not found" }); return; }
  res.json({ ...doc, fileData: undefined });
});

router.delete("/tprm/vendors/:id/compliance/:docId", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId);
  await db.delete(tprmComplianceDocumentsTable).where(and(eq(tprmComplianceDocumentsTable.id, docId), eq(tprmComplianceDocumentsTable.tenantId, tenantId)));
  res.json({ ok: true });
});

router.get("/tprm/vendors/:id/compliance/:docId/download", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const docId = parseInt(req.params.docId);
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
  const vendorId = parseInt(req.params.id);
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
  const vendorId = parseInt(req.params.id);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const rows = await db.select().from(tprmSbomUploadsTable).where(and(eq(tprmSbomUploadsTable.vendorId, vendorId), eq(tprmSbomUploadsTable.tenantId, tenantId))).orderBy(desc(tprmSbomUploadsTable.createdAt));
  res.json(rows.map(r => ({ ...r, fileData: undefined })));
});

router.get("/tprm/sbom/:uploadId/components", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const uploadId = parseInt(req.params.uploadId);
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
  const uploadId = parseInt(req.params.uploadId);
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
  const vendorId = parseInt(req.params.id);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  res.json(await db.select().from(tprmVendorContactsTable).where(and(eq(tprmVendorContactsTable.vendorId, vendorId), eq(tprmVendorContactsTable.tenantId, tenantId))));
});

router.post("/tprm/vendors/:id/contacts", requireAuth, requireTprm, async (req: AuthenticatedRequest, res) => {
  const { tenantId } = req.user!;
  const vendorId = parseInt(req.params.id);
  if (!await resolveVendor(vendorId, tenantId)) { res.status(404).json({ error: "Vendor not found" }); return; }
  const { name, email, role: contactRole, isPrimary } = req.body;
  if (!name || !email) { res.status(400).json({ error: "name and email are required" }); return; }
  const [row] = await db.insert(tprmVendorContactsTable).values({ vendorId, tenantId, name, email, role: contactRole ?? null, isPrimary: !!isPrimary }).returning();
  res.status(201).json(row);
});

export default router;
