import { Router, type NextFunction, type Response } from "express";
import { eq, and, inArray, desc, sql } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter } from "../lib/tenantScoping";
import {
  db, complianceFrameworksTable, complianceControlsTable, complianceControlAssetsTable,
  complianceModuleAssignmentsTable, complianceGlobalControlsTable,
  complianceControlAnswersTable, complianceAssetControlsTable,
  complianceAssetSettingsTable,
  tenantsTable, assetGroupsTable, assetsTable, usersTable,
} from "@workspace/db";
import { requireAuth, requireRole, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { getPlatformTenantId } from "../lib/seedPlatform";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const router = Router();
router.use(denyExternalMembers);

const EVIDENCE_DIR = path.join(process.cwd(), "compliance-evidence");
if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, EVIDENCE_DIR),
    filename: (_req, file, cb) => {
      const unique = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
      const ext = path.extname(file.originalname);
      cb(null, `${unique}${ext}`);
    },
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// ── Module gate middleware ─────────────────────────────────────────────────────
async function requireCompliance(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  const { tenantId, role } = req.user!;
  if (role === "admin" || role === "super_admin" || role === "account_manager") { next(); return; }
  const [row] = await db.select().from(complianceModuleAssignmentsTable)
    .where(eq(complianceModuleAssignmentsTable.tenantId, tenantId));
  if (!row?.isEnabled) { res.status(403).json({ error: "Compliance module not enabled for this tenant" }); return; }
  next();
}

// ── Module status + toggle ────────────────────────────────────────────────────
router.get("/compliance/module", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const [row] = await db.select().from(complianceModuleAssignmentsTable)
    .where(eq(complianceModuleAssignmentsTable.tenantId, req.user!.tenantId));
  res.json({ isEnabled: row?.isEnabled ?? false });
});

router.patch("/compliance/module", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const isEnabled = !!req.body.isEnabled;
  const tenantId = req.body.tenantId ? parseInt(req.body.tenantId) : req.user!.tenantId;
  await db.insert(complianceModuleAssignmentsTable)
    .values({ tenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: isEnabled ? new Date() : null })
    .onConflictDoUpdate({ target: complianceModuleAssignmentsTable.tenantId, set: { isEnabled, updatedAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "enable_compliance_module" : "disable_compliance_module", "compliance", tenantId, `tenantId: ${tenantId}`, req);
  res.json({ isEnabled, tenantId });
});

// Super admin: list all tenant module statuses
router.get("/compliance/module/assignments", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenants = await db.select({ id: tenantsTable.id, name: tenantsTable.name, isPlatform: tenantsTable.isPlatform })
    .from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
  const assignments = await db.select().from(complianceModuleAssignmentsTable);
  const map = new Map(assignments.map(a => [a.tenantId, a]));
  res.json(tenants.map(t => ({
    tenantId: t.id, tenantName: t.name,
    isEnabled: map.get(t.id)?.isEnabled ?? false,
    enabledAt: map.get(t.id)?.enabledAt ?? null,
  })));
});

// ── Global control library (platform admin manages) ───────────────────────────
router.get("/compliance/library", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const frameworkId = req.query.frameworkId ? parseInt(req.query.frameworkId as string) : null;
  const conds: any[] = [];
  if (frameworkId) conds.push(eq(complianceGlobalControlsTable.frameworkId, frameworkId));
  const controls = await db.select({
    control: complianceGlobalControlsTable,
    frameworkName: complianceFrameworksTable.name,
    frameworkShortName: complianceFrameworksTable.shortName,
  }).from(complianceGlobalControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceGlobalControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(complianceGlobalControlsTable.frameworkId, complianceGlobalControlsTable.sortOrder);
  res.json(controls.map(({ control, frameworkName, frameworkShortName }) => ({
    ...control, frameworkName, frameworkShortName,
  })));
});

router.post("/compliance/library", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { frameworkId, controlId, title, description, category, domain, controlType, riskLevel, guidance, testingProcedures, evidenceRequired, sortOrder } = req.body;
  if (!frameworkId || !controlId || !title) { res.status(400).json({ error: "frameworkId, controlId, title required" }); return; }
  const [fw] = await db.select().from(complianceFrameworksTable).where(eq(complianceFrameworksTable.id, parseInt(frameworkId)));
  if (!fw) { res.status(400).json({ error: "Framework not found" }); return; }
  const [ctrl] = await db.insert(complianceGlobalControlsTable).values({
    frameworkId: fw.id, controlId: String(controlId), title: String(title),
    description: description || null, category: category || null,
    domain: domain || null, controlType: controlType || null, riskLevel: riskLevel || null,
    guidance: guidance || null, testingProcedures: testingProcedures || null,
    evidenceRequired: evidenceRequired || null,
    sortOrder: sortOrder ? parseInt(sortOrder) : 0,
  }).returning();
  await logAudit(req.user!, "create_global_control", "compliance", ctrl.id, `${fw.shortName}: ${controlId} — ${title}`, req);
  res.status(201).json({ ...ctrl, frameworkName: fw.name, frameworkShortName: fw.shortName });
});

router.patch("/compliance/library/:id", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id as string);
  const allowed = ["controlId", "title", "description", "category", "domain", "controlType", "riskLevel", "guidance", "testingProcedures", "evidenceRequired", "isEnabled", "sortOrder"];
  const updates: Record<string, any> = { updatedAt: new Date() };
  for (const k of allowed) {
    if (req.body[k] !== undefined) {
      updates[k] = k === "isEnabled" ? Boolean(req.body[k]) : k === "sortOrder" ? parseInt(req.body[k]) : req.body[k];
    }
  }
  const [ctrl] = await db.update(complianceGlobalControlsTable).set(updates)
    .where(eq(complianceGlobalControlsTable.id, id)).returning();
  if (!ctrl) { res.status(404).json({ error: "Control not found" }); return; }
  await logAudit(req.user!, "update_global_control", "compliance", id, JSON.stringify(updates), req);
  res.json(ctrl);
});

router.delete("/compliance/library/:id", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id as string);
  const [ctrl] = await db.select().from(complianceGlobalControlsTable).where(eq(complianceGlobalControlsTable.id, id));
  if (!ctrl) { res.status(404).json({ error: "Control not found" }); return; }
  await db.delete(complianceGlobalControlsTable).where(eq(complianceGlobalControlsTable.id, id));
  await logAudit(req.user!, "delete_global_control", "compliance", id, `${ctrl.controlId} — ${ctrl.title}`, req);
  res.json({ ok: true });
});

// ── Per-tenant answers to global controls ────────────────────────────────────
router.get("/compliance/answers", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId, role } = req.user!;
  const frameworkId = req.query.frameworkId ? parseInt(req.query.frameworkId as string) : null;

  // Resolve which tenantId to pull answers for
  let targetTenantId = tenantId;
  if ((role === "super_admin" || role === "admin") && req.query.tenantId) {
    targetTenantId = parseInt(req.query.tenantId as string);
  }

  const ctrls = await db.select({
    control: complianceGlobalControlsTable,
    answer: complianceControlAnswersTable,
    frameworkName: complianceFrameworksTable.name,
    frameworkShortName: complianceFrameworksTable.shortName,
  }).from(complianceGlobalControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceGlobalControlsTable.frameworkId, complianceFrameworksTable.id))
    .leftJoin(complianceControlAnswersTable, and(
      eq(complianceControlAnswersTable.globalControlId, complianceGlobalControlsTable.id),
      eq(complianceControlAnswersTable.tenantId, targetTenantId),
    ))
    .where(frameworkId ? eq(complianceGlobalControlsTable.frameworkId, frameworkId) : undefined)
    .orderBy(complianceGlobalControlsTable.frameworkId, complianceGlobalControlsTable.sortOrder);

  res.json(ctrls.map(({ control, answer, frameworkName, frameworkShortName }) => ({
    globalControlId: control.id,
    controlId: control.controlId,
    title: control.title,
    description: control.description,
    category: control.category,
    domain: control.domain,
    controlType: control.controlType,
    riskLevel: control.riskLevel,
    guidance: control.guidance,
    testingProcedures: control.testingProcedures,
    evidenceRequired: control.evidenceRequired,
    isEnabled: control.isEnabled,
    sortOrder: control.sortOrder,
    frameworkId: control.frameworkId,
    frameworkName,
    frameworkShortName,
    answerId: answer?.id ?? null,
    status: answer?.status ?? "non_compliant",
    evidence: answer?.evidence ?? null,
    notes: answer?.notes ?? null,
    assignedTo: answer?.assignedTo ?? null,
    dueDate: answer?.dueDate ?? null,
    reviewedAt: answer?.reviewedAt ?? null,
    updatedAt: answer?.updatedAt ?? null,
  })));
});

router.put("/compliance/answers/:globalControlId", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const globalControlId = parseInt(req.params.globalControlId as string);
  if (isNaN(globalControlId)) { res.status(400).json({ error: "Invalid globalControlId" }); return; }

  const [ctrl] = await db.select().from(complianceGlobalControlsTable).where(eq(complianceGlobalControlsTable.id, globalControlId));
  if (!ctrl) { res.status(404).json({ error: "Global control not found" }); return; }

  const { status, notes, assignedTo, dueDate, reviewedAt } = req.body;
  const validStatuses = ["non_compliant", "in_progress", "compliant", "not_applicable"];
  const safeStatus = validStatuses.includes(status) ? status : "non_compliant";

  const payload: any = {
    tenantId, globalControlId,
    status: safeStatus,
    notes: notes || null,
    assignedTo: assignedTo || null,
    dueDate: dueDate || null,
    reviewedAt: reviewedAt ? new Date(reviewedAt) : (safeStatus === "compliant" ? new Date() : null),
  };

  const [answer] = await db.insert(complianceControlAnswersTable).values(payload)
    .onConflictDoUpdate({
      target: [complianceControlAnswersTable.tenantId, complianceControlAnswersTable.globalControlId],
      set: { status: payload.status, notes: payload.notes, assignedTo: payload.assignedTo, dueDate: payload.dueDate, reviewedAt: payload.reviewedAt, updatedAt: new Date() },
    }).returning();

  await logAudit(req.user!, "update_compliance_answer", "compliance", answer.id, `${ctrl.controlId}: ${safeStatus}`, req);
  res.json(answer);
});

// Evidence upload for global control answer
router.post("/compliance/answers/:globalControlId/evidence", requireAuth, requireCompliance, upload.array("files", 10), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const globalControlId = parseInt(req.params.globalControlId as string);
  if (isNaN(globalControlId)) { res.status(400).json({ error: "Invalid id" }); return; }

  const files = req.files as Express.Multer.File[];
  const newFiles = files.map(f => ({ name: f.originalname, path: f.filename, size: f.size, uploadedAt: new Date().toISOString() }));

  // Upsert answer record first
  const [existing] = await db.select().from(complianceControlAnswersTable)
    .where(and(eq(complianceControlAnswersTable.tenantId, tenantId), eq(complianceControlAnswersTable.globalControlId, globalControlId)));

  let existingFiles: object[] = [];
  try { if (existing?.evidence) existingFiles = JSON.parse(existing.evidence); } catch {}
  const merged = [...existingFiles, ...newFiles];

  if (existing) {
    await db.update(complianceControlAnswersTable).set({ evidence: JSON.stringify(merged), updatedAt: new Date() })
      .where(eq(complianceControlAnswersTable.id, existing.id));
  } else {
    await db.insert(complianceControlAnswersTable).values({ tenantId, globalControlId, status: "in_progress", evidence: JSON.stringify(merged) })
      .onConflictDoUpdate({ target: [complianceControlAnswersTable.tenantId, complianceControlAnswersTable.globalControlId], set: { evidence: JSON.stringify(merged), updatedAt: new Date() } });
  }
  res.json({ ok: true, files: newFiles });
});

// Evidence download
router.get("/compliance/answers/:globalControlId/evidence/:filename", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const globalControlId = parseInt(req.params.globalControlId as string);
  const filename = req.params.filename as string;
  if (isNaN(globalControlId) || !filename || filename.includes("..")) { res.status(400).json({ error: "Invalid" }); return; }

  const [row] = await db.select().from(complianceControlAnswersTable)
    .where(and(eq(complianceControlAnswersTable.tenantId, tenantId), eq(complianceControlAnswersTable.globalControlId, globalControlId)));
  if (!row) { res.status(404).json({ error: "Answer not found" }); return; }

  let files: { name: string; path: string }[] = [];
  try { if (row.evidence) files = JSON.parse(row.evidence); } catch {}
  const entry = files.find(f => f.path === filename);
  if (!entry) { res.status(404).json({ error: "File not found" }); return; }

  const filePath = path.join(EVIDENCE_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File missing" }); return; }
  res.download(filePath, entry.name);
});

// Evidence delete
router.delete("/compliance/answers/:globalControlId/evidence/:filename", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const globalControlId = parseInt(req.params.globalControlId as string);
  const filename = req.params.filename as string;
  if (isNaN(globalControlId) || !filename || filename.includes("..")) { res.status(400).json({ error: "Invalid" }); return; }

  const [row] = await db.select().from(complianceControlAnswersTable)
    .where(and(eq(complianceControlAnswersTable.tenantId, tenantId), eq(complianceControlAnswersTable.globalControlId, globalControlId)));
  if (!row) { res.status(404).json({ error: "Not found" }); return; }

  let files: { name: string; path: string; size: number; uploadedAt: string }[] = [];
  try { if (row.evidence) files = JSON.parse(row.evidence); } catch {}
  const idx = files.findIndex(f => f.path === filename);
  if (idx === -1) { res.status(404).json({ error: "File not found" }); return; }
  files.splice(idx, 1);
  try { fs.unlinkSync(path.join(EVIDENCE_DIR, filename)); } catch {}
  await db.update(complianceControlAnswersTable).set({ evidence: JSON.stringify(files), updatedAt: new Date() })
    .where(eq(complianceControlAnswersTable.id, row.id));
  res.json({ ok: true });
});

// ── Compliance summary (per framework, per tenant) ────────────────────────────
router.get("/compliance/summary", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId, role } = req.user!;
  let targetTenantId = tenantId;
  if ((role === "super_admin" || role === "admin") && req.query.tenantId) {
    targetTenantId = parseInt(req.query.tenantId as string);
  }

  const frameworks = await db.select().from(complianceFrameworksTable);
  // Get all global controls grouped by framework
  const allControls = await db.select().from(complianceGlobalControlsTable).where(eq(complianceGlobalControlsTable.isEnabled, true));
  // Get answers for this tenant
  const answers = await db.select().from(complianceControlAnswersTable).where(eq(complianceControlAnswersTable.tenantId, targetTenantId));
  const answerMap = new Map(answers.map(a => [a.globalControlId, a]));

  const summary = frameworks.map(fw => {
    const fwControls = allControls.filter(c => c.frameworkId === fw.id);
    const total = fwControls.length || fw.totalControls;
    const statuses = fwControls.map(c => answerMap.get(c.id)?.status ?? "non_compliant");
    const compliant = statuses.filter(s => s === "compliant").length;
    const inProgress = statuses.filter(s => s === "in_progress").length;
    const nonCompliant = statuses.filter(s => s === "non_compliant").length;
    const notApplicable = statuses.filter(s => s === "not_applicable").length;
    const score = total > 0 ? Math.round((compliant / (total - notApplicable || 1)) * 100) : 0;
    return {
      frameworkId: fw.id, frameworkName: fw.name, shortName: fw.shortName,
      version: fw.version, description: fw.description,
      total, compliant, inProgress, nonCompliant, notApplicable, score,
    };
  });
  res.json(summary);
});

// ── Client compliance overview (admin/SA/AM) ──────────────────────────────────
// Returns per-tenant compliance scores so admin can see client posture in Overview
router.get("/compliance/clients/overview", requireAuth, requireRole("admin", "super_admin", "account_manager"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { userId, role } = req.user!;
  let clientTenantIds: number[];
  if (role === "account_manager") {
    clientTenantIds = await getAmClientTenantIds(userId);
  } else {
    const privIds = await getPrivilegedTenantIds(req.user!);
    clientTenantIds = privIds;
  }
  if (clientTenantIds.length === 0) { res.json([]); return; }

  const tenants = await db.select({ id: tenantsTable.id, name: tenantsTable.name })
    .from(tenantsTable).where(inArray(tenantsTable.id, clientTenantIds));

  const allControls = await db.select().from(complianceGlobalControlsTable)
    .where(eq(complianceGlobalControlsTable.isEnabled, true));

  const allAnswers = await db.select().from(complianceControlAnswersTable)
    .where(inArray(complianceControlAnswersTable.tenantId, clientTenantIds));

  const assignments = await db.select().from(complianceModuleAssignmentsTable)
    .where(inArray(complianceModuleAssignmentsTable.tenantId, clientTenantIds));

  const result = tenants.map(t => {
    const answers = allAnswers.filter(a => a.tenantId === t.id);
    const answerMap = new Map(answers.map(a => [a.globalControlId, a]));
    const total = allControls.length;
    const statuses = allControls.map(c => answerMap.get(c.id)?.status ?? "non_compliant");
    const compliant = statuses.filter(s => s === "compliant").length;
    const inProgress = statuses.filter(s => s === "in_progress").length;
    const nonCompliant = statuses.filter(s => s === "non_compliant").length;
    const notApplicable = statuses.filter(s => s === "not_applicable").length;
    const score = total > 0 ? Math.round((compliant / (total - notApplicable || 1)) * 100) : 0;
    const moduleEnabled = assignments.find(a => a.tenantId === t.id)?.isEnabled ?? false;
    return { tenantId: t.id, tenantName: t.name, moduleEnabled, total, compliant, inProgress, nonCompliant, notApplicable, score };
  });
  res.json(result);
});

// Returns verified assets for a specific client tenant (admin view for Assignments tab)
router.get("/compliance/clients/:tenantId/assets", requireAuth, requireRole("admin", "super_admin", "account_manager"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const clientTenantId = parseInt(req.params.tenantId as string);
  const rows = await db.select({
    assetId:            assetsTable.id,
    assetName:          assetsTable.name,
    assetValue:         assetsTable.value,
    assetType:          assetsTable.type,
    verificationStatus: assetsTable.verificationStatus,
    isComplianceEnabled: complianceAssetSettingsTable.isEnabled,
    enabledAt:          complianceAssetSettingsTable.enabledAt,
  }).from(assetsTable)
    .leftJoin(complianceAssetSettingsTable, eq(complianceAssetSettingsTable.assetId, assetsTable.id))
    .where(and(
      eq(assetsTable.tenantId, clientTenantId),
      eq(assetsTable.verificationStatus, "verified"),
    ))
    .orderBy(assetsTable.name);
  res.json(rows.map(r => ({
    id: r.assetId, name: r.assetName, value: r.assetValue, type: r.assetType,
    verificationStatus: r.verificationStatus,
    isComplianceEnabled: r.isComplianceEnabled ?? false,
    enabledAt: r.enabledAt,
  })));
});

// ── Asset compliance settings: list enabled+verified assets ──────────────────
// IMPORTANT: must be registered BEFORE /:assetId to avoid Express swallowing it
router.get("/compliance/assets/enabled", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const rows = await db.select({
    assetId:            assetsTable.id,
    assetName:          assetsTable.name,
    assetValue:         assetsTable.value,
    assetType:          assetsTable.type,
    assetRiskLevel:     assetsTable.riskLevel,
    verificationStatus: assetsTable.verificationStatus,
    isEnabled:          complianceAssetSettingsTable.isEnabled,
    enabledAt:          complianceAssetSettingsTable.enabledAt,
  }).from(assetsTable)
    .innerJoin(complianceAssetSettingsTable, eq(complianceAssetSettingsTable.assetId, assetsTable.id))
    .where(and(
      eq(assetsTable.tenantId, tenantId),
      eq(assetsTable.verificationStatus, "verified"),
      eq(complianceAssetSettingsTable.isEnabled, true),
    ))
    .orderBy(assetsTable.name);
  res.json(rows.map(r => ({ id: r.assetId, name: r.assetName, domain: r.assetValue, type: r.assetType, riskLevel: r.assetRiskLevel, isEnabled: r.isEnabled, enabledAt: r.enabledAt })));
});

// ── Per-asset compliance settings (enable/disable for a specific asset) ────────
router.get("/compliance/assets/:assetId/settings", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);
  const [asset] = await db.select({ id: assetsTable.id, verificationStatus: assetsTable.verificationStatus })
    .from(assetsTable).where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  const [settings] = await db.select().from(complianceAssetSettingsTable)
    .where(eq(complianceAssetSettingsTable.assetId, assetId));
  res.json({ assetId, isEnabled: settings?.isEnabled ?? false, enabledAt: settings?.enabledAt ?? null, verificationStatus: asset.verificationStatus });
});

router.patch("/compliance/assets/:assetId/settings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId, userId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);
  const { isEnabled } = req.body;
  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }
  if (asset.verificationStatus !== "verified") {
    res.status(400).json({ error: "Only verified assets can have compliance tracking enabled" });
    return;
  }
  const [settings] = await db.insert(complianceAssetSettingsTable).values({
    assetId, tenantId,
    isEnabled: !!isEnabled,
    enabledBy: isEnabled ? (userId as any) : null,
    enabledAt: isEnabled ? new Date() : null,
    updatedAt: new Date(),
  }).onConflictDoUpdate({
    target: complianceAssetSettingsTable.assetId,
    set: { isEnabled: !!isEnabled, enabledBy: isEnabled ? (userId as any) : null, enabledAt: isEnabled ? new Date() : null, updatedAt: new Date() },
  }).returning();
  await logAudit(req.user!, isEnabled ? "compliance_enable_asset" : "compliance_disable_asset", "asset", assetId, asset.name ?? String(assetId), req);
  res.json(settings);
});

// ── Asset-level compliance ────────────────────────────────────────────────────
router.get("/compliance/assets/:assetId", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);
  const frameworkId = req.query.frameworkId ? parseInt(req.query.frameworkId as string) : null;

  // All global controls (optionally filtered by framework)
  const conds: any[] = frameworkId ? [eq(complianceGlobalControlsTable.frameworkId, frameworkId)] : [];
  const controls = await db.select({
    control: complianceGlobalControlsTable,
    frameworkName: complianceFrameworksTable.name,
    frameworkShortName: complianceFrameworksTable.shortName,
    assetControl: complianceAssetControlsTable,
    tenantAnswer: complianceControlAnswersTable,
  }).from(complianceGlobalControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceGlobalControlsTable.frameworkId, complianceFrameworksTable.id))
    .leftJoin(complianceAssetControlsTable, and(
      eq(complianceAssetControlsTable.globalControlId, complianceGlobalControlsTable.id),
      eq(complianceAssetControlsTable.assetId, assetId),
      eq(complianceAssetControlsTable.tenantId, tenantId),
    ))
    .leftJoin(complianceControlAnswersTable, and(
      eq(complianceControlAnswersTable.globalControlId, complianceGlobalControlsTable.id),
      eq(complianceControlAnswersTable.tenantId, tenantId),
    ))
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(complianceGlobalControlsTable.frameworkId, complianceGlobalControlsTable.sortOrder);

  res.json(controls.map(({ control, frameworkName, frameworkShortName, assetControl, tenantAnswer }) => ({
    globalControlId: control.id,
    controlId: control.controlId,
    title: control.title,
    description: control.description,
    category: control.category,
    isEnabled: control.isEnabled,
    frameworkId: control.frameworkId,
    frameworkName, frameworkShortName,
    // Asset-specific status (overrides tenant-level if set)
    assetControlId: assetControl?.id ?? null,
    assetStatus: assetControl?.status ?? null,
    assetNotes: assetControl?.notes ?? null,
    assetAssignedTo: assetControl?.assignedTo ?? null,
    // Tenant-level answer
    tenantStatus: tenantAnswer?.status ?? "non_compliant",
    // Effective: asset-level takes priority
    status: assetControl?.status ?? tenantAnswer?.status ?? "non_compliant",
  })));
});

router.put("/compliance/assets/:assetId/:globalControlId", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);
  const globalControlId = parseInt(req.params.globalControlId as string);
  const { status, notes, assignedTo, evidence } = req.body;
  const validStatuses = ["non_compliant", "in_progress", "compliant", "not_applicable"];
  const safeStatus = validStatuses.includes(status) ? status : "non_compliant";

  const [answer] = await db.insert(complianceAssetControlsTable).values({
    tenantId, assetId, globalControlId, status: safeStatus,
    notes: notes || null, assignedTo: assignedTo || null, evidence: evidence || null,
  }).onConflictDoUpdate({
    target: [complianceAssetControlsTable.tenantId, complianceAssetControlsTable.assetId, complianceAssetControlsTable.globalControlId],
    set: { status: safeStatus, notes: notes || null, assignedTo: assignedTo || null, evidence: evidence || null, updatedAt: new Date() },
  }).returning();

  res.json(answer);
});

// Asset compliance summary (rollup per framework for a specific asset)
router.get("/compliance/assets/:assetId/summary", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);

  const frameworks = await db.select().from(complianceFrameworksTable);
  const allControls = await db.select().from(complianceGlobalControlsTable).where(eq(complianceGlobalControlsTable.isEnabled, true));
  const assetControls = await db.select().from(complianceAssetControlsTable)
    .where(and(eq(complianceAssetControlsTable.assetId, assetId), eq(complianceAssetControlsTable.tenantId, tenantId)));
  const tenantAnswers = await db.select().from(complianceControlAnswersTable)
    .where(eq(complianceControlAnswersTable.tenantId, tenantId));

  const assetMap = new Map(assetControls.map(a => [a.globalControlId, a]));
  const answerMap = new Map(tenantAnswers.map(a => [a.globalControlId, a]));

  const summary = frameworks.map(fw => {
    const fwControls = allControls.filter(c => c.frameworkId === fw.id);
    const statuses = fwControls.map(c => assetMap.get(c.id)?.status ?? answerMap.get(c.id)?.status ?? "non_compliant");
    const total = fwControls.length;
    const compliant = statuses.filter(s => s === "compliant").length;
    const inProgress = statuses.filter(s => s === "in_progress").length;
    const nonCompliant = statuses.filter(s => s === "non_compliant").length;
    const notApplicable = statuses.filter(s => s === "not_applicable").length;
    const score = total > 0 ? Math.round((compliant / (total - notApplicable || 1)) * 100) : 0;
    return { frameworkId: fw.id, frameworkName: fw.name, shortName: fw.shortName, total, compliant, inProgress, nonCompliant, notApplicable, score };
  });
  res.json(summary);
});

// Bulk assign controls to asset (scope controls to assets)
router.post("/compliance/assets/:assetId/scope", requireAuth, requireCompliance, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId } = req.user!;
  const assetId = parseInt(req.params.assetId as string);
  const { frameworkId } = req.body;
  if (!frameworkId) { res.status(400).json({ error: "frameworkId required" }); return; }

  // Add all controls from this framework to this asset (non_compliant by default)
  const controls = await db.select({ id: complianceGlobalControlsTable.id })
    .from(complianceGlobalControlsTable)
    .where(and(eq(complianceGlobalControlsTable.frameworkId, parseInt(frameworkId)), eq(complianceGlobalControlsTable.isEnabled, true)));

  for (const ctrl of controls) {
    await db.insert(complianceAssetControlsTable).values({ tenantId, assetId, globalControlId: ctrl.id, status: "non_compliant" })
      .onConflictDoNothing();
  }
  res.json({ ok: true, count: controls.length });
});

// ── Framework management (create custom) ────────────────────────────────────
router.get("/compliance/frameworks", requireAuth, requireCompliance, async (_req, res): Promise<void> => {
  const frameworks = await db.select().from(complianceFrameworksTable).orderBy(complianceFrameworksTable.id);
  res.json(frameworks);
});

router.post("/compliance/frameworks", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { name, shortName, version, description } = req.body;
  if (!name || !shortName || !version) { res.status(400).json({ error: "name, shortName, version required" }); return; }
  const [fw] = await db.insert(complianceFrameworksTable).values({ name, shortName, version, description: description || null, totalControls: 0 }).returning();
  await logAudit(req.user!, "create_framework", "compliance", fw.id, `${name} ${version}`, req);
  res.status(201).json(fw);
});

router.patch("/compliance/frameworks/:id", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.id as string);
  const { name, shortName, version, description } = req.body;
  const updates: any = {};
  if (name) updates.name = name;
  if (shortName) updates.shortName = shortName;
  if (version) updates.version = version;
  if (description !== undefined) updates.description = description;
  const [fw] = await db.update(complianceFrameworksTable).set(updates).where(eq(complianceFrameworksTable.id, id)).returning();
  if (!fw) { res.status(404).json({ error: "Framework not found" }); return; }
  res.json(fw);
});

// ── Legacy routes (keep for backward compat) ─────────────────────────────────
router.get("/compliance/controls", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { tenantId, role } = req.user!;
  let tenantFilter;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    tenantFilter = inArray(complianceControlsTable.tenantId, filtered);
  } else if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(complianceControlsTable.tenantId, ids);
  } else {
    tenantFilter = eq(complianceControlsTable.tenantId, tenantId);
  }
  const controls = await db.select({ control: complianceControlsTable, frameworkName: complianceFrameworksTable.name })
    .from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(tenantFilter);
  res.json(controls.map(({ control, frameworkName }) => ({ ...control, frameworkName })));
});

router.get("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.controlId as string);
  const [row] = await db.select({ control: complianceControlsTable, frameworkName: complianceFrameworksTable.name })
    .from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(and(eq(complianceControlsTable.id, id), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }
  res.json({ ...row.control, frameworkName: row.frameworkName });
});

router.patch("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(req.params.controlId as string);
  const allowed = ["status", "evidence", "assignedTo", "targetGroupId", "targetAssetId", "dueDate", "isEnabled"];
  const updates: any = { updatedAt: new Date() };
  for (const k of allowed) {
    if (req.body[k] !== undefined) updates[k] = k === "isEnabled" ? Boolean(req.body[k]) : req.body[k];
  }
  const [ctrl] = await db.update(complianceControlsTable).set(updates)
    .where(and(eq(complianceControlsTable.id, id), eq(complianceControlsTable.tenantId, req.user!.tenantId))).returning();
  if (!ctrl) { res.status(404).json({ error: "Control not found" }); return; }
  res.json(ctrl);
});

router.post("/compliance/controls/:controlId/evidence", requireAuth, upload.array("files", 10), async (req: AuthenticatedRequest, res): Promise<void> => {
  const controlId = parseInt(req.params.controlId as string, 10);
  if (isNaN(controlId)) { res.status(400).json({ error: "Invalid controlId" }); return; }
  const [row] = await db.select({ control: complianceControlsTable })
    .from(complianceControlsTable)
    .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }
  const files = req.files as Express.Multer.File[];
  const newFiles = files.map(f => ({ name: f.originalname, path: f.filename, size: f.size, uploadedAt: new Date().toISOString() }));
  let existing: object[] = [];
  try { if (row.control.evidence) existing = JSON.parse(row.control.evidence); } catch {}
  const [updated] = await db.update(complianceControlsTable)
    .set({ evidence: JSON.stringify([...existing, ...newFiles]) })
    .where(eq(complianceControlsTable.id, controlId)).returning();
  res.json(updated);
});

router.get("/compliance/controls/:controlId/evidence/:filename", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const controlId = parseInt(req.params.controlId as string, 10);
  const filename = req.params.filename as string;
  if (isNaN(controlId) || !filename || filename.includes("..") || filename.includes("/")) { res.status(400).json({ error: "Invalid" }); return; }
  const [row] = await db.select({ control: complianceControlsTable })
    .from(complianceControlsTable).where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Not found" }); return; }
  let files: { name: string; path: string }[] = [];
  try { if (row.control.evidence) files = JSON.parse(row.control.evidence); } catch {}
  const entry = files.find(f => f.path === filename);
  if (!entry) { res.status(404).json({ error: "File not found" }); return; }
  const filePath = path.join(EVIDENCE_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File missing" }); return; }
  res.download(filePath, entry.name);
});

router.delete("/compliance/controls/:controlId/evidence/:filename", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const controlId = parseInt(req.params.controlId as string, 10);
  const filename = req.params.filename as string;
  if (isNaN(controlId) || !filename || filename.includes("..") || filename.includes("/")) { res.status(400).json({ error: "Invalid" }); return; }
  const [row] = await db.select({ control: complianceControlsTable })
    .from(complianceControlsTable).where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Not found" }); return; }
  let files: { name: string; path: string; size: number; uploadedAt: string }[] = [];
  try { if (row.control.evidence) files = JSON.parse(row.control.evidence); } catch {}
  const idx = files.findIndex(f => f.path === filename);
  if (idx === -1) { res.status(404).json({ error: "File not found" }); return; }
  files.splice(idx, 1);
  try { fs.unlinkSync(path.join(EVIDENCE_DIR, filename)); } catch {}
  await db.update(complianceControlsTable).set({ evidence: JSON.stringify(files) }).where(eq(complianceControlsTable.id, controlId));
  res.json({ ok: true });
});

router.post("/compliance/controls", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const { frameworkId, controlId, title, description, status } = req.body;
  if (!frameworkId || !controlId || !title) { res.status(400).json({ error: "frameworkId, controlId, and title required" }); return; }
  const fwId = parseInt(String(frameworkId), 10);
  const [fw] = await db.select().from(complianceFrameworksTable).where(eq(complianceFrameworksTable.id, fwId));
  if (!fw) { res.status(400).json({ error: "Framework not found" }); return; }
  const tenantId = req.user!.tenantId;
  const platformId = await getPlatformTenantId();
  const validStatuses = ["non_compliant", "in_progress", "compliant", "not_applicable"];
  const controlStatus = (validStatuses.includes(String(status)) ? String(status) : "non_compliant") as any;
  const [control] = await db.insert(complianceControlsTable).values({ tenantId, frameworkId: fw.id, controlId: String(controlId), title: String(title), description: description ? String(description) : null, status: controlStatus }).returning();
  if (tenantId === platformId) {
    const clientTenants = await db.select({ id: tenantsTable.id }).from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
    for (const ct of clientTenants) {
      const exists = await db.select({ id: complianceControlsTable.id }).from(complianceControlsTable)
        .where(and(eq(complianceControlsTable.tenantId, ct.id), eq(complianceControlsTable.frameworkId, fw.id), eq(complianceControlsTable.controlId, String(controlId)))).then(r => r.length > 0);
      if (!exists) await db.insert(complianceControlsTable).values({ tenantId: ct.id, frameworkId: fw.id, controlId: String(controlId), title: String(title), description: description ? String(description) : null, status: "non_compliant" });
    }
  }
  await logAudit(req.user!, "create_compliance_control", "compliance", control.id, `${fw.name}: ${controlId} — ${title}`, req);
  res.status(201).json({ ...control, frameworkName: fw.name });
});

router.delete("/compliance/controls/:controlId", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const controlId = parseInt(req.params.controlId as string, 10);
  if (isNaN(controlId)) { res.status(400).json({ error: "Invalid controlId" }); return; }
  const tenantId = req.user!.tenantId;
  const platformId = await getPlatformTenantId();
  const [row] = await db.select({ control: complianceControlsTable }).from(complianceControlsTable)
    .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, tenantId)));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }
  if (tenantId === platformId) {
    const clientTenants = await db.select({ id: tenantsTable.id }).from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
    for (const ct of clientTenants) {
      await db.delete(complianceControlsTable).where(and(eq(complianceControlsTable.tenantId, ct.id), eq(complianceControlsTable.frameworkId, row.control.frameworkId), eq(complianceControlsTable.controlId, row.control.controlId)));
    }
  }
  await db.delete(complianceControlsTable).where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, tenantId)));
  await logAudit(req.user!, "delete_compliance_control", "compliance", controlId, undefined, req);
  res.sendStatus(204);
});

export default router;
