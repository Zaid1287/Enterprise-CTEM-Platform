import { Router } from "express";
import { eq, and, count, sql } from "drizzle-orm";
import { db, complianceFrameworksTable, complianceControlsTable } from "@workspace/db";
import {
  GetComplianceControlParams, UpdateComplianceControlParams,
  UpdateComplianceControlBody, ListComplianceControlsQueryParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const router = Router();

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

function toControlResponse(control: typeof complianceControlsTable.$inferSelect, frameworkName: string | null) {
  return {
    id: control.id, frameworkId: control.frameworkId, frameworkName: frameworkName ?? "",
    controlId: control.controlId, title: control.title, description: control.description,
    status: control.status, evidence: control.evidence, assignedTo: control.assignedTo,
    dueDate: control.dueDate, createdAt: control.createdAt.toISOString(),
  };
}

router.get("/compliance/frameworks", requireAuth, async (_req, res): Promise<void> => {
  const frameworks = await db.select().from(complianceFrameworksTable);
  res.json(frameworks.map(f => ({
    id: f.id, name: f.name, shortName: f.shortName, version: f.version,
    description: f.description, totalControls: f.totalControls,
  })));
});

router.get("/compliance/controls", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListComplianceControlsQueryParams.safeParse(req.query);
  const filters = [eq(complianceControlsTable.tenantId, req.user!.tenantId)];
  if (q.success) {
    if (q.data.frameworkId) filters.push(eq(complianceControlsTable.frameworkId, q.data.frameworkId));
    if (q.data.status) filters.push(eq(complianceControlsTable.status, q.data.status));
  }
  const controls = await db.select({
    control: complianceControlsTable,
    frameworkName: complianceFrameworksTable.name,
  }).from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(and(...filters));
  res.json(controls.map(({ control, frameworkName }) => toControlResponse(control, frameworkName)));
});

router.get("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetComplianceControlParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [row] = await db.select({
    control: complianceControlsTable,
    frameworkName: complianceFrameworksTable.name,
  }).from(complianceControlsTable)
    .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
    .where(and(eq(complianceControlsTable.id, params.data.controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Control not found" }); return; }
  res.json(toControlResponse(row.control, row.frameworkName));
});

router.patch("/compliance/controls/:controlId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateComplianceControlParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateComplianceControlBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [control] = await db.update(complianceControlsTable).set(parsed.data)
    .where(and(eq(complianceControlsTable.id, params.data.controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!control) { res.status(404).json({ error: "Control not found" }); return; }
  await logAudit(req.user!, "update_compliance_control", "compliance", control.id, `status: ${parsed.data.status ?? "unchanged"}`);
  const [fw] = await db.select().from(complianceFrameworksTable).where(eq(complianceFrameworksTable.id, control.frameworkId));
  res.json(toControlResponse(control, fw?.name ?? null));
});

router.post(
  "/compliance/controls/:controlId/evidence",
  requireAuth,
  upload.array("files", 10),
  async (req: AuthenticatedRequest, res): Promise<void> => {
    const controlId = parseInt(req.params.controlId, 10);
    if (isNaN(controlId)) { res.status(400).json({ error: "Invalid controlId" }); return; }

    const [row] = await db.select({
      control: complianceControlsTable,
      frameworkName: complianceFrameworksTable.name,
    }).from(complianceControlsTable)
      .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)));
    if (!row) { res.status(404).json({ error: "Control not found" }); return; }

    const files = req.files as Express.Multer.File[];
    const newFilePaths = files.map(f => ({
      name: f.originalname,
      path: f.filename,
      size: f.size,
      uploadedAt: new Date().toISOString(),
    }));

    let existing: object[] = [];
    try {
      const raw = row.control.evidence;
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) existing = parsed;
      }
    } catch {}

    const merged = [...existing, ...newFilePaths];
    const [updated] = await db.update(complianceControlsTable)
      .set({ evidence: JSON.stringify(merged) })
      .where(and(eq(complianceControlsTable.id, controlId), eq(complianceControlsTable.tenantId, req.user!.tenantId)))
      .returning();

    await logAudit(req.user!, "upload_compliance_evidence", "compliance", controlId, `${files.length} file(s) uploaded`);
    res.json(toControlResponse(updated, row.frameworkName));
  },
);

router.get("/compliance/summary", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const frameworks = await db.select().from(complianceFrameworksTable);
  const controls = await db.select().from(complianceControlsTable)
    .where(eq(complianceControlsTable.tenantId, req.user!.tenantId));

  const summary = frameworks.map(fw => {
    const fwControls = controls.filter(c => c.frameworkId === fw.id);
    const total = fwControls.length || fw.totalControls;
    const compliant = fwControls.filter(c => c.status === "compliant").length;
    const inProgress = fwControls.filter(c => c.status === "in_progress").length;
    const nonCompliant = fwControls.filter(c => c.status === "non_compliant").length;
    const score = total > 0 ? Math.round((compliant / total) * 100) : 0;
    return {
      frameworkId: fw.id, frameworkName: fw.name, shortName: fw.shortName,
      total, compliant, inProgress, nonCompliant, score,
    };
  });

  res.json(summary);
});

export default router;
