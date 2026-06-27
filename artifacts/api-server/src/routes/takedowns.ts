import { Router } from "express";
import { eq, and, desc, inArray } from "drizzle-orm";
import { db, takedownRequestsTable, assetsTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getPrivilegedTenantIds, buildRecordFilter } from "../lib/tenantScoping";
import { logAudit } from "../lib/audit";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const router = Router();
router.use(denyExternalMembers);

const EVIDENCE_DIR = path.join(process.cwd(), "evidence");
if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, EVIDENCE_DIR),
    filename: (_req, file, cb) => {
      const unique = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
      cb(null, `td-${unique}-${file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_")}`);
    },
  }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/gif", "image/webp",
      "application/pdf", "text/plain", "application/zip",
      "video/mp4", "video/webm"];
    cb(null, allowed.includes(file.mimetype));
  },
});

// GET /api/takedowns
router.get("/takedowns", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const tdRole = req.user!.role;

  // Client: show only takedowns (same tenant) whose targetDomain exactly matches an assigned asset domain
  if (tdRole === "client") {
    const assignedAssets = await db.select({ value: assetsTable.value })
      .from(assetsTable)
      .where(and(eq(assetsTable.assignedClientId, req.user!.userId), eq(assetsTable.tenantId, tid)));
    if (assignedAssets.length === 0) { res.json([]); return; }
    const domains = new Set(
      assignedAssets.map(a =>
        String(a.value).toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!
      )
    );
    const tenantRows = await db.select().from(takedownRequestsTable)
      .where(eq(takedownRequestsTable.tenantId, tid))
      .orderBy(desc(takedownRequestsTable.createdAt));
    const filtered = tenantRows.filter(t => {
      if (!t.targetDomain) return false;
      const td = String(t.targetDomain).toLowerCase().replace(/^www\./, "");
      return domains.has(td);
    });
    res.json(filtered); return;
  }

  let tdWhere;
  if (tdRole === "super_admin" || tdRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    tdWhere = privIds.length > 0 ? inArray(takedownRequestsTable.tenantId, privIds) : eq(takedownRequestsTable.tenantId, -1);
  } else {
    tdWhere = eq(takedownRequestsTable.tenantId, tid);
  }
  const rows = await db
    .select()
    .from(takedownRequestsTable)
    .where(tdWhere)
    .orderBy(desc(takedownRequestsTable.createdAt));
  res.json(rows);
});

// POST /api/takedowns  (supports multipart/form-data for file uploads)
router.post("/takedowns", requireAuth, upload.array("evidenceFiles", 10), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const { type, targetUrl, targetDomain, targetIp, hostingProvider, registrar,
          title, description, evidence, brandAbused, priority } = req.body;

  if (!type || !targetUrl || !title) {
    res.status(400).json({ error: "type, targetUrl, and title are required" });
    return;
  }

  const uploadedFiles = (req.files as Express.Multer.File[] | undefined) ?? [];
  const evidenceFilenames = uploadedFiles.map(f => f.filename);

  const [row] = await db.insert(takedownRequestsTable).values({
    tenantId: tid,
    submittedByUserId: req.user!.userId,
    type, targetUrl, targetDomain, targetIp, hostingProvider, registrar,
    title, description,
    evidence: evidence ?? null,
    evidenceFiles: evidenceFilenames.length > 0 ? evidenceFilenames : [],
    brandAbused,
    priority: priority ?? "medium",
    status: "submitted",
  }).returning();

  await logAudit(req.user!.userId as any, tid, "takedown_request.create",
    `Created takedown request: ${title}`, req);

  res.status(201).json(row);
});

// PATCH /api/takedowns/:id
router.patch("/takedowns/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const id = parseInt(req.params.id, 10);
  const { status, resolutionNote, isSuccessful } = req.body;

  const updates: Record<string, unknown> = {};
  if (status) updates.status = status;
  if (resolutionNote !== undefined) updates.resolutionNote = resolutionNote;
  if (isSuccessful !== undefined) updates.isSuccessful = isSuccessful;
  if (status === "closed") updates.resolvedAt = new Date();

  let patchWhere;
  const patchRole = req.user!.role;
  if (patchRole === "super_admin" || patchRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    patchWhere = buildRecordFilter(eq(takedownRequestsTable.id, id), takedownRequestsTable.tenantId, privIds);
  } else {
    patchWhere = and(eq(takedownRequestsTable.id, id), eq(takedownRequestsTable.tenantId, tid));
  }
  const [row] = await db
    .update(takedownRequestsTable)
    .set(updates)
    .where(patchWhere)
    .returning();

  if (!row) { res.status(404).json({ error: "Not found" }); return; }

  await logAudit(req.user!.userId as any, tid, "takedown_request.update",
    `Updated takedown #${id} status: ${status}`, req);

  res.json(row);
});

// DELETE /api/takedowns/:id
router.delete("/takedowns/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const id = parseInt(req.params.id, 10);

  let delWhere;
  const delRole = req.user!.role;
  if (delRole === "super_admin" || delRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    delWhere = buildRecordFilter(eq(takedownRequestsTable.id, id), takedownRequestsTable.tenantId, privIds);
  } else {
    delWhere = and(eq(takedownRequestsTable.id, id), eq(takedownRequestsTable.tenantId, tid));
  }
  const [row] = await db
    .delete(takedownRequestsTable)
    .where(delWhere)
    .returning();

  if (!row) { res.status(404).json({ error: "Not found" }); return; }
  res.status(204).end();
});

// Serve uploaded evidence files
router.get("/takedowns/evidence/:filename", requireAuth, (req: AuthenticatedRequest, res): void => {
  const filename = path.basename(req.params.filename);
  const filePath = path.join(EVIDENCE_DIR, filename);
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: "File not found" }); return; }
  res.sendFile(filePath);
});

export default router;
