import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, takedownRequestsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const router = Router();

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
  const rows = await db
    .select()
    .from(takedownRequestsTable)
    .where(eq(takedownRequestsTable.tenantId, tid))
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

  const [row] = await db
    .update(takedownRequestsTable)
    .set(updates)
    .where(and(eq(takedownRequestsTable.id, id), eq(takedownRequestsTable.tenantId, tid)))
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

  const [row] = await db
    .delete(takedownRequestsTable)
    .where(and(eq(takedownRequestsTable.id, id), eq(takedownRequestsTable.tenantId, tid)))
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
