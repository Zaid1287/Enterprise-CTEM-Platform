import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, takedownRequestsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

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

// POST /api/takedowns
router.post("/takedowns", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const { type, targetUrl, targetDomain, targetIp, hostingProvider, registrar,
          title, description, evidence, brandAbused, priority } = req.body;

  if (!type || !targetUrl || !title) {
    res.status(400).json({ error: "type, targetUrl, and title are required" });
    return;
  }

  const [row] = await db.insert(takedownRequestsTable).values({
    tenantId: tid,
    submittedByUserId: req.user!.userId,
    type, targetUrl, targetDomain, targetIp, hostingProvider, registrar,
    title, description, evidence, brandAbused,
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

export default router;
