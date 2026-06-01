import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, scansTable, scanJobsTable } from "@workspace/db";
import {
  CreateScanBody, GetScanParams, DeleteScanParams, CancelScanParams,
  ListScansQueryParams, ListScanJobsParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toScanResponse(s: typeof scansTable.$inferSelect) {
  return {
    id: s.id, tenantId: s.tenantId, name: s.name, type: s.type, status: s.status,
    schedule: s.schedule, assetIds: s.assetIds ?? [], findingsCount: s.findingsCount,
    startedAt: s.startedAt?.toISOString() ?? null,
    completedAt: s.completedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  };
}

router.get("/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListScansQueryParams.safeParse(req.query);
  const filters = [eq(scansTable.tenantId, req.user!.tenantId)];
  if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status));
  const scans = await db.select().from(scansTable).where(and(...filters));
  res.json(scans.map(toScanResponse));
});

router.post("/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [scan] = await db.insert(scansTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, status: "pending",
    startedAt: new Date(),
  }).returning();
  // Simulate scan jobs
  if (scan.assetIds.length > 0) {
    await db.insert(scanJobsTable).values(
      scan.assetIds.map(assetId => ({ scanId: scan.id, assetId, status: "pending" }))
    );
    // Auto-simulate completion after insertion
    setTimeout(async () => {
      await db.update(scansTable).set({ status: "running" }).where(eq(scansTable.id, scan.id));
      setTimeout(async () => {
        await db.update(scansTable).set({ status: "completed", completedAt: new Date() }).where(eq(scansTable.id, scan.id));
        await db.update(scanJobsTable).set({ status: "completed", completedAt: new Date() }).where(eq(scanJobsTable.scanId, scan.id));
      }, 5000);
    }, 2000);
  }
  await logAudit(req.user!, "create_scan", "scan", scan.id);
  res.status(201).json(toScanResponse(scan));
});

router.get("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [scan] = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(toScanResponse(scan));
});

router.delete("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  await db.delete(scanJobsTable).where(eq(scanJobsTable.scanId, params.data.scanId));
  const [scan] = await db.delete(scansTable)
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.sendStatus(204);
});

router.post("/scans/:scanId/cancel", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CancelScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [scan] = await db.update(scansTable).set({ status: "cancelled", completedAt: new Date() })
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(toScanResponse(scan));
});

router.get("/scans/:scanId/jobs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = ListScanJobsParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const jobs = await db.select().from(scanJobsTable).where(eq(scanJobsTable.scanId, params.data.scanId));
  res.json(jobs.map(j => ({
    id: j.id, scanId: j.scanId, assetId: j.assetId, status: j.status,
    result: j.result, errorMessage: j.errorMessage,
    startedAt: j.startedAt?.toISOString() ?? null,
    completedAt: j.completedAt?.toISOString() ?? null,
    createdAt: j.createdAt.toISOString(),
  })));
});

export default router;
