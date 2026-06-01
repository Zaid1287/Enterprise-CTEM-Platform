import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, reportsTable } from "@workspace/db";
import { CreateReportBody, GetReportParams, DeleteReportParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toReportResponse(r: typeof reportsTable.$inferSelect) {
  return {
    id: r.id, tenantId: r.tenantId, title: r.title, type: r.type, format: r.format,
    status: r.status, downloadUrl: r.downloadUrl,
    generatedAt: r.generatedAt?.toISOString() ?? null,
    createdAt: r.createdAt.toISOString(),
  };
}

router.get("/reports", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const reports = await db.select().from(reportsTable)
    .where(eq(reportsTable.tenantId, req.user!.tenantId));
  res.json(reports.map(toReportResponse));
});

router.post("/reports", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateReportBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [report] = await db.insert(reportsTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, status: "pending",
  }).returning();
  // Simulate report generation
  setTimeout(async () => {
    await db.update(reportsTable).set({
      status: "ready",
      generatedAt: new Date(),
      downloadUrl: `/api/reports/${report.id}/download`,
    }).where(eq(reportsTable.id, report.id));
  }, 3000);
  await logAudit(req.user!, "create_report", "report", report.id);
  res.status(201).json(toReportResponse(report));
});

router.get("/reports/:reportId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetReportParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [report] = await db.select().from(reportsTable)
    .where(and(eq(reportsTable.id, params.data.reportId), eq(reportsTable.tenantId, req.user!.tenantId)));
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }
  res.json(toReportResponse(report));
});

router.delete("/reports/:reportId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteReportParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [report] = await db.delete(reportsTable)
    .where(and(eq(reportsTable.id, params.data.reportId), eq(reportsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }
  await logAudit(req.user!, "delete_report", "report", report.id);
  res.sendStatus(204);
});

export default router;
