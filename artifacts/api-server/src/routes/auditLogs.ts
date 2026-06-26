import { Router } from "express";
import { eq, and, gte, lte } from "drizzle-orm";
import { db, auditLogsTable } from "@workspace/db";
import { ListAuditLogsQueryParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/audit-logs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListAuditLogsQueryParams.safeParse(req.query);
  const filters = [eq(auditLogsTable.tenantId, req.user!.tenantId)];
  if (q.success) {
    if (q.data.userId) filters.push(eq(auditLogsTable.userId, q.data.userId));
    if (q.data.action) filters.push(eq(auditLogsTable.action, q.data.action));
    if (q.data.from) filters.push(gte(auditLogsTable.createdAt, new Date(q.data.from)));
    if (q.data.to) filters.push(lte(auditLogsTable.createdAt, new Date(q.data.to)));
  }
  const logs = await db.select().from(auditLogsTable).where(and(...filters));
  res.json(logs.map(l => ({
    id: l.id, tenantId: l.tenantId, userId: l.userId, userEmail: l.userEmail,
    action: l.action, resource: l.resource, resourceId: l.resourceId,
    details: l.details, ipAddress: l.ipAddress,
    device: l.device, browser: l.browser, os: l.os, userAgent: l.userAgent,
    createdAt: l.createdAt.toISOString(),
  })));
});

export default router;
