import { Router } from "express";
import { eq, and, gte, lte, desc, count } from "drizzle-orm";
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

  const pageNum  = Math.max(1, parseInt(String(req.query.page  ?? "1"),  10) || 1);
  const pageSize = Math.min(200, Math.max(1, parseInt(String(req.query.limit ?? "50"), 10) || 50));
  const offset   = (pageNum - 1) * pageSize;

  const whereClause = and(...filters);
  const [{ total }] = await db.select({ total: count() }).from(auditLogsTable).where(whereClause);
  const logs = await db.select().from(auditLogsTable).where(whereClause)
    .orderBy(desc(auditLogsTable.createdAt))
    .limit(pageSize).offset(offset);

  res.json({
    data: logs.map(l => ({
      id: l.id, tenantId: l.tenantId, userId: l.userId, userEmail: l.userEmail,
      action: l.action, resource: l.resource, resourceId: l.resourceId,
      details: l.details, ipAddress: l.ipAddress,
      device: l.device, browser: l.browser, os: l.os, userAgent: l.userAgent,
      createdAt: l.createdAt.toISOString(),
    })),
    total,
    page: pageNum,
    limit: pageSize,
    totalPages: Math.ceil(total / pageSize),
  });
});

export default router;
