import { Router } from "express";
import { eq, and } from "drizzle-orm";
import { db, alertsTable, alertRulesTable } from "@workspace/db";
import {
  GetAlertParams, UpdateAlertParams, UpdateAlertBody, ListAlertsQueryParams,
  CreateAlertRuleBody,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

function toAlertResponse(a: typeof alertsTable.$inferSelect) {
  return {
    id: a.id, tenantId: a.tenantId, title: a.title, message: a.message,
    type: a.type, severity: a.severity, isRead: a.isRead,
    relatedAssetId: a.relatedAssetId, relatedFindingId: a.relatedFindingId,
    createdAt: a.createdAt.toISOString(),
  };
}

router.get("/alerts", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListAlertsQueryParams.safeParse(req.query);
  const filters = [eq(alertsTable.tenantId, req.user!.tenantId)];
  if (q.success) {
    if (q.data.severity) filters.push(eq(alertsTable.severity, q.data.severity));
    if (q.data.read !== undefined) filters.push(eq(alertsTable.isRead, q.data.read));
  }
  const alerts = await db.select().from(alertsTable).where(and(...filters));
  res.json(alerts.map(toAlertResponse));
});

router.get("/alerts/rules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const rules = await db.select().from(alertRulesTable)
    .where(eq(alertRulesTable.tenantId, req.user!.tenantId));
  res.json(rules.map(r => ({
    id: r.id, tenantId: r.tenantId, name: r.name, triggerType: r.triggerType,
    channel: r.channel, destination: r.destination, isActive: r.isActive,
    createdAt: r.createdAt.toISOString(),
  })));
});

router.post("/alerts/rules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAlertRuleBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [rule] = await db.insert(alertRulesTable).values({
    ...parsed.data, tenantId: req.user!.tenantId,
  }).returning();
  res.status(201).json({
    id: rule.id, tenantId: rule.tenantId, name: rule.name, triggerType: rule.triggerType,
    channel: rule.channel, destination: rule.destination, isActive: rule.isActive,
    createdAt: rule.createdAt.toISOString(),
  });
});

router.get("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAlertParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [alert] = await db.select().from(alertsTable)
    .where(and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId)));
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  res.json(toAlertResponse(alert));
});

router.patch("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAlertParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAlertBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [alert] = await db.update(alertsTable).set(parsed.data)
    .where(and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  res.json(toAlertResponse(alert));
});

export default router;
