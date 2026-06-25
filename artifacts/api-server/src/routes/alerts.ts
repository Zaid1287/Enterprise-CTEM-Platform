import { Router, type Request, type Response } from "express";
import { eq, and, inArray, isNull, or } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { db, alertsTable, alertRulesTable, assetsTable } from "@workspace/db";
import {
  GetAlertParams, UpdateAlertParams, UpdateAlertBody, ListAlertsQueryParams,
  CreateAlertRuleBody, UpdateAlertRuleBody, UpdateAlertRuleParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest, verifyToken } from "../lib/auth";
import { addSseClient, removeSseClient } from "../lib/sseManager";

const router = Router();

function toAlertResponse(a: typeof alertsTable.$inferSelect) {
  return {
    id: a.id, tenantId: a.tenantId, title: a.title, message: a.message,
    type: a.type, severity: a.severity, isRead: a.isRead,
    relatedAssetId: a.relatedAssetId, relatedFindingId: a.relatedFindingId,
    createdAt: a.createdAt.toISOString(),
  };
}

router.get("/alerts/stream", (req: Request, res: Response): void => {
  const token = req.query.token as string;
  if (!token) { res.status(401).end(); return; }
  let user: ReturnType<typeof verifyToken>;
  try { user = verifyToken(token); } catch { res.status(401).end(); return; }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  addSseClient(user.tenantId, res);
  res.write(": connected\n\n");

  const keepAlive = setInterval(() => {
    try { res.write(": keepalive\n\n"); } catch {}
  }, 25000);

  req.on("close", () => {
    clearInterval(keepAlive);
    removeSseClient(user.tenantId, res);
  });
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

router.get("/alerts", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListAlertsQueryParams.safeParse(req.query);
  const role = req.user!.role;
  let tenantFilter;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(alertsTable.tenantId, ids);
  } else {
    tenantFilter = eq(alertsTable.tenantId, req.user!.tenantId);
  }
  const filters = [tenantFilter];

  if (role === "client") {
    // Look up assigned assets cross-tenant (no tenant_id restriction — client assets can span tenants)
    const assignedAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = assignedAssets.map(a => a.id);
    if (assignedIds.length > 0) {
      filters.push(inArray(alertsTable.relatedAssetId, assignedIds) as any);
    } else {
      res.json([]); return;
    }
  }

  if (q.success) {
    if (q.data.severity) filters.push(eq(alertsTable.severity, q.data.severity));
    if (q.data.read !== undefined) filters.push(eq(alertsTable.isRead, q.data.read));
  }
  const alerts = await db.select().from(alertsTable).where(and(...filters));
  res.json(alerts.map(toAlertResponse));
});

router.get("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAlertParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [alert] = await db.select().from(alertsTable)
    .where(and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId)));
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  res.json(toAlertResponse(alert));
});

router.patch("/alerts/rules/:ruleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAlertRuleParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAlertRuleBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [rule] = await db.update(alertRulesTable)
    .set(parsed.data)
    .where(and(eq(alertRulesTable.id, params.data.ruleId), eq(alertRulesTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }
  res.json({
    id: rule.id, tenantId: rule.tenantId, name: rule.name, triggerType: rule.triggerType,
    channel: rule.channel, destination: rule.destination, isActive: rule.isActive,
    createdAt: rule.createdAt.toISOString(),
  });
});

router.delete("/alerts/rules/:ruleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const ruleId = parseInt(req.params.ruleId, 10);
  if (isNaN(ruleId)) { res.status(400).json({ error: "Invalid ruleId" }); return; }
  const [deleted] = await db.delete(alertRulesTable)
    .where(and(eq(alertRulesTable.id, ruleId), eq(alertRulesTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!deleted) { res.status(404).json({ error: "Rule not found" }); return; }
  res.status(204).end();
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
