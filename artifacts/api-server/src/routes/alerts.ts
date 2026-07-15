import { Router, type Request, type Response } from "express";
import { eq, and, inArray, or, isNull } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter, buildRecordFilter } from "../lib/tenantScoping";
import { db, alertsTable, alertRulesTable, assetsTable, tenantsTable, findingsTable } from "@workspace/db";
import {
  GetAlertParams, UpdateAlertParams, UpdateAlertBody, ListAlertsQueryParams,
  CreateAlertRuleBody, UpdateAlertRuleBody, UpdateAlertRuleParams,
} from "@workspace/api-zod";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest, verifyToken } from "../lib/auth";
import { addSseClient, removeSseClient } from "../lib/sseManager";
import { sendChannelNotification } from "../lib/notifier";
import { cacheDelete, ck } from "../lib/cache";
import type { NotificationEvent } from "../lib/notifier";
import { getPlatformSetting } from "./platformSettings";
import { logger } from "../lib/logger";

const router = Router();
router.use(denyExternalMembers);

// Org-level notification channels are stored as alert rules with this name prefix.
// They have triggerType="any" so they fire on every event for the tenant.
const CHANNEL_PREFIX = "__channel__";
const CHANNEL_KEYS = ["email", "slack", "discord", "telegram", "webhook"] as const;
type ChannelKey = typeof CHANNEL_KEYS[number];

function toAlertResponse(a: typeof alertsTable.$inferSelect & { tenantName?: string | null; tenantCount?: number }) {
  return {
    id: a.id, tenantId: a.tenantId, tenantName: a.tenantName ?? null,
    title: a.title, message: a.message,
    type: a.type, severity: a.severity, isRead: a.isRead,
    relatedAssetId: a.relatedAssetId, relatedFindingId: a.relatedFindingId,
    createdAt: a.createdAt.toISOString(),
    tenantCount: a.tenantCount ?? 1,
  };
}

function toRuleResponse(r: typeof alertRulesTable.$inferSelect) {
  return {
    id: r.id, tenantId: r.tenantId, name: r.name, triggerType: r.triggerType,
    channel: r.channel, destination: r.destination, isActive: r.isActive,
    groupId: (r as any).groupId ?? null,
    createdAt: r.createdAt.toISOString(),
  };
}

// ── SSE stream ────────────────────────────────────────────────────────────────
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

// ── Alert rules ───────────────────────────────────────────────────────────────
// List alert rules — excludes org-level channel rules (shown in /notification-channels)
router.get("/alerts/rules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const rules = await db.select().from(alertRulesTable)
    .where(eq(alertRulesTable.tenantId, req.user!.tenantId));
  // Filter out internal __channel__ rules — those are managed via /notification-channels
  res.json(rules.filter(r => !r.name.startsWith(CHANNEL_PREFIX)).map(toRuleResponse));
});

router.post("/alerts/rules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateAlertRuleBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const groupId = typeof req.body.groupId === "number" ? req.body.groupId : null;
  const [rule] = await db.insert(alertRulesTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, ...(groupId ? { groupId } : {}),
  } as any).returning();
  res.status(201).json(toRuleResponse(rule));
});

// ── Test a specific alert rule ────────────────────────────────────────────────
router.post("/alerts/rules/:ruleId/test", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const ruleId = parseInt(req.params.ruleId as string, 10);
  if (isNaN(ruleId)) { res.status(400).json({ error: "Invalid ruleId" }); return; }

  const [rule] = await db.select().from(alertRulesTable)
    .where(and(eq(alertRulesTable.id, ruleId), eq(alertRulesTable.tenantId, req.user!.tenantId)));
  if (!rule) { res.status(404).json({ error: "Rule not found" }); return; }

  const testEvent: NotificationEvent = {
    tenantId: req.user!.tenantId,
    eventType: "scan_complete",
    title: "🧪 Test Notification — Sentinelware CTEM",
    message: `Test for rule "${rule.name}". If you received this, your ${rule.channel} channel is configured correctly.`,
    severity: "info",
    findingsCount: 3, criticalCount: 1, highCount: 2,
    assetName: "test-asset.example.com", scanId: 0,
  };

  let dest = rule.destination;
  if (!dest) {
    dest = await getPlatformSetting(
      rule.channel === "slack"    ? "slack_webhook_url" :
      rule.channel === "discord"  ? "discord_webhook_url" :
      rule.channel === "telegram" ? "telegram_bot_token" : ""
    ) ?? "";
    if (rule.channel === "telegram" && dest) {
      const chatId = await getPlatformSetting("telegram_chat_id") ?? "";
      dest = `${dest}:${chatId}`;
    }
  }

  if (!dest) {
    res.status(422).json({ error: `No destination for "${rule.channel}". Set a destination on the rule or configure platform settings.` });
    return;
  }

  try {
    await sendChannelNotification(rule.channel, dest, testEvent);
    logger.info({ ruleId, channel: rule.channel, tenantId: req.user!.tenantId }, "Test notification sent");
    res.json({ success: true, channel: rule.channel, destination: dest.length > 40 ? dest.slice(0, 37) + "…" : dest });
  } catch (err: any) {
    logger.warn({ err, ruleId, channel: rule.channel }, "Test notification failed");
    res.status(502).json({ error: err?.message ?? "Delivery failed. Check your destination URL/token." });
  }
});

// ── Test a channel without saving a rule ──────────────────────────────────────
router.post("/alerts/test-channel", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { channel, destination } = req.body as { channel?: string; destination?: string };
  if (!channel || !destination) {
    res.status(400).json({ error: "channel and destination are required" }); return;
  }
  const allowed = ["email", "slack", "discord", "telegram", "webhook"];
  if (!allowed.includes(channel)) {
    res.status(400).json({ error: `Invalid channel. Must be one of: ${allowed.join(", ")}` }); return;
  }

  const testEvent: NotificationEvent = {
    tenantId: req.user!.tenantId,
    eventType: "scan_complete",
    title: "🧪 Test Notification — Sentinelware CTEM",
    message: `Test notification via ${channel}. Your channel is configured correctly.`,
    severity: "info", findingsCount: 3, criticalCount: 1, highCount: 2,
    assetName: "test-asset.example.com", scanId: 0,
  };

  try {
    await sendChannelNotification(channel, destination, testEvent);
    res.json({ success: true });
  } catch (err: any) {
    res.status(502).json({ error: err?.message ?? "Delivery failed" });
  }
});

// ── Org-level notification channels ──────────────────────────────────────────
// GET /notification-channels — returns the org's configured notification channels
router.get("/notification-channels", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const rules = await db.select().from(alertRulesTable)
    .where(eq(alertRulesTable.tenantId, req.user!.tenantId));

  const channelRules = new Map<string, typeof alertRulesTable.$inferSelect>();
  for (const rule of rules) {
    if (rule.name.startsWith(CHANNEL_PREFIX)) {
      channelRules.set(rule.name.slice(CHANNEL_PREFIX.length), rule);
    }
  }

  const result: Record<string, { enabled: boolean; destination: string; ruleId?: number }> = {};
  for (const ch of CHANNEL_KEYS) {
    const rule = channelRules.get(ch);
    result[ch] = {
      enabled: rule ? rule.isActive : false,
      destination: rule?.destination ?? "",
      ruleId: rule?.id,
    };
  }
  res.json(result);
});

// PUT /notification-channels — saves org-level notification channel config
router.put("/notification-channels", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const channels = req.body as Record<string, { enabled: boolean; destination: string }>;
  const tenantId = req.user!.tenantId;

  // Load existing __channel__ rules for this tenant
  const existing = await db.select().from(alertRulesTable)
    .where(eq(alertRulesTable.tenantId, tenantId));
  const existingMap = new Map<string, number>(); // channelKey → ruleId
  for (const rule of existing) {
    if (rule.name.startsWith(CHANNEL_PREFIX)) {
      existingMap.set(rule.name.slice(CHANNEL_PREFIX.length), rule.id);
    }
  }

  for (const ch of CHANNEL_KEYS) {
    const config = channels[ch];
    if (!config) continue;
    const name = `${CHANNEL_PREFIX}${ch}`;
    const existingId = existingMap.get(ch);

    if (existingId) {
      await db.update(alertRulesTable).set({
        isActive: config.enabled,
        destination: config.destination || null,
      }).where(eq(alertRulesTable.id, existingId));
    } else if (config.enabled || config.destination) {
      await db.insert(alertRulesTable).values({
        tenantId,
        name,
        triggerType: "any",
        channel: ch,
        destination: config.destination || null,
        isActive: config.enabled,
      });
    }
  }

  res.json({ ok: true });
});

// ── Test a specific notification channel from org settings ────────────────────
router.post("/notification-channels/:channel/test", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const channel = req.params.channel as string;
  const { destination } = req.body as { destination?: string };
  const allowed = ["email", "slack", "discord", "telegram", "webhook"];
  if (!allowed.includes(channel)) {
    res.status(400).json({ error: "Invalid channel" }); return;
  }

  if (!destination) {
    res.status(422).json({ error: "destination is required" }); return;
  }

  const testEvent: NotificationEvent = {
    tenantId: req.user!.tenantId,
    eventType: "scan_complete",
    title: "🧪 Test Notification — Sentinelware CTEM",
    message: `Org-level ${channel} channel is configured correctly and ready to receive alerts.`,
    severity: "info", findingsCount: 5, criticalCount: 2, highCount: 2,
    assetName: "production-app.yourdomain.com", scanId: 0,
  };

  try {
    await sendChannelNotification(channel, destination, testEvent);
    logger.info({ channel, tenantId: req.user!.tenantId }, "Org channel test notification sent");
    res.json({ success: true });
  } catch (err: any) {
    logger.warn({ err, channel }, "Org channel test failed");
    res.status(502).json({ error: err?.message ?? "Delivery failed. Check your destination URL or credentials." });
  }
});

// ── Alerts ────────────────────────────────────────────────────────────────────
router.get("/alerts", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListAlertsQueryParams.safeParse(req.query);
  const role = req.user!.role;
  let tenantFilter;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    tenantFilter = inArray(alertsTable.tenantId, filtered);
  } else if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(alertsTable.tenantId, ids);
  } else if (role === "client") {
    tenantFilter = undefined;
  } else {
    tenantFilter = eq(alertsTable.tenantId, req.user!.tenantId);
  }
  const filters: any[] = tenantFilter ? [tenantFilter] : [];

  // Determine "all-clients" view once — used for dedup below and for the verified-asset gate
  const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
  const isAllTenantsAdminView = (role === "super_admin" || role === "admin") && isNaN(qTenantId);

  // When showing alerts across ALL clients, only surface alerts linked to verified assets.
  // Alerts with no relatedAssetId (tool_update, scan_complete, orchestrator, etc.) always pass through.
  if (isAllTenantsAdminView) {
    filters.push(or(isNull(alertsTable.relatedAssetId), eq(assetsTable.verificationStatus, "verified")) as any);
  }

  if (role === "client") {
    // Platform-managed assets assigned to this client (may be in a different tenant, e.g. tenantId=1)
    const assignedAssets = await db.select({ id: assetsTable.id, tenantId: assetsTable.tenantId })
      .from(assetsTable).where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = assignedAssets.map(a => a.id);
    if (assignedIds.length === 0) { res.json([]); return; }

    // All tenantIds the client's assigned assets belong to, plus own tenant
    const assetTenantIds = [...new Set([...assignedAssets.map(a => a.tenantId), req.user!.tenantId])];

    // Finding IDs for assigned assets — enables relatedFindingId linkage
    const assignedFindings = await db.select({ id: findingsTable.id })
      .from(findingsTable).where(inArray(findingsTable.assetId, assignedIds));
    const assignedFindingIds = assignedFindings.map(f => f.id);

    // Alert visibility rules (OR):
    //  1. Alert explicitly linked to one of the client's assigned assets
    //  2. Alert linked to a finding on one of their assigned assets
    //  3. Scan-completion / global alerts (no asset/finding) in the same tenant scope
    const conditions: any[] = [
      inArray(alertsTable.relatedAssetId, assignedIds),
      and(inArray(alertsTable.tenantId, assetTenantIds.filter((t): t is number => t !== null)), isNull(alertsTable.relatedAssetId), isNull(alertsTable.relatedFindingId)),
    ];
    if (assignedFindingIds.length > 0) {
      conditions.push(inArray(alertsTable.relatedFindingId, assignedFindingIds));
    }
    filters.push(or(...conditions) as any);
  }

  if (q.success) {
    if (q.data.severity) filters.push(eq(alertsTable.severity, q.data.severity));
    if (q.data.read !== undefined) filters.push(eq(alertsTable.isRead, q.data.read));
  }
  // Type filter — not in generated schema, read directly from query
  const qType = req.query.type as string | undefined;
  if (qType) filters.push(eq(alertsTable.type, qType));
  // Asset filter — narrow to a specific verified asset
  const qAssetId = req.query.assetId ? parseInt(req.query.assetId as string, 10) : NaN;
  if (!isNaN(qAssetId)) filters.push(eq(alertsTable.relatedAssetId, qAssetId));

  // Fetch alerts with tenant name via left join; also join assets for verificationStatus filtering
  const rows = await db
    .select({
      id: alertsTable.id, tenantId: alertsTable.tenantId, title: alertsTable.title,
      message: alertsTable.message, type: alertsTable.type, severity: alertsTable.severity,
      isRead: alertsTable.isRead, relatedAssetId: alertsTable.relatedAssetId,
      relatedFindingId: alertsTable.relatedFindingId, createdAt: alertsTable.createdAt,
      tenantName: tenantsTable.name,
    })
    .from(alertsTable)
    .leftJoin(tenantsTable, eq(alertsTable.tenantId, tenantsTable.id))
    .leftJoin(assetsTable, eq(alertsTable.relatedAssetId, assetsTable.id))
    .where(filters.length ? and(...filters) : undefined);

  // For privileged users viewing all tenants (no specific tenant filter), deduplicate
  // tool_update alerts by title — the same tool update fires for every tenant but is
  // platform-wide news, so showing N identical rows is confusing. Keep the most recent
  // per title and report how many tenants share it via tenantCount.
  let result: typeof rows;
  if (isAllTenantsAdminView) {
    const seen = new Map<string, typeof rows[number] & { tenantCount: number }>();
    for (const row of rows) {
      if (row.type === "tool_update") {
        const key = row.title;
        const existing = seen.get(key);
        if (!existing) {
          seen.set(key, { ...row, tenantName: null, tenantCount: 1 });
        } else {
          existing.tenantCount++;
          // Keep most recent
          if (row.createdAt > existing.createdAt) {
            seen.set(key, { ...row, tenantName: null, tenantCount: existing.tenantCount });
          }
        }
      } else {
        seen.set(`${row.type}:${row.id}`, { ...row, tenantCount: 1 });
      }
    }
    result = [...seen.values()];
  } else {
    result = rows.map(r => ({ ...r, tenantCount: 1 }));
  }

  res.json(result.map((a: any) => toAlertResponse(a)));
});

router.get("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetAlertParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const alertRole = req.user!.role;
  let alertWhere;
  if (alertRole === "super_admin" || alertRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    alertWhere = buildRecordFilter(eq(alertsTable.id, params.data.alertId), alertsTable.tenantId, privIds);
  } else if (alertRole === "client") {
    const assignedAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = assignedAssets.map(a => a.id);
    if (assignedIds.length === 0) { res.status(404).json({ error: "Alert not found" }); return; }
    alertWhere = and(eq(alertsTable.id, params.data.alertId), inArray(alertsTable.relatedAssetId, assignedIds));
  } else {
    alertWhere = and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId));
  }
  const [alert] = await db.select().from(alertsTable).where(alertWhere);
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
  res.json(toRuleResponse(rule));
});

router.delete("/alerts/rules/:ruleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const ruleId = parseInt(req.params.ruleId as string, 10);
  if (isNaN(ruleId)) { res.status(400).json({ error: "Invalid ruleId" }); return; }
  const [deleted] = await db.delete(alertRulesTable)
    .where(and(eq(alertRulesTable.id, ruleId), eq(alertRulesTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!deleted) { res.status(404).json({ error: "Rule not found" }); return; }
  res.status(204).end();
});

router.delete("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const alertId = parseInt(req.params.alertId as string, 10);
  if (isNaN(alertId)) { res.status(400).json({ error: "Invalid alertId" }); return; }
  const delRole = req.user!.role;

  // Clients cannot delete alerts
  if (delRole === "client") {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  let delWhere;
  if (delRole === "super_admin" || delRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    delWhere = buildRecordFilter(eq(alertsTable.id, alertId), alertsTable.tenantId, privIds);
  } else {
    delWhere = and(eq(alertsTable.id, alertId), eq(alertsTable.tenantId, req.user!.tenantId));
  }
  const [deleted] = await db.delete(alertsTable).where(delWhere).returning();
  if (!deleted) { res.status(404).json({ error: "Alert not found" }); return; }
  res.status(204).end();
});

router.patch("/alerts/:alertId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateAlertParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateAlertBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const patchAlertRole = req.user!.role;

  // Client role: verify the alert's relatedAssetId is one of their assigned assets
  if (patchAlertRole === "client") {
    const [alertRow] = await db.select({ relatedAssetId: alertsTable.relatedAssetId })
      .from(alertsTable)
      .where(and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId)));
    if (!alertRow) { res.status(404).json({ error: "Alert not found" }); return; }
    // Alerts without a relatedAssetId are not scoped to this client
    if (alertRow.relatedAssetId == null) { res.status(404).json({ error: "Alert not found" }); return; }
    const [assigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, alertRow.relatedAssetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!assigned) { res.status(404).json({ error: "Alert not found" }); return; }
  }

  let patchAlertWhere;
  if (patchAlertRole === "super_admin" || patchAlertRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    patchAlertWhere = buildRecordFilter(eq(alertsTable.id, params.data.alertId), alertsTable.tenantId, privIds);
  } else {
    patchAlertWhere = and(eq(alertsTable.id, params.data.alertId), eq(alertsTable.tenantId, req.user!.tenantId));
  }
  const [alert] = await db.update(alertsTable).set(parsed.data)
    .where(patchAlertWhere)
    .returning();
  if (!alert) { res.status(404).json({ error: "Alert not found" }); return; }
  // Invalidate the dashboard overview cache so Open Alerts count is immediately accurate
  await cacheDelete(ck("dash:overview", alert.tenantId));
  res.json(toAlertResponse(alert));
});

export default router;
