import { Router } from "express";
import {
  db,
  shadowItAssetsTable,
  shadowItSaasAppsTable,
  shadowItIdpConnectionsTable,
  shadowItOauthAppsTable,
  shadowItOauthUsersTable,
  shadowItNetworkDevicesTable,
} from "@workspace/db";
import { eq, and, desc, count, sql } from "drizzle-orm";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { runShadowItDiscovery } from "../lib/shadowItCorrelation";
import { syncIdpConnection, syncAllIdpConnections } from "../lib/idpConnectors/idpSync";
import { runInternalNetworkScan, detectLocalSubnets } from "../lib/internalNetworkScanner";
import { logger } from "../lib/logger";

const router = Router();
router.use(requireAuth);

// ── Helpers ───────────────────────────────────────────────────────────────────

function pid(req: AuthenticatedRequest, name: string): number {
  const v = parseInt(req.params[name] as string, 10);
  return isNaN(v) ? -1 : v;
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/dashboard", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  try {
    const [
      assetStats,
      saasStats,
      idpConns,
      oauthRisk,
      topRiskyApps,
      netDeviceStats,
    ] = await Promise.all([
      // shadow assets
      db.select({ status: shadowItAssetsTable.status, riskLevel: shadowItAssetsTable.riskLevel, c: count() })
        .from(shadowItAssetsTable).where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.status, shadowItAssetsTable.riskLevel),
      // saas apps
      db.select({ isSanctioned: shadowItSaasAppsTable.isSanctioned, c: count() })
        .from(shadowItSaasAppsTable).where(eq(shadowItSaasAppsTable.tenantId, tenantId))
        .groupBy(shadowItSaasAppsTable.isSanctioned),
      // idp connections
      db.select().from(shadowItIdpConnectionsTable).where(eq(shadowItIdpConnectionsTable.tenantId, tenantId)),
      // oauth risk breakdown
      db.select({ riskLevel: shadowItOauthAppsTable.riskLevel, c: count() })
        .from(shadowItOauthAppsTable).where(eq(shadowItOauthAppsTable.tenantId, tenantId))
        .groupBy(shadowItOauthAppsTable.riskLevel),
      // top risky oauth apps
      db.select().from(shadowItOauthAppsTable)
        .where(and(eq(shadowItOauthAppsTable.tenantId, tenantId), eq(shadowItOauthAppsTable.status, "active")))
        .orderBy(desc(shadowItOauthAppsTable.riskScore))
        .limit(10),
      // network device counts
      db.select({ deviceType: shadowItNetworkDevicesTable.deviceType, status: shadowItNetworkDevicesTable.status, c: count() })
        .from(shadowItNetworkDevicesTable).where(eq(shadowItNetworkDevicesTable.tenantId, tenantId))
        .groupBy(shadowItNetworkDevicesTable.deviceType, shadowItNetworkDevicesTable.status),
    ]);

    const assetRisk: Record<string, number> = {};
    let assetTotal = 0; let assetPending = 0;
    for (const r of assetStats) {
      assetTotal += Number(r.c);
      if (r.status === "new") assetPending += Number(r.c);
      if (r.riskLevel === "critical" || r.riskLevel === "high") {
        assetRisk[r.riskLevel] = (assetRisk[r.riskLevel] ?? 0) + Number(r.c);
      }
    }

    let saasTotal = 0; let saasUnsanctioned = 0;
    for (const r of saasStats) {
      saasTotal += Number(r.c);
      if (!r.isSanctioned) saasUnsanctioned += Number(r.c);
    }

    const oauthByRisk: Record<string, number> = {};
    let oauthTotal = 0;
    for (const r of oauthRisk) {
      oauthByRisk[r.riskLevel] = Number(r.c);
      oauthTotal += Number(r.c);
    }

    let netTotal = 0; let netNew = 0;
    const netByType: Record<string, number> = {};
    for (const r of netDeviceStats) {
      netTotal += Number(r.c);
      if (r.status === "new") netNew += Number(r.c);
      netByType[r.deviceType] = (netByType[r.deviceType] ?? 0) + Number(r.c);
    }

    res.json({
      shadowAssets: {
        total: assetTotal,
        critical: assetRisk.critical ?? 0,
        high: assetRisk.high ?? 0,
        pending: assetPending,
      },
      shadowSaas: {
        total: saasTotal,
        unsanctioned: saasUnsanctioned,
        critical: 0,
      },
      idpConnections: idpConns,
      oauthApps: {
        total: oauthTotal,
        critical: oauthByRisk.critical ?? 0,
        high: oauthByRisk.high ?? 0,
        medium: oauthByRisk.medium ?? 0,
        low: oauthByRisk.low ?? 0,
        topRisky: topRiskyApps,
      },
      networkDevices: {
        total: netTotal,
        new: netNew,
        byType: netByType,
      },
    });
  } catch (err) {
    logger.error({ err }, "GET /shadow-it/dashboard failed");
    res.status(500).json({ error: "Failed to fetch Shadow IT dashboard" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SHADOW ASSETS (original)
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/summary", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  try {
    const [assetsByStatus, assetsByRisk, assetsByType, saasApps, totalAssets, totalSaas] = await Promise.all([
      db.select({ status: shadowItAssetsTable.status, count: count() })
        .from(shadowItAssetsTable).where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.status),
      db.select({ riskLevel: shadowItAssetsTable.riskLevel, count: count() })
        .from(shadowItAssetsTable).where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.riskLevel),
      db.select({ type: shadowItAssetsTable.type, count: count() })
        .from(shadowItAssetsTable).where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.type),
      db.select({ status: shadowItSaasAppsTable.status, count: count() })
        .from(shadowItSaasAppsTable).where(eq(shadowItSaasAppsTable.tenantId, tenantId))
        .groupBy(shadowItSaasAppsTable.status),
      db.select({ count: count() }).from(shadowItAssetsTable).where(eq(shadowItAssetsTable.tenantId, tenantId)),
      db.select({ count: count() }).from(shadowItSaasAppsTable).where(eq(shadowItSaasAppsTable.tenantId, tenantId)),
    ]);

    const byStatus: Record<string, number> = {};
    for (const r of assetsByStatus) byStatus[r.status] = Number(r.count);
    const byRisk: Record<string, number> = {};
    for (const r of assetsByRisk) byRisk[r.riskLevel] = Number(r.count);
    const byType: Record<string, number> = {};
    for (const r of assetsByType) byType[r.type] = Number(r.count);
    const saasByStatus: Record<string, number> = {};
    for (const r of saasApps) saasByStatus[r.status] = Number(r.count);

    res.json({
      totalAssets: Number(totalAssets[0]?.count ?? 0),
      totalSaasApps: Number(totalSaas[0]?.count ?? 0),
      pendingReview: byStatus["new"] ?? 0,
      approved: byStatus["approved"] ?? 0,
      remediated: byStatus["remediated"] ?? 0,
      byRisk, byType, saasByStatus,
    });
  } catch (err) {
    logger.error({ err }, "GET /shadow-it/summary failed");
    res.status(500).json({ error: "Failed to fetch Shadow IT summary" });
  }
});

router.get("/shadow-it/assets", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { status, riskLevel, type, classification, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItAssetsTable.tenantId, tenantId)];
    if (status) conds.push(eq(shadowItAssetsTable.status, status));
    if (riskLevel) conds.push(eq(shadowItAssetsTable.riskLevel, riskLevel));
    if (type) conds.push(eq(shadowItAssetsTable.type, type));
    if (classification) conds.push(eq(shadowItAssetsTable.classification, classification));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItAssetsTable).where(and(...conds))
        .orderBy(desc(shadowItAssetsTable.riskScore), desc(shadowItAssetsTable.lastSeenAt))
        .limit(Math.min(parseInt(limit, 10) || 100, 200))
        .offset(parseInt(offset, 10) || 0),
      db.select({ count: count() }).from(shadowItAssetsTable).where(and(...conds)),
    ]);
    res.json({ items: rows, total: Number(totalRow[0]?.count ?? 0) });
  } catch (err) {
    logger.error({ err }, "GET /shadow-it/assets failed");
    res.status(500).json({ error: "Failed to fetch Shadow IT assets" });
  }
});

router.get("/shadow-it/assets/:id", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [row] = await db.select().from(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)));
    if (!row) { res.status(404).json({ error: "Not found" }); return; }
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch Shadow IT asset" });
  }
});

router.patch("/shadow-it/assets/:id/triage", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  const { status, reviewNote, riskLevel } = req.body as { status?: string; reviewNote?: string; riskLevel?: string };
  const validStatus = ["new", "under_review", "approved", "remediated", "false_positive"];
  const validRisk   = ["critical", "high", "medium", "low", "info"];
  if (status && !validStatus.includes(status)) { res.status(400).json({ error: `Invalid status` }); return; }
  if (riskLevel && !validRisk.includes(riskLevel)) { res.status(400).json({ error: `Invalid riskLevel` }); return; }
  try {
    const [existing] = await db.select({ id: shadowItAssetsTable.id }).from(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)));
    if (!existing) { res.status(404).json({ error: "Not found" }); return; }
    const [updated] = await db.update(shadowItAssetsTable)
      .set({
        ...(status ? { status } : {}),
        ...(reviewNote !== undefined ? { reviewNote } : {}),
        ...(riskLevel ? { riskLevel } : {}),
        ...(status && status !== "new" ? { reviewedBy: req.user!.userId, reviewedAt: new Date() } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)))
      .returning();
    await logAudit(req.user! as any, "shadow_it.triage", "shadow_it_asset", id, JSON.stringify({ status, reviewNote, riskLevel }));
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "PATCH /shadow-it/assets/:id/triage failed");
    res.status(500).json({ error: "Failed to triage" });
  }
});

router.delete("/shadow-it/assets/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)))
      .returning({ id: shadowItAssetsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.delete", "shadow_it_asset", id, "{}");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SAAS APPS (correlation-based)
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/saas", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { status, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItSaasAppsTable.tenantId, tenantId)];
    if (status) conds.push(eq(shadowItSaasAppsTable.status, status));
    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItSaasAppsTable).where(and(...conds))
        .orderBy(desc(shadowItSaasAppsTable.createdAt))
        .limit(Math.min(parseInt(limit, 10) || 100, 200))
        .offset(parseInt(offset, 10) || 0),
      db.select({ count: count() }).from(shadowItSaasAppsTable).where(and(...conds)),
    ]);
    res.json({ items: rows, total: Number(totalRow[0]?.count ?? 0) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch Shadow IT SaaS apps" });
  }
});

router.patch("/shadow-it/saas/:id", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  const { status, isSanctioned } = req.body as { status?: string; isSanctioned?: boolean };
  try {
    const [updated] = await db.update(shadowItSaasAppsTable)
      .set({
        ...(status !== undefined ? { status } : {}),
        ...(isSanctioned !== undefined ? { isSanctioned, reviewedBy: req.user!.userId, reviewedAt: new Date() } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItSaasAppsTable.id, id), eq(shadowItSaasAppsTable.tenantId, tenantId)))
      .returning();
    if (!updated) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.saas_update", "shadow_it_saas_app", id, JSON.stringify({ status, isSanctioned }));
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update SaaS app" });
  }
});

router.delete("/shadow-it/saas/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItSaasAppsTable)
      .where(and(eq(shadowItSaasAppsTable.id, id), eq(shadowItSaasAppsTable.tenantId, tenantId)))
      .returning({ id: shadowItSaasAppsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// IDP CONNECTIONS
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/idp-connections", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  try {
    const rows = await db.select().from(shadowItIdpConnectionsTable)
      .where(eq(shadowItIdpConnectionsTable.tenantId, tenantId))
      .orderBy(shadowItIdpConnectionsTable.provider);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch IdP connections" });
  }
});

router.post("/shadow-it/idp-connections", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const {
    provider, displayName,
    configDomain, configEmail,
    configTenantId, configClientId,
  } = req.body as Record<string, string>;

  if (!provider || !displayName) {
    res.status(400).json({ error: "provider and displayName are required" });
    return;
  }
  const validProviders = ["google_workspace", "microsoft_graph", "okta"];
  if (!validProviders.includes(provider)) {
    res.status(400).json({ error: `Invalid provider. Must be one of: ${validProviders.join(", ")}` });
    return;
  }

  try {
    const [existing] = await db.select({ id: shadowItIdpConnectionsTable.id })
      .from(shadowItIdpConnectionsTable)
      .where(and(eq(shadowItIdpConnectionsTable.tenantId, tenantId), eq(shadowItIdpConnectionsTable.provider, provider)));
    if (existing) {
      res.status(409).json({ error: `A ${provider} connection already exists. Update the existing one.` });
      return;
    }

    const [conn] = await db.insert(shadowItIdpConnectionsTable)
      .values({
        tenantId, provider, displayName,
        configDomain: configDomain ?? null,
        configEmail: configEmail ?? null,
        configTenantId: configTenantId ?? null,
        configClientId: configClientId ?? null,
        isActive: true,
      })
      .returning();
    await logAudit(req.user! as any, "shadow_it.idp_create", "shadow_it_idp_connection", conn.id, JSON.stringify({ provider }));
    res.status(201).json(conn);
  } catch (err) {
    logger.error({ err }, "POST /shadow-it/idp-connections failed");
    res.status(500).json({ error: "Failed to create IdP connection" });
  }
});

router.patch("/shadow-it/idp-connections/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  const { displayName, configDomain, configEmail, configTenantId, configClientId, isActive } = req.body as Record<string, any>;
  try {
    const [updated] = await db.update(shadowItIdpConnectionsTable)
      .set({
        ...(displayName !== undefined ? { displayName } : {}),
        ...(configDomain !== undefined ? { configDomain } : {}),
        ...(configEmail !== undefined ? { configEmail } : {}),
        ...(configTenantId !== undefined ? { configTenantId } : {}),
        ...(configClientId !== undefined ? { configClientId } : {}),
        ...(isActive !== undefined ? { isActive } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItIdpConnectionsTable.id, id), eq(shadowItIdpConnectionsTable.tenantId, tenantId)))
      .returning();
    if (!updated) { res.status(404).json({ error: "Not found" }); return; }
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update IdP connection" });
  }
});

router.delete("/shadow-it/idp-connections/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItIdpConnectionsTable)
      .where(and(eq(shadowItIdpConnectionsTable.id, id), eq(shadowItIdpConnectionsTable.tenantId, tenantId)))
      .returning({ id: shadowItIdpConnectionsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.idp_delete", "shadow_it_idp_connection", id, "{}");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete IdP connection" });
  }
});

// POST /shadow-it/idp-connections/:id/sync — trigger manual sync for one connection
router.post("/shadow-it/idp-connections/:id/sync", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }

  res.json({ message: "IdP sync started", connectionId: id });

  setImmediate(async () => {
    try {
      const result = await syncIdpConnection(id, tenantId);
      logger.info({ id, ...result }, "IdP sync complete");
    } catch (err) {
      logger.error({ err, id }, "IdP sync failed");
    }
  });
});

// POST /shadow-it/sync — sync all active IdP connections
router.post("/shadow-it/sync", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  res.json({ message: "Syncing all active IdP connections" });
  setImmediate(() => syncAllIdpConnections(tenantId).catch(err => logger.error({ err }, "syncAllIdpConnections failed")));
});

// ─────────────────────────────────────────────────────────────────────────────
// OAUTH APPS (from IdP sync)
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/oauth-apps", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { provider, riskLevel, isSanctioned, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItOauthAppsTable.tenantId, tenantId)];
    if (provider)    conds.push(eq(shadowItOauthAppsTable.provider, provider));
    if (riskLevel)   conds.push(eq(shadowItOauthAppsTable.riskLevel, riskLevel));
    if (isSanctioned !== undefined) conds.push(eq(shadowItOauthAppsTable.isSanctioned, isSanctioned === "true"));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItOauthAppsTable).where(and(...conds))
        .orderBy(desc(shadowItOauthAppsTable.riskScore))
        .limit(Math.min(parseInt(limit, 10) || 100, 200))
        .offset(parseInt(offset, 10) || 0),
      db.select({ count: count() }).from(shadowItOauthAppsTable).where(and(...conds)),
    ]);
    res.json({ items: rows, total: Number(totalRow[0]?.count ?? 0) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch OAuth apps" });
  }
});

router.get("/shadow-it/oauth-apps/:id", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [[app], users] = await Promise.all([
      db.select().from(shadowItOauthAppsTable)
        .where(and(eq(shadowItOauthAppsTable.id, id), eq(shadowItOauthAppsTable.tenantId, tenantId))),
      db.select().from(shadowItOauthUsersTable)
        .where(and(eq(shadowItOauthUsersTable.oauthAppId, id), eq(shadowItOauthUsersTable.tenantId, tenantId)))
        .orderBy(desc(shadowItOauthUsersTable.riskLevel))
        .limit(100),
    ]);
    if (!app) { res.status(404).json({ error: "Not found" }); return; }
    res.json({ ...app, users });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch OAuth app" });
  }
});

router.patch("/shadow-it/oauth-apps/:id", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  const { isSanctioned, status } = req.body as { isSanctioned?: boolean; status?: string };
  try {
    const [updated] = await db.update(shadowItOauthAppsTable)
      .set({
        ...(isSanctioned !== undefined ? { isSanctioned } : {}),
        ...(status !== undefined ? { status } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItOauthAppsTable.id, id), eq(shadowItOauthAppsTable.tenantId, tenantId)))
      .returning();
    if (!updated) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.oauth_app_update", "shadow_it_oauth_app", id, JSON.stringify({ isSanctioned, status }));
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update OAuth app" });
  }
});

router.delete("/shadow-it/oauth-apps/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItOauthAppsTable)
      .where(and(eq(shadowItOauthAppsTable.id, id), eq(shadowItOauthAppsTable.tenantId, tenantId)))
      .returning({ id: shadowItOauthAppsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete OAuth app" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// OAUTH USERS (employee attribution)
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/oauth-users", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { email, oauthAppId, riskLevel, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItOauthUsersTable.tenantId, tenantId)];
    if (email)      conds.push(sql`lower(${shadowItOauthUsersTable.userEmail}) like ${"%" + email.toLowerCase() + "%"}`);
    if (oauthAppId) conds.push(eq(shadowItOauthUsersTable.oauthAppId, parseInt(oauthAppId, 10)));
    if (riskLevel)  conds.push(eq(shadowItOauthUsersTable.riskLevel, riskLevel));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItOauthUsersTable).where(and(...conds))
        .orderBy(desc(shadowItOauthUsersTable.riskLevel), shadowItOauthUsersTable.userEmail)
        .limit(Math.min(parseInt(limit, 10) || 100, 200))
        .offset(parseInt(offset, 10) || 0),
      db.select({ count: count() }).from(shadowItOauthUsersTable).where(and(...conds)),
    ]);
    res.json({ items: rows, total: Number(totalRow[0]?.count ?? 0) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch OAuth users" });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// NETWORK DEVICES
// ─────────────────────────────────────────────────────────────────────────────

router.get("/shadow-it/network-devices", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { deviceType, status, riskLevel, subnet, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItNetworkDevicesTable.tenantId, tenantId)];
    if (deviceType) conds.push(eq(shadowItNetworkDevicesTable.deviceType, deviceType));
    if (status)     conds.push(eq(shadowItNetworkDevicesTable.status, status));
    if (riskLevel)  conds.push(eq(shadowItNetworkDevicesTable.riskLevel, riskLevel));
    if (subnet)     conds.push(eq(shadowItNetworkDevicesTable.subnet, subnet));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItNetworkDevicesTable).where(and(...conds))
        .orderBy(desc(shadowItNetworkDevicesTable.lastSeenAt))
        .limit(Math.min(parseInt(limit, 10) || 100, 200))
        .offset(parseInt(offset, 10) || 0),
      db.select({ count: count() }).from(shadowItNetworkDevicesTable).where(and(...conds)),
    ]);
    res.json({ items: rows, total: Number(totalRow[0]?.count ?? 0) });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch network devices" });
  }
});

router.get("/shadow-it/network-devices/:id", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [row] = await db.select().from(shadowItNetworkDevicesTable)
      .where(and(eq(shadowItNetworkDevicesTable.id, id), eq(shadowItNetworkDevicesTable.tenantId, tenantId)));
    if (!row) { res.status(404).json({ error: "Not found" }); return; }
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch network device" });
  }
});

router.patch("/shadow-it/network-devices/:id", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  const { status, isManaged, riskLevel } = req.body as { status?: string; isManaged?: boolean; riskLevel?: string };
  try {
    const [updated] = await db.update(shadowItNetworkDevicesTable)
      .set({
        ...(status !== undefined ? { status } : {}),
        ...(isManaged !== undefined ? { isManaged } : {}),
        ...(riskLevel !== undefined ? { riskLevel } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItNetworkDevicesTable.id, id), eq(shadowItNetworkDevicesTable.tenantId, tenantId)))
      .returning();
    if (!updated) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.network_device_update", "shadow_it_network_device", id, JSON.stringify({ status, isManaged }));
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: "Failed to update network device" });
  }
});

router.delete("/shadow-it/network-devices/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = pid(req, "id");
  if (id < 0) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItNetworkDevicesTable)
      .where(and(eq(shadowItNetworkDevicesTable.id, id), eq(shadowItNetworkDevicesTable.tenantId, tenantId)))
      .returning({ id: shadowItNetworkDevicesTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete network device" });
  }
});

// GET /shadow-it/network-devices/detect-subnet — auto-detect local subnets
router.get("/shadow-it/network-scan/subnets", async (_req: AuthenticatedRequest, res): Promise<void> => {
  try {
    const subnets = detectLocalSubnets();
    res.json({ subnets });
  } catch (err) {
    res.status(500).json({ error: "Failed to detect subnets" });
  }
});

// POST /shadow-it/network-scan — run internal network scan
router.post("/shadow-it/network-scan", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { subnet } = req.body as { subnet?: string };

  res.json({ message: "Network scan started", subnet: subnet ?? "auto-detect" });

  setImmediate(async () => {
    try {
      const result = await runInternalNetworkScan(subnet);
      logger.info({ subnet: result.subnet, devices: result.devices.length, methods: result.discoveryMethods }, "Network scan complete");

      // Persist devices
      for (const device of result.devices) {
        await db.insert(shadowItNetworkDevicesTable)
          .values({
            tenantId,
            ipAddress: device.ipAddress,
            macAddress: device.macAddress ?? null,
            macVendor: device.macVendor ?? null,
            hostname: device.hostname ?? null,
            netbiosName: device.netbiosName ?? null,
            mdnsName: device.mdnsName ?? null,
            mdnsServices: device.mdnsServices,
            deviceType: device.deviceType,
            vendor: device.macVendor ?? null,
            osGuess: device.osGuess ?? null,
            snmpSysDescr: device.snmpSysDescr ?? null,
            snmpSysName: device.snmpSysName ?? null,
            snmpSysLocation: device.snmpSysLocation ?? null,
            openPorts: device.openPorts,
            discoveryMethods: device.discoveryMethods,
            subnet: result.subnet,
            riskLevel: "info",
            lastSeenAt: new Date(),
          })
          .onConflictDoUpdate({
            target: [shadowItNetworkDevicesTable.tenantId, shadowItNetworkDevicesTable.ipAddress],
            set: {
              macAddress: device.macAddress ?? null,
              macVendor: device.macVendor ?? null,
              hostname: device.hostname ?? null,
              netbiosName: device.netbiosName ?? null,
              mdnsName: device.mdnsName ?? null,
              mdnsServices: device.mdnsServices,
              deviceType: device.deviceType,
              snmpSysDescr: device.snmpSysDescr ?? null,
              snmpSysName: device.snmpSysName ?? null,
              snmpSysLocation: device.snmpSysLocation ?? null,
              discoveryMethods: device.discoveryMethods,
              lastSeenAt: new Date(),
              updatedAt: new Date(),
            },
          });
      }
      logger.info({ tenantId, persisted: result.devices.length }, "Network devices persisted");
    } catch (err) {
      logger.error({ err, tenantId }, "Network scan failed");
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// DISCOVERY SCAN (original)
// ─────────────────────────────────────────────────────────────────────────────

router.post("/shadow-it/scan", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { assetId } = req.body as { assetId?: number };
  res.json({ message: "Shadow IT discovery scan started", tenantId, assetId: assetId ?? null });
  setImmediate(async () => {
    try {
      const result = await runShadowItDiscovery(tenantId, assetId);
      logger.info({ tenantId, assetId, ...result }, "Manual Shadow IT scan complete");
    } catch (err) {
      logger.error({ err, tenantId }, "Manual Shadow IT scan failed");
    }
  });
});

export default router;
