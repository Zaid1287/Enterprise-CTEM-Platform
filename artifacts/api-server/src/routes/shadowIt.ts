import { Router } from "express";
import { db, shadowItAssetsTable, shadowItSaasAppsTable } from "@workspace/db";
import { eq, and, desc, count } from "drizzle-orm";
import { requireAuth, requireRole, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { runShadowItDiscovery } from "../lib/shadowItCorrelation";
import { logger } from "../lib/logger";

const router = Router();

router.use(requireAuth);

// ── GET /shadow-it/summary ────────────────────────────────────────────────────
router.get("/shadow-it/summary", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  try {
    const [assetsByStatus, assetsByRisk, assetsByType, saasApps, totalAssets, totalSaas] = await Promise.all([
      db.select({ status: shadowItAssetsTable.status, count: count() })
        .from(shadowItAssetsTable)
        .where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.status),
      db.select({ riskLevel: shadowItAssetsTable.riskLevel, count: count() })
        .from(shadowItAssetsTable)
        .where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.riskLevel),
      db.select({ type: shadowItAssetsTable.type, count: count() })
        .from(shadowItAssetsTable)
        .where(eq(shadowItAssetsTable.tenantId, tenantId))
        .groupBy(shadowItAssetsTable.type),
      db.select({ status: shadowItSaasAppsTable.status, count: count() })
        .from(shadowItSaasAppsTable)
        .where(eq(shadowItSaasAppsTable.tenantId, tenantId))
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
      byRisk,
      byType,
      saasByStatus,
    });
  } catch (err) {
    logger.error({ err }, "GET /shadow-it/summary failed");
    res.status(500).json({ error: "Failed to fetch Shadow IT summary" });
  }
});

// ── GET /shadow-it/assets ─────────────────────────────────────────────────────
router.get("/shadow-it/assets", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { status, riskLevel, type, classification, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItAssetsTable.tenantId, tenantId)];
    if (status)         conds.push(eq(shadowItAssetsTable.status, status));
    if (riskLevel)      conds.push(eq(shadowItAssetsTable.riskLevel, riskLevel));
    if (type)           conds.push(eq(shadowItAssetsTable.type, type));
    if (classification) conds.push(eq(shadowItAssetsTable.classification, classification));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItAssetsTable)
        .where(and(...conds))
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

// ── GET /shadow-it/assets/:id ─────────────────────────────────────────────────
router.get("/shadow-it/assets/:id", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = parseInt(req.params["id"] as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [row] = await db.select().from(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)));
    if (!row) { res.status(404).json({ error: "Not found" }); return; }
    res.json(row);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch Shadow IT asset" });
  }
});

// ── PATCH /shadow-it/assets/:id/triage ───────────────────────────────────────
router.patch("/shadow-it/assets/:id/triage", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = parseInt(req.params["id"] as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

  const { status, reviewNote } = req.body as { status?: string; reviewNote?: string };
  const validStatuses = ["new", "under_review", "approved", "remediated", "false_positive"];
  if (status && !validStatuses.includes(status)) {
    res.status(400).json({ error: `Invalid status. Must be one of: ${validStatuses.join(", ")}` });
    return;
  }

  try {
    const [existing] = await db.select({ id: shadowItAssetsTable.id }).from(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)));
    if (!existing) { res.status(404).json({ error: "Not found" }); return; }

    const [updated] = await db.update(shadowItAssetsTable)
      .set({
        ...(status ? { status } : {}),
        ...(reviewNote !== undefined ? { reviewNote } : {}),
        ...(status && status !== "new" ? { reviewedBy: req.user!.userId, reviewedAt: new Date() } : {}),
        updatedAt: new Date(),
      })
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)))
      .returning();

    await logAudit(req.user! as any, "shadow_it.triage", "shadow_it_asset", id, JSON.stringify({ status, reviewNote }));
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "PATCH /shadow-it/assets/:id/triage failed");
    res.status(500).json({ error: "Failed to triage Shadow IT asset" });
  }
});

// ── DELETE /shadow-it/assets/:id ──────────────────────────────────────────────
router.delete("/shadow-it/assets/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = parseInt(req.params["id"] as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItAssetsTable)
      .where(and(eq(shadowItAssetsTable.id, id), eq(shadowItAssetsTable.tenantId, tenantId)))
      .returning({ id: shadowItAssetsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    await logAudit(req.user! as any, "shadow_it.delete", "shadow_it_asset", id, "{}");
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete Shadow IT asset" });
  }
});

// ── GET /shadow-it/saas ───────────────────────────────────────────────────────
router.get("/shadow-it/saas", async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const { status, limit = "100", offset = "0" } = req.query as Record<string, string>;
  try {
    const conds = [eq(shadowItSaasAppsTable.tenantId, tenantId)];
    if (status) conds.push(eq(shadowItSaasAppsTable.status, status));

    const [rows, totalRow] = await Promise.all([
      db.select().from(shadowItSaasAppsTable)
        .where(and(...conds))
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

// ── PATCH /shadow-it/saas/:id ─────────────────────────────────────────────────
router.patch("/shadow-it/saas/:id", requireRole("manager", "admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = parseInt(req.params["id"] as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
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
    res.status(500).json({ error: "Failed to update Shadow IT SaaS app" });
  }
});

// ── DELETE /shadow-it/saas/:id ────────────────────────────────────────────────
router.delete("/shadow-it/saas/:id", requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const id = parseInt(req.params["id"] as string, 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
  try {
    const [deleted] = await db.delete(shadowItSaasAppsTable)
      .where(and(eq(shadowItSaasAppsTable.id, id), eq(shadowItSaasAppsTable.tenantId, tenantId)))
      .returning({ id: shadowItSaasAppsTable.id });
    if (!deleted) { res.status(404).json({ error: "Not found" }); return; }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete Shadow IT SaaS app" });
  }
});

// ── POST /shadow-it/scan ──────────────────────────────────────────────────────
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
