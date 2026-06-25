import { Router } from "express";
import { eq, and, desc, inArray } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import {
  db,
  brandThreatScansTable, brandThreatResultsTable,
  brandWatchlistItemsTable, dataLeakResultsTable,
  phishingDetectionsTable, brandAbuseResultsTable,
  assetsTable,
} from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { runBrandThreatScan } from "../lib/brandThreatRunner";
import { dispatchNotifications } from "../lib/notifier";
import { logger } from "../lib/logger";

const router = Router();

function toScanResponse(s: typeof brandThreatScansTable.$inferSelect) {
  return {
    ...s,
    createdAt: s.createdAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
  };
}

// ── GET /brand-threats ────────────────────────────────────────────────────────
router.get("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  let btWhere;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    btWhere = inArray(brandThreatScansTable.tenantId, ids);
  } else if (role === "client") {
    const assignedAssets = await db.select({ value: assetsTable.value })
      .from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedDomains = new Set<string>();
    for (const a of assignedAssets) {
      if (a.value) {
        const v = a.value.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
        if (v) assignedDomains.add(v);
      }
    }
    if (assignedDomains.size === 0) { res.json([]); return; }
    const allScans = await db.select().from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.tenantId, req.user!.tenantId))
      .orderBy(desc(brandThreatScansTable.createdAt));
    res.json(allScans
      .filter(s => assignedDomains.has(s.domain.toLowerCase().replace(/^www\./, "")))
      .map(toScanResponse));
    return;
  } else {
    btWhere = eq(brandThreatScansTable.tenantId, req.user!.tenantId);
  }
  const scans = await db.select().from(brandThreatScansTable)
    .where(btWhere)
    .orderBy(desc(brandThreatScansTable.createdAt));
  res.json(scans.map(toScanResponse));
});

// ── POST /brand-threats ───────────────────────────────────────────────────────
router.post("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const raw = String(req.body?.domain ?? "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
  if (!raw || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(raw)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }

  const tenantId = req.user!.tenantId;
  const [existing] = await db.select({ id: brandThreatScansTable.id })
    .from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.tenantId, tenantId), eq(brandThreatScansTable.domain, raw)));

  let scan: typeof brandThreatScansTable.$inferSelect;

  if (existing) {
    await db.delete(brandThreatResultsTable).where(eq(brandThreatResultsTable.scanId, existing.id));
    await db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, existing.id));
    await db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, existing.id));
    await db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, existing.id));
    const [updated] = await db.update(brandThreatScansTable)
      .set({
        status: "pending",
        totalPermutations: 0,
        liveCount: 0,
        registeredCount: 0,
        phishingRisk: "low",
        fuzzerBreakdown: null,
        error: null,
        completedAt: null,
        dataLeakCount: 0,
        phishingCount: 0,
        brandAbuseCount: 0,
        darkWebCount: 0,
      })
      .where(eq(brandThreatScansTable.id, existing.id))
      .returning();
    scan = updated!;
  } else {
    const [created] = await db.insert(brandThreatScansTable).values({
      tenantId,
      domain: raw,
      status: "pending",
    }).returning();
    scan = created!;
  }

  const scanId = scan.id;
  setImmediate(async () => {
    try {
      await runBrandThreatScan(scanId, raw);
      const results = await db.select().from(brandThreatResultsTable)
        .where(eq(brandThreatResultsTable.scanId, scanId));
      const highRiskCount = results.filter(r => (r.riskScore ?? 0) >= 60).length;
      const phishCount = results.filter(r => r.isPhishing).length;
      await dispatchNotifications({
        tenantId,
        eventType: "brand_threat",
        title: `Brand Threat Scan Complete — ${raw}`,
        message: `Found ${results.length} lookalike domain${results.length !== 1 ? "s" : ""} for "${raw}". ${highRiskCount} high-risk. ${phishCount > 0 ? `${phishCount} confirmed phishing.` : ""}`,
        severity: phishCount > 0 ? "critical" : highRiskCount > 0 ? "high" : results.length > 0 ? "medium" : "info",
        findingsCount: results.length,
        criticalCount: phishCount,
        highCount: highRiskCount,
        domain: raw,
      });
    } catch (err) {
      logger.warn({ err, scanId }, "Brand threat scan or notification failed");
    }
  });
  res.json(toScanResponse(scan));
});

// ── GET /brand-threats/:id ────────────────────────────────────────────────────
router.get("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select().from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const [results, phishing, dataLeaks, brandAbuse] = await Promise.all([
    db.select().from(brandThreatResultsTable)
      .where(eq(brandThreatResultsTable.scanId, id))
      .orderBy(desc(brandThreatResultsTable.riskScore)),
    db.select().from(phishingDetectionsTable)
      .where(eq(phishingDetectionsTable.scanId, id))
      .orderBy(desc(phishingDetectionsTable.createdAt)),
    db.select().from(dataLeakResultsTable)
      .where(eq(dataLeakResultsTable.scanId, id))
      .orderBy(desc(dataLeakResultsTable.createdAt)),
    db.select().from(brandAbuseResultsTable)
      .where(eq(brandAbuseResultsTable.scanId, id))
      .orderBy(desc(brandAbuseResultsTable.createdAt)),
  ]);
  res.json({
    ...toScanResponse(scan),
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    phishingDetections: phishing.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    dataLeaks: dataLeaks.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    brandAbuse: brandAbuse.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
  });
});

// ── DELETE /brand-threats/:id ─────────────────────────────────────────────────
router.delete("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Scan not found" }); return; }
  await db.delete(brandThreatScansTable).where(eq(brandThreatScansTable.id, id));
  res.json({ success: true });
});

// ── GET /brand-threats/:id/typosquatting ─────────────────────────────────────
router.get("/brand-threats/:id/typosquatting", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandThreatResultsTable)
    .where(eq(brandThreatResultsTable.scanId, id))
    .orderBy(desc(brandThreatResultsTable.riskScore));
  const registered = results.filter(r => r.registrationStatus === "registered" || r.registrationStatus === "active" || r.registrationStatus === "protected");
  const unregistered = results.filter(r => !r.registrationStatus || r.registrationStatus === "unresolved" || r.registrationStatus === "unregistered");
  res.json({
    total: results.length,
    registered: registered.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    unregistered: unregistered.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
  });
});

// ── GET /brand-threats/:scanId/permutations/:permutationId ────────────────────
router.get("/brand-threats/:scanId/permutations/:permutationId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scanId = parseInt(String(req.params.scanId), 10);
  const permId = parseInt(String(req.params.permutationId), 10);
  if (isNaN(scanId) || isNaN(permId)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, scanId), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const [result] = await db.select().from(brandThreatResultsTable)
    .where(and(eq(brandThreatResultsTable.id, permId), eq(brandThreatResultsTable.scanId, scanId)));
  if (!result) { res.status(404).json({ error: "Permutation not found" }); return; }
  res.json({ ...result, createdAt: result.createdAt.toISOString() });
});

// ── GET /brand-threats/:id/phishing ──────────────────────────────────────────
router.get("/brand-threats/:id/phishing", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(phishingDetectionsTable)
    .where(eq(phishingDetectionsTable.scanId, id))
    .orderBy(desc(phishingDetectionsTable.createdAt));
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

// ── GET /brand-threats/:id/data-leaks ────────────────────────────────────────
router.get("/brand-threats/:id/data-leaks", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(dataLeakResultsTable)
    .where(eq(dataLeakResultsTable.scanId, id))
    .orderBy(desc(dataLeakResultsTable.createdAt));
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

// ── GET /brand-threats/:id/brand-abuse ───────────────────────────────────────
router.get("/brand-threats/:id/brand-abuse", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandAbuseResultsTable)
    .where(eq(brandAbuseResultsTable.scanId, id))
    .orderBy(desc(brandAbuseResultsTable.createdAt));
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

// ── GET /brand-watchlist ──────────────────────────────────────────────────────
router.get("/brand-watchlist", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const items = await db.select().from(brandWatchlistItemsTable)
    .where(eq(brandWatchlistItemsTable.tenantId, req.user!.tenantId))
    .orderBy(desc(brandWatchlistItemsTable.createdAt));
  res.json(items.map(i => ({ ...i, createdAt: i.createdAt.toISOString() })));
});

// ── POST /brand-watchlist ─────────────────────────────────────────────────────
router.post("/brand-watchlist", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const type = String(req.body?.type ?? "").trim();
  const value = String(req.body?.value ?? "").trim();
  const notes = String(req.body?.notes ?? "").trim() || null;

  if (!type || !value) {
    res.status(400).json({ error: "type and value are required" }); return;
  }
  const validTypes = ["domain", "brand_name", "trademark", "email_pattern", "logo_hash", "executive_name", "social_handle"];
  if (!validTypes.includes(type)) {
    res.status(400).json({ error: `type must be one of: ${validTypes.join(", ")}` }); return;
  }

  const [item] = await db.insert(brandWatchlistItemsTable).values({
    tenantId: req.user!.tenantId,
    type,
    value,
    notes,
  }).returning();

  res.status(201).json({ ...item, createdAt: item!.createdAt.toISOString() });
});

// ── DELETE /brand-watchlist/:id ───────────────────────────────────────────────
router.delete("/brand-watchlist/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select({ id: brandWatchlistItemsTable.id }).from(brandWatchlistItemsTable)
    .where(and(eq(brandWatchlistItemsTable.id, id), eq(brandWatchlistItemsTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Watchlist item not found" }); return; }
  await db.delete(brandWatchlistItemsTable).where(eq(brandWatchlistItemsTable.id, id));
  res.json({ success: true });
});

// ── GET /data-leaks (tenant-wide) ─────────────────────────────────────────────
router.get("/data-leaks", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const results = await db.select().from(dataLeakResultsTable)
    .where(eq(dataLeakResultsTable.tenantId, req.user!.tenantId))
    .orderBy(desc(dataLeakResultsTable.createdAt))
    .limit(200);
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

// ── GET /phishing-detections (tenant-wide) ────────────────────────────────────
router.get("/phishing-detections", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const results = await db.select().from(phishingDetectionsTable)
    .where(eq(phishingDetectionsTable.tenantId, req.user!.tenantId))
    .orderBy(desc(phishingDetectionsTable.createdAt))
    .limit(200);
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

export default router;
