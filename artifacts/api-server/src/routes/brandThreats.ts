import { Router } from "express";
import { eq, and, desc, inArray } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { db, brandThreatScansTable, brandThreatResultsTable, assetsTable } from "@workspace/db";
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
    // Clients see only brand threat scans whose domain matches their assigned assets
    const assignedAssets = await db.select({ value: assetsTable.value })
      .from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    // Collect all domain-like values from assigned assets (strip protocol/www/path)
    const assignedDomains = new Set<string>();
    for (const a of assignedAssets) {
      if (a.value) {
        const v = a.value.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
        if (v) assignedDomains.add(v);
      }
    }
    if (assignedDomains.size === 0) { res.json([]); return; }
    // Fetch all scans the client's tenant can see, then filter by matching domain
    const allScans = await db.select().from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.tenantId, req.user!.tenantId))
      .orderBy(desc(brandThreatScansTable.createdAt));
    const filtered = allScans.filter(s =>
      assignedDomains.has(s.domain.toLowerCase().replace(/^www\./, ""))
    );
    res.json(filtered.map(toScanResponse));
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
// If a scan for the same domain already exists for this tenant, reset and re-run it
// instead of creating a duplicate entry.
router.post("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const raw = String(req.body?.domain ?? "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
  if (!raw || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(raw)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }

  const tenantId = req.user!.tenantId;

  // Check for existing scan for same domain + tenant
  const [existing] = await db.select({ id: brandThreatScansTable.id })
    .from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.tenantId, tenantId), eq(brandThreatScansTable.domain, raw)));

  let scan: typeof brandThreatScansTable.$inferSelect;

  if (existing) {
    // Re-run: wipe old results and reset the existing scan record
    await db.delete(brandThreatResultsTable).where(eq(brandThreatResultsTable.scanId, existing.id));
    const [updated] = await db.update(brandThreatScansTable)
      .set({
        status: "pending",
        totalPermutations: null,
        liveCount: null,
        registeredCount: null,
        phishingRisk: null,
        fuzzerBreakdown: null,
        error: null,
        completedAt: null,
      })
      .where(eq(brandThreatScansTable.id, existing.id))
      .returning();
    scan = updated;
  } else {
    // First time: create new scan record
    const [created] = await db.insert(brandThreatScansTable).values({
      tenantId,
      domain: raw,
      status: "pending",
    }).returning();
    scan = created;
  }

  const scanId = scan.id;
  setImmediate(async () => {
    try {
      await runBrandThreatScan(scanId, raw);
      const results = await db.select().from(brandThreatResultsTable)
        .where(eq(brandThreatResultsTable.scanId, scanId));
      const highRiskCount = results.filter(r => (r.riskScore ?? 0) >= 7).length;
      await dispatchNotifications({
        tenantId,
        eventType: "brand_threat",
        title: `Brand Threat Scan Complete — ${raw}`,
        message: `Found ${results.length} lookalike domain${results.length !== 1 ? "s" : ""} resembling "${raw}". ${highRiskCount} high-risk.`,
        severity: highRiskCount > 0 ? "high" : results.length > 0 ? "medium" : "info",
        findingsCount: results.length,
        criticalCount: 0,
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
  const results = await db.select().from(brandThreatResultsTable)
    .where(eq(brandThreatResultsTable.scanId, id))
    .orderBy(desc(brandThreatResultsTable.riskScore));
  res.json({
    ...toScanResponse(scan),
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
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

export default router;
