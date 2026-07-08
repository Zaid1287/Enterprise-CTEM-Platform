import { Router } from "express";
import { eq, and, desc, inArray, isNull } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import {
  db,
  brandThreatScansTable, brandThreatResultsTable,
  brandWatchlistItemsTable, dataLeakResultsTable,
  phishingDetectionsTable, brandAbuseResultsTable,
  adMonitoringResultsTable,
  platformSettingsTable,
  assetsTable,
  brandThreatSchedulesTable,
} from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { runBrandThreatScan } from "../lib/brandThreatRunner";
import { dispatchNotifications } from "../lib/notifier";
import { logger } from "../lib/logger";

const STUCK_SCAN_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes

const router = Router();
router.use(denyExternalMembers);

/**
 * Build a WHERE clause that restricts brand threat scan access by role.
 * - super_admin / admin: unrestricted (operator view, same as assets list)
 * - account_manager: restricted to client tenant IDs
 * - client: own tenant + scan domain must match one of their assigned asset domains
 * - others: own tenant only
 *
 * Returns null when the caller has no access (caller must respond 404).
 */
async function btScanAccessFilter(
  scanId: number,
  user: { tenantId: number; role: string; userId: number },
) {
  const byId = eq(brandThreatScansTable.id, scanId);
  if (user.role === "super_admin" || user.role === "admin") return byId;
  if (user.role === "account_manager") {
    const amTids = await getAmClientTenantIds(user.userId);
    if (amTids.length === 0) return null;
    return and(byId, inArray(brandThreatScansTable.tenantId, amTids));
  }
  if (user.role === "client") {
    // Fetch the scan (tenant-scoped) to check its domain against the client's assigned assets
    const [scan] = await db.select({ domain: brandThreatScansTable.domain })
      .from(brandThreatScansTable)
      .where(and(byId, eq(brandThreatScansTable.tenantId, user.tenantId)));
    if (!scan) return null;
    const scanDomain = scan.domain.toLowerCase().replace(/^www\./, "");
    const assignedAssets = await db.select({ value: assetsTable.value })
      .from(assetsTable)
      .where(and(eq(assetsTable.assignedClientId, user.userId), eq(assetsTable.tenantId, user.tenantId)));
    const assignedDomains = new Set(
      assignedAssets.map(a =>
        String(a.value ?? "").toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!
      ).filter(Boolean)
    );
    if (!assignedDomains.has(scanDomain)) return null;
    return byId; // access verified — no further tenant filter needed (already checked above)
  }
  return and(byId, eq(brandThreatScansTable.tenantId, user.tenantId));
}

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
  const user = req.user!;
  let domainSource: string | undefined;
  let scanTenantId = user.tenantId;

  // If assetId is provided, derive domain from the asset and validate role access
  const assetId = req.body?.assetId ? parseInt(String(req.body.assetId), 10) : null;
  if (assetId && !isNaN(assetId)) {
    // Fetch asset and validate role-based access
    const [asset] = await db.select().from(assetsTable).where(eq(assetsTable.id, assetId));
    if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

    // Role-based access check
    const role = user.role;
    if (role === "client") {
      if (asset.assignedClientId !== user.userId) {
        res.status(403).json({ error: "Access denied to this asset" }); return;
      }
    } else if (role === "account_manager") {
      const amTids = await getAmClientTenantIds(user.userId);
      if (!amTids.includes(asset.tenantId)) {
        res.status(403).json({ error: "Access denied to this asset" }); return;
      }
    } else if (role !== "admin" && role !== "super_admin") {
      if (asset.tenantId !== user.tenantId) {
        res.status(403).json({ error: "Access denied to this asset" }); return;
      }
    }

    // Enforce: only verified assets may be scanned for brand threats
    if (asset.verificationStatus !== "verified") {
      res.status(422).json({ error: "Asset ownership must be verified before running a brand threat scan. Please verify the asset first." });
      return;
    }

    // Derive domain from asset value (strip protocol, www, path)
    domainSource = asset.value;
    scanTenantId = asset.tenantId;
  } else {
    domainSource = String(req.body?.domain ?? "").trim();
  }

  const raw = (domainSource ?? "").toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
  if (!raw || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(raw)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }

  const tenantId = scanTenantId;
  const [existing] = await db.select({ id: brandThreatScansTable.id })
    .from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.tenantId, tenantId), eq(brandThreatScansTable.domain, raw)));

  let scan: typeof brandThreatScansTable.$inferSelect;

  if (existing) {
    await db.update(brandThreatResultsTable).set({ archivedAt: new Date() }).where(eq(brandThreatResultsTable.scanId, existing.id));
    await db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, existing.id));
    await db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, existing.id));
    await db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, existing.id));
    await db.delete(adMonitoringResultsTable).where(eq(adMonitoringResultsTable.scanId, existing.id));
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
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select().from(brandThreatScansTable).where(filter);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const [results, phishing, dataLeaks, brandAbuse, adMonitoring, metaAdsSetting] = await Promise.all([
    db.select().from(brandThreatResultsTable)
      .where(and(eq(brandThreatResultsTable.scanId, id), isNull(brandThreatResultsTable.archivedAt)))
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
    db.select().from(adMonitoringResultsTable)
      .where(eq(adMonitoringResultsTable.scanId, id))
      .orderBy(desc(adMonitoringResultsTable.createdAt)),
    db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, "meta_ads_access_token"))
      .limit(1),
  ]);
  const metaAdsChecked = !!(metaAdsSetting[0]?.value);
  res.json({
    ...toScanResponse(scan),
    metaAdsChecked,
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    phishingDetections: phishing.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    dataLeaks: dataLeaks.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    brandAbuse: brandAbuse.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    adMonitoringResults: adMonitoring.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
  });
});

// ── DELETE /brand-threats/:id ─────────────────────────────────────────────────
router.delete("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  // Use btScanAccessFilter so admin/SA can delete any scan
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [existing] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
  if (!existing) { res.status(404).json({ error: "Scan not found" }); return; }
  await db.delete(brandThreatScansTable).where(eq(brandThreatScansTable.id, id));
  res.json({ success: true });
});

// ── GET /brand-threats/:id/typosquatting ─────────────────────────────────────
router.get("/brand-threats/:id/typosquatting", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandThreatResultsTable)
    .where(and(eq(brandThreatResultsTable.scanId, id), isNull(brandThreatResultsTable.archivedAt)))
    .orderBy(desc(brandThreatResultsTable.riskScore));
  const registered = results.filter(r => r.registrationStatus === "registered" || r.registrationStatus === "active" || r.registrationStatus === "parked" || r.registrationStatus === "protected");
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
  const filter = await btScanAccessFilter(scanId, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
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
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
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
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
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
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }
  const [scan] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable).where(filter);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandAbuseResultsTable)
    .where(eq(brandAbuseResultsTable.scanId, id))
    .orderBy(desc(brandAbuseResultsTable.createdAt));
  res.json(results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })));
});

function computeWatchlistNextScanAt(
  frequency: string,
  from?: Date,
  scanTime?: string | null,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
): Date | null {
  if (!frequency || frequency === "none") return null;
  const now = from ?? new Date();
  const [h, m] = (scanTime ?? "03:00").split(":").map(Number);
  const next = new Date(now);

  if (frequency === "daily") {
    next.setDate(next.getDate() + 1);
    next.setHours(h ?? 3, m ?? 0, 0, 0);
    return next;
  }
  if (frequency === "weekly") {
    const dow = dayOfWeek ?? 1; // default Monday
    let diff = (dow - now.getDay() + 7) % 7;
    if (diff === 0) diff = 7;
    next.setDate(now.getDate() + diff);
    next.setHours(h ?? 3, m ?? 0, 0, 0);
    return next;
  }
  if (frequency === "monthly") {
    const dom = dayOfMonth ?? 1;
    next.setDate(dom);
    next.setHours(h ?? 3, m ?? 0, 0, 0);
    if (next <= now) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(dom);
      next.setHours(h ?? 3, m ?? 0, 0, 0);
    }
    return next;
  }
  return null;
}

function toWatchlistResponse(i: typeof brandWatchlistItemsTable.$inferSelect) {
  return {
    ...i,
    createdAt:       i.createdAt.toISOString(),
    nextScanAt:      i.nextScanAt ? i.nextScanAt.toISOString() : null,
    lastScanAt:      i.lastScanAt ? i.lastScanAt.toISOString() : null,
    prevScanSummary: (i.prevScanSummary as Record<string, number> | null) ?? null,
  };
}

// ── GET /brand-watchlist ──────────────────────────────────────────────────────
router.get("/brand-watchlist", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const items = await db.select().from(brandWatchlistItemsTable)
    .where(eq(brandWatchlistItemsTable.tenantId, req.user!.tenantId))
    .orderBy(desc(brandWatchlistItemsTable.createdAt));
  res.json(items.map(toWatchlistResponse));
});

// ── POST /brand-watchlist ─────────────────────────────────────────────────────
router.post("/brand-watchlist", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const type = String(req.body?.type ?? "").trim();
  const value = String(req.body?.value ?? "").trim();
  const notes = String(req.body?.notes ?? "").trim() || null;
  const frequency = String(req.body?.frequency ?? "none").trim();
  const scanTime = req.body?.scanTime ? String(req.body.scanTime).trim() : null;
  const dayOfWeek = req.body?.dayOfWeek != null ? parseInt(String(req.body.dayOfWeek), 10) : null;
  const dayOfMonth = req.body?.dayOfMonth != null ? parseInt(String(req.body.dayOfMonth), 10) : null;

  if (!type || !value) {
    res.status(400).json({ error: "type and value are required" }); return;
  }
  const validTypes = ["keyword", "logo_url", "domain", "ip", "email", "social_handle", "mobile_app"];
  if (!validTypes.includes(type)) {
    res.status(400).json({ error: `type must be one of: ${validTypes.join(", ")}` }); return;
  }
  const validFrequencies = ["none", "daily", "weekly", "monthly"];
  if (!validFrequencies.includes(frequency)) {
    res.status(400).json({ error: `frequency must be one of: ${validFrequencies.join(", ")}` }); return;
  }

  // All types support automatic monitoring (not just domain)
  const nextScanAt = frequency !== "none"
    ? computeWatchlistNextScanAt(frequency, undefined, scanTime, dayOfWeek, dayOfMonth)
    : null;

  const [item] = await db.insert(brandWatchlistItemsTable).values({
    tenantId: req.user!.tenantId,
    type,
    value,
    notes,
    frequency,
    scanTime,
    dayOfWeek: !isNaN(dayOfWeek!) ? dayOfWeek : null,
    dayOfMonth: !isNaN(dayOfMonth!) ? dayOfMonth : null,
    nextScanAt,
  }).returning();

  res.status(201).json(toWatchlistResponse(item!));
});

// ── PATCH /brand-watchlist/:id ────────────────────────────────────────────────
router.patch("/brand-watchlist/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select().from(brandWatchlistItemsTable)
    .where(and(eq(brandWatchlistItemsTable.id, id), eq(brandWatchlistItemsTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Watchlist item not found" }); return; }

  const updates: Partial<typeof brandWatchlistItemsTable.$inferInsert> = {};
  if (req.body?.notes !== undefined) updates.notes = String(req.body.notes).trim() || null;
  if (req.body?.scanTime !== undefined) updates.scanTime = req.body.scanTime ? String(req.body.scanTime) : null;
  if (req.body?.dayOfWeek !== undefined) updates.dayOfWeek = req.body.dayOfWeek != null ? parseInt(String(req.body.dayOfWeek), 10) : null;
  if (req.body?.dayOfMonth !== undefined) updates.dayOfMonth = req.body.dayOfMonth != null ? parseInt(String(req.body.dayOfMonth), 10) : null;

  if (req.body?.frequency !== undefined) {
    const freq = String(req.body.frequency).trim();
    const validFrequencies = ["none", "daily", "weekly", "monthly"];
    if (!validFrequencies.includes(freq)) {
      res.status(400).json({ error: `frequency must be one of: ${validFrequencies.join(", ")}` }); return;
    }
    updates.frequency = freq;
    const newScanTime = updates.scanTime !== undefined ? updates.scanTime : existing.scanTime;
    const newDow = updates.dayOfWeek !== undefined ? updates.dayOfWeek : existing.dayOfWeek;
    const newDom = updates.dayOfMonth !== undefined ? updates.dayOfMonth : existing.dayOfMonth;
    updates.nextScanAt = computeWatchlistNextScanAt(freq, undefined, newScanTime, newDow, newDom);
  }

  const [updated] = await db.update(brandWatchlistItemsTable)
    .set(updates)
    .where(eq(brandWatchlistItemsTable.id, id))
    .returning();
  res.json(toWatchlistResponse(updated!));
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

// ── POST /brand-threats/:id/rescan ───────────────────────────────────────────
router.post("/brand-threats/:id/rescan", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const filter = await btScanAccessFilter(id, req.user!);
  if (!filter) { res.status(404).json({ error: "Scan not found" }); return; }

  const [existing] = await db.select({
    domain:    brandThreatScansTable.domain,
    tenantId:  brandThreatScansTable.tenantId,
    status:    brandThreatScansTable.status,
    createdAt: brandThreatScansTable.createdAt,
  }).from(brandThreatScansTable).where(filter);
  if (!existing) { res.status(404).json({ error: "Scan not found" }); return; }

  if (existing.status === "running" || existing.status === "pending") {
    const ageMs = Date.now() - new Date(existing.createdAt).getTime();
    if (existing.status === "running" && ageMs > STUCK_SCAN_THRESHOLD_MS) {
      // Stale running scan — reset it so the rescan can proceed
      const ageMinutes = Math.round(ageMs / 60_000);
      logger.warn(
        { scanId: id, domain: existing.domain, ageMinutes },
        "Rescan requested — existing scan stuck for >30 min, resetting to error",
      );
      await db.update(brandThreatScansTable)
        .set({
          status: "error",
          error: `Scan timed out: automatically reset after ${ageMinutes} minutes of inactivity`,
          completedAt: new Date(),
        })
        .where(eq(brandThreatScansTable.id, id));
    } else {
      // Active scan that hasn't exceeded the timeout — block the rescan
      const statusLabel = existing.status === "pending" ? "queued" : "running";
      res.status(409).json({
        error: `A scan is already ${statusLabel} for this domain. Please wait for it to complete before starting a new one.`,
        status: existing.status,
      });
      return;
    }
  }

  const { triggerBrandThreatScan } = await import("../lib/brandThreatRunner");
  const newScan = await triggerBrandThreatScan(existing.tenantId, existing.domain);
  if (!newScan) {
    res.status(409).json({
      error: "A scan is already running for this domain. Please wait for it to complete.",
      status: "running",
    });
    return;
  }
  res.status(201).json(toScanResponse(newScan));
});

// ── GET /brand-threat-schedules ───────────────────────────────────────────────
router.get("/brand-threat-schedules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const schedules = await db
    .select()
    .from(brandThreatSchedulesTable)
    .where(eq(brandThreatSchedulesTable.tenantId, req.user!.tenantId))
    .orderBy(desc(brandThreatSchedulesTable.createdAt));
  res.json(schedules.map(s => ({
    ...s,
    createdAt: s.createdAt.toISOString(),
    nextRunAt: s.nextRunAt ? s.nextRunAt.toISOString() : null,
    lastRunAt: s.lastRunAt ? s.lastRunAt.toISOString() : null,
  })));
});

// ── POST /brand-threat-schedules ──────────────────────────────────────────────
router.post("/brand-threat-schedules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const domain = String(req.body?.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!;
  const frequency = String(req.body?.frequency ?? "weekly").trim();
  const runTime = String(req.body?.runTime ?? "09:00").trim();
  const dayOfWeek = req.body?.dayOfWeek != null ? parseInt(String(req.body.dayOfWeek), 10) : null;
  const dayOfMonth = req.body?.dayOfMonth != null ? parseInt(String(req.body.dayOfMonth), 10) : null;
  const label = req.body?.label ? String(req.body.label).trim() : null;

  if (!domain) { res.status(400).json({ error: "domain is required" }); return; }
  const validFreqs = ["daily", "weekly", "monthly"];
  if (!validFreqs.includes(frequency)) {
    res.status(400).json({ error: `frequency must be one of: ${validFreqs.join(", ")}` }); return;
  }

  const { computeNextRunAt } = await import("../workers/beatScheduler");
  const nextRunAt = computeNextRunAt(frequency, runTime, dayOfWeek, dayOfMonth);

  const [schedule] = await db.insert(brandThreatSchedulesTable).values({
    tenantId: req.user!.tenantId,
    domain,
    frequency,
    runTime,
    dayOfWeek: !isNaN(dayOfWeek!) ? dayOfWeek : null,
    dayOfMonth: !isNaN(dayOfMonth!) ? dayOfMonth : null,
    label,
    status: "active",
    nextRunAt,
  }).returning();

  res.status(201).json({
    ...schedule!,
    createdAt: schedule!.createdAt.toISOString(),
    nextRunAt: schedule!.nextRunAt ? schedule!.nextRunAt.toISOString() : null,
    lastRunAt: null,
  });
});

// ── PATCH /brand-threat-schedules/:id ─────────────────────────────────────────
router.patch("/brand-threat-schedules/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select().from(brandThreatSchedulesTable)
    .where(and(eq(brandThreatSchedulesTable.id, id), eq(brandThreatSchedulesTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Schedule not found" }); return; }

  const updates: Partial<typeof brandThreatSchedulesTable.$inferInsert> = {};
  if (req.body?.status !== undefined) updates.status = req.body.status === "paused" ? "paused" : "active";
  if (req.body?.label !== undefined) updates.label = req.body.label ? String(req.body.label) : null;
  if (req.body?.runTime !== undefined) updates.runTime = String(req.body.runTime);
  if (req.body?.dayOfWeek !== undefined) updates.dayOfWeek = req.body.dayOfWeek != null ? parseInt(String(req.body.dayOfWeek), 10) : null;
  if (req.body?.dayOfMonth !== undefined) updates.dayOfMonth = req.body.dayOfMonth != null ? parseInt(String(req.body.dayOfMonth), 10) : null;
  if (req.body?.frequency !== undefined) {
    const freq = String(req.body.frequency).trim();
    const validFreqs = ["daily", "weekly", "monthly"];
    if (!validFreqs.includes(freq)) {
      res.status(400).json({ error: `frequency must be one of: ${validFreqs.join(", ")}` }); return;
    }
    updates.frequency = freq;
    const { computeNextRunAt } = await import("../workers/beatScheduler");
    const rt = updates.runTime ?? existing.runTime ?? "09:00";
    const dow = updates.dayOfWeek !== undefined ? updates.dayOfWeek : existing.dayOfWeek;
    const dom = updates.dayOfMonth !== undefined ? updates.dayOfMonth : existing.dayOfMonth;
    updates.nextRunAt = computeNextRunAt(freq, rt, dow, dom);
  }

  const [updated] = await db.update(brandThreatSchedulesTable)
    .set(updates)
    .where(eq(brandThreatSchedulesTable.id, id))
    .returning();
  res.json({
    ...updated!,
    createdAt: updated!.createdAt.toISOString(),
    nextRunAt: updated!.nextRunAt ? updated!.nextRunAt.toISOString() : null,
    lastRunAt: updated!.lastRunAt ? updated!.lastRunAt.toISOString() : null,
  });
});

// ── DELETE /brand-threat-schedules/:id ────────────────────────────────────────
router.delete("/brand-threat-schedules/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select({ id: brandThreatSchedulesTable.id }).from(brandThreatSchedulesTable)
    .where(and(eq(brandThreatSchedulesTable.id, id), eq(brandThreatSchedulesTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Schedule not found" }); return; }
  await db.delete(brandThreatSchedulesTable).where(eq(brandThreatSchedulesTable.id, id));
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
