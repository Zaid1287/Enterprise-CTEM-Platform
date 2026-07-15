import { Router } from "express";
import { eq, and, desc, inArray, isNull, isNotNull } from "drizzle-orm";
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
  scanAssetResultsTable,
} from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { triggerBrandThreatScan, detectSubdomainThreats, type SubdomainThreat } from "../lib/brandThreatRunner";
import { dispatchNotifications } from "../lib/notifier";
import { logger } from "../lib/logger";

const STUCK_SCAN_THRESHOLD_MS = 120 * 60 * 1000; // 2 hours — brand threat scans for large domains can take 40–90 min

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

/**
 * Extract root/apex domain from any hostname.
 * docs.example.com → example.com
 * example.co.uk    → example.co.uk  (two-part TLD)
 * example.com      → example.com
 */
function extractRootDomain(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const twoPartTlds = ["co.uk","co.in","co.jp","co.nz","co.za","com.au","com.br","com.cn","com.mx","org.uk","net.uk","me.uk","ac.uk","gov.uk"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPartTlds.includes(lastTwo)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
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
  if (role === "super_admin") {
    // SA sees ALL brand threats across every tenant — no tenant restriction
    btWhere = undefined;
  } else if (role === "account_manager") {
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
      if (asset.tenantId === null || !amTids.includes(asset.tenantId)) {
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
    scanTenantId = asset.tenantId ?? user.tenantId;
  } else {
    domainSource = String(req.body?.domain ?? "").trim();
  }

  const hostname = (domainSource ?? "").toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
  if (!hostname || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(hostname)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }
  // Always normalize to root domain — brand threat scanning is a brand-level concern.
  // Scanning docs.example.com or status.example.com should use example.com so all
  // subdomain assets contribute to the same brand threat entry rather than creating
  // hundreds of per-subdomain scan records.
  const raw = extractRootDomain(hostname);

  const tenantId = scanTenantId;

  // Upsert: find existing scan for this tenant+domain, archive old results, reuse same row.
  // Creates a new row only on first-ever scan for this domain.
  const scan = await triggerBrandThreatScan(tenantId, raw);
  if (!scan) {
    // Already actively running — return current state
    const [active] = await db.select().from(brandThreatScansTable)
      .where(and(
        eq(brandThreatScansTable.tenantId, tenantId),
        eq(brandThreatScansTable.domain, raw),
        inArray(brandThreatScansTable.status, ["pending", "running"]),
      ))
      .orderBy(desc(brandThreatScansTable.id))
      .limit(1);
    res.status(202).json({ ...(active ? toScanResponse(active) : {}), _alreadyRunning: true });
    return;
  }
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
  const [results, phishing, dataLeaks, brandAbuse, adMonitoring, metaAdsSetting, archivedResults] = await Promise.all([
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
    db.select({
      id: brandThreatResultsTable.id,
      permutation: brandThreatResultsTable.permutation,
      riskScore: brandThreatResultsTable.riskScore,
      registrationStatus: brandThreatResultsTable.registrationStatus,
      isPhishing: brandThreatResultsTable.isPhishing,
      fuzzer: brandThreatResultsTable.fuzzer,
      archivedAt: brandThreatResultsTable.archivedAt,
    }).from(brandThreatResultsTable)
      .where(and(eq(brandThreatResultsTable.scanId, id), isNotNull(brandThreatResultsTable.archivedAt)))
      .orderBy(desc(brandThreatResultsTable.archivedAt)),
  ]);

  // Group archived results into scan rounds by archivedAt minute-level bucket
  const scanRounds: Record<string, { archivedAt: string; total: number; registered: number; phishing: number; highRisk: number }> = {};
  for (const r of archivedResults) {
    if (!r.archivedAt) continue;
    const bucket = new Date(r.archivedAt).toISOString().slice(0, 16); // minute precision
    if (!scanRounds[bucket]) {
      scanRounds[bucket] = { archivedAt: r.archivedAt.toISOString(), total: 0, registered: 0, phishing: 0, highRisk: 0 };
    }
    scanRounds[bucket]!.total++;
    if (r.registrationStatus === "registered" || r.registrationStatus === "active") scanRounds[bucket]!.registered++;
    if (r.isPhishing) scanRounds[bucket]!.phishing++;
    if ((r.riskScore ?? 0) >= 60) scanRounds[bucket]!.highRisk++;
  }
  const scanHistory = Object.values(scanRounds).sort((a, b) => new Date(b.archivedAt).getTime() - new Date(a.archivedAt).getTime());

  // Fetch discovered subdomains from the linked pipeline scan (if any)
  // scan_asset_results.subdomains is a jsonb array of objects: { name, ip, cname, status, sources, ... }
  // or legacy plain strings — handle both.
  let pipelineSubdomains: Array<{ name: string; ip?: string; cname?: string; status?: string; sources?: string[] }> = [];
  if (scan.pipelineScanId) {
    const sarRows = await db.select({ subdomains: scanAssetResultsTable.subdomains })
      .from(scanAssetResultsTable)
      .where(eq(scanAssetResultsTable.scanId, scan.pipelineScanId));
    const seen = new Set<string>();
    for (const row of sarRows) {
      if (!Array.isArray(row.subdomains)) continue;
      for (const sub of row.subdomains as unknown[]) {
        if (typeof sub === "string" && sub.trim()) {
          const name = sub.toLowerCase().trim();
          if (!seen.has(name)) { seen.add(name); pipelineSubdomains.push({ name }); }
        } else if (typeof sub === "object" && sub !== null) {
          const s = sub as Record<string, unknown>;
          if (typeof s.name !== "string" || !s.name.trim()) continue;
          const name = s.name.toLowerCase().trim();
          if (seen.has(name)) continue;
          seen.add(name);
          pipelineSubdomains.push({
            name,
            ip:      typeof s.ip === "string" ? s.ip : undefined,
            cname:   typeof s.cname === "string" ? s.cname : undefined,
            status:  typeof s.status === "string" ? s.status : undefined,
            sources: Array.isArray(s.sources) ? (s.sources as string[]).filter(x => typeof x === "string") : undefined,
          });
        }
      }
    }
    pipelineSubdomains.sort((a, b) => a.name.localeCompare(b.name));
  }

  // Lazily compute + cache subdomain threat intelligence
  let subdomainThreats: SubdomainThreat[] = [];
  if (pipelineSubdomains.length > 0) {
    if (Array.isArray(scan.subdomainThreats) && (scan.subdomainThreats as unknown[]).length > 0) {
      subdomainThreats = scan.subdomainThreats as unknown as SubdomainThreat[];
    } else {
      subdomainThreats = await detectSubdomainThreats(pipelineSubdomains, scan.domain);
      await db.update(brandThreatScansTable)
        .set({ subdomainThreats: subdomainThreats as unknown as Record<string, unknown>[] })
        .where(eq(brandThreatScansTable.id, scan.id));
    }
  }

  const metaAdsChecked = !!(metaAdsSetting[0]?.value);
  res.json({
    ...toScanResponse(scan),
    metaAdsChecked,
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    phishingDetections: phishing.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    dataLeaks: dataLeaks.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    brandAbuse: brandAbuse.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    adMonitoringResults: adMonitoring.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
    scanHistory,
    pipelineSubdomains,
    subdomainThreats,
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
    .where(and(
      eq(brandThreatResultsTable.id, permId),
      eq(brandThreatResultsTable.scanId, scanId),
      isNull(brandThreatResultsTable.archivedAt),
    ));
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

  const reScan = await triggerBrandThreatScan(existing.tenantId, existing.domain);
  if (!reScan) {
    res.status(409).json({
      error: "A scan is already running for this domain. Please wait for it to complete.",
      status: "running",
    });
    return;
  }
  res.status(201).json(toScanResponse(reScan));
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
    name: label ?? domain,
    domain,
    frequency,
    runTime,
    dayOfWeek: !isNaN(dayOfWeek!) ? dayOfWeek : null,
    dayOfMonth: !isNaN(dayOfMonth!) ? dayOfMonth : null,
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
  if (req.body?.label !== undefined && req.body.label) updates.name = String(req.body.label);
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

// ── GET /brand-threats/:id/false-positives ────────────────────────────────────
router.get("/brand-threats/:id/false-positives", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scanId = parseInt(String(req.params.id), 10);
  if (isNaN(scanId)) { res.status(400).json({ error: "Invalid scan ID" }); return; }
  const filter = await btScanAccessFilter(scanId, req.user!);
  if (!filter) { res.status(404).json({ error: "Not found" }); return; }
  const { sql } = await import("drizzle-orm");
  const result = await db.execute(
    sql`SELECT id, scan_id, item_type, item_id, item_ref, comment, status, created_at, created_by, reviewed_at, reviewed_by, review_note FROM brand_threat_false_positives WHERE scan_id = ${scanId} AND tenant_id = ${req.user!.tenantId} ORDER BY created_at DESC`
  );
  res.json((result.rows ?? result) as unknown[]);
});

// ── POST /brand-threats/:id/false-positives ───────────────────────────────────
router.post("/brand-threats/:id/false-positives", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scanId = parseInt(String(req.params.id), 10);
  if (isNaN(scanId)) { res.status(400).json({ error: "Invalid scan ID" }); return; }
  const filter = await btScanAccessFilter(scanId, req.user!);
  if (!filter) { res.status(404).json({ error: "Not found" }); return; }
  const { itemType, itemId, itemRef, comment } = req.body as { itemType: string; itemId?: number; itemRef: string; comment?: string };
  if (!itemType || !itemRef) { res.status(400).json({ error: "itemType and itemRef are required" }); return; }
  const { sql } = await import("drizzle-orm");
  const result = await db.execute<{ id: number; status: string; created_at: string }>(
    sql`INSERT INTO brand_threat_false_positives (tenant_id, scan_id, item_type, item_id, item_ref, comment, status, created_by)
        VALUES (${req.user!.tenantId}, ${scanId}, ${itemType}, ${itemId ?? null}, ${itemRef}, ${comment ?? null}, 'pending', ${req.user!.userId})
        RETURNING id, status, created_at`
  );
  const row = ((result.rows ?? result) as any[])[0];
  res.status(201).json(row);
});

// ── PATCH /brand-threats/false-positives/:fpId ────────────────────────────────
router.patch("/brand-threats/false-positives/:fpId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const fpId = parseInt(String(req.params.fpId), 10);
  if (isNaN(fpId)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const { status, reviewNote } = req.body as { status?: string; reviewNote?: string };
  if (!status && !reviewNote) { res.status(400).json({ error: "Nothing to update" }); return; }
  const validStatuses = ["pending", "confirmed", "rejected"];
  if (status && !validStatuses.includes(status)) { res.status(400).json({ error: "Invalid status" }); return; }
  const { sql } = await import("drizzle-orm");
  const result = await db.execute<{ id: number; status: string }>(
    sql`UPDATE brand_threat_false_positives
        SET status = COALESCE(${status ?? null}, status),
            review_note = COALESCE(${reviewNote ?? null}, review_note),
            reviewed_by = CASE WHEN ${status ?? null} IS NOT NULL THEN ${req.user!.userId} ELSE reviewed_by END,
            reviewed_at = CASE WHEN ${status ?? null} IS NOT NULL THEN NOW() ELSE reviewed_at END
        WHERE id = ${fpId} AND tenant_id = ${req.user!.tenantId}
        RETURNING id, status`
  );
  const rows = (result.rows ?? result) as any[];
  if (!rows.length) { res.status(404).json({ error: "Not found" }); return; }
  res.json(rows[0]);
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
