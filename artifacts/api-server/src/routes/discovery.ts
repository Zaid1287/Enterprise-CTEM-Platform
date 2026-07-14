import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, assetsTable, discoveryResultsTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getPrivilegedTenantIds, buildRecordFilter } from "../lib/tenantScoping";
import { getPlatformSetting } from "./platformSettings";
import { logger } from "../lib/logger";
import { runPassiveDiscovery, type PassiveDiscoveryOptions } from "../lib/passiveDiscovery";
import { triggerBrandThreatScan } from "../lib/brandThreatRunner";

const router = Router();
router.use(denyExternalMembers);

// POST /api/discovery/run/:assetId
// Run all passive discovery modules for an asset and persist results
router.post("/discovery/run/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const discoveryRole = req.user!.role;
  const callerTenantId = req.user!.tenantId;
  const assetId = parseInt(req.params.assetId as string, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }

  let assetWhere;
  if (discoveryRole === "super_admin" || discoveryRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    assetWhere = buildRecordFilter(eq(assetsTable.id, assetId), assetsTable.tenantId, privIds);
  } else if (discoveryRole === "client") {
    assetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.assignedClientId, req.user!.userId));
  } else {
    assetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, callerTenantId));
  }
  const [asset] = await db.select().from(assetsTable).where(assetWhere);
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  // Load all platform API keys in parallel
  const [
    githubToken, shodanApiKey,
    fofaEmail, fofaApiKey,
    censysApiId, censysApiSecret,
    intelxApiKey, criminalIpApiKey,
  ] = await Promise.all([
    getPlatformSetting("github_token"),
    getPlatformSetting("shodan_api_key"),
    getPlatformSetting("fofa_email"),
    getPlatformSetting("fofa_api_key"),
    getPlatformSetting("censys_api_id"),
    getPlatformSetting("censys_api_secret"),
    getPlatformSetting("intelx_api_key"),
    getPlatformSetting("criminalip_api_key"),
  ]);

  const opts: PassiveDiscoveryOptions = {
    githubToken, shodanApiKey, fofaEmail, fofaApiKey,
    censysApiId, censysApiSecret, intelxApiKey, criminalIpApiKey,
    modules: (req.body?.modules as string[] | undefined) ?? undefined,
  };

  const results = await runPassiveDiscovery(asset.value, opts);

  // Persist each module result to discovery_results table
  const savedIds: number[] = [];
  for (const result of results) {
    const [row] = await db.insert(discoveryResultsTable).values({
      tenantId: asset.tenantId!,
      assetId,
      scanId: req.body?.scanId ?? null,
      source: result.source,
      status: result.status,
      data: result.data as any,
      summary: result.summary,
    }).returning({ id: discoveryResultsTable.id });
    if (row) savedIds.push(row.id);
  }

  res.json({ assetId, asset: { id: asset.id, name: asset.name, value: asset.value }, results, savedIds });

  // Auto-trigger brand threat scan for Domain/Subdomain assets
  if (asset.type === "domain" || asset.type === "subdomain") {
    const rawDomain = String(asset.value ?? "")
      .toLowerCase()
      .replace(/^https?:\/\//, "")
      .replace(/^www\./, "")
      .split("/")[0]!.split("?")[0]!;
    if (rawDomain && /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(rawDomain)) {
      setImmediate(() => {
        void triggerBrandThreatScan(asset.tenantId!, rawDomain).catch((err: unknown) => {
          logger.warn({ err, domain: rawDomain }, "Auto brand-threat trigger from discovery failed");
        });
      });
    }
  }
});

// GET /api/discovery/results/:assetId
// Return historical discovery results for an asset
router.get("/discovery/results/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const resultsRole = req.user!.role;
  const assetId = parseInt(req.params.assetId as string, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }

  let resultsAssetWhere;
  if (resultsRole === "super_admin" || resultsRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    resultsAssetWhere = buildRecordFilter(eq(assetsTable.id, assetId), assetsTable.tenantId, privIds);
  } else if (resultsRole === "client") {
    resultsAssetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.assignedClientId, req.user!.userId));
  } else {
    resultsAssetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId));
  }
  const [asset] = await db.select().from(assetsTable).where(resultsAssetWhere);
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const source = req.query.source as string | undefined;
  const limit = Math.min(parseInt(req.query.limit as string ?? "100", 10), 500);

  let query = db.select().from(discoveryResultsTable)
    .where(and(
      eq(discoveryResultsTable.tenantId, asset.tenantId!),
      eq(discoveryResultsTable.assetId, assetId),
      ...(source ? [eq(discoveryResultsTable.source, source)] : []),
    ))
    .orderBy(desc(discoveryResultsTable.createdAt))
    .limit(limit);

  const rows = await query;

  // Group by source for a cleaner response
  const bySource: Record<string, typeof rows> = {};
  for (const row of rows) {
    if (!bySource[row.source]) bySource[row.source] = [];
    bySource[row.source].push(row);
  }

  res.json({
    assetId,
    asset: { id: asset.id, name: asset.name, value: asset.value },
    totalResults: rows.length,
    bySource,
    results: rows,
  });
});

// GET /api/discovery/latest/:assetId
// Return the most recent result per source for an asset
router.get("/discovery/latest/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const latestRole = req.user!.role;
  const assetId = parseInt(req.params.assetId as string, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }

  let latestAssetWhere;
  if (latestRole === "super_admin" || latestRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    latestAssetWhere = buildRecordFilter(eq(assetsTable.id, assetId), assetsTable.tenantId, privIds);
  } else if (latestRole === "client") {
    latestAssetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.assignedClientId, req.user!.userId));
  } else {
    latestAssetWhere = and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId));
  }
  const [asset] = await db.select().from(assetsTable).where(latestAssetWhere);
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const rows = await db.select().from(discoveryResultsTable)
    .where(and(eq(discoveryResultsTable.tenantId, asset.tenantId!), eq(discoveryResultsTable.assetId, assetId)))
    .orderBy(desc(discoveryResultsTable.createdAt))
    .limit(200);

  // Keep only the most recent per source
  const latest: Record<string, typeof rows[number]> = {};
  for (const row of rows) {
    if (!latest[row.source]) latest[row.source] = row;
  }

  const sources = Object.entries(latest).map(([source, row]) => ({
    source, status: row.status, summary: row.summary,
    createdAt: row.createdAt, id: row.id,
    hasData: !!row.data,
  }));

  res.json({ assetId, asset: { id: asset.id, name: asset.name, value: asset.value }, sources });
});

export default router;
