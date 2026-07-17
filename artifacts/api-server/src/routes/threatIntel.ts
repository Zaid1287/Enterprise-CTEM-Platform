import { Router } from "express";
import { eq, desc, and, ilike, inArray, or, sql, gte, lte } from "drizzle-orm";
import {
  db,
  tenantsTable,
  threatIntelModuleAssignmentsTable,
  tiIocsTable,
  tiThreatActorsTable,
  tiCampaignsTable,
  tiMalwareTable,
  tiC2ServersTable,
  tiFeedRunsTable,
  tiAssetCorrelationsTable,
  tiActorTtpsTable,
  tiCveIntelTable,
  tiReportsTable,
  tiNewsFeedsTable,
  tiDarkWebMentionsTable,
  findingsTable,
  assetsTable,
} from "@workspace/db";
import type { AuthenticatedRequest } from "../lib/auth";
import { requireAuth } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { logger } from "../lib/logger";

const router = Router();

// ── Helpers ───────────────────────────────────────────────────────────────────

function requireAdminOrSA(req: AuthenticatedRequest, res: any): boolean {
  const { role } = req.user!;
  if (role !== "admin" && role !== "super_admin") {
    res.status(403).json({ error: "Admin or Super Admin access required" });
    return false;
  }
  return true;
}

async function getThreatIntelEnabled(tenantId: number, role: string, opts?: { allowClient?: boolean }): Promise<boolean> {
  // Client role is restricted to correlations only — deny all other TI endpoints
  if (role === "client" && !opts?.allowClient) return false;
  if (role === "admin" || role === "super_admin" || role === "account_manager") return true;
  const [row] = await db
    .select({ isEnabled: threatIntelModuleAssignmentsTable.isEnabled })
    .from(threatIntelModuleAssignmentsTable)
    .where(eq(threatIntelModuleAssignmentsTable.tenantId, tenantId))
    .limit(1);
  return row?.isEnabled ?? false;
}

// ── Module gate ───────────────────────────────────────────────────────────────

router.get("/threat-intel/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  if (role === "admin" || role === "super_admin" || role === "account_manager") {
    const [tenant] = await db.select({ plan: tenantsTable.plan }).from(tenantsTable).where(eq(tenantsTable.id, tenantId));
    res.json({ isEnabled: true, updatedAt: null, plan: tenant?.plan ?? null });
    return;
  }
  const [[row], [tenant]] = await Promise.all([
    db.select().from(threatIntelModuleAssignmentsTable).where(eq(threatIntelModuleAssignmentsTable.tenantId, tenantId)),
    db.select({ plan: tenantsTable.plan }).from(tenantsTable).where(eq(tenantsTable.id, tenantId)),
  ]);
  res.json({ isEnabled: row?.isEnabled ?? false, updatedAt: row?.updatedAt ?? null, plan: tenant?.plan ?? null });
});

router.get("/threat-intel/module/all", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const rows = await db.select({ tenantId: threatIntelModuleAssignmentsTable.tenantId, isEnabled: threatIntelModuleAssignmentsTable.isEnabled }).from(threatIntelModuleAssignmentsTable);
  const map: Record<number, boolean> = {};
  for (const r of rows) map[r.tenantId] = r.isEnabled ?? false;
  res.json(map);
});

router.patch("/threat-intel/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { role, tenantId: callerTenantId } = req.user!;
  const targetTenantId = req.body.tenantId ? Number(req.body.tenantId) : callerTenantId;
  const isEnabled = !!req.body.isEnabled;
  await db.insert(threatIntelModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: threatIntelModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  await logAudit(req.user!, isEnabled ? "threat_intel_enabled" : "threat_intel_disabled", "tenant", targetTenantId, JSON.stringify({ targetTenantId, isEnabled }), req.ip ?? "");
  res.json({ isEnabled });
});

router.patch("/threat-intel/client/:tenantId/module", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "super_admin only" }); return; }
  const targetTenantId = parseInt(req.params.tenantId as string);
  if (isNaN(targetTenantId)) { res.status(400).json({ error: "Invalid tenantId" }); return; }
  const isEnabled = !!req.body.isEnabled;
  await db.insert(threatIntelModuleAssignmentsTable)
    .values({ tenantId: targetTenantId, isEnabled, enabledBy: req.user!.userId as any, enabledAt: new Date(), updatedAt: new Date() })
    .onConflictDoUpdate({ target: threatIntelModuleAssignmentsTable.tenantId, set: { isEnabled, enabledBy: req.user!.userId as any, updatedAt: new Date(), enabledAt: new Date() } });
  res.json({ isEnabled });
});

// ── Dashboard summary ─────────────────────────────────────────────────────────

router.get("/threat-intel/dashboard", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId: callerTenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(callerTenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  // super_admin can filter by a specific tenant; otherwise use caller's tenant
  let scopeTenantId = callerTenantId;
  if (role === "super_admin" && req.query.tenantId) {
    const parsed = Number(req.query.tenantId);
    if (!isNaN(parsed)) scopeTenantId = parsed;
  }

  try {
    const [
      iocCount,
      actorCount,
      campaignCount,
      malwareCount,
      c2Count,
      c2Active,
      kevCount,
      correlationCount,
      latestFeedRuns,
      topActors,
      recentC2,
      severityDist,
    ] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(tiIocsTable).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiThreatActorsTable).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiCampaignsTable).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiMalwareTable).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiC2ServersTable).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiC2ServersTable).where(eq(tiC2ServersTable.isActive, true)).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiCveIntelTable).where(eq(tiCveIntelTable.isKev, true)).then(r => Number(r[0]?.count ?? 0)),
      db.select({ count: sql<number>`count(*)` }).from(tiAssetCorrelationsTable).where(eq(tiAssetCorrelationsTable.tenantId, scopeTenantId)).then(r => Number(r[0]?.count ?? 0)),
      db.select().from(tiFeedRunsTable).orderBy(desc(tiFeedRunsTable.startedAt)).limit(20),
      db.select({ id: tiThreatActorsTable.id, name: tiThreatActorsTable.name, country: tiThreatActorsTable.country, motivation: tiThreatActorsTable.motivation, riskScore: tiThreatActorsTable.riskScore, targetIndustries: tiThreatActorsTable.targetIndustries, isActive: tiThreatActorsTable.isActive }).from(tiThreatActorsTable).orderBy(desc(tiThreatActorsTable.riskScore)).limit(10),
      db.select().from(tiC2ServersTable).where(eq(tiC2ServersTable.isActive, true)).orderBy(desc(tiC2ServersTable.discoveredAt)).limit(10),
      db.select({ severity: tiIocsTable.severity, count: sql<number>`count(*)` }).from(tiIocsTable).groupBy(tiIocsTable.severity),
    ]);

    // Distinct countries from C2 servers
    const countries = await db.select({ country: tiC2ServersTable.country }).from(tiC2ServersTable).where(sql`country IS NOT NULL`).groupBy(tiC2ServersTable.country);

    // Top C2 countries
    const topCountries = await db.select({ country: tiC2ServersTable.country, count: sql<number>`count(*)` }).from(tiC2ServersTable).where(sql`country IS NOT NULL`).groupBy(tiC2ServersTable.country).orderBy(desc(sql`count(*)`)).limit(10);

    // Monthly C2 trend (last 12 months)
    const monthlyC2Result = await db.execute(sql`
      SELECT TO_CHAR(discovered_at, 'YYYY-MM') as month, COUNT(*) as count
      FROM ti_c2_servers
      WHERE discovered_at >= NOW() - INTERVAL '12 months'
      GROUP BY month ORDER BY month
    `);
    const monthlyC2 = (monthlyC2Result as any).rows ?? [];

    // Feed status (latest run per source)
    const feedStatus: Record<string, any> = {};
    for (const run of latestFeedRuns) {
      if (!feedStatus[run.source]) feedStatus[run.source] = run;
    }

    // Tenant correlations with critical exploitation
    const criticalCorrelations = await db.select({ count: sql<number>`count(*)` })
      .from(tiAssetCorrelationsTable)
      .where(and(eq(tiAssetCorrelationsTable.tenantId, scopeTenantId), eq(tiAssetCorrelationsTable.exploitationStatus, "active")))
      .then(r => Number(r[0]?.count ?? 0));

    // ── Tenant-scoped extended data ────────────────────────────────────────────

    // Top threat actors with asset hit counts (actors appearing in tenant correlations)
    const topActorsWithHitsResult = await db.execute(sql`
      SELECT
        elem->>'name' AS name,
        COUNT(DISTINCT c.asset_id)::int AS asset_count,
        COUNT(*)::int AS correlation_count
      FROM ti_asset_correlations c,
      jsonb_array_elements(c.matched_actors) elem
      WHERE c.tenant_id = ${scopeTenantId}
        AND jsonb_array_length(c.matched_actors) > 0
      GROUP BY elem->>'name'
      ORDER BY asset_count DESC, correlation_count DESC
      LIMIT 10
    `);
    const topActorsWithHits: { name: string; asset_count: number; correlation_count: number }[] =
      ((topActorsWithHitsResult as any).rows ?? []).map((r: any) => ({
        name: r.name,
        asset_count: Number(r.asset_count),
        correlation_count: Number(r.correlation_count),
      }));

    // Active IOC matches — IOC values appearing in tenant correlations, with per-asset hit count
    const activeIocMatchesResult = await db.execute(sql`
      SELECT
        elem->>'value'  AS value,
        elem->>'type'   AS type,
        elem->>'severity' AS severity,
        COUNT(DISTINCT c.asset_id)::int AS hit_count,
        COUNT(*)::int   AS match_count
      FROM ti_asset_correlations c,
      jsonb_array_elements(c.matched_iocs) elem
      WHERE c.tenant_id = ${scopeTenantId}
        AND jsonb_array_length(c.matched_iocs) > 0
      GROUP BY elem->>'value', elem->>'type', elem->>'severity'
      ORDER BY hit_count DESC, match_count DESC
      LIMIT 15
    `);
    const activeIocMatches: { value: string; type: string; severity: string; hit_count: number; match_count: number }[] =
      ((activeIocMatchesResult as any).rows ?? []).map((r: any) => ({
        value: r.value,
        type: r.type,
        severity: r.severity,
        hit_count: Number(r.hit_count),
        match_count: Number(r.match_count),
      }));

    // Most targeted CVEs — CVE IDs appearing in tenant correlations
    // matched_cves stores objects like {cveId, cvss, isKev, ...} — extract cveId field
    const mostTargetedCvesResult = await db.execute(sql`
      SELECT
        elem->>'cveId' AS cve_id,
        COUNT(DISTINCT c.asset_id)::int AS hit_count,
        COUNT(*)::int AS match_count
      FROM ti_asset_correlations c,
      jsonb_array_elements(c.matched_cves) elem
      WHERE c.tenant_id = ${scopeTenantId}
        AND jsonb_array_length(c.matched_cves) > 0
        AND elem->>'cveId' IS NOT NULL
        AND elem->>'cveId' != ''
      GROUP BY elem->>'cveId'
      ORDER BY hit_count DESC, match_count DESC
      LIMIT 10
    `);
    const mostTargetedCvesRaw: { cve_id: string; hit_count: number; match_count: number }[] =
      ((mostTargetedCvesResult as any).rows ?? []).map((r: any) => ({
        cve_id: r.cve_id,
        hit_count: Number(r.hit_count),
        match_count: Number(r.match_count),
      }));

    // Enrich most targeted CVEs with CVSS/KEV info from ti_cve_intel
    const cveIds = mostTargetedCvesRaw.map(r => r.cve_id).filter(Boolean);
    const cveIntelRows = cveIds.length
      ? await db.select({ cveId: tiCveIntelTable.cveId, cvss: tiCveIntelTable.cvss, severity: tiCveIntelTable.severity, isKev: tiCveIntelTable.isKev, epss: tiCveIntelTable.epss })
          .from(tiCveIntelTable).where(inArray(tiCveIntelTable.cveId, cveIds))
      : [];
    const cveIntelMap = new Map(cveIntelRows.map(r => [r.cveId, r]));
    const mostTargetedCves = mostTargetedCvesRaw.map(r => ({
      ...r,
      cvss: cveIntelMap.get(r.cve_id)?.cvss ?? null,
      severity: cveIntelMap.get(r.cve_id)?.severity ?? null,
      isKev: cveIntelMap.get(r.cve_id)?.isKev ?? false,
      epss: cveIntelMap.get(r.cve_id)?.epss ?? null,
    }));

    // Recent correlations feed with asset + finding info
    const recentCorrelations = await db.select({
      id: tiAssetCorrelationsTable.id,
      assetId: tiAssetCorrelationsTable.assetId,
      findingId: tiAssetCorrelationsTable.findingId,
      exploitationStatus: tiAssetCorrelationsTable.exploitationStatus,
      threatScore: tiAssetCorrelationsTable.threatScore,
      riskBoost: tiAssetCorrelationsTable.riskBoost,
      correlationBasis: tiAssetCorrelationsTable.correlationBasis,
      matchedActors: tiAssetCorrelationsTable.matchedActors,
      matchedCves: tiAssetCorrelationsTable.matchedCves,
      matchedIocs: tiAssetCorrelationsTable.matchedIocs,
      correlatedAt: tiAssetCorrelationsTable.correlatedAt,
      assetName: assetsTable.name,
      findingTitle: findingsTable.title,
      findingSeverity: findingsTable.severity,
    })
      .from(tiAssetCorrelationsTable)
      .leftJoin(assetsTable, eq(tiAssetCorrelationsTable.assetId, assetsTable.id))
      .leftJoin(findingsTable, eq(tiAssetCorrelationsTable.findingId, findingsTable.id))
      .where(eq(tiAssetCorrelationsTable.tenantId, scopeTenantId))
      .orderBy(desc(tiAssetCorrelationsTable.correlatedAt))
      .limit(15);

    // Tenants list for super_admin filter dropdown
    const tenantsList = role === "super_admin"
      ? await db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable).orderBy(tenantsTable.name)
      : [];

    res.json({
      totals: { iocs: iocCount, actors: actorCount, campaigns: campaignCount, malware: malwareCount, c2: c2Count, c2Active, kevCves: kevCount, correlations: correlationCount, criticalCorrelations },
      countries: countries.map(c => c.country).filter(Boolean),
      topActors,
      recentC2,
      topCountries,
      monthlyC2: monthlyC2.map((r: any) => ({ month: r.month, count: Number(r.count) })),
      severityDistribution: severityDist.map(r => ({ severity: r.severity, count: Number(r.count) })),
      feedStatus,
      // Extended fields
      topActorsWithHits,
      activeIocMatches,
      mostTargetedCves,
      recentCorrelations,
      tenants: tenantsList,
      scopeTenantId,
    });
  } catch (err) {
    logger.error({ err }, "TI dashboard error");
    res.status(500).json({ error: "Failed to load dashboard" });
  }
});

// ── IOCs ──────────────────────────────────────────────────────────────────────

router.get("/threat-intel/iocs", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { type, severity, tlp, source, q, limit = "50", offset = "0", active, dateFrom, dateTo } = req.query as Record<string, string>;
  const conditions = [];
  if (type) conditions.push(eq(tiIocsTable.type, type));
  if (severity) conditions.push(eq(tiIocsTable.severity, severity));
  if (tlp) conditions.push(eq(tiIocsTable.tlp, tlp));
  if (source) conditions.push(eq(tiIocsTable.source, source));
  if (active === "true") conditions.push(eq(tiIocsTable.isActive, true));
  if (q) conditions.push(or(ilike(tiIocsTable.value, `%${q}%`), ilike(tiIocsTable.description, `%${q}%`))!);
  if (dateFrom) conditions.push(gte(tiIocsTable.firstSeen, new Date(dateFrom)));
  if (dateTo)   conditions.push(lte(tiIocsTable.firstSeen, new Date(dateTo + "T23:59:59Z")));

  const [rows, total] = await Promise.all([
    db.select().from(tiIocsTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiIocsTable.threatScore)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiIocsTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ iocs: rows, total });
});

router.get("/threat-intel/iocs/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const [row] = await db.select().from(tiIocsTable).where(eq(tiIocsTable.id, Number(req.params.id)));
  if (!row) { res.status(404).json({ error: "IOC not found" }); return; }
  res.json(row);
});

router.post("/threat-intel/iocs", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const {
    type, value, source, sourceUrl, tlp, confidence, severity, tags, description,
    threatScore, firstSeen, lastSeen, expiresAt, country, asn,
    malwareFamilies, threatActors, campaigns, exploitationStatus, isActive,
  } = req.body;
  if (!type || !value || !source) { res.status(400).json({ error: "type, value, source required" }); return; }
  const [row] = await db.insert(tiIocsTable).values({
    type, value,
    source: source ?? "manual",
    sourceUrl: sourceUrl ?? null,
    tlp: tlp ?? "white",
    confidence: confidence != null ? Number(confidence) : 50,
    severity: severity ?? "medium",
    tags: Array.isArray(tags) ? tags : [],
    description: description ?? null,
    threatScore: threatScore != null ? Number(threatScore) : 0,
    firstSeen: firstSeen ? new Date(firstSeen) : new Date(),
    lastSeen: lastSeen ? new Date(lastSeen) : new Date(),
    expiresAt: expiresAt ? new Date(expiresAt) : null,
    country: country ?? null,
    asn: asn ?? null,
    malwareFamilies: Array.isArray(malwareFamilies) ? malwareFamilies : [],
    threatActors: Array.isArray(threatActors) ? threatActors : [],
    campaigns: Array.isArray(campaigns) ? campaigns : [],
    exploitationStatus: exploitationStatus ?? "unknown",
    isActive: isActive !== undefined ? Boolean(isActive) : true,
  }).returning();
  await logAudit(req.user!, "ti_ioc_created", "ti_ioc", row.id, JSON.stringify({ type, value }), req.ip ?? "");
  res.status(201).json(row);
});

router.patch("/threat-intel/iocs/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const {
    type, value, source, sourceUrl, tlp, confidence, severity, tags, description, isActive,
    threatScore, firstSeen, lastSeen, expiresAt, country, asn,
    malwareFamilies, threatActors, campaigns, exploitationStatus,
  } = req.body;
  const patch: Record<string, unknown> = { lastSeen: new Date() };
  if (type !== undefined)               patch.type = type;
  if (value !== undefined)              patch.value = value;
  if (source !== undefined)             patch.source = source;
  if (sourceUrl !== undefined)          patch.sourceUrl = sourceUrl;
  if (tlp !== undefined)                patch.tlp = tlp;
  if (confidence !== undefined)         patch.confidence = Number(confidence);
  if (severity !== undefined)           patch.severity = severity;
  if (tags !== undefined)               patch.tags = Array.isArray(tags) ? tags : [];
  if (description !== undefined)        patch.description = description;
  if (isActive !== undefined)           patch.isActive = Boolean(isActive);
  if (threatScore !== undefined)        patch.threatScore = Number(threatScore);
  if (firstSeen !== undefined)          patch.firstSeen = firstSeen ? new Date(firstSeen) : new Date();
  if (lastSeen !== undefined)           patch.lastSeen = lastSeen ? new Date(lastSeen) : new Date();
  if (expiresAt !== undefined)          patch.expiresAt = expiresAt ? new Date(expiresAt) : null;
  if (country !== undefined)            patch.country = country;
  if (asn !== undefined)                patch.asn = asn;
  if (malwareFamilies !== undefined)    patch.malwareFamilies = Array.isArray(malwareFamilies) ? malwareFamilies : [];
  if (threatActors !== undefined)       patch.threatActors = Array.isArray(threatActors) ? threatActors : [];
  if (campaigns !== undefined)          patch.campaigns = Array.isArray(campaigns) ? campaigns : [];
  if (exploitationStatus !== undefined) patch.exploitationStatus = exploitationStatus;
  const [row] = await db.update(tiIocsTable).set(patch as any).where(eq(tiIocsTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "IOC not found" }); return; }
  await logAudit(req.user!, "ti_ioc_updated", "ti_ioc", row.id, JSON.stringify({ severity, isActive }), req.ip ?? "");
  res.json(row);
});

router.delete("/threat-intel/iocs/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  await db.delete(tiIocsTable).where(eq(tiIocsTable.id, Number(req.params.id)));
  res.sendStatus(204);
});

// ── Threat Actors ─────────────────────────────────────────────────────────────

router.get("/threat-intel/actors", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, country, motivation, active, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(or(ilike(tiThreatActorsTable.name, `%${q}%`), ilike(tiThreatActorsTable.description, `%${q}%`))!);
  if (country) conditions.push(eq(tiThreatActorsTable.country, country));
  if (motivation) conditions.push(eq(tiThreatActorsTable.motivation, motivation));
  if (active === "true") conditions.push(eq(tiThreatActorsTable.isActive, true));

  const [rows, total] = await Promise.all([
    db.select().from(tiThreatActorsTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiThreatActorsTable.riskScore)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiThreatActorsTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ actors: rows, total });
});

router.get("/threat-intel/actors/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const actorId = Number(req.params.id);
  const [[actor], ttps, campaigns, malware] = await Promise.all([
    db.select().from(tiThreatActorsTable).where(eq(tiThreatActorsTable.id, actorId)),
    db.select().from(tiActorTtpsTable).where(eq(tiActorTtpsTable.actorId, actorId)),
    db.select().from(tiCampaignsTable).where(eq(tiCampaignsTable.actorId, actorId)),
    db.select().from(tiMalwareTable).where(sql`${actorId}::text = ANY(actor_ids)`),
  ]);
  if (!actor) { res.status(404).json({ error: "Actor not found" }); return; }
  // Infrastructure IOCs: IOCs that reference this actor by name in their threat_actors array
  const iocs = actor.name
    ? await db.select().from(tiIocsTable).where(sql`${actor.name} = ANY(${tiIocsTable.threatActors})`).limit(100)
    : [];
  res.json({ ...actor, ttps, campaigns, malware, iocs });
});

router.post("/threat-intel/actors", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const {
    name, aliases, country, motivation, description, overview, executiveSummary,
    targetIndustries, targetCountries, source, firstSeen, lastSeen,
    sophistication, resourceLevel, isActive, riskScore, confidenceScore,
    mitreId, mitreUrl, killChain, detectionRules, mitigation, referenceUrls,
  } = req.body;
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  try {
    const [row] = await db.insert(tiThreatActorsTable).values({
      name,
      aliases: Array.isArray(aliases) ? aliases : [],
      country: country ?? null,
      motivation: motivation ?? null,
      description: description ?? null,
      overview: overview ?? null,
      executiveSummary: executiveSummary ?? null,
      targetIndustries: Array.isArray(targetIndustries) ? targetIndustries : [],
      targetCountries: Array.isArray(targetCountries) ? targetCountries : [],
      source: source ?? "manual",
      firstSeen: firstSeen ?? null,
      lastSeen: lastSeen ?? null,
      sophistication: sophistication ?? null,
      resourceLevel: resourceLevel ?? null,
      isActive: isActive !== undefined ? Boolean(isActive) : true,
      riskScore: riskScore != null ? Number(riskScore) : 0,
      confidenceScore: confidenceScore != null ? Number(confidenceScore) : 0,
      mitreId: mitreId ?? null,
      mitreUrl: mitreUrl ?? null,
      killChain: Array.isArray(killChain) ? killChain : [],
      detectionRules: Array.isArray(detectionRules) ? detectionRules : [],
      mitigation: mitigation ?? null,
      referenceUrls: Array.isArray(referenceUrls) ? referenceUrls : [],
    }).returning();
    await logAudit(req.user!, "ti_actor_created", "ti_actor", row.id, JSON.stringify({ name }), req.ip ?? "");
    res.status(201).json({ actor: row });
  } catch (err: any) {
    if (err?.code === "23505") {
      res.status(409).json({ error: `An actor named "${name}" already exists` });
    } else {
      throw err;
    }
  }
});

router.patch("/threat-intel/actors/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const update = { ...req.body, updatedAt: new Date() };
  delete update.id;
  const [row] = await db.update(tiThreatActorsTable).set(update).where(eq(tiThreatActorsTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "Actor not found" }); return; }
  res.json(row);
});

router.delete("/threat-intel/actors/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  await db.delete(tiThreatActorsTable).where(eq(tiThreatActorsTable.id, Number(req.params.id)));
  res.sendStatus(204);
});

// ── Campaigns ─────────────────────────────────────────────────────────────────

router.get("/threat-intel/campaigns", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, status, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(ilike(tiCampaignsTable.name, `%${q}%`));
  if (status) conditions.push(eq(tiCampaignsTable.status, status));

  const [rows, total] = await Promise.all([
    db.select().from(tiCampaignsTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiCampaignsTable.updatedAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiCampaignsTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ campaigns: rows, total });
});

router.get("/threat-intel/campaigns/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const [row] = await db.select().from(tiCampaignsTable).where(eq(tiCampaignsTable.id, Number(req.params.id)));
  if (!row) { res.status(404).json({ error: "Campaign not found" }); return; }
  res.json(row);
});

router.post("/threat-intel/campaigns", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { name, aliases, description, actorId, actorName, status, targetIndustries, targetCountries, startDate, endDate, mitreId, objectives } = req.body;
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  const [row] = await db.insert(tiCampaignsTable).values({ name, aliases: aliases ?? [], description, actorId: actorId ?? null, actorName, status: status ?? "active", targetIndustries: targetIndustries ?? [], targetCountries: targetCountries ?? [], startDate, endDate, mitreId, objectives, source: "manual" }).returning();
  res.status(201).json(row);
});

router.patch("/threat-intel/campaigns/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const update = { ...req.body, updatedAt: new Date() };
  delete update.id;
  const [row] = await db.update(tiCampaignsTable).set(update).where(eq(tiCampaignsTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "Campaign not found" }); return; }
  res.json(row);
});

router.delete("/threat-intel/campaigns/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  await db.delete(tiCampaignsTable).where(eq(tiCampaignsTable.id, Number(req.params.id)));
  res.sendStatus(204);
});

// ── Malware ───────────────────────────────────────────────────────────────────

router.get("/threat-intel/malware", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, malwareType, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(or(ilike(tiMalwareTable.name, `%${q}%`), ilike(tiMalwareTable.description, `%${q}%`))!);
  if (malwareType) conditions.push(eq(tiMalwareTable.malwareType, malwareType));

  const [rows, total] = await Promise.all([
    db.select().from(tiMalwareTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiMalwareTable.riskScore)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiMalwareTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ malware: rows, total });
});

router.get("/threat-intel/malware/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const [row] = await db.select().from(tiMalwareTable).where(eq(tiMalwareTable.id, Number(req.params.id)));
  if (!row) { res.status(404).json({ error: "Malware not found" }); return; }
  res.json(row);
});

router.post("/threat-intel/malware", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const {
    name, aliases, malwareType, description, platforms, targetIndustries,
    capabilities, mitreId, mitreUrl, actorIds, actorNames, campaignIds,
    riskScore, iocCount, source,
  } = req.body;
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  const [row] = await db.insert(tiMalwareTable).values({
    name,
    aliases:          aliases ?? [],
    malwareType:      malwareType ?? "malware",
    description,
    platforms:        platforms ?? [],
    targetIndustries: targetIndustries ?? [],
    capabilities:     capabilities ?? [],
    actorIds:         actorIds ?? [],
    actorNames:       actorNames ?? [],
    campaignIds:      campaignIds ?? [],
    mitreId,
    mitreUrl,
    riskScore:        riskScore ?? 0,
    iocCount:         iocCount ?? 0,
    source:           source ?? "manual",
  }).returning();
  res.status(201).json(row);
});

router.patch("/threat-intel/malware/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const update = { ...req.body, updatedAt: new Date() };
  delete update.id;
  const [row] = await db.update(tiMalwareTable).set(update).where(eq(tiMalwareTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "Malware not found" }); return; }
  res.json(row);
});

router.delete("/threat-intel/malware/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  await db.delete(tiMalwareTable).where(eq(tiMalwareTable.id, Number(req.params.id)));
  res.sendStatus(204);
});

// ── C2 Servers ────────────────────────────────────────────────────────────────

router.get("/threat-intel/c2-servers", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, country, malwareFamily, active, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(or(ilike(tiC2ServersTable.ip, `%${q}%`), ilike(tiC2ServersTable.domain, `%${q}%`), ilike(tiC2ServersTable.actorName, `%${q}%`))!);
  if (country) conditions.push(eq(tiC2ServersTable.country, country));
  if (malwareFamily) conditions.push(eq(tiC2ServersTable.malwareFamily, malwareFamily));
  if (active === "true") conditions.push(eq(tiC2ServersTable.isActive, true));

  const [rows, total] = await Promise.all([
    db.select().from(tiC2ServersTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiC2ServersTable.discoveredAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiC2ServersTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ c2Servers: rows, total });
});

router.get("/threat-intel/c2-servers/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const [row] = await db.select().from(tiC2ServersTable).where(eq(tiC2ServersTable.id, Number(req.params.id)));
  if (!row) { res.status(404).json({ error: "C2 server not found" }); return; }
  res.json(row);
});

router.post("/threat-intel/c2-servers", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const {
    ip, port, domain, country, countryCode, asn, asnOrg, isp, city, lat, lng,
    malwareFamily, actorName, tags, confidence, isActive,
    cloudProvider, serviceCategory, sectorsAtRisk, platformsAtRisk, orgsAtRisk, source,
  } = req.body;
  if (!ip) { res.status(400).json({ error: "ip is required" }); return; }
  try {
    const [row] = await db.insert(tiC2ServersTable).values({
      ip: ip.trim(),
      port: port ? Number(port) : null,
      domain: domain?.trim() || null,
      country: country?.trim() || null,
      countryCode: countryCode?.trim() || null,
      asn: asn?.trim() || null,
      asnOrg: asnOrg?.trim() || null,
      isp: isp?.trim() || null,
      city: city?.trim() || null,
      lat: lat ? Number(lat) : null,
      lng: lng ? Number(lng) : null,
      malwareFamily: malwareFamily?.trim() || null,
      actorName: actorName?.trim() || null,
      tags: Array.isArray(tags) ? tags : [],
      confidence: confidence !== undefined ? Number(confidence) : 70,
      isActive: isActive !== undefined ? Boolean(isActive) : true,
      cloudProvider: cloudProvider?.trim() || null,
      serviceCategory: serviceCategory?.trim() || null,
      sectorsAtRisk: Array.isArray(sectorsAtRisk) ? sectorsAtRisk : [],
      platformsAtRisk: Array.isArray(platformsAtRisk) ? platformsAtRisk : [],
      orgsAtRisk: Array.isArray(orgsAtRisk) ? orgsAtRisk : [],
      source: source?.trim() || "manual",
    }).returning();
    res.status(201).json(row);
  } catch (err: any) {
    if (err.code === "23505") { res.status(409).json({ error: "A C2 server with this IP and source already exists" }); return; }
    throw err;
  }
});

router.patch("/threat-intel/c2-servers/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const update = { ...req.body, updatedAt: new Date() };
  delete update.id;
  if (update.port !== undefined) update.port = update.port ? Number(update.port) : null;
  if (update.lat !== undefined) update.lat = update.lat ? Number(update.lat) : null;
  if (update.lng !== undefined) update.lng = update.lng ? Number(update.lng) : null;
  if (update.confidence !== undefined) update.confidence = Number(update.confidence);
  const [row] = await db.update(tiC2ServersTable).set(update).where(eq(tiC2ServersTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "C2 server not found" }); return; }
  res.json(row);
});

router.delete("/threat-intel/c2-servers/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  await db.delete(tiC2ServersTable).where(eq(tiC2ServersTable.id, Number(req.params.id)));
  res.sendStatus(204);
});

// ── CVE Intelligence ──────────────────────────────────────────────────────────

router.get("/threat-intel/cves", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, severity, kev, exploited, limit = "50", offset = "0", dateFrom, dateTo } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(or(ilike(tiCveIntelTable.cveId, `%${q}%`), ilike(tiCveIntelTable.description, `%${q}%`))!);
  if (severity) conditions.push(eq(tiCveIntelTable.severity, severity));
  if (kev === "true") conditions.push(eq(tiCveIntelTable.isKev, true));
  if (exploited === "true") conditions.push(eq(tiCveIntelTable.exploitationStatus, "active"));
  if (dateFrom) conditions.push(gte(tiCveIntelTable.updatedAt, new Date(dateFrom)));
  if (dateTo)   conditions.push(lte(tiCveIntelTable.updatedAt, new Date(dateTo + "T23:59:59Z")));

  const [rows, total] = await Promise.all([
    db.select().from(tiCveIntelTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiCveIntelTable.updatedAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiCveIntelTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ cves: rows, total });
});

router.get("/threat-intel/cves/:cveId", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const [row] = await db.select().from(tiCveIntelTable).where(eq(tiCveIntelTable.cveId, req.params.cveId as string));
  if (!row) { res.status(404).json({ error: "CVE not found" }); return; }
  res.json(row);
});

// ── TTPs ──────────────────────────────────────────────────────────────────────

router.get("/threat-intel/ttps", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { limit = "50", tactic } = req.query as Record<string, string>;
  const conditions = tactic ? [eq(tiActorTtpsTable.tacticName, tactic)] : [];

  const rows = await db
    .select({
      mitreId:  tiActorTtpsTable.techniqueId,
      name:     tiActorTtpsTable.techniqueName,
      tactic:   tiActorTtpsTable.tacticName,
      tacticId: tiActorTtpsTable.tacticId,
      count:    sql<number>`cast(count(*) as int)`,
    })
    .from(tiActorTtpsTable)
    .where(conditions.length ? and(...conditions) : undefined)
    .groupBy(tiActorTtpsTable.techniqueId, tiActorTtpsTable.techniqueName, tiActorTtpsTable.tacticName, tiActorTtpsTable.tacticId)
    .orderBy(desc(sql`count(*)`))
    .limit(Math.min(Number(limit), 200));

  res.json({ ttps: rows, total: rows.length });
});

// ── Correlations ──────────────────────────────────────────────────────────────

router.get("/threat-intel/correlations", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role, userId } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role, { allowClient: true });
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { limit = "50", offset = "0" } = req.query as Record<string, string>;

  // Scope: client role sees only correlations for assets in their own tenant (tenant boundary)
  // admin/super_admin/manager/account_manager see all tenant correlations
  let scopeCond = eq(tiAssetCorrelationsTable.tenantId, tenantId);
  if (role === "client") {
    // Client users only see correlations for assets explicitly assigned to them
    // (assignedClientId = their userId — same gate as findings/TPRM routes)
    const userId = req.user!.userId;
    const assetIds = await db
      .select({ id: assetsTable.id })
      .from(assetsTable)
      .where(and(
        eq(assetsTable.tenantId, tenantId),
        eq(assetsTable.assignedClientId, userId),
      ))
      .then(rows => rows.map(r => r.id));
    if (assetIds.length === 0) { res.json({ correlations: [], total: 0 }); return; }
    scopeCond = and(
      eq(tiAssetCorrelationsTable.tenantId, tenantId),
      inArray(tiAssetCorrelationsTable.assetId, assetIds),
    ) as any;
  }

  const [rows, total] = await Promise.all([
    db.select({
      id: tiAssetCorrelationsTable.id,
      tenantId: tiAssetCorrelationsTable.tenantId,
      findingId: tiAssetCorrelationsTable.findingId,
      assetId: tiAssetCorrelationsTable.assetId,
      matchedActors: tiAssetCorrelationsTable.matchedActors,
      matchedCampaigns: tiAssetCorrelationsTable.matchedCampaigns,
      matchedMalware: tiAssetCorrelationsTable.matchedMalware,
      matchedIocs: tiAssetCorrelationsTable.matchedIocs,
      matchedCves: tiAssetCorrelationsTable.matchedCves,
      exploitationStatus: tiAssetCorrelationsTable.exploitationStatus,
      threatScore: tiAssetCorrelationsTable.threatScore,
      riskBoost: tiAssetCorrelationsTable.riskBoost,
      correlationBasis: tiAssetCorrelationsTable.correlationBasis,
      correlatedAt: tiAssetCorrelationsTable.correlatedAt,
      findingTitle: findingsTable.title,
      findingSeverity: findingsTable.severity,
      assetName: assetsTable.name,
    })
      .from(tiAssetCorrelationsTable)
      .leftJoin(findingsTable, eq(tiAssetCorrelationsTable.findingId, findingsTable.id))
      .leftJoin(assetsTable, eq(tiAssetCorrelationsTable.assetId, assetsTable.id))
      .where(scopeCond)
      .orderBy(desc(tiAssetCorrelationsTable.correlatedAt))
      .limit(Math.min(Number(limit), 200))
      .offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiAssetCorrelationsTable).where(scopeCond).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ correlations: rows, total });
});

router.get("/threat-intel/correlations/finding/:findingId", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role, userId } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role, { allowClient: true });
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const findingId = Number(req.params.findingId);

  // For client role: verify the finding belongs to an asset assigned to this user
  if (role === "client") {
    const assignedAssetIds = await db
      .select({ id: assetsTable.id })
      .from(assetsTable)
      .where(and(
        eq(assetsTable.tenantId, tenantId),
        eq(assetsTable.assignedClientId, userId),
      ))
      .then(rows => rows.map(r => r.id));
    if (assignedAssetIds.length === 0) { res.json({ correlations: [] }); return; }
    // Confirm this finding is attached to one of the client's assigned assets
    const finding = await db
      .select({ assetId: findingsTable.assetId })
      .from(findingsTable)
      .where(and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, tenantId)))
      .limit(1);
    if (!finding[0] || !assignedAssetIds.includes(finding[0].assetId!)) {
      res.status(403).json({ error: "Access denied" }); return;
    }
  }

  const rows = await db.select().from(tiAssetCorrelationsTable).where(
    and(eq(tiAssetCorrelationsTable.tenantId, tenantId), eq(tiAssetCorrelationsTable.findingId, findingId))
  ).orderBy(desc(tiAssetCorrelationsTable.correlatedAt));
  res.json({ correlations: rows });
});

router.post("/threat-intel/correlate", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  // Trigger correlation in background — actual logic implemented in Task 3
  setImmediate(async () => {
    try {
      const { runThreatIntelCorrelation } = await import("../lib/threatIntel/correlationEngine.js");
      await runThreatIntelCorrelation(tenantId);
    } catch {
      // Correlation engine not yet implemented — will be added in Task 3
    }
  });
  res.json({ message: "Correlation triggered in background" });
});

// ── Feed status & manual refresh ──────────────────────────────────────────────

router.get("/threat-intel/feeds/status", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  // Latest run per source
  const runs = await db.select().from(tiFeedRunsTable).orderBy(desc(tiFeedRunsTable.startedAt)).limit(100);
  const latest: Record<string, any> = {};
  for (const r of runs) {
    if (!latest[r.source]) latest[r.source] = r;
  }

  // List all known sources with their status
  const KNOWN_SOURCES = [
    "alienvault_otx", "abuseipdb", "greynoise", "threatfox", "malwarebazaar",
    "urlhaus", "phishtank", "cisa_kev", "mitre_attack", "nvd_cve",
  ];

  // Check which API-key-required feeds have keys configured
  const API_KEY_SETTINGS: Record<string, string> = {
    abuseipdb: "ti_abuseipdb_key",
    greynoise: "ti_greynoise_key",
    alienvault_otx: "ti_otx_key",
    nvd_cve: "nvd_api_key",
  };
  const { platformSettingsTable } = await import("@workspace/db");
  const settingKeys = Object.values(API_KEY_SETTINGS);
  const settingRows = await db.select().from(platformSettingsTable).where(inArray(platformSettingsTable.key, settingKeys));
  const configuredKeys = new Set(settingRows.filter(r => r.value && r.value.trim() !== "").map(r => r.key));

  const status = KNOWN_SOURCES.map(src => {
    const settingKey = API_KEY_SETTINGS[src];
    return {
      source: src,
      displayName: src.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
      lastRun: latest[src] ?? null,
      status: latest[src]?.status ?? "never",
      recordsAdded: latest[src]?.recordsAdded ?? 0,
      completedAt: latest[src]?.completedAt ?? null,
      error: latest[src]?.error ?? null,
      apiKeyRequired: !!settingKey,
      apiKeyConfigured: settingKey ? configuredKeys.has(settingKey) : null,
    };
  });

  res.json({ feeds: status });
});

router.post("/threat-intel/feeds/refresh", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { source } = req.body;

  setImmediate(async () => {
    try {
      const { runThreatIntelFeedRefresh } = await import("../lib/threatIntel/feedEngine.js");
      await runThreatIntelFeedRefresh(req.user?.tenantId, source);
    } catch {
      // Feed engine not yet implemented — will be added in Task 2
    }
  });

  res.json({ message: source ? `Feed refresh triggered for ${source}` : "Full feed refresh triggered" });
});

// ── News ──────────────────────────────────────────────────────────────────────

router.get("/threat-intel/news", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { severity, source, q, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (severity) conditions.push(eq(tiNewsFeedsTable.severity, severity));
  if (source)   conditions.push(eq(tiNewsFeedsTable.source, source));
  if (q) conditions.push(or(ilike(tiNewsFeedsTable.title, `%${q}%`), ilike(tiNewsFeedsTable.summary, `%${q}%`))!);

  const [rows, total] = await Promise.all([
    db.select().from(tiNewsFeedsTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiNewsFeedsTable.publishedAt), desc(tiNewsFeedsTable.createdAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiNewsFeedsTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ news: rows, total });
});

router.get("/threat-intel/news/sources", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const { getNewsSourcesStatus } = await import("../lib/threatIntel/newsFetcher.js");
  const sources = await getNewsSourcesStatus();
  res.json({ sources });
});

router.post("/threat-intel/news/refresh", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { source } = req.body as { source?: string };

  // Respond immediately — fetch runs in background
  res.json({ message: source ? `Fetching news from ${source}…` : "Fetching from all news sources…" });

  setImmediate(async () => {
    try {
      const { runNewsFeedRefresh } = await import("../lib/threatIntel/newsFetcher.js");
      await runNewsFeedRefresh(source);
    } catch (err: any) {
      logger.warn({ err: err.message }, "[news] Background fetch failed");
    }
  });
});

// ── Dark web mentions ─────────────────────────────────────────────────────────

router.get("/threat-intel/dark-web", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const isGlobal = role === "admin" || role === "super_admin";
  const { severity, source, assetDomain, q, limit = "50", offset = "0" } = req.query as Record<string, string>;

  const conds: any[] = [];
  // Scope: admin/SA see all tenants, others see only their own
  if (!isGlobal) conds.push(eq(tiDarkWebMentionsTable.tenantId, tenantId));
  if (severity)    conds.push(eq(tiDarkWebMentionsTable.severity, severity));
  if (source)      conds.push(eq(tiDarkWebMentionsTable.source, source));
  if (assetDomain) conds.push(ilike(tiDarkWebMentionsTable.assetDomain, `%${assetDomain}%`));
  if (q)           conds.push(or(ilike(tiDarkWebMentionsTable.title, `%${q}%`), ilike(tiDarkWebMentionsTable.content, `%${q}%`))!);

  const where = conds.length ? and(...conds) : undefined;

  const [rawRows, total, tenants, lastRun] = await Promise.all([
    db.select({ m: tiDarkWebMentionsTable, tenantName: tenantsTable.name })
      .from(tiDarkWebMentionsTable)
      .leftJoin(tenantsTable, eq(tiDarkWebMentionsTable.tenantId, tenantsTable.id))
      .where(where)
      .orderBy(desc(tiDarkWebMentionsTable.detectedAt), desc(tiDarkWebMentionsTable.createdAt))
      .limit(Math.min(Number(limit), 200))
      .offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiDarkWebMentionsTable).where(where).then(r => Number(r[0]?.count ?? 0)),
    isGlobal
      ? db.select({ id: tenantsTable.id, name: tenantsTable.name }).from(tenantsTable)
      : Promise.resolve([]),
    (async () => {
      const { tiFeedRunsTable: frt } = await import("@workspace/db");
      const [row] = await db.select().from(frt)
        .where(eq(frt.source, "dark_web_monitor"))
        .orderBy(desc(frt.startedAt))
        .limit(1);
      return row ?? null;
    })(),
  ]);

  // Normalise field names for the frontend
  const mentions = rawRows.map(({ m, tenantName }) => ({
    id: m.id,
    tenantId: m.tenantId,
    tenantName: tenantName ?? null,
    sourceType: m.source,          // alias for frontend
    source: m.source,
    url: m.sourceUrl,              // alias for frontend
    sourceUrl: m.sourceUrl,
    riskLevel: m.severity,         // alias for frontend
    severity: m.severity,
    snippet: m.content,            // alias for frontend
    content: m.content,
    title: m.title,
    keywords: m.keywords,
    actors: m.actors,
    isVerified: m.isVerified,
    assetDomain: m.assetDomain,
    mentionType: m.mentionType,
    rawData: m.rawData,
    detectedAt: m.detectedAt,
    createdAt: m.createdAt,
  }));

  res.json({ mentions, total, tenants, lastRun });
});

// Monitored assets — returns all assets that can be dark-web-monitored with mention counts
router.get("/threat-intel/dark-web/assets", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const isGlobal = role === "admin" || role === "super_admin";

  // Assets with domains/IPs that dark web monitoring can scan
  const rawAssets = await db.select({
    id: assetsTable.id,
    tenantId: assetsTable.tenantId,
    name: assetsTable.name,
    type: assetsTable.type,
    value: assetsTable.value,
    ipAddress: assetsTable.ipAddress,
    tenantName: tenantsTable.name,
  })
    .from(assetsTable)
    .leftJoin(tenantsTable, eq(assetsTable.tenantId, tenantsTable.id))
    .where(isGlobal ? undefined : eq(assetsTable.tenantId, tenantId))
    .orderBy(assetsTable.tenantId, assetsTable.name)
    .limit(500);

  // Count mentions per asset domain
  const domainCounts: Record<string, number> = {};
  const countRows = await db.select({
    assetDomain: tiDarkWebMentionsTable.assetDomain,
    cnt: sql<number>`count(*)`,
  }).from(tiDarkWebMentionsTable).groupBy(tiDarkWebMentionsTable.assetDomain);
  for (const r of countRows) if (r.assetDomain) domainCounts[r.assetDomain] = Number(r.cnt);

  const DOMAIN_TYPES = ["domain", "subdomain", "url", "host", "ssl_certificate"];
  const IP_TYPES = ["ip"];

  const assets = rawAssets
    .filter(a => {
      const v = (a.value ?? "").trim().toLowerCase();
      return DOMAIN_TYPES.includes(a.type.toLowerCase()) || IP_TYPES.includes(a.type.toLowerCase()) || /^([a-z0-9][\w-]*\.)+[a-z]{2,}$/.test(v);
    })
    .map(a => {
      let domain: string | null = null;
      const v = (a.value ?? "").trim();
      const t = a.type.toLowerCase();
      if (t === "domain" || t === "subdomain") domain = v.replace(/^www\./, "").split(".").slice(-2).join(".");
      else if (t === "url") { try { domain = new URL(v).hostname.replace(/^www\./, "").split(".").slice(-2).join("."); } catch {} }
      else if (t === "ssl_certificate") domain = v.replace(/^\*\./, "").split(".").slice(-2).join(".");
      else if (t === "host" && /^[a-z][\w.-]*\.[a-z]{2,}$/i.test(v)) domain = v.split(".").slice(-2).join(".");
      return {
        id: a.id,
        tenantId: a.tenantId,
        tenantName: a.tenantName,
        name: a.name,
        type: a.type,
        value: a.value,
        domain,
        ipAddress: a.ipAddress,
        mentionCount: domain ? (domainCounts[domain] ?? 0) : (a.ipAddress ? (domainCounts[a.ipAddress] ?? 0) : 0),
      };
    });

  res.json({ assets });
});

// Trigger a dark web monitor scan (admin/SA only)
router.post("/threat-intel/dark-web/scan", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { targetTenantId, assetId } = req.body as { targetTenantId?: number; assetId?: number };

  res.json({ message: "Dark web monitor scan started. Results will appear within 1–2 minutes." });

  setImmediate(async () => {
    try {
      const { runDarkWebMonitor } = await import("../lib/threatIntel/darkWebMonitor.js");
      await runDarkWebMonitor({ tenantId: targetTenantId, assetId });
    } catch (err: any) {
      logger.warn({ err: err.message }, "[dark-web] Background scan failed");
    }
  });
});

// ── Reports ───────────────────────────────────────────────────────────────────

router.get("/threat-intel/reports", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }
  const rows = await db.select().from(tiReportsTable).where(eq(tiReportsTable.tenantId, tenantId)).orderBy(desc(tiReportsTable.createdAt)).limit(50);
  res.json({ reports: rows });
});

router.post("/threat-intel/reports", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { tenantId } = req.user!;
  const { title, reportType } = req.body;
  if (!title) { res.status(400).json({ error: "title required" }); return; }
  const [row] = await db.insert(tiReportsTable).values({ tenantId, title, reportType: reportType ?? "summary", status: "generating", generatedBy: req.user!.userId as any }).returning();
  res.status(201).json(row);
});

// ── Global search ─────────────────────────────────────────────────────────────

router.get("/threat-intel/search", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q } = req.query as { q: string };
  if (!q || q.trim().length < 2) { res.json({ iocs: [], actors: [], malware: [], cves: [], campaigns: [] }); return; }
  const term = `%${q.trim()}%`;

  const [iocs, actors, malware, cves, campaigns] = await Promise.all([
    db.select({ id: tiIocsTable.id, type: tiIocsTable.type, value: tiIocsTable.value, severity: tiIocsTable.severity, source: tiIocsTable.source }).from(tiIocsTable).where(ilike(tiIocsTable.value, term)).limit(10),
    db.select({ id: tiThreatActorsTable.id, name: tiThreatActorsTable.name, country: tiThreatActorsTable.country, motivation: tiThreatActorsTable.motivation }).from(tiThreatActorsTable).where(or(ilike(tiThreatActorsTable.name, term), ilike(tiThreatActorsTable.description, term))!).limit(5),
    db.select({ id: tiMalwareTable.id, name: tiMalwareTable.name, malwareType: tiMalwareTable.malwareType }).from(tiMalwareTable).where(or(ilike(tiMalwareTable.name, term), ilike(tiMalwareTable.description, term))!).limit(5),
    db.select({ id: tiCveIntelTable.id, cveId: tiCveIntelTable.cveId, severity: tiCveIntelTable.severity, isKev: tiCveIntelTable.isKev }).from(tiCveIntelTable).where(ilike(tiCveIntelTable.cveId, term)).limit(5),
    db.select({ id: tiCampaignsTable.id, name: tiCampaignsTable.name, status: tiCampaignsTable.status }).from(tiCampaignsTable).where(ilike(tiCampaignsTable.name, term)).limit(5),
  ]);
  res.json({ iocs, actors, malware, cves, campaigns });
});

export default router;
