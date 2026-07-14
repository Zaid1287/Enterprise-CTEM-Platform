import { Router } from "express";
import { eq, desc, and, ilike, inArray, or, sql } from "drizzle-orm";
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

async function getThreatIntelEnabled(tenantId: number, role: string): Promise<boolean> {
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
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

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
      db.select({ count: sql<number>`count(*)` }).from(tiAssetCorrelationsTable).where(eq(tiAssetCorrelationsTable.tenantId, tenantId)).then(r => Number(r[0]?.count ?? 0)),
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
      .where(and(eq(tiAssetCorrelationsTable.tenantId, tenantId), eq(tiAssetCorrelationsTable.exploitationStatus, "active")))
      .then(r => Number(r[0]?.count ?? 0));

    res.json({
      totals: { iocs: iocCount, actors: actorCount, campaigns: campaignCount, malware: malwareCount, c2: c2Count, c2Active, kevCves: kevCount, correlations: correlationCount, criticalCorrelations },
      countries: countries.map(c => c.country).filter(Boolean),
      topActors,
      recentC2,
      topCountries,
      monthlyC2: monthlyC2.map((r: any) => ({ month: r.month, count: Number(r.count) })),
      severityDistribution: severityDist.map(r => ({ severity: r.severity, count: Number(r.count) })),
      feedStatus,
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

  const { type, severity, tlp, source, q, limit = "50", offset = "0", active } = req.query as Record<string, string>;
  const conditions = [];
  if (type) conditions.push(eq(tiIocsTable.type, type));
  if (severity) conditions.push(eq(tiIocsTable.severity, severity));
  if (tlp) conditions.push(eq(tiIocsTable.tlp, tlp));
  if (source) conditions.push(eq(tiIocsTable.source, source));
  if (active === "true") conditions.push(eq(tiIocsTable.isActive, true));
  if (q) conditions.push(or(ilike(tiIocsTable.value, `%${q}%`), ilike(tiIocsTable.description, `%${q}%`))!);

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
  const { type, value, source, tlp, confidence, severity, tags, description } = req.body;
  if (!type || !value || !source) { res.status(400).json({ error: "type, value, source required" }); return; }
  const [row] = await db.insert(tiIocsTable).values({ type, value, source, tlp: tlp ?? "white", confidence: confidence ?? 50, severity: severity ?? "medium", tags: tags ?? [], description }).returning();
  await logAudit(req.user!, "ti_ioc_created", "ti_ioc", row.id, JSON.stringify({ type, value }), req.ip ?? "");
  res.status(201).json(row);
});

router.patch("/threat-intel/iocs/:id", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { type, value, source, tlp, confidence, severity, tags, description, isActive } = req.body;
  const [row] = await db.update(tiIocsTable).set({ type, value, source, tlp, confidence, severity, tags, description, isActive, lastSeen: new Date() }).where(eq(tiIocsTable.id, Number(req.params.id))).returning();
  if (!row) { res.status(404).json({ error: "IOC not found" }); return; }
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
  res.json({ ...actor, ttps, campaigns, malware });
});

router.post("/threat-intel/actors", requireAuth, async (req: AuthenticatedRequest, res) => {
  if (!requireAdminOrSA(req, res)) return;
  const { name, aliases, country, motivation, description, targetIndustries, targetCountries, source } = req.body;
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  try {
    const [row] = await db.insert(tiThreatActorsTable).values({
      name, aliases: aliases ?? [], country, motivation, description,
      targetIndustries: targetIndustries ?? [], targetCountries: targetCountries ?? [],
      source: source ?? "manual",
    }).returning();
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
  const { name, aliases, malwareType, description, platforms, targetIndustries, capabilities, mitreId } = req.body;
  if (!name) { res.status(400).json({ error: "name required" }); return; }
  const [row] = await db.insert(tiMalwareTable).values({ name, aliases: aliases ?? [], malwareType: malwareType ?? "malware", description, platforms: platforms ?? [], targetIndustries: targetIndustries ?? [], capabilities: capabilities ?? [], mitreId, source: "manual" }).returning();
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

  const { country, malwareFamily, active, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (country) conditions.push(eq(tiC2ServersTable.country, country));
  if (malwareFamily) conditions.push(eq(tiC2ServersTable.malwareFamily, malwareFamily));
  if (active === "true") conditions.push(eq(tiC2ServersTable.isActive, true));

  const [rows, total] = await Promise.all([
    db.select().from(tiC2ServersTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiC2ServersTable.discoveredAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiC2ServersTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ c2Servers: rows, total });
});

// ── CVE Intelligence ──────────────────────────────────────────────────────────

router.get("/threat-intel/cves", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { q, severity, kev, exploited, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (q) conditions.push(or(ilike(tiCveIntelTable.cveId, `%${q}%`), ilike(tiCveIntelTable.description, `%${q}%`))!);
  if (severity) conditions.push(eq(tiCveIntelTable.severity, severity));
  if (kev === "true") conditions.push(eq(tiCveIntelTable.isKev, true));
  if (exploited === "true") conditions.push(eq(tiCveIntelTable.exploitationStatus, "active"));

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

// ── Correlations ──────────────────────────────────────────────────────────────

router.get("/threat-intel/correlations", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role, userId } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
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
  const enabled = await getThreatIntelEnabled(tenantId, role);
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

  const status = KNOWN_SOURCES.map(src => ({
    source: src,
    displayName: src.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
    lastRun: latest[src] ?? null,
    status: latest[src]?.status ?? "never",
    recordsAdded: latest[src]?.recordsAdded ?? 0,
    completedAt: latest[src]?.completedAt ?? null,
    error: latest[src]?.error ?? null,
  }));

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

  const { severity, q, limit = "50", offset = "0" } = req.query as Record<string, string>;
  const conditions = [];
  if (severity) conditions.push(eq(tiNewsFeedsTable.severity, severity));
  if (q) conditions.push(or(ilike(tiNewsFeedsTable.title, `%${q}%`), ilike(tiNewsFeedsTable.summary, `%${q}%`))!);

  const [rows, total] = await Promise.all([
    db.select().from(tiNewsFeedsTable).where(conditions.length ? and(...conditions) : undefined).orderBy(desc(tiNewsFeedsTable.createdAt)).limit(Math.min(Number(limit), 200)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiNewsFeedsTable).where(conditions.length ? and(...conditions) : undefined).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ news: rows, total });
});

// ── Dark web mentions ─────────────────────────────────────────────────────────

router.get("/threat-intel/dark-web", requireAuth, async (req: AuthenticatedRequest, res) => {
  const { tenantId, role } = req.user!;
  const enabled = await getThreatIntelEnabled(tenantId, role);
  if (!enabled) { res.status(403).json({ error: "Threat Intelligence module not enabled" }); return; }

  const { limit = "50", offset = "0" } = req.query as Record<string, string>;
  const [rows, total] = await Promise.all([
    db.select().from(tiDarkWebMentionsTable).where(eq(tiDarkWebMentionsTable.tenantId, tenantId)).orderBy(desc(tiDarkWebMentionsTable.detectedAt)).limit(Math.min(Number(limit), 100)).offset(Number(offset)),
    db.select({ count: sql<number>`count(*)` }).from(tiDarkWebMentionsTable).where(eq(tiDarkWebMentionsTable.tenantId, tenantId)).then(r => Number(r[0]?.count ?? 0)),
  ]);
  res.json({ mentions: rows, total });
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
