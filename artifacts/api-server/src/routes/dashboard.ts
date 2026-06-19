import { Router } from "express";
import { eq, count, and, desc, sql, inArray, or, isNull, lte, gte } from "drizzle-orm";
import { db, assetsTable, findingsTable, scansTable, alertsTable, riskScoresTable, auditLogsTable, complianceControlsTable, tenantsTable, usersTable, accountManagerClientsTable, takedownRequestsTable, brandThreatScansTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { cacheGet, cacheSet, cacheDelete, ck } from "../lib/cache";

const router = Router();

router.get("/dashboard/overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const cKey = ck("dash:overview", tid);
  const cached = await cacheGet(cKey);
  if (cached) { res.json(cached); return; }

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const [assets, findings, scans, alerts] = await Promise.all([
    db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid)),
    db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid)),
    db.select().from(scansTable).where(eq(scansTable.tenantId, tid)),
    db.select().from(alertsTable).where(eq(alertsTable.tenantId, tid)),
  ]);

  const totalAssets = assets.length;
  const totalFindings = findings.length;
  const criticalFindings = findings.filter(f => f.severity === "critical").length;
  const highFindings = findings.filter(f => f.severity === "high").length;
  const openFindings = findings.filter(f => f.status === "open").length;
  const activeScans = scans.filter(s => s.status === "running" || s.status === "pending").length;
  const unreadAlerts = alerts.filter(a => !a.isRead).length;

  const riskScores = await db.select().from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(eq(assetsTable.tenantId, tid));
  const avgRisk = riskScores.length > 0
    ? riskScores.reduce((sum, r) => sum + r.risk_scores.score, 0) / riskScores.length
    : 0;

  const controls = await db.select().from(complianceControlsTable).where(eq(complianceControlsTable.tenantId, tid));
  const compliantControls = controls.filter(c => c.status === "compliant").length;
  const complianceScore = controls.length > 0 ? Math.round((compliantControls / controls.length) * 100) : 0;

  // Real trend: compare now vs 7 days ago
  const assetsLastWeek = assets.filter(a => new Date(a.createdAt) < sevenDaysAgo).length;
  const findingsLastWeek = findings.filter(f => new Date(f.createdAt) < sevenDaysAgo).length;
  const assetsTrend = assetsLastWeek > 0
    ? Math.round(((totalAssets - assetsLastWeek) / assetsLastWeek) * 100)
    : totalAssets > 0 ? 100 : 0;
  const findingsTrend = findingsLastWeek > 0
    ? Math.round(((totalFindings - findingsLastWeek) / findingsLastWeek) * 100)
    : totalFindings > 0 ? 100 : 0;

  const payload = {
    totalAssets, totalFindings, criticalFindings, highFindings, openFindings,
    activeScans, complianceScore, riskScore: Math.round(avgRisk),
    unreadAlerts, assetsTrend, findingsTrend,
  };
  await cacheSet(cKey, payload, 120);
  res.json(payload);
});

router.get("/dashboard/risk-trend", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const days = parseInt(String(req.query.days ?? "30"), 10);
  const tid = req.user!.tenantId;

  const [findings, assets] = await Promise.all([
    db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid)),
    db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid)),
  ]);

  const assetCount = Math.max(1, assets.length);
  const now = new Date();

  // For each day in the window, compute what the risk score would have been
  // based on which findings were open at end-of-day (created before or on that day,
  // not yet resolved as of that day).
  const trend = Array.from({ length: days }, (_, i) => {
    const dayEnd = new Date(now);
    dayEnd.setDate(dayEnd.getDate() - (days - 1 - i));
    dayEnd.setHours(23, 59, 59, 999);

    const closedStatuses = ["mitigated", "accepted_risk", "false_positive"];
    const openOnDay = findings.filter(f => {
      const created = new Date(f.createdAt);
      if (created > dayEnd) return false;
      if (closedStatuses.includes(f.status)) {
        const updated = new Date(f.updatedAt);
        return updated > dayEnd;
      }
      return true;
    });

    let penalty = 0;
    for (const f of openOnDay) {
      if (f.severity === "critical")    penalty += 20;
      else if (f.severity === "high")   penalty += 12;
      else if (f.severity === "medium") penalty += 6;
      else if (f.severity === "low")    penalty += 2;
    }
    const value = Math.max(0, Math.min(100, 100 - Math.round(penalty / assetCount)));
    return { date: dayEnd.toISOString().split("T")[0], value };
  });

  res.json(trend);
});

router.get("/dashboard/findings-by-severity", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid));
  const severities = ["critical", "high", "medium", "low", "info"];
  const result = severities.map(severity => ({
    severity,
    count: findings.filter(f => f.severity === severity).length,
  }));
  res.json(result);
});

router.get("/dashboard/asset-breakdown", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const assets = await db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid));
  const typeMap: Record<string, number> = {};
  for (const a of assets) {
    typeMap[a.type] = (typeMap[a.type] ?? 0) + 1;
  }
  res.json(Object.entries(typeMap).map(([type, count]) => ({ type, count })));
});

router.get("/dashboard/top-risky-assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const limit = parseInt(String(req.query.limit ?? "10"), 10);
  const scores = await db.select({
    score: riskScoresTable,
    assetName: assetsTable.name,
    assetType: assetsTable.type,
    tenantId: assetsTable.tenantId,
  }).from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(eq(assetsTable.tenantId, req.user!.tenantId));

  const tid = req.user!.tenantId;
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid));
  const findingsByAsset: Record<number, number> = {};
  for (const f of findings) {
    findingsByAsset[f.assetId] = (findingsByAsset[f.assetId] ?? 0) + 1;
  }

  const result = scores
    .sort((a, b) => b.score.score - a.score.score)
    .slice(0, limit)
    .map(({ score, assetName, assetType }) => ({
      assetId: score.assetId, assetName: assetName ?? "Unknown", assetType: assetType ?? "unknown",
      riskScore: score.score, riskLevel: score.level, findingsCount: findingsByAsset[score.assetId] ?? 0,
    }));
  res.json(result);
});

router.get("/dashboard/recent-activity", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const [recentFindings, recentScans, recentAlerts] = await Promise.all([
    db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid)).orderBy(desc(findingsTable.createdAt)).limit(5),
    db.select().from(scansTable).where(eq(scansTable.tenantId, tid)).orderBy(desc(scansTable.createdAt)).limit(3),
    db.select().from(alertsTable).where(eq(alertsTable.tenantId, tid)).orderBy(desc(alertsTable.createdAt)).limit(5),
  ]);

  const activity = [
    ...recentFindings.map(f => ({
      id: f.id, type: "finding", title: `New ${f.severity} finding`,
      description: f.title, severity: f.severity, createdAt: f.createdAt.toISOString(),
    })),
    ...recentScans.map(s => ({
      id: s.id + 1000, type: "scan", title: `Scan ${s.status}`,
      description: s.name, severity: null, createdAt: s.createdAt.toISOString(),
    })),
    ...recentAlerts.map(a => ({
      id: a.id + 2000, type: "alert", title: a.title,
      description: a.message ?? a.title, severity: a.severity, createdAt: a.createdAt.toISOString(),
    })),
  ].sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).slice(0, 10);

  res.json(activity);
});

router.get("/dashboard/exposure-breakdown", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const findings = await db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid));

  const exposureTypes: Record<string, number> = {
    "Exposed Admin Panels": findings.filter(f => f.title.toLowerCase().includes("admin")).length,
    "Public Storage Buckets": findings.filter(f => f.title.toLowerCase().includes("bucket") || f.title.toLowerCase().includes("storage")).length,
    "SSL/TLS Issues": findings.filter(f => f.title.toLowerCase().includes("ssl") || f.title.toLowerCase().includes("tls")).length,
    "Injection Vulnerabilities": findings.filter(f => f.cwe === "CWE-89" || f.cwe === "CWE-78").length,
    "Information Disclosure": findings.filter(f => f.cwe === "CWE-200").length,
    "Known Exploited (KEV)": findings.filter(f => f.isKev).length,
  };

  res.json(Object.entries(exposureTypes)
    .filter(([, count]) => count > 0)
    .map(([exposureType, count]) => ({ exposureType, count })));
});

router.get("/dashboard/platform-overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role !== "super_admin") { res.status(403).json({ error: "Forbidden" }); return; }

  const allTenants = await db.select().from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
  const tenantIds = allTenants.map(t => t.id);

  if (tenantIds.length === 0) {
    res.json({
      tenantCount: 0, activeTenantCount: 0, amCount: 0, clientsAtCriticalRisk: 0,
      userCount: 0, assetCount: 0, findingCount: 0, criticalCount: 0, openFindingCount: 0,
      activeScans: 0, openAlertsCount: 0, platformRiskScore: 0, brandThreatsCount: 0,
      takedownsCount: 0, newVulns7D: 0, resolvedVulns7D: 0, exposedPortsCount: 0,
      severityBreakdown: [], clientRiskRankings: [], recentAlerts: [], riskTrend: [], tenants: [],
    });
    return;
  }

  const [allUsers, allAssets, allFindings, allScans, allAlerts, brandThreats, allTakedowns] = await Promise.all([
    db.select({ id: usersTable.id, tenantId: usersTable.tenantId, role: usersTable.role }).from(usersTable).where(inArray(usersTable.tenantId, tenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, tenantIds)),
    db.select().from(findingsTable).where(inArray(findingsTable.tenantId, tenantIds)),
    db.select().from(scansTable).where(inArray(scansTable.tenantId, tenantIds)),
    db.select().from(alertsTable).where(inArray(alertsTable.tenantId, tenantIds)).orderBy(desc(alertsTable.createdAt)),
    db.select().from(brandThreatScansTable).where(inArray(brandThreatScansTable.tenantId, tenantIds)),
    db.select().from(takedownRequestsTable).where(inArray(takedownRequestsTable.tenantId, tenantIds)),
  ]);

  const assetIds = allAssets.map(a => a.id);
  const [allRiskScores, allAmAssignments] = await Promise.all([
    assetIds.length > 0
      ? db.select().from(riskScoresTable).where(inArray(riskScoresTable.assetId, assetIds))
      : Promise.resolve([]),
    db.select().from(accountManagerClientsTable),
  ]);

  const amUserIds = [...new Set(allAmAssignments.map(a => a.accountManagerUserId))];
  const amUsers = amUserIds.length > 0
    ? await db.select({
        id: usersTable.id, email: usersTable.email,
        firstName: usersTable.firstName, lastName: usersTable.lastName,
      }).from(usersTable).where(inArray(usersTable.id, amUserIds))
    : [];

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const amCount = allUsers.filter(u => u.role === "account_manager").length;
  const tenantsWithCritical = new Set(allFindings.filter(f => f.severity === "critical").map(f => f.tenantId));
  const clientsAtCriticalRisk = [...tenantsWithCritical].filter(tid => tenantIds.includes(tid)).length;
  const openAlertsCount = allAlerts.filter(a => !a.isRead).length;

  const platformRiskScore = allRiskScores.length > 0
    ? Math.round(allRiskScores.reduce((s, r) => s + r.score, 0) / allRiskScores.length)
    : 0;

  const CLOSED_STATUSES = ["mitigated", "accepted_risk", "false_positive"];
  const newVulns7D = allFindings.filter(f => new Date(f.createdAt) >= sevenDaysAgo).length;
  const resolvedVulns7D = allFindings.filter(f => CLOSED_STATUSES.includes(f.status) && new Date(f.updatedAt) >= sevenDaysAgo).length;
  const exposedPortsCount = allFindings.filter(f => f.cveId?.startsWith("EXP-PORT-")).length;

  const severityBreakdown = ["critical", "high", "medium", "low", "info"].map(severity => ({
    severity,
    count: allFindings.filter(f => f.severity === severity).length,
  })).filter(s => s.count > 0);

  const TREND_DAYS = 14;
  const now = new Date();
  const assetCountForTrend = Math.max(1, allAssets.length);
  const riskTrend = Array.from({ length: TREND_DAYS }, (_, i) => {
    const dayEnd = new Date(now);
    dayEnd.setDate(dayEnd.getDate() - (TREND_DAYS - 1 - i));
    dayEnd.setHours(23, 59, 59, 999);
    const openOnDay = allFindings.filter(f => {
      const created = new Date(f.createdAt);
      if (created > dayEnd) return false;
      if (CLOSED_STATUSES.includes(f.status)) return new Date(f.updatedAt) > dayEnd;
      return true;
    });
    let penalty = 0;
    for (const f of openOnDay) {
      if (f.severity === "critical") penalty += 20;
      else if (f.severity === "high") penalty += 12;
      else if (f.severity === "medium") penalty += 6;
      else if (f.severity === "low") penalty += 2;
    }
    return {
      date: dayEnd.toISOString().split("T")[0],
      value: Math.max(0, Math.min(100, 100 - Math.round(penalty / assetCountForTrend))),
    };
  });

  const amPortfolio = amUsers.map(am => {
    const assignedTenantIds = allAmAssignments
      .filter(a => a.accountManagerUserId === am.id)
      .map(a => a.clientTenantId);
    const assignedTenants = allTenants.filter(t => assignedTenantIds.includes(t.id));
    return {
      amId: am.id,
      amName: `${am.firstName} ${am.lastName}`.trim() || am.email,
      amEmail: am.email,
      clientCount: assignedTenants.length,
      clients: assignedTenants.map(t => ({
        id: t.id,
        name: t.name,
        plan: t.plan,
        isActive: t.isActive,
        criticalCount: allFindings.filter(f => f.tenantId === t.id && f.severity === "critical").length,
        openFindingCount: allFindings.filter(f => f.tenantId === t.id && f.status === "open").length,
        assetCount: allAssets.filter(a => a.tenantId === t.id).length,
      })),
    };
  });

  const riskScoreMap = new Map(allRiskScores.map(r => [r.assetId, r.score]));
  const clientRiskRankings = allTenants.map(t => {
    const clientAssets = allAssets.filter(a => a.tenantId === t.id);
    const scores = clientAssets.map(a => riskScoreMap.get(a.id) ?? 0).filter(s => s > 0);
    const avgRisk = scores.length > 0 ? Math.round(scores.reduce((s, r) => s + r, 0) / scores.length) : 0;
    const tFindings = allFindings.filter(f => f.tenantId === t.id);
    return {
      id: t.id, name: t.name, plan: t.plan, isActive: t.isActive,
      riskScore: avgRisk,
      riskLevel: avgRisk >= 70 ? "critical" : avgRisk >= 40 ? "high" : avgRisk >= 20 ? "medium" : "low",
      assetCount: clientAssets.length,
      criticalCount: tFindings.filter(f => f.severity === "critical").length,
      openFindingCount: tFindings.filter(f => f.status === "open").length,
      userCount: allUsers.filter(u => u.tenantId === t.id).length,
    };
  }).sort((a, b) => b.riskScore - a.riskScore);

  const recentAlerts = allAlerts.slice(0, 8).map(a => ({
    id: a.id, title: a.title, severity: a.severity, isRead: a.isRead,
    type: a.type, status: a.status,
    createdAt: a.createdAt.toISOString(),
    clientName: allTenants.find(t => t.id === a.tenantId)?.name ?? "Unknown",
  }));

  const tenantMetrics = allTenants.map(t => ({
    id: t.id, name: t.name, slug: t.slug, plan: t.plan, isActive: t.isActive,
    createdAt: t.createdAt.toISOString(),
    userCount: allUsers.filter(u => u.tenantId === t.id).length,
    assetCount: allAssets.filter(a => a.tenantId === t.id).length,
    findingCount: allFindings.filter(f => f.tenantId === t.id).length,
    criticalCount: allFindings.filter(f => f.tenantId === t.id && f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.tenantId === t.id && f.status === "open").length,
    activeScans: allScans.filter(s => s.tenantId === t.id && (s.status === "running" || s.status === "pending")).length,
  }));

  res.json({
    tenantCount: allTenants.length,
    activeTenantCount: allTenants.filter(t => t.isActive).length,
    amCount,
    clientsAtCriticalRisk,
    userCount: allUsers.length,
    assetCount: allAssets.length,
    findingCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.status === "open").length,
    highCount: allFindings.filter(f => f.severity === "high").length,
    activeScans: allScans.filter(s => s.status === "running" || s.status === "pending").length,
    openAlertsCount,
    platformRiskScore,
    brandThreatsCount: brandThreats.length,
    takedownsCount: allTakedowns.length,
    newVulns7D,
    resolvedVulns7D,
    exposedPortsCount,
    severityBreakdown,
    clientRiskRankings,
    recentAlerts,
    riskTrend,
    tenants: tenantMetrics,
    amPortfolio,
  });
});

router.get("/dashboard/am-overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role !== "account_manager" && req.user!.role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" }); return;
  }

  const amUserId = req.user!.role === "super_admin" && req.query.userId
    ? Number(req.query.userId) : req.user!.userId;

  const assignments = await db.select().from(accountManagerClientsTable)
    .where(eq(accountManagerClientsTable.accountManagerUserId, amUserId));

  const empty = {
    clientCount: 0, assetCount: 0, findingCount: 0, criticalCount: 0,
    openFindingCount: 0, activeScans: 0, portfolioRiskScore: 0,
    riskTrend: [], topRiskAssets: [], severityBreakdown: [],
    recentAlerts: [], takedownRequests: [], clients: [],
  };
  if (assignments.length === 0) { res.json(empty); return; }

  const clientTenantIds = assignments.map(a => a.clientTenantId);

  // Parallel fetch: clients + assets (AM-assigned only) + scans + alerts + takedowns + client users
  const [clients, rawAssets, allScans, rawAlerts, allTakedowns, clientUsers] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, clientTenantIds)),
    db.select().from(assetsTable).where(
      and(
        inArray(assetsTable.tenantId, clientTenantIds),
        eq(assetsTable.assignedAccountManagerId, amUserId),
      ),
    ),
    db.select().from(scansTable).where(inArray(scansTable.tenantId, clientTenantIds)),
    db.select().from(alertsTable)
      .where(inArray(alertsTable.tenantId, clientTenantIds))
      .orderBy(desc(alertsTable.createdAt))
      .limit(20),
    db.select().from(takedownRequestsTable)
      .where(inArray(takedownRequestsTable.tenantId, clientTenantIds))
      .orderBy(desc(takedownRequestsTable.createdAt))
      .limit(10),
    db.select({
      id: usersTable.id, tenantId: usersTable.tenantId,
      firstName: usersTable.firstName, lastName: usersTable.lastName,
      email: usersTable.email, role: usersTable.role,
    }).from(usersTable).where(inArray(usersTable.tenantId, clientTenantIds)),
  ]);

  const assignedAssetIds = rawAssets.map(a => a.id);

  // Fetch findings + risk scores keyed by assigned asset IDs
  const [allFindings, allRiskScores] = await (assignedAssetIds.length > 0
    ? Promise.all([
        db.select().from(findingsTable).where(inArray(findingsTable.assetId, assignedAssetIds)),
        db.select().from(riskScoresTable).where(inArray(riskScoresTable.assetId, assignedAssetIds)),
      ])
    : Promise.resolve([[], []] as [typeof findingsTable.$inferSelect[], typeof riskScoresTable.$inferSelect[]]));

  // ── Portfolio risk score ─────────────────────────────────────────────────────
  const portfolioRiskScore = allRiskScores.length > 0
    ? Math.round(allRiskScores.reduce((s, r) => s + r.score, 0) / allRiskScores.length)
    : 0;

  // ── Risk trend (14 days) — same algorithm as /dashboard/risk-trend ───────────
  const TREND_DAYS = 14;
  const now = new Date();
  const assetCountForTrend = Math.max(1, rawAssets.length);
  const riskTrend = Array.from({ length: TREND_DAYS }, (_, i) => {
    const dayEnd = new Date(now);
    dayEnd.setDate(dayEnd.getDate() - (TREND_DAYS - 1 - i));
    dayEnd.setHours(23, 59, 59, 999);
    const openOnDay = allFindings.filter(f => {
      const created = new Date(f.createdAt);
      if (created > dayEnd) return false;
      if (f.status === "resolved") return new Date(f.updatedAt) > dayEnd;
      return true;
    });
    let penalty = 0;
    for (const f of openOnDay) {
      if (f.severity === "critical") penalty += 20;
      else if (f.severity === "high") penalty += 12;
      else if (f.severity === "medium") penalty += 6;
      else if (f.severity === "low") penalty += 2;
    }
    return { date: dayEnd.toISOString().split("T")[0], value: Math.max(0, Math.min(100, 100 - Math.round(penalty / assetCountForTrend))) };
  });

  // ── Top risk assets ──────────────────────────────────────────────────────────
  const riskScoreMap = new Map(allRiskScores.map(r => [r.assetId, r]));
  const findingsByAsset: Record<number, number> = {};
  for (const f of allFindings) findingsByAsset[f.assetId] = (findingsByAsset[f.assetId] ?? 0) + 1;

  const topRiskAssets = rawAssets
    .filter(a => riskScoreMap.has(a.id))
    .sort((a, b) => (riskScoreMap.get(b.id)?.score ?? 0) - (riskScoreMap.get(a.id)?.score ?? 0))
    .slice(0, 5)
    .map(a => ({
      assetId: a.id, assetName: a.name, assetType: a.type,
      riskScore: Math.round(riskScoreMap.get(a.id)?.score ?? 0),
      riskLevel: riskScoreMap.get(a.id)?.level ?? "low",
      findingsCount: findingsByAsset[a.id] ?? 0,
      clientName: clients.find(c => c.id === a.tenantId)?.name ?? "Unknown",
    }));

  // ── Severity breakdown ───────────────────────────────────────────────────────
  const severityBreakdown = ["critical", "high", "medium", "low", "info"]
    .map(severity => ({ severity, count: allFindings.filter(f => f.severity === severity).length }))
    .filter(s => s.count > 0);

  // ── Recent alerts (only those related to assigned assets) ───────────────────
  const recentAlerts = rawAlerts
    .filter(a => !a.relatedAssetId || assignedAssetIds.includes(a.relatedAssetId))
    .slice(0, 8)
    .map(a => ({
      id: a.id, title: a.title, severity: a.severity,
      isRead: a.isRead, createdAt: a.createdAt.toISOString(),
      clientName: clients.find(c => c.id === a.tenantId)?.name ?? "Unknown",
    }));

  // ── Takedown requests ────────────────────────────────────────────────────────
  const takedownRequests = allTakedowns.map(t => ({
    id: t.id, domain: t.domain, status: t.status,
    reason: (t as any).reason ?? null,
    createdAt: t.createdAt?.toISOString() ?? new Date().toISOString(),
    clientName: clients.find(c => c.id === t.tenantId)?.name ?? "Unknown",
  }));

  // ── Client metrics (with admin user name + per-client risk score) ────────────
  const clientAdminMap = new Map<number, { name: string; email: string }>();
  for (const u of clientUsers) {
    if (!clientAdminMap.has(u.tenantId) || u.role === "admin") {
      clientAdminMap.set(u.tenantId, { name: `${u.firstName} ${u.lastName}`, email: u.email });
    }
  }

  const clientMetrics = clients.map(t => {
    const clientAssets = rawAssets.filter(a => a.tenantId === t.id);
    const clientAssetIds = clientAssets.map(a => a.id);
    const clientFindings = allFindings.filter(f => clientAssetIds.includes(f.assetId));
    const clientRiskScores = allRiskScores.filter(r => clientAssetIds.includes(r.assetId));
    const avgRisk = clientRiskScores.length > 0
      ? Math.round(clientRiskScores.reduce((s, r) => s + r.score, 0) / clientRiskScores.length)
      : 0;
    const contact = clientAdminMap.get(t.id);
    return {
      id: t.id, name: t.name, plan: t.plan, isActive: t.isActive,
      clientUserName: contact?.name ?? "—",
      clientUserEmail: contact?.email ?? null,
      assetCount: clientAssets.length,
      riskScore: avgRisk,
      findingCount: clientFindings.length,
      criticalCount: clientFindings.filter(f => f.severity === "critical").length,
      openFindingCount: clientFindings.filter(f => f.status === "open").length,
      activeScans: allScans.filter(s => s.tenantId === t.id && (s.status === "running" || s.status === "pending")).length,
      assignedAt: assignments.find(a => a.clientTenantId === t.id)?.assignedAt?.toISOString() ?? null,
    };
  });

  res.json({
    clientCount: clients.length,
    assetCount: rawAssets.length,
    findingCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.status === "open").length,
    activeScans: allScans.filter(s => s.status === "running" || s.status === "pending").length,
    portfolioRiskScore,
    riskTrend,
    topRiskAssets,
    severityBreakdown,
    recentAlerts,
    takedownRequests,
    clients: clientMetrics,
  });
});

router.get("/dashboard/client-overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
  const uid = req.user!.userId;
  const isClient = req.user!.role === "client";

  // For client role: scope to only their assigned assets
  const assetFilter = isClient
    ? and(eq(assetsTable.tenantId, tid), eq(assetsTable.assignedClientId, uid))
    : eq(assetsTable.tenantId, tid);

  const assets = await db.select().from(assetsTable).where(assetFilter);
  const assignedAssetIds = assets.map(a => a.id);

  // Build findings/alerts/scans/takedowns filters based on assigned assets
  const findingsWhere = isClient
    ? (assignedAssetIds.length > 0 ? and(eq(findingsTable.tenantId, tid), inArray(findingsTable.assetId, assignedAssetIds)) : null)
    : eq(findingsTable.tenantId, tid);
  const alertsWhere = isClient
    ? (assignedAssetIds.length > 0
        ? and(eq(alertsTable.tenantId, tid), or(isNull(alertsTable.relatedAssetId), inArray(alertsTable.relatedAssetId, assignedAssetIds)))
        : and(eq(alertsTable.tenantId, tid), isNull(alertsTable.relatedAssetId)))
    : eq(alertsTable.tenantId, tid);

  const [findings, alerts, scans, takedowns] = await Promise.all([
    findingsWhere ? db.select().from(findingsTable).where(findingsWhere) : Promise.resolve([]),
    db.select().from(alertsTable).where(alertsWhere!),
    db.select().from(scansTable).where(eq(scansTable.tenantId, tid)),
    db.select().from(takedownRequestsTable).where(eq(takedownRequestsTable.tenantId, tid)),
  ]);

  const riskScoresWhere = isClient && assignedAssetIds.length > 0
    ? inArray(riskScoresTable.assetId, assignedAssetIds)
    : isClient
      ? null
      : undefined;

  const riskScores = riskScoresWhere === null
    ? []
    : await db.select().from(riskScoresTable)
        .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
        .where(riskScoresWhere ?? eq(assetsTable.tenantId, tid));

  // Risk score (avg across all assets, 0–100)
  const avgRisk = riskScores.length > 0
    ? Math.round(riskScores.reduce((s, r) => s + r.risk_scores.score, 0) / riskScores.length)
    : 0;

  // Assets at risk breakdown
  const riskLevels = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const { risk_scores } of riskScores) {
    const lvl = risk_scores.level as keyof typeof riskLevels;
    if (lvl in riskLevels) riskLevels[lvl]++;
  }

  // Findings stats
  const openFindings = findings.filter(f => f.status === "open" && !f.isFalsePositive);
  const resolvedFindings = findings.filter(f => f.status === "resolved");
  const criticalVulns = openFindings.filter(f => f.severity === "critical").length;

  // New vulns from latest scan (findings added in last 7 days)
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const newVulnsFromLatestScan = openFindings.filter(f => new Date(f.createdAt) >= sevenDaysAgo).length;

  // Severity breakdown of open findings
  const severityBreakdown = ["critical", "high", "medium", "low", "info"].map(sev => ({
    severity: sev,
    count: openFindings.filter(f => f.severity === sev).length,
  }));

  // Open alerts (unread)
  const openAlerts = alerts.filter(a => !a.isRead);

  // Recent alerts (last 5)
  const recentAlerts = [...alerts]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 5)
    .map(a => ({ id: a.id, title: a.title, message: a.message, severity: a.severity, isRead: a.isRead, createdAt: a.createdAt }));

  // False positive breakdown
  const fpSubmitted = findings.filter(f => f.falsePositiveStatus === "submitted").length;
  const fpConfirmed = findings.filter(f => f.falsePositiveStatus === "confirmed" || f.isFalsePositive).length;
  const fpRejected = findings.filter(f => f.falsePositiveStatus === "rejected").length;

  // Takedown breakdown
  const tdTotal = takedowns.length;
  const tdSubmitted = takedowns.filter(t => t.status === "submitted").length;
  const tdInProgress = takedowns.filter(t => t.status === "in_progress").length;
  const tdClosed = takedowns.filter(t => t.status === "closed").length;
  const recentTakedowns = [...takedowns]
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 5)
    .map(t => ({ id: t.id, title: t.title, type: t.type, status: t.status, priority: t.priority, createdAt: t.createdAt }));

  // ── Score Timeline (30 days) ─────────────────────────────────────
  const timelineDays = 30;
  const now = new Date();
  const scoreTimeline: { date: string; score: number }[] = [];
  for (let i = timelineDays - 1; i >= 0; i--) {
    const dayEnd = new Date(now);
    dayEnd.setDate(dayEnd.getDate() - i);
    dayEnd.setHours(23, 59, 59, 999);
    const openOnDay = findings.filter(f => {
      const created = new Date(f.createdAt);
      if (created > dayEnd) return false;
      if (f.status === "resolved") {
        const resolved = new Date(f.updatedAt);
        return resolved > dayEnd;
      }
      return true;
    });
    let penalty = 0;
    for (const f of openOnDay) {
      if (f.severity === "critical")     penalty += 20;
      else if (f.severity === "high")    penalty += 12;
      else if (f.severity === "medium")  penalty += 6;
      else if (f.severity === "low")     penalty += 2;
    }
    const divisor = Math.max(1, assets.length);
    const score = Math.max(0, Math.min(100, 100 - Math.round(penalty / divisor)));
    scoreTimeline.push({ date: dayEnd.toISOString().split("T")[0], score });
  }

  // ── Category-Based Risk Scoring ──────────────────────────────────
  const CATEGORY_RULES = [
    { id: "security_hygiene",       name: "Security Hygiene",           keywords: ["patch", "update", "outdated", "version", "end-of-life", "deprecated", "unpatched", "obsolete"],  cwes: [] },
    { id: "data_leakage",           name: "Data Leakage",               keywords: ["data leak", "pii", "sensitive data", "exposed data", "database dump", "breach", "disclosure"],   cwes: ["CWE-200", "CWE-359", "CWE-312"] },
    { id: "dns_security",           name: "DNS Security",               keywords: ["dns", "dkim", "spf", "dmarc", "mx record", "nameserver", "zone transfer", "subdomain takeover"], cwes: ["CWE-290"] },
    { id: "exposed_infrastructure", name: "Exposed Infrastructure",     keywords: ["exposed", "open port", "admin panel", "management interface", "rdp", "telnet", "ftp", "vnc"],   cwes: ["CWE-284"] },
    { id: "information_leakage",    name: "Information Leakage",        keywords: ["information disclosure", "error message", "debug", "stack trace", "directory listing", "server banner", "header leak"], cwes: ["CWE-209"] },
    { id: "network_security",       name: "Network Security",           keywords: ["network", "firewall", "routing", "icmp", "snmp", "mitm", "arp spoofing", "packet"],              cwes: ["CWE-311"] },
    { id: "third_party_security",   name: "Third Party Security",       keywords: ["third party", "vendor", "supply chain", "dependency", "library", "component", "npm", "package", "outdated library"], cwes: ["CWE-1035", "CWE-937"] },
    { id: "transport_layer",        name: "Transport Layer Security",   keywords: ["ssl", "tls", "certificate", "cipher", "https", "hsts", "weak cipher", "self-signed", "expired cert"], cwes: ["CWE-326", "CWE-295", "CWE-327"] },
    { id: "weak_credentials",       name: "Weak / Default Credentials", keywords: ["credential", "password", "default password", "weak password", "brute force", "authentication bypass", "login"], cwes: ["CWE-521", "CWE-798", "CWE-307"] },
    { id: "web_security",           name: "Web Security",               keywords: ["xss", "csrf", "sql injection", "rce", "lfi", "rfi", "clickjacking", "cors", "content security", "open redirect"], cwes: ["CWE-79", "CWE-89", "CWE-352", "CWE-78", "CWE-22"] },
    { id: "dark_web",               name: "Dark Web",                   keywords: ["dark web", "darkweb", "paste", "leaked", "tor", "breach", "credential dump", "hacker forum", "underground"],        cwes: [] },
    { id: "cloud_security",         name: "Cloud Security",             keywords: ["cloud", "s3 bucket", "azure", "aws", "gcp", "iam", "misconfigured", "storage bucket", "blob", "lambda"],          cwes: ["CWE-732"] },
  ] as const;

  const categoryScores = CATEGORY_RULES.map(cat => {
    const catFindings = openFindings.filter(f => {
      const text = `${f.title} ${f.description ?? ""} ${f.remediation ?? ""}`.toLowerCase();
      const hasCwe = cat.cwes.length > 0 && (cat.cwes as readonly string[]).some(cwe => f.cwe === cwe);
      const hasKeyword = (cat.keywords as readonly string[]).some(kw => text.includes(kw));
      return hasCwe || hasKeyword;
    });
    let penalty = 0;
    for (const f of catFindings) {
      if (f.severity === "critical")     penalty += 25;
      else if (f.severity === "high")    penalty += 15;
      else if (f.severity === "medium")  penalty += 8;
      else if (f.severity === "low")     penalty += 3;
    }
    const score = Math.max(0, Math.min(100, 100 - penalty));
    return { id: cat.id, name: cat.name, score, findingsCount: catFindings.length };
  });

  // ── Top Asset Types Discovered ───────────────────────────────────
  const typeMap: Record<string, number> = {};
  for (const a of assets) { typeMap[a.type] = (typeMap[a.type] ?? 0) + 1; }
  const topAssetTypes = Object.entries(typeMap)
    .sort((a, b) => b[1] - a[1])
    .map(([type, count]) => ({ type, count }));

  // ── Top Vulnerable Assets ────────────────────────────────────────
  const findingsByAsset: Record<number, { total: number; critical: number; high: number }> = {};
  for (const f of openFindings) {
    if (!findingsByAsset[f.assetId]) findingsByAsset[f.assetId] = { total: 0, critical: 0, high: 0 };
    findingsByAsset[f.assetId].total++;
    if (f.severity === "critical") findingsByAsset[f.assetId].critical++;
    if (f.severity === "high")     findingsByAsset[f.assetId].high++;
  }
  const riskScoreByAsset: Record<number, number> = {};
  for (const { risk_scores } of riskScores) riskScoreByAsset[risk_scores.assetId] = risk_scores.score;

  const topVulnerableAssets = assets
    .filter(a => (findingsByAsset[a.id]?.total ?? 0) > 0)
    .sort((a, b) => {
      const scoreA = (riskScoreByAsset[a.id] ?? 0);
      const scoreB = (riskScoreByAsset[b.id] ?? 0);
      if (scoreB !== scoreA) return scoreB - scoreA;
      return (findingsByAsset[b.id]?.total ?? 0) - (findingsByAsset[a.id]?.total ?? 0);
    })
    .slice(0, 6)
    .map(a => ({
      id: a.id, name: a.name, type: a.type, value: a.value,
      riskScore: riskScoreByAsset[a.id] ?? null,
      findings: findingsByAsset[a.id] ?? { total: 0, critical: 0, high: 0 },
    }));

  // ── Top Security Risks ───────────────────────────────────────────
  const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const topSecurityRisks = [...openFindings]
    .sort((a, b) => {
      const wA = sevWeight[a.severity ?? "info"] ?? 0;
      const wB = sevWeight[b.severity ?? "info"] ?? 0;
      if (wB !== wA) return wB - wA;
      if (a.isKev && !b.isKev) return -1;
      if (!a.isKev && b.isKev) return 1;
      return (b.cvss ?? 0) - (a.cvss ?? 0);
    })
    .slice(0, 8)
    .map(f => {
      const asset = assets.find(a => a.id === f.assetId);
      return {
        id: f.id, title: f.title, severity: f.severity, cve: f.cve, cwe: f.cwe,
        cvss: f.cvss, epss: f.epss, isKev: f.isKev,
        assetName: asset?.name ?? "Unknown", assetType: asset?.type ?? "unknown",
      };
    });

  res.json({
    riskScore: avgRisk,
    totalAssets: assets.length,
    openFindings: openFindings.length,
    criticalVulns,
    newVulnsFromLatestScan,
    openVulnerabilities: openFindings.length,
    openAlerts: openAlerts.length,
    resolvedVulns: resolvedFindings.length,
    riskLevels,
    severityBreakdown,
    recentAlerts,
    takedowns: { total: tdTotal, submitted: tdSubmitted, inProgress: tdInProgress, closed: tdClosed },
    recentTakedowns,
    falsePositives: { submitted: fpSubmitted, confirmed: fpConfirmed, rejected: fpRejected },
    scoreTimeline,
    categoryScores,
    topAssetTypes,
    topVulnerableAssets,
    topSecurityRisks,
  });
});

router.get("/dashboard/admin-overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;
  if (role !== "admin" && role !== "manager") { res.status(403).json({ error: "Forbidden" }); return; }

  const tid = req.user!.tenantId;

  const [allAssets, allFindings, allScans, allAlerts, brandThreats, allTakedowns] = await Promise.all([
    db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid)),
    db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid)),
    db.select().from(scansTable).where(eq(scansTable.tenantId, tid)),
    db.select().from(alertsTable).where(eq(alertsTable.tenantId, tid)).orderBy(desc(alertsTable.createdAt)),
    db.select().from(brandThreatScansTable).where(eq(brandThreatScansTable.tenantId, tid)),
    db.select().from(takedownRequestsTable).where(eq(takedownRequestsTable.tenantId, tid)),
  ]);

  const assetIds = allAssets.map(a => a.id);
  const [allRiskScores, tenantAmAssignments] = await Promise.all([
    assetIds.length > 0
      ? db.select().from(riskScoresTable).where(inArray(riskScoresTable.assetId, assetIds))
      : Promise.resolve([]),
    db.select().from(accountManagerClientsTable)
      .where(eq(accountManagerClientsTable.clientTenantId, tid)),
  ]);

  const tenantAmUserIds = [...new Set(tenantAmAssignments.map(a => a.accountManagerUserId))];
  const tenantAmUsers = tenantAmUserIds.length > 0
    ? await db.select({ id: usersTable.id, email: usersTable.email, firstName: usersTable.firstName, lastName: usersTable.lastName })
      .from(usersTable).where(inArray(usersTable.id, tenantAmUserIds))
    : [];

  const amPortfolio = tenantAmUsers.map(am => ({
    amId: am.id,
    amName: `${am.firstName} ${am.lastName}`.trim() || am.email,
    amEmail: am.email,
  }));

  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

  const riskScore = allRiskScores.length > 0
    ? Math.round(allRiskScores.reduce((s, r) => s + r.score, 0) / allRiskScores.length)
    : 0;

  const openAlertsCount = allAlerts.filter(a => !a.isRead).length;
  const CLOSED_STATUSES_ADMIN = ["mitigated", "accepted_risk", "false_positive"];
  const newVulns7D = allFindings.filter(f => new Date(f.createdAt) >= sevenDaysAgo).length;
  const resolvedVulns7D = allFindings.filter(f => CLOSED_STATUSES_ADMIN.includes(f.status) && new Date(f.updatedAt) >= sevenDaysAgo).length;
  const exposedPortsCount = allFindings.filter(f => f.cveId?.startsWith("EXP-PORT-")).length;

  const severityBreakdown = ["critical", "high", "medium", "low", "info"].map(severity => ({
    severity,
    count: allFindings.filter(f => f.severity === severity).length,
  })).filter(s => s.count > 0);

  const TREND_DAYS = 14;
  const now = new Date();
  const assetCount = Math.max(1, allAssets.length);
  const riskTrend = Array.from({ length: TREND_DAYS }, (_, i) => {
    const dayEnd = new Date(now);
    dayEnd.setDate(dayEnd.getDate() - (TREND_DAYS - 1 - i));
    dayEnd.setHours(23, 59, 59, 999);
    const openOnDay = allFindings.filter(f => {
      const created = new Date(f.createdAt);
      if (created > dayEnd) return false;
      if (CLOSED_STATUSES_ADMIN.includes(f.status)) return new Date(f.updatedAt) > dayEnd;
      return true;
    });
    let penalty = 0;
    for (const f of openOnDay) {
      if (f.severity === "critical") penalty += 20;
      else if (f.severity === "high") penalty += 12;
      else if (f.severity === "medium") penalty += 6;
      else if (f.severity === "low") penalty += 2;
    }
    return {
      date: dayEnd.toISOString().split("T")[0],
      value: Math.max(0, Math.min(100, 100 - Math.round(penalty / assetCount))),
    };
  });

  const riskScoreMap = new Map(allRiskScores.map(r => [r.assetId, r]));
  const assetRiskRankings = allAssets
    .filter(a => riskScoreMap.has(a.id))
    .sort((a, b) => (riskScoreMap.get(b.id)?.score ?? 0) - (riskScoreMap.get(a.id)?.score ?? 0))
    .slice(0, 8)
    .map(a => {
      const rs = riskScoreMap.get(a.id)!;
      return {
        assetId: a.id, assetName: a.name, assetType: a.type,
        riskScore: Math.round(rs.score), riskLevel: rs.level,
        findingsCount: allFindings.filter(f => f.assetId === a.id).length,
        criticalCount: allFindings.filter(f => f.assetId === a.id && f.severity === "critical").length,
      };
    });

  const recentAlerts = allAlerts.slice(0, 8).map(a => ({
    id: a.id, title: a.title, severity: a.severity, isRead: a.isRead,
    type: a.type, status: a.status,
    createdAt: a.createdAt.toISOString(),
  }));

  res.json({
    assetCount: allAssets.length,
    findingCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === "critical").length,
    highCount: allFindings.filter(f => f.severity === "high").length,
    openFindingCount: allFindings.filter(f => f.status === "open").length,
    activeScans: allScans.filter(s => s.status === "running" || s.status === "pending").length,
    openAlertsCount,
    riskScore,
    brandThreatsCount: brandThreats.length,
    takedownsCount: allTakedowns.length,
    newVulns7D,
    resolvedVulns7D,
    exposedPortsCount,
    severityBreakdown,
    assetRiskRankings,
    recentAlerts,
    riskTrend,
    amPortfolio,
  });
});

export default router;
