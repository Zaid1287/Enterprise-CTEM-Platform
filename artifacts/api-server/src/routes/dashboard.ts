import { Router } from "express";
import { eq, count, and, desc, sql, inArray } from "drizzle-orm";
import { db, assetsTable, findingsTable, scansTable, alertsTable, riskScoresTable, auditLogsTable, complianceControlsTable, tenantsTable, usersTable, accountManagerClientsTable, takedownRequestsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

router.get("/dashboard/overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;
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

  res.json({
    totalAssets, totalFindings, criticalFindings, highFindings, openFindings,
    activeScans, complianceScore, riskScore: Math.round(avgRisk),
    unreadAlerts, assetsTrend: 12, findingsTrend: -8,
  });
});

router.get("/dashboard/risk-trend", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const days = parseInt(String(req.query.days ?? "30"), 10);
  const trend = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now);
    date.setDate(date.getDate() - i);
    trend.push({
      date: date.toISOString().split("T")[0],
      value: Math.round(50 + Math.sin(i * 0.3) * 20 + Math.random() * 10),
    });
  }
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
    res.json({ tenantCount: 0, activeTenantCount: 0, userCount: 0, assetCount: 0, findingCount: 0, criticalCount: 0, openFindingCount: 0, activeScans: 0, tenants: [] });
    return;
  }

  const [allUsers, allAssets, allFindings, allScans] = await Promise.all([
    db.select().from(usersTable).where(inArray(usersTable.tenantId, tenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, tenantIds)),
    db.select().from(findingsTable).where(inArray(findingsTable.tenantId, tenantIds)),
    db.select().from(scansTable).where(inArray(scansTable.tenantId, tenantIds)),
  ]);

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
    userCount: allUsers.length,
    assetCount: allAssets.length,
    findingCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.status === "open").length,
    activeScans: allScans.filter(s => s.status === "running" || s.status === "pending").length,
    tenants: tenantMetrics,
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
  if (assignments.length === 0) {
    res.json({ clientCount: 0, assetCount: 0, findingCount: 0, criticalCount: 0, openFindingCount: 0, activeScans: 0, clients: [] });
    return;
  }

  const clientTenantIds = assignments.map(a => a.clientTenantId);
  const [clients, allAssets, allFindings, allScans] = await Promise.all([
    db.select().from(tenantsTable).where(inArray(tenantsTable.id, clientTenantIds)),
    db.select().from(assetsTable).where(inArray(assetsTable.tenantId, clientTenantIds)),
    db.select().from(findingsTable).where(inArray(findingsTable.tenantId, clientTenantIds)),
    db.select().from(scansTable).where(inArray(scansTable.tenantId, clientTenantIds)),
  ]);

  const clientMetrics = clients.map(t => ({
    id: t.id, name: t.name, plan: t.plan, isActive: t.isActive,
    assetCount: allAssets.filter(a => a.tenantId === t.id).length,
    findingCount: allFindings.filter(f => f.tenantId === t.id).length,
    criticalCount: allFindings.filter(f => f.tenantId === t.id && f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.tenantId === t.id && f.status === "open").length,
    activeScans: allScans.filter(s => s.tenantId === t.id && (s.status === "running" || s.status === "pending")).length,
    assignedAt: assignments.find(a => a.clientTenantId === t.id)?.assignedAt?.toISOString() ?? null,
  }));

  res.json({
    clientCount: clients.length,
    assetCount: allAssets.length,
    findingCount: allFindings.length,
    criticalCount: allFindings.filter(f => f.severity === "critical").length,
    openFindingCount: allFindings.filter(f => f.status === "open").length,
    activeScans: allScans.filter(s => s.status === "running" || s.status === "pending").length,
    clients: clientMetrics,
  });
});

router.get("/dashboard/client-overview", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tid = req.user!.tenantId;

  const [assets, findings, alerts, scans, takedowns] = await Promise.all([
    db.select().from(assetsTable).where(eq(assetsTable.tenantId, tid)),
    db.select().from(findingsTable).where(eq(findingsTable.tenantId, tid)),
    db.select().from(alertsTable).where(eq(alertsTable.tenantId, tid)),
    db.select().from(scansTable).where(eq(scansTable.tenantId, tid)),
    db.select().from(takedownRequestsTable).where(eq(takedownRequestsTable.tenantId, tid)),
  ]);

  const riskScores = await db.select().from(riskScoresTable)
    .leftJoin(assetsTable, eq(riskScoresTable.assetId, assetsTable.id))
    .where(eq(assetsTable.tenantId, tid));

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
  });
});

export default router;
