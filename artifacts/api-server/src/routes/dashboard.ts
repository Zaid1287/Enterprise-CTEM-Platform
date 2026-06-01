import { Router } from "express";
import { eq, count, and, desc, sql } from "drizzle-orm";
import { db, assetsTable, findingsTable, scansTable, alertsTable, riskScoresTable, auditLogsTable, complianceControlsTable } from "@workspace/db";
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

export default router;
