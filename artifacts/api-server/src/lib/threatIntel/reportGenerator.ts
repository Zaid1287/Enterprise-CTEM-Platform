/**
 * TI Report Generator
 * Compiles real threat intelligence data from the DB into structured reports.
 * Report types: summary | ioc | actor | vulnerability | custom
 *
 * Data sources (all real — no mock data):
 *  GLOBAL (no tenantId filter):
 *   - tiIocsTable            → IOC indicators
 *   - tiThreatActorsTable    → threat actor profiles
 *   - tiCampaignsTable       → active campaigns
 *   - tiMalwareTable         → malware families (MITRE ATT&CK)
 *   - tiCveIntelTable        → CVE intelligence
 *   - tiC2ServersTable       → C2 server infrastructure
 *   - tiNewsFeedsTable       → recent threat news
 *  TENANT-SCOPED:
 *   - tiDarkWebMentionsTable → dark web findings (tenant-scoped)
 *   - findingsTable          → vulnerability findings (tenant-scoped)
 */

import {
  db, tiIocsTable, tiThreatActorsTable, tiCampaignsTable,
  tiMalwareTable, tiCveIntelTable, tiDarkWebMentionsTable, tiNewsFeedsTable,
  findingsTable, tiC2ServersTable, tiActorTtpsTable, tiReportsTable,
} from "@workspace/db";
import { eq, desc, and } from "drizzle-orm";
import { logger } from "../logger.js";

// ── Data loaders ──────────────────────────────────────────────────────────────

async function loadIocs(limit = 100) {
  return db.select({
    id: tiIocsTable.id,
    type: tiIocsTable.type,
    value: tiIocsTable.value,
    severity: tiIocsTable.severity,
    confidence: tiIocsTable.confidence,
    source: tiIocsTable.source,
    tags: tiIocsTable.tags,
    firstSeen: tiIocsTable.firstSeen,
    lastSeen: tiIocsTable.lastSeen,
    isActive: tiIocsTable.isActive,
    malwareFamilies: tiIocsTable.malwareFamilies,
  }).from(tiIocsTable)
    .orderBy(desc(tiIocsTable.createdAt))
    .limit(limit);
}

async function loadActors(limit = 50) {
  return db.select({
    id: tiThreatActorsTable.id,
    name: tiThreatActorsTable.name,
    aliases: tiThreatActorsTable.aliases,
    country: tiThreatActorsTable.country,
    motivation: tiThreatActorsTable.motivation,
    sophistication: tiThreatActorsTable.sophistication,
    isActive: tiThreatActorsTable.isActive,
    targetIndustries: tiThreatActorsTable.targetIndustries,
    targetCountries: tiThreatActorsTable.targetCountries,
    description: tiThreatActorsTable.description,
    firstSeen: tiThreatActorsTable.firstSeen,
    lastSeen: tiThreatActorsTable.lastSeen,
  }).from(tiThreatActorsTable)
    .orderBy(desc(tiThreatActorsTable.updatedAt))
    .limit(limit);
}

async function loadCampaigns(limit = 20) {
  return db.select({
    id: tiCampaignsTable.id,
    name: tiCampaignsTable.name,
    status: tiCampaignsTable.status,
    targetIndustries: tiCampaignsTable.targetIndustries,
    targetCountries: tiCampaignsTable.targetCountries,
    startDate: tiCampaignsTable.startDate,
    endDate: tiCampaignsTable.endDate,
    description: tiCampaignsTable.description,
  }).from(tiCampaignsTable)
    .orderBy(desc(tiCampaignsTable.createdAt))
    .limit(limit);
}

async function loadCves(limit = 50) {
  return db.select({
    id: tiCveIntelTable.id,
    cveId: tiCveIntelTable.cveId,
    severity: tiCveIntelTable.severity,
    cvss: tiCveIntelTable.cvss,
    epss: tiCveIntelTable.epss,
    isKev: tiCveIntelTable.isKev,
    affectedProducts: tiCveIntelTable.affectedProducts,
    publishedDate: tiCveIntelTable.publishedDate,
    description: tiCveIntelTable.description,
    exploitationStatus: tiCveIntelTable.exploitationStatus,
    pocPublic: tiCveIntelTable.pocPublic,
    patchAvailable: tiCveIntelTable.patchAvailable,
  }).from(tiCveIntelTable)
    .orderBy(desc(tiCveIntelTable.createdAt))
    .limit(limit);
}

async function loadDarkWebMentions(tenantId: number, limit = 30) {
  return db.select({
    id: tiDarkWebMentionsTable.id,
    title: tiDarkWebMentionsTable.title,
    source: tiDarkWebMentionsTable.source,
    severity: tiDarkWebMentionsTable.severity,
    mentionType: tiDarkWebMentionsTable.mentionType,
    assetDomain: tiDarkWebMentionsTable.assetDomain,
    keywords: tiDarkWebMentionsTable.keywords,
    isVerified: tiDarkWebMentionsTable.isVerified,
    detectedAt: tiDarkWebMentionsTable.detectedAt,
    content: tiDarkWebMentionsTable.content,
  }).from(tiDarkWebMentionsTable)
    .where(eq(tiDarkWebMentionsTable.tenantId, tenantId))
    .orderBy(desc(tiDarkWebMentionsTable.detectedAt))
    .limit(limit);
}

async function loadFindings(tenantId: number, limit = 50) {
  return db.select({
    id: findingsTable.id,
    title: findingsTable.title,
    severity: findingsTable.severity,
    status: findingsTable.status,
    cve: findingsTable.cve,
    cvss: findingsTable.cvss,
    epss: findingsTable.epss,
    isKev: findingsTable.isKev,
    createdAt: findingsTable.createdAt,
  }).from(findingsTable)
    .where(eq(findingsTable.tenantId, tenantId))
    .orderBy(desc(findingsTable.createdAt))
    .limit(limit);
}

async function loadNews(limit = 20) {
  return db.select({
    id: tiNewsFeedsTable.id,
    title: tiNewsFeedsTable.title,
    url: tiNewsFeedsTable.url,
    sourceName: tiNewsFeedsTable.sourceName,
    severity: tiNewsFeedsTable.severity,
    tags: tiNewsFeedsTable.tags,
    cves: tiNewsFeedsTable.cves,
    actors: tiNewsFeedsTable.actors,
    publishedAt: tiNewsFeedsTable.publishedAt,
  }).from(tiNewsFeedsTable)
    .orderBy(desc(tiNewsFeedsTable.publishedAt))
    .limit(limit);
}

async function loadMalware(limit = 20) {
  return db.select({
    id: tiMalwareTable.id,
    name: tiMalwareTable.name,
    malwareType: tiMalwareTable.malwareType,
    aliases: tiMalwareTable.aliases,
    platforms: tiMalwareTable.platforms,
  }).from(tiMalwareTable)
    .orderBy(desc(tiMalwareTable.updatedAt))
    .limit(limit);
}

async function loadC2Servers(limit = 20) {
  return db.select({
    id: tiC2ServersTable.id,
    ip: tiC2ServersTable.ip,
    port: tiC2ServersTable.port,
    domain: tiC2ServersTable.domain,
    malwareFamily: tiC2ServersTable.malwareFamily,
    isActive: tiC2ServersTable.isActive,
    discoveredAt: tiC2ServersTable.discoveredAt,
    lastSeenAt: tiC2ServersTable.lastSeenAt,
    country: tiC2ServersTable.country,
  }).from(tiC2ServersTable)
    .orderBy(desc(tiC2ServersTable.lastSeenAt))
    .limit(limit);
}

// ── Report builders ───────────────────────────────────────────────────────────

async function buildSummaryReport(tenantId: number): Promise<any> {
  const [iocs, actors, campaigns, cves, darkWeb, findings, news, malware, c2] = await Promise.all([
    loadIocs(50),
    loadActors(20),
    loadCampaigns(10),
    loadCves(30),
    loadDarkWebMentions(tenantId, 20),
    loadFindings(tenantId, 30),
    loadNews(15),
    loadMalware(15),
    loadC2Servers(15),
  ]);

  const findingsBySeverity = countBySeverity(findings, f => f.severity);
  const iocsBySeverity = countBySeverity(iocs, i => i.severity ?? "medium");
  const cveKev = cves.filter(c => c.isKev);
  const cveHighEpss = cves.filter(c => (c.epss ?? 0) >= 0.5);
  const activeActors = actors.filter(a => a.isActive);
  const activeCampaigns = campaigns.filter(c => c.status === "active");
  const criticalDarkWeb = darkWeb.filter(d => d.severity === "critical" || d.severity === "high");
  const riskScore = computeRiskScore({ iocs, cves, darkWeb, findings });

  return {
    generatedAt: new Date().toISOString(),
    reportType: "summary",
    riskScore,
    overview: {
      totalIocs: iocs.length,
      activeIocs: iocs.filter(i => i.isActive).length,
      totalActors: actors.length,
      activeActors: activeActors.length,
      activeCampaigns: activeCampaigns.length,
      totalCves: cves.length,
      kevCount: cveKev.length,
      highEpssCount: cveHighEpss.length,
      darkWebMentions: darkWeb.length,
      criticalDarkWebMentions: criticalDarkWeb.length,
      openFindings: findings.filter(f => f.status === "open").length,
      criticalFindings: findings.filter(f => f.severity === "critical").length,
      totalMalware: malware.length,
      activeC2: c2.filter(s => s.isActive).length,
      findingsBySeverity,
      iocsBySeverity,
    },
    topThreats: {
      iocs: iocs.filter(i => i.severity === "critical" || i.severity === "high").slice(0, 10),
      actors: activeActors.slice(0, 5),
      campaigns: activeCampaigns.slice(0, 5),
      cves: cveKev.concat(cveHighEpss.filter(c => !c.isKev)).slice(0, 10),
      darkWeb: criticalDarkWeb.slice(0, 5),
      findings: findings.filter(f => f.severity === "critical").slice(0, 10),
    },
    recentNews: news.slice(0, 10),
    malware,
    c2Servers: c2.filter(s => s.isActive),
    allIocs: iocs,
    allCves: cves,
    allDarkWeb: darkWeb,
  };
}

async function buildIocReport(_tenantId: number): Promise<any> {
  const [iocs, malware, c2] = await Promise.all([
    loadIocs(500),
    loadMalware(50),
    loadC2Servers(50),
  ]);

  const byType: Record<string, any[]> = {};
  for (const ioc of iocs) {
    const t = ioc.type ?? "unknown";
    (byType[t] = byType[t] ?? []).push(ioc);
  }

  return {
    generatedAt: new Date().toISOString(),
    reportType: "ioc",
    overview: {
      total: iocs.length,
      active: iocs.filter(i => i.isActive).length,
      byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length])),
      bySeverity: countBySeverity(iocs, i => i.severity ?? "medium"),
    },
    indicators: iocs,
    malwareFamilies: malware,
    c2Servers: c2,
    byType,
  };
}

async function buildActorReport(_tenantId: number): Promise<any> {
  const [actors, campaigns, malware] = await Promise.all([
    loadActors(100),
    loadCampaigns(50),
    loadMalware(50),
  ]);

  const ttps = actors.length > 0
    ? await db.select().from(tiActorTtpsTable).limit(200)
    : [];

  const ttpsByActor: Record<number, any[]> = {};
  for (const ttp of ttps) {
    (ttpsByActor[ttp.actorId] = ttpsByActor[ttp.actorId] ?? []).push(ttp);
  }

  const enrichedActors = actors.map(a => ({
    ...a,
    ttps: ttpsByActor[a.id] ?? [],
  }));

  return {
    generatedAt: new Date().toISOString(),
    reportType: "actor",
    overview: {
      total: actors.length,
      active: actors.filter(a => a.isActive).length,
      byCountry: groupBy(actors, a => a.country ?? "Unknown"),
      byMotivation: groupBy(actors, a => a.motivation ?? "Unknown"),
      activeCampaigns: campaigns.filter(c => c.status === "active").length,
    },
    actors: enrichedActors,
    campaigns,
    malware,
  };
}

async function buildVulnerabilityReport(tenantId: number): Promise<any> {
  const [cves, findings] = await Promise.all([
    loadCves(200),
    loadFindings(tenantId, 200),
  ]);

  const kevCves = cves.filter(c => c.isKev);
  const criticalCves = cves.filter(c => c.severity === "critical");
  const highEpss = cves.filter(c => (c.epss ?? 0) >= 0.5);

  return {
    generatedAt: new Date().toISOString(),
    reportType: "vulnerability",
    overview: {
      totalCves: cves.length,
      kevCount: kevCves.length,
      criticalCount: criticalCves.length,
      highEpssCount: highEpss.length,
      exploitableCount: cves.filter(c => c.exploitationStatus !== "unknown" && c.exploitationStatus !== "theoretical").length,
      pocPublicCount: cves.filter(c => c.pocPublic).length,
      bySeverity: countBySeverity(cves, c => c.severity ?? "medium"),
      openFindings: findings.filter(f => f.status === "open").length,
      findingsBySeverity: countBySeverity(findings, f => f.severity),
    },
    kevCves,
    criticalCves: criticalCves.slice(0, 50),
    highEpssCves: highEpss.slice(0, 30),
    allCves: cves,
    findings: findings.filter(f => f.status === "open").slice(0, 100),
    closedFindings: findings.filter(f => f.status !== "open").slice(0, 50),
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function countBySeverity<T>(items: T[], getSev: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const item of items) {
    const s = getSev(item).toLowerCase();
    counts[s] = (counts[s] ?? 0) + 1;
  }
  return counts;
}

function groupBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const result: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    result[k] = (result[k] ?? 0) + 1;
  }
  return result;
}

function computeRiskScore(data: {
  iocs: any[];
  cves: any[];
  darkWeb: any[];
  findings: any[];
}): number {
  let score = 0;
  const critIocs = data.iocs.filter(i => i.severity === "critical").length;
  const highIocs = data.iocs.filter(i => i.severity === "high").length;
  score += Math.min(25, critIocs * 5 + highIocs * 2);

  const kevCount = data.cves.filter(c => c.isKev).length;
  const critCves = data.cves.filter(c => c.severity === "critical").length;
  score += Math.min(25, kevCount * 5 + critCves * 3);

  const critDw = data.darkWeb.filter(d => d.severity === "critical").length;
  const highDw = data.darkWeb.filter(d => d.severity === "high").length;
  score += Math.min(25, critDw * 5 + highDw * 2);

  const critFindings = data.findings.filter(f => f.severity === "critical" && f.status === "open").length;
  const highFindings = data.findings.filter(f => f.severity === "high" && f.status === "open").length;
  score += Math.min(25, critFindings * 5 + highFindings * 2);

  return Math.min(100, score);
}

// ── Main generator ────────────────────────────────────────────────────────────

export async function generateReport(reportId: number, tenantId: number, reportType: string): Promise<void> {
  logger.info(`[ti-report] Generating report ${reportId} (type: ${reportType}, tenant: ${tenantId})`);

  try {
    let data: any;
    switch (reportType) {
      case "ioc":           data = await buildIocReport(tenantId); break;
      case "actor":         data = await buildActorReport(tenantId); break;
      case "vulnerability": data = await buildVulnerabilityReport(tenantId); break;
      case "summary":
      case "custom":
      default:              data = await buildSummaryReport(tenantId); break;
    }

    const metadata = {
      completedAt: new Date().toISOString(),
      reportType,
      tenantId,
      stats: data.overview ?? {},
      riskScore: data.riskScore ?? null,
    };

    await db.update(tiReportsTable)
      .set({
        status: "ready",
        content: JSON.stringify(data),
        metadata,
        completedAt: new Date(),
      })
      .where(eq(tiReportsTable.id, reportId));

    logger.info(`[ti-report] Report ${reportId} completed successfully`);
  } catch (err: any) {
    logger.error({ err: err.message }, `[ti-report] Report ${reportId} generation failed`);
    await db.update(tiReportsTable)
      .set({
        status: "failed",
        metadata: { error: err.message, failedAt: new Date().toISOString() },
        completedAt: new Date(),
      })
      .where(eq(tiReportsTable.id, reportId));
  }
}
