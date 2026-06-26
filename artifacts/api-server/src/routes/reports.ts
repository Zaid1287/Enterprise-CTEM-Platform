import { Router } from "express";
import { eq, and, desc, inArray } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import {
  db, reportsTable, findingsTable, assetsTable, complianceControlsTable,
  complianceFrameworksTable, brandThreatScansTable, brandThreatResultsTable,
  dataLeakResultsTable, phishingDetectionsTable, brandAbuseResultsTable,
  riskScoresTable, technologyDetectionsTable,
} from "@workspace/db";
import { CreateReportBody, GetReportParams, DeleteReportParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toReportResponse(r: typeof reportsTable.$inferSelect) {
  return {
    id: r.id, tenantId: r.tenantId, title: r.title, type: r.type, format: r.format,
    status: r.status, downloadUrl: r.downloadUrl,
    generatedAt: r.generatedAt?.toISOString() ?? null,
    createdAt: r.createdAt.toISOString(),
  };
}

function csvEscape(v: unknown): string {
  const s = v == null ? "" : String(v);
  if (s.includes(",") || s.includes('"') || s.includes("\n")) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function toCsv(headers: string[], rows: unknown[][]): string {
  const lines = [headers.join(",")];
  for (const row of rows) lines.push(row.map(csvEscape).join(","));
  return lines.join("\n");
}

router.get("/reports", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const role = req.user!.role;

  // Client: only show reports that include at least one asset assigned to them
  if (role === "client") {
    const assignedAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = new Set(assignedAssets.map(a => a.id));
    if (assignedIds.size === 0) { res.json([]); return; }
    const allReports = await db.select().from(reportsTable)
      .where(eq(reportsTable.tenantId, req.user!.tenantId));
    const clientReports = allReports.filter(r =>
      Array.isArray(r.assetIds) && (r.assetIds as number[]).some(id => assignedIds.has(id))
    );
    res.json(clientReports.map(toReportResponse)); return;
  }

  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    const clientAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(inArray(assetsTable.tenantId, ids));
    const clientAssetIds = new Set(clientAssets.map(a => a.id));
    if (clientAssetIds.size === 0) { res.json([]); return; }
    const allReports = await db.select().from(reportsTable);
    const amReports = allReports.filter(r =>
      Array.isArray(r.assetIds) && (r.assetIds as number[]).some(id => clientAssetIds.has(id))
    );
    res.json(amReports.map(toReportResponse)); return;
  }
  const rWhere = eq(reportsTable.tenantId, req.user!.tenantId);
  const reports = await db.select().from(reportsTable).where(rWhere);
  res.json(reports.map(toReportResponse));
});

router.post("/reports", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateReportBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [report] = await db.insert(reportsTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, status: "pending",
  }).returning();
  setTimeout(async () => {
    await db.update(reportsTable).set({
      status: "ready",
      generatedAt: new Date(),
      downloadUrl: `/api/reports/${report.id}/download`,
    }).where(eq(reportsTable.id, report.id));
  }, 2000);
  await logAudit(req.user!, "create_report", "report", report.id);
  res.status(201).json(toReportResponse(report));
});

// ── PDF data: asset ──────────────────────────────────────────────────────────
router.get("/reports/pdf-data/asset/:assetId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const assetId  = parseInt(req.params.assetId, 10);
  if (isNaN(assetId)) { res.status(400).json({ error: "Invalid assetId" }); return; }
  const tenantId = req.user!.tenantId;

  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const [findings, technologies, riskRows] = await Promise.all([
    db.select().from(findingsTable)
      .where(and(eq(findingsTable.assetId, assetId), eq(findingsTable.tenantId, tenantId)))
      .orderBy(
        desc(findingsTable.severity === "critical" ? findingsTable.id : findingsTable.id),
      ),
    db.select().from(technologyDetectionsTable)
      .where(eq(technologyDetectionsTable.assetId, assetId)),
    db.select().from(riskScoresTable)
      .where(eq(riskScoresTable.assetId, assetId))
      .limit(1),
  ]);

  const riskScore = riskRows[0] ?? null;

  // Sort findings by severity weight
  const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (sevWeight[b.severity] ?? 0) - (sevWeight[a.severity] ?? 0));

  const findingCounts = {
    total:    findings.length,
    open:     findings.filter(f => f.status === "open").length,
    critical: findings.filter(f => f.severity === "critical").length,
    high:     findings.filter(f => f.severity === "high").length,
    medium:   findings.filter(f => f.severity === "medium").length,
    low:      findings.filter(f => f.severity === "low").length,
  };

  res.json({
    asset: {
      id:                 asset.id,
      name:               asset.name,
      type:               asset.type,
      value:              asset.value,
      ipAddress:          asset.ipAddress ?? null,
      port:               asset.port ?? null,
      riskLevel:          asset.riskLevel,
      verificationStatus: asset.verificationStatus,
      lastScannedAt:      asset.lastScannedAt?.toISOString() ?? null,
      createdAt:          asset.createdAt.toISOString(),
    },
    riskScore: riskScore
      ? { score: riskScore.score, level: riskScore.level }
      : null,
    findings: findings.map(f => ({
      id:          f.id,
      title:       f.title,
      severity:    f.severity,
      status:      f.status,
      cve:         f.cve ?? null,
      cvss:        f.cvss ?? null,
      cwe:         f.cwe ?? null,
      description: f.description ?? null,
      remediation: f.remediation ?? null,
      createdAt:   f.createdAt.toISOString(),
    })),
    technologies: technologies.map(t => ({
      id:         t.id,
      technology: t.technology,
      version:    t.version ?? null,
      confidence: t.confidence ?? null,
      category:   t.category ?? null,
    })),
    findingCounts,
    generatedAt: new Date().toISOString(),
  });
});

// ── PDF data: brand threat ────────────────────────────────────────────────────
router.get("/reports/pdf-data/brand-threat/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scanId   = parseInt(req.params.scanId, 10);
  if (isNaN(scanId)) { res.status(400).json({ error: "Invalid scanId" }); return; }
  const tenantId = req.user!.tenantId;

  const [scan] = await db.select().from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, scanId), eq(brandThreatScansTable.tenantId, tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const [allResults, dataLeaks, phishingDetections, brandAbuse] = await Promise.all([
    db.select().from(brandThreatResultsTable)
      .where(eq(brandThreatResultsTable.scanId, scanId))
      .orderBy(desc(brandThreatResultsTable.riskScore))
      .limit(200),
    db.select().from(dataLeakResultsTable)
      .where(eq(dataLeakResultsTable.scanId, scanId))
      .orderBy(desc(dataLeakResultsTable.createdAt))
      .limit(50),
    db.select().from(phishingDetectionsTable)
      .where(eq(phishingDetectionsTable.scanId, scanId))
      .orderBy(desc(phishingDetectionsTable.createdAt))
      .limit(50),
    db.select().from(brandAbuseResultsTable)
      .where(eq(brandAbuseResultsTable.scanId, scanId))
      .orderBy(desc(brandAbuseResultsTable.createdAt))
      .limit(50),
  ]);

  const liveResults = allResults.filter(r => r.dnsA && r.dnsA.length > 0);
  const topResults  = allResults.slice(0, 100);

  res.json({
    scan: {
      id:                scan.id,
      domain:            scan.domain,
      status:            scan.status,
      totalPermutations: scan.totalPermutations,
      liveCount:         scan.liveCount,
      registeredCount:   scan.registeredCount,
      phishingRisk:      scan.phishingRisk,
      dataLeakCount:     scan.dataLeakCount ?? 0,
      phishingCount:     scan.phishingCount ?? 0,
      brandAbuseCount:   scan.brandAbuseCount ?? 0,
      darkWebCount:      scan.darkWebCount ?? 0,
      fuzzerBreakdown:   scan.fuzzerBreakdown ?? null,
      faviconUrl:        scan.faviconUrl ?? null,
      faviconMmh3:       scan.faviconMmh3 ?? null,
      faviconMd5:        scan.faviconMd5 ?? null,
      faviconSha256:     scan.faviconSha256 ?? null,
      faviconSearchUrls: scan.faviconSearchUrls ?? null,
      favihunterStatus:  scan.favihunterStatus ?? null,
      createdAt:         scan.createdAt.toISOString(),
      completedAt:       scan.completedAt?.toISOString() ?? null,
    },
    // Pillar 1: Typosquatting — top domains by risk
    topResults: topResults.map(r => ({
      permutation:      r.permutation,
      fuzzer:           r.fuzzer,
      dnsA:             r.dnsA ?? null,
      dnsMx:            r.dnsMx ?? null,
      dnsNs:            r.dnsNs ?? null,
      mxSpf:            r.mxSpf ?? null,
      riskScore:        r.riskScore,
      isSuspicious:     r.isSuspicious,
      whoisRegistrar:   r.whoisRegistrar ?? null,
      whoisCreated:     r.whoisCreated ?? null,
      whoisAgeDays:     r.whoisAgeDays ?? null,
      geoCountry:       r.geoCountry ?? null,
      vtMalicious:      r.vtMalicious ?? null,
      isPhishing:       r.isPhishing ?? false,
      phishingSource:   r.phishingSource ?? null,
      registrationStatus: r.registrationStatus ?? null,
    })),
    liveResults: liveResults.slice(0, 100).map(r => ({
      permutation:      r.permutation,
      fuzzer:           r.fuzzer,
      dnsA:             r.dnsA ?? null,
      dnsMx:            r.dnsMx ?? null,
      dnsNs:            r.dnsNs ?? null,
      mxSpf:            r.mxSpf ?? null,
      riskScore:        r.riskScore,
      isSuspicious:     r.isSuspicious,
      whoisRegistrar:   r.whoisRegistrar ?? null,
      whoisCreated:     r.whoisCreated ?? null,
      whoisAgeDays:     r.whoisAgeDays ?? null,
      geoCountry:       r.geoCountry ?? null,
      vtMalicious:      r.vtMalicious ?? null,
      isPhishing:       r.isPhishing ?? false,
      phishingSource:   r.phishingSource ?? null,
      registrationStatus: r.registrationStatus ?? null,
    })),
    // Pillar 2: Data Leak / HIBP
    dataLeaks: dataLeaks.map(d => ({
      id:           d.id,
      source:       d.source,
      title:        d.title,
      breachDate:   d.breachDate ?? null,
      description:  d.description ?? null,
      exposedData:  d.exposedData ?? null,
      domainMatch:  d.domainMatch ?? null,
      emailMatch:   d.emailMatch ?? null,
      severity:     d.severity,
      url:          d.url ?? null,
    })),
    // Pillar 3: Phishing Detections (PhishTank / OpenPhish / GSB)
    phishingDetections: phishingDetections.map(p => ({
      id:           p.id,
      url:          p.url,
      source:       p.source,
      threatType:   p.threatType ?? null,
      verified:     p.verified,
      targetBrand:  p.targetBrand ?? null,
      submittedAt:  p.submittedAt ?? null,
    })),
    // Pillar 4: Brand Abuse (CT certs, app store, social, lookalike domains)
    brandAbuse: brandAbuse.map(b => ({
      id:              b.id,
      type:            b.type,
      platform:        b.platform ?? null,
      url:             b.url ?? null,
      title:           b.title ?? null,
      description:     b.description ?? null,
      evidenceSnippet: b.evidenceSnippet ?? null,
      risk:            b.risk,
    })),
    generatedAt: new Date().toISOString(),
  });
});

// ── PDF data: report (all assets + findings) ─────────────────────────────────
router.get("/reports/pdf-data/report/:reportId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const reportId = parseInt(req.params.reportId, 10);
  if (isNaN(reportId)) { res.status(400).json({ error: "Invalid reportId" }); return; }
  const tenantId = req.user!.tenantId;

  const [report] = await db.select().from(reportsTable)
    .where(and(eq(reportsTable.id, reportId), eq(reportsTable.tenantId, tenantId)));
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }

  const assets = await db.select().from(assetsTable).where(eq(assetsTable.tenantId, tenantId));
  const assetIds = assets.map(a => a.id);
  const assetDomains = assets.map(a => a.value).filter(Boolean);

  const [allFindings, riskRows, brandScans] = await Promise.all([
    db.select().from(findingsTable)
      .where(eq(findingsTable.tenantId, tenantId))
      .orderBy(desc(findingsTable.id)),
    assetIds.length > 0
      ? db.select().from(riskScoresTable).where(inArray(riskScoresTable.assetId, assetIds))
      : Promise.resolve([]),
    assetDomains.length > 0
      ? db.select().from(brandThreatScansTable)
          .where(and(eq(brandThreatScansTable.tenantId, tenantId), inArray(brandThreatScansTable.domain, assetDomains)))
          .orderBy(desc(brandThreatScansTable.id))
          .limit(30)
      : Promise.resolve([]),
  ]);

  const brandScanIds = brandScans.map(s => s.id);
  const brandResults = brandScanIds.length > 0
    ? await db.select({
        scanId:       brandThreatResultsTable.scanId,
        permutation:  brandThreatResultsTable.permutation,
        fuzzer:       brandThreatResultsTable.fuzzer,
        dnsA:         brandThreatResultsTable.dnsA,
        riskScore:    brandThreatResultsTable.riskScore,
        isSuspicious: brandThreatResultsTable.isSuspicious,
        geoCountry:   brandThreatResultsTable.geoCountry,
        vtMalicious:  brandThreatResultsTable.vtMalicious,
        whoisRegistrar: brandThreatResultsTable.whoisRegistrar,
        whoisCreated:   brandThreatResultsTable.whoisCreated,
      }).from(brandThreatResultsTable)
        .where(inArray(brandThreatResultsTable.scanId, brandScanIds))
        .orderBy(desc(brandThreatResultsTable.riskScore))
        .limit(300)
    : [];

  const assetMap: Record<number, typeof assets[0]> = Object.fromEntries(assets.map(a => [a.id, a]));

  const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  allFindings.sort((a, b) => (sevWeight[b.severity] ?? 0) - (sevWeight[a.severity] ?? 0));

  const findingCounts = {
    total:    allFindings.length,
    open:     allFindings.filter(f => f.status === "open").length,
    critical: allFindings.filter(f => f.severity === "critical").length,
    high:     allFindings.filter(f => f.severity === "high").length,
    medium:   allFindings.filter(f => f.severity === "medium").length,
    low:      allFindings.filter(f => f.severity === "low").length,
  };

  res.json({
    report: toReportResponse(report),
    assets: assets.map(a => ({
      id:             a.id,
      name:           a.name,
      type:           a.type,
      value:          a.value,
      riskLevel:      a.riskLevel,
      ipAddress:      a.ipAddress ?? null,
      lastScannedAt:  a.lastScannedAt?.toISOString() ?? null,
    })),
    findings: allFindings.map(f => ({
      id:          f.id,
      title:       f.title,
      severity:    f.severity,
      status:      f.status,
      cve:         f.cve ?? null,
      cvss:        f.cvss ?? null,
      cwe:         f.cwe ?? null,
      description: f.description ?? null,
      remediation: f.remediation ?? null,
      assetId:     f.assetId ?? 0,
      assetName:   f.assetId ? (assetMap[f.assetId]?.name ?? "Unknown") : "Unknown",
    })),
    riskScores: riskRows.map(r => ({
      assetId: r.assetId,
      score:   r.score,
      level:   r.level,
    })),
    brandScans: brandScans.map(s => ({
      id:                s.id,
      domain:            s.domain,
      status:            s.status,
      totalPermutations: s.totalPermutations,
      liveCount:         s.liveCount,
      registeredCount:   s.registeredCount,
      phishingRisk:      s.phishingRisk,
      dataLeakCount:     s.dataLeakCount ?? 0,
      phishingCount:     s.phishingCount ?? 0,
      brandAbuseCount:   s.brandAbuseCount ?? 0,
      completedAt:       s.completedAt?.toISOString() ?? null,
    })),
    brandResults: brandResults.map(r => ({
      scanId:         r.scanId,
      permutation:    r.permutation,
      fuzzer:         r.fuzzer,
      dnsA:           r.dnsA ?? [],
      riskScore:      r.riskScore,
      isSuspicious:   r.isSuspicious,
      geoCountry:     r.geoCountry ?? null,
      vtMalicious:    r.vtMalicious ?? null,
      whoisRegistrar: r.whoisRegistrar ?? null,
      whoisCreated:   r.whoisCreated ?? null,
    })),
    findingCounts,
    generatedAt: new Date().toISOString(),
  });
});

// ── PDF data: selected assets (findings + brand threats) ─────────────────────
router.get("/reports/pdf-data/assets", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const raw = String(req.query.ids ?? "");
  const requestedIds = raw.split(",").map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
  if (requestedIds.length === 0) { res.status(400).json({ error: "No asset IDs provided" }); return; }

  const assets = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.tenantId, tenantId), inArray(assetsTable.id, requestedIds)));
  if (assets.length === 0) { res.status(404).json({ error: "No assets found" }); return; }

  const assetIds   = assets.map(a => a.id);
  const assetDomains = assets.map(a => a.value).filter(Boolean);

  const [findings, riskRows, brandScans] = await Promise.all([
    db.select().from(findingsTable)
      .where(and(eq(findingsTable.tenantId, tenantId), inArray(findingsTable.assetId, assetIds)))
      .orderBy(desc(findingsTable.id)),
    db.select().from(riskScoresTable).where(inArray(riskScoresTable.assetId, assetIds)),
    assetDomains.length > 0
      ? db.select().from(brandThreatScansTable)
          .where(and(eq(brandThreatScansTable.tenantId, tenantId), inArray(brandThreatScansTable.domain, assetDomains)))
          .orderBy(desc(brandThreatScansTable.id))
      : Promise.resolve([]),
  ]);

  const brandScanIds = brandScans.map(s => s.id);
  const brandResults = brandScanIds.length > 0
    ? await db.select().from(brandThreatResultsTable)
        .where(inArray(brandThreatResultsTable.scanId, brandScanIds))
        .orderBy(desc(brandThreatResultsTable.riskScore))
    : [];

  const assetMap: Record<number, typeof assets[0]> = Object.fromEntries(assets.map(a => [a.id, a]));
  const riskMap:  Record<number, { score: number; level: string }> = Object.fromEntries(riskRows.map(r => [r.assetId, r]));

  const sevWeight: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (sevWeight[b.severity] ?? 0) - (sevWeight[a.severity] ?? 0));

  res.json({
    assets: assets.map(a => ({
      id:            a.id,
      name:          a.name,
      type:          a.type,
      value:         a.value,
      riskLevel:     a.riskLevel,
      ipAddress:     a.ipAddress ?? null,
      lastScannedAt: a.lastScannedAt?.toISOString() ?? null,
      riskScore:     riskMap[a.id]?.score ?? null,
      riskScoreLevel: riskMap[a.id]?.level ?? null,
    })),
    findings: findings.map(f => ({
      id:          f.id,
      title:       f.title,
      severity:    f.severity,
      status:      f.status,
      cve:         f.cve ?? null,
      cvss:        f.cvss ?? null,
      description: f.description ?? null,
      remediation: f.remediation ?? null,
      assetId:     f.assetId ?? 0,
      assetName:   f.assetId ? (assetMap[f.assetId]?.name ?? "Unknown") : "Unknown",
    })),
    brandScans: brandScans.map(s => ({
      id:                 s.id,
      domain:             s.domain,
      status:             s.status,
      totalPermutations:  s.totalPermutations,
      liveCount:          s.liveCount,
      registeredCount:    s.registeredCount,
      phishingRisk:       s.phishingRisk,
      completedAt:        s.completedAt?.toISOString() ?? null,
    })),
    brandResults: brandResults.map(r => ({
      id:             r.id,
      scanId:         r.scanId,
      permutation:    r.permutation,
      fuzzer:         r.fuzzer,
      dnsA:           r.dnsA ?? [],
      dnsMx:          r.dnsMx ?? [],
      mxSpf:          r.mxSpf ?? null,
      whoisRegistrar: r.whoisRegistrar ?? null,
      whoisCreated:   r.whoisCreated ?? null,
      whoisCountry:   r.whoisCountry ?? null,
      riskScore:      r.riskScore,
      isSuspicious:   r.isSuspicious,
    })),
  });
});

router.get("/reports/:reportId/download", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const reportId = parseInt(req.params.reportId, 10);
  if (isNaN(reportId)) { res.status(400).json({ error: "Invalid reportId" }); return; }

  const [report] = await db.select().from(reportsTable)
    .where(and(eq(reportsTable.id, reportId), eq(reportsTable.tenantId, req.user!.tenantId)));
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }
  if (report.status !== "ready") { res.status(409).json({ error: "Report is not ready yet" }); return; }

  const tenantId = req.user!.tenantId;
  const fmt = report.format ?? "csv";
  const safeName = report.title.replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");

  let csvContent = "";
  let jsonData: object = {};

  if (report.type === "technical" || report.type === "executive") {
    const findings = await db.select({
      id: findingsTable.id,
      title: findingsTable.title,
      severity: findingsTable.severity,
      status: findingsTable.status,
      cve: findingsTable.cve,
      cvss: findingsTable.cvss,
      cwe: findingsTable.cwe,
      description: findingsTable.description,
      remediation: findingsTable.remediation,
      assetId: findingsTable.assetId,
      createdAt: findingsTable.createdAt,
    }).from(findingsTable).where(eq(findingsTable.tenantId, tenantId));

    const assets = await db.select({ id: assetsTable.id, name: assetsTable.name, value: assetsTable.value, type: assetsTable.type, riskLevel: assetsTable.riskLevel })
      .from(assetsTable).where(eq(assetsTable.tenantId, tenantId));
    const assetMap = Object.fromEntries(assets.map(a => [a.id, a]));

    if (fmt === "json") {
      jsonData = { report: toReportResponse(report), findings: findings.map(f => ({ ...f, asset: assetMap[f.assetId ?? 0] ?? null })), generatedAt: new Date().toISOString() };
    } else {
      const headers = ["ID", "Title", "Severity", "Status", "CVE", "CVSS", "CWE", "Asset Name", "Asset Value", "Asset Type", "Risk Level", "Description", "Remediation", "Created At"];
      const rows = findings.map(f => {
        const a = assetMap[f.assetId ?? 0];
        return [f.id, f.title, f.severity, f.status, f.cve ?? "", f.cvss ?? "", f.cwe ?? "", a?.name ?? "", a?.value ?? "", a?.type ?? "", a?.riskLevel ?? "", f.description ?? "", f.remediation ?? "", f.createdAt.toISOString()];
      });
      csvContent = toCsv(headers, rows);
    }
  } else if (report.type === "compliance") {
    const rows = await db.select({
      control: complianceControlsTable,
      frameworkName: complianceFrameworksTable.name,
    }).from(complianceControlsTable)
      .leftJoin(complianceFrameworksTable, eq(complianceControlsTable.frameworkId, complianceFrameworksTable.id))
      .where(eq(complianceControlsTable.tenantId, tenantId));

    if (fmt === "json") {
      jsonData = { report: toReportResponse(report), controls: rows.map(r => ({ ...r.control, frameworkName: r.frameworkName })), generatedAt: new Date().toISOString() };
    } else {
      const headers = ["ID", "Framework", "Control ID", "Title", "Status", "Assigned To", "Due Date", "Has Evidence", "Description"];
      const csvRows = rows.map(({ control: c, frameworkName }) => {
        let hasEvidence = false;
        try { hasEvidence = !!c.evidence && JSON.parse(c.evidence).length > 0; } catch { hasEvidence = !!c.evidence; }
        return [c.id, frameworkName ?? "", c.controlId, c.title, c.status, c.assignedTo ?? "", c.dueDate ?? "", hasEvidence ? "Yes" : "No", c.description ?? ""];
      });
      csvContent = toCsv(headers, csvRows);
    }
  } else {
    const assets = await db.select({
      id: assetsTable.id,
      name: assetsTable.name,
      type: assetsTable.type,
      value: assetsTable.value,
      verificationStatus: assetsTable.verificationStatus,
      riskLevel: assetsTable.riskLevel,
      ipAddress: assetsTable.ipAddress,
      lastScannedAt: assetsTable.lastScannedAt,
      createdAt: assetsTable.createdAt,
    }).from(assetsTable)
      .where(eq(assetsTable.tenantId, tenantId));

    if (fmt === "json") {
      jsonData = { report: toReportResponse(report), assets, generatedAt: new Date().toISOString() };
    } else {
      const headers = ["ID", "Name", "Type", "Value", "Verification Status", "Risk Level", "IP Address", "Last Scanned", "Created At"];
      const csvRows = assets.map(a => [a.id, a.name ?? "", a.type, a.value, a.verificationStatus, a.riskLevel, a.ipAddress ?? "", a.lastScannedAt?.toISOString() ?? "", a.createdAt.toISOString()]);
      csvContent = toCsv(headers, csvRows);
    }
  }

  if (fmt === "json") {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}.json"`);
    res.json(jsonData);
  } else {
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="${safeName}.csv"`);
    res.send(csvContent);
  }
});

router.get("/reports/:reportId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetReportParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [report] = await db.select().from(reportsTable)
    .where(and(eq(reportsTable.id, params.data.reportId), eq(reportsTable.tenantId, req.user!.tenantId)));
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }
  res.json(toReportResponse(report));
});

router.delete("/reports/:reportId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteReportParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [report] = await db.delete(reportsTable)
    .where(and(eq(reportsTable.id, params.data.reportId), eq(reportsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!report) { res.status(404).json({ error: "Report not found" }); return; }
  await logAudit(req.user!, "delete_report", "report", report.id);
  res.sendStatus(204);
});

export default router;
