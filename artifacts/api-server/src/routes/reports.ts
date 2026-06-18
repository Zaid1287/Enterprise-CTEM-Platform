import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import {
  db, reportsTable, findingsTable, assetsTable, complianceControlsTable,
  complianceFrameworksTable, brandThreatScansTable, brandThreatResultsTable,
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
  const reports = await db.select().from(reportsTable)
    .where(eq(reportsTable.tenantId, req.user!.tenantId));
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

  const allResults = await db.select().from(brandThreatResultsTable)
    .where(eq(brandThreatResultsTable.scanId, scanId))
    .orderBy(desc(brandThreatResultsTable.riskScore))
    .limit(200);

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
    topResults: topResults.map(r => ({
      permutation:   r.permutation,
      fuzzer:        r.fuzzer,
      dnsA:          r.dnsA ?? null,
      dnsMx:         r.dnsMx ?? null,
      mxSpf:         r.mxSpf ?? null,
      riskScore:     r.riskScore,
      isSuspicious:  r.isSuspicious,
    })),
    liveResults: liveResults.slice(0, 100).map(r => ({
      permutation:   r.permutation,
      fuzzer:        r.fuzzer,
      dnsA:          r.dnsA ?? null,
      dnsMx:         r.dnsMx ?? null,
      mxSpf:         r.mxSpf ?? null,
      riskScore:     r.riskScore,
      isSuspicious:  r.isSuspicious,
    })),
    generatedAt: new Date().toISOString(),
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
