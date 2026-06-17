import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import { db, reportsTable, findingsTable, assetsTable, complianceControlsTable, complianceFrameworksTable } from "@workspace/db";
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
    }).from(findingsTable).where(eq(findingsTable.tenantId, tenantId))
      .orderBy(desc(findingsTable.createdAt));

    const assets = await db.select({ id: assetsTable.id, name: assetsTable.name, value: assetsTable.value, type: assetsTable.type, riskScore: assetsTable.riskScore })
      .from(assetsTable).where(eq(assetsTable.tenantId, tenantId));
    const assetMap = Object.fromEntries(assets.map(a => [a.id, a]));

    if (fmt === "json") {
      jsonData = { report: toReportResponse(report), findings: findings.map(f => ({ ...f, asset: assetMap[f.assetId ?? 0] ?? null })), generatedAt: new Date().toISOString() };
    } else {
      const headers = ["ID", "Title", "Severity", "Status", "CVE", "CVSS", "CWE", "Asset Name", "Asset Value", "Asset Type", "Risk Score", "Description", "Remediation", "Created At"];
      const rows = findings.map(f => {
        const a = assetMap[f.assetId ?? 0];
        return [f.id, f.title, f.severity, f.status, f.cve ?? "", f.cvss ?? "", f.cwe ?? "", a?.name ?? "", a?.value ?? "", a?.type ?? "", a?.riskScore ?? "", f.description ?? "", f.remediation ?? "", f.createdAt.toISOString()];
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
    const assets = await db.select().from(assetsTable)
      .where(eq(assetsTable.tenantId, tenantId))
      .orderBy(desc(assetsTable.createdAt));

    if (fmt === "json") {
      jsonData = { report: toReportResponse(report), assets, generatedAt: new Date().toISOString() };
    } else {
      const headers = ["ID", "Name", "Type", "Value", "Status", "Risk Score", "IP Address", "Last Scanned", "Created At"];
      const csvRows = assets.map(a => [a.id, a.name ?? "", a.type, a.value, a.status, a.riskScore ?? "", a.ipAddress ?? "", a.lastScannedAt?.toISOString() ?? "", a.createdAt.toISOString()]);
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
