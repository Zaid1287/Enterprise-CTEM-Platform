import { Router } from "express";
import { eq, and, ilike, inArray, desc } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { db, findingsTable, findingCommentsTable, assetsTable, usersTable, scanAssetResultsTable, riskScoresTable } from "@workspace/db";
import {
  GetFindingParams, UpdateFindingParams, UpdateFindingBody,
  ListFindingsQueryParams, ListFindingCommentsParams,
  CreateFindingCommentParams, CreateFindingCommentBody,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toFindingResponse(
  f: typeof findingsTable.$inferSelect,
  assetName?: string | null,
  assetValue?: string | null,
  assetType?: string | null,
  assetLastScannedAt?: Date | null,
  assetIpAddress?: string | null,
  assetPort?: number | null,
  assetTags?: string[] | null,
  assetRiskScore?: number | null,
) {
  const SEV_RISK: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 10 };
  const riskScore = assetRiskScore ?? f.riskScore ?? SEV_RISK[f.severity ?? "medium"] ?? 45;
  return {
    id: f.id, tenantId: f.tenantId, assetId: f.assetId,
    assetName: assetName ?? null,
    assetValue: assetValue ?? null,
    assetType: assetType ?? null,
    assetLastScannedAt: assetLastScannedAt ? assetLastScannedAt.toISOString() : null,
    assetIpAddress: assetIpAddress ?? null,
    assetPort: assetPort ?? null,
    assetTags: assetTags ?? [],
    title: f.title, description: f.description, severity: f.severity, status: f.status,
    cve: f.cve, cvss: f.cvss, epss: f.epss, cwe: f.cwe, isKev: f.isKev,
    remediation: f.remediation, evidence: f.evidence, riskScore,
    createdAt: f.createdAt.toISOString(), updatedAt: f.updatedAt.toISOString(),
  };
}

router.get("/findings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListFindingsQueryParams.safeParse(req.query);
  const role = req.user!.role;
  let tenantFilter;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    tenantFilter = inArray(findingsTable.tenantId, ids);
  } else {
    tenantFilter = eq(findingsTable.tenantId, req.user!.tenantId);
  }
  const filters = [tenantFilter];

  if (role === "client") {
    // Cross-tenant: fetch assigned asset IDs without tenant restriction
    const assignedAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = assignedAssets.map(a => a.id);
    if (assignedIds.length === 0) { res.json([]); return; }
    // Replace the tenant filter with an asset-scoped filter (findings span tenants via assets)
    filters.length = 0;
    filters.push(inArray(findingsTable.assetId, assignedIds));
  }

  if (q.success) {
    if (q.data.status) filters.push(eq(findingsTable.status, q.data.status));
    if (q.data.severity) filters.push(eq(findingsTable.severity, q.data.severity));
    if (q.data.assetId) filters.push(eq(findingsTable.assetId, q.data.assetId));
    if (q.data.search) filters.push(ilike(findingsTable.title, `%${q.data.search}%`));
  }
  const findings = await db.select({
    finding: findingsTable,
    assetName: assetsTable.name,
    assetValue: assetsTable.value,
    assetType: assetsTable.type,
    assetLastScannedAt: assetsTable.lastScannedAt,
    assetIpAddress: assetsTable.ipAddress,
    assetPort: assetsTable.port,
    assetTags: assetsTable.tags,
    assetRiskScore: riskScoresTable.score,
  }).from(findingsTable)
    .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
    .leftJoin(riskScoresTable, eq(findingsTable.assetId, riskScoresTable.assetId))
    .where(and(...filters));
  res.json(findings.map(({ finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore }) =>
    toFindingResponse(finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore)));
});

router.get("/findings/:findingId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [row] = await db.select({
    finding: findingsTable,
    assetName: assetsTable.name,
    assetValue: assetsTable.value,
    assetType: assetsTable.type,
    assetLastScannedAt: assetsTable.lastScannedAt,
    assetIpAddress: assetsTable.ipAddress,
    assetPort: assetsTable.port,
    assetTags: assetsTable.tags,
    assetRiskScore: riskScoresTable.score,
  }).from(findingsTable)
    .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
    .leftJoin(riskScoresTable, eq(findingsTable.assetId, riskScoresTable.assetId))
    .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
  if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
  res.json(toFindingResponse(row.finding, row.assetName, row.assetValue, row.assetType, row.assetLastScannedAt, row.assetIpAddress, row.assetPort, row.assetTags, row.assetRiskScore));
});

// ── GET /findings/:findingId/scan-data ─────────────────────────────────────
// Returns aggregated ports, httpInfo, intelligence, vulnerabilities from the
// most recent scan that covered this finding's asset.
router.get("/findings/:findingId/scan-data", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  const [finding] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
    .from(findingsTable)
    .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  // Get the most recent scan asset results for this asset
  const scanResults = await db.select().from(scanAssetResultsTable)
    .where(and(
      eq(scanAssetResultsTable.assetId, finding.assetId),
      eq(scanAssetResultsTable.tenantId, req.user!.tenantId),
    ))
    .orderBy(desc(scanAssetResultsTable.createdAt));

  if (scanResults.length === 0) {
    res.json({ assetId: finding.assetId, ports: [], httpInfo: null, intelligence: [], subdomains: [], vulnerabilities: [] });
    return;
  }

  // Aggregate all results across tool runs
  const allPorts: unknown[] = [];
  const allVulns: unknown[] = [];
  const allSubdomains: unknown[] = [];
  const allDns: unknown[] = [];
  const allIntel: unknown[] = [];
  let httpInfo: unknown = null;

  for (const r of scanResults) {
    if (r.ports)        allPorts.push(...(r.ports as unknown[]));
    if (r.vulnerabilities) allVulns.push(...(r.vulnerabilities as unknown[]));
    if (r.subdomains)   allSubdomains.push(...(r.subdomains as unknown[]));
    if (r.dnsRecords)   allDns.push(...(r.dnsRecords as unknown[]));
    if (r.intelligence) allIntel.push(...(r.intelligence as unknown[]));
    if (r.httpInfo && !httpInfo) httpInfo = r.httpInfo;
  }

  function dedup<T extends Record<string, unknown>>(arr: T[], key: string): T[] {
    const seen = new Set<string>();
    return arr.filter(i => {
      const k = String(i[key] ?? JSON.stringify(i));
      return seen.has(k) ? false : (seen.add(k), true);
    });
  }

  const ports = dedup(allPorts as Record<string, unknown>[], "port");
  const vulns = dedup(allVulns as Record<string, unknown>[], "cve");
  const subs  = dedup(allSubdomains as Record<string, unknown>[], "name");
  const intel = dedup(allIntel as Record<string, unknown>[], "key");

  res.json({
    assetId: finding.assetId,
    ports,
    httpInfo: httpInfo ?? null,
    intelligence: intel,
    subdomains: subs,
    vulnerabilities: vulns,
  });
});

router.patch("/findings/:findingId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = UpdateFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = UpdateFindingBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [finding] = await db.update(findingsTable).set(parsed.data)
    .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
  await logAudit(req.user!, "update_finding", "finding", finding.id, `status: ${parsed.data.status ?? "unchanged"}`);
  res.json(toFindingResponse(finding));
});

router.get("/findings/:findingId/comments", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = ListFindingCommentsParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const comments = await db.select({
    comment: findingCommentsTable,
    authorName: usersTable.firstName,
    authorLast: usersTable.lastName,
  }).from(findingCommentsTable)
    .leftJoin(usersTable, eq(findingCommentsTable.userId, usersTable.id))
    .where(eq(findingCommentsTable.findingId, params.data.findingId));
  res.json(comments.map(({ comment, authorName, authorLast }) => ({
    id: comment.id, findingId: comment.findingId, userId: comment.userId,
    authorName: authorName ? `${authorName} ${authorLast ?? ""}`.trim() : "Unknown",
    content: comment.content, createdAt: comment.createdAt.toISOString(),
  })));
});

router.post("/findings/:findingId/comments", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CreateFindingCommentParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const parsed = CreateFindingCommentBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const [comment] = await db.insert(findingCommentsTable).values({
    findingId: params.data.findingId, userId: req.user!.userId, content: parsed.data.content,
  }).returning();
  const [user] = await db.select().from(usersTable).where(eq(usersTable.id, req.user!.userId));
  res.status(201).json({
    id: comment.id, findingId: comment.findingId, userId: comment.userId,
    authorName: user ? `${user.firstName} ${user.lastName}` : "Unknown",
    content: comment.content, createdAt: comment.createdAt.toISOString(),
  });
});

export default router;
