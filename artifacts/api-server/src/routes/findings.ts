import { Router } from "express";
import { eq, and, ilike, inArray, desc, isNotNull, or, ne } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter, buildRecordFilter, getEffectiveAssetIdsForTenant } from "../lib/tenantScoping";
import { db, findingsTable, findingCommentsTable, assetsTable, usersTable, scanAssetResultsTable, riskScoresTable, tenantsTable, externalMemberAssetsTable, scanSuppressionsTable } from "@workspace/db";
import {
  GetFindingParams, UpdateFindingParams, UpdateFindingBody,
  ListFindingsQueryParams, ListFindingCommentsParams,
  CreateFindingCommentParams, CreateFindingCommentBody,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { finalizeScannedAssets } from "../lib/scanScheduler";
import { logger } from "../lib/logger";

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
  tenantName?: string | null,
) {
  const SEV_RISK: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 10 };
  const riskScore = assetRiskScore ?? f.riskScore ?? SEV_RISK[f.severity ?? "medium"] ?? 45;
  // A finding is "new since last scan" when it was first seen in its current scan
  const isNewSinceLastScan = f.firstSeenScanId !== null && f.firstSeenScanId === f.scanId && f.previousScanId === null;
  return {
    id: f.id, tenantId: f.tenantId, tenantName: tenantName ?? null, assetId: f.assetId,
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
    isFalsePositive: f.isFalsePositive,
    falsePositiveStatus: f.falsePositiveStatus ?? "none",
    fpSubmittedBy: f.fpSubmittedBy ?? null,
    fpSubmittedAt: f.fpSubmittedAt ? f.fpSubmittedAt.toISOString() : null,
    fpReviewedBy: f.fpReviewedBy ?? null,
    fpReviewedAt: f.fpReviewedAt ? f.fpReviewedAt.toISOString() : null,
    fpNote: f.fpNote ?? null,
    lastSeenAt: f.lastSeenAt ? f.lastSeenAt.toISOString() : null,
    consecutiveMissedScans: f.consecutiveMissedScans,
    previousScanId: f.previousScanId ?? null,
    firstSeenScanId: f.firstSeenScanId ?? null,
    isNewSinceLastScan,
    createdAt: f.createdAt.toISOString(), updatedAt: f.updatedAt.toISOString(),
  };
}

// Shared helper: add delta / stale filters when query params are present
function applyDeltaFilters(filters: any[], q: ReturnType<typeof ListFindingsQueryParams.safeParse>) {
  if (!q.success) return;
  // ?newSinceScanId=N → only findings first discovered in scan N
  if (q.data.newSinceScanId) filters.push(eq(findingsTable.firstSeenScanId, q.data.newSinceScanId));
  // ?isStale=true → findings that have been missed in at least 1 consecutive scan
  if (q.data.isStale === "true") filters.push(isNotNull(findingsTable.lastSeenAt));
}

router.get("/findings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListFindingsQueryParams.safeParse(req.query);
  const role = req.user!.role;

  // External members: restrict to open findings for their explicitly granted assets (read-only)
  if (role === "vendor" || role === "employee" || role === "third_party") {
    const rows = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(eq(externalMemberAssetsTable.userId, req.user!.userId));
    if (rows.length === 0) { res.json([]); return; }
    const allowedIds = rows.map(r => r.assetId);
    // Always enforce status="open" for external members — no closed/resolved findings
    const extFilters: any[] = [inArray(findingsTable.assetId, allowedIds), eq(findingsTable.status, "open")];
    if (q.success) {
      if (q.data.severity) extFilters.push(eq(findingsTable.severity, q.data.severity));
      if (q.data.assetId) extFilters.push(eq(findingsTable.assetId, q.data.assetId));
      if (q.data.search) extFilters.push(ilike(findingsTable.title, `%${q.data.search}%`));
      applyDeltaFilters(extFilters, q);
    }
    const extFindings = await db.select({
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
      .where(and(...extFilters));
    res.json(extFindings.map(({ finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore }) =>
      toFindingResponse(finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore)));
    return;
  }

  // Account Manager: filter by assets from client tenants (data spans tenants via asset IDs)
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    const clientAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(inArray(assetsTable.tenantId, ids));
    const clientAssetIds = clientAssets.map(a => a.id);
    if (clientAssetIds.length === 0) { res.json([]); return; }
    const amFilters: any[] = [inArray(findingsTable.assetId, clientAssetIds)];
    if (q.success) {
      if (q.data.status) amFilters.push(eq(findingsTable.status, q.data.status));
      if (q.data.severity) amFilters.push(eq(findingsTable.severity, q.data.severity));
      if (q.data.assetId) amFilters.push(eq(findingsTable.assetId, q.data.assetId));
      if (q.data.search) amFilters.push(ilike(findingsTable.title, `%${q.data.search}%`));
      applyDeltaFilters(amFilters, q);
    }
    const amFindings = await db.select({
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
      .where(and(...amFilters));
    res.json(amFindings.map(({ finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore }) =>
      toFindingResponse(finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore)));
    return;
  }

  // super_admin and admin: cross-tenant access constrained to accessible client tenants
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;

    let saFilters: any[];
    if (!isNaN(qTenantId) && privIds.includes(qTenantId)) {
      // Specific client tenant selected: resolve to effective asset IDs.
      // Platform assets live in tenant 1 with assignedClientId → client user in tenant X.
      // Filtering by tenantId alone misses these cross-tenant assets.
      const effectiveAssetIds = await getEffectiveAssetIdsForTenant(qTenantId);
      if (effectiveAssetIds.length === 0) { res.json([]); return; }
      saFilters = [inArray(findingsTable.assetId, effectiveAssetIds)];
    } else {
      // "All Clients" or invalid tenantId: show all findings across all accessible tenants
      const filteredTids = resolvePrivilegedTenantFilter(privIds, null);
      saFilters = [inArray(findingsTable.tenantId, filteredTids)];
    }
    if (q.success) {
      if (q.data.status) saFilters.push(eq(findingsTable.status, q.data.status));
      if (q.data.severity) saFilters.push(eq(findingsTable.severity, q.data.severity));
      if (q.data.assetId) saFilters.push(eq(findingsTable.assetId, q.data.assetId));
      if (q.data.search) saFilters.push(ilike(findingsTable.title, `%${q.data.search}%`));
      applyDeltaFilters(saFilters, q);
    }
    const saFindings = await db.select({
      finding: findingsTable,
      assetName: assetsTable.name,
      assetValue: assetsTable.value,
      assetType: assetsTable.type,
      assetLastScannedAt: assetsTable.lastScannedAt,
      assetIpAddress: assetsTable.ipAddress,
      assetPort: assetsTable.port,
      assetTags: assetsTable.tags,
      assetRiskScore: riskScoresTable.score,
      tenantName: tenantsTable.name,
    }).from(findingsTable)
      .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
      .leftJoin(riskScoresTable, eq(findingsTable.assetId, riskScoresTable.assetId))
      .leftJoin(tenantsTable, eq(findingsTable.tenantId, tenantsTable.id))
      .where(and(...saFilters));
    res.json(saFindings.map(({ finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore, tenantName }) =>
      toFindingResponse(finding, assetName, assetValue, assetType, assetLastScannedAt, assetIpAddress, assetPort, assetTags, assetRiskScore, tenantName)));
    return;
  }

  let tenantFilter;
  tenantFilter = eq(findingsTable.tenantId, req.user!.tenantId);
  const filters: any[] = [tenantFilter];

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
    applyDeltaFilters(filters, q);
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

// ── False Positive: list (role-scoped) ───────────────────────────────────────
// GET /findings/false-positives  ← MUST be before /:findingId to avoid param shadowing
router.get("/findings/false-positives", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, tenantId, userId } = req.user!;
  const { status, severity, search, page = "1", limit = "50" } = req.query as Record<string, string>;

  // ── 1. Determine which tenant IDs to include ─────────────────────────────
  // For this platform: findings live in the platform tenant (tenant_id=1) but
  // their assets may be assigned to client users. We fetch ALL tenant findings
  // for SA/admin so nothing is missed, then enrich with client-tenant context.
  let tenantIds: number[];
  if (role === "super_admin" || role === "admin") {
    // All tenants (platform + clients)
    const rows = await db.select({ id: tenantsTable.id }).from(tenantsTable);
    tenantIds = rows.map(r => r.id);
    // Also always include the caller's own tenant (covers platform findings)
    if (!tenantIds.includes(tenantId)) tenantIds.push(tenantId);
  } else if (role === "account_manager") {
    const clientIds = await getAmClientTenantIds(userId);
    tenantIds = [...new Set([tenantId, ...clientIds])];
  } else {
    tenantIds = [tenantId];
  }

  // ── 2. Build broad FP condition ───────────────────────────────────────────
  // Catches: directly marked via status change, via suppress, or via fp-status review
  const fpCondition = or(
    eq(findingsTable.status, "false_positive"),
    eq(findingsTable.isFalsePositive, true),
    inArray(findingsTable.falsePositiveStatus, ["submitted", "confirmed", "rejected"])
  )!;

  const filters: any[] = [
    inArray(findingsTable.tenantId, tenantIds),
    fpCondition,
  ];

  // ── 3. Client scope: restrict to assigned assets ─────────────────────────
  if (role === "client") {
    const myAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, userId));
    if (myAssets.length === 0) { res.json({ findings: [], total: 0 }); return; }
    filters.push(inArray(findingsTable.assetId, myAssets.map(a => a.id)));
  }

  // ── 4. Optional filters ───────────────────────────────────────────────────
  if (status && status !== "all") {
    if (status === "submitted")
      filters.push(eq(findingsTable.falsePositiveStatus, "submitted"));
    else if (status === "confirmed")
      filters.push(or(
        eq(findingsTable.falsePositiveStatus, "confirmed"),
        and(eq(findingsTable.status, "false_positive"), ne(findingsTable.falsePositiveStatus, "rejected"))!
      )!);
    else if (status === "rejected")
      filters.push(eq(findingsTable.falsePositiveStatus, "rejected"));
  }
  if (severity && severity !== "all") filters.push(eq(findingsTable.severity, severity));
  if (search)   filters.push(ilike(findingsTable.title, `%${search}%`));

  const offsetN = (Math.max(1, parseInt(page, 10)) - 1) * Math.min(200, parseInt(limit, 10));
  const limitN  = Math.min(200, parseInt(limit, 10));

  // ── 5. Main query — include assignedClientId from assets ──────────────────
  const rows = await db.select({
    f:                findingsTable,
    assetName:        assetsTable.name,
    assetValue:       assetsTable.value,
    assignedClientId: assetsTable.assignedClientId,
    tenantName:       tenantsTable.name,
  }).from(findingsTable)
    .leftJoin(assetsTable,  eq(findingsTable.assetId,  assetsTable.id))
    .leftJoin(tenantsTable, eq(findingsTable.tenantId, tenantsTable.id))
    .where(and(...filters))
    .orderBy(desc(findingsTable.updatedAt))
    .limit(limitN)
    .offset(offsetN);

  // ── 6. Resolve user names + client tenant names ───────────────────────────
  const userIdSet = new Set<number>();
  rows.forEach(r => {
    if (r.f.fpSubmittedBy) userIdSet.add(r.f.fpSubmittedBy);
    if (r.f.fpReviewedBy)  userIdSet.add(r.f.fpReviewedBy);
    if (r.assignedClientId) userIdSet.add(r.assignedClientId);
  });

  const userMap: Record<number, { name: string; tenantId: number | null }> = {};
  if (userIdSet.size > 0) {
    const uRows = await db.select({
      id: usersTable.id,
      firstName: usersTable.firstName,
      lastName:  usersTable.lastName,
      tenantId:  usersTable.tenantId,
    }).from(usersTable).where(inArray(usersTable.id, [...userIdSet]));
    uRows.forEach(u => {
      userMap[u.id] = {
        name: (`${u.firstName ?? ""} ${u.lastName ?? ""}`.trim() || u.email) ?? "User",
        tenantId: u.tenantId,
      };
    });
  }

  // Resolve client tenant names from gathered tenantIds
  const clientTenantIdSet = new Set<number>();
  Object.values(userMap).forEach(u => { if (u.tenantId) clientTenantIdSet.add(u.tenantId); });
  const clientTenantMap: Record<number, string> = {};
  if (clientTenantIdSet.size > 0) {
    const tRows = await db.select({ id: tenantsTable.id, name: tenantsTable.name })
      .from(tenantsTable).where(inArray(tenantsTable.id, [...clientTenantIdSet]));
    tRows.forEach(t => { clientTenantMap[t.id] = t.name; });
  }

  // ── 7. Map to response ────────────────────────────────────────────────────
  const findings = rows.map(({ f, assetName, assetValue, assignedClientId, tenantName }) => {
    // Normalise FP status — handle legacy FPs that predate fp tracking columns
    let fpStatus = f.falsePositiveStatus ?? "none";
    if (fpStatus === "none" && (f.status === "false_positive" || f.isFalsePositive)) {
      fpStatus = "confirmed";
    }

    // Resolve client tenant (asset's assigned client tenant > direct finding tenant)
    const clientUser    = assignedClientId ? userMap[assignedClientId] : null;
    const clientTenId   = clientUser?.tenantId ?? null;
    const clientTenName = clientTenId ? (clientTenantMap[clientTenId] ?? null) : null;
    // Show the client tenant when it differs from the platform (platform manages on behalf of clients)
    const displayTenantId   = clientTenId ?? f.tenantId;
    const displayTenantName = clientTenName ?? tenantName ?? null;

    return {
      id:           f.id,
      title:        f.title,
      severity:     f.severity,
      status:       f.status,
      assetId:      f.assetId,
      assetName:    assetName ?? null,
      assetValue:   assetValue ?? null,
      tenantId:     displayTenantId,
      tenantName:   displayTenantName,
      cve:          f.cve,
      cvss:         f.cvss,
      isFalsePositive:     f.isFalsePositive,
      falsePositiveStatus: fpStatus,
      fpNote:       f.fpNote ?? null,
      fpSubmittedBy:     f.fpSubmittedBy ?? null,
      fpSubmittedByName: f.fpSubmittedBy ? (userMap[f.fpSubmittedBy]?.name ?? "Unknown") : null,
      fpSubmittedAt: f.fpSubmittedAt ? f.fpSubmittedAt.toISOString() : f.updatedAt.toISOString(),
      fpReviewedBy:     f.fpReviewedBy ?? null,
      fpReviewedByName: f.fpReviewedBy ? (userMap[f.fpReviewedBy]?.name ?? "Unknown") : null,
      fpReviewedAt:  f.fpReviewedAt ? f.fpReviewedAt.toISOString() : null,
      updatedAt:    f.updatedAt.toISOString(),
      createdAt:    f.createdAt.toISOString(),
    };
  });

  res.json({ findings, total: findings.length });
});

// ── False Positive: confirm or reject ────────────────────────────────────────
// PATCH /findings/:findingId/fp-status  ← keep BEFORE bare /:findingId patch
router.patch("/findings/:findingId/fp-status", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { role, userId } = req.user!;
  if (role !== "super_admin" && role !== "admin" && role !== "account_manager") {
    res.status(403).json({ error: "Only admin, super_admin, or account_manager can review false positives" });
    return;
  }

  const findingId = parseInt(req.params.findingId as string, 10);
  if (isNaN(findingId)) { res.status(400).json({ error: "Invalid findingId" }); return; }

  const { action, note } = req.body as { action?: string; note?: string };
  if (action !== "confirm" && action !== "reject") {
    res.status(400).json({ error: "action must be 'confirm' or 'reject'" });
    return;
  }

  let finding: typeof findingsTable.$inferSelect | undefined;
  if (role === "super_admin" || role === "admin") {
    const [row] = await db.select().from(findingsTable).where(eq(findingsTable.id, findingId));
    finding = row;
  } else {
    const clientIds = await getAmClientTenantIds(userId);
    const allIds = [...new Set([req.user!.tenantId, ...clientIds])];
    const [row] = await db.select().from(findingsTable)
      .where(and(eq(findingsTable.id, findingId), inArray(findingsTable.tenantId, allIds)));
    finding = row;
  }
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const now = new Date();
  const updateSet: Record<string, any> = {
    fpReviewedBy: userId,
    fpReviewedAt: now,
    fpNote:       note ?? null,
    updatedAt:    now,
  };

  if (action === "confirm") {
    updateSet.falsePositiveStatus = "confirmed";
    updateSet.isFalsePositive     = true;
    updateSet.status              = "false_positive";
    if (!finding.fpSubmittedAt) {
      updateSet.fpSubmittedAt = now;
      updateSet.fpSubmittedBy = userId;
    }
  } else {
    updateSet.falsePositiveStatus = "rejected";
    updateSet.isFalsePositive     = false;
    updateSet.status              = "open";
  }

  const [updated] = await db.update(findingsTable).set(updateSet as any)
    .where(eq(findingsTable.id, findingId))
    .returning();

  await logAudit(req.user!, `finding.fp_${action}`, "finding", findingId, JSON.stringify({ action, note }), req.ip ?? "");

  if (updated?.assetId) {
    finalizeScannedAssets([updated.assetId], { updateLastScannedAt: false }).catch(() => {});
  }

  res.json({ ok: true, id: updated?.id, falsePositiveStatus: updateSet.falsePositiveStatus, status: updateSet.status });
});

router.get("/findings/:findingId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;

  // External members: only if the finding belongs to one of their granted assets
  if (role === "vendor" || role === "employee" || role === "third_party") {
    const [finding] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
    const [granted] = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(and(eq(externalMemberAssetsTable.userId, req.user!.userId), eq(externalMemberAssetsTable.assetId, finding.assetId)));
    if (!granted) { res.status(404).json({ error: "Finding not found" }); return; }
    const [row] = await db.select({ finding: findingsTable, assetName: assetsTable.name, assetValue: assetsTable.value, assetType: assetsTable.type, assetLastScannedAt: assetsTable.lastScannedAt, assetIpAddress: assetsTable.ipAddress, assetPort: assetsTable.port, assetTags: assetsTable.tags, assetRiskScore: riskScoresTable.score })
      .from(findingsTable).leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id)).leftJoin(riskScoresTable, eq(findingsTable.assetId, riskScoresTable.assetId))
      .where(eq(findingsTable.id, params.data.findingId));
    if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
    res.json(toFindingResponse(row.finding, row.assetName, row.assetValue, row.assetType, row.assetLastScannedAt, row.assetIpAddress, row.assetPort, row.assetTags, row.assetRiskScore));
    return;
  }

  // Client: verify the finding's asset is assigned to them
  if (role === "client") {
    const [f] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [assigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, f.assetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!assigned) { res.status(404).json({ error: "Finding not found" }); return; }
    const [row] = await db.select({
      finding: findingsTable, assetName: assetsTable.name, assetValue: assetsTable.value,
      assetType: assetsTable.type, assetLastScannedAt: assetsTable.lastScannedAt,
      assetIpAddress: assetsTable.ipAddress, assetPort: assetsTable.port,
      assetTags: assetsTable.tags, assetRiskScore: riskScoresTable.score,
    }).from(findingsTable)
      .leftJoin(assetsTable, eq(findingsTable.assetId, assetsTable.id))
      .leftJoin(riskScoresTable, eq(findingsTable.assetId, riskScoresTable.assetId))
      .where(eq(findingsTable.id, params.data.findingId));
    if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
    res.json(toFindingResponse(row.finding, row.assetName, row.assetValue, row.assetType, row.assetLastScannedAt, row.assetIpAddress, row.assetPort, row.assetTags, row.assetRiskScore));
    return;
  }

  let findingWhere;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    findingWhere = buildRecordFilter(eq(findingsTable.id, params.data.findingId), findingsTable.tenantId, privIds);
  } else {
    findingWhere = and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId));
  }
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
    .where(findingWhere);
  if (!row) { res.status(404).json({ error: "Finding not found" }); return; }
  res.json(toFindingResponse(row.finding, row.assetName, row.assetValue, row.assetType, row.assetLastScannedAt, row.assetIpAddress, row.assetPort, row.assetTags, row.assetRiskScore));
});

// ── GET /findings/:findingId/scan-data ─────────────────────────────────────
// Returns aggregated ports, httpInfo, intelligence, vulnerabilities from the
// most recent scan that covered this finding's asset.
router.get("/findings/:findingId/scan-data", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetFindingParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  const scanDataRole = req.user!.role;

  // External members: verify finding belongs to one of their granted assets
  if (scanDataRole === "vendor" || scanDataRole === "employee" || scanDataRole === "third_party") {
    const [f] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [granted] = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(and(eq(externalMemberAssetsTable.userId, req.user!.userId), eq(externalMemberAssetsTable.assetId, f.assetId)));
    if (!granted) { res.status(404).json({ error: "Finding not found" }); return; }
  }

  // Client: verify finding's asset is assigned to them
  if (scanDataRole === "client") {
    const [f] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [assigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, f.assetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!assigned) { res.status(404).json({ error: "Finding not found" }); return; }
  }

  let scanDataFindingWhere;
  if (scanDataRole === "super_admin" || scanDataRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    scanDataFindingWhere = buildRecordFilter(eq(findingsTable.id, params.data.findingId), findingsTable.tenantId, privIds);
  } else {
    scanDataFindingWhere = and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId));
  }
  const [finding] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId, tenantId: findingsTable.tenantId })
    .from(findingsTable)
    .where(scanDataFindingWhere);
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  // Get the most recent scan asset results for this asset
  const scanResults = await db.select().from(scanAssetResultsTable)
    .where(and(
      eq(scanAssetResultsTable.assetId, finding.assetId),
      eq(scanAssetResultsTable.tenantId, finding.tenantId),
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
  const patchRole = req.user!.role;

  // External members cannot mutate findings
  if (patchRole === "vendor" || patchRole === "employee" || patchRole === "third_party") {
    res.status(403).json({ error: "External members cannot modify findings" }); return;
  }

  const parsed = UpdateFindingBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  // Client role: verify the finding's asset is assigned to them before mutating
  if (patchRole === "client") {
    const [f] = await db.select({ assetId: findingsTable.assetId })
      .from(findingsTable)
      .where(and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId)));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [assigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, f.assetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!assigned) { res.status(404).json({ error: "Finding not found" }); return; }
  }

  let patchWhere;
  if (patchRole === "super_admin" || patchRole === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    patchWhere = buildRecordFilter(eq(findingsTable.id, params.data.findingId), findingsTable.tenantId, privIds);
  } else {
    patchWhere = and(eq(findingsTable.id, params.data.findingId), eq(findingsTable.tenantId, req.user!.tenantId));
  }
  // Role-aware FP tracking: clients "submit" for review; privileged roles directly confirm.
  const updateData: Record<string, unknown> = { ...parsed.data };
  if (parsed.data.status === "false_positive") {
    if (patchRole === "client") {
      // Client submits for review — pending confirmation by admin/AM
      updateData.falsePositiveStatus = "submitted";
      updateData.isFalsePositive = false;
      updateData.fpSubmittedBy = req.user!.userId;
      updateData.fpSubmittedAt = new Date();
    } else {
      // SA/Admin/AM directly confirm
      updateData.falsePositiveStatus = "confirmed";
      updateData.isFalsePositive = true;
      updateData.fpSubmittedBy = req.user!.userId;
      updateData.fpSubmittedAt = new Date();
      updateData.fpReviewedBy = req.user!.userId;
      updateData.fpReviewedAt = new Date();
    }
  }
  // When status is changed away from false_positive, clear the FP tracking fields
  if (parsed.data.status && parsed.data.status !== "false_positive") {
    updateData.falsePositiveStatus = "none";
    updateData.isFalsePositive = false;
    updateData.fpReviewedBy = null;
    updateData.fpReviewedAt = null;
    updateData.fpNote = null;
  }
  const [finding] = await db.update(findingsTable).set(updateData as any)
    .where(patchWhere)
    .returning();
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }
  await logAudit(req.user!, "update_finding", "finding", finding.id, `status: ${parsed.data.status ?? "unchanged"}`);
  res.json(toFindingResponse(finding));

  // Issue 4: Recalculate risk score whenever a finding is updated (status change, etc.)
  // Fire-and-forget — does not block the response
  if (finding.assetId) {
    finalizeScannedAssets([finding.assetId], { updateLastScannedAt: false }).catch(err =>
      logger.warn({ err, assetId: finding.assetId }, "Risk recalculation after finding update failed (non-fatal)"),
    );
  }
});

router.get("/findings/:findingId/comments", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = ListFindingCommentsParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }

  // External members: verify finding belongs to one of their granted assets (read-only allowed)
  const commentsRole = req.user!.role;
  if (commentsRole === "vendor" || commentsRole === "employee" || commentsRole === "third_party") {
    const [f] = await db.select({ assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [granted] = await db.select({ assetId: externalMemberAssetsTable.assetId })
      .from(externalMemberAssetsTable)
      .where(and(eq(externalMemberAssetsTable.userId, req.user!.userId), eq(externalMemberAssetsTable.assetId, f.assetId)));
    if (!granted) { res.status(404).json({ error: "Finding not found" }); return; }
  }

  // Client: verify finding's asset is assigned to them
  if (commentsRole === "client") {
    const [f] = await db.select({ assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!f) { res.status(404).json({ error: "Finding not found" }); return; }
    const [assigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, f.assetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!assigned) { res.status(404).json({ error: "Finding not found" }); return; }
  }

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

  // External members cannot post comments
  const commentRole = req.user!.role;
  if (commentRole === "vendor" || commentRole === "employee" || commentRole === "third_party") {
    res.status(403).json({ error: "External members cannot post comments" }); return;
  }

  // Client: verify the finding's asset is assigned to them before allowing a comment
  if (commentRole === "client") {
    const [postF] = await db.select({ id: findingsTable.id, assetId: findingsTable.assetId })
      .from(findingsTable).where(eq(findingsTable.id, params.data.findingId));
    if (!postF) { res.status(404).json({ error: "Finding not found" }); return; }
    const [postAssigned] = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(and(eq(assetsTable.id, postF.assetId), eq(assetsTable.assignedClientId, req.user!.userId)));
    if (!postAssigned) { res.status(404).json({ error: "Finding not found" }); return; }
  }

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

// ── Confirm false positive + add to suppression list ─────────────────────────
// POST /findings/:findingId/suppress
// Body: { matchType: "cve_id"|"title_contains"|"url_exact"|"url_pattern", note?: string, applyToAsset?: boolean }
// Effect: marks finding as false_positive with full FP tracking + creates a suppression rule.
// SA/Admin can suppress findings across all accessible tenants (cross-tenant).
router.post("/findings/:findingId/suppress", requireAuth, async (req, res) => {
  const { tenantId, userId, role } = (req as AuthenticatedRequest).user;
  const findingId = parseInt(req.params.findingId, 10);
  if (isNaN(findingId)) { res.status(400).json({ error: "Invalid findingId" }); return; }

  // Cross-tenant: SA/admin can suppress findings in any accessible tenant
  let findingWhere;
  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds((req as AuthenticatedRequest).user!);
    findingWhere = buildRecordFilter(eq(findingsTable.id, findingId), findingsTable.tenantId, privIds);
  } else {
    findingWhere = and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, tenantId));
  }

  const [finding] = await db.select().from(findingsTable).where(findingWhere);
  if (!finding) { res.status(404).json({ error: "Finding not found" }); return; }

  const { matchType = "title_contains", note, applyToAsset = true } = req.body as {
    matchType?: string; note?: string; applyToAsset?: boolean;
  };

  // Derive the suppression pattern — always falls back to title so pattern is never empty
  let pattern: string;
  if (matchType === "cve_id" && finding.cve) {
    pattern = finding.cve;
  } else if (matchType === "url_exact" || matchType === "url_pattern") {
    let url = "";
    try { const ev = JSON.parse(finding.evidence ?? "{}"); url = ev.url ?? ev.matched_at ?? ""; } catch {}
    pattern = url || finding.title.slice(0, 200);
  } else {
    // title_contains (default) or fallback
    pattern = finding.title.slice(0, 200);
  }

  // Create suppression rule — BEST-EFFORT: failure must not prevent FP marking
  let suppressionId: number | undefined;
  try {
    const [suppression] = await db.insert(scanSuppressionsTable).values({
      tenantId: finding.tenantId,
      assetId: applyToAsset ? finding.assetId : null,
      matchType,
      pattern,
      note: note ? note.trim() : `Suppressed from finding #${findingId}`,
      createdByUserId: userId as any,
    }).returning();
    suppressionId = suppression?.id;
  } catch (suppErr: any) {
    logger.warn({ err: suppErr?.message, findingId }, "Suppression rule INSERT failed — still marking finding as FP");
  }

  // Mark finding as false positive with FULL tracking fields
  // This is the authoritative step — suppression is advisory
  const now = new Date();
  const [updated] = await db.update(findingsTable).set({
    status:              "false_positive",
    isFalsePositive:     true,
    falsePositiveStatus: "confirmed",
    fpSubmittedBy:       userId as any,
    fpSubmittedAt:       now,
    fpReviewedBy:        userId as any,
    fpReviewedAt:        now,
    fpNote:              note ? note.trim() : null,
    updatedAt:           now,
  }).where(eq(findingsTable.id, findingId)).returning();

  await logAudit(db, {
    tenantId: finding.tenantId,
    userId: userId as any,
    action: "finding.suppress",
    resourceType: "finding",
    resourceId: String(findingId),
    metadata: { suppressionId, matchType, pattern, applyToAsset },
    ip: req.ip ?? "",
  });

  // Recalculate risk score for the asset (non-blocking)
  if (updated?.assetId) {
    finalizeScannedAssets([updated.assetId], { updateLastScannedAt: false }).catch(() => {});
  }

  res.status(201).json({ success: true, suppressionId, matchType, pattern, applyToAsset });
});

export default router;
