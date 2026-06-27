import { Router } from "express";
import { eq, and, inArray, desc } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { getPrivilegedTenantIds, resolvePrivilegedTenantFilter } from "../lib/tenantScoping";
import { db, scansTable, scanJobsTable, assetsTable, findingsTable, riskScoresTable, securityToolsTable, toolPipelineStepsTable } from "@workspace/db";
import { enqueueAndRun, type AssetToolConfigItem } from "./pipelineScans";
import {
  CreateScanBody, GetScanParams, DeleteScanParams, CancelScanParams,
  ListScansQueryParams, ListScanJobsParams,
} from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function toScanResponse(s: typeof scansTable.$inferSelect) {
  return {
    id: s.id, tenantId: s.tenantId, name: s.name, type: s.type, status: s.status,
    schedule: s.schedule, assetIds: s.assetIds ?? [], findingsCount: s.findingsCount,
    startedAt: s.startedAt?.toISOString() ?? null,
    completedAt: s.completedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  };
}

function scoreToLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/**
 * After scan completes:
 * 1. Stamp lastScannedAt on every scanned asset
 * 2. Recompute riskScore + riskLevel from live findings
 * 3. Upsert risk_scores and update assets.risk_level
 */
async function finalizeScannedAssets(assetIds: number[]) {
  if (assetIds.length === 0) return;
  const now = new Date();

  await db.update(assetsTable)
    .set({ lastScannedAt: now })
    .where(inArray(assetsTable.id, assetIds));

  const findings = await db
    .select({
      assetId: findingsTable.assetId,
      severity: findingsTable.severity,
      cvss: findingsTable.cvss,
      epss: findingsTable.epss,
      isKev: findingsTable.isKev,
      status: findingsTable.status,
    })
    .from(findingsTable)
    .where(inArray(findingsTable.assetId, assetIds));

  const byAsset = new Map<number, typeof findings>();
  for (const f of findings) {
    if (!byAsset.has(f.assetId!)) byAsset.set(f.assetId!, []);
    byAsset.get(f.assetId!)!.push(f);
  }

  for (const assetId of assetIds) {
    const all = byAsset.get(assetId) ?? [];
    const open = all.filter(f => f.status !== "mitigated" && f.status !== "resolved");

    const critical = open.filter(f => f.severity === "critical").length;
    const high     = open.filter(f => f.severity === "high").length;
    const medium   = open.filter(f => f.severity === "medium").length;

    let score = critical * 22 + high * 12 + medium * 5;

    const cvssVals = open.map(f => f.cvss ?? 0).filter(v => v > 0);
    const avgCvss = cvssVals.length ? cvssVals.reduce((a, b) => a + b, 0) / cvssVals.length : 0;
    score += (avgCvss / 10) * 25;

    const maxEpss = open.reduce((m, f) => Math.max(m, f.epss ?? 0), 0);
    score += maxEpss * 15;

    const kevCount = open.filter(f => f.isKev).length;
    score += kevCount * 8;

    score = Math.round(Math.min(100, Math.max(0, score)));
    const level = scoreToLevel(score);

    const cvssComponent = Math.round((avgCvss / 10) * 25 * 10) / 10;
    const epssComponent = Math.round(maxEpss * 15 * 10) / 10;
    const kevBonus      = kevCount * 8;

    const [existing] = await db.select({ id: riskScoresTable.id })
      .from(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
    if (existing) {
      await db.update(riskScoresTable)
        .set({ score, level, cvssComponent, epssComponent, kevBonus })
        .where(eq(riskScoresTable.assetId, assetId));
    } else {
      await db.insert(riskScoresTable).values({ assetId, score, level, cvssComponent, epssComponent, kevBonus });
    }

    await db.update(assetsTable).set({ riskLevel: level }).where(eq(assetsTable.id, assetId));
  }
}

router.get("/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListScansQueryParams.safeParse(req.query);
  const role = req.user!.role;

  // Client: only show scans that include at least one asset assigned to them
  if (role === "client") {
    const assignedAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(eq(assetsTable.assignedClientId, req.user!.userId));
    const assignedIds = new Set(assignedAssets.map(a => a.id));
    if (assignedIds.size === 0) { res.json([]); return; }
    const filters: ReturnType<typeof eq>[] = [eq(scansTable.tenantId, req.user!.tenantId) as any];
    if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status) as any);
    const allScans = await db.select().from(scansTable).where(and(...filters))
      .orderBy(desc(scansTable.createdAt));
    const clientScans = allScans.filter(s =>
      Array.isArray(s.assetIds) && (s.assetIds as number[]).some(id => assignedIds.has(id))
    );
    res.json(clientScans.map(toScanResponse)); return;
  }

  if (role === "super_admin" || role === "admin") {
    const privIds = await getPrivilegedTenantIds(req.user!);
    if (privIds.length === 0) { res.json([]); return; }
    const qTenantId = req.query.tenantId ? parseInt(req.query.tenantId as string, 10) : NaN;
    const filtered = resolvePrivilegedTenantFilter(privIds, !isNaN(qTenantId) ? qTenantId : null);
    const filters: any[] = [inArray(scansTable.tenantId, filtered)];
    if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status));
    const allScans = await db.select().from(scansTable)
      .where(and(...filters))
      .orderBy(desc(scansTable.createdAt));
    res.json(allScans.map(toScanResponse)); return;
  }

  let tenantFilter;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    // Scope scans to client tenants — no full-table scan
    const filters: ReturnType<typeof eq>[] = [inArray(scansTable.tenantId, ids) as any];
    if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status) as any);
    const amScans = await db.select().from(scansTable).where(and(...filters))
      .orderBy(desc(scansTable.createdAt));
    res.json(amScans.map(toScanResponse)); return;
  }
  tenantFilter = eq(scansTable.tenantId, req.user!.tenantId);
  const filters = [tenantFilter];
  if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status));
  const scans = await db.select().from(scansTable).where(and(...filters))
    .orderBy(desc(scansTable.createdAt));
  res.json(scans.map(toScanResponse));
});

router.post("/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  // Enforce ownership verification — no scanning unverified assets
  const assetIds = (parsed.data as any).assetIds as number[] | undefined;
  const role = req.user!.role;

  // For AM: resolve allowed tenantIds from client assignments so we can verify
  // ownership across the client tenants they manage.
  // For admin/super_admin: allowedTenantIds = null means unrestricted cross-tenant access.
  let allowedTenantIds: number[] | null = null;
  if (role === "account_manager") {
    allowedTenantIds = await getAmClientTenantIds(req.user!.userId);
    if (allowedTenantIds.length === 0) {
      res.status(403).json({ error: "No client tenants assigned" }); return;
    }
  } else if (role !== "super_admin" && role !== "admin") {
    // Regular users: restrict to own tenant
    allowedTenantIds = [req.user!.tenantId];
  }
  // super_admin and admin: allowedTenantIds stays null (unrestricted)

  let assetTenantId = req.user!.tenantId; // default for non-AM roles
  // Validated asset ID list derived from DB lookup — used for the scan record
  // so unauthorized IDs from the raw payload can never be enqueued.
  let validatedAssetIds: number[] = assetIds ?? [];

  if (assetIds && assetIds.length > 0) {
    const deduped = [...new Set(assetIds)];
    const tenantFilter = allowedTenantIds
      ? inArray(assetsTable.tenantId, allowedTenantIds)
      : undefined;
    const assetRows = await db
      .select({ id: assetsTable.id, name: assetsTable.name, verificationStatus: assetsTable.verificationStatus, tenantId: assetsTable.tenantId })
      .from(assetsTable)
      .where(and(inArray(assetsTable.id, deduped), tenantFilter));

    // 1. All requested IDs must resolve — missing means out-of-scope or non-existent
    if (assetRows.length !== deduped.length) {
      res.status(403).json({ error: "One or more asset IDs are not accessible in your scope." });
      return;
    }

    // 2. Single-tenant scan semantics — reject mixed-tenant asset sets
    const tenantIds = [...new Set(assetRows.map(a => a.tenantId))];
    if (tenantIds.length > 1) {
      res.status(400).json({ error: "All assets in a scan must belong to the same tenant." });
      return;
    }

    const unverified = assetRows.filter(a => a.verificationStatus !== "verified");
    if (unverified.length > 0) {
      res.status(422).json({
        error: "Cannot scan unverified assets. Verify ownership before scanning.",
        unverifiedAssets: unverified.map(a => ({ id: a.id, name: a.name })),
      });
      return;
    }

    // 3. Derive asset IDs and tenantId from validated rows only
    validatedAssetIds = assetRows.map(a => a.id);
    assetTenantId = (tenantIds[0] ?? assetTenantId) as number;
  }

  const [scan] = await db.insert(scansTable).values({
    ...parsed.data, assetIds: validatedAssetIds, tenantId: assetTenantId, status: "pending",
    startedAt: new Date(),
  }).returning();

  if (scan.assetIds.length > 0) {
    await db.insert(scanJobsTable).values(
      (scan.assetIds as number[]).map(assetId => ({ scanId: scan.id, assetId, status: "pending" }))
    );
    setImmediate(async () => {
      try {
        const [allTools, pipelineSteps] = await Promise.all([
          db.select().from(securityToolsTable).where(eq(securityToolsTable.tenantId, scan.tenantId)),
          db.select({ toolId: toolPipelineStepsTable.toolId }).from(toolPipelineStepsTable)
            .where(and(eq(toolPipelineStepsTable.tenantId, scan.tenantId), eq(toolPipelineStepsTable.isEnabled, true))),
        ]);
        const enabledToolIds = new Set(pipelineSteps.map(p => p.toolId));
        const enabledTools = allTools.filter(t => enabledToolIds.has(t.id));
        const toolsToRun = enabledTools.length > 0 ? enabledTools : allTools;
        const configs: AssetToolConfigItem[] = (scan.assetIds as number[]).map(assetId => ({
          assetId,
          toolIds: toolsToRun.map(t => t.id),
        }));
        await enqueueAndRun({
          scanId: scan.id,
          tenantId: scan.tenantId,
          userId: req.user!.userId,
          configs,
          allTools,
          enabledTools: toolsToRun,
        });
      } catch {
        await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
          .where(eq(scansTable.id, scan.id)).catch(() => {});
      }
    });
  }
  await logAudit(req.user!, "create_scan", "scan", scan.id);
  res.status(201).json(toScanResponse(scan));
});

router.get("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;
  let scan: typeof scansTable.$inferSelect | undefined;
  if (role === "super_admin" || role === "admin" || role === "manager") {
    [scan] = await db.select().from(scansTable).where(eq(scansTable.id, params.data.scanId));
  } else {
    [scan] = await db.select().from(scansTable)
      .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)));
  }
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(toScanResponse(scan));
});

router.delete("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;
  await db.delete(scanJobsTable).where(eq(scanJobsTable.scanId, params.data.scanId));
  const deleteWhere = (role === "super_admin" || role === "admin")
    ? eq(scansTable.id, params.data.scanId)
    : and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId));
  const [scan] = await db.delete(scansTable).where(deleteWhere).returning();
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.sendStatus(204);
});

router.post("/scans/:scanId/cancel", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CancelScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const role = req.user!.role;
  const cancelWhere = (role === "super_admin" || role === "admin")
    ? eq(scansTable.id, params.data.scanId)
    : and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId));
  const [scan] = await db.update(scansTable).set({ status: "cancelled", completedAt: new Date() })
    .where(cancelWhere).returning();
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(toScanResponse(scan));
});

router.get("/scans/:scanId/jobs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = ListScanJobsParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const jobs = await db.select().from(scanJobsTable).where(eq(scanJobsTable.scanId, params.data.scanId));
  res.json(jobs.map(j => ({
    id: j.id, scanId: j.scanId, assetId: j.assetId, status: j.status,
    result: j.result, errorMessage: j.errorMessage,
    startedAt: j.startedAt?.toISOString() ?? null,
    completedAt: j.completedAt?.toISOString() ?? null,
    createdAt: j.createdAt.toISOString(),
  })));
});

export default router;
