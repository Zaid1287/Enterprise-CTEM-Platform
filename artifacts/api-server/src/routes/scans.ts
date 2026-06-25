import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { getAmClientTenantIds } from "../lib/amScoping";
import { db, scansTable, scanJobsTable, assetsTable, findingsTable, riskScoresTable } from "@workspace/db";
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

    const [existing] = await db.select({ id: riskScoresTable.id })
      .from(riskScoresTable).where(eq(riskScoresTable.assetId, assetId));
    if (existing) {
      await db.update(riskScoresTable).set({ score, level }).where(eq(riskScoresTable.assetId, assetId));
    } else {
      await db.insert(riskScoresTable).values({ assetId, score, level });
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
    const allScans = await db.select().from(scansTable).where(and(...filters));
    const clientScans = allScans.filter(s =>
      Array.isArray(s.assetIds) && (s.assetIds as number[]).some(id => assignedIds.has(id))
    );
    res.json(clientScans.map(toScanResponse)); return;
  }

  let tenantFilter;
  if (role === "account_manager") {
    const ids = await getAmClientTenantIds(req.user!.userId);
    if (ids.length === 0) { res.json([]); return; }
    const clientAssets = await db.select({ id: assetsTable.id }).from(assetsTable)
      .where(inArray(assetsTable.tenantId, ids));
    const clientAssetIds = clientAssets.map(a => a.id);
    if (clientAssetIds.length === 0) { res.json([]); return; }
    const allScansRaw = await db.select().from(scansTable);
    const amScans = allScansRaw.filter(s =>
      Array.isArray(s.assetIds) && (s.assetIds as number[]).some(id => clientAssetIds.includes(id))
    );
    const filtered = q.success && q.data.status
      ? amScans.filter(s => s.status === (q.data as any).status)
      : amScans;
    res.json(filtered.map(toScanResponse)); return;
  }
  tenantFilter = eq(scansTable.tenantId, req.user!.tenantId);
  const filters = [tenantFilter];
  if (q.success && q.data.status) filters.push(eq(scansTable.status, q.data.status));
  const scans = await db.select().from(scansTable).where(and(...filters));
  res.json(scans.map(toScanResponse));
});

router.post("/scans", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  // Enforce ownership verification — no scanning unverified assets
  const assetIds = (parsed.data as any).assetIds as number[] | undefined;
  if (assetIds && assetIds.length > 0) {
    const assetRows = await db
      .select({ id: assetsTable.id, name: assetsTable.name, verificationStatus: assetsTable.verificationStatus })
      .from(assetsTable)
      .where(and(inArray(assetsTable.id, assetIds), eq(assetsTable.tenantId, req.user!.tenantId)));
    const unverified = assetRows.filter(a => a.verificationStatus !== "verified");
    if (unverified.length > 0) {
      res.status(422).json({
        error: "Cannot scan unverified assets. Verify ownership before scanning.",
        unverifiedAssets: unverified.map(a => ({ id: a.id, name: a.name })),
      });
      return;
    }
  }

  const [scan] = await db.insert(scansTable).values({
    ...parsed.data, tenantId: req.user!.tenantId, status: "pending",
    startedAt: new Date(),
  }).returning();

  if (scan.assetIds.length > 0) {
    await db.insert(scanJobsTable).values(
      scan.assetIds.map(assetId => ({ scanId: scan.id, assetId, status: "pending" }))
    );
    setTimeout(async () => {
      try {
        await db.update(scansTable).set({ status: "running" }).where(eq(scansTable.id, scan.id));
        await db.update(scanJobsTable).set({ status: "running" }).where(eq(scanJobsTable.scanId, scan.id));
      } catch { /* ignore */ }
      setTimeout(async () => {
        try {
          const completedAt = new Date();
          await db.update(scansTable).set({ status: "completed", completedAt }).where(eq(scansTable.id, scan.id));
          await db.update(scanJobsTable).set({ status: "completed", completedAt }).where(eq(scanJobsTable.scanId, scan.id));
          await finalizeScannedAssets(scan.assetIds as number[]);
        } catch { /* ignore */ }
      }, 8000);
    }, 2000);
  }
  await logAudit(req.user!, "create_scan", "scan", scan.id);
  res.status(201).json(toScanResponse(scan));
});

router.get("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = GetScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [scan] = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(toScanResponse(scan));
});

router.delete("/scans/:scanId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = DeleteScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  await db.delete(scanJobsTable).where(eq(scanJobsTable.scanId, params.data.scanId));
  const [scan] = await db.delete(scansTable)
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  res.sendStatus(204);
});

router.post("/scans/:scanId/cancel", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const params = CancelScanParams.safeParse(req.params);
  if (!params.success) { res.status(400).json({ error: params.error.message }); return; }
  const [scan] = await db.update(scansTable).set({ status: "cancelled", completedAt: new Date() })
    .where(and(eq(scansTable.id, params.data.scanId), eq(scansTable.tenantId, req.user!.tenantId)))
    .returning();
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
