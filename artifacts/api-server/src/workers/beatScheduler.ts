/**
 * Beat scheduler — polls both asset-level scan frequencies and the
 * scan_schedules table (nextRunAt-based).
 *
 * When Redis is available → enqueues to BullMQ (worker handles execution).
 * When Redis is absent   → calls enqueueAndRun() directly in-process
 *                          (no HTTP round-trip, no auth token needed).
 */
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import { db, assetsTable, scansTable, scanJobsTable, scanSchedulesTable, brandWatchlistItemsTable, brandThreatScansTable, securityToolsTable, toolPipelineStepsTable, alertsTable, platformSettingsTable, brandThreatSchedulesTable, aiMapperScanSchedulesTable, aiMapperScansTable, assetGroupMembersTable } from "@workspace/db";
import { runShadowItDiscovery } from "../lib/shadowItCorrelation";
import { and, eq, sql, lt, lte, isNotNull, ne, desc, inArray } from "drizzle-orm";
import { getScanQueue } from "../queues/scanQueue";
import { fetchLatestVersion } from "../lib/githubVersionChecker";
import { pushSseEvent } from "../lib/sseManager";

let _port = 8080;
let _intervalHandle: ReturnType<typeof setInterval> | null = null;
let _toolUpdateCheckRunning = false;

function isDue(asset: { scanFrequency: string; lastScannedAt: Date | null }): boolean {
  if (asset.scanFrequency === "manual" || asset.scanFrequency === "once") return false;
  if (!asset.lastScannedAt) return true;
  const elapsed = Date.now() - asset.lastScannedAt.getTime();
  const intervals: Record<string, number> = {
    hourly:  3_600_000,
    daily:   86_400_000,
    weekly:  604_800_000,
    monthly: 2_592_000_000,
  };
  const interval = intervals[asset.scanFrequency];
  return !!interval && elapsed >= interval;
}

/**
 * Parse a UTC offset string like "+05:30" or "-08:00" into milliseconds.
 * Returns 0 for invalid or missing values (= UTC).
 */
function parseUtcOffsetMs(timezone: string | null | undefined): number {
  const tz = (timezone ?? "+00:00").trim();
  const m = /^([+-])(\d{2}):(\d{2})$/.exec(tz);
  if (!m) return 0;
  const sign = m[1] === "+" ? 1 : -1;
  return sign * (parseInt(m[2]!, 10) * 60 + parseInt(m[3]!, 10)) * 60_000;
}

export function computeNextRunAt(
  frequency: string,
  runTime: string,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
  timezone?: string | null,
): Date {
  const offsetMs = parseUtcOffsetMs(timezone);
  const [h, m] = (runTime ?? "09:00").split(":").map(Number);

  // Shift "now" into the user's timezone for correct date arithmetic, then
  // shift the result back to UTC for storage. This handles day-boundary rollovers.
  const nowUtcMs = Date.now();
  const nowLocal = new Date(nowUtcMs + offsetMs);

  const next = new Date(nowLocal);
  next.setUTCSeconds(0, 0);
  next.setUTCHours(h ?? 9, m ?? 0, 0, 0);

  if (frequency === "hourly") {
    if (next <= nowLocal) next.setUTCHours(next.getUTCHours() + 1);
  } else if (frequency === "daily") {
    if (next <= nowLocal) next.setUTCDate(next.getUTCDate() + 1);
  } else if (frequency === "weekly") {
    const dow = dayOfWeek ?? 1;
    let diff = (dow - nowLocal.getUTCDay() + 7) % 7;
    if (diff === 0 && next <= nowLocal) diff = 7;
    next.setUTCDate(nowLocal.getUTCDate() + diff);
    next.setUTCHours(h ?? 9, m ?? 0, 0, 0);
  } else if (frequency === "monthly") {
    const dom = dayOfMonth ?? 1;
    next.setUTCDate(dom);
    if (next <= nowLocal) {
      next.setUTCMonth(next.getUTCMonth() + 1);
      next.setUTCDate(dom);
    }
  } else {
    next.setUTCDate(next.getUTCDate() + 1);
  }
  // Convert back to true UTC by reversing the timezone shift
  return new Date(next.getTime() - offsetMs);
}

/**
 * Runs a scheduled scan directly by calling enqueueAndRun() in-process.
 * Avoids the old HTTP round-trip approach which required a synthetic JWT
 * that requireAuth rejected (userId: 0 has no DB row → 401).
 */
async function runDirect(
  scanId: number,
  tenantId: number,
  assetIds: number[],
): Promise<void> {
  try {
    const { enqueueAndRun } = await import("../routes/pipelineScans");

    const [allTools, pipelineStepRows] = await Promise.all([
      db.select().from(securityToolsTable).where(eq(securityToolsTable.tenantId, tenantId)),
      db.select({ tool: securityToolsTable })
        .from(toolPipelineStepsTable)
        .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
        .where(and(eq(toolPipelineStepsTable.tenantId, tenantId), eq(toolPipelineStepsTable.isEnabled, true)))
        .orderBy(toolPipelineStepsTable.stepOrder),
    ]);
    const enabledTools = pipelineStepRows.map(p => p.tool);
    const configs = assetIds.map(assetId => ({ assetId, toolIds: [] as number[] }));

    logger.info({ scanId, tenantId, assetCount: configs.length }, "Beat: starting inline scan via direct enqueueAndRun");
    await enqueueAndRun({ scanId, tenantId, userId: 0, configs, allTools, enabledTools });
    logger.info({ scanId }, "Beat: inline scan completed");
  } catch (err: unknown) {
    // Queue full — leave scan in "pending" state so the next beat cycle can retry.
    // Do NOT mark as "failed" — the scan has not actually failed, just been deferred.
    const { QueueFullError } = await import("../routes/pipelineScans");
    if (err instanceof QueueFullError) {
      logger.warn({ scanId, depth: err.queueDepth, cap: err.queueCap }, "Beat: queue full — scan deferred, will retry on next cycle");
      return;
    }
    logger.error({ err, scanId }, "Beat: inline scan failed");
    await db.update(scansTable)
      .set({ status: "failed", completedAt: new Date() })
      .where(eq(scansTable.id, scanId))
      .catch(() => {});
  }
}

async function enqueueOrRun(
  scanId: number,
  tenantId: number,
  assetIds: number[],
): Promise<void> {
  const queue = getScanQueue();
  if (queue) {
    await queue.add(
      `scheduled:${scanId}`,
      { scanId, tenantId, userId: 0, assetIds },
      { delay: 0 },
    );
    logger.info({ tenantId, scanId }, "Beat: scan enqueued to BullMQ");
  } else {
    setImmediate(() => runDirect(scanId, tenantId, assetIds).catch(() => {}));
    logger.info({ tenantId, scanId }, "Beat: inline scan triggered");
  }
}

async function dispatchDueAssets(): Promise<void> {
  const assets = await db
    .select({
      id:            assetsTable.id,
      tenantId:      assetsTable.tenantId,
      scanFrequency: assetsTable.scanFrequency,
      lastScannedAt: assetsTable.lastScannedAt,
    })
    .from(assetsTable)
    .where(
      and(
        eq(assetsTable.isActive, true),
        eq(assetsTable.verificationStatus, "verified"),
        sql`${assetsTable.scanFrequency} != 'manual'`,
      ),
    );

  const dueAssets = assets.filter(isDue);
  if (dueAssets.length === 0) return;

  const byTenant = new Map<number, typeof dueAssets>();
  for (const a of dueAssets) {
    const tid = a.tenantId!;
    if (!byTenant.has(tid)) byTenant.set(tid, []);
    byTenant.get(tid)!.push(a);
  }

  for (const [tenantId, tenantAssets] of byTenant) {
    const allDueIds = tenantAssets.map((a) => a.id);

    // Double-fire guard: skip assets already covered by an active named Scan Schedule.
    // Combining scanFrequency + a named schedule on the same asset would launch two scans.
    const scheduleRows = await db
      .select({ assetToolConfig: scanSchedulesTable.assetToolConfig })
      .from(scanSchedulesTable)
      .where(and(eq(scanSchedulesTable.tenantId, tenantId), eq(scanSchedulesTable.status, "active")));
    const scheduledAssetIds = new Set<number>(
      scheduleRows.flatMap(r => {
        const cfg = r.assetToolConfig as { assetId: number }[] | null;
        return Array.isArray(cfg) ? cfg.map(c => c.assetId) : [];
      }),
    );
    const assetIds = allDueIds.filter(id => !scheduledAssetIds.has(id));
    if (assetIds.length < allDueIds.length) {
      logger.info(
        { tenantId, skipped: allDueIds.length - assetIds.length },
        "Beat: asset-frequency — skipping assets already covered by named Scan Schedules",
      );
    }
    if (assetIds.length === 0) {
      logger.info({ tenantId }, "Beat: asset-frequency scan skipped — all due assets covered by named Schedules");
      continue;
    }

    // Duplicate-run guard: filter out assets already covered by an active scan.
    // "Running" scans older than 10 minutes are considered stuck (server restarted
    // before startup recovery ran) and are NOT treated as blocking — a new scan
    // will be created and the stuck one will be cleaned up on next restart.
    const STUCK_THRESHOLD_MS = 10 * 60 * 1000;
    const activeScans = await db
      .select({ assetIds: scansTable.assetIds, status: scansTable.status, startedAt: scansTable.startedAt })
      .from(scansTable)
      .where(and(
        eq(scansTable.tenantId, tenantId),
        inArray(scansTable.status, ["running", "pending"]),
      ));
    const busyAssetIds = new Set<number>(
      activeScans
        .filter(s => {
          if (s.status === "running" && s.startedAt) {
            const ageMs = Date.now() - new Date(s.startedAt).getTime();
            if (ageMs > STUCK_THRESHOLD_MS) return false; // treat as not blocking
          }
          return true;
        })
        .flatMap(s => Array.isArray(s.assetIds) ? (s.assetIds as number[]) : []),
    );
    const freeAssetIds = assetIds.filter(id => !busyAssetIds.has(id));
    if (freeAssetIds.length === 0) {
      logger.info({ tenantId }, "Beat: asset-frequency scan skipped — all due assets already have active scans");
      continue;
    }

    const [scan] = await db
      .insert(scansTable)
      .values({
        tenantId,
        name: `Scheduled Scan — ${new Date().toLocaleDateString()}`,
        type: "scheduled",
        status: "pending",
        assetIds: freeAssetIds,
        startedAt: new Date(),
      })
      .returning();

    await db.insert(scanJobsTable).values(
      freeAssetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
    );

    await enqueueOrRun(scan.id, tenantId, freeAssetIds);
    logger.info({ tenantId, scanId: scan.id, count: freeAssetIds.length }, "Beat: asset-frequency scan dispatched");
  }
}

async function dispatchDueSchedules(): Promise<void> {
  const now = new Date();
  const dueSchedules = await db
    .select()
    .from(scanSchedulesTable)
    .where(
      and(
        eq(scanSchedulesTable.status, "active"),
        isNotNull(scanSchedulesTable.nextRunAt),
        lte(scanSchedulesTable.nextRunAt, now),
      ),
    );

  for (const schedule of dueSchedules) {
    try {
      let rawIds: number[];

      // If schedule is group-scoped, expand current group members dynamically
      const scheduleGroupId = (schedule as any).groupId as number | null;
      if (scheduleGroupId) {
        const groupMembers = await db
          .select({ assetId: assetGroupMembersTable.assetId })
          .from(assetGroupMembersTable)
          .where(eq(assetGroupMembersTable.groupId, scheduleGroupId));
        rawIds = groupMembers.map((m) => m.assetId);
        if (rawIds.length === 0) {
          logger.warn({ scheduleId: schedule.id, groupId: scheduleGroupId }, "Beat: group schedule skipped — group has no members");
          continue;
        }
      } else {
        const config = schedule.assetToolConfig as { assetId: number }[] | null;
        if (!config || !Array.isArray(config) || config.length === 0) continue;
        rawIds = config.map((c) => c.assetId).filter(Boolean);
        if (rawIds.length === 0) continue;
      }

      // Only scan assets that have been verified — avoids 422 from pipeline-run
      const verifiedRows = await db
        .select({ id: assetsTable.id })
        .from(assetsTable)
        .where(
          and(
            eq(assetsTable.verificationStatus, "verified"),
            eq(assetsTable.tenantId, schedule.tenantId),
            inArray(assetsTable.id, rawIds),
          ),
        );
      const assetIds = verifiedRows.map((r) => r.id);
      if (assetIds.length === 0) {
        logger.warn({ scheduleId: schedule.id }, "Beat: schedule skipped — no verified assets");
        continue;
      }

      // Duplicate-run guard: skip if the previous scan for this schedule is still running
      if (schedule.lastScanId) {
        const [lastScan] = await db
          .select({ status: scansTable.status })
          .from(scansTable)
          .where(eq(scansTable.id, schedule.lastScanId));
        if (lastScan?.status === "running" || lastScan?.status === "pending") {
          logger.warn({ scheduleId: schedule.id, lastScanId: schedule.lastScanId }, "Beat: schedule skipped — previous scan still running");
          continue;
        }
      }

      const [scan] = await db
        .insert(scansTable)
        .values({
          tenantId: schedule.tenantId,
          name: `${schedule.name} — ${now.toLocaleDateString()}`,
          type: "scheduled",
          status: "pending",
          assetIds,
          startedAt: now,
        })
        .returning();

      await db.insert(scanJobsTable).values(
        assetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
      );

      const nextRunAt = computeNextRunAt(
        schedule.frequency ?? "daily",
        schedule.runTime ?? "09:00",
        schedule.dayOfWeek,
        schedule.dayOfMonth,
        (schedule as any).timezone,
      );

      await db
        .update(scanSchedulesTable)
        .set({ lastRunAt: now, lastScanId: scan.id, nextRunAt })
        .where(eq(scanSchedulesTable.id, schedule.id));

      await enqueueOrRun(scan.id, schedule.tenantId, assetIds);
      logger.info(
        { scheduleId: schedule.id, scanId: scan.id, nextRunAt },
        "Beat: schedule dispatched",
      );
    } catch (err) {
      logger.error({ err, scheduleId: schedule.id }, "Beat: failed to dispatch schedule");
    }
  }
}

export function computeWatchlistNextScanAt(
  frequency: string,
  from: Date,
  scanTime?: string | null,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
): Date | null {
  if (!frequency || frequency === "none") return null;
  const [h, m] = (scanTime ?? "03:00").split(":").map(Number);
  const next = new Date(from);

  if (frequency === "daily") {
    next.setDate(next.getDate() + 1);
    next.setUTCHours(h ?? 3, m ?? 0, 0, 0);
    return next;
  }
  if (frequency === "weekly") {
    const dow = dayOfWeek ?? 1; // default Monday
    let diff = (dow - from.getDay() + 7) % 7;
    if (diff === 0) diff = 7;
    next.setDate(from.getDate() + diff);
    next.setUTCHours(h ?? 3, m ?? 0, 0, 0);
    return next;
  }
  if (frequency === "monthly") {
    const dom = dayOfMonth ?? 1;
    next.setDate(dom);
    next.setUTCHours(h ?? 3, m ?? 0, 0, 0);
    if (next <= from) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(dom);
      next.setUTCHours(h ?? 3, m ?? 0, 0, 0);
    }
    return next;
  }
  return null;
}

export async function dispatchDueWatchlistDomains(): Promise<void> {
  const now = new Date();
  const dueItems = await db
    .select()
    .from(brandWatchlistItemsTable)
    .where(
      and(
        eq(brandWatchlistItemsTable.type, "domain"),
        isNotNull(brandWatchlistItemsTable.nextScanAt),
        lte(brandWatchlistItemsTable.nextScanAt, now),
      ),
    );

  if (dueItems.length === 0) return;

  const { runBrandThreatScan } = await import("../lib/brandThreatRunner");
  const { brandThreatResultsTable, phishingDetectionsTable, dataLeakResultsTable, brandAbuseResultsTable, adMonitoringResultsTable } = await import("@workspace/db");

  for (const item of dueItems) {
    try {
      const domain = item.value.toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/^www\./, "")
        .split("/")[0]!
        .split("?")[0]!;

      if (!domain) continue;

      const [existing] = await db
        .select()
        .from(brandThreatScansTable)
        .where(
          and(
            eq(brandThreatScansTable.tenantId, item.tenantId),
            eq(brandThreatScansTable.domain, domain),
          ),
        );

      let scanId: number;
      let prevScanSummary: Record<string, number> | null = null;

      if (existing) {
        // Concurrency guard: skip if a scan for this domain is already in progress
        if (existing.status === "running" || existing.status === "pending") {
          const nextScanAt = computeWatchlistNextScanAt(
            item.frequency ?? "none",
            now,
            item.scanTime,
            item.dayOfWeek,
            item.dayOfMonth,
          );
          await db.update(brandWatchlistItemsTable)
            .set({ nextScanAt })
            .where(eq(brandWatchlistItemsTable.id, item.id));
          logger.warn(
            { scanId: existing.id, domain, status: existing.status },
            "Beat: watchlist brand scan already in progress — skipped, rescheduled",
          );
          continue;
        }

        // Snapshot the current scan summary BEFORE deletion for delta computation
        prevScanSummary = {
          totalPermutations: existing.totalPermutations ?? 0,
          liveCount:         existing.liveCount ?? 0,
          registeredCount:   existing.registeredCount ?? 0,
          phishingCount:     existing.phishingCount ?? 0,
          dataLeakCount:     existing.dataLeakCount ?? 0,
          brandAbuseCount:   existing.brandAbuseCount ?? 0,
        };

        // Delete prior child rows so new scan results are clean
        await Promise.all([
          db.update(brandThreatResultsTable).set({ archivedAt: new Date() }).where(eq(brandThreatResultsTable.scanId, existing.id)),
          db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, existing.id)),
          db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, existing.id)),
          db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, existing.id)),
          db.delete(adMonitoringResultsTable).where(eq(adMonitoringResultsTable.scanId, existing.id)),
        ]);
        await db.update(brandThreatScansTable)
          .set({
            status: "pending",
            totalPermutations: 0,
            liveCount: 0,
            registeredCount: 0,
            phishingRisk: "low",
            fuzzerBreakdown: null,
            error: null,
            completedAt: null,
            dataLeakCount: 0,
            phishingCount: 0,
            brandAbuseCount: 0,
            darkWebCount: 0,
          })
          .where(eq(brandThreatScansTable.id, existing.id));
        scanId = existing.id;
      } else {
        const [created] = await db.insert(brandThreatScansTable).values({
          tenantId: item.tenantId,
          domain,
          status: "pending",
        }).returning();
        scanId = created!.id;
      }

      const nextScanAt = computeWatchlistNextScanAt(
        item.frequency ?? "none",
        now,
        item.scanTime,
        item.dayOfWeek,
        item.dayOfMonth,
      );

      await db.update(brandWatchlistItemsTable)
        .set({
          lastScanAt: now,
          lastScanId: scanId,
          nextScanAt,
          prevScanSummary: prevScanSummary ?? undefined,
        })
        .where(eq(brandWatchlistItemsTable.id, item.id));

      setImmediate(async () => {
        try {
          await runBrandThreatScan(scanId, domain);
          logger.info({ scanId, domain, itemId: item.id }, "Beat: watchlist brand scan completed");
        } catch (err) {
          logger.error({ err, scanId, domain }, "Beat: watchlist brand scan failed");
        }
      });

      logger.info({ itemId: item.id, domain, scanId, nextScanAt }, "Beat: watchlist domain scan dispatched");
    } catch (err) {
      logger.error({ err, itemId: item.id }, "Beat: failed to dispatch watchlist item");
    }
  }
}

async function dispatchDueBrandThreatSchedules(): Promise<void> {
  const now = new Date();
  const dueSchedules = await db
    .select()
    .from(brandThreatSchedulesTable)
    .where(
      and(
        eq(brandThreatSchedulesTable.status, "active"),
        isNotNull(brandThreatSchedulesTable.nextRunAt),
        lte(brandThreatSchedulesTable.nextRunAt, now),
      ),
    );

  if (dueSchedules.length === 0) return;

  const { triggerBrandThreatScan } = await import("../lib/brandThreatRunner");

  for (const schedule of dueSchedules) {
    try {
      await triggerBrandThreatScan(schedule.tenantId, schedule.domain);
      const nextRunAt = computeNextRunAt(
        schedule.frequency ?? "weekly",
        schedule.runTime ?? "09:00",
        schedule.dayOfWeek,
        schedule.dayOfMonth,
      );
      await db
        .update(brandThreatSchedulesTable)
        .set({ lastRunAt: now, nextRunAt })
        .where(eq(brandThreatSchedulesTable.id, schedule.id));
      logger.info({ scheduleId: schedule.id, domain: schedule.domain, nextRunAt }, "Beat: brand threat schedule dispatched");
    } catch (err) {
      logger.error({ err, scheduleId: schedule.id }, "Beat: brand threat schedule dispatch failed");
    }
  }
}

async function dispatchDueWatchlistNonDomainItems(): Promise<void> {
  const now = new Date();
  const dueItems = await db
    .select()
    .from(brandWatchlistItemsTable)
    .where(
      and(
        ne(brandWatchlistItemsTable.type, "domain"),
        isNotNull(brandWatchlistItemsTable.nextScanAt),
        lte(brandWatchlistItemsTable.nextScanAt, now),
      ),
    );

  if (dueItems.length === 0) return;

  const { getPlatformSetting } = await import("../routes/platformSettings");
  const { intelxSearch, intelxTypeToBucket } = await import("../lib/intelxClient");
  const { scanBrandAbuse } = await import("../lib/brandAbuseScanner");
  const { dataLeakResultsTable, brandAbuseResultsTable } = await import("@workspace/db");

  const intelxKey = await getPlatformSetting("intelx_api_key").catch(() => null);
  const youtubeKey = await getPlatformSetting("youtube_api_key").catch(() => null);

  for (const item of dueItems) {
    try {
      // Find most recent completed brand threat scan for this tenant to attach results to
      const [recentScan] = await db
        .select({ id: brandThreatScansTable.id })
        .from(brandThreatScansTable)
        .where(
          and(
            eq(brandThreatScansTable.tenantId, item.tenantId),
            eq(brandThreatScansTable.status, "done"),
          ),
        )
        .orderBy(desc(brandThreatScansTable.createdAt))
        .limit(1);

      const scanId = recentScan?.id ?? null;

      // IntelX search for keyword / email / social_handle
      if (intelxKey && ["keyword", "email", "social_handle"].includes(item.type)) {
        const results = await intelxSearch(item.value, intelxKey, 10).catch(() => null);
        if (results?.length) {
          const leakInserts: typeof dataLeakResultsTable.$inferInsert[] = [];
          const abuseInserts: typeof brandAbuseResultsTable.$inferInsert[] = [];
          for (const r of results) {
            const bucket = intelxTypeToBucket(r.type);
            const url = r.storageid ? `https://intelx.io/?did=${encodeURIComponent(r.storageid)}` : "https://intelx.io";
            const isBrandAbuse = ["forum", "reddit", "twitter", "linkedin", "documents"].includes(bucket);
            if (isBrandAbuse) {
              abuseInserts.push({
                tenantId: item.tenantId,
                scanId,
                type: "fake_social",
                platform: bucket.charAt(0).toUpperCase() + bucket.slice(1),
                url,
                title: r.name || `IntelX ${bucket} mention`,
                description: r.preview ?? `Watchlist "${item.value}" mention found in ${bucket} via IntelX`,
                evidenceSnippet: r.preview ?? undefined,
                risk: "medium",
              });
            } else {
              leakInserts.push({
                tenantId: item.tenantId,
                scanId,
                source: bucket === "darkweb" ? "IntelX-DarkWeb" : bucket === "pastes" ? "IntelX-Paste" : "IntelX",
                title: r.name || "IntelX match",
                breachDate: r.date ? r.date.slice(0, 10) : null,
                description: r.preview ?? `Watchlist item "${item.value}" found in dark/deep web via IntelX`,
                domainMatch: item.value,
                severity: bucket === "darkweb" ? "critical" : bucket === "credential" ? "high" : "medium",
                url,
              });
            }
          }
          if (leakInserts.length) {
            for (let i = 0; i < leakInserts.length; i += 50) {
              await db.insert(dataLeakResultsTable).values(leakInserts.slice(i, i + 50));
            }
          }
          if (abuseInserts.length) {
            for (let i = 0; i < abuseInserts.length; i += 50) {
              await db.insert(brandAbuseResultsTable).values(abuseInserts.slice(i, i + 50));
            }
          }
        }
      }

      // Social handle + mobile app: run brand abuse scanner
      if (item.type === "social_handle" || item.type === "mobile_app") {
        const brandName = item.value.replace(/^@/, "");
        const handles = item.type === "social_handle" ? [item.value] : [];
        const abuseData = await scanBrandAbuse(brandName, "", handles, youtubeKey ?? undefined).catch(() => ({ results: [], warnings: [] }));
        const abuseResults = abuseData.results;
        if (abuseResults.length) {
          await db.insert(brandAbuseResultsTable).values(
            abuseResults.map(a => ({
              tenantId: item.tenantId,
              scanId,
              type: a.type,
              platform: a.platform ?? undefined,
              url: a.url ?? undefined,
              title: a.title ?? undefined,
              description: a.description ?? undefined,
              evidenceSnippet: a.evidenceSnippet ?? undefined,
              risk: a.risk,
            })),
          );
        }
      }

      const nextScanAt = computeWatchlistNextScanAt(
        item.frequency ?? "none",
        now,
        item.scanTime,
        item.dayOfWeek,
        item.dayOfMonth,
      );
      await db
        .update(brandWatchlistItemsTable)
        .set({ lastScanAt: now, nextScanAt })
        .where(eq(brandWatchlistItemsTable.id, item.id));

      logger.info({ itemId: item.id, type: item.type, value: item.value }, "Beat: non-domain watchlist intel scan done");
    } catch (err) {
      logger.error({ err, itemId: item.id }, "Beat: non-domain watchlist item intel scan failed");
    }
  }
}

async function dispatchToolUpdateCheck(): Promise<void> {
  // In-memory lock prevents overlapping runs when the check takes >60s
  if (_toolUpdateCheckRunning) return;

  const SETTING_KEY = "tool_update_last_checked";
  const todayStr = new Date().toISOString().slice(0, 10);

  try {
    const [setting] = await db
      .select()
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, SETTING_KEY))
      .limit(1);

    // Skip if already completed today
    if (setting?.value === todayStr) return;

    _toolUpdateCheckRunning = true;

    // Write in-progress marker immediately so concurrent ticks skip this pass
    await db
      .insert(platformSettingsTable)
      .values({ key: SETTING_KEY, value: `${todayStr}:running`, label: "Tool Update Last Checked", category: "system" })
      .onConflictDoUpdate({ target: platformSettingsTable.key, set: { value: `${todayStr}:running` } });

    const tools = await db
      .select({
        id:             securityToolsTable.id,
        tenantId:       securityToolsTable.tenantId,
        name:           securityToolsTable.name,
        githubUrl:      securityToolsTable.githubUrl,
        currentVersion: securityToolsTable.currentVersion,
        latestVersion:  securityToolsTable.latestVersion,
        updateCommand:  securityToolsTable.updateCommand,
      })
      .from(securityToolsTable);

    // Group by GitHub URL — one API call per repo (handles multiple tenants/tools sharing same URL)
    const urlToTools = new Map<string, typeof tools>();
    for (const tool of tools) {
      if (!tool.githubUrl) continue;
      const arr = urlToTools.get(tool.githubUrl) ?? [];
      arr.push(tool);
      urlToTools.set(tool.githubUrl, arr);
    }

    let checked = 0;
    for (const [githubUrl, toolGroup] of urlToTools) {
      if (checked > 0) await new Promise((r) => setTimeout(r, 1_000));
      checked++;

      // fetchLatestVersion returns pre-normalized version (leading 'v' stripped)
      const latestVersion = await fetchLatestVersion(githubUrl);
      if (!latestVersion) continue;

      const now = new Date();

      for (const tool of toolGroup) {
        await db
          .update(securityToolsTable)
          .set({ latestVersion, toolUpdateCheckedAt: now })
          .where(eq(securityToolsTable.id, tool.id));

        // Normalize stored versions the same way (strip leading 'v') for comparison
        const prevLatest   = tool.latestVersion  ? tool.latestVersion.replace(/^v/i, "")  : null;
        const installedVer = tool.currentVersion ? tool.currentVersion.replace(/^v/i, "") : null;

        // Skip if nothing changed from last known latest
        if (latestVersion === prevLatest) continue;
        // Skip if user has already installed this version
        if (installedVer && installedVer === latestVersion) continue;

        const alertTitle  = `Tool update available: ${tool.name} ${latestVersion}`;
        const releasesUrl = `${githubUrl.replace(/\.git$/, "")}/releases/latest`;

        const [existing] = await db
          .select({ id: alertsTable.id })
          .from(alertsTable)
          .where(
            and(
              eq(alertsTable.tenantId, tool.tenantId),
              eq(alertsTable.type, "tool_update"),
              eq(alertsTable.isRead, false),
              eq(alertsTable.title, alertTitle),
            ),
          )
          .limit(1);

        if (existing) continue;

        const [alert] = await db.insert(alertsTable).values({
          tenantId:  tool.tenantId,
          title:     alertTitle,
          message:   `A new version of ${tool.name} is available (${latestVersion}).${installedVer ? ` Installed: ${tool.currentVersion}.` : ""} View release notes at ${releasesUrl}${tool.updateCommand ? ` — or run: ${tool.updateCommand}` : ""}.`,
          type:      "tool_update",
          severity:  "medium",
        }).returning();

        if (alert) {
          pushSseEvent(tool.tenantId, "new-alert", {
            id: alert.id, title: alert.title, message: alert.message,
            type: alert.type, severity: alert.severity, isRead: false,
            createdAt: alert.createdAt.toISOString(),
          });
        }

        logger.info({ toolName: tool.name, latestVersion, tenantId: tool.tenantId }, "Beat: tool update alert created");
      }
    }

    // Mark complete for today
    await db
      .insert(platformSettingsTable)
      .values({ key: SETTING_KEY, value: todayStr, label: "Tool Update Last Checked", category: "system" })
      .onConflictDoUpdate({ target: platformSettingsTable.key, set: { value: todayStr } });

    logger.info({ urlsChecked: checked }, "Beat: tool update check complete");
  } catch (err) {
    logger.error({ err }, "Beat: tool update check failed");
  } finally {
    _toolUpdateCheckRunning = false;
  }
}

let _queueDepthAlertCount = 0; // consecutive over-threshold poll count
let _lastQueueDepthAlertAt = 0; // epoch ms of last DB alert insertion

async function checkQueueDepth(): Promise<void> {
  try {
    const { getInProcessQueueStats } = await import("../routes/pipelineScans");
    const { activeScans: active, pendingCount: pending, maxConcurrent } = getInProcessQueueStats();

    // Also count BullMQ waiting jobs when Redis is available
    let bullmqWaiting = 0;
    try {
      const { getScanQueue } = await import("../queues/scanQueue");
      const q = getScanQueue();
      if (q) bullmqWaiting = await q.getWaitingCount();
    } catch { /* non-fatal */ }

    const totalWaiting = pending + bullmqWaiting;
    const total        = active + totalWaiting;
    const threshold    = maxConcurrent * 2;

    if (totalWaiting > 20 || total > threshold) {
      _queueDepthAlertCount++;
      if (_queueDepthAlertCount >= 2) {
        logger.warn({ active, pending, bullmqWaiting, total, threshold }, "Beat: scan queue depth alert — queue backing up");

        // Insert DB alert for all tenants with active/pending scans — max once per hour
        const now = Date.now();
        if (now - _lastQueueDepthAlertAt > 60 * 60 * 1000) {
          _lastQueueDepthAlertAt = now;
          try {
            const activeRows = await db
              .select({ tenantId: scansTable.tenantId })
              .from(scansTable)
              .where(sql`${scansTable.status} IN ('pending', 'running')`);
            const tenantIds = [...new Set(activeRows.map(r => r.tenantId))];
            if (tenantIds.length > 0) {
              await db.insert(alertsTable).values(
                tenantIds.map(tenantId => ({
                  tenantId,
                  title: `Queue depth alert — ${totalWaiting} jobs waiting`,
                  message: `The scan queue has ${totalWaiting} waiting jobs (threshold: 20). Consider investigating stuck scans or increasing capacity.`,
                  type: "queue_depth",
                  severity: "high",
                  isRead: false,
                })),
              );
              logger.info({ tenantCount: tenantIds.length }, "Beat: queue depth DB alerts inserted");
            }
          } catch (alertErr) {
            logger.error({ alertErr }, "Beat: failed to insert queue depth alerts");
          }
        }
        _queueDepthAlertCount = 0; // reset so we don't spam every 60s
      }
    } else {
      _queueDepthAlertCount = 0;
    }
  } catch {
    // Non-fatal
  }
}

async function dispatchDueScans(): Promise<void> {
  try {
    await Promise.all([
      dispatchDueAssets(),
      dispatchDueSchedules(),
      dispatchDueWatchlistDomains(),
      dispatchDueBrandThreatSchedules(),
      dispatchDueWatchlistNonDomainItems(),
      dispatchToolUpdateCheck(),
      checkQueueDepth(),
      dispatchTprmVendorRescans(),
      dispatchTprmComplianceExpiryReminders(),
      dispatchThreatIntelFeedRefresh(),
    ]);
  } catch (err) {
    logger.error({ err }, "Beat scheduler error");
  }
}

/**
 * On startup, find scans that got stuck in "pending" or "running" status during a
 * previous server crash or restart.  Re-enqueue them so they aren't silently lost.
 * Scans stuck for >10 min that are in "pending" status are safe to re-enqueue.
 * Scans stuck in "running" for >60 min are marked failed (they were mid-execution
 * when the process died and cannot be safely resumed).
 */
async function recoverStalePendingScans(): Promise<void> {
  try {
    const cutoffPending = new Date(Date.now() - 10 * 60 * 1000);
    const cutoffRunning = new Date(Date.now() - 60 * 60 * 1000);

    // Mark stale "running" scans as failed (cannot safely resume mid-execution)
    const staleRunning = await db
      .select({ id: scansTable.id, tenantId: scansTable.tenantId })
      .from(scansTable)
      .where(and(
        eq(scansTable.status, "running"),
        lt(scansTable.startedAt, cutoffRunning),
      ));

    for (const scan of staleRunning) {
      await db.update(scansTable)
        .set({ status: "failed" })
        .where(eq(scansTable.id, scan.id))
        .catch(() => {});
      logger.warn({ scanId: scan.id, tenantId: scan.tenantId }, "Beat: marked stale running scan as failed (server restart recovery)");
    }

    // Re-enqueue stale "pending" scans (server crashed before they could start)
    const stalePending = await db
      .select({
        id:       scansTable.id,
        tenantId: scansTable.tenantId,
        assetIds: scansTable.assetIds,
      })
      .from(scansTable)
      .where(and(
        eq(scansTable.status, "pending"),
        lt(scansTable.createdAt, cutoffPending),
      ));

    if (stalePending.length === 0) {
      logger.info("Beat: no stale pending scans to recover");
      return;
    }

    logger.info({ count: stalePending.length }, "Beat: recovering stale pending scans");

    for (const scan of stalePending) {
      try {
        const assetIds = Array.isArray(scan.assetIds) ? (scan.assetIds as number[]) : [];
        if (assetIds.length === 0) {
          await db.update(scansTable).set({ status: "failed" }).where(eq(scansTable.id, scan.id)).catch(() => {});
          logger.warn({ scanId: scan.id }, "Beat: stale pending scan has no assetIds — marking failed");
          continue;
        }
        await enqueueOrRun(scan.id, scan.tenantId, assetIds);
        logger.info({ scanId: scan.id, tenantId: scan.tenantId, assetCount: assetIds.length }, "Beat: stale pending scan re-enqueued");
      } catch (err) {
        logger.error({ err, scanId: scan.id }, "Beat: failed to recover stale pending scan");
      }
    }
  } catch (err) {
    logger.error({ err }, "Beat: stale scan recovery error (non-fatal)");
  }
}

/**
 * On startup, recover brand threat scans that were interrupted by a server restart.
 *
 * Three cases:
 *  1. status="running" + checkpoint="phase1_done" + permutationsCache present
 *     → Resume from Phase 2 (permutations already computed; skip the slow dnstwist step).
 *  2. status="running" + no checkpoint (interrupted before Phase 1 finished)
 *     → Mark "error"; the scan lost its in-flight data and cannot be safely resumed.
 *  3. status="pending" (server died before the scan ever started)
 *     → Re-trigger a fresh scan via setImmediate.
 *
 * The 15-second startup grace period in startBeatScheduler() ensures the DB
 * connection pool is ready before this function runs.
 */
export async function recoverStaleBrandThreatScans(): Promise<void> {
  try {
    // ── Case 1 & 2: All "running" scans ──────────────────────────────────────
    //
    // At startup time, ALL brand threat scans in "running" state are orphaned —
    // the Node.js process (and any setImmediate callbacks) that was executing
    // them no longer exists.  We must NOT gate by age here: a scan interrupted
    // 30 seconds before the restart is just as orphaned as one from 2 hours ago.
    //
    // Age gating is appropriate in the periodic beat loop (to avoid racing
    // against scans that just started), but NOT at startup where we have
    // authoritative knowledge that all in-process work is gone.
    const staleRunning = await db
      .select({
        id:                brandThreatScansTable.id,
        tenantId:          brandThreatScansTable.tenantId,
        domain:            brandThreatScansTable.domain,
        checkpoint:        brandThreatScansTable.checkpoint,
        permutationsCache: brandThreatScansTable.permutationsCache,
        createdAt:         brandThreatScansTable.createdAt,
      })
      .from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.status, "running"));

    if (staleRunning.length > 0) {
      logger.warn(
        { count: staleRunning.length },
        "Beat: found stale brand threat scans in 'running' state — starting recovery",
      );

      const { runBrandThreatScan } = await import("../lib/brandThreatRunner");
      type PermResult = Parameters<typeof runBrandThreatScan>[2];

      for (const scan of staleRunning) {
        const hasCheckpoint = scan.checkpoint === "phase1_done" && Array.isArray(scan.permutationsCache) && scan.permutationsCache.length > 0;

        if (hasCheckpoint) {
          // Resume from Phase 2 — Phase 1 permutations are safely cached in DB.
          logger.info(
            { scanId: scan.id, domain: scan.domain, cachedPerms: (scan.permutationsCache as unknown[]).length },
            "Beat: resuming interrupted brand threat scan from Phase 1 checkpoint",
          );
          const cached = scan.permutationsCache as unknown as PermResult;
          setImmediate(() => {
            runBrandThreatScan(scan.id, scan.domain, cached).catch(err => {
              logger.error({ err, scanId: scan.id }, "Beat: resumed brand threat scan failed");
            });
          });
        } else {
          // No checkpoint — Phase 1 data is lost; mark as error so the user can re-trigger.
          logger.warn(
            { scanId: scan.id, domain: scan.domain },
            "Beat: brand threat scan interrupted before Phase 1 checkpoint — marking error",
          );
          await db.update(brandThreatScansTable)
            .set({
              status: "error",
              error: "Scan interrupted by server restart before Phase 1 checkpoint; please re-run the scan.",
              completedAt: new Date(),
            })
            .where(eq(brandThreatScansTable.id, scan.id))
            .catch(() => {});
        }
      }
    } else {
      logger.info("Beat: no stale brand threat running scans to recover");
    }

    // ── Case 3: All "pending" scans ──────────────────────────────────────────
    //
    // Same rationale: at startup, a scan in "pending" state was never picked up
    // by the in-process queue.  Regardless of age, we should re-trigger it.
    const stalePending = await db
      .select({
        id:       brandThreatScansTable.id,
        tenantId: brandThreatScansTable.tenantId,
        domain:   brandThreatScansTable.domain,
      })
      .from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.status, "pending"));

    if (stalePending.length > 0) {
      logger.info({ count: stalePending.length }, "Beat: re-triggering stale pending brand threat scans");
      const { runBrandThreatScan } = await import("../lib/brandThreatRunner");

      for (const scan of stalePending) {
        setImmediate(() => {
          runBrandThreatScan(scan.id, scan.domain).catch(err => {
            logger.error({ err, scanId: scan.id }, "Beat: re-triggered brand threat scan failed");
          });
        });
        logger.info({ scanId: scan.id, domain: scan.domain }, "Beat: re-triggered stale pending brand threat scan");
      }
    } else {
      logger.info("Beat: no stale brand threat pending scans to recover");
    }
  } catch (err) {
    logger.error({ err }, "Beat: brand threat stale scan recovery error (non-fatal)");
  }
}

// ── AI Mapper orphan recovery — marks "running" scans stale after 45 min ──────
async function recoverStaleAiMapperScans(): Promise<void> {
  try {
    const cutoff = new Date(Date.now() - 45 * 60 * 1_000); // 45-minute timeout
    const stale = await db
      .update(aiMapperScansTable)
      .set({ status: "failed", completedAt: new Date() })
      .where(and(eq(aiMapperScansTable.status, "running"), lt(aiMapperScansTable.startedAt, cutoff)))
      .returning({ id: aiMapperScansTable.id, tenantId: aiMapperScansTable.tenantId });
    if (stale.length > 0) {
      logger.warn({ count: stale.length }, "Beat: timed out orphaned AI Mapper running scans");
    }
    // Also re-queue any pending AI Mapper scans older than 10 minutes (stuck in queue)
    const stalePending = new Date(Date.now() - 10 * 60 * 1_000);
    const stuck = await db
      .select({ id: aiMapperScansTable.id, tenantId: aiMapperScansTable.tenantId })
      .from(aiMapperScansTable)
      .where(and(eq(aiMapperScansTable.status, "pending"), lt(aiMapperScansTable.createdAt, stalePending)));
    for (const s of stuck) {
      try {
        fetch(`http://localhost:${_port}/api/ai-mapper/scans/${s.id}/run-internal`, {
          method: "POST",
          headers: { "x-internal-beat": "1" },
        }).catch(() => {});
        logger.info({ scanId: s.id }, "Beat: re-triggered stale pending AI Mapper scan");
      } catch { /* non-fatal */ }
    }
  } catch (err) {
    logger.error({ err }, "Beat: AI Mapper stale scan recovery error (non-fatal)");
  }
}

async function dispatchDueAiMapperSchedules(): Promise<void> {
  const now = new Date();
  const due = await db.select().from(aiMapperScanSchedulesTable).where(
    and(eq(aiMapperScanSchedulesTable.isActive, true), lte(aiMapperScanSchedulesTable.nextRunAt, now))
  );
  for (const sched of due) {
    try {
      const [{ c }] = await db.select({ c: sql<number>`count(*)` }).from(aiMapperScansTable).where(
        and(eq(aiMapperScansTable.tenantId, sched.tenantId), eq(aiMapperScansTable.status, "running"))
      );
      if (Number(c) >= 3) continue;
      const [newScan] = await db.insert(aiMapperScansTable).values({
        tenantId: sched.tenantId,
        status: "pending",
        queryPresets: sched.queryPresets as any,
        cidrScope: sched.cidrScope as any,
        triggeredBy: `schedule:${sched.id}`,
      } as any).returning();
      const nextRunAt = computeNextRunAt(sched.frequency, sched.runTime, sched.dayOfWeek, sched.dayOfMonth);
      await db.update(aiMapperScanSchedulesTable).set({ lastRunAt: now, nextRunAt, lastScanId: newScan.id } as any).where(eq(aiMapperScanSchedulesTable.id, sched.id));
      logger.info({ scheduleId: sched.id, tenantId: sched.tenantId, scanId: newScan.id }, "Beat: AI Mapper schedule triggered scan");
      // Trigger via internal API so the full scan pipeline runs
      fetch(`http://localhost:${_port}/api/ai-mapper/scans/${newScan.id}/run-internal`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-internal-beat": "1" },
      }).catch(() => {});
    } catch (err) {
      logger.error({ err, scheduleId: sched.id }, "Beat: AI Mapper schedule dispatch failed");
    }
  }
}

export async function startBeatScheduler(port = 8080): Promise<void> {
  _port = port;
  logger.info(
    process.env.REDIS_URL
      ? "Beat scheduler active (BullMQ mode)"
      : "Beat scheduler active (inline-execution mode with retry)",
  );

  // Run once after a 15-second grace period so the DB is ready
  setTimeout(() => {
    recoverStalePendingScans().catch(() => {});
    recoverStaleAiMapperScans().catch(() => {});
    recoverStaleBrandThreatScans().catch(() => {});
  }, 15_000);

  const beatPoll = async () => {
    await dispatchDueScans();
    await dispatchDueAiMapperSchedules().catch(err => logger.error({ err }, "Beat: AI Mapper schedule dispatch failed (non-fatal)"));
    await recoverStaleAiMapperScans().catch(err => logger.error({ err }, "Beat: AI Mapper orphan recovery failed (non-fatal)"));
  };
  setTimeout(async () => {
    await beatPoll();
    _intervalHandle = setInterval(beatPoll, 60 * 1_000);
    logger.info("Beat scheduler polling started (60 s interval)");
  }, 30_000);

  // Issue 5: Proxy score decay — runs every 6 hours to decay idle proxy health scores.
  // Proxies that haven't been used for 6+ hours have their scores decayed to avoid
  // stale high scores on proxies that haven't been validated recently.
  const runProxyDecay = async () => {
    try {
      const { decayIdleProxyScores } = await import("../lib/proxyManager.js");
      await decayIdleProxyScores();
    } catch (err) {
      logger.warn({ err }, "Beat: proxy decay job failed (non-fatal)");
    }
  };
  // Start after 2 min (let server warm up), then every 6 hours
  setTimeout(() => {
    runProxyDecay().catch(() => {});
    setInterval(runProxyDecay, 6 * 60 * 60_000);
  }, 2 * 60_000);

  // Auto-tuner: adjusts scan_delay_multiplier and waf_bypass_strategy per-tenant
  // based on observed WAF hit rates in orchestrator_waf_stats.  Runs every 10 minutes
  // starting 3 minutes after boot (let initial traffic accumulate first).
  const runAutoTuner = async () => {
    try {
      const { runAutoTunerCycle } = await import("../lib/autoTuner.js");
      await runAutoTunerCycle();
    } catch (err) {
      logger.warn({ err }, "Beat: auto-tuner cycle failed (non-fatal)");
    }
  };
  setTimeout(() => {
    runAutoTuner().catch(() => {});
    setInterval(runAutoTuner, 10 * 60_000);
  }, 3 * 60_000);

  // ── Shadow IT daily discovery (runs once per day per tenant) ─────────────────
  const runShadowItDailyDiscovery = async () => {
    try {
      const domainRows = await db
        .selectDistinct({ tenantId: assetsTable.tenantId })
        .from(assetsTable)
        .where(sql`${assetsTable.type} IN ('domain', 'subdomain', 'url')`);

      for (const { tenantId } of domainRows) {
        if (!tenantId) continue;
        setImmediate(() => {
          runShadowItDiscovery(tenantId as number).catch(err =>
            logger.warn({ err, tenantId }, "Beat: Shadow IT daily discovery failed (non-fatal)")
          );
        });
      }
      if (domainRows.length > 0) {
        logger.info({ tenantCount: domainRows.length }, "Beat: Shadow IT daily discovery dispatched");
      }
    } catch (err) {
      logger.warn({ err }, "Beat: Shadow IT daily discovery dispatch failed (non-fatal)");
    }
  };
  // Start 10 minutes after boot (let scans settle first), then every 24 hours
  setTimeout(() => {
    runShadowItDailyDiscovery().catch(() => {});
    setInterval(runShadowItDailyDiscovery, 24 * 60 * 60_000);
  }, 10 * 60_000);

  // ── IdP Sync (every 6 hours — syncs all active IdP connections per tenant) ─
  const runIdpSync = async () => {
    try {
      const { syncAllIdpConnections } = await import("../lib/idpConnectors/idpSync.js");
      const { db } = await import("@workspace/db");
      const { tenantsTable } = await import("@workspace/db");
      const tenants = await db.select({ id: tenantsTable.id })
        .from(tenantsTable)
        .where(eq(tenantsTable.isPlatform, false));
      for (const t of tenants) {
        await syncAllIdpConnections(t.id).catch(err =>
          logger.warn({ err, tenantId: t.id }, "Beat: IdP sync failed for tenant (non-fatal)")
        );
      }
      logger.info({ tenantCount: tenants.length }, "Beat: IdP sync dispatched");
    } catch (err) {
      logger.warn({ err }, "Beat: IdP sync dispatch failed (non-fatal)");
    }
  };
  // Start 15 minutes after boot, then every 6 hours
  setTimeout(() => {
    runIdpSync().catch(() => {});
    setInterval(runIdpSync, 6 * 60 * 60_000);
  }, 15 * 60_000);
}

// ── TPRM compliance expiry reminders ─────────────────────────────────────────
async function dispatchTprmComplianceExpiryReminders(): Promise<void> {
  try {
    const { tprmModuleAssignmentsTable, tprmComplianceDocumentsTable, tprmVendorsTable, alertsTable: _alertsTable } = await import("@workspace/db");
    const { ne: _ne, inArray: _inArray } = await import("drizzle-orm");
    const enabled = await db.select({ tenantId: tprmModuleAssignmentsTable.tenantId }).from(tprmModuleAssignmentsTable).where(eq(tprmModuleAssignmentsTable.isEnabled, true));
    if (enabled.length === 0) return;
    const tenantIds = enabled.map(t => t.tenantId);
    const now = new Date();
    const thirtyDaysOut = new Date(now.getTime() + 30 * 86400000);
    const docs = await db.select().from(tprmComplianceDocumentsTable)
      .where(and(
        _inArray(tprmComplianceDocumentsTable.tenantId, tenantIds),
        sql`expires_at IS NOT NULL AND expires_at > NOW() AND expires_at <= ${thirtyDaysOut.toISOString()}`,
        _ne(tprmComplianceDocumentsTable.status, "expired"),
      ));
    let reminded = 0;
    for (const doc of docs) {
      const daysLeft = Math.ceil((new Date(doc.expiresAt!).getTime() - now.getTime()) / 86400000);
      if (![30, 14, 7, 3, 1].includes(daysLeft)) continue;

      // Dedup: skip if an alert for this exact document + daysLeft milestone was already created today
      // Use a 20-hour window (beat runs every 60s so same milestone can't fire twice in one day)
      const todayStart = new Date(now);
      todayStart.setHours(0, 0, 0, 0);
      const dedupeTitle = `Compliance document expiring: ${doc.title}`;
      const [existing] = await db
        .select({ id: _alertsTable.id })
        .from(_alertsTable)
        .where(and(
          eq(_alertsTable.tenantId, doc.tenantId),
          eq(_alertsTable.title, dedupeTitle),
          eq(_alertsTable.type, "tprm_compliance_expiry" as any),
          sql`created_at >= ${todayStart.toISOString()}`,
        ));
      if (existing) continue;

      const [vendor] = await db.select({ companyName: tprmVendorsTable.companyName }).from(tprmVendorsTable).where(eq(tprmVendorsTable.id, doc.vendorId));
      // Dispatch through the full notification pipeline (DB alert + tenant rules + email/Slack/webhook)
      try {
        const { dispatchNotifications } = await import("../lib/notifier");
        await dispatchNotifications({
          tenantId: doc.tenantId,
          eventType: "tprm_compliance_expiry",
          title: dedupeTitle,
          message: `${doc.documentType.toUpperCase()} for "${vendor?.companyName ?? "Unknown"}" expires in ${daysLeft} day${daysLeft !== 1 ? "s" : ""}.`,
          severity: daysLeft <= 3 ? "high" : daysLeft <= 7 ? "medium" : "low",
        });
      } catch { /* non-fatal */ }
      reminded++;
    }
    if (reminded > 0) logger.info({ reminded }, "Beat: TPRM compliance expiry reminders dispatched");
  } catch (err) {
    logger.warn({ err }, "Beat: TPRM compliance expiry check failed (non-fatal)");
  }
}

// ── TPRM vendor rescan ────────────────────────────────────────────────────────
async function dispatchTprmVendorRescans(): Promise<void> {
  try {
    const { tprmModuleAssignmentsTable, tprmVendorsTable } = await import("@workspace/db");
    const { runFullVendorScan } = await import("../lib/tprmEnrichment.js");

    // Get all tenants with TPRM enabled
    const enabledTenants = await db
      .select({ tenantId: tprmModuleAssignmentsTable.tenantId })
      .from(tprmModuleAssignmentsTable)
      .where(eq(tprmModuleAssignmentsTable.isEnabled, true));

    if (enabledTenants.length === 0) return;

    const tenantIds = enabledTenants.map(t => t.tenantId);
    const now = new Date();

    // Find vendors that are due for a rescan based on their scanFrequency
    const vendors = await db
      .select({ id: tprmVendorsTable.id, tenantId: tprmVendorsTable.tenantId, scanFrequency: tprmVendorsTable.scanFrequency, lastScannedAt: tprmVendorsTable.lastScannedAt, status: tprmVendorsTable.status })
      .from(tprmVendorsTable)
      .where(and(
        inArray(tprmVendorsTable.tenantId, tenantIds),
        ne(tprmVendorsTable.scanFrequency, "manual"),
        ne(tprmVendorsTable.status, "scanning"),
      ));

    const intervals: Record<string, number> = {
      daily:   86_400_000,
      weekly:  604_800_000,
      monthly: 2_592_000_000,
    };

    let queued = 0;
    for (const vendor of vendors) {
      const interval = intervals[vendor.scanFrequency ?? "weekly"];
      if (!interval) continue;
      const lastScan = vendor.lastScannedAt?.getTime() ?? 0;
      if (now.getTime() - lastScan >= interval) {
        setImmediate(() => {
          runFullVendorScan(vendor.id, vendor.tenantId).catch(err =>
            logger.warn({ err, vendorId: vendor.id }, "Beat: TPRM vendor rescan failed")
          );
        });
        queued++;
      }
    }

    if (queued > 0) {
      logger.info({ queued }, "Beat: queued TPRM vendor rescans");
    }
  } catch (err) {
    logger.warn({ err }, "Beat: TPRM vendor rescan dispatch failed (non-fatal)");
  }
}

// ── Threat Intelligence feed refresh ─────────────────────────────────────────

const TI_FEED_INTERVAL_MS = 6 * 60 * 60_000; // every 6 hours
let _tiLastFeedRunTs = 0;
let _tiFeedRunning = false;

/**
 * Dispatches the TI feed refresh if it hasn't run in the last 6 hours.
 * Called every beat cycle (60s); throttled internally to 6h intervals.
 */
export async function dispatchThreatIntelFeedRefresh(): Promise<void> {
  const now = Date.now();
  if (_tiFeedRunning) return; // already in progress
  if (now - _tiLastFeedRunTs < TI_FEED_INTERVAL_MS) return; // not due yet

  // Check whether any tenant has TI module enabled
  try {
    const { threatIntelModuleAssignmentsTable } = await import("@workspace/db");
    const { gt: _gt } = await import("drizzle-orm");
    const enabled = await db.select({ tenantId: threatIntelModuleAssignmentsTable.tenantId })
      .from(threatIntelModuleAssignmentsTable)
      .where(eq(threatIntelModuleAssignmentsTable.isEnabled, true))
      .limit(1);
    if (enabled.length === 0) return; // no tenants enabled — skip
  } catch {
    // Table might not exist yet during first boot
    return;
  }

  _tiFeedRunning = true;
  _tiLastFeedRunTs = now;

  setImmediate(async () => {
    try {
      logger.info("Beat: starting TI feed refresh");
      const { runThreatIntelFeedRefresh } = await import("../lib/threatIntel/feedEngine.js");
      await runThreatIntelFeedRefresh();
      logger.info("Beat: TI feed refresh completed");
    } catch (err) {
      logger.warn({ err }, "Beat: TI feed refresh failed (non-fatal)");
    } finally {
      _tiFeedRunning = false;
    }
  });
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
