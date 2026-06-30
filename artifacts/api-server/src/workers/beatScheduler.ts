/**
 * Beat scheduler — polls both asset-level scan frequencies and the
 * scan_schedules table (nextRunAt-based).
 *
 * When Redis is available → enqueues to BullMQ (worker handles execution).
 * When Redis is absent   → runs inline via internal HTTP with exponential
 *                          back-off retry (up to 3 attempts per scan).
 */
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import { db, assetsTable, scansTable, scanJobsTable, scanSchedulesTable, brandWatchlistItemsTable, brandThreatScansTable, securityToolsTable, alertsTable, platformSettingsTable, brandThreatSchedulesTable } from "@workspace/db";
import { and, eq, sql, lte, isNotNull, ne, desc, inArray } from "drizzle-orm";
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

export function computeNextRunAt(
  frequency: string,
  runTime: string,
  dayOfWeek?: number | null,
  dayOfMonth?: number | null,
): Date {
  const [h, m] = (runTime ?? "09:00").split(":").map(Number);
  const now = new Date();
  const next = new Date();
  next.setSeconds(0, 0);
  next.setHours(h ?? 9, m ?? 0, 0, 0);

  if (frequency === "hourly") {
    if (next <= now) next.setHours(next.getHours() + 1);
  } else if (frequency === "daily") {
    if (next <= now) next.setDate(next.getDate() + 1);
  } else if (frequency === "weekly") {
    const dow = dayOfWeek ?? 1;
    let diff = (dow - now.getDay() + 7) % 7;
    if (diff === 0 && next <= now) diff = 7;
    next.setDate(now.getDate() + diff);
    next.setHours(h ?? 9, m ?? 0, 0, 0);
  } else if (frequency === "monthly") {
    const dom = dayOfMonth ?? 1;
    next.setDate(dom);
    if (next <= now) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(dom);
    }
  } else {
    next.setDate(next.getDate() + 1);
  }
  return next;
}

async function runWithRetry(
  scanId: number,
  tenantId: number,
  assetIds: number[],
  maxAttempts = 3,
): Promise<void> {
  const { signAccessToken } = await import("../lib/auth");
  const token = signAccessToken({ userId: 0, tenantId, role: "admin", email: "" });
  const origin = `http://127.0.0.1:${_port}`;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await db
        .update(scansTable)
        .set({ status: "running", startedAt: new Date() })
        .where(eq(scansTable.id, scanId));

      const resp = await fetch(`${origin}/api/scans/pipeline-run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ scanId, assetIds }),
      });

      if (!resp.ok) throw new Error(`Pipeline HTTP ${resp.status}`);
      logger.info({ scanId, attempt }, "Beat: inline scan started");
      return;
    } catch (err) {
      if (attempt === maxAttempts) {
        logger.error({ err, scanId }, "Beat: inline scan failed after retries");
        await db
          .update(scansTable)
          .set({ status: "failed" })
          .where(eq(scansTable.id, scanId))
          .catch(() => {});
      } else {
        const delay = 5_000 * Math.pow(2, attempt - 1);
        logger.warn({ err, attempt, scanId, delay }, "Beat: retrying inline scan");
        await new Promise((r) => setTimeout(r, delay));
      }
    }
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
    setImmediate(() => runWithRetry(scanId, tenantId, assetIds).catch(() => {}));
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
    const assetIds = tenantAssets.map((a) => a.id);

    // Duplicate-run guard: filter out any assets already covered by a running/pending scan
    const activeScans = await db
      .select({ assetIds: scansTable.assetIds })
      .from(scansTable)
      .where(and(
        eq(scansTable.tenantId, tenantId),
        inArray(scansTable.status, ["running", "pending"]),
      ));
    const busyAssetIds = new Set<number>(
      activeScans.flatMap(s => Array.isArray(s.assetIds) ? (s.assetIds as number[]) : []),
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
      const config = schedule.assetToolConfig as { assetId: number }[] | null;
      if (!config || !Array.isArray(config) || config.length === 0) continue;
      const rawIds = config.map((c) => c.assetId).filter(Boolean);
      if (rawIds.length === 0) continue;

      // Only scan assets that have been verified — avoids 422 from pipeline-run
      const verifiedRows = await db
        .select({ id: assetsTable.id })
        .from(assetsTable)
        .where(
          and(
            eq(assetsTable.verificationStatus, "verified"),
            eq(assetsTable.tenantId, schedule.tenantId),
          ),
        );
      const verifiedSet = new Set(verifiedRows.map((r) => r.id));
      const assetIds = rawIds.filter((id) => verifiedSet.has(id));
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

function computeWatchlistNextScanAt(
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

async function dispatchDueWatchlistDomains(): Promise<void> {
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
        const abuseResults = await scanBrandAbuse(brandName, "", handles, youtubeKey ?? undefined).catch(() => []);
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

async function dispatchDueScans(): Promise<void> {
  try {
    await Promise.all([
      dispatchDueAssets(),
      dispatchDueSchedules(),
      dispatchDueWatchlistDomains(),
      dispatchDueBrandThreatSchedules(),
      dispatchDueWatchlistNonDomainItems(),
      dispatchToolUpdateCheck(),
    ]);
  } catch (err) {
    logger.error({ err }, "Beat scheduler error");
  }
}

export async function startBeatScheduler(port = 8080): Promise<void> {
  _port = port;
  logger.info(
    process.env.REDIS_URL
      ? "Beat scheduler active (BullMQ mode)"
      : "Beat scheduler active (inline-execution mode with retry)",
  );

  setTimeout(async () => {
    await dispatchDueScans();
    _intervalHandle = setInterval(dispatchDueScans, 60 * 1_000);
    logger.info("Beat scheduler polling started (60 s interval)");
  }, 30_000);
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
