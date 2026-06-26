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
import { db, assetsTable, scansTable, scanJobsTable, scanSchedulesTable, brandWatchlistItemsTable, brandThreatScansTable, securityToolsTable, alertsTable, platformSettingsTable } from "@workspace/db";
import { and, eq, sql, lte, isNotNull } from "drizzle-orm";
import { getScanQueue } from "../queues/scanQueue";
import { fetchLatestVersion } from "../lib/githubVersionChecker";

let _port = 8080;
let _intervalHandle: ReturnType<typeof setInterval> | null = null;

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

function computeNextRunAt(
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
  const token = signAccessToken({ userId: 0, tenantId, role: "admin" });
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
    if (!byTenant.has(a.tenantId)) byTenant.set(a.tenantId, []);
    byTenant.get(a.tenantId)!.push(a);
  }

  for (const [tenantId, tenantAssets] of byTenant) {
    const assetIds = tenantAssets.map((a) => a.id);

    const [scan] = await db
      .insert(scansTable)
      .values({
        tenantId,
        name: `Scheduled Scan — ${new Date().toLocaleDateString()}`,
        type: "scheduled",
        status: "pending",
        assetIds,
        startedAt: new Date(),
      })
      .returning();

    await db.insert(scanJobsTable).values(
      assetIds.map((assetId) => ({ scanId: scan.id, assetId, status: "pending" })),
    );

    await enqueueOrRun(scan.id, tenantId, assetIds);
    logger.info({ tenantId, scanId: scan.id, count: assetIds.length }, "Beat: asset-frequency scan dispatched");
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

function computeWatchlistNextScanAt(frequency: string, from: Date): Date | null {
  if (frequency === "daily") {
    const next = new Date(from);
    next.setDate(next.getDate() + 1);
    next.setUTCHours(3, 0, 0, 0);
    return next;
  }
  if (frequency === "weekly") {
    const next = new Date(from);
    next.setDate(next.getDate() + 7);
    next.setUTCHours(3, 0, 0, 0);
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
  const { brandThreatResultsTable, phishingDetectionsTable, dataLeakResultsTable, brandAbuseResultsTable } = await import("@workspace/db");

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
          db.delete(brandThreatResultsTable).where(eq(brandThreatResultsTable.scanId, existing.id)),
          db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, existing.id)),
          db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, existing.id)),
          db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, existing.id)),
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

      const nextScanAt = computeWatchlistNextScanAt(item.frequency ?? "none", now);

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

async function dispatchToolUpdateCheck(): Promise<void> {
  const SETTING_KEY = "tool_update_last_checked";
  const todayStr = new Date().toISOString().slice(0, 10);

  try {
    const [setting] = await db
      .select()
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, SETTING_KEY))
      .limit(1);

    if (setting?.value === todayStr) return;

    const tools = await db
      .select({
        id:                 securityToolsTable.id,
        tenantId:           securityToolsTable.tenantId,
        name:               securityToolsTable.name,
        githubUrl:          securityToolsTable.githubUrl,
        currentVersion:     securityToolsTable.currentVersion,
        latestVersion:      securityToolsTable.latestVersion,
        updateCommand:      securityToolsTable.updateCommand,
      })
      .from(securityToolsTable);

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

      const { latestVersion, error } = await fetchLatestVersion(githubUrl);
      if (error || !latestVersion) continue;

      const now = new Date();

      for (const tool of toolGroup) {
        await db
          .update(securityToolsTable)
          .set({ latestVersion, toolUpdateCheckedAt: now })
          .where(eq(securityToolsTable.id, tool.id));

        const prevLatest = tool.latestVersion;
        if (!latestVersion || latestVersion === prevLatest) continue;
        if (tool.currentVersion && latestVersion === tool.currentVersion) continue;

        const alertTitle = `Update available: ${tool.name} ${latestVersion}`;
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

        await db.insert(alertsTable).values({
          tenantId:  tool.tenantId,
          title:     alertTitle,
          message:   `A new version of ${tool.name} is available (${latestVersion}).${tool.updateCommand ? ` Update command: ${tool.updateCommand}` : " See the tool's GitHub page for update instructions."}`,
          type:      "tool_update",
          severity:  "medium",
        });

        logger.info({ toolName: tool.name, latestVersion, tenantId: tool.tenantId }, "Beat: tool update alert created");
      }
    }

    await db
      .insert(platformSettingsTable)
      .values({ key: SETTING_KEY, value: todayStr, label: "Tool Update Last Checked", category: "system" })
      .onConflictDoUpdate({ target: platformSettingsTable.key, set: { value: todayStr } });

    logger.info({ urlsChecked: checked }, "Beat: tool update check complete");
  } catch (err) {
    logger.error({ err }, "Beat: tool update check failed");
  }
}

async function dispatchDueScans(): Promise<void> {
  try {
    await Promise.all([dispatchDueAssets(), dispatchDueSchedules(), dispatchDueWatchlistDomains()]);
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
    setImmediate(() => dispatchToolUpdateCheck().catch(() => {}));
  }, 30_000);
}

export async function stopBeatScheduler(): Promise<void> {
  if (_intervalHandle) {
    clearInterval(_intervalHandle);
    _intervalHandle = null;
  }
}
