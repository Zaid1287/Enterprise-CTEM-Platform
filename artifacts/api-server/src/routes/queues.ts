/**
 * Queue monitor API — BullMQ stats, in-process queue, worker health,
 * throughput chart, upcoming schedules, pause/resume (both modes), job kill, DLQ.
 */
import { Router } from "express";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getScanQueue } from "../queues/scanQueue";
import { getAlertQueue } from "../queues/alertQueue";
import { isRedisAvailable } from "../lib/redis";
import { db, scansTable, scanSchedulesTable, assetsTable, alertsTable } from "@workspace/db";
import { count, sql, desc, eq, and, isNotNull, asc, inArray, gte, lt } from "drizzle-orm";
import {
  getInProcessQueueStats,
  pauseInProcessQueue,
  resumeInProcessQueue,
  isInProcessQueuePaused,
} from "./pipelineScans";
import { getScanWorkerHealth } from "../workers/scanWorker";
import { getAlertWorkerHealth } from "../workers/alertWorker";
import { logger } from "../lib/logger";

const router = Router();
router.use(denyExternalMembers);

function isAdmin(req: AuthenticatedRequest) {
  return req.user!.role === "admin" || req.user!.role === "super_admin";
}

async function queueStats(queue: ReturnType<typeof getScanQueue> | ReturnType<typeof getAlertQueue>) {
  if (!queue) return { active: 0, waiting: 0, completed: 0, failed: 0, delayed: 0, paused: false };
  const [active, waiting, completed, failed, delayed, isPaused] = await Promise.all([
    queue.getActiveCount(),
    queue.getWaitingCount(),
    queue.getCompletedCount(),
    queue.getFailedCount(),
    queue.getDelayedCount(),
    queue.isPaused(),
  ]);
  return { active, waiting, completed, failed, delayed, paused: isPaused };
}

async function getDbScanStats() {
  const rows = await db
    .select({ status: scansTable.status, cnt: count() })
    .from(scansTable)
    .groupBy(scansTable.status);
  const map: Record<string, number> = {};
  for (const r of rows) map[r.status] = Number(r.cnt);
  return {
    running:   map["running"]   ?? 0,
    pending:   map["pending"]   ?? 0,
    completed: map["completed"] ?? 0,
    failed:    map["failed"]    ?? 0,
    cancelled: map["cancelled"] ?? 0,
  };
}

async function getActiveScans() {
  const rows = await db
    .select({
      id: scansTable.id, name: scansTable.name, type: scansTable.type,
      status: scansTable.status, startedAt: scansTable.startedAt,
      assetIds: scansTable.assetIds, bullmqJobId: scansTable.bullmqJobId,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('running','pending')`)
    .orderBy(desc(scansTable.startedAt))
    .limit(20);
  return rows.map(s => ({
    id: s.id, name: s.name, type: s.type, status: s.status,
    startedAt: s.startedAt?.toISOString() ?? null,
    assetCount: s.assetIds?.length ?? 0,
    bullmqJobId: s.bullmqJobId ?? null,
  }));
}

async function getRecentScans() {
  const rows = await db
    .select({
      id: scansTable.id, name: scansTable.name, type: scansTable.type,
      status: scansTable.status, startedAt: scansTable.startedAt,
      completedAt: scansTable.completedAt, assetIds: scansTable.assetIds,
      bullmqJobId: scansTable.bullmqJobId,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('completed','failed','cancelled')`)
    .orderBy(desc(scansTable.completedAt))
    .limit(15);
  return rows.map(s => ({
    id: s.id, name: s.name, type: s.type, status: s.status,
    startedAt: s.startedAt?.toISOString() ?? null,
    completedAt: s.completedAt?.toISOString() ?? null,
    assetCount: s.assetIds?.length ?? 0,
    bullmqJobId: s.bullmqJobId ?? null,
  }));
}

async function getUpcomingSchedules() {
  const rows = await db
    .select({
      id: scanSchedulesTable.id,
      name: scanSchedulesTable.name,
      frequency: scanSchedulesTable.frequency,
      nextRunAt: scanSchedulesTable.nextRunAt,
      lastRunAt: scanSchedulesTable.lastRunAt,
      assetToolConfig: scanSchedulesTable.assetToolConfig,
    })
    .from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.status, "active"), isNotNull(scanSchedulesTable.nextRunAt)))
    .orderBy(asc(scanSchedulesTable.nextRunAt))
    .limit(10);

  // Extract assetIds from assetToolConfig jsonb, then batch-fetch asset names
  const assetIdSet = new Set<number>();
  for (const r of rows) {
    const cfg = r.assetToolConfig as { assetId?: number }[] | null;
    if (Array.isArray(cfg) && cfg[0]?.assetId) {
      assetIdSet.add(Number(cfg[0].assetId));
    }
  }

  const assetMap = new Map<number, string>();
  if (assetIdSet.size > 0) {
    const assetRows = await db
      .select({ id: assetsTable.id, name: assetsTable.name })
      .from(assetsTable)
      .where(inArray(assetsTable.id, [...assetIdSet]));
    for (const a of assetRows) assetMap.set(a.id, a.name);
  }

  return rows.map(r => {
    const cfg = r.assetToolConfig as { assetId?: number }[] | null;
    const firstAssetId = Array.isArray(cfg) && cfg[0]?.assetId ? Number(cfg[0].assetId) : null;
    const assetCount = Array.isArray(cfg) ? cfg.length : 0;
    return {
      id: r.id,
      name: r.name ?? `Schedule #${r.id}`,
      frequency: r.frequency,
      nextRunAt: r.nextRunAt?.toISOString() ?? null,
      lastRunAt: r.lastRunAt?.toISOString() ?? null,
      assetName: firstAssetId ? (assetMap.get(firstAssetId) ?? null) : null,
      assetCount,
    };
  });
}

// Debounce queue depth DB alerts — max one per hour
let _lastDepthAlertAt = 0;

/** Insert a queue depth alert into the DB for all admin tenants with active scans. */
async function fireQueueDepthAlert(waiting: number): Promise<void> {
  const now = Date.now();
  if (now - _lastDepthAlertAt < 60 * 60 * 1000) return; // once per hour max
  _lastDepthAlertAt = now;

  try {
    // Find all tenant IDs with currently pending/running scans
    const activeRows = await db
      .select({ tenantId: scansTable.tenantId })
      .from(scansTable)
      .where(sql`${scansTable.status} IN ('pending', 'running')`);
    const tenantIds = [...new Set(activeRows.map(r => r.tenantId))];
    if (tenantIds.length === 0) return;

    await db.insert(alertsTable).values(
      tenantIds.map(tenantId => ({
        tenantId,
        title: `Queue depth alert — ${waiting} jobs waiting`,
        message: `The scan queue has ${waiting} waiting jobs which exceeds the threshold of 20. Consider investigating stuck scans or increasing capacity.`,
        type: "queue_depth",
        severity: "high",
        isRead: false,
      })),
    );
    logger.warn({ waiting, tenantCount: tenantIds.length }, "Queue depth alert fired — inserted DB alerts for admin tenants");
  } catch (err) {
    logger.error({ err }, "Failed to insert queue depth alert");
  }
}

// ── GET /queues/status ─────────────────────────────────────────────────────
router.get("/queues/status", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const redisOk = isRedisAvailable();
  const inProcess = getInProcessQueueStats();
  const [scanStats, alertStats, dbStats, activeScans, recentScans, upcomingSchedules] = await Promise.all([
    queueStats(getScanQueue()),
    queueStats(getAlertQueue()),
    getDbScanStats(),
    getActiveScans(),
    getRecentScans(),
    getUpcomingSchedules(),
  ]);

  // depthWarning: in Redis mode use BullMQ waiting; in-memory use FIFO pending
  const bullmqWaiting = redisOk ? scanStats.waiting : 0;
  const inMemWaiting  = inProcess.pendingCount;
  const totalWaiting  = bullmqWaiting + inMemWaiting;

  const depthWarning  = totalWaiting > 20 ||
    inProcess.activeScans + inProcess.pendingCount > inProcess.maxConcurrent * 2;

  // Fire DB alert if threshold exceeded (non-blocking, fire-and-forget)
  if (totalWaiting > 20) {
    fireQueueDepthAlert(totalWaiting).catch(() => {});
  }

  res.json({
    redis: { connected: redisOk, url: process.env.REDIS_URL ? "configured" : "not configured" },
    queues: {
      scans:  { name: "ctem:scans",  ...scanStats, paused: scanStats.paused || (redisOk ? false : inProcess.paused) },
      alerts: { name: "ctem:alerts", ...alertStats },
    },
    mode: process.env.REDIS_URL ? "redis" : "in-memory",
    inProcess,
    depthWarning,
    dbStats,
    activeScans,
    recentScans,
    upcomingSchedules,
  });
});

// ── GET /queues/jobs ────────────────────────────────────────────────────────
router.get("/queues/jobs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const type = (req.query.type as string) ?? "active";
  const queueName = (req.query.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();

  if (!queue) { res.json({ jobs: [], redis: false }); return; }

  const validTypes = ["active", "waiting", "completed", "failed", "delayed"] as const;
  type JobType = typeof validTypes[number];
  const safeType: JobType = validTypes.includes(type as JobType) ? (type as JobType) : "active";

  const jobs = await queue.getJobs([safeType], 0, 50);
  res.json({
    jobs: jobs.map(j => ({
      id: j.id, name: j.name, data: j.data, progress: j.progress,
      attemptsMade: j.attemptsMade, failedReason: j.failedReason,
      opts: { attempts: (j.opts as any)?.attempts ?? 3 },
      timestamp: j.timestamp, processedOn: j.processedOn, finishedOn: j.finishedOn,
    })),
    redis: true,
  });
});

// ── GET /queues/dlq ─────────────────────────────────────────────────────────
// Dead Letter Queue: failed jobs that exhausted all retries.
router.get("/queues/dlq", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const q = getScanQueue();
  if (!q) { res.json({ jobs: [], redis: false, total: 0 }); return; }

  const failed = await q.getFailed(0, 200);
  const dlqJobs = failed.filter(j => j.attemptsMade >= ((j.opts as any)?.attempts ?? 3));

  res.json({
    redis: true,
    total: dlqJobs.length,
    jobs: dlqJobs.map(j => ({
      id: j.id,
      name: j.name,
      data: j.data,
      attemptsMade: j.attemptsMade,
      maxAttempts: (j.opts as any)?.attempts ?? 3,
      failedReason: j.failedReason,
      timestamp: j.timestamp,
      finishedOn: j.finishedOn,
    })),
  });
});

// ── POST /queues/dlq/:jobId/retry ─────────────────────────────────────────
router.post("/queues/dlq/:jobId/retry", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const q = getScanQueue();
  if (!q) { res.status(503).json({ error: "Redis not available" }); return; }

  const jobId = String(req.params.jobId);
  const job = await q.getJob(jobId);
  if (!job) { res.status(404).json({ error: "Job not found in DLQ" }); return; }

  await job.retry();
  res.json({ ok: true, jobId });
});

// ── DELETE /queues/dlq/:jobId ─────────────────────────────────────────────
router.delete("/queues/dlq/:jobId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const q = getScanQueue();
  if (!q) { res.status(503).json({ error: "Redis not available" }); return; }

  const job = await q.getJob(String(req.params.jobId));
  if (!job) { res.status(404).json({ error: "Job not found" }); return; }

  await job.remove();
  res.json({ ok: true });
});

// ── POST /queues/pause ──────────────────────────────────────────────────────
// Works in both Redis mode (pauses BullMQ queue) and in-memory mode (pauses FIFO drainQueue).
router.post("/queues/pause", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const queueName = (req.body.queue as string) ?? "scans";

  if (queueName === "scans") {
    const queue = getScanQueue();
    if (queue) {
      await queue.pause();
    } else {
      pauseInProcessQueue();
    }
  } else if (queueName === "alerts") {
    const queue = getAlertQueue();
    if (!queue) { res.status(503).json({ error: "Redis not available for alerts queue" }); return; }
    await queue.pause();
  }

  res.json({ ok: true, queue: queueName, paused: true });
});

// ── POST /queues/resume ─────────────────────────────────────────────────────
router.post("/queues/resume", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const queueName = (req.body.queue as string) ?? "scans";

  if (queueName === "scans") {
    const queue = getScanQueue();
    if (queue) {
      await queue.resume();
    } else {
      resumeInProcessQueue();
    }
  } else if (queueName === "alerts") {
    const queue = getAlertQueue();
    if (!queue) { res.status(503).json({ error: "Redis not available for alerts queue" }); return; }
    await queue.resume();
  }

  res.json({ ok: true, queue: queueName, paused: false });
});

// ── DELETE /queues/jobs/:jobId ──────────────────────────────────────────────
// Kill a waiting job (remove) or signal an active job to abort.
router.delete("/queues/jobs/:jobId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const jobId = String(req.params.jobId);
  const queueName = (req.query.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();
  if (!queue) { res.status(503).json({ error: "Redis not available" }); return; }

  const job = await queue.getJob(jobId);
  if (!job) { res.status(404).json({ error: "Job not found" }); return; }

  const state = await job.getState();
  if (state === "active") {
    // Signal the worker to abort its pipeline HTTP call via AbortController
    const scanId = (job.data as any)?.scanId;
    if (scanId) {
      const { abortActiveScanJob } = await import("../workers/scanWorker");
      abortActiveScanJob(Number(scanId));
    }
    // Also move to failed so BullMQ stops tracking it as active
    await job.moveToFailed(new Error("Killed by admin"), job.token ?? "0", true).catch(() => {});
  } else {
    await job.remove();
  }
  res.json({ ok: true, jobId, state });
});

// ── POST /queues/retry-failed ───────────────────────────────────────────────
router.post("/queues/retry-failed", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const queueName = (req.body.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();
  if (!queue) { res.status(503).json({ error: "Redis not available" }); return; }

  const failedJobs = await queue.getJobs(["failed"], 0, 100);
  // Only retry jobs that haven't exhausted all attempts (exclude DLQ)
  const retryable = failedJobs.filter(j => j.attemptsMade < ((j.opts as any)?.attempts ?? 3));
  await Promise.all(retryable.map(j => j.retry()));
  res.json({ retried: retryable.length });
});

// ── GET /queues/worker-health ───────────────────────────────────────────────
router.get("/queues/worker-health", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  res.json({
    scanWorker:  getScanWorkerHealth(),
    alertWorker: getAlertWorkerHealth(),
    redis: isRedisAvailable(),
    inProcessPaused: isInProcessQueuePaused(),
  });
});

// ── GET /queues/throughput ──────────────────────────────────────────────────
// Returns hourly completed/failed/cancelled counts for the last 24 h.
router.get("/queues/throughput", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const result = await db.execute(sql`
    SELECT
      DATE_TRUNC('hour', completed_at) AS hour,
      COUNT(*) FILTER (WHERE status = 'completed')  AS completed,
      COUNT(*) FILTER (WHERE status = 'failed')     AS failed,
      COUNT(*) FILTER (WHERE status = 'cancelled')  AS cancelled
    FROM scans
    WHERE completed_at >= NOW() - INTERVAL '24 hours'
    GROUP BY hour
    ORDER BY hour
  `);

  res.json({
    hourly: (result.rows as any[]).map(r => ({
      hour:      r.hour ? new Date(r.hour).toISOString() : null,
      completed: Number(r.completed ?? 0),
      failed:    Number(r.failed    ?? 0),
      cancelled: Number(r.cancelled ?? 0),
    })),
  });
});

export default router;
