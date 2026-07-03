/**
 * Queue monitor API — BullMQ stats, in-process queue, worker health,
 * throughput chart, upcoming schedules, pause/resume, and job kill.
 */
import { Router } from "express";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getScanQueue } from "../queues/scanQueue";
import { getAlertQueue } from "../queues/alertQueue";
import { isRedisAvailable } from "../lib/redis";
import { db, scansTable, scanSchedulesTable } from "@workspace/db";
import { count, sql, desc, eq, and, isNotNull, asc } from "drizzle-orm";
import { getInProcessQueueStats } from "./pipelineScans";
import { getScanWorkerHealth } from "../workers/scanWorker";
import { getAlertWorkerHealth } from "../workers/alertWorker";

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
      status: scansTable.status, startedAt: scansTable.startedAt, assetIds: scansTable.assetIds,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('running','pending')`)
    .orderBy(desc(scansTable.startedAt))
    .limit(20);
  return rows.map(s => ({
    id: s.id, name: s.name, type: s.type, status: s.status,
    startedAt: s.startedAt?.toISOString() ?? null,
    assetCount: s.assetIds?.length ?? 0,
  }));
}

async function getRecentScans() {
  const rows = await db
    .select({
      id: scansTable.id, name: scansTable.name, type: scansTable.type,
      status: scansTable.status, startedAt: scansTable.startedAt,
      completedAt: scansTable.completedAt, assetIds: scansTable.assetIds,
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
      status: scanSchedulesTable.status,
    })
    .from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.status, "active"), isNotNull(scanSchedulesTable.nextRunAt)))
    .orderBy(asc(scanSchedulesTable.nextRunAt))
    .limit(10);

  return rows.map(r => ({
    id: r.id,
    name: r.name,
    frequency: r.frequency,
    nextRunAt: r.nextRunAt?.toISOString() ?? null,
    lastRunAt: r.lastRunAt?.toISOString() ?? null,
    assetName: null as string | null,
  }));
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

  const depthWarning =
    inProcess.activeScans + inProcess.pendingCount > inProcess.maxConcurrent * 2;

  res.json({
    redis: { connected: redisOk, url: process.env.REDIS_URL ? "configured" : "not configured" },
    queues: {
      scans:  { name: "ctem:scans",  ...scanStats },
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
      timestamp: j.timestamp, processedOn: j.processedOn, finishedOn: j.finishedOn,
    })),
    redis: true,
  });
});

// ── POST /queues/pause ──────────────────────────────────────────────────────
router.post("/queues/pause", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const queueName = (req.body.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();
  if (!queue) { res.status(503).json({ error: "Redis not available" }); return; }

  await queue.pause();
  res.json({ ok: true, queue: queueName, paused: true });
});

// ── POST /queues/resume ─────────────────────────────────────────────────────
router.post("/queues/resume", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const queueName = (req.body.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();
  if (!queue) { res.status(503).json({ error: "Redis not available" }); return; }

  await queue.resume();
  res.json({ ok: true, queue: queueName, paused: false });
});

// ── DELETE /queues/jobs/:jobId ──────────────────────────────────────────────
router.delete("/queues/jobs/:jobId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  const { jobId } = req.params;
  const queueName = (req.query.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();
  if (!queue) { res.status(503).json({ error: "Redis not available" }); return; }

  const job = await queue.getJob(jobId);
  if (!job) { res.status(404).json({ error: "Job not found" }); return; }

  const state = await job.getState();
  if (state === "active") {
    // Can't truly kill a running worker thread, but we can move to failed
    await job.moveToFailed(new Error("Killed by admin"), "0", true);
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
  await Promise.all(failedJobs.map(j => j.retry()));
  res.json({ retried: failedJobs.length });
});

// ── GET /queues/worker-health ───────────────────────────────────────────────
router.get("/queues/worker-health", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isAdmin(req)) { res.status(403).json({ error: "Forbidden" }); return; }

  res.json({
    scanWorker:  getScanWorkerHealth(),
    alertWorker: getAlertWorkerHealth(),
    redis: isRedisAvailable(),
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
