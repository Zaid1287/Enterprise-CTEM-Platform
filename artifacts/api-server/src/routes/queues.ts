/**
 * Queue monitor API — exposes BullMQ queue stats + DB-backed scan stats.
 */
import { Router } from "express";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { getScanQueue } from "../queues/scanQueue";
import { getAlertQueue } from "../queues/alertQueue";
import { isRedisAvailable } from "../lib/redis";
import { db, scansTable } from "@workspace/db";
import { count, sql, desc } from "drizzle-orm";

const router = Router();
router.use(denyExternalMembers);

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
    .select({
      status: scansTable.status,
      cnt: count(),
    })
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
      id:        scansTable.id,
      name:      scansTable.name,
      type:      scansTable.type,
      status:    scansTable.status,
      startedAt: scansTable.startedAt,
      assetIds:  scansTable.assetIds,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('running','pending')`)
    .orderBy(desc(scansTable.startedAt))
    .limit(20);

  return rows.map(s => ({
    id:         s.id,
    name:       s.name,
    type:       s.type,
    status:     s.status,
    startedAt:  s.startedAt?.toISOString() ?? null,
    assetCount: s.assetIds?.length ?? 0,
  }));
}

async function getRecentScans() {
  const rows = await db
    .select({
      id:          scansTable.id,
      name:        scansTable.name,
      type:        scansTable.type,
      status:      scansTable.status,
      startedAt:   scansTable.startedAt,
      completedAt: scansTable.completedAt,
      assetIds:    scansTable.assetIds,
    })
    .from(scansTable)
    .where(sql`${scansTable.status} IN ('completed','failed','cancelled')`)
    .orderBy(desc(scansTable.completedAt))
    .limit(15);

  return rows.map(s => ({
    id:          s.id,
    name:        s.name,
    type:        s.type,
    status:      s.status,
    startedAt:   s.startedAt?.toISOString() ?? null,
    completedAt: s.completedAt?.toISOString() ?? null,
    assetCount:  s.assetIds?.length ?? 0,
  }));
}

router.get("/queues/status", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role !== "admin" && req.user!.role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" });
    return;
  }

  const redisOk = isRedisAvailable();
  const [scanStats, alertStats, dbStats, activeScans, recentScans] = await Promise.all([
    queueStats(getScanQueue()),
    queueStats(getAlertQueue()),
    getDbScanStats(),
    getActiveScans(),
    getRecentScans(),
  ]);

  res.json({
    redis: { connected: redisOk, url: process.env.REDIS_URL ? "configured" : "not configured" },
    queues: {
      scans:  { name: "ctem:scans",  ...scanStats },
      alerts: { name: "ctem:alerts", ...alertStats },
    },
    mode: process.env.REDIS_URL ? "redis" : "in-memory",
    dbStats,
    activeScans,
    recentScans,
  });
});

router.get("/queues/jobs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role !== "admin" && req.user!.role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" });
    return;
  }

  const type = (req.query.type as string) ?? "active";
  const queueName = (req.query.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();

  if (!queue) {
    res.json({ jobs: [], redis: false });
    return;
  }

  const validTypes = ["active", "waiting", "completed", "failed", "delayed"] as const;
  type JobType = typeof validTypes[number];
  const safeType: JobType = validTypes.includes(type as JobType) ? (type as JobType) : "active";

  const jobs = await queue.getJobs([safeType], 0, 50);
  res.json({
    jobs: jobs.map((j) => ({
      id:           j.id,
      name:         j.name,
      data:         j.data,
      progress:     j.progress,
      attemptsMade: j.attemptsMade,
      failedReason: j.failedReason,
      timestamp:    j.timestamp,
      processedOn:  j.processedOn,
      finishedOn:   j.finishedOn,
    })),
    redis: true,
  });
});

router.post("/queues/retry-failed", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (req.user!.role !== "admin" && req.user!.role !== "super_admin") {
    res.status(403).json({ error: "Forbidden" });
    return;
  }

  const queueName = (req.body.queue as string) ?? "scans";
  const queue = queueName === "alerts" ? getAlertQueue() : getScanQueue();

  if (!queue) {
    res.status(503).json({ error: "Queue not available (Redis not configured)" });
    return;
  }

  const failedJobs = await queue.getJobs(["failed"], 0, 100);
  await Promise.all(failedJobs.map((j) => j.retry()));
  res.json({ retried: failedJobs.length });
});

export default router;
