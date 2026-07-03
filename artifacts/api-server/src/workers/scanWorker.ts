import { Worker, type ConnectionOptions } from "bullmq";
import { makeBullConnection, getActiveRedisUrl } from "../lib/redis";
import { logger } from "../lib/logger";
import type { ScanJobData } from "../queues/scanQueue";
import { db, scansTable } from "@workspace/db";
import { eq } from "drizzle-orm";

let _worker: Worker<ScanJobData> | null = null;
let _port = 0;

// Per-job AbortControllers so we can abort the pipeline HTTP request on demand
const activeJobControllers = new Map<number, AbortController>();

/** Abort the in-flight pipeline HTTP request for a scan (called by cancel route). */
export function abortActiveScanJob(scanId: number): boolean {
  const ctrl = activeJobControllers.get(scanId);
  if (ctrl) {
    ctrl.abort();
    activeJobControllers.delete(scanId);
    logger.info({ scanId }, "Scan worker: aborted active job fetch");
    return true;
  }
  return false;
}

export function startScanWorker(port: number): void {
  _port = port;
  if (!getActiveRedisUrl()) {
    logger.info("Scan worker: no Redis URL, using inline execution");
    return;
  }

  const conn = makeBullConnection();
  if (!conn) return;

  _worker = new Worker<ScanJobData>(
    "ctem:scans",
    async (job) => {
      const { scanId, tenantId, assetIds } = job.data;
      logger.info({ scanId, tenantId, assetCount: assetIds.length }, "Scan worker: processing job");

      await job.updateProgress(5);

      // Store the BullMQ job ID on the scan record for traceability
      await db.update(scansTable)
        .set({ bullmqJobId: job.id ?? null })
        .where(eq(scansTable.id, scanId))
        .catch(() => {});

      const controller = new AbortController();
      activeJobControllers.set(scanId, controller);

      try {
        const origin = `http://127.0.0.1:${_port}`;
        const { signAccessToken } = await import("../lib/auth");
        const token = signAccessToken({ userId: job.data.userId, tenantId, role: "admin", email: "" });

        await db.update(scansTable)
          .set({ status: "running", startedAt: new Date() })
          .where(eq(scansTable.id, scanId));
        await job.updateProgress(10);

        const resp = await fetch(`${origin}/api/scans/pipeline-run`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ scanId, assetIds }),
          signal: controller.signal,
        });

        if (!resp.ok) {
          const text = await resp.text().catch(() => "");
          throw new Error(`Pipeline run failed (${resp.status}): ${text}`);
        }

        await job.updateProgress(100);
        logger.info({ scanId }, "Scan worker: job complete");
      } catch (err: any) {
        if (err?.name === "AbortError") {
          // Cancelled by admin — scan already marked cancelled in DB by cancel route
          logger.info({ scanId }, "Scan worker: job aborted (scan cancelled)");
          return; // Don't throw — let the job complete gracefully
        }
        logger.error({ err, scanId }, "Scan worker: job failed");
        await db.update(scansTable)
          .set({ status: "failed" })
          .where(eq(scansTable.id, scanId))
          .catch(() => {});
        throw err;
      } finally {
        activeJobControllers.delete(scanId);
      }
    },
    {
      connection: conn as unknown as ConnectionOptions,
      concurrency: 5,
      limiter: { max: 10, duration: 60000 },
    },
  );

  _worker.on("completed", (job) => logger.info({ jobId: job.id, scanId: job.data.scanId }, "Scan job completed"));
  _worker.on("failed", (job, err) => {
    if (!job) return;
    const allAttemptsUsed = job.attemptsMade >= (job.opts?.attempts ?? 3);
    if (allAttemptsUsed) {
      logger.warn({ jobId: job.id, scanId: job.data?.scanId, reason: err?.message }, "Scan job moved to Dead Letter Queue (all retries exhausted)");
    } else {
      logger.error({ err, jobId: job?.id }, "Scan job failed (will retry)");
    }
  });
  _worker.on("error", (err) => logger.error({ err }, "Scan worker error"));

  logger.info("Scan worker started (BullMQ)");
}

export async function stopScanWorker(): Promise<void> {
  if (_worker) {
    await _worker.close();
    _worker = null;
  }
}

export async function restartScanWorker(): Promise<void> {
  await stopScanWorker();
  startScanWorker(_port);
}

export function getScanWorkerHealth() {
  return {
    running: _worker !== null,
    mode: _worker ? "redis" : "inline",
    status: _worker
      ? (_worker.isRunning() ? "active" : "idle")
      : "disabled",
    concurrency: _worker ? 5 : 0,
  };
}
