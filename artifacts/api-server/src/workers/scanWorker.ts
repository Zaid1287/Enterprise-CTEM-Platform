import { Worker, type ConnectionOptions } from "bullmq";
import { makeBullConnection, getActiveRedisUrl } from "../lib/redis";
import { logger } from "../lib/logger";
import type { ScanJobData } from "../queues/scanQueue";
import { db, scansTable } from "@workspace/db";
import { eq } from "drizzle-orm";

let _worker: Worker<ScanJobData> | null = null;
let _port = 0;

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

      try {
        const origin = `http://127.0.0.1:${_port}`;
        const { signAccessToken } = await import("../lib/auth");
        const token = signAccessToken({ userId: job.data.userId, tenantId, role: "admin", email: "" });

        await db.update(scansTable).set({ status: "running", startedAt: new Date() }).where(eq(scansTable.id, scanId));
        await job.updateProgress(10);

        const resp = await fetch(`${origin}/api/scans/pipeline-run`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },
          body: JSON.stringify({ scanId, assetIds }),
        });

        if (!resp.ok) {
          const text = await resp.text().catch(() => "");
          throw new Error(`Pipeline run failed (${resp.status}): ${text}`);
        }

        await job.updateProgress(100);
        logger.info({ scanId }, "Scan worker: job complete");
      } catch (err) {
        logger.error({ err, scanId }, "Scan worker: job failed");
        await db.update(scansTable).set({ status: "failed" }).where(eq(scansTable.id, scanId)).catch(() => {});
        throw err;
      }
    },
    {
      connection: conn as unknown as ConnectionOptions,
      concurrency: 5,
      limiter: { max: 10, duration: 60000 },
    },
  );

  _worker.on("completed", (job) => logger.info({ jobId: job.id, scanId: job.data.scanId }, "Scan job completed"));
  _worker.on("failed", (job, err) => logger.error({ err, jobId: job?.id }, "Scan job failed"));
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
