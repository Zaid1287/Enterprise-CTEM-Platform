import { Queue, type ConnectionOptions } from "bullmq";
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";

export interface ScanJobData {
  scanId: number;
  tenantId: number;
  userId: number;
  assetIds: number[];
  scheduleId?: number;
}

let _queue: Queue<ScanJobData> | null = null;

export function getScanQueue(): Queue<ScanJobData> | null {
  if (!process.env.REDIS_URL) return null;
  if (_queue) return _queue;

  const conn = makeBullConnection();
  if (!conn) return null;

  _queue = new Queue<ScanJobData>("ctem:scans", {
    connection: conn as unknown as ConnectionOptions,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: "exponential", delay: 5000 },
      removeOnComplete: { count: 200 },
      removeOnFail: { count: 500 },
    },
  });

  _queue.on("error", (err: Error) => logger.error({ err }, "Scan queue error"));
  logger.info("Scan queue initialized");
  return _queue;
}

export async function enqueueScan(data: ScanJobData, opts?: { delay?: number; repeat?: { pattern: string } }): Promise<string | null> {
  const q = getScanQueue();
  if (!q) return null;
  try {
    const job = await q.add(`scan:${data.scanId}`, data, opts);
    return job.id ?? null;
  } catch (err) {
    logger.error({ err }, "Failed to enqueue scan job");
    return null;
  }
}
