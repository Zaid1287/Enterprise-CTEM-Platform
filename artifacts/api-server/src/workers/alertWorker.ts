import { Worker, type ConnectionOptions } from "bullmq";
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import { dispatchNotifications } from "../lib/notifier";
import type { NotificationEvent } from "../lib/notifier";

let _worker: Worker<NotificationEvent> | null = null;

export function startAlertWorker(): void {
  if (!process.env.REDIS_URL) {
    logger.info("Alert worker: no REDIS_URL, using inline dispatch");
    return;
  }

  const conn = makeBullConnection();
  if (!conn) return;

  _worker = new Worker<NotificationEvent>(
    "ctem:alerts",
    async (job) => {
      logger.info({ eventType: job.data.eventType, tenantId: job.data.tenantId }, "Alert worker: dispatching notification");
      await dispatchNotifications(job.data);
    },
    {
      connection: conn as unknown as ConnectionOptions,
      concurrency: 10,
    },
  );

  _worker.on("completed", (job) => logger.info({ jobId: job.id }, "Alert dispatched"));
  _worker.on("failed", (job, err) => logger.error({ err, jobId: job?.id }, "Alert dispatch failed"));
  _worker.on("error", (err) => logger.error({ err }, "Alert worker error"));

  logger.info("Alert worker started");
}

export async function stopAlertWorker(): Promise<void> {
  if (_worker) {
    await _worker.close();
    _worker = null;
  }
}
