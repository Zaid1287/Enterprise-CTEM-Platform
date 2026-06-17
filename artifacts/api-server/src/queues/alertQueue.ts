import { Queue, type ConnectionOptions } from "bullmq";
import { makeBullConnection } from "../lib/redis";
import { logger } from "../lib/logger";
import type { NotificationEvent } from "../lib/notifier";

let _queue: Queue<NotificationEvent> | null = null;

export function getAlertQueue(): Queue<NotificationEvent> | null {
  if (!process.env.REDIS_URL) return null;
  if (_queue) return _queue;

  const conn = makeBullConnection();
  if (!conn) return null;

  _queue = new Queue<NotificationEvent>("ctem:alerts", {
    connection: conn as unknown as ConnectionOptions,
    defaultJobOptions: {
      attempts: 5,
      backoff: { type: "exponential", delay: 2000 },
      removeOnComplete: { count: 500 },
      removeOnFail: { count: 500 },
    },
  });

  _queue.on("error", (err: Error) => logger.error({ err }, "Alert queue error"));
  logger.info("Alert queue initialized");
  return _queue;
}

export async function enqueueAlert(event: NotificationEvent): Promise<string | null> {
  const q = getAlertQueue();
  if (!q) return null;
  try {
    const job = await q.add("alert", event, { priority: event.severity === "critical" ? 1 : 5 });
    return job.id ?? null;
  } catch (err) {
    logger.error({ err }, "Failed to enqueue alert");
    return null;
  }
}
