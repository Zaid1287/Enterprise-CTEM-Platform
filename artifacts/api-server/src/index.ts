import app from "./app";
import { logger } from "./lib/logger";
import { seedPlatformOnStartup } from "./lib/seedPlatform";
import { startScanScheduler } from "./lib/scanScheduler";
import { getRedis } from "./lib/redis";
import { startScanWorker } from "./workers/scanWorker";
import { startAlertWorker } from "./workers/alertWorker";
import { startBeatScheduler } from "./workers/beatScheduler";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  seedPlatformOnStartup().catch(e => logger.error({ err: e }, "Platform seed error"));

  // ── Redis initialisation (warm up connection) ─────────────────────────────
  getRedis();

  if (process.env.REDIS_URL) {
    logger.info("Redis URL detected — starting BullMQ workers");
    startScanWorker(port);
    startAlertWorker();
  } else {
    logger.info("No REDIS_URL — BullMQ workers disabled, using in-process fallback");
  }

  // Beat scheduler replaces the legacy startScanScheduler when Redis is available
  startBeatScheduler().catch(e => logger.error({ err: e }, "Beat scheduler startup error"));
  if (!process.env.REDIS_URL) {
    startScanScheduler();
  }
});
