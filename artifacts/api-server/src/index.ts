import app from "./app";
import { logger } from "./lib/logger";
import { seedPlatformOnStartup } from "./lib/seedPlatform";
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

// ── Initialize Stripe (non-blocking, errors logged but don't crash server) ────
async function initStripe() {
  try {
    const { runMigrations } = await import("stripe-replit-sync");
    const { getStripeSync } = await import("./lib/stripeClient");

    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) throw new Error("DATABASE_URL required");

    logger.info("Initializing Stripe schema...");
    await runMigrations({ databaseUrl });
    logger.info("Stripe schema ready");

    const stripeSync = await getStripeSync();

    const domain = process.env.REPLIT_DOMAINS?.split(",")[0];
    if (domain) {
      const webhookUrl = `https://${domain}/api/stripe/webhook`;
      await stripeSync.findOrCreateManagedWebhook(webhookUrl);
      logger.info({ webhookUrl }, "Stripe webhook configured");
    }

    stripeSync.syncBackfill()
      .then(() => logger.info("Stripe backfill complete"))
      .catch(err => logger.error({ err }, "Stripe backfill error"));
  } catch (err: any) {
    logger.warn({ err: err?.message }, "Stripe init skipped (integration not connected?)");
  }
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  seedPlatformOnStartup().catch(e => logger.error({ err: e }, "Platform seed error"));
  initStripe().catch(e => logger.error({ err: e }, "Stripe init error"));

  // ── Redis initialisation (warm up connection) ─────────────────────────────
  getRedis();

  if (process.env.REDIS_URL) {
    logger.info("Redis URL detected — starting BullMQ workers");
    startScanWorker(port);
    startAlertWorker();
  } else {
    logger.info("No REDIS_URL — BullMQ workers disabled, using in-process fallback");
  }

  // Beat scheduler handles asset-frequency and schedule-based scans (BullMQ or inline with retry)
  startBeatScheduler(port).catch(e => logger.error({ err: e }, "Beat scheduler startup error"));
});
