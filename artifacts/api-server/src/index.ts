import app from "./app";
import { logger } from "./lib/logger";
import { bootstrapNucleiTemplates } from "./lib/nucleiScanner";
import { seedPlatformOnStartup } from "./lib/seedPlatform";
import { getRedis, setRuntimeRedisUrl } from "./lib/redis";
import { startScanWorker } from "./workers/scanWorker";
import { startAlertWorker } from "./workers/alertWorker";
import { startBeatScheduler } from "./workers/beatScheduler";
import { db, platformSettingsTable } from "@workspace/db";
import { aiMapperScansTable, aiMapperAttackRunsTable } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { WebSocketServer } from "ws";
import { scanProgressSockets, attackRunSockets } from "./routes/aiMapper";
import { verifyToken } from "./lib/auth";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error("PORT environment variable is required but was not provided.");
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

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

/** Read Redis URL from platform_settings if not set in environment */
async function loadRediUrlFromPlatformSettings(): Promise<void> {
  if (process.env.REDIS_URL) {
    logger.info("REDIS_URL already set via environment variable");
    return;
  }
  try {
    const [row] = await db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, "redis_url"));
    if (row?.value) {
      setRuntimeRedisUrl(row.value);
      logger.info("Redis URL loaded from platform settings");
    } else {
      logger.info("No Redis URL found in platform settings — BullMQ workers disabled");
    }
  } catch (err) {
    logger.warn({ err }, "Could not read redis_url from platform settings (DB may not be ready yet)");
  }
}

/** Init workers with current Redis URL. Call after loadRedisUrlFromPlatformSettings(). */
export function startWorkersIfRedisAvailable(): void {
  if (process.env.REDIS_URL) {
    logger.info("Starting BullMQ workers");
    startScanWorker(port);
    startAlertWorker();
  } else {
    logger.info("No Redis URL — BullMQ workers disabled, using in-process fallback");
  }
}

const server = app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
  seedPlatformOnStartup().catch(e => logger.error({ err: e }, "Platform seed error"));
  initStripe().catch(e => logger.error({ err: e }, "Stripe init error"));

  // ── Load Redis URL from platform settings (if not in env), then start workers
  loadRediUrlFromPlatformSettings()
    .then(() => {
      getRedis();
      startWorkersIfRedisAvailable();
    })
    .catch(e => {
      logger.error({ err: e }, "Redis init error");
      getRedis();
    });

  // Beat scheduler handles asset-frequency and schedule-based scans
  startBeatScheduler(port).catch(e => logger.error({ err: e }, "Beat scheduler startup error"));

  // Download official nuclei-templates in the background (non-blocking)
  bootstrapNucleiTemplates().catch(() => {});
});

// ── WebSocket server for AI Mapper real-time scan/attack streams ──────────────
const wss = new WebSocketServer({ noServer: true });
server.on("upgrade", (req, socket, head) => {
  const rawUrl = req.url ?? "";
  const searchStart = rawUrl.indexOf("?");
  const search = searchStart !== -1 ? rawUrl.slice(searchStart + 1) : "";
  const params = new URLSearchParams(search);
  const token = params.get("token");

  if (!token) { socket.destroy(); return; }

  let payload: ReturnType<typeof verifyToken>;
  try { payload = verifyToken(token); } catch { socket.destroy(); return; }

  const tenantId = payload.tenantId;

  const scanMatch   = rawUrl.match(/\/api\/ai-mapper\/scans\/(\d+)\/ws/);
  const attackMatch = rawUrl.match(/\/api\/ai-mapper\/attacks\/(\d+)\/ws/);
  if (!scanMatch && !attackMatch) { socket.destroy(); return; }

  // Verify ownership (tenant isolation) asynchronously before accepting the socket.
  (async () => {
    try {
      if (scanMatch) {
        const id = Number(scanMatch[1]);
        const [row] = await db
          .select({ id: aiMapperScansTable.id })
          .from(aiMapperScansTable)
          .where(and(eq(aiMapperScansTable.id, id), eq(aiMapperScansTable.tenantId, tenantId)));
        if (!row) { socket.destroy(); return; }
      } else if (attackMatch) {
        const id = Number(attackMatch[1]);
        const [row] = await db
          .select({ id: aiMapperAttackRunsTable.id })
          .from(aiMapperAttackRunsTable)
          .where(and(eq(aiMapperAttackRunsTable.id, id), eq(aiMapperAttackRunsTable.tenantId, tenantId)));
        if (!row) { socket.destroy(); return; }
      }

      wss.handleUpgrade(req, socket as any, head, async (ws) => {
        if (scanMatch) {
          const id = Number(scanMatch[1]);
          if (!scanProgressSockets.has(id)) scanProgressSockets.set(id, new Set());
          scanProgressSockets.get(id)!.add(ws);
          ws.on("close", () => {
            const s = scanProgressSockets.get(id);
            if (s) { s.delete(ws); if (!s.size) scanProgressSockets.delete(id); }
          });
          // Replay current scan state immediately so clients joining mid-scan get latest progress
          try {
            const [cur] = await db.select({ status: aiMapperScansTable.status, progress: aiMapperScansTable.progress, liveHosts: aiMapperScansTable.liveHosts, totalHosts: aiMapperScansTable.totalHosts, scannedHosts: aiMapperScansTable.scannedHosts, endpointCount: aiMapperScansTable.endpointCount }).from(aiMapperScansTable).where(eq(aiMapperScansTable.id, id));
            if (cur && ws.readyState === 1) ws.send(JSON.stringify({ ...cur, type: "state_replay" }));
          } catch { /* ignore replay error */ }
        } else if (attackMatch) {
          const id = Number(attackMatch[1]);
          if (!attackRunSockets.has(id)) attackRunSockets.set(id, new Set());
          attackRunSockets.get(id)!.add(ws);
          ws.on("close", () => {
            const s = attackRunSockets.get(id);
            if (s) { s.delete(ws); if (!s.size) attackRunSockets.delete(id); }
          });
          // Replay existing attack results for clients joining mid-run
          try {
            const [cur] = await db.select({ status: aiMapperAttackRunsTable.status, progress: aiMapperAttackRunsTable.progress, results: aiMapperAttackRunsTable.results }).from(aiMapperAttackRunsTable).where(eq(aiMapperAttackRunsTable.id, id));
            if (cur && ws.readyState === 1) ws.send(JSON.stringify({ ...cur, type: "state_replay" }));
          } catch { /* ignore replay error */ }
        }
      });
    } catch {
      socket.destroy();
    }
  })();
});
