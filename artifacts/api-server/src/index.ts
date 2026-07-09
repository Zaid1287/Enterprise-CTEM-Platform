import app from "./app";
import { logger } from "./lib/logger";
import { scheduleRetestCoolingProxies } from "./lib/proxyManager";
import { initCircuitBreaker } from "./lib/circuitBreaker";
import { initRateLimiter } from "./lib/adaptiveRateLimiter";
import { bootstrapNucleiTemplates } from "./lib/nucleiScanner";
import { warmBrowser } from "./lib/screenshotEngine";
import { seedPlatformOnStartup } from "./lib/seedPlatform";
import { getRedis, setRuntimeRedisUrl } from "./lib/redis";
import { startScanWorker } from "./workers/scanWorker";
import { startAlertWorker } from "./workers/alertWorker";
import { startBeatScheduler } from "./workers/beatScheduler";
import { db, platformSettingsTable, brandThreatScansTable, orchestratorConfigTable, scanFingerprintProfilesTable, tenantsTable } from "@workspace/db";
import { aiMapperScansTable, aiMapperAttackRunsTable } from "@workspace/db";
import { eq, and, inArray } from "drizzle-orm";
import { runBrandThreatScan, startBrandThreatWatchdog, PermResult } from "./lib/brandThreatRunner";
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

const STUCK_SCAN_THRESHOLD_MS = 30 * 60 * 1000; // 30 minutes

/**
 * On startup: recover brand threat scans that were interrupted by a server restart.
 *
 * - "running" scans older than 30 minutes are considered permanently stuck and are
 *   reset to "error" — they will never self-recover and would block all future scans
 *   for that domain if left in "running" state.
 * - "running" scans younger than 30 minutes (or "pending" scans) are resumed:
 *   - If Phase 1 completed (checkpoint = "phase1_done"), resume from Phase 2 cache.
 *   - Otherwise restart from Phase 1 (dnstwist re-runs).
 */
async function resumeOrResetStuckBrandThreatScans(): Promise<void> {
  try {
    const stuckScans = await db.select({
      id:                brandThreatScansTable.id,
      domain:            brandThreatScansTable.domain,
      status:            brandThreatScansTable.status,
      checkpoint:        brandThreatScansTable.checkpoint,
      permutationsCache: brandThreatScansTable.permutationsCache,
      createdAt:         brandThreatScansTable.createdAt,
    }).from(brandThreatScansTable)
      .where(inArray(brandThreatScansTable.status, ["running", "pending"]));

    if (stuckScans.length === 0) return;

    const staleThreshold = new Date(Date.now() - STUCK_SCAN_THRESHOLD_MS);
    const staleScans  = stuckScans.filter(s => s.status === "running" && s.createdAt < staleThreshold);
    const freshScans  = stuckScans.filter(s => !staleScans.includes(s));

    // Reset permanently stuck scans to error
    if (staleScans.length > 0) {
      logger.warn({ count: staleScans.length }, "Startup: resetting brand threat scans stuck >30 min to error");
      for (const scan of staleScans) {
        const ageMinutes = Math.round((Date.now() - new Date(scan.createdAt).getTime()) / 60_000);
        logger.warn({ scanId: scan.id, domain: scan.domain, ageMinutes },
          "Startup: brand threat scan exceeded 30-minute timeout — marking as error");
        await db.update(brandThreatScansTable)
          .set({
            status: "error",
            error: `Scan timed out: found in 'running' state for ${ageMinutes} minutes on server restart`,
            completedAt: new Date(),
          })
          .where(eq(brandThreatScansTable.id, scan.id));
      }
    }

    // Resume fresh interrupted scans
    if (freshScans.length > 0) {
      logger.warn({ count: freshScans.length }, "Startup: found interrupted brand threat scans — resuming");
      for (const scan of freshScans) {
        if (scan.checkpoint === "phase1_done" && scan.permutationsCache) {
          // Phase 1 was already complete — resume from Phase 2 using cached permutations
          const cachedPerms = scan.permutationsCache as PermResult[];
          logger.info({ scanId: scan.id, domain: scan.domain, permCount: cachedPerms.length },
            "Startup: resuming brand threat scan from Phase 1 checkpoint");
          setImmediate(() => { void runBrandThreatScan(scan.id, scan.domain, cachedPerms); });
        } else {
          // Phase 1 never completed (or no cache) — restart from scratch
          logger.info({ scanId: scan.id, domain: scan.domain },
            "Startup: restarting brand threat scan from Phase 1 (no checkpoint)");
          await db.update(brandThreatScansTable)
            .set({ status: "pending", progress: 0, checkpoint: null })
            .where(eq(brandThreatScansTable.id, scan.id));
          setImmediate(() => { void runBrandThreatScan(scan.id, scan.domain); });
        }
      }
    }
  } catch (err) {
    logger.warn({ err }, "Could not resume stuck brand threat scans on startup (non-fatal)");
  }
}

async function seedOrchestratorDefaults(): Promise<void> {
  try {
    // 15 orchestrator config knobs
    const DEFAULT_CONFIG: Array<{ key: string; value: string }> = [
      { key: "enabled",                       value: "true"        },
      { key: "use_proxies",                   value: "false"       },
      { key: "rotate_fingerprints",           value: "true"        },
      { key: "adaptive_rate_limit",           value: "true"        },
      { key: "proxy_health_scoring",          value: "true"        },
      { key: "circuit_breaker_enabled",       value: "true"        },
      { key: "log_all_requests",              value: "true"        },
      { key: "proxy_rotation_strategy",       value: "round-robin" },
      { key: "resolver_rotation_strategy",    value: "round-robin" },
      { key: "fingerprint_rotation_strategy", value: "round-robin" },
      { key: "scan_delay_intensity",          value: "endpoint-discovery" },
      { key: "max_requests_per_host",         value: "2000"        },
      { key: "max_requests_per_proxy",        value: "500"         },
      { key: "max_concurrent_requests",       value: "20"          },
      { key: "proxy_health_threshold",        value: "60"          },
      { key: "proxy_cooldown_minutes",        value: "15"          },
      { key: "scan_delay_multiplier",         value: "1.0"         },
      { key: "waf_bypass_strategy",           value: "rotate"      },
      { key: "retry_base_delay_ms",           value: "1000"        },
      { key: "max_retries",                   value: "4"           },
      { key: "max_backoff_ms",                value: "30000"       },
    ];
    // Scope defaults to the platform tenant (first registered tenant)
    const [platTenant] = await db.select({ id: tenantsTable.id }).from(tenantsTable).orderBy(tenantsTable.id).limit(1);
    const platTenantId = platTenant?.id ?? 1;

    for (const row of DEFAULT_CONFIG) {
      await db.insert(orchestratorConfigTable)
        .values({ ...row, tenantId: platTenantId })
        .onConflictDoUpdate({
          target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
          set:    { value: row.value },
        });
    }

    const existing = await db.select({ id: scanFingerprintProfilesTable.id }).from(scanFingerprintProfilesTable).limit(1);
    if (existing.length === 0) {
      await db.insert(scanFingerprintProfilesTable).values([
        {
          name: "Chrome 137 / Windows 10",
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="137", "Google Chrome";v="137"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
          },
          isActive: true,
        },
        {
          name: "Firefox 128 / Linux",
          headers: {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
          },
          isActive: true,
        },
        {
          name: "Edge 127 / Windows 11",
          headers: {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="127", "Microsoft Edge";v="127"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
          },
          isActive: true,
        },
        {
          name: "Safari 17 / macOS",
          headers: {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
          },
          isActive: true,
        },
        {
          name: "Chrome 137 / Android Mobile",
          headers: {
            "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA-Mobile": "?1",
            "Sec-CH-UA-Platform": '"Android"',
          },
          isActive: true,
        },
        {
          name: "Safari / iOS 17",
          headers: {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
          },
          isActive: false,
        },
      ]);
      logger.info("Orchestrator: seeded 6 default fingerprint profiles");
    }

    // Seed 10 well-known public proxy IPs as starting examples (disabled by default)
    const { scanProxiesTable } = await import("@workspace/db");
    const existingProxies = await db.select({ id: scanProxiesTable.id }).from(scanProxiesTable).limit(1);
    if (existingProxies.length === 0) {
      const SEED_PROXIES = [
        { ip: "13.41.174.221",   port: 3128, type: "http",   country: "GB", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "18.132.253.89",   port: 3128, type: "http",   country: "GB", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "3.10.209.190",    port: 3128, type: "http",   country: "GB", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "52.56.180.151",   port: 3128, type: "http",   country: "GB", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "13.37.4.46",      port: 3128, type: "http",   country: "FR", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "15.188.51.175",   port: 3128, type: "http",   country: "FR", provider: "AWS",         healthScore: 50, status: "inactive" as const },
        { ip: "185.191.236.47",  port: 3128, type: "http",   country: "NL", provider: "Hetzner",     healthScore: 50, status: "inactive" as const },
        { ip: "194.163.45.55",   port: 3128, type: "http",   country: "DE", provider: "Contabo",     healthScore: 50, status: "inactive" as const },
        { ip: "172.104.137.176", port: 1080, type: "socks5", country: "AU", provider: "Akamai",      healthScore: 50, status: "inactive" as const },
        { ip: "139.59.1.14",     port: 1080, type: "socks5", country: "IN", provider: "DigitalOcean", healthScore: 50, status: "inactive" as const },
      ];
      await db.insert(scanProxiesTable).values(SEED_PROXIES);
      logger.info("Orchestrator: seeded 10 example proxy entries (all inactive by default)");
    }

    logger.info("Orchestrator: config defaults ensured");
  } catch (err) {
    logger.warn({ err }, "Orchestrator seed failed (non-fatal)");
  }
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
  resumeOrResetStuckBrandThreatScans().catch(e => logger.error({ err: e }, "Scan resume error"));
  seedPlatformOnStartup().catch(e => logger.error({ err: e }, "Platform seed error"));
  seedOrchestratorDefaults().catch(e => logger.error({ err: e }, "Orchestrator seed error"));
  scheduleRetestCoolingProxies().catch(e => logger.error({ err: e }, "Proxy retest scheduler error"));
  initCircuitBreaker().catch(e => logger.error({ err: e }, "Circuit breaker state restore error"));
  initRateLimiter().catch(e => logger.error({ err: e }, "Rate limiter state restore error"));
  import("./lib/wafStatsRecorder.js").then(m => m.initWafStatsRecorder()).catch(e => logger.error({ err: e }, "WAF stats recorder init error"));
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

  // Watchdog: periodically reset brand threat scans stuck in "running" mid-run
  const stopBrandThreatWatchdog = startBrandThreatWatchdog();
  const shutdown = () => {
    stopBrandThreatWatchdog();
    process.exit(0);
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT",  shutdown);

  // Download official nuclei-templates in the background (non-blocking)
  bootstrapNucleiTemplates().catch(() => {});

  // Pre-warm the Puppeteer browser so the first scan has zero cold-start cost
  warmBrowser()
    .then(() => logger.info("Puppeteer browser pre-warmed"))
    .catch(e => logger.warn({ err: e?.message }, "Puppeteer pre-warm failed (non-fatal)"));
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
