import { Router } from "express";
import { requireAuth } from "../lib/auth.js";
import { db, scanProxiesTable, orchestratorConfigTable, scanFingerprintProfilesTable, scanRequestTelemetryTable } from "@workspace/db";
import { eq, desc, sql, gte, and } from "drizzle-orm";
import { healthCheckProxy } from "../lib/proxyHealthCheck.js";
import { getAllCircuits } from "../lib/circuitBreaker.js";
import { getAllRateLimiterStats } from "../lib/adaptiveRateLimiter.js";
import { getDnsResolverStats } from "../lib/dnsResolverPool.js";
import { invalidateConfigCache } from "../lib/scanOrchestrator.js";
import { logger } from "../lib/logger.js";

const router = Router();

function requireSuperAdmin(req: any, res: any, next: any): void {
  if (req.user?.role !== "super_admin") { res.status(403).json({ error: "Forbidden" }); return; }
  next();
}

function requireAdmin(req: any, res: any, next: any): void {
  const role = req.user?.role;
  if (role !== "super_admin" && role !== "admin") { res.status(403).json({ error: "Forbidden" }); return; }
  next();
}

function parseId(param: string | string[] | undefined): number {
  return parseInt(String(param ?? ""), 10);
}

// ── Proxy CRUD ─────────────────────────────────────────────────────────────────

router.get("/api/scan-proxies", requireAuth, requireAdmin, async (req, res) => {
  try {
    const proxies = await db
      .select()
      .from(scanProxiesTable)
      .orderBy(desc(scanProxiesTable.healthScore));
    res.json(proxies);
  } catch (err) {
    logger.error({ err }, "GET /api/scan-proxies error");
    res.status(500).json({ error: "Failed to fetch proxies" });
  }
});

router.post("/api/scan-proxies", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { ip, port = 8080, label, type = "http", country, asn } = req.body;
    if (!ip) { res.status(400).json({ error: "ip is required" }); return; }

    const health = await healthCheckProxy(ip, port);

    const [proxy] = await db
      .insert(scanProxiesTable)
      .values({
        ip,
        port,
        label,
        type,
        country,
        asn,
        status:      health.reachable ? "active" : "inactive",
        healthScore: health.reachable ? 100 : 0,
        avgLatencyMs: health.reachable ? health.latencyMs : undefined,
        lastTestedAt: new Date(),
      } as any)
      .returning();

    res.status(201).json({ ...proxy, healthCheck: health });
  } catch (err) {
    logger.error({ err }, "POST /api/scan-proxies error");
    res.status(500).json({ error: "Failed to create proxy" });
  }
});

router.patch("/api/scan-proxies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    const { ip, port, label, type, country, asn, status } = req.body;
    const updates: Record<string, any> = {};
    if (ip      !== undefined) updates.ip      = ip;
    if (port    !== undefined) updates.port    = port;
    if (label   !== undefined) updates.label   = label;
    if (type    !== undefined) updates.type    = type;
    if (country !== undefined) updates.country = country;
    if (asn     !== undefined) updates.asn     = asn;
    if (status  !== undefined) updates.status  = status;

    const [updated] = await db
      .update(scanProxiesTable)
      .set(updates)
      .where(eq(scanProxiesTable.id, id))
      .returning();

    if (!updated) { res.status(404).json({ error: "Proxy not found" }); return; }
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "PATCH /api/scan-proxies/:id error");
    res.status(500).json({ error: "Failed to update proxy" });
  }
});

router.delete("/api/scan-proxies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    await db.delete(scanProxiesTable).where(eq(scanProxiesTable.id, id));
    res.json({ success: true });
  } catch (err) {
    logger.error({ err }, "DELETE /api/scan-proxies/:id error");
    res.status(500).json({ error: "Failed to delete proxy" });
  }
});

router.get("/api/scan-proxies/:id/health", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    const [proxy] = await db
      .select({ id: scanProxiesTable.id, ip: scanProxiesTable.ip, port: scanProxiesTable.port })
      .from(scanProxiesTable)
      .where(eq(scanProxiesTable.id, id));

    if (!proxy) { res.status(404).json({ error: "Proxy not found" }); return; }

    const health = await healthCheckProxy(proxy.ip, proxy.port ?? 8080);

    await db.update(scanProxiesTable)
      .set({
        lastTestedAt: new Date(),
        status: health.reachable ? "active" : "inactive",
        avgLatencyMs: health.reachable ? health.latencyMs : undefined,
      } as any)
      .where(eq(scanProxiesTable.id, id));

    res.json({ proxyId: id, ...health });
  } catch (err) {
    logger.error({ err }, "GET /api/scan-proxies/:id/health error");
    res.status(500).json({ error: "Failed to health-check proxy" });
  }
});

// ── Orchestrator Config ────────────────────────────────────────────────────────

router.get("/api/orchestrator-config", requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await db.select().from(orchestratorConfigTable).orderBy(orchestratorConfigTable.key);
    const config: Record<string, string> = {};
    for (const row of rows) config[row.key] = row.value;
    res.json({ config, rows });
  } catch (err) {
    logger.error({ err }, "GET /api/orchestrator-config error");
    res.status(500).json({ error: "Failed to fetch config" });
  }
});

router.patch("/api/orchestrator-config", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const updates: Record<string, string> = req.body;
    if (typeof updates !== "object" || Array.isArray(updates)) {
      res.status(400).json({ error: "Body must be an object of key→value pairs" }); return;
    }

    const results = [];
    for (const [key, value] of Object.entries(updates)) {
      const [row] = await db
        .insert(orchestratorConfigTable)
        .values({ key, value, updatedAt: new Date() } as any)
        .onConflictDoUpdate({ target: orchestratorConfigTable.key, set: { value, updatedAt: new Date() } })
        .returning();
      results.push(row);
    }

    invalidateConfigCache();
    res.json({ updated: results });
  } catch (err) {
    logger.error({ err }, "PATCH /api/orchestrator-config error");
    res.status(500).json({ error: "Failed to update config" });
  }
});

// ── Fingerprint Profiles ───────────────────────────────────────────────────────

router.get("/api/scan-fingerprints", requireAuth, requireAdmin, async (req, res) => {
  try {
    const profiles = await db
      .select()
      .from(scanFingerprintProfilesTable)
      .orderBy(scanFingerprintProfilesTable.id);
    res.json(profiles);
  } catch (err) {
    logger.error({ err }, "GET /api/scan-fingerprints error");
    res.status(500).json({ error: "Failed to fetch fingerprint profiles" });
  }
});

router.get("/api/scan-fingerprints/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }
    const [profile] = await db
      .select()
      .from(scanFingerprintProfilesTable)
      .where(eq(scanFingerprintProfilesTable.id, id));
    if (!profile) { res.status(404).json({ error: "Profile not found" }); return; }
    res.json(profile);
  } catch (err) {
    logger.error({ err }, "GET /api/scan-fingerprints/:id error");
    res.status(500).json({ error: "Failed to fetch fingerprint profile" });
  }
});

router.patch("/api/scan-fingerprints/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    const { name, headers, isActive } = req.body;
    const updates: Record<string, any> = { updatedAt: new Date() };
    if (name     !== undefined) updates.name     = name;
    if (headers  !== undefined) updates.headers  = headers;
    if (isActive !== undefined) updates.isActive = isActive;

    const [updated] = await db
      .update(scanFingerprintProfilesTable)
      .set(updates)
      .where(eq(scanFingerprintProfilesTable.id, id))
      .returning();

    if (!updated) { res.status(404).json({ error: "Profile not found" }); return; }
    invalidateConfigCache();
    res.json(updated);
  } catch (err) {
    logger.error({ err }, "PATCH /api/scan-fingerprints/:id error");
    res.status(500).json({ error: "Failed to update fingerprint profile" });
  }
});

// ── Telemetry ──────────────────────────────────────────────────────────────────

router.get("/api/scan-telemetry", requireAuth, requireAdmin, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page  as string ?? "1",  10));
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit as string ?? "50", 10)));
    const offset = (page - 1) * limit;

    const rows = await db
      .select()
      .from(scanRequestTelemetryTable)
      .orderBy(desc(scanRequestTelemetryTable.createdAt))
      .limit(limit)
      .offset(offset);

    const [{ count }] = await db
      .select({ count: sql<number>`count(*)::int` })
      .from(scanRequestTelemetryTable);

    res.json({ rows, total: count, page, limit });
  } catch (err) {
    logger.error({ err }, "GET /api/scan-telemetry error");
    res.status(500).json({ error: "Failed to fetch telemetry" });
  }
});

router.get("/api/scan-telemetry/stats", requireAuth, requireAdmin, async (req, res) => {
  try {
    const now = Date.now();
    const since60m = new Date(now - 60 * 60_000);
    const since5m  = new Date(now -  5 * 60_000);

    const [totals] = await db
      .select({
        totalRequests:      sql<number>`count(*)::int`,
        avgLatencyMs:       sql<number>`round(avg(latency_ms))::int`,
        p95LatencyMs:       sql<number>`round(percentile_cont(0.95) within group (order by latency_ms))::int`,
        count429:           sql<number>`count(*) filter (where status_code = 429)::int`,
        count403:           sql<number>`count(*) filter (where status_code = 403)::int`,
        countWaf:           sql<number>`count(*) filter (where waf_detected)::int`,
        countCaptcha:       sql<number>`count(*) filter (where captcha_detected)::int`,
        totalRetries:       sql<number>`coalesce(sum(retries),0)::int`,
        avgBytesDownloaded: sql<number>`round(avg(bytes_downloaded))::int`,
      })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since60m));

    // Requests in last 5 minutes → req/s
    const [recent] = await db
      .select({ count5m: sql<number>`count(*)::int` })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since5m));
    const reqPerSecond = Math.round((recent.count5m ?? 0) / 300 * 100) / 100;

    // Per-minute trend for the last 60 minutes (1-min buckets)
    const trend = await db
      .select({
        minute:       sql<string>`date_trunc('minute', created_at)::text`,
        requests:     sql<number>`count(*)::int`,
        avgLatencyMs: sql<number>`round(avg(latency_ms))::int`,
        wafCount:     sql<number>`count(*) filter (where waf_detected)::int`,
        retryCount:   sql<number>`coalesce(sum(retries),0)::int`,
        count429:     sql<number>`count(*) filter (where status_code = 429)::int`,
        count403:     sql<number>`count(*) filter (where status_code = 403)::int`,
      })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since60m))
      .groupBy(sql`date_trunc('minute', created_at)`)
      .orderBy(sql`date_trunc('minute', created_at)`);

    const [proxyStats] = await db
      .select({
        activeProxies:   sql<number>`count(*) filter (where status = 'active')::int`,
        coolingProxies:  sql<number>`count(*) filter (where status = 'cooldown')::int`,
        inactiveProxies: sql<number>`count(*) filter (where status = 'inactive')::int`,
        avgHealthScore:  sql<number>`round(avg(health_score))::int`,
      })
      .from(scanProxiesTable);

    const circuits         = getAllCircuits();
    const openCircuits     = circuits.filter(c => c.state === "open").length;
    const rateLimiterStats = getAllRateLimiterStats();
    const dnsStats         = getDnsResolverStats();

    // Retry queue size — count requests still being retried (retries > 0 in last 5 min)
    const [retryQueue] = await db
      .select({ size: sql<number>`count(*) filter (where retries > 0)::int` })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since5m));

    res.json({
      window: "last_60_minutes",
      generatedAt: new Date().toISOString(),
      requests:  { ...totals, reqPerSecond },
      retryQueueSize: retryQueue.size ?? 0,
      trend: trend.slice(-60),
      proxies:   proxyStats,
      circuits: { open: openCircuits, total: circuits.length, details: circuits.slice(0, 20) },
      rateLimiters: rateLimiterStats.slice(0, 20),
      dnsResolvers: dnsStats,
    });
  } catch (err) {
    logger.error({ err }, "GET /api/scan-telemetry/stats error");
    res.status(500).json({ error: "Failed to fetch telemetry stats" });
  }
});

export default router;
