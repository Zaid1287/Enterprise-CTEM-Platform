import { Router } from "express";
import { requireAuth } from "../lib/auth.js";
import { db, scanProxiesTable, orchestratorConfigTable, scanFingerprintProfilesTable, scanRequestTelemetryTable } from "@workspace/db";
import { eq, desc, sql, gte, and, isNotNull } from "drizzle-orm";
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

    // Attach requestsToday count from telemetry table (requests where proxy_ip matches)
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const perIpToday = await db
      .select({
        proxyId: scanRequestTelemetryTable.proxyId,
        count:   sql<number>`count(*)::int`,
      })
      .from(scanRequestTelemetryTable)
      .where(and(gte(scanRequestTelemetryTable.createdAt, todayStart), isNotNull(scanRequestTelemetryTable.proxyId)))
      .groupBy(scanRequestTelemetryTable.proxyId);
    const todayMap = new Map(perIpToday.map(r => [r.proxyId, r.count]));

    const enriched = proxies.map(p => ({ ...p, requestsToday: todayMap.get(p.id) ?? 0 }));
    res.json(enriched);
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

router.get("/api/orchestrator-config", requireAuth, requireSuperAdmin, async (req, res) => {
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

router.get("/api/scan-fingerprints", requireAuth, requireSuperAdmin, async (req, res) => {
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

router.get("/api/scan-fingerprints/:id", requireAuth, requireSuperAdmin, async (req, res) => {
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
    const page   = Math.max(1, parseInt(req.query.page  as string ?? "1",  10));
    const limit  = Math.min(200, Math.max(1, parseInt(req.query.limit as string ?? "50", 10)));
    const offset = (page - 1) * limit;

    // Server-side filters
    const proxyIp   = (req.query.proxyIp  as string | undefined)?.trim() || null;
    const dateFrom  = (req.query.dateFrom as string | undefined)?.trim() || null;
    const dateTo    = (req.query.dateTo   as string | undefined)?.trim() || null;
    const status    = (req.query.status   as string | undefined)?.trim() || null;

    const conds = [];
    if (proxyIp)  conds.push(sql`proxy_ip = ${proxyIp}`);
    if (dateFrom) conds.push(sql`created_at >= ${new Date(dateFrom)}`);
    if (dateTo)   conds.push(sql`created_at <= ${new Date(dateTo)}`);
    if (status === "429") conds.push(sql`status_code = 429`);
    else if (status === "403") conds.push(sql`status_code = 403`);
    else if (status === "2xx") conds.push(sql`status_code between 200 and 299`);
    else if (status === "4xx") conds.push(sql`status_code between 400 and 499`);
    else if (status === "5xx") conds.push(sql`status_code between 500 and 599`);

    const wafOnly     = req.query.waf     === "1";
    const captchaOnly = req.query.captcha === "1";
    if (wafOnly)     conds.push(sql`waf_detected = true`);
    if (captchaOnly) conds.push(sql`captcha_detected = true`);

    const whereClause = conds.length > 0 ? and(...conds) : undefined;

    const rowsQuery = db
      .select()
      .from(scanRequestTelemetryTable)
      .orderBy(desc(scanRequestTelemetryTable.createdAt))
      .limit(limit)
      .offset(offset);

    const countQuery = db
      .select({ count: sql<number>`count(*)::int` })
      .from(scanRequestTelemetryTable);

    if (whereClause) {
      const rows = await rowsQuery.where(whereClause);
      const [{ count }] = await countQuery.where(whereClause);
      res.json({ rows, total: count, page, limit });
    } else {
      const rows = await rowsQuery;
      const [{ count }] = await countQuery;
      res.json({ rows, total: count, page, limit });
    }
  } catch (err) {
    logger.error({ err }, "GET /api/scan-telemetry error");
    res.status(500).json({ error: "Failed to fetch telemetry" });
  }
});

router.get("/api/scan-telemetry/stats", requireAuth, requireAdmin, async (req, res) => {
  try {
    const now = Date.now();
    const since30m = new Date(now - 30 * 60_000);
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
      .where(gte(scanRequestTelemetryTable.createdAt, since30m));

    // Requests in last 60 seconds → req/s
    const since60s = new Date(now - 60_000);
    const [recent] = await db
      .select({ count60s: sql<number>`count(*)::int` })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since60s));
    const reqPerSecond = Math.round((recent.count60s ?? 0) / 60 * 100) / 100;

    // Per-minute trend for the last 30 minutes (1-min buckets)
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
      .where(gte(scanRequestTelemetryTable.createdAt, since30m))
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

    // Per-host last status code + recent req/s (for Target Blocking Health table)
    const hostStatsRaw = await db
      .select({
        host:        sql<string>`regexp_replace(url, '^https?://([^/:]+).*$', '\\1')`,
        lastStatus:  sql<number | null>`(array_agg(status_code ORDER BY created_at DESC))[1]`,
        recentCount: sql<number>`count(*) filter (where created_at >= ${since5m})::int`,
      })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since30m))
      .groupBy(sql`regexp_replace(url, '^https?://([^/:]+).*$', '\\1')`);

    const hostStats: Record<string, { lastStatus: number | null; reqPerSec: number }> = {};
    for (const hs of hostStatsRaw) {
      if (hs.host) {
        hostStats[hs.host] = {
          lastStatus: hs.lastStatus ?? null,
          reqPerSec: Math.round((hs.recentCount ?? 0) / 300 * 100) / 100,
        };
      }
    }

    res.json({
      window: "last_30_minutes",
      generatedAt: new Date().toISOString(),
      requests:  { ...totals, reqPerSecond },
      retryQueueSize: retryQueue.size ?? 0,
      trend: trend.slice(-30),
      proxies:   proxyStats,
      circuits: { open: openCircuits, total: circuits.length, details: circuits.slice(0, 20) },
      rateLimiters: rateLimiterStats.slice(0, 20),
      dnsResolvers: dnsStats,
      hostStats,
    });
  } catch (err) {
    logger.error({ err }, "GET /api/scan-telemetry/stats error");
    res.status(500).json({ error: "Failed to fetch telemetry stats" });
  }
});

export default router;
