import { Router } from "express";
import { requireAuth, verifyToken } from "../lib/auth.js";
import { db, scanProxiesTable, orchestratorConfigTable, scanFingerprintProfilesTable, scanRequestTelemetryTable } from "@workspace/db";
import { eq, desc, sql, gte, and, isNotNull } from "drizzle-orm";
import { healthCheckProxy } from "../lib/proxyHealthCheck.js";
import { getAllCircuits } from "../lib/circuitBreaker.js";
import { getAllRateLimiterStats } from "../lib/adaptiveRateLimiter.js";
import { getDnsResolverStats } from "../lib/dnsResolverPool.js";
import { invalidateConfigCache, getWafProtectedHosts } from "../lib/scanOrchestrator.js";
import { addWaterfallSseClient, removeWaterfallSseClient } from "../lib/sseManager.js";
import { logger } from "../lib/logger.js";
import { encryptCredential } from "../lib/proxyCredentialEncryption.js";

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

    // Never expose raw password over the API — replace with a boolean hasAuth flag
    const enriched = proxies.map(p => ({
      ...p,
      password: undefined,
      hasAuth: !!(p.username && p.password),
      requestsToday: todayMap.get(p.id) ?? 0,
    }));
    res.json(enriched);
  } catch (err) {
    logger.error({ err }, "GET /api/scan-proxies error");
    res.status(500).json({ error: "Failed to fetch proxies" });
  }
});

router.post("/api/scan-proxies", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { ip, port = 8080, label, type = "http", country, asn, username, password } = req.body;
    if (!ip) { res.status(400).json({ error: "ip is required" }); return; }

    const health = await healthCheckProxy(ip, port);

    const [proxy] = await db
      .insert(scanProxiesTable)
      .values({
        ip, port, label, type, country, asn,
        username: username || null,
        password: password ? encryptCredential(password) : null,
        status:      health.reachable ? "active" : "inactive",
        healthScore: health.reachable ? 100 : 0,
        avgLatencyMs: health.reachable ? health.latencyMs : undefined,
        lastTestedAt: new Date(),
      } as any)
      .returning();

    res.status(201).json({ ...proxy, password: undefined, hasAuth: !!(proxy.username && proxy.password), healthCheck: health });
  } catch (err) {
    logger.error({ err }, "POST /api/scan-proxies error");
    res.status(500).json({ error: "Failed to create proxy" });
  }
});

router.patch("/api/scan-proxies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    // Issue 2: support username/password updates
    const { ip, port, label, type, country, asn, status, username, password } = req.body;
    const updates: Record<string, any> = {};
    if (ip       !== undefined) updates.ip       = ip;
    if (port     !== undefined) updates.port     = port;
    if (label    !== undefined) updates.label    = label;
    if (type     !== undefined) updates.type     = type;
    if (country  !== undefined) updates.country  = country;
    if (asn      !== undefined) updates.asn      = asn;
    if (status   !== undefined) updates.status   = status;
    if (username !== undefined) updates.username = username || null;
    if (password !== undefined) updates.password = password ? encryptCredential(password) : null;

    const [updated] = await db
      .update(scanProxiesTable)
      .set(updates)
      .where(eq(scanProxiesTable.id, id))
      .returning();

    if (!updated) { res.status(404).json({ error: "Proxy not found" }); return; }
    res.json({ ...updated, password: undefined, hasAuth: !!(updated.username && updated.password) });
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

// ── Issue 3: Bulk proxy import (CSV / paste) ───────────────────────────────────
// Accepts: { proxies: "1.2.3.4:8080\n5.6.7.8:3128:user:pass" }
// Or: { proxies: [{ ip, port, username?, password?, label?, type?, country? }] }
router.post("/api/scan-proxies/bulk", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const { proxies: raw, type: defaultType = "http" } = req.body;
    if (!raw) { res.status(400).json({ error: "proxies field is required" }); return; }

    type ProxyEntry = { ip: string; port: number; username?: string; password?: string; label?: string; type?: string; country?: string };
    let entries: ProxyEntry[] = [];

    if (typeof raw === "string") {
      // CSV / newline-separated: ip:port[:user:pass]  or  ip:port:user:pass:label
      entries = raw
        .split(/[\n,;]+/)
        .map(s => s.trim())
        .filter(s => s.length > 0 && !s.startsWith("#"))
        .flatMap(line => {
          const parts = line.split(":");
          const ip = parts[0]?.trim();
          const port = parseInt(parts[1]?.trim() ?? "8080", 10);
          if (!ip || isNaN(port)) return [];
          const username = parts[2]?.trim() || undefined;
          const password = parts[3]?.trim() || undefined;
          const label    = parts[4]?.trim() || undefined;
          return [{ ip, port, username, password, label, type: defaultType }];
        });
    } else if (Array.isArray(raw)) {
      entries = raw
        .filter(e => typeof e === "object" && e && e.ip)
        .map(e => ({ ip: e.ip, port: e.port ?? 8080, username: e.username, password: e.password, label: e.label, type: e.type ?? defaultType, country: e.country }));
    } else {
      res.status(400).json({ error: "proxies must be a string or array" }); return;
    }

    if (entries.length === 0) { res.status(400).json({ error: "No valid proxy entries found" }); return; }
    if (entries.length > 500) { res.status(400).json({ error: "Maximum 500 proxies per bulk import" }); return; }

    const results: { ip: string; port: number; ok: boolean; latencyMs?: number; error?: string }[] = [];

    // Health-check and insert each proxy (parallel, up to 20 at a time)
    const BATCH = 20;
    for (let i = 0; i < entries.length; i += BATCH) {
      const batch = entries.slice(i, i + BATCH);
      await Promise.allSettled(
        batch.map(async entry => {
          try {
            const health = await healthCheckProxy(entry.ip, entry.port);
            await db
              .insert(scanProxiesTable)
              .values({
                ip:          entry.ip,
                port:        entry.port,
                label:       entry.label ?? null,
                type:        entry.type  ?? "http",
                country:     entry.country ?? null,
                username:    entry.username ?? null,
                password:    entry.password ? encryptCredential(entry.password) : null,
                status:      health.reachable ? "active" : "inactive",
                healthScore: health.reachable ? 100 : 0,
                avgLatencyMs: health.reachable ? health.latencyMs : undefined,
                lastTestedAt: new Date(),
              } as any)
              .onConflictDoNothing();
            results.push({ ip: entry.ip, port: entry.port, ok: health.reachable, latencyMs: health.latencyMs });
          } catch (err: any) {
            results.push({ ip: entry.ip, port: entry.port, ok: false, error: err?.message ?? "insert failed" });
          }
        })
      );
    }

    const imported = results.filter(r => r.ok).length;
    const failed   = results.filter(r => !r.ok).length;
    logger.info({ imported, failed, total: entries.length }, "Bulk proxy import complete");
    res.status(201).json({ imported, failed, total: entries.length, results });
  } catch (err) {
    logger.error({ err }, "POST /api/scan-proxies/bulk error");
    res.status(500).json({ error: "Bulk import failed" });
  }
});

// ── Orchestrator Config ────────────────────────────────────────────────────────

router.get("/api/orchestrator-config", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;
    const rows = await db.select().from(orchestratorConfigTable)
      .where(eq(orchestratorConfigTable.tenantId, tenantId))
      .orderBy(orchestratorConfigTable.key);
    const config: Record<string, string> = {};
    for (const row of rows) config[row.key] = row.value;
    res.json({ config, rows });
  } catch (err) {
    logger.error({ err }, "GET /api/orchestrator-config error");
    res.status(500).json({ error: "Failed to fetch config" });
  }
});

router.patch("/api/orchestrator-config", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;
    const updates: Record<string, string> = req.body;
    if (typeof updates !== "object" || Array.isArray(updates)) {
      res.status(400).json({ error: "Body must be an object of key→value pairs" }); return;
    }

    const results = [];
    for (const [key, value] of Object.entries(updates)) {
      const [row] = await db
        .insert(orchestratorConfigTable)
        .values({ tenantId, key, value, updatedAt: new Date() } as any)
        .onConflictDoUpdate({
          target: [orchestratorConfigTable.tenantId, orchestratorConfigTable.key],
          set:    { value, updatedAt: new Date() },
        })
        .returning();
      results.push(row);
    }

    invalidateConfigCache(tenantId);
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

// ── Issue 4: Real-time waterfall SSE stream ────────────────────────────────────
// Uses query-param token (like the alerts/stream endpoint) because EventSource
// cannot send custom Authorization headers.
router.get("/api/scan-telemetry/stream", (req: any, res: any) => {
  const token = req.query.token as string | undefined;
  if (!token) { res.status(401).end(); return; }

  let user: any;
  try { user = verifyToken(token); } catch { res.status(401).end(); return; }

  const role = user?.role;
  if (role !== "super_admin" && role !== "admin") { res.status(403).end(); return; }

  const tenantId = user?.tenantId as number;
  if (!tenantId) { res.status(400).end(); return; }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  addWaterfallSseClient(tenantId, res);

  // Send heartbeat every 15s to keep the connection alive through proxies
  const heartbeat = setInterval(() => {
    try { res.write(": heartbeat\n\n"); } catch { clearInterval(heartbeat); }
  }, 15_000);

  req.on("close", () => {
    clearInterval(heartbeat);
    removeWaterfallSseClient(tenantId, res);
  });
});

// ── Telemetry ──────────────────────────────────────────────────────────────────

router.get("/api/scan-telemetry", requireAuth, requireAdmin, async (req, res) => {
  try {
    const page   = Math.max(1, parseInt(req.query.page  as string ?? "1",  10));
    const limit  = Math.min(200, Math.max(1, parseInt(req.query.limit as string ?? "50", 10)));
    const offset = (page - 1) * limit;

    const proxyIp   = (req.query.proxyIp  as string | undefined)?.trim() || null;
    const host      = (req.query.host     as string | undefined)?.trim() || null;
    const dateFrom  = (req.query.dateFrom as string | undefined)?.trim() || null;
    const dateTo    = (req.query.dateTo   as string | undefined)?.trim() || null;
    const status    = (req.query.status   as string | undefined)?.trim() || null;

    const conds = [];
    if (proxyIp)  conds.push(sql`proxy_ip = ${proxyIp}`);
    if (host)     conds.push(sql`url ilike ${"%" + host + "%"}`);
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

    const tenantId         = (req as any).user!.tenantId as number;
    const circuits         = getAllCircuits(tenantId);
    const openCircuits     = circuits.filter(c => c.state === "open").length;
    const rateLimiterStats = getAllRateLimiterStats(tenantId);
    const dnsStats         = getDnsResolverStats();

    // Retry queue size — count requests still being retried (retries > 0 in last 5 min)
    const [retryQueue] = await db
      .select({ size: sql<number>`count(*) filter (where retries > 0)::int` })
      .from(scanRequestTelemetryTable)
      .where(gte(scanRequestTelemetryTable.createdAt, since5m));

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
      wafProtectedHosts: getWafProtectedHosts(tenantId).slice(0, 50),
    });
  } catch (err) {
    logger.error({ err }, "GET /api/scan-telemetry/stats error");
    res.status(500).json({ error: "Failed to fetch telemetry stats" });
  }
});

export default router;
