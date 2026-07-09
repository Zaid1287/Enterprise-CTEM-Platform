import { Router } from "express";
import { requireAuth, verifyToken } from "../lib/auth.js";
import { db, scanProxiesTable, orchestratorConfigTable, scanFingerprintProfilesTable, scanRequestTelemetryTable, orchestratorWafStatsTable, orchestratorProfileStatsTable, orchestratorTuningLogTable } from "@workspace/db";
import { eq, desc, sql, gte, and, isNotNull, asc } from "drizzle-orm";
import { healthCheckProxy, testProxyWithAuth } from "../lib/proxyHealthCheck.js";
import { getAllCircuits } from "../lib/circuitBreaker.js";
import { getAllRateLimiterStats } from "../lib/adaptiveRateLimiter.js";
import { getDnsResolverStats } from "../lib/dnsResolverPool.js";
import { invalidateConfigCache, getWafProtectedHosts, orchestratedFetch } from "../lib/scanOrchestrator.js";
import { addWaterfallSseClient, removeWaterfallSseClient } from "../lib/sseManager.js";
import { logger } from "../lib/logger.js";
import { encryptCredential, decryptCredential, decryptCredentialWithSecret } from "../lib/proxyCredentialEncryption.js";
import { logAudit, getClientIp } from "../lib/audit.js";

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

router.get("/scan-proxies", requireAuth, requireAdmin, async (req, res) => {
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

router.post("/scan-proxies", requireAuth, requireSuperAdmin, async (req, res) => {
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

router.patch("/scan-proxies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    const { ip, port, label, type, country, asn, status, username, password, resetAuthFailed } = req.body;
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

    // If the caller wants to re-enable an auth-failed proxy, verify it is actually
    // in that state first and then reset its health/cooldown fields.
    if (resetAuthFailed === true) {
      const [existing] = await db
        .select({ status: scanProxiesTable.status })
        .from(scanProxiesTable)
        .where(eq(scanProxiesTable.id, id));
      if (!existing) { res.status(404).json({ error: "Proxy not found" }); return; }
      if (existing.status !== "auth_failed") {
        res.status(400).json({ error: "Proxy is not in auth_failed state" }); return;
      }
      updates.status        = "active";
      updates.healthScore   = 50;
      updates.cooldownUntil = null;
    }

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

router.delete("/scan-proxies/:id", requireAuth, requireSuperAdmin, async (req, res) => {
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

router.get("/scan-proxies/:id/health", requireAuth, requireAdmin, async (req, res) => {
  try {
    const id = parseId(req.params.id);
    if (isNaN(id)) { res.status(400).json({ error: "Invalid id" }); return; }

    const testUrl = typeof req.query.testUrl === "string" ? req.query.testUrl.trim() : null;

    const [proxy] = await db
      .select({
        id: scanProxiesTable.id,
        ip: scanProxiesTable.ip,
        port: scanProxiesTable.port,
        type: scanProxiesTable.type,
        username: scanProxiesTable.username,
        password: scanProxiesTable.password,
      })
      .from(scanProxiesTable)
      .where(eq(scanProxiesTable.id, id));

    if (!proxy) { res.status(404).json({ error: "Proxy not found" }); return; }

    const proxyPort = proxy.port ?? 8080;

    if (testUrl) {
      // Auth-aware test: decrypt credentials and make a real connection through the proxy
      const plainPassword = proxy.password ? decryptCredential(proxy.password) : null;

      const result = await testProxyWithAuth(
        proxy.ip,
        proxyPort,
        proxy.type ?? "http",
        proxy.username ?? null,
        plainPassword,
        testUrl,
      );

      await db.update(scanProxiesTable)
        .set({
          lastTestedAt: new Date(),
          status: result.reachable ? "active" : "inactive",
          avgLatencyMs: result.reachable ? result.latencyMs : undefined,
        } as any)
        .where(eq(scanProxiesTable.id, id));

      res.json({ proxyId: id, ...result });
    } else {
      // TCP-only reachability check (legacy behaviour)
      const health = await healthCheckProxy(proxy.ip, proxyPort);

      await db.update(scanProxiesTable)
        .set({
          lastTestedAt: new Date(),
          status: health.reachable ? "active" : "inactive",
          avgLatencyMs: health.reachable ? health.latencyMs : undefined,
        } as any)
        .where(eq(scanProxiesTable.id, id));

      res.json({ proxyId: id, ...health });
    }
  } catch (err) {
    logger.error({ err }, "GET /api/scan-proxies/:id/health error");
    res.status(500).json({ error: "Failed to health-check proxy" });
  }
});

// ── Issue 3: Bulk proxy import (CSV / paste) ───────────────────────────────────
// Accepts: { proxies: "1.2.3.4:8080\n5.6.7.8:3128:user:pass" }
// Or: { proxies: [{ ip, port, username?, password?, label?, type?, country? }] }
router.post("/scan-proxies/bulk", requireAuth, requireSuperAdmin, async (req, res) => {
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

// ── Key rotation ──────────────────────────────────────────────────────────────
// POST /api/scan-proxies/rotate-key
// Decrypts all stored proxy passwords with the supplied old SESSION_SECRET and
// re-encrypts them with the current SESSION_SECRET.  super_admin only.
// Body: { oldSecret: string }
// Response: { reencrypted: number, failed: number, failures: { id, error }[] }

router.post("/scan-proxies/rotate-key", requireAuth, requireSuperAdmin, async (req: any, res) => {
  try {
    const { oldSecret } = req.body ?? {};
    if (!oldSecret || typeof oldSecret !== "string") {
      res.status(400).json({ error: "oldSecret is required" });
      return;
    }

    const proxies = await db
      .select({ id: scanProxiesTable.id, password: scanProxiesTable.password })
      .from(scanProxiesTable)
      .where(isNotNull(scanProxiesTable.password));

    let reencrypted = 0;
    const failures: { id: number; error: string }[] = [];

    for (const proxy of proxies) {
      const stored = proxy.password!;
      const plaintext = decryptCredentialWithSecret(stored, oldSecret);
      if (plaintext === null) {
        failures.push({ id: proxy.id, error: "Decryption failed — wrong key or corrupted data" });
        continue;
      }
      try {
        const newEncrypted = encryptCredential(plaintext);
        await db
          .update(scanProxiesTable)
          .set({ password: newEncrypted } as any)
          .where(eq(scanProxiesTable.id, proxy.id));
        reencrypted++;
      } catch (err: any) {
        failures.push({ id: proxy.id, error: err?.message ?? "DB update failed" });
      }
    }

    logger.info({ reencrypted, failed: failures.length }, "Proxy key rotation complete");

    await logAudit(
      req.user!,
      "rotate_proxy_encryption_key",
      "scan_proxy",
      undefined,
      JSON.stringify({ reencrypted, failed: failures.length }),
      getClientIp(req),
      { userAgent: req.headers["user-agent"] }
    );

    res.json({ reencrypted, failed: failures.length, failures });
  } catch (err) {
    logger.error({ err }, "POST /api/scan-proxies/rotate-key error");
    res.status(500).json({ error: "Key rotation failed" });
  }
});

// ── Orchestrator Config ────────────────────────────────────────────────────────

router.get("/orchestrator-config", requireAuth, requireAdmin, async (req: any, res) => {
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

router.patch("/orchestrator-config", requireAuth, requireAdmin, async (req: any, res) => {
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

router.get("/scan-fingerprints", requireAuth, requireAdmin, async (req, res) => {
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

router.get("/scan-fingerprints/:id", requireAuth, requireAdmin, async (req, res) => {
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

router.patch("/scan-fingerprints/:id", requireAuth, requireSuperAdmin, async (req, res) => {
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
router.get("/scan-telemetry/stream", (req: any, res: any) => {
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

router.get("/scan-telemetry", requireAuth, requireAdmin, async (req, res) => {
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

router.get("/scan-telemetry/stats", requireAuth, requireAdmin, async (req, res) => {
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

// ── WAF Bypass Dashboard: per-hostname, per-day stats ─────────────────────────
router.get("/waf-bypass-stats", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;
    const days = Math.min(parseInt(String(req.query.days ?? "30"), 10) || 30, 90);
    const sinceDate = new Date(Date.now() - days * 24 * 60 * 60_000).toISOString().slice(0, 10);

    const rows = await db
      .select()
      .from(orchestratorWafStatsTable)
      .where(and(
        eq(orchestratorWafStatsTable.tenantId, tenantId),
        gte(orchestratorWafStatsTable.statDate, sinceDate),
      ))
      .orderBy(asc(orchestratorWafStatsTable.statDate));

    // Aggregate totals across all hostnames
    const totals = rows.reduce(
      (acc, r) => {
        acc.totalRequests   += r.totalRequests;
        acc.wafHits         += r.wafHits;
        acc.bypassSuccesses += r.bypassSuccesses;
        acc.captchaHits     += r.captchaHits;
        acc.directSuccesses += r.directSuccesses;
        return acc;
      },
      { totalRequests: 0, wafHits: 0, bypassSuccesses: 0, captchaHits: 0, directSuccesses: 0 },
    );

    // Per-hostname summary
    const byHost: Record<string, typeof totals> = {};
    for (const r of rows) {
      if (!byHost[r.hostname]) {
        byHost[r.hostname] = { totalRequests: 0, wafHits: 0, bypassSuccesses: 0, captchaHits: 0, directSuccesses: 0 };
      }
      const h = byHost[r.hostname]!;
      h.totalRequests   += r.totalRequests;
      h.wafHits         += r.wafHits;
      h.bypassSuccesses += r.bypassSuccesses;
      h.captchaHits     += r.captchaHits;
      h.directSuccesses += r.directSuccesses;
    }

    // Per-day trend (aggregated across all hosts)
    const byDay: Record<string, typeof totals> = {};
    for (const r of rows) {
      if (!byDay[r.statDate]) {
        byDay[r.statDate] = { totalRequests: 0, wafHits: 0, bypassSuccesses: 0, captchaHits: 0, directSuccesses: 0 };
      }
      const d = byDay[r.statDate]!;
      d.totalRequests   += r.totalRequests;
      d.wafHits         += r.wafHits;
      d.bypassSuccesses += r.bypassSuccesses;
      d.captchaHits     += r.captchaHits;
      d.directSuccesses += r.directSuccesses;
    }

    const computeBypassRate = (b: typeof totals) =>
      b.wafHits + b.bypassSuccesses > 0
        ? Math.round((b.bypassSuccesses / (b.wafHits + b.bypassSuccesses)) * 1000) / 10
        : null;

    const trend = Object.entries(byDay)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, b]) => ({
        date,
        totalRequests:   b.totalRequests,
        wafHits:         b.wafHits,
        bypassSuccesses: b.bypassSuccesses,
        captchaHits:     b.captchaHits,
        directSuccesses: b.directSuccesses,
        bypassRate:      computeBypassRate(b),
        wafRate:         b.totalRequests > 0 ? Math.round(b.wafHits / b.totalRequests * 1000) / 10 : 0,
      }));

    const hostSummary = Object.entries(byHost).map(([hostname, b]) => ({
      hostname,
      totalRequests:   b.totalRequests,
      wafHits:         b.wafHits,
      bypassSuccesses: b.bypassSuccesses,
      captchaHits:     b.captchaHits,
      directSuccesses: b.directSuccesses,
      bypassRate:      computeBypassRate(b),
      wafRate:         b.totalRequests > 0 ? Math.round(b.wafHits / b.totalRequests * 1000) / 10 : 0,
    })).sort((a, b) => b.totalRequests - a.totalRequests);

    res.json({
      days,
      sinceDate,
      totals: { ...totals, bypassRate: computeBypassRate(totals), wafRate: totals.totalRequests > 0 ? Math.round(totals.wafHits / totals.totalRequests * 1000) / 10 : 0 },
      trend,
      hostSummary,
    });
  } catch (err) {
    logger.error({ err }, "GET /api/waf-bypass-stats error");
    res.status(500).json({ error: "Failed to fetch WAF bypass stats" });
  }
});

// ── A/B Profile Stats: UCB1 performance per fingerprint profile ───────────────
router.get("/fingerprint-profile-stats", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;

    // Join profile stats with profile names
    const profiles = await db
      .select({
        id:        scanFingerprintProfilesTable.id,
        name:      scanFingerprintProfilesTable.name,
        isActive:  scanFingerprintProfilesTable.isActive,
        updatedAt: scanFingerprintProfilesTable.updatedAt,
      })
      .from(scanFingerprintProfilesTable);

    const stats = await db
      .select()
      .from(orchestratorProfileStatsTable)
      .where(eq(orchestratorProfileStatsTable.tenantId, tenantId));

    const statsMap = new Map(stats.map(s => [s.profileId, s]));

    // Compute UCB1 scores for display
    const totalUses = stats.reduce((sum, s) => sum + s.totalUses, 0) || 1;
    const C = Math.SQRT2;

    const result = profiles.map(p => {
      const s = statsMap.get(p.id);
      let ucb1Score: number | null = null;
      let successRate: number | null = null;
      let wafBlockRate: number | null = null;
      if (s && s.totalUses > 0) {
        successRate  = Math.round(s.successes / s.totalUses * 1000) / 10;
        wafBlockRate = Math.round(s.wafBlocked / s.totalUses * 1000) / 10;
        ucb1Score    = Math.round((s.successes / s.totalUses + C * Math.sqrt(Math.log(totalUses) / s.totalUses)) * 1000) / 1000;
      }
      return {
        profileId:    p.id,
        name:         p.name,
        isActive:     p.isActive,
        totalUses:    s?.totalUses ?? 0,
        successes:    s?.successes ?? 0,
        wafBlocked:   s?.wafBlocked ?? 0,
        lastUsedAt:   s?.lastUsedAt ?? null,
        successRate,
        wafBlockRate,
        ucb1Score,
        status: !s || s.totalUses === 0 ? "untested" : ucb1Score! > 0.8 ? "excellent" : ucb1Score! > 0.5 ? "good" : "poor",
      };
    }).sort((a, b) => (b.ucb1Score ?? Infinity) - (a.ucb1Score ?? Infinity));

    res.json({ profiles: result, totalUses });
  } catch (err) {
    logger.error({ err }, "GET /api/fingerprint-profile-stats error");
    res.status(500).json({ error: "Failed to fetch profile stats" });
  }
});

// ── Dry-Run Test Bypass: validate bypass effectiveness on a real URL ───────────
// Runs one real HTTP request through the full orchestrator stack (proxy, fingerprint
// rotation, WAF detection, retry logic) and returns detailed diagnostics.  Does NOT
// store any findings or create scans — purely a readiness test.
router.post("/orchestrator/test-bypass", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;
    const { url } = req.body as { url?: string };
    if (!url || typeof url !== "string") {
      res.status(400).json({ error: "url is required" }); return;
    }

    // Validate URL
    let parsedUrl: URL;
    try { parsedUrl = new URL(url.startsWith("http") ? url : `https://${url}`); }
    catch { res.status(400).json({ error: "Invalid URL" }); return; }

    const targetUrl = parsedUrl.href;
    const startMs   = Date.now();
    let statusCode: number | null = null;
    let wafDetected = false;
    let bypassSuccess = false;
    let responseHeaders: Record<string, string> = {};
    let bodyExcerpt = "";
    let error: string | null = null;
    let retries = 0;

    // Peek at the most recent telemetry for this tenant+url after the fetch
    try {
      const resp = await orchestratedFetch(
        targetUrl,
        { method: "GET" },
        {
          tenantId,
          target:    parsedUrl.hostname,
          isDryRun:  true,
        } as any,
      );

      statusCode = resp.status;
      resp.headers.forEach((v, k) => { responseHeaders[k.toLowerCase()] = v; });
      const body = await resp.text().catch(() => "");
      bodyExcerpt = body.slice(0, 600);
    } catch (err: any) {
      error = err?.message ?? "Request failed";
    }

    const latencyMs = Date.now() - startMs;

    // Query most recent telemetry row for this URL to get orchestrator internals
    const [tel] = await db
      .select()
      .from(scanRequestTelemetryTable)
      .where(
        and(
          eq(scanRequestTelemetryTable.tenantId, tenantId),
          eq(scanRequestTelemetryTable.url, targetUrl),
        )
      )
      .orderBy(desc(scanRequestTelemetryTable.createdAt))
      .limit(1);

    if (tel) {
      wafDetected   = tel.wafDetected;
      retries       = tel.retries;
      // bypass successful = WAF was detected but we eventually got through (200)
      bypassSuccess = tel.wafDetected && (statusCode !== null && statusCode < 400);
    } else {
      wafDetected   = statusCode !== null && (statusCode === 403 || statusCode === 429);
      bypassSuccess = false;
    }

    // Also query WAF bypass stats to get historical bypass rate for this hostname
    const sinceDate = new Date(Date.now() - 7 * 24 * 60 * 60_000).toISOString().slice(0, 10);
    const [hostStats] = await db
      .select({
        totalRequests:   sql<number>`sum(total_requests)::int`,
        wafHits:         sql<number>`sum(waf_hits)::int`,
        bypassSuccesses: sql<number>`sum(bypass_successes)::int`,
      })
      .from(orchestratorWafStatsTable)
      .where(and(
        eq(orchestratorWafStatsTable.tenantId, tenantId),
        eq(orchestratorWafStatsTable.hostname, parsedUrl.hostname),
        gte(orchestratorWafStatsTable.statDate, sinceDate),
      ));

    const historicalBypassRate = hostStats && (hostStats.wafHits ?? 0) + (hostStats.bypassSuccesses ?? 0) > 0
      ? Math.round((hostStats.bypassSuccesses ?? 0) / ((hostStats.wafHits ?? 0) + (hostStats.bypassSuccesses ?? 0)) * 1000) / 10
      : null;

    res.json({
      url:                targetUrl,
      hostname:           parsedUrl.hostname,
      statusCode,
      latencyMs,
      wafDetected,
      bypassSuccess,
      retries,
      error,
      responseHeaders,
      bodyExcerpt,
      proxyUsed:          tel?.proxyId != null,
      profileUsed:        tel?.fingerprintProfileId ?? null,
      circuitBreakerState: tel?.circuitBreakerState ?? null,
      historicalBypassRate,
      historicalWafHits:  hostStats?.wafHits ?? 0,
      testedAt:           new Date().toISOString(),
    });
  } catch (err) {
    logger.error({ err }, "POST /api/orchestrator/test-bypass error");
    res.status(500).json({ error: "Test failed" });
  }
});

// ── Auto-Tuner Log: recent tuning decisions ───────────────────────────────────
router.get("/orchestrator/tuning-log", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const tenantId = req.user!.tenantId as number;
    const limit = Math.min(parseInt(String(req.query.limit ?? "50"), 10) || 50, 200);

    const rows = await db
      .select()
      .from(orchestratorTuningLogTable)
      .where(eq(orchestratorTuningLogTable.tenantId, tenantId))
      .orderBy(desc(orchestratorTuningLogTable.createdAt))
      .limit(limit);

    // Current delay multiplier from config
    const [multiplierRow] = await db
      .select({ value: orchestratorConfigTable.value })
      .from(orchestratorConfigTable)
      .where(and(
        eq(orchestratorConfigTable.tenantId, tenantId),
        eq(orchestratorConfigTable.key, "scan_delay_multiplier"),
      ));

    const [bypassRow] = await db
      .select({ value: orchestratorConfigTable.value })
      .from(orchestratorConfigTable)
      .where(and(
        eq(orchestratorConfigTable.tenantId, tenantId),
        eq(orchestratorConfigTable.key, "waf_bypass_strategy"),
      ));

    // Last 24h WAF rate for this tenant
    const sinceDate = new Date(Date.now() - 24 * 60 * 60_000).toISOString().slice(0, 10);
    const [agg24h] = await db
      .select({
        total:   sql<number>`coalesce(sum(total_requests), 0)::int`,
        wafHits: sql<number>`coalesce(sum(waf_hits), 0)::int`,
      })
      .from(orchestratorWafStatsTable)
      .where(and(
        eq(orchestratorWafStatsTable.tenantId, tenantId),
        gte(orchestratorWafStatsTable.statDate, sinceDate),
      ));

    const wafRate24h = (agg24h?.total ?? 0) > 0
      ? Math.round((agg24h?.wafHits ?? 0) / (agg24h?.total ?? 1) * 1000) / 10
      : null;

    res.json({
      currentMultiplier:     parseFloat(multiplierRow?.value ?? "1.0"),
      currentBypassStrategy: bypassRow?.value ?? "none",
      wafRate24h,
      totalRequests24h:      agg24h?.total ?? 0,
      wafHits24h:            agg24h?.wafHits ?? 0,
      log: rows,
    });
  } catch (err) {
    logger.error({ err }, "GET /api/orchestrator/tuning-log error");
    res.status(500).json({ error: "Failed to fetch tuning log" });
  }
});

// ── Trigger manual auto-tuner run ─────────────────────────────────────────────
router.post("/orchestrator/run-tuner", requireAuth, requireAdmin, async (req: any, res) => {
  try {
    const { runAutoTunerCycle } = await import("../lib/autoTuner.js");
    await runAutoTunerCycle();
    res.json({ ok: true, message: "Auto-tuner cycle completed" });
  } catch (err) {
    logger.error({ err }, "POST /api/orchestrator/run-tuner error");
    res.status(500).json({ error: "Tuner run failed" });
  }
});

export default router;
