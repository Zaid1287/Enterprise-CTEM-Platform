import { pgTable, serial, text, integer, real, boolean, timestamp, jsonb, unique } from "drizzle-orm/pg-core";

export const scanProxiesTable = pgTable("scan_proxies", {
  id:                 serial("id").primaryKey(),
  ip:                 text("ip").notNull(),
  port:               integer("port").notNull().default(8080),
  label:              text("label"),
  type:               text("type").notNull().default("http"),
  country:            text("country"),
  asn:                text("asn"),
  username:           text("username"),
  password:           text("password"),
  healthScore:        real("health_score").notNull().default(100),
  successCount:       integer("success_count").notNull().default(0),
  failCount:          integer("fail_count").notNull().default(0),
  count429:           integer("count_429").notNull().default(0),
  count403:           integer("count_403").notNull().default(0),
  timeoutCount:       integer("timeout_count").notNull().default(0),
  avgLatencyMs:       real("avg_latency_ms"),
  consecutiveFailures:integer("consecutive_failures").notNull().default(0),
  cooldownUntil:      timestamp("cooldown_until", { withTimezone: true }),
  status:             text("status").notNull().default("active"),
  lastTestedAt:       timestamp("last_tested_at", { withTimezone: true }),
  createdAt:          timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const orchestratorConfigTable = pgTable("orchestrator_config", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull(),
  key:         text("key").notNull(),
  value:       text("value").notNull(),
  description: text("description"),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [unique("orchestrator_config_tenant_key_unique").on(t.tenantId, t.key)]);

export const scanFingerprintProfilesTable = pgTable("scan_fingerprint_profiles", {
  id:        serial("id").primaryKey(),
  name:      text("name").notNull().unique(),
  headers:   jsonb("headers").$type<Record<string, string>>().notNull(),
  isActive:  boolean("is_active").notNull().default(true),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export const scanRequestTelemetryTable = pgTable("scan_request_telemetry", {
  id:                    serial("id").primaryKey(),
  tenantId:              integer("tenant_id"),
  scanId:                integer("scan_id"),
  assetId:               integer("asset_id"),
  target:                text("target"),
  method:                text("method").notNull().default("GET"),
  url:                   text("url").notNull(),
  proxyId:               integer("proxy_id"),
  fingerprintProfileId:  integer("fingerprint_profile_id"),
  statusCode:            integer("status_code"),
  latencyMs:             real("latency_ms"),
  retries:               integer("retries").notNull().default(0),
  delayAppliedMs:        real("delay_applied_ms"),
  backoffAppliedMs:      real("backoff_applied_ms"),
  healthScoreAtDispatch: real("health_score_at_dispatch"),
  circuitBreakerState:   text("circuit_breaker_state"),
  wafDetected:           boolean("waf_detected").notNull().default(false),
  captchaDetected:       boolean("captcha_detected").notNull().default(false),
  bytesDownloaded:       integer("bytes_downloaded"),
  degradedMode:          boolean("degraded_mode").notNull().default(false),
  createdAt:             timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── WAF bypass stats — per-tenant/hostname/day aggregated counters ─────────────
// Incremented atomically on every orchestrated request; used by:
//   • Auto-tuner: reads last-24h WAF rate to adjust scan_delay_multiplier
//   • Dashboard:  drives the "WAF Bypass Success %" chart per domain over time
//   • A/B tests:  one counter per profile via orchestratorProfileStatsTable
export const orchestratorWafStatsTable = pgTable("orchestrator_waf_stats", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull(),
  hostname:        text("hostname").notNull(),
  statDate:        text("stat_date").notNull(), // YYYY-MM-DD UTC
  totalRequests:   integer("total_requests").notNull().default(0),
  wafHits:         integer("waf_hits").notNull().default(0),
  bypassSuccesses: integer("bypass_successes").notNull().default(0),
  captchaHits:     integer("captcha_hits").notNull().default(0),
  directSuccesses: integer("direct_successes").notNull().default(0),
  updatedAt:       timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [unique("orchestrator_waf_stats_unique").on(t.tenantId, t.hostname, t.statDate)]);

// ── Fingerprint profile A/B stats — per-profile success/WAF-block counters ────
// UCB1 (Upper Confidence Bound) algorithm uses these to pick the highest-
// performing profile while still exploring under-tested ones.
export const orchestratorProfileStatsTable = pgTable("orchestrator_profile_stats", {
  id:          serial("id").primaryKey(),
  profileId:   integer("profile_id").notNull(),
  tenantId:    integer("tenant_id").notNull(),
  totalUses:   integer("total_uses").notNull().default(0),
  successes:   integer("successes").notNull().default(0),
  wafBlocked:  integer("waf_blocked").notNull().default(0),
  lastUsedAt:  timestamp("last_used_at", { withTimezone: true }),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [unique("orchestrator_profile_stats_unique").on(t.profileId, t.tenantId)]);

// ── Auto-tuner action log — immutable record of every tuning decision ──────────
// Written whenever the auto-tuner adjusts scan_delay_multiplier or enables/
// disables WAF bypass.  Surfaced in the "Auto-Tuner" dashboard tab so operators
// can audit what the system changed and why.
export const orchestratorTuningLogTable = pgTable("orchestrator_tuning_log", {
  id:        serial("id").primaryKey(),
  tenantId:  integer("tenant_id").notNull(),
  hostname:  text("hostname"),
  action:    text("action").notNull(),
  oldValue:  text("old_value"),
  newValue:  text("new_value"),
  reason:    text("reason"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type ScanProxy              = typeof scanProxiesTable.$inferSelect;
export type OrchestratorConfig     = typeof orchestratorConfigTable.$inferSelect;
export type ScanFingerprintProfile = typeof scanFingerprintProfilesTable.$inferSelect;
export type ScanRequestTelemetry   = typeof scanRequestTelemetryTable.$inferSelect;
export type OrchestratorWafStats   = typeof orchestratorWafStatsTable.$inferSelect;
export type OrchestratorProfileStats = typeof orchestratorProfileStatsTable.$inferSelect;
export type OrchestratorTuningLog  = typeof orchestratorTuningLogTable.$inferSelect;
