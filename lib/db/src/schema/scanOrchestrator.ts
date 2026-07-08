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

export type ScanProxy           = typeof scanProxiesTable.$inferSelect;
export type OrchestratorConfig  = typeof orchestratorConfigTable.$inferSelect;
export type ScanFingerprintProfile = typeof scanFingerprintProfilesTable.$inferSelect;
export type ScanRequestTelemetry = typeof scanRequestTelemetryTable.$inferSelect;
