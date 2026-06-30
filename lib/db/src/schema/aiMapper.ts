import { pgTable, serial, integer, text, boolean, jsonb, real, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";

export const aiMapperModuleAssignmentsTable = pgTable("ai_mapper_module_assignments", {
  tenantId:  integer("tenant_id").primaryKey().references(() => tenantsTable.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").notNull().default(false),
  enabledBy: integer("enabled_by").references(() => usersTable.id, { onDelete: "set null" }),
  enabledAt: timestamp("enabled_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
});

export const aiMapperScansTable = pgTable("ai_mapper_scans", {
  id:            serial("id").primaryKey(),
  tenantId:      integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  title:         text("title").notNull().default("AI Surface Scan"),
  status:        text("status").notNull().default("pending"),
  progress:      integer("progress").notNull().default(0),
  queryPresets:  jsonb("query_presets").notNull().default([]),
  cidrScope:     text("cidr_scope"),
  totalHosts:    integer("total_hosts").notNull().default(0),
  liveHosts:     integer("live_hosts").notNull().default(0),
  scannedHosts:  integer("scanned_hosts").notNull().default(0),
  endpointCount: integer("endpoint_count").notNull().default(0),
  modalJobId:    text("modal_job_id"),
  createdBy:     integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  startedAt:     timestamp("started_at",   { withTimezone: true }),
  completedAt:   timestamp("completed_at", { withTimezone: true }),
  createdAt:     timestamp("created_at",   { withTimezone: true }).notNull().defaultNow(),
});

export const aiMapperEndpointsTable = pgTable("ai_mapper_endpoints", {
  id:                  serial("id").primaryKey(),
  tenantId:            integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  scanId:              integer("scan_id").references(() => aiMapperScansTable.id, { onDelete: "set null" }),
  ip:                  text("ip").notNull(),
  port:                integer("port").notNull(),
  hostname:            text("hostname"),
  url:                 text("url").notNull(),
  protocol:            text("protocol").notNull().default("unknown"),
  framework:           text("framework"),
  authStatus:          text("auth_status").notNull().default("unknown"),
  riskScore:           real("risk_score").notNull().default(0),
  riskLevel:           text("risk_level").notNull().default("low"),
  tools:               jsonb("tools").notNull().default([]),
  models:              jsonb("models").notNull().default([]),
  systemPromptLeaked:  boolean("system_prompt_leaked").notNull().default(false),
  systemPromptContent: text("system_prompt_content"),
  corsPolicy:          text("cors_policy"),
  hasTls:              boolean("has_tls").notNull().default(false),
  signupEnabled:       boolean("signup_enabled").notNull().default(false),
  country:             text("country"),
  org:                 text("org"),
  city:                text("city"),
  lat:                 real("lat"),
  lng:                 real("lng"),
  rawNucleiOutput:     text("raw_nuclei_output"),
  firstSeenAt:         timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt:          timestamp("last_seen_at",  { withTimezone: true }).notNull().defaultNow(),
});

export const aiMapperAttackRunsTable = pgTable("ai_mapper_attack_runs", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  endpointId:  integer("endpoint_id").notNull().references(() => aiMapperEndpointsTable.id, { onDelete: "cascade" }),
  profile:     text("profile").notNull().default("generic"),
  status:      text("status").notNull().default("pending"),
  progress:    integer("progress").notNull().default(0),
  results:     jsonb("results").notNull().default([]),
  createdBy:   integer("created_by").references(() => usersTable.id, { onDelete: "set null" }),
  startedAt:   timestamp("started_at",   { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  createdAt:   timestamp("created_at",   { withTimezone: true }).notNull().defaultNow(),
});

export const aiMapperBomItemsTable = pgTable("ai_mapper_bom_items", {
  id:               serial("id").primaryKey(),
  tenantId:         integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  framework:        text("framework").notNull(),
  endpointCount:    integer("endpoint_count").notNull().default(0),
  highestRiskLevel: text("highest_risk_level").notNull().default("low"),
  uniqueModels:     jsonb("unique_models").notNull().default([]),
  uniqueTools:      jsonb("unique_tools").notNull().default([]),
  firstSeenAt:      timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt:       timestamp("last_seen_at",  { withTimezone: true }).notNull().defaultNow(),
});

export type AiMapperModuleAssignment = typeof aiMapperModuleAssignmentsTable.$inferSelect;
export type AiMapperScan             = typeof aiMapperScansTable.$inferSelect;
export type AiMapperEndpoint         = typeof aiMapperEndpointsTable.$inferSelect;
export type AiMapperAttackRun        = typeof aiMapperAttackRunsTable.$inferSelect;
export type AiMapperBomItem          = typeof aiMapperBomItemsTable.$inferSelect;
