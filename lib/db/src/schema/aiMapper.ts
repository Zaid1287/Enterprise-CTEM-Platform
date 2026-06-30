import { pgTable, serial, integer, text, boolean, jsonb, real, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const aiMapperScansTable = pgTable("ai_mapper_scans", {
  id:             serial("id").primaryKey(),
  tenantId:       integer("tenant_id").notNull().references(() => tenantsTable.id),
  status:         text("status").notNull().default("pending"),
  assetIds:       jsonb("asset_ids").notNull().default([]),
  resultCount:    integer("result_count").notNull().default(0),
  unauthCount:    integer("unauth_count").notNull().default(0),
  highRiskCount:  integer("high_risk_count").notNull().default(0),
  error:          text("error"),
  startedAt:      timestamp("started_at",   { withTimezone: true }).notNull().defaultNow(),
  completedAt:    timestamp("completed_at", { withTimezone: true }),
});

export const aiMapperResultsTable = pgTable("ai_mapper_results", {
  id:             serial("id").primaryKey(),
  scanId:         integer("scan_id").notNull().references(() => aiMapperScansTable.id, { onDelete: "cascade" }),
  tenantId:       integer("tenant_id").notNull().references(() => tenantsTable.id),
  assetId:        integer("asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  url:            text("url").notNull(),
  host:           text("host"),
  port:           integer("port"),
  serviceType:    text("service_type").notNull(),
  framework:      text("framework"),
  version:        text("version"),
  isAuthenticated: boolean("is_authenticated").notNull().default(false),
  corsPolicy:     text("cors_policy"),
  riskScore:      integer("risk_score").notNull().default(0),
  riskLevel:      text("risk_level").notNull().default("info"),
  modelsExposed:  jsonb("models_exposed"),
  toolsExposed:   jsonb("tools_exposed"),
  rawResponse:    text("raw_response"),
  ip:             text("ip"),
  country:        text("country"),
  countryCode:    text("country_code"),
  city:           text("city"),
  org:            text("org"),
  lat:            real("lat"),
  lon:            real("lon"),
  discoveredAt:   timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AiMapperScan   = typeof aiMapperScansTable.$inferSelect;
export type AiMapperResult = typeof aiMapperResultsTable.$inferSelect;
