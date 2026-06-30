import { pgTable, serial, text, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  type: text("type").notNull().default("full"),
  status: text("status").notNull().default("pending"),
  schedule: text("schedule"),
  assetIds: integer("asset_ids").array().notNull().default([]),
  scanModules: text("scan_modules").array().notNull().default([]),
  findingsCount: integer("findings_count").notNull().default(0),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const scanJobsTable = pgTable("scan_jobs", {
  id: serial("id").primaryKey(),
  scanId: integer("scan_id").notNull().references(() => scansTable.id),
  assetId: integer("asset_id").notNull(),
  status: text("status").notNull().default("pending"),
  result: text("result"),
  errorMessage: text("error_message"),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const scanAssetResultsTable = pgTable("scan_asset_results", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  scanId: integer("scan_id").notNull().references(() => scansTable.id, { onDelete: "cascade" }),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id),
  toolName: text("tool_name").notNull(),
  toolCategory: text("tool_category").notNull(),
  rawOutput: text("raw_output"),
  ports: jsonb("ports"),
  subdomains: jsonb("subdomains"),
  endpoints: jsonb("endpoints"),
  httpInfo: jsonb("http_info"),
  dnsRecords: jsonb("dns_records"),
  intelligence: jsonb("intelligence"),
  vulnerabilities: jsonb("vulnerabilities"),
  jsAnalysis: jsonb("js_analysis"),
  paramDiscovery: jsonb("param_discovery"),
  cloudRecon: jsonb("cloud_recon"),
  secretsHunt: jsonb("secrets_hunt"),
  dirFuzz: jsonb("dir_fuzz"),
  vulnScan: jsonb("vuln_scan"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const scanSchedulesTable = pgTable("scan_schedules", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  assetToolConfig: jsonb("asset_tool_config").notNull(),
  frequency: text("frequency").notNull().default("once"),
  runTime: text("run_time").notNull().default("09:00"),
  dayOfWeek: integer("day_of_week"),
  dayOfMonth: integer("day_of_month"),
  timezone: text("timezone").notNull().default("+00:00"),
  status: text("status").notNull().default("active"),
  lastRunAt: timestamp("last_run_at", { withTimezone: true }),
  nextRunAt: timestamp("next_run_at", { withTimezone: true }),
  lastScanId: integer("last_scan_id"),
  createdBy: integer("created_by"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
export type ScanAssetResult = typeof scanAssetResultsTable.$inferSelect;
export type ScanSchedule = typeof scanSchedulesTable.$inferSelect;
