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
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
export type ScanAssetResult = typeof scanAssetResultsTable.$inferSelect;
