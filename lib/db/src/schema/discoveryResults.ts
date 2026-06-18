import { pgTable, serial, text, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const discoveryResultsTable = pgTable("discovery_results", {
  id:        serial("id").primaryKey(),
  tenantId:  integer("tenant_id").notNull().references(() => tenantsTable.id),
  assetId:   integer("asset_id").notNull().references(() => assetsTable.id),
  scanId:    integer("scan_id"),
  source:    text("source").notNull(),
  status:    text("status").notNull().default("ok"),
  data:      jsonb("data"),
  summary:   text("summary"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type DiscoveryResult = typeof discoveryResultsTable.$inferSelect;
