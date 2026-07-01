import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";
import { assetsTable } from "./assets";

export const customScriptsTable = pgTable("custom_scripts", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:        text("name").notNull(),
  description: text("description"),
  language:    text("language").notNull().default("bash"),
  content:     text("content").notNull(),
  timeout:     integer("timeout").notNull().default(60),
  createdBy:   integer("created_by").references(() => usersTable.id),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const customScriptAssignmentsTable = pgTable("custom_script_assignments", {
  id:        serial("id").primaryKey(),
  tenantId:  integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  scriptId:  integer("script_id").notNull().references(() => customScriptsTable.id, { onDelete: "cascade" }),
  assetId:   integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const customScriptRunsTable = pgTable("custom_script_runs", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  scriptId:    integer("script_id").notNull().references(() => customScriptsTable.id),
  assetId:     integer("asset_id").notNull(),
  scanId:      integer("scan_id"),
  status:      text("status").notNull().default("pending"),
  stdout:      text("stdout"),
  stderr:      text("stderr"),
  exitCode:    integer("exit_code"),
  startedAt:   timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type CustomScript = typeof customScriptsTable.$inferSelect;
export type CustomScriptRun = typeof customScriptRunsTable.$inferSelect;
