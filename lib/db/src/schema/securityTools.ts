import { pgTable, serial, text, integer, boolean, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";

export const securityToolsTable = pgTable("security_tools", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  description: text("description"),
  githubUrl: text("github_url").notNull(),
  category: text("category").notNull().default("recon"),
  runCommand: text("run_command"),
  isActive: boolean("is_active").notNull().default(true),
  createdBy: integer("created_by").references(() => usersTable.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const toolPipelineStepsTable = pgTable("tool_pipeline_steps", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  toolId: integer("tool_id").notNull().references(() => securityToolsTable.id, { onDelete: "cascade" }),
  stepOrder: integer("step_order").notNull(),
  isEnabled: boolean("is_enabled").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const toolRunsTable = pgTable("tool_runs", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  toolId: integer("tool_id").notNull().references(() => securityToolsTable.id),
  assetId: integer("asset_id"),
  status: text("status").notNull().default("pending"),
  output: text("output"),
  triggeredBy: integer("triggered_by").references(() => usersTable.id),
  startedAt: timestamp("started_at", { withTimezone: true }),
  completedAt: timestamp("completed_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertSecurityToolSchema = createInsertSchema(securityToolsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertSecurityTool = z.infer<typeof insertSecurityToolSchema>;
export type SecurityTool = typeof securityToolsTable.$inferSelect;

export const insertToolRunSchema = createInsertSchema(toolRunsTable).omit({ id: true, createdAt: true });
export type InsertToolRun = z.infer<typeof insertToolRunSchema>;
export type ToolRun = typeof toolRunsTable.$inferSelect;
