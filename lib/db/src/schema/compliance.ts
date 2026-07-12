import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetGroupsTable } from "./assetGroups";
import { assetsTable } from "./assets";

export const complianceFrameworksTable = pgTable("compliance_frameworks", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  shortName: text("short_name").notNull(),
  version: text("version").notNull(),
  description: text("description"),
  totalControls: integer("total_controls").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const complianceControlsTable = pgTable("compliance_controls", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  frameworkId: integer("framework_id").notNull().references(() => complianceFrameworksTable.id),
  controlId: text("control_id").notNull(),
  title: text("title").notNull(),
  description: text("description"),
  status: text("status").notNull().default("non_compliant"),
  evidence: text("evidence"),
  assignedTo: text("assigned_to"),
  targetGroupId: integer("target_group_id").references(() => assetGroupsTable.id),
  targetAssetId: integer("target_asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  dueDate: text("due_date"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertComplianceControlSchema = createInsertSchema(complianceControlsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertComplianceControl = z.infer<typeof insertComplianceControlSchema>;
export type ComplianceControl = typeof complianceControlsTable.$inferSelect;

// Junction table: many-to-many between compliance controls and assets
export const complianceControlAssetsTable = pgTable("compliance_control_assets", {
  id: serial("id").primaryKey(),
  controlId: integer("control_id").notNull().references(() => complianceControlsTable.id, { onDelete: "cascade" }),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  tenantId: integer("tenant_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
