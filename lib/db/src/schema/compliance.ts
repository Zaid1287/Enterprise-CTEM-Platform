import { pgTable, serial, text, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";
import { assetGroupsTable } from "./assetGroups";
import { assetsTable } from "./assets";

// ── Module gate (one row per tenant) ─────────────────────────────────────────
export const complianceModuleAssignmentsTable = pgTable("compliance_module_assignments", {
  tenantId:  integer("tenant_id").primaryKey().references(() => tenantsTable.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").notNull().default(false),
  enabledBy: integer("enabled_by").references(() => usersTable.id, { onDelete: "set null" }),
  enabledAt: timestamp("enabled_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
});

// ── Global control library (platform admin manages; clients read) ─────────────
// This is the canonical list of controls per framework — shared across tenants.
// controlId e.g. "A.5.1", "CC6.1", "1.1.1" etc.
export const complianceGlobalControlsTable = pgTable("compliance_global_controls", {
  id:          serial("id").primaryKey(),
  frameworkId: integer("framework_id").notNull().references(() => complianceFrameworksTable.id, { onDelete: "cascade" }),
  controlId:   text("control_id").notNull(),
  title:       text("title").notNull(),
  description: text("description"),
  category:    text("category"),       // Annex clause / domain (e.g. "Organizational Controls")
  guidance:    text("guidance"),       // Implementation guidance
  isEnabled:   boolean("is_enabled").notNull().default(true),
  sortOrder:   integer("sort_order").notNull().default(0),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

// ── Per-tenant control answers (status + evidence per global control) ─────────
export const complianceControlAnswersTable = pgTable("compliance_control_answers", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  globalControlId: integer("global_control_id").notNull().references(() => complianceGlobalControlsTable.id, { onDelete: "cascade" }),
  status:          text("status").notNull().default("non_compliant"),
  evidence:        text("evidence"),      // JSON array of { name, path, size, uploadedAt }
  notes:           text("notes"),
  assignedTo:      text("assigned_to"),
  dueDate:         text("due_date"),
  reviewedAt:      timestamp("reviewed_at", { withTimezone: true }),
  createdAt:       timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:       timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

// ── Asset-level compliance (which controls apply to which assets) ─────────────
export const complianceAssetControlsTable = pgTable("compliance_asset_controls", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  assetId:         integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  globalControlId: integer("global_control_id").notNull().references(() => complianceGlobalControlsTable.id, { onDelete: "cascade" }),
  status:          text("status").notNull().default("non_compliant"),
  notes:           text("notes"),
  assignedTo:      text("assigned_to"),
  evidence:        text("evidence"),
  createdAt:       timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:       timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

// ── Legacy tables (kept for backward compat, new system uses global controls) ─
export const complianceFrameworksTable = pgTable("compliance_frameworks", {
  id:            serial("id").primaryKey(),
  name:          text("name").notNull(),
  shortName:     text("short_name").notNull(),
  version:       text("version").notNull(),
  description:   text("description"),
  totalControls: integer("total_controls").notNull().default(0),
  createdAt:     timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const complianceControlsTable = pgTable("compliance_controls", {
  id:             serial("id").primaryKey(),
  tenantId:       integer("tenant_id").notNull().references(() => tenantsTable.id),
  frameworkId:    integer("framework_id").notNull().references(() => complianceFrameworksTable.id),
  controlId:      text("control_id").notNull(),
  title:          text("title").notNull(),
  description:    text("description"),
  status:         text("status").notNull().default("non_compliant"),
  evidence:       text("evidence"),
  assignedTo:     text("assigned_to"),
  targetGroupId:  integer("target_group_id").references(() => assetGroupsTable.id),
  targetAssetId:  integer("target_asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  dueDate:        text("due_date"),
  isEnabled:      boolean("is_enabled").notNull().default(true),
  createdAt:      timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:      timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertComplianceControlSchema = createInsertSchema(complianceControlsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertComplianceControl = z.infer<typeof insertComplianceControlSchema>;
export type ComplianceControl = typeof complianceControlsTable.$inferSelect;

export const complianceControlAssetsTable = pgTable("compliance_control_assets", {
  id:        serial("id").primaryKey(),
  controlId: integer("control_id").notNull().references(() => complianceControlsTable.id, { onDelete: "cascade" }),
  assetId:   integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  tenantId:  integer("tenant_id").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
