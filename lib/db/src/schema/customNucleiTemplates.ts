import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";
import { assetsTable } from "./assets";

export const customNucleiTemplatesTable = pgTable("custom_nuclei_templates", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  name:        text("name").notNull(),
  description: text("description"),
  content:     text("content").notNull(),
  createdBy:   integer("created_by").references(() => usersTable.id),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const customNucleiTemplateAssignmentsTable = pgTable("custom_nuclei_template_assignments", {
  id:         serial("id").primaryKey(),
  tenantId:   integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  templateId: integer("template_id").notNull().references(() => customNucleiTemplatesTable.id, { onDelete: "cascade" }),
  assetId:    integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  createdAt:  timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type CustomNucleiTemplate = typeof customNucleiTemplatesTable.$inferSelect;
