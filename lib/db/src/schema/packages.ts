import { pgTable, serial, text, boolean, integer, numeric, jsonb, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";

export const packagesTable = pgTable("packages", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  price: numeric("price", { precision: 10, scale: 2 }).notNull().default("0"),
  features: jsonb("features").$type<string[]>().notNull().default([]),
  maxAssets: integer("max_assets"),
  maxUsers: integer("max_users"),
  toolIds: jsonb("tool_ids").$type<number[]>().notNull().default([]),
  isActive: boolean("is_active").notNull().default(true),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export type Package = typeof packagesTable.$inferSelect;

export const tenantPackagesTable = pgTable("tenant_packages", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  packageId: integer("package_id").notNull().references(() => packagesTable.id),
  assignedAt: timestamp("assigned_at", { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp("expires_at", { withTimezone: true }),
});

export type TenantPackage = typeof tenantPackagesTable.$inferSelect;
