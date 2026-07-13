import { pgTable, serial, text, integer, boolean, real, timestamp, jsonb, uniqueIndex, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";
import { usersTable } from "./users";
import { scansTable } from "./scans";

export const shadowItAssetsTable = pgTable("shadow_it_assets", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  classification: text("classification").notNull().default("rogue"),
  source: text("source").notNull(),
  parentAssetId: integer("parent_asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  relatedScanId: integer("related_scan_id").references(() => scansTable.id, { onDelete: "set null" }),
  evidence: jsonb("evidence"),
  riskScore: real("risk_score"),
  riskLevel: text("risk_level").notNull().default("medium"),
  hasOpenPorts: boolean("has_open_ports").notNull().default(false),
  hasAdminPanel: boolean("has_admin_panel").notNull().default(false),
  hasAuthBypass: boolean("has_auth_bypass").notNull().default(false),
  isPubliclyAccessible: boolean("is_publicly_accessible").notNull().default(false),
  certFirstSeen: timestamp("cert_first_seen", { withTimezone: true }),
  status: text("status").notNull().default("new"),
  reviewedBy: integer("reviewed_by").references(() => usersTable.id, { onDelete: "set null" }),
  reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
  reviewNote: text("review_note"),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_assets_tenant").on(t.tenantId),
  index("idx_shadow_it_assets_status").on(t.status),
  index("idx_shadow_it_assets_risk").on(t.riskLevel),
  uniqueIndex("idx_shadow_it_assets_name_tenant").on(t.tenantId, t.name, t.type),
]);

export const shadowItSaasAppsTable = pgTable("shadow_it_saas_apps", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  appName: text("app_name").notNull(),
  appCategory: text("app_category"),
  idpSource: text("idp_source").notNull(),
  appId: text("app_id"),
  scopes: jsonb("scopes"),
  userCount: integer("user_count").notNull().default(0),
  isSanctioned: boolean("is_sanctioned").notNull().default(false),
  riskRating: text("risk_rating").notNull().default("medium"),
  evidence: jsonb("evidence"),
  status: text("status").notNull().default("new"),
  discoveredViaAssetId: integer("discovered_via_asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  relatedScanId: integer("related_scan_id").references(() => scansTable.id, { onDelete: "set null" }),
  reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
  reviewedBy: integer("reviewed_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_saas_tenant").on(t.tenantId),
  index("idx_shadow_it_saas_status").on(t.status),
  uniqueIndex("idx_shadow_it_saas_name_tenant").on(t.tenantId, t.appName, t.idpSource),
]);

export const insertShadowItAssetSchema = createInsertSchema(shadowItAssetsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertShadowItAsset = z.infer<typeof insertShadowItAssetSchema>;
export type ShadowItAsset = typeof shadowItAssetsTable.$inferSelect;

export const insertShadowItSaasAppSchema = createInsertSchema(shadowItSaasAppsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertShadowItSaasApp = z.infer<typeof insertShadowItSaasAppSchema>;
export type ShadowItSaasApp = typeof shadowItSaasAppsTable.$inferSelect;
