import { pgTable, serial, text, integer, boolean, real, timestamp, jsonb, uniqueIndex, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";
import { usersTable } from "./users";
import { scansTable } from "./scans";

// ── Original tables (unchanged) ───────────────────────────────────────────────

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

// ── New tables: IdP integrations, OAuth apps, user attribution, network devices ──

/**
 * shadow_it_idp_connections
 * Stores non-secret IdP config. Secrets go in platform_settings.
 * provider: google_workspace | microsoft_graph | okta
 */
export const shadowItIdpConnectionsTable = pgTable("shadow_it_idp_connections", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  provider: text("provider").notNull(),
  displayName: text("display_name").notNull(),
  configDomain: text("config_domain"),
  configEmail: text("config_email"),
  configTenantId: text("config_tenant_id"),
  configClientId: text("config_client_id"),
  isActive: boolean("is_active").notNull().default(true),
  lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
  lastSyncStatus: text("last_sync_status").notNull().default("never"),
  lastSyncError: text("last_sync_error"),
  syncedApps: integer("synced_apps").notNull().default(0),
  syncedUsers: integer("synced_users").notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_idp_tenant").on(t.tenantId),
  uniqueIndex("idx_shadow_it_idp_provider_tenant").on(t.tenantId, t.provider),
]);

/**
 * shadow_it_oauth_apps
 * OAuth / SAML / OIDC apps discovered from IdP sync, with scope risk scoring.
 */
export const shadowItOauthAppsTable = pgTable("shadow_it_oauth_apps", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  idpConnectionId: integer("idp_connection_id").notNull().references(() => shadowItIdpConnectionsTable.id, { onDelete: "cascade" }),
  provider: text("provider").notNull(),
  externalId: text("external_id").notNull(),
  displayName: text("display_name").notNull(),
  appType: text("app_type").notNull().default("oauth2"),
  publisherDomain: text("publisher_domain"),
  homepageUrl: text("homepage_url"),
  logoUrl: text("logo_url"),
  scopes: jsonb("scopes").$type<string[]>(),
  permissionSummary: jsonb("permission_summary"),
  riskScore: real("risk_score").notNull().default(0),
  riskLevel: text("risk_level").notNull().default("low"),
  riskFactors: jsonb("risk_factors"),
  userCount: integer("user_count").notNull().default(0),
  isAdminConsented: boolean("is_admin_consented").notNull().default(false),
  isSanctioned: boolean("is_sanctioned").notNull().default(false),
  status: text("status").notNull().default("active"),
  firstDiscoveredAt: timestamp("first_discovered_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_oauth_apps_tenant").on(t.tenantId),
  index("idx_shadow_it_oauth_apps_risk").on(t.riskLevel),
  index("idx_shadow_it_oauth_apps_provider").on(t.provider),
  uniqueIndex("idx_shadow_it_oauth_apps_ext").on(t.tenantId, t.provider, t.externalId),
]);

/**
 * shadow_it_oauth_users
 * Employee-level attribution: which user authorised which OAuth app with what scopes.
 */
export const shadowItOauthUsersTable = pgTable("shadow_it_oauth_users", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  idpConnectionId: integer("idp_connection_id").notNull().references(() => shadowItIdpConnectionsTable.id, { onDelete: "cascade" }),
  oauthAppId: integer("oauth_app_id").notNull().references(() => shadowItOauthAppsTable.id, { onDelete: "cascade" }),
  externalUserId: text("external_user_id").notNull(),
  userEmail: text("user_email").notNull(),
  userDisplayName: text("user_display_name").notNull(),
  userDepartment: text("user_department"),
  userJobTitle: text("user_job_title"),
  scopesGranted: jsonb("scopes_granted").$type<string[]>(),
  riskLevel: text("risk_level").notNull().default("low"),
  isAdminUser: boolean("is_admin_user").notNull().default(false),
  grantedAt: timestamp("granted_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_oauth_users_tenant").on(t.tenantId),
  index("idx_shadow_it_oauth_users_app").on(t.oauthAppId),
  index("idx_shadow_it_oauth_users_email").on(t.userEmail),
  uniqueIndex("idx_shadow_it_oauth_users_unique").on(t.tenantId, t.oauthAppId, t.externalUserId),
]);

/**
 * shadow_it_network_devices
 * Internal network devices discovered via ARP/mDNS/SNMP/NetBIOS scanning.
 */
export const shadowItNetworkDevicesTable = pgTable("shadow_it_network_devices", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  ipAddress: text("ip_address").notNull(),
  macAddress: text("mac_address"),
  macVendor: text("mac_vendor"),
  hostname: text("hostname"),
  netbiosName: text("netbios_name"),
  mdnsName: text("mdns_name"),
  mdnsServices: jsonb("mdns_services").$type<string[]>(),
  deviceType: text("device_type").notNull().default("unknown"),
  vendor: text("vendor"),
  osGuess: text("os_guess"),
  snmpSysDescr: text("snmp_sys_descr"),
  snmpSysName: text("snmp_sys_name"),
  snmpSysLocation: text("snmp_sys_location"),
  openPorts: jsonb("open_ports").$type<number[]>(),
  services: jsonb("services"),
  discoveryMethods: jsonb("discovery_methods").$type<string[]>(),
  subnet: text("subnet"),
  isManaged: boolean("is_managed").notNull().default(false),
  relatedAssetId: integer("related_asset_id").references(() => assetsTable.id, { onDelete: "set null" }),
  riskLevel: text("risk_level").notNull().default("info"),
  status: text("status").notNull().default("new"),
  scanTrigger: text("scan_trigger").notNull().default("manual"),
  firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
}, (t) => [
  index("idx_shadow_it_net_tenant").on(t.tenantId),
  index("idx_shadow_it_net_type").on(t.deviceType),
  index("idx_shadow_it_net_status").on(t.status),
  uniqueIndex("idx_shadow_it_net_ip_tenant").on(t.tenantId, t.ipAddress),
]);

// ── Zod schemas + exported types ──────────────────────────────────────────────

export const insertShadowItAssetSchema = createInsertSchema(shadowItAssetsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertShadowItAsset = z.infer<typeof insertShadowItAssetSchema>;
export type ShadowItAsset = typeof shadowItAssetsTable.$inferSelect;

export const insertShadowItSaasAppSchema = createInsertSchema(shadowItSaasAppsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertShadowItSaasApp = z.infer<typeof insertShadowItSaasAppSchema>;
export type ShadowItSaasApp = typeof shadowItSaasAppsTable.$inferSelect;

export type ShadowItIdpConnection = typeof shadowItIdpConnectionsTable.$inferSelect;
export type ShadowItOauthApp = typeof shadowItOauthAppsTable.$inferSelect;
export type ShadowItOauthUser = typeof shadowItOauthUsersTable.$inferSelect;
export type ShadowItNetworkDevice = typeof shadowItNetworkDevicesTable.$inferSelect;
