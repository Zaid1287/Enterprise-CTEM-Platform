import { pgTable, serial, integer, text, boolean, jsonb, real, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";
import { assetsTable } from "./assets";
import { findingsTable } from "./findings";

// ── Module gate ───────────────────────────────────────────────────────────────
export const threatIntelModuleAssignmentsTable = pgTable("threat_intel_module_assignments", {
  tenantId:  integer("tenant_id").primaryKey().references(() => tenantsTable.id, { onDelete: "cascade" }),
  isEnabled: boolean("is_enabled").notNull().default(false),
  enabledBy: integer("enabled_by").references(() => usersTable.id, { onDelete: "set null" }),
  enabledAt: timestamp("enabled_at", { withTimezone: true }),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow(),
});

// ── IOC database ─────────────────────────────────────────────────────────────
// Stores deduplicated, multi-source IOC records.
// type values: ip, domain, url, email, hash_md5, hash_sha1, hash_sha256, hash_sha512,
//              ja3, ja4, tls_fingerprint, ssl_cert, asn, cidr, wallet, telegram,
//              discord, github, filename, mutex, registry, service, user_agent,
//              dns, uri, cookie, http_header
export const tiIocsTable = pgTable("ti_iocs", {
  id:             serial("id").primaryKey(),
  type:           text("type").notNull(),
  value:          text("value").notNull(),
  source:         text("source").notNull(),   // canonical / first-reporter source
  sources:        text("sources").array().notNull().default([]), // all sources that reported this IOC
  sourceUrl:      text("source_url"),
  tlp:            text("tlp").notNull().default("white"),
  confidence:     integer("confidence").notNull().default(50),
  severity:       text("severity").notNull().default("medium"),
  tags:           text("tags").array().notNull().default([]),
  malwareFamilies: text("malware_families").array().notNull().default([]),
  threatActors:   text("threat_actors").array().notNull().default([]),
  campaigns:      text("campaigns").array().notNull().default([]),
  country:        text("country"),
  asn:            text("asn"),
  description:    text("description"),
  threatScore:    real("threat_score").notNull().default(0),
  seenCount:      integer("seen_count").notNull().default(1),
  exploitationStatus: text("exploitation_status").notNull().default("unknown"),
  isActive:       boolean("is_active").notNull().default(true),
  firstSeen:      timestamp("first_seen", { withTimezone: true }).notNull().defaultNow(),
  lastSeen:       timestamp("last_seen", { withTimezone: true }).notNull().defaultNow(),
  expiresAt:      timestamp("expires_at", { withTimezone: true }),
  rawData:        jsonb("raw_data"),
  createdAt:      timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [uniqueIndex("ti_iocs_type_value_idx").on(t.type, t.value)]);

// ── Threat Actors ─────────────────────────────────────────────────────────────
export const tiThreatActorsTable = pgTable("ti_threat_actors", {
  id:               serial("id").primaryKey(),
  name:             text("name").notNull().unique(),
  aliases:          text("aliases").array().notNull().default([]),
  country:          text("country"),
  motivation:       text("motivation"),
  targetIndustries: text("target_industries").array().notNull().default([]),
  targetCountries:  text("target_countries").array().notNull().default([]),
  description:      text("description"),
  overview:         text("overview"),
  firstSeen:        text("first_seen"),
  lastSeen:         text("last_seen"),
  sophistication:   text("sophistication"),
  resourceLevel:    text("resource_level"),
  isActive:         boolean("is_active").notNull().default(true),
  riskScore:        real("risk_score").notNull().default(0),
  confidenceScore:  real("confidence_score").notNull().default(0),
  mitreId:          text("mitre_id"),
  mitreUrl:         text("mitre_url"),
  killChain:        jsonb("kill_chain").notNull().default([]),
  detectionRules:   text("detection_rules").array().notNull().default([]),
  mitigation:       text("mitigation"),
  referenceUrls:    text("reference_urls").array().notNull().default([]),
  executiveSummary: text("executive_summary"),
  source:           text("source").notNull().default("mitre_attack"),
  createdAt:        timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:        timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── Campaigns ─────────────────────────────────────────────────────────────────
export const tiCampaignsTable = pgTable("ti_campaigns", {
  id:               serial("id").primaryKey(),
  name:             text("name").notNull().unique(),
  aliases:          text("aliases").array().notNull().default([]),
  description:      text("description"),
  actorId:          integer("actor_id").references(() => tiThreatActorsTable.id, { onDelete: "set null" }),
  actorName:        text("actor_name"),
  status:           text("status").notNull().default("active"),
  targetIndustries: text("target_industries").array().notNull().default([]),
  targetCountries:  text("target_countries").array().notNull().default([]),
  startDate:        text("start_date"),
  endDate:          text("end_date"),
  mitreId:          text("mitre_id"),
  objectives:       text("objectives"),
  source:           text("source").notNull().default("mitre_attack"),
  rawData:          jsonb("raw_data"),
  createdAt:        timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:        timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── Malware ───────────────────────────────────────────────────────────────────
export const tiMalwareTable = pgTable("ti_malware", {
  id:               serial("id").primaryKey(),
  name:             text("name").notNull().unique(),
  aliases:          text("aliases").array().notNull().default([]),
  malwareType:      text("malware_type").notNull().default("malware"),
  description:      text("description"),
  platforms:        text("platforms").array().notNull().default([]),
  targetIndustries: text("target_industries").array().notNull().default([]),
  actorIds:         text("actor_ids").array().notNull().default([]),
  actorNames:       text("actor_names").array().notNull().default([]),
  campaignIds:      text("campaign_ids").array().notNull().default([]),
  capabilities:     text("capabilities").array().notNull().default([]),
  mitreId:          text("mitre_id"),
  mitreUrl:         text("mitre_url"),
  iocCount:         integer("ioc_count").notNull().default(0),
  riskScore:        real("risk_score").notNull().default(0),
  source:           text("source").notNull().default("mitre_attack"),
  rawData:          jsonb("raw_data"),
  createdAt:        timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:        timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── C2 Servers ────────────────────────────────────────────────────────────────
export const tiC2ServersTable = pgTable("ti_c2_servers", {
  id:               serial("id").primaryKey(),
  ip:               text("ip").notNull(),
  port:             integer("port"),
  domain:           text("domain"),
  country:          text("country"),
  countryCode:      text("country_code"),
  asn:              text("asn"),
  asnOrg:           text("asn_org"),
  isp:              text("isp"),
  city:             text("city"),
  lat:              real("lat"),
  lng:              real("lng"),
  malwareFamily:    text("malware_family"),
  actorName:        text("actor_name"),
  tags:             text("tags").array().notNull().default([]),
  confidence:       integer("confidence").notNull().default(70),
  isActive:         boolean("is_active").notNull().default(true),
  cloudProvider:    text("cloud_provider"),
  serviceCategory:  text("service_category"),
  sectorsAtRisk:    text("sectors_at_risk").array().notNull().default([]),
  platformsAtRisk:  text("platforms_at_risk").array().notNull().default([]),
  orgsAtRisk:       text("orgs_at_risk").array().notNull().default([]),
  source:           text("source").notNull().default("threatfox"),
  rawData:          jsonb("raw_data"),
  discoveredAt:     timestamp("discovered_at", { withTimezone: true }).notNull().defaultNow(),
  lastSeenAt:       timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [uniqueIndex("ti_c2_servers_ip_port_source_idx").on(t.ip, t.source)]);

// ── Feed Runs ─────────────────────────────────────────────────────────────────
export const tiFeedRunsTable = pgTable("ti_feed_runs", {
  id:             serial("id").primaryKey(),
  source:         text("source").notNull(),
  status:         text("status").notNull().default("running"),
  recordsAdded:   integer("records_added").notNull().default(0),
  recordsUpdated: integer("records_updated").notNull().default(0),
  durationMs:     integer("duration_ms"),
  error:          text("error"),
  startedAt:      timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt:    timestamp("completed_at", { withTimezone: true }),
});

// ── Asset ↔ TI Correlations ───────────────────────────────────────────────────
export const tiAssetCorrelationsTable = pgTable("ti_asset_correlations", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  findingId:       integer("finding_id").references(() => findingsTable.id, { onDelete: "cascade" }),
  assetId:         integer("asset_id").references(() => assetsTable.id, { onDelete: "cascade" }),
  matchedActors:   jsonb("matched_actors").notNull().default([]),
  matchedCampaigns: jsonb("matched_campaigns").notNull().default([]),
  matchedMalware:  jsonb("matched_malware").notNull().default([]),
  matchedIocs:     jsonb("matched_iocs").notNull().default([]),
  matchedCves:     jsonb("matched_cves").notNull().default([]),
  exploitationStatus: text("exploitation_status").notNull().default("unknown"),
  threatScore:     real("threat_score").notNull().default(0),
  riskBoost:       real("risk_boost").notNull().default(0),
  aiExplanation:   text("ai_explanation"),
  correlationBasis: text("correlation_basis").array().notNull().default([]),
  correlatedAt:    timestamp("correlated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── Threat Actor TTPs ─────────────────────────────────────────────────────────
export const tiActorTtpsTable = pgTable("ti_actor_ttps", {
  id:          serial("id").primaryKey(),
  actorId:     integer("actor_id").notNull().references(() => tiThreatActorsTable.id, { onDelete: "cascade" }),
  tacticId:    text("tactic_id").notNull(),
  tacticName:  text("tactic_name").notNull(),
  techniqueId: text("technique_id").notNull(),
  techniqueName: text("technique_name").notNull(),
  subtechniqueId: text("subtechnique_id"),
  subtechniqueName: text("subtechnique_name"),
  description: text("description"),
  detection:   text("detection"),
  platforms:   text("platforms").array().notNull().default([]),
  source:      text("source").notNull().default("mitre_attack"),
});

// ── CVE Intel ─────────────────────────────────────────────────────────────────
export const tiCveIntelTable = pgTable("ti_cve_intel", {
  id:                  serial("id").primaryKey(),
  cveId:               text("cve_id").notNull().unique(),
  cvss:                real("cvss"),
  cvssVector:          text("cvss_vector"),
  epss:                real("epss"),
  isKev:               boolean("is_kev").notNull().default(false),
  kevDateAdded:        text("kev_date_added"),
  severity:            text("severity").notNull().default("medium"),
  description:         text("description"),
  publishedDate:       text("published_date"),
  modifiedDate:        text("modified_date"),
  affectedProducts:    text("affected_products").array().notNull().default([]),
  affectedVendors:     text("affected_vendors").array().notNull().default([]),
  linkedActors:        text("linked_actors").array().notNull().default([]),
  linkedCampaigns:     text("linked_campaigns").array().notNull().default([]),
  linkedMalware:       text("linked_malware").array().notNull().default([]),
  exploitationStatus:  text("exploitation_status").notNull().default("unknown"),
  exploitationEvidence: text("exploitation_evidence"),
  patchAvailable:      boolean("patch_available").notNull().default(false),
  pocPublic:           boolean("poc_public").notNull().default(false),
  referenceUrls:       text("reference_urls").array().notNull().default([]),
  cwe:                 text("cwe"),
  capec:               text("capec"),
  rawData:             jsonb("raw_data"),
  createdAt:           timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt:           timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── TI Reports ────────────────────────────────────────────────────────────────
export const tiReportsTable = pgTable("ti_reports", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  title:       text("title").notNull(),
  reportType:  text("report_type").notNull().default("summary"),
  status:      text("status").notNull().default("generating"),
  content:     text("content"),
  metadata:    jsonb("metadata"),
  generatedBy: integer("generated_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── News / Threat Feeds ───────────────────────────────────────────────────────
export const tiNewsFeedsTable = pgTable("ti_news_feeds", {
  id:          serial("id").primaryKey(),
  title:       text("title").notNull(),
  url:         text("url"),
  source:      text("source").notNull(),
  sourceName:  text("source_name"),
  summary:     text("summary"),
  aiSummary:   text("ai_summary"),
  severity:    text("severity").notNull().default("info"),
  tags:        text("tags").array().notNull().default([]),
  sectors:     text("sectors").array().notNull().default([]),
  cves:        text("cves").array().notNull().default([]),
  actors:      text("actors").array().notNull().default([]),
  publishedAt: timestamp("published_at", { withTimezone: true }),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [uniqueIndex("ti_news_feeds_url_idx").on(t.url)]);

// ── Dark Web Mentions ─────────────────────────────────────────────────────────
export const tiDarkWebMentionsTable = pgTable("ti_dark_web_mentions", {
  id:          serial("id").primaryKey(),
  tenantId:    integer("tenant_id").references(() => tenantsTable.id, { onDelete: "cascade" }),
  mentionType: text("mention_type").notNull().default("general"),
  title:       text("title"),
  content:     text("content"),
  source:      text("source").notNull(),
  sourceUrl:   text("source_url"),
  severity:    text("severity").notNull().default("medium"),
  keywords:    text("keywords").array().notNull().default([]),
  actors:      text("actors").array().notNull().default([]),
  isVerified:  boolean("is_verified").notNull().default(false),
  rawData:     jsonb("raw_data"),
  assetDomain: text("asset_domain"),
  breachKey:   text("breach_key"),
  detectedAt:  timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

// ── Types ─────────────────────────────────────────────────────────────────────
export type ThreatIntelModuleAssignment = typeof threatIntelModuleAssignmentsTable.$inferSelect;
export type TiIoc                       = typeof tiIocsTable.$inferSelect;
export type TiThreatActor               = typeof tiThreatActorsTable.$inferSelect;
export type TiCampaign                  = typeof tiCampaignsTable.$inferSelect;
export type TiMalware                   = typeof tiMalwareTable.$inferSelect;
export type TiC2Server                  = typeof tiC2ServersTable.$inferSelect;
export type TiFeedRun                   = typeof tiFeedRunsTable.$inferSelect;
export type TiAssetCorrelation          = typeof tiAssetCorrelationsTable.$inferSelect;
export type TiActorTtp                  = typeof tiActorTtpsTable.$inferSelect;
export type TiCveIntel                  = typeof tiCveIntelTable.$inferSelect;
export type TiReport                    = typeof tiReportsTable.$inferSelect;
export type TiNewsFeed                  = typeof tiNewsFeedsTable.$inferSelect;
export type TiDarkWebMention            = typeof tiDarkWebMentionsTable.$inferSelect;
