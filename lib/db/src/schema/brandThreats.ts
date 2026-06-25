import { pgTable, serial, integer, text, boolean, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";

export const brandThreatScansTable = pgTable("brand_threat_scans", {
  id:                serial("id").primaryKey(),
  tenantId:          integer("tenant_id").notNull().references(() => tenantsTable.id),
  domain:            text("domain").notNull(),
  status:            text("status").notNull().default("pending"),
  totalPermutations: integer("total_permutations").notNull().default(0),
  liveCount:         integer("live_count").notNull().default(0),
  registeredCount:   integer("registered_count").notNull().default(0),
  phishingRisk:      text("phishing_risk").notNull().default("low"),
  fuzzerBreakdown:   jsonb("fuzzer_breakdown"),
  error:             text("error"),
  pipelineScanId:    integer("pipeline_scan_id"),

  favihunterStatus:  text("favihunter_status"),
  favihunterError:   text("favihunter_error"),
  faviconUrl:        text("favicon_url"),
  faviconMmh3:       integer("favicon_mmh3"),
  faviconMmh3Hex:    text("favicon_mmh3_hex"),
  faviconMd5:        text("favicon_md5"),
  faviconSha256:     text("favicon_sha256"),
  faviconSearchUrls: jsonb("favicon_search_urls"),

  dataLeakCount:     integer("data_leak_count").notNull().default(0),
  phishingCount:     integer("phishing_count").notNull().default(0),
  brandAbuseCount:   integer("brand_abuse_count").notNull().default(0),
  darkWebCount:      integer("dark_web_count").notNull().default(0),

  createdAt:         timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt:       timestamp("completed_at", { withTimezone: true }),
});

export const brandThreatResultsTable = pgTable("brand_threat_results", {
  id:              serial("id").primaryKey(),
  scanId:          integer("scan_id").notNull().references(() => brandThreatScansTable.id, { onDelete: "cascade" }),
  permutation:     text("permutation").notNull(),
  fuzzer:          text("fuzzer").notNull(),
  dnsA:            text("dns_a").array(),
  dnsNs:           text("dns_ns").array(),
  dnsAaaa:         text("dns_aaaa").array(),
  dnsMx:           text("dns_mx").array(),
  mxSpf:           text("mx_spf"),
  whoisRegistrar:  text("whois_registrar"),
  whoisCreated:    text("whois_created"),
  whoisExpires:    text("whois_expires"),
  whoisUpdated:    text("whois_updated"),
  whoisCountry:    text("whois_country"),
  whoisAbuseContact: text("whois_abuse_contact"),
  whoisAgeDays:    integer("whois_age_days"),
  geoCountry:      text("geo_country"),
  geoCity:         text("geo_city"),
  geoAsn:          text("geo_asn"),
  geoOrg:          text("geo_org"),
  vtMalicious:     integer("vt_malicious"),
  vtSuspicious:    integer("vt_suspicious"),
  vtLastAnalysisDate: text("vt_last_analysis_date"),
  vtPermalink:     text("vt_permalink"),
  isPhishing:      boolean("is_phishing").notNull().default(false),
  phishingSource:  text("phishing_source"),
  registrationStatus: text("registration_status"),
  riskScore:       integer("risk_score").notNull().default(0),
  isSuspicious:    boolean("is_suspicious").notNull().default(false),
  createdAt:       timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const brandWatchlistItemsTable = pgTable("brand_watchlist_items", {
  id:        serial("id").primaryKey(),
  tenantId:  integer("tenant_id").notNull().references(() => tenantsTable.id),
  type:      text("type").notNull(),
  value:     text("value").notNull(),
  notes:     text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const dataLeakResultsTable = pgTable("data_leak_results", {
  id:           serial("id").primaryKey(),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id),
  scanId:       integer("scan_id").references(() => brandThreatScansTable.id, { onDelete: "cascade" }),
  source:       text("source").notNull(),
  title:        text("title").notNull(),
  breachDate:   text("breach_date"),
  description:  text("description"),
  exposedData:  jsonb("exposed_data"),
  domainMatch:  text("domain_match"),
  emailMatch:   text("email_match"),
  severity:     text("severity").notNull().default("medium"),
  url:          text("url"),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const phishingDetectionsTable = pgTable("phishing_detections", {
  id:           serial("id").primaryKey(),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id),
  scanId:       integer("scan_id").references(() => brandThreatScansTable.id, { onDelete: "cascade" }),
  url:          text("url").notNull(),
  source:       text("source").notNull(),
  verified:     boolean("verified").notNull().default(false),
  targetBrand:  text("target_brand"),
  submittedAt:  text("submitted_at"),
  threatType:   text("threat_type"),
  createdAt:    timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const brandAbuseResultsTable = pgTable("brand_abuse_results", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id),
  scanId:          integer("scan_id").references(() => brandThreatScansTable.id, { onDelete: "cascade" }),
  type:            text("type").notNull(),
  platform:        text("platform"),
  url:             text("url"),
  title:           text("title"),
  description:     text("description"),
  evidenceSnippet: text("evidence_snippet"),
  risk:            text("risk").notNull().default("medium"),
  createdAt:       timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertBrandThreatScanSchema = createInsertSchema(brandThreatScansTable)
  .omit({ id: true, createdAt: true, completedAt: true });
export type InsertBrandThreatScan = z.infer<typeof insertBrandThreatScanSchema>;
export type BrandThreatScan = typeof brandThreatScansTable.$inferSelect;

export const insertBrandThreatResultSchema = createInsertSchema(brandThreatResultsTable)
  .omit({ id: true, createdAt: true });
export type InsertBrandThreatResult = z.infer<typeof insertBrandThreatResultSchema>;
export type BrandThreatResult = typeof brandThreatResultsTable.$inferSelect;

export const insertBrandWatchlistItemSchema = createInsertSchema(brandWatchlistItemsTable)
  .omit({ id: true, createdAt: true });
export type InsertBrandWatchlistItem = z.infer<typeof insertBrandWatchlistItemSchema>;
export type BrandWatchlistItem = typeof brandWatchlistItemsTable.$inferSelect;

export const insertDataLeakResultSchema = createInsertSchema(dataLeakResultsTable)
  .omit({ id: true, createdAt: true });
export type InsertDataLeakResult = z.infer<typeof insertDataLeakResultSchema>;
export type DataLeakResult = typeof dataLeakResultsTable.$inferSelect;

export const insertPhishingDetectionSchema = createInsertSchema(phishingDetectionsTable)
  .omit({ id: true, createdAt: true });
export type InsertPhishingDetection = z.infer<typeof insertPhishingDetectionSchema>;
export type PhishingDetection = typeof phishingDetectionsTable.$inferSelect;

export const insertBrandAbuseResultSchema = createInsertSchema(brandAbuseResultsTable)
  .omit({ id: true, createdAt: true });
export type InsertBrandAbuseResult = z.infer<typeof insertBrandAbuseResultSchema>;
export type BrandAbuseResult = typeof brandAbuseResultsTable.$inferSelect;
