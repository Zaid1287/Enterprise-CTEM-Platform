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
  createdAt:         timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  completedAt:       timestamp("completed_at", { withTimezone: true }),
});

export const brandThreatResultsTable = pgTable("brand_threat_results", {
  id:              serial("id").primaryKey(),
  scanId:          integer("scan_id").notNull().references(() => brandThreatScansTable.id, { onDelete: "cascade" }),
  permutation:     text("permutation").notNull(),
  fuzzer:          text("fuzzer").notNull(),
  dnsA:            text("dns_a").array(),
  dnsMx:           text("dns_mx").array(),
  mxSpf:           text("mx_spf"),
  whoisRegistrar:  text("whois_registrar"),
  whoisCreated:    text("whois_created"),
  whoisCountry:    text("whois_country"),
  riskScore:       integer("risk_score").notNull().default(0),
  isSuspicious:    boolean("is_suspicious").notNull().default(false),
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
