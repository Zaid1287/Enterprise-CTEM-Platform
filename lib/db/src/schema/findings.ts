import { pgTable, serial, text, integer, boolean, real, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";
import { usersTable } from "./users";

export const findingsTable = pgTable("findings", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id),
  scanId: integer("scan_id"),
  title: text("title").notNull(),
  description: text("description"),
  severity: text("severity").notNull().default("medium"),
  status: text("status").notNull().default("open"),
  cve: text("cve"),
  cvss: real("cvss"),
  epss: real("epss"),
  cwe: text("cwe"),
  isKev: boolean("is_kev").notNull().default(false),
  remediation: text("remediation"),
  evidence: text("evidence"),
  riskScore: real("risk_score"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const findingCommentsTable = pgTable("finding_comments", {
  id: serial("id").primaryKey(),
  findingId: integer("finding_id").notNull().references(() => findingsTable.id),
  userId: integer("user_id").notNull().references(() => usersTable.id),
  content: text("content").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertFindingSchema = createInsertSchema(findingsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findingsTable.$inferSelect;
