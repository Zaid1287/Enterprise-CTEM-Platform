import { pgTable, serial, text, integer, timestamp, boolean, json } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";

export const takedownRequestsTable = pgTable("takedown_requests", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  submittedByUserId: integer("submitted_by_user_id").references(() => usersTable.id),

  // Type of abuse/threat
  type: text("type").notNull(), // "phishing", "brand_impersonation", "domain_squatting", "fake_social", "malware_hosting", "other"

  // Target details
  targetUrl: text("target_url").notNull(),
  targetDomain: text("target_domain"),
  targetIp: text("target_ip"),
  hostingProvider: text("hosting_provider"),
  registrar: text("registrar"),

  // Incident details
  title: text("title").notNull(),
  description: text("description"),
  evidence: text("evidence"),
  evidenceFiles: json("evidence_files").$type<string[]>().default([]),
  brandAbused: text("brand_abused"),

  // Workflow status
  status: text("status").notNull().default("submitted"), // "submitted" | "in_progress" | "closed" | "rejected"
  priority: text("priority").notNull().default("medium"), // "critical" | "high" | "medium" | "low"

  // Resolution
  resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  resolutionNote: text("resolution_note"),
  isSuccessful: boolean("is_successful"),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertTakedownRequestSchema = createInsertSchema(takedownRequestsTable).omit({
  id: true, createdAt: true, updatedAt: true,
});
export type InsertTakedownRequest = z.infer<typeof insertTakedownRequestSchema>;
export type TakedownRequest = typeof takedownRequestsTable.$inferSelect;
