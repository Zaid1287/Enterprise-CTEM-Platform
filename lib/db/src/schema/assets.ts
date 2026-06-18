import { pgTable, serial, text, boolean, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";

export const assetsTable = pgTable("assets", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  value: text("value").notNull(),
  verificationStatus: text("verification_status").notNull().default("unverified"),
  verificationToken: text("verification_token"),
  verificationMethod: text("verification_method"),
  verificationEmailToken: text("verification_email_token"),
  verificationEmailExpiry: timestamp("verification_email_expiry", { withTimezone: true }),
  riskLevel: text("risk_level").notNull().default("low"),
  tags: text("tags").array().notNull().default([]),
  description: text("description"),
  ipAddress: text("ip_address"),
  port: integer("port"),
  isActive: boolean("is_active").notNull().default(true),
  assignedClientId: integer("assigned_client_id").references(() => usersTable.id),
  assignedAccountManagerId: integer("assigned_account_manager_id").references(() => usersTable.id),
  scanFrequency: text("scan_frequency").notNull().default("manual"),
  lastScannedAt: timestamp("last_scanned_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertAssetSchema = createInsertSchema(assetsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assetsTable.$inferSelect;
