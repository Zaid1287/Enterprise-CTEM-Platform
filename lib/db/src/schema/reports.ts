import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";

export const reportsTable = pgTable("reports", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  title: text("title").notNull(),
  type: text("type").notNull(),
  format: text("format").notNull(),
  status: text("status").notNull().default("pending"),
  downloadUrl: text("download_url"),
  assetIds: integer("asset_ids").array().default([]),
  dateFrom: text("date_from"),
  dateTo: text("date_to"),
  generatedAt: timestamp("generated_at", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertReportSchema = createInsertSchema(reportsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertReport = z.infer<typeof insertReportSchema>;
export type Report = typeof reportsTable.$inferSelect;
