import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const assetGroupsTable = pgTable("asset_groups", {
  id: serial("id").primaryKey(),
  tenantId: integer("tenant_id").notNull().references(() => tenantsTable.id),
  name: text("name").notNull(),
  description: text("description"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const assetGroupMembersTable = pgTable("asset_group_members", {
  id: serial("id").primaryKey(),
  groupId: integer("group_id").notNull().references(() => assetGroupsTable.id),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const insertAssetGroupSchema = createInsertSchema(assetGroupsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertAssetGroup = z.infer<typeof insertAssetGroupSchema>;
export type AssetGroup = typeof assetGroupsTable.$inferSelect;
