import { pgTable, serial, integer, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { usersTable } from "./users";
import { assetsTable } from "./assets";

export const externalMemberAssetsTable = pgTable("external_member_assets", {
  id:          serial("id").primaryKey(),
  userId:      integer("user_id").notNull().references(() => usersTable.id, { onDelete: "cascade" }),
  assetId:     integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  tenantId:    integer("tenant_id").notNull().references(() => tenantsTable.id, { onDelete: "cascade" }),
  invitedBy:   integer("invited_by").references(() => usersTable.id, { onDelete: "set null" }),
  createdAt:   timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type ExternalMemberAsset = typeof externalMemberAssetsTable.$inferSelect;
