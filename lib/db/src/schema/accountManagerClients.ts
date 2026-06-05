import { pgTable, serial, integer, timestamp } from "drizzle-orm/pg-core";
import { usersTable } from "./users";
import { tenantsTable } from "./tenants";

export const accountManagerClientsTable = pgTable("account_manager_clients", {
  id: serial("id").primaryKey(),
  accountManagerUserId: integer("account_manager_user_id").notNull().references(() => usersTable.id),
  clientTenantId: integer("client_tenant_id").notNull().references(() => tenantsTable.id),
  assignedAt: timestamp("assigned_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AccountManagerClient = typeof accountManagerClientsTable.$inferSelect;
