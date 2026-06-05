import { pgTable, serial, integer, text, timestamp } from "drizzle-orm/pg-core";
import { usersTable } from "./users";

export const userAiSettingsTable = pgTable("user_ai_settings", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => usersTable.id),
  provider: text("provider").notNull(),
  apiKey: text("api_key").notNull(),
  baseUrl: text("base_url"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export type UserAiSetting = typeof userAiSettingsTable.$inferSelect;
