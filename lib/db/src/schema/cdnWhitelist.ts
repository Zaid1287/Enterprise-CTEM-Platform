import { pgTable, serial, text, boolean, timestamp } from "drizzle-orm/pg-core";

export const cdnWhitelistTable = pgTable("cdn_whitelist_entries", {
  id:          serial("id").primaryKey(),
  label:       text("label").notNull(),
  cidr:        text("cidr").notNull(),
  ipStart:     text("ip_start").notNull(),
  ipEnd:       text("ip_end").notNull(),
  description: text("description"),
  isActive:    boolean("is_active").notNull().default(true),
  isBuiltIn:   boolean("is_built_in").notNull().default(false),
  createdAt:   timestamp("created_at",  { withTimezone: true }).notNull().defaultNow(),
  updatedAt:   timestamp("updated_at",  { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export type CdnWhitelistEntry = typeof cdnWhitelistTable.$inferSelect;
export type InsertCdnWhitelist = typeof cdnWhitelistTable.$inferInsert;
