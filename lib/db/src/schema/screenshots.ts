import { pgTable, serial, text, integer, timestamp, jsonb } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const screenshotsTable = pgTable("screenshots", {
  id:              serial("id").primaryKey(),
  tenantId:        integer("tenant_id").notNull().references(() => tenantsTable.id),
  assetId:         integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  scanId:          integer("scan_id"),
  url:             text("url").notNull(),
  pageType:        text("page_type").notNull(), // index | login | signup | admin | api | sensitive
  screenshotData:  text("screenshot_data").notNull(), // base64-encoded PNG
  title:           text("title"),
  statusCode:      integer("status_code"),
  findings:        jsonb("findings"), // detected sensitive info: { type, value, severity }[]
  capturedAt:      timestamp("captured_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Screenshot = typeof screenshotsTable.$inferSelect;
