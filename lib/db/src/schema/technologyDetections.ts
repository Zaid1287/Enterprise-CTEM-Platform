import { pgTable, serial, text, integer, timestamp } from "drizzle-orm/pg-core";
import { tenantsTable } from "./tenants";
import { assetsTable } from "./assets";

export const technologyDetectionsTable = pgTable("technology_detections", {
  id:           serial("id").primaryKey(),
  tenantId:     integer("tenant_id").notNull().references(() => tenantsTable.id),
  assetId:      integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  scanId:       integer("scan_id"),
  technology:   text("technology").notNull(),
  slug:         text("slug").notNull(),
  category:     text("category").notNull(),
  version:      text("version"),
  confidence:   integer("confidence").notNull().default(100),
  website:      text("website"),
  cpe:          text("cpe"),
  icon:         text("icon"),
  detectedAt:   timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
});

export type TechnologyDetection = typeof technologyDetectionsTable.$inferSelect;
