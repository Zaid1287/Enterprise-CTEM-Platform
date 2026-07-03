import { pgTable, serial, integer, real, text, timestamp, index } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { assetsTable } from "./assets";

export const riskScoreHistoryTable = pgTable("risk_score_history", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id, { onDelete: "cascade" }),
  score: real("score").notNull(),
  level: text("level").notNull(),
  cvssComponent: real("cvss_component").notNull().default(0),
  epssComponent: real("epss_component").notNull().default(0),
  kevBonus: real("kev_bonus").notNull().default(0),
  criticalityBonus: real("criticality_bonus").notNull().default(0),
  exposureBonus: real("exposure_bonus").notNull().default(0),
  businessImpactComponent: real("business_impact_component").notNull().default(0),
  calculatedAt: timestamp("calculated_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [
  index("idx_rsh_asset_at").on(t.assetId, t.calculatedAt),
]);

export const insertRiskScoreHistorySchema = createInsertSchema(riskScoreHistoryTable).omit({ id: true });
export type InsertRiskScoreHistory = z.infer<typeof insertRiskScoreHistorySchema>;
export type RiskScoreHistory = typeof riskScoreHistoryTable.$inferSelect;
