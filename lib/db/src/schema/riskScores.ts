import { pgTable, serial, integer, real, text, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { assetsTable } from "./assets";

export const riskScoresTable = pgTable("risk_scores", {
  id: serial("id").primaryKey(),
  assetId: integer("asset_id").notNull().references(() => assetsTable.id).unique(),
  score: real("score").notNull().default(0),
  level: text("level").notNull().default("low"),
  cvssComponent: real("cvss_component").notNull().default(0),
  epssComponent: real("epss_component").notNull().default(0),
  kevBonus: real("kev_bonus").notNull().default(0),
  criticalityBonus: real("criticality_bonus").notNull().default(0),
  exposureBonus: real("exposure_bonus").notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertRiskScoreSchema = createInsertSchema(riskScoresTable).omit({ id: true });
export type InsertRiskScore = z.infer<typeof insertRiskScoreSchema>;
export type RiskScore = typeof riskScoresTable.$inferSelect;
