import { eq, inArray } from "drizzle-orm";
import { db, assetsTable, findingsTable, riskScoresTable, riskScoreHistoryTable } from "@workspace/db";
import { logger } from "./logger";

// ── Shared level thresholds (single source of truth) ────────────────────────
export function scoreToLevel(score: number): string {
  if (score >= 80) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  return "low";
}

// Statuses that mean the finding is no longer an active risk
const CLOSED_STATUSES = new Set(["mitigated", "resolved", "false_positive", "accepted_risk"]);

// ── Unified risk score computation ───────────────────────────────────────────

interface RiskComponents {
  score: number;
  level: string;
  cvssComponent: number;
  epssComponent: number;
  kevBonus: number;
  criticalityBonus: number;
  exposureBonus: number;
  businessImpactComponent: number;
}

function computeRiskComponents(
  openFindings: { severity: string | null; cvss: number | null; epss: number | null; isKev: boolean | null; cve: string | null }[],
  businessImpact: number,
): RiskComponents {
  const critical = openFindings.filter(f => f.severity === "critical").length;
  const high     = openFindings.filter(f => f.severity === "high").length;
  const medium   = openFindings.filter(f => f.severity === "medium").length;

  // Factor 1: Severity volume
  const severityScore = critical * 22 + high * 12 + medium * 5;

  // Factor 2: CVSS average (0–25 pts)
  const cvssVals = openFindings.map(f => f.cvss ?? 0).filter(v => v > 0);
  const avgCvss = cvssVals.length ? cvssVals.reduce((a, b) => a + b, 0) / cvssVals.length : 0;
  const cvssComponent = Math.round((avgCvss / 10) * 25 * 10) / 10;

  // Factor 3: Max EPSS (0–15 pts)
  const maxEpss = openFindings.reduce((m, f) => Math.max(m, f.epss ?? 0), 0);
  const epssComponent = Math.round(maxEpss * 15 * 10) / 10;

  // Factor 4: KEV bonus — 8 pts per confirmed exploited finding, capped at 30
  // Cap prevents a single KEV API response from dominating the score and causing
  // large swings when KEV enrichment partially fails between scans.
  const kevCount = openFindings.filter(f => f.isKev).length;
  const kevBonus = Math.min(kevCount * 8, 30);

  // Factor 5: Business impact (0–20 pts based on 1–10 field)
  const clampedImpact = Math.max(1, Math.min(10, businessImpact));
  const businessImpactComponent = Math.round((clampedImpact / 10) * 20 * 10) / 10;

  // Factor 6: Criticality bonus — based on highest open finding severity (0–20 pts)
  const critMap: Record<string, number> = { critical: 20, high: 15, medium: 10, low: 5 };
  const highestSev = critical > 0 ? "critical" : high > 0 ? "high" : medium > 0 ? "medium" : "low";
  const criticalityBonus = critMap[highestSev] ?? 5;

  // Factor 7: Exposure bonus — dangerous exposed ports (0–5 pts)
  const portCount = openFindings.filter(f => (f.cve ?? "").startsWith("EXP-PORT-")).length;
  const exposureBonus = Math.round(Math.min(5, portCount * 1.5) * 10) / 10;

  const raw = severityScore + cvssComponent + epssComponent + kevBonus + businessImpactComponent + criticalityBonus + exposureBonus;
  const score = Math.round(Math.min(100, Math.max(0, raw)));
  const level = scoreToLevel(score);

  return { score, level, cvssComponent, epssComponent, kevBonus, criticalityBonus, exposureBonus, businessImpactComponent };
}

// ── Public API ────────────────────────────────────────────────────────────────

export interface FinalizeOptions {
  /** Update assets.lastScannedAt to now(). True for real pipeline scans; false for manual recalculate / finding status changes. */
  updateLastScannedAt?: boolean;
}

/**
 * Unified risk score computation — THE single source of truth for all asset risk scores.
 *
 * Called by:
 *   - pipelineScans.ts after a real scan completes (updateLastScannedAt: true)
 *   - POST /risk/recalculate (updateLastScannedAt: false)
 *   - PATCH /findings/:id after a status change (updateLastScannedAt: false)
 */
export async function finalizeScannedAssets(assetIds: number[], options: FinalizeOptions = {}) {
  if (assetIds.length === 0) return;
  const { updateLastScannedAt = true } = options;

  if (updateLastScannedAt) {
    await db.update(assetsTable).set({ lastScannedAt: new Date() }).where(inArray(assetsTable.id, assetIds));
  }

  // Load all findings for these assets (all statuses — we filter open below)
  const findings = await db
    .select({
      assetId: findingsTable.assetId,
      severity: findingsTable.severity,
      cvss: findingsTable.cvss,
      epss: findingsTable.epss,
      isKev: findingsTable.isKev,
      status: findingsTable.status,
      cve: findingsTable.cve,
    })
    .from(findingsTable)
    .where(inArray(findingsTable.assetId, assetIds));

  // Group by asset
  const byAsset = new Map<number, typeof findings>();
  for (const f of findings) {
    const aid = f.assetId!;
    if (!byAsset.has(aid)) byAsset.set(aid, []);
    byAsset.get(aid)!.push(f);
  }

  // Load asset metadata (businessImpact)
  const assetRows = await db
    .select({ id: assetsTable.id, businessImpact: assetsTable.businessImpact })
    .from(assetsTable)
    .where(inArray(assetsTable.id, assetIds));
  const biMap = new Map(assetRows.map(a => [a.id, a.businessImpact ?? 5]));

  for (const assetId of assetIds) {
    const all = byAsset.get(assetId) ?? [];
    const open = all.filter(f => !CLOSED_STATUSES.has(f.status ?? ""));

    const bi = biMap.get(assetId) ?? 5;
    const components = computeRiskComponents(open, bi);
    const { score, level, cvssComponent, epssComponent, kevBonus, criticalityBonus, exposureBonus, businessImpactComponent } = components;

    // Upsert risk_scores (Issue 1: unified formula; Issue 2: criticalityBonus + exposureBonus; Issue 3: businessImpactComponent)
    await db.insert(riskScoresTable).values({
      assetId, score, level, cvssComponent, epssComponent, kevBonus,
      criticalityBonus, exposureBonus, businessImpactComponent,
    }).onConflictDoUpdate({
      target: riskScoresTable.assetId,
      set: { score, level, cvssComponent, epssComponent, kevBonus, criticalityBonus, exposureBonus, businessImpactComponent },
    });

    // Update asset risk level
    await db.update(assetsTable).set({ riskLevel: level }).where(eq(assetsTable.id, assetId));

    // Issue 5: Insert history snapshot on every risk score update
    await db.insert(riskScoreHistoryTable).values({
      assetId, score, level, cvssComponent, epssComponent, kevBonus,
      criticalityBonus, exposureBonus, businessImpactComponent,
    });

    logger.debug(
      { assetId, score, level, cvssComponent, epssComponent, kevBonus, criticalityBonus, exposureBonus, businessImpactComponent },
      "Risk score finalized",
    );
  }
}
