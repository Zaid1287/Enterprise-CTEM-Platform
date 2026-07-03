---
name: Risk Scoring Unified Formula
description: finalizeScannedAssets is the single source of truth for all asset risk scoring — formula, thresholds, component storage, and history snapshots.
---

## The Rule

`finalizeScannedAssets(assetIds, options?)` in `lib/scanScheduler.ts` is the ONLY place asset risk scores are computed. Never reimplement the formula elsewhere.

**Why:** Previously POST /risk/recalculate had a divergent formula (different weights, thresholds, missing businessImpact). This caused assets to flip level just from clicking recalculate.

## Formula (7 components)

```
severity     = (critical × 22) + (high × 12) + (medium × 5)
cvssComp     = (avgCvss / 10) × 25          → max 25 pts
epssComp     = maxEpss × 15                 → max 15 pts
kevBonus     = kevCount × 8                 → 8 per confirmed exploited CVE
bizImpact    = (businessImpact / 10) × 20   → max 20 pts  (1–10 field on asset)
criticality  = 20/15/10/5 based on highest finding severity
exposure     = min(5, portCount × 1.5)       → EXP-PORT-* findings
score        = clamp(sum, 0, 100)
```

**Thresholds:** critical ≥ 80 · high ≥ 55 · medium ≥ 30 · low < 30

**Closed statuses** (excluded from open findings): mitigated, resolved, false_positive, accepted_risk

## DB Schema

`risk_scores` columns: score, level, cvss_component, epss_component, kev_bonus, criticality_bonus, exposure_bonus, **business_impact_component** (added)

`risk_score_history`: full component snapshot inserted on every finalizeScannedAssets call (for trend charts)

## Callers

| Caller | updateLastScannedAt |
|---|---|
| pipelineScans.ts after real scan | true (default) |
| POST /risk/recalculate | false |
| PATCH /findings/:id (fire-and-forget) | false |

## APIs

- `GET /risk/history` — daily aggregate trend data (powers LineChart)
- `GET /risk/scores/:assetId/history` — per-asset history up to 90 days

## KEV Cache (DB-backed)

platform_settings keys: `cisa_kev_cache` (JSON array), `cisa_kev_cache_at` (ISO timestamp).
Priority: in-memory → DB cache (if fresh) → CISA API fetch → stale DB fallback.
platform_settings has NO tenantId — it's a global table.

**How to apply:** When extending risk scoring or adding new risk factors, add the component to `computeRiskComponents()` in scanScheduler.ts, add a column to risk_scores via executeSql, update the Drizzle schema, and update the onConflictDoUpdate set clause.
