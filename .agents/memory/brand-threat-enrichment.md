---
name: Brand threat enrichment three-phase startup + watchdog bugs
description: enrichStaleScans() phases, watchdog pitfalls, and count-save ordering in brand threat pipeline
---

## Rule
`enrichStaleScans()` in brandThreatRunner.ts runs three phases on every server startup:

- **Phase A**: DNS backfill for `status="done"` scans with `liveCount=0` — re-resolves brand_threat_results rows using Node.js dns where `dnsA IS NULL`, then updates liveCount/registeredCount/phishingRisk.
- **Phase B**: Phishing checks for `status="done"` scans with `liveCount>0` AND `phishingCount=0` — runs checkPhishingFeed + queryAbuseChFeeds for live domains, inserts phishing_detections rows, counts lookalike_domain brandAbuse entries, updates phishingCount = phishingDetections + lookalikeDomainCount.
- **Phase C**: Auto-rescan for `status="error"` scans with `totalPermutations>0` but ZERO ACTIVE brand_threat_results rows — calls triggerBrandThreatScan automatically.

## Watchdog pitfalls (fixed)

1. **createdAt not reset on rescan**: When `triggerBrandThreatScan` reuses an existing scan row, it MUST update `createdAt: new Date()`. Without this the watchdog calculates age from the original creation time (could be hours old) and kills the fresh scan within seconds of it starting.
2. **30-min threshold too short**: Brand threat scans for large domains (2334 permutations) take 40–90 min. Both `WATCHDOG_STUCK_THRESHOLD_MS` and `STUCK_SCAN_THRESHOLD_MS` must be 2 hours (`120 * 60 * 1000`). There are THREE locations to update: `brandThreatRunner.ts` (WATCHDOG_STUCK_THRESHOLD_MS), `brandThreatRunner.ts` (STUCK_SCAN_THRESHOLD_MS, separate const ~line 1309), and `brandThreats.ts` (STUCK_SCAN_THRESHOLD_MS).
3. **Counts not zeroed on rescan**: When reusing a scan row, explicitly zero `liveCount`, `registeredCount`, `phishingCount`, `dataLeakCount`, `brandAbuseCount` in the update set. Otherwise old counts carry over and the Phase B "phishingCount=0" check won't run.

## Count-save ordering (fixed)

liveCount / registeredCount / phishingCount must be saved to the DB immediately after Phase 3 (DNS insert + recompute from DB), NOT only at the very end of the pipeline. If the scan errors in Phase 4 or 5 (brand abuse, HIBP, screenshots), the card will still show real live counts instead of 0.

## Phase C must use isNull(archivedAt)
Error scans can have 4000+ ARCHIVED rows from a previous completed scan. Without the filter, Phase C sees archived rows and skips the rescan.

## phishingCount definition
The stored phishingCount must include BOTH phishing_detections rows AND lookalike_domain entries from brand_abuse_results. The detail page Phishing tab shows `phishingDetections.length + lookalikeDomains.length` — the stored phishingCount must match this total.

## UI gating (fixed)
ScanCard stats, detail page overview, and ALL detail page tabs were gated on `status === "done"`. For error scans with partial data, this must be `status === "done" || status === "error"`. Also: "View" button on ScanCard was only shown for done scans — must also show for error scans.

## How to apply
Any change to the rescan path in `triggerBrandThreatScan` must: (1) reset createdAt, (2) zero all counts, (3) save partial counts after Phase 3 not just at final step.
