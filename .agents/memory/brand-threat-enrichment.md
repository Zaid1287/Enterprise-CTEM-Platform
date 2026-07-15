---
name: Brand threat enrichment three-phase startup
description: enrichStaleScans() runs three phases at startup to fix brand threat scan data
---

## Rule
`enrichStaleScans()` in brandThreatRunner.ts runs three phases on every server startup:

- **Phase A**: DNS backfill for `status="done"` scans with `liveCount=0` — re-resolves brand_threat_results rows using Node.js dns where `dnsA IS NULL`, then updates liveCount/registeredCount/phishingRisk.
- **Phase B**: Phishing checks for `status="done"` scans with `liveCount>0` AND `phishingCount=0` — runs checkPhishingFeed + queryAbuseChFeeds for live domains, inserts phishing_detections rows, counts lookalike_domain brandAbuse entries, updates phishingCount = phishingDetections + lookalikeDomainCount.
- **Phase C**: Auto-rescan for `status="error"` scans with `totalPermutations>0` but ZERO ACTIVE brand_threat_results rows — calls triggerBrandThreatScan automatically.

## Why
During original scans, dnstwist's internal DNS resolver was blocked → all permutations had dnsA=null → liveCount=0 → runPhishingChecks(liveResults) was called with empty array → phishingDetections=0. Phase A fixes DNS, Phase B fixes phishing, Phase C fixes failed scans.

Phase C must use `isNull(archivedAt)` filter — error scans can have 4000+ ARCHIVED rows from a previous completed scan (user triggered rescan which then failed). Without the filter, Phase C sees archived rows and skips the rescan.

## How to apply
The phishingCount stored on brand_threat_scans must include BOTH phishing_detections rows AND lookalike_domain entries from brand_abuse_results. The detail page Phishing tab shows `phishingDetections.length + lookalikeDomains.length` — the stored phishingCount must match this total or the ScanCard shows a different number than the tab count badge.
