---
name: Pipeline scan bugs and fixes
description: Key bugs found comparing scans 114 (26 min, risk=11) and 115 (7 min, risk=95) for windsurf.com; all fixes applied.
---

## Rules

**Phase 3 hard timeout (10 min):** `runDirFuzz` has no hard cap — wrap in `Promise.race` with 10-min resolve(null). Without it, a BFS crawl can run 22+ minutes on large targets. Already implemented at pipelineScans.ts Phase 3 block.

**Why:** Scan 114 ran 22 min in Phase 3 (134 endpoints) vs 5 min in scan 115 (34 endpoints) — pure non-determinism.

**Endpoint finding verification:** CRITICAL/HIGH dir-fuzz findings must be verified with a real HTTP fetch + body check before generating a finding. Soft-404s (pages returning 200 with "not found" body) otherwise generate false critical findings like `EXPOSED-FILE-backup.zip`. Code already added: `SOFT_404_PATTERNS` + `REAL_CONTENT_INDICATORS` verification after dirVulnCandidates is built.

**finalizeScannedAssets must be awaited:** Previously called fire-and-forget (`.catch(...)` only). The scan was marked `completed` before risk score was updated — causing scan reports to show the *pre-scan* risk score (showed 11 instead of 100). Fixed: `await finalizeScannedAssets(...)` with try/catch.

**auto_mitigate_threshold default = 2:** Was 3. Findings not seen in 2 consecutive scans are almost certainly resolved; 3 was too slow to clean up false positives.

**findingsCount accuracy:** `findingTotals.push(...)` previously counted intended inserts, not confirmed DB inserts. Now wrapped in try/catch per batch and counts only `insertedCount` (successful rows).

**Phase 4 fast-exit guard:** If Phase 4 completes < 500ms, emit a WARN log with `isHostLive`, `needsVulns`, `needsSecrets` flags. In scan 115, Phase 4 ran in 280ms — essentially a no-op. The log helps diagnose which guard caused the skip.

**Startup scan recovery:** Running scans interrupted by restart are now auto-requeued if < 2 hours old (previously just marked "failed"). Scans ≥ 2 hours old are still marked failed with notification. Pending scans > 10 min were already re-enqueued (unchanged).

**All tools share phase timestamps (known limitation):** `startTool`/`doneTool` stamps ALL tools in a phase with the phase start/end — no individual per-tool timing. Progress tool breakdown is fabricated. Not fixed yet (would require major refactor of pipeline structure).

**Port scanner non-determinism:** 175s vs 8s for identical 2-port result on same target. Nmap `-T4` + `--host-timeout 50s` already set, but timing still varies by network conditions. No deterministic fix available without sacrificing accuracy.
