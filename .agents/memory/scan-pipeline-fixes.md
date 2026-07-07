---
name: Scan pipeline OOM and scheduling fixes
description: Root causes and fixes for scans always failing — OOM from Puppeteer+port-scanner, no incremental saves, beat scheduler 401, stuck-scan duplicate guard
---

## Rules

### OOM during port scanning
Puppeteer browser (~300MB) must be CLOSED before port scanning starts (naabu/nmap/masscan).
Call `closeBrowser()` from screenshotEngine at the Phase 1→Phase 2 boundary.
Browser lazily reopens when Phase 3 screenshots run.

**Why:** Chromium + port scanners coexist → OOM kill in Replit's container → scan stuck in "running" indefinitely.

### Phase 1 incremental save
Insert a `scan_asset_results` row (tool_name="passive_recon") immediately after Phase 1 completes
(before port scanning). Saves DNS/subdomains/intelligence so results exist even if Phase 2 crashes.

**Why:** The pipeline previously saved scan_asset_results only at the end of all phases. OOM during Phase 2 wiped all results.

### Beat scheduler must NOT call HTTP
`runDirect()` in beatScheduler.ts calls `enqueueAndRun()` via dynamic import — never via HTTP.
HTTP approach fails with 401 because requireAuth does `WHERE id = 0` and finds no user.
`enqueueOrRun` → `setImmediate(() => runDirect(...))` is the correct path.

**Why:** HTTP endpoint requires valid JWT; userId=0 is not a real user.

### Startup recovery threshold
`_serverBootTime - 30_000` (30 seconds), not 3 minutes.
In-process queue is lost on ANY restart — any "running" scan from before boot is definitively orphaned.

**Why:** 3min threshold missed scans that started 8s before the restart (most server restarts happen within seconds).

### Beat scheduler stuck-scan guard
Filter running scans older than 10 minutes out of `busyAssetIds`.
Pattern: `if (s.status === "running" && ageMs > 10 * 60 * 1000) return false`

**Why:** Stuck "running" scans (not recovered yet) permanently blocked new scans for those assets.

### Memory limits
MAX_CONCURRENT_SCANS=2, MAX_PARALLEL_ASSETS=1 in pipelineScans.ts.
Higher values (5 and 3) cause OOM from concurrent port scans + Puppeteer instances.
