# TOOL DOCUMENTATION

Notes on the changes made to the scan tooling. Covers four things: stuck-scan
handling, CVE accuracy, making repeat scans consistent, and the pipeline tab UI.

Quick heads-up before anything else: on a plain local checkout most findings
come from the passive Shodan InternetDB lookup. The actual binary scanners
(nmap, naabu, masscan, etc.) go through `orchestratedExec` and need the real
runtime to do anything useful (root for raw sockets, the Shodan/Censys keys,
the Nix tool wrappers). Without that they no-op, so local runs won't show many
live findings. Nothing below depends on that; I tested it all against real
NVD/Shodan responses.

## 1. Stuck pipeline scans

`artifacts/api-server/src/index.ts`

The startup recovery and the watchdog only handled brand-threat scans. A normal
pipeline scan whose worker died (restart, crash, or a tool hanging on a target
that doesn't respond) just sat in `running` forever. It showed as active in the
UI with nothing actually running, and it cluttered the queue view.

Added two functions, same shape as the existing brand-threat ones:

- `resetStuckPipelineScans()` runs on startup and marks any `scans` row that's
  been `running`/`active` past the 30 min threshold as `failed`. Leaves fresh
  ones alone so it doesn't kill a scan that's genuinely mid-run.
- `startPipelineScanWatchdog()` polls every 5 min and does the same thing
  mid-run, so you don't have to wait for a restart. It's stopped in the
  shutdown handler next to the brand-threat watchdog.

Tested it by inserting a `running` scan aged 40 min plus a fresh one, restarting,
and confirming the old one flipped to `failed` and the fresh one didn't.

The threshold is the existing `STUCK_SCAN_THRESHOLD_MS` (30 min). If real scans
on big targets legitimately run longer than that, bump it or the watchdog will
reap them. Related: a few tools run with no per-tool timeout on purpose, so a
target that hangs can block a tool for a long time. If that becomes an issue the
real fix is per-tool timeouts.

## 2. CVE accuracy

`artifacts/api-server/src/lib/nvdLookup.ts`, `artifacts/api-server/src/routes/pipelineScans.ts`

Shodan InternetDB gives back a big version-based CVE list per IP and we were
showing all of it. It's noisy and includes CVEs for unrelated products. Example:
a host running Apache 2.4.7 / OpenSSH 6.6.1 got `CVE-2007-4723` flagged, which is
a Ragnarok Online control panel bug that just happens to mention Apache. That's
a straight false positive.

Now every Shodan CVE gets checked against NVD's CPE data before it counts:

- `parseNvdItem()` pulls each CVE's vulnerable CPE matches into
  `NvdCve.cpeMatches` (vendor, product, version range). CPEs marked
  `vulnerable: false` are skipped so a CVE doesn't get attributed to Apache just
  because Apache is the platform it runs on.
- Added `parseCpe()` (handles both `cpe:/a:...` and `cpe:2.3:a:...`),
  `cmpVersion()` (copes with things like `6.6.1p1`), a range check, and
  `cveAffectsProducts()`.
- `cveAffectsProducts(cve, detected)` only returns true if one of the CVE's
  vulnerable CPEs matches a product actually on the host at a version in range.
- In `lookupRealCves()` the Shodan branch runs each CVE through that check using
  the host's real CPEs (nmap + Shodan). The caller passes
  `portScanReport.shodan.cpes`.

Checked against live NVD: `CVE-2017-7679` and `CVE-2023-25690` (Apache) stay,
`CVE-2007-4723` (Ragnarok) gets dropped.

One thing to watch: `parseCpe` needs `.slice(2)` for `cpe:2.3:` strings, not
`.slice(3)`. I had it wrong at first and it read every product as `*`, which
dropped everything. So test it against real NVD data, don't eyeball it.

## 3. Consistent repeat scans

`artifacts/api-server/src/lib/nvdLookup.ts`

Running the same scan twice gave different CVE counts. The cause was `fetchNvd`
throwing away rate-limited (429) lookups: the 429 branch returned null and the
retry loop only retried network errors. So under load a CVE would drop on one run
and come back on the next.

- `fetchNvd()` retries on 429 now, respecting `Retry-After`, up to 6 tries.
  Timeout bumped to 20s.
- `lookupCveById()` caches results in memory by CVE id. NVD records don't change
  for a published CVE, so caching makes repeats consistent and takes pressure off
  the rate limit. Only successful lookups are cached.
- `enrichShodanCves()` sorts and dedupes the CVE ids before capping at 20. Shodan
  doesn't return them in a guaranteed order, so without sorting each scan would
  process a different subset of 20 and produce a different result. Sorting makes
  the subset stable.

End state: 5 back-to-back scans of the same target returned the identical CVE
set, and every CVE in it checked out against NVD as actually affecting the
detected version. See "Results" at the bottom.

One thing to tune later: the sort is by CVE id, so the capped-at-20 subset skews
toward the oldest CVEs. All of them are real, but you'd probably rather cap by
severity/EPSS. That needs the CVSS, which only comes back after the NVD lookup,
so it's a second pass — left as a follow-up.

## 4. Pipeline tab

`artifacts/ctem-platform/src/pages/SecurityToolsPage.tsx` + a DB seed

The Pipeline tab was empty. The platform seeds the 59 tools into `security_tools`
but never creates any `tool_pipeline_steps`, so there was nothing to list.

- Seeded `tool_pipeline_steps` for the platform tenant from `security_tools`,
  ordered by phase (recon, port scan, web recon, ssl, vuln, secrets, osint,
  cloud, screenshot). This is a one-time SQL insert right now; worth folding into
  `seedPlatform.ts` so it happens automatically.
- Grouped the Execution Order list by category with a header per group and a
  count. Added a `categoryLabel` map and a few more `categoryColor` entries; the
  render emits a header whenever the category changes.

## Circuit breaker (operational finding, not a code change)

Worth writing down because it cost a lot of time. Findings kept disappearing
between runs: one scan would return ~16 CVEs, the next 0. Turned out the circuit
breaker (`scanOrchestrator` / `circuitBreaker.ts`) had tripped OPEN for several
external hosts after repeated failures during a long session, including the KEV
feed (`www.cisa.gov`, 20 consecutive failures), `urlscan.io`, phishing feeds,
and the Shodan InternetDB host. Once a breaker is open, `orchestratedFetch`
short-circuits that call and returns nothing, so the CVE source goes silent and
the scan reports 0 findings.

The state is persisted in `orchestrator_config` under `circuit_breaker_state`
and restored on boot, so restarting doesn't clear it. I reset it by deleting
that row; after that, findings came back immediately.

Two things to consider fixing in the code:
- A tripped breaker on a data source we depend on (Shodan, KEV) shouldn't
  silently zero out findings. At minimum it should surface a clear warning on
  the scan so it's obvious the source was skipped, not that the target is clean.
- The cooldown for those feeds is 15–60 min and it persists across restarts.
  That's fine for genuinely dead endpoints but painful when it trips on
  something that's actually up. Worth a manual "reset breakers" action.

## Files touched

- `artifacts/api-server/src/index.ts` — stuck-scan reset + watchdog
- `artifacts/api-server/src/lib/nvdLookup.ts` — CPE parsing/matching, 429 retry, CVE cache
- `artifacts/api-server/src/routes/pipelineScans.ts` — CPE gating in `lookupRealCves`
- `artifacts/ctem-platform/src/pages/SecurityToolsPage.tsx` — pipeline grouping
- `tool_pipeline_steps` seed

Two local-only changes I made to run it on macOS from a stripped checkout aren't
meant to be committed: a Vite dev proxy pointing `/api` at `:8090`, and re-adding
the darwin native binaries that the install pruned.

## Background

CVEs come from nmap `-sV` -> CPE -> NVD CPE API, cross-checked with Shodan.
It's CPE-based rather than banner-string matching, so it's more precise to start
with; the change in section 2 tightens it further by filtering Shodan's list
down to what actually matches the host.

## Results

Ran 5 back-to-back scans of scanme.nmap.org (Apache httpd 2.4.7, OpenSSH
6.6.1p1) after all the above:

- All 5 returned the identical 8-CVE set.
- Every CVE checked against NVD affects Apache 2.4.7:
  CVE-2006-20001, CVE-2013-5704, CVE-2013-6438, CVE-2014-0098, CVE-2014-0117,
  CVE-2014-0118, CVE-2014-0226, CVE-2014-0231.
- No cross-product false positives (the Ragnarok-type entry from before is gone).

So: consistent run to run, and everything in the list is a real match for the
detected version. The severity-ordering follow-up noted in section 3 still
applies (the set skews old because of the id sort).
