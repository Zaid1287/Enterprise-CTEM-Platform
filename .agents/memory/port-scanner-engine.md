---
name: Port Scanner Engine
description: How the Naabu+Nmap+Shodan port scanning engine is set up and what files to change.
---

## Engine location
`artifacts/api-server/src/lib/portScanner.ts` — exports `scanPorts(target)` returning `PortScanReport`.

## Three-phase scan
1. **Naabu** (`/tmp/naabu`): full 65535-port TCP discovery, rate 3000, timeout 5s.
2. **Nmap**: service/version detection (intensity 6) + NSE scripts (banner, http-title, ssl-cert, ssh-hostkey, smtp-commands, ftp-anon, rdp-enum-encryption, mysql-info, ms-sql-info, mongodb-info) on naabu-discovered ports.
3. **Shodan InternetDB** (`https://internetdb.shodan.io/{ip}`): free, no API key; returns ports, tags, CPEs, CVEs, hostnames.

## Naabu binary persistence
- Binary zip stored at `artifacts/api-server/binaries/naabu.zip` (committed to workspace for persistence).
- `ensureNaabu()` in portScanner.ts auto-extracts to `/tmp/naabu` if missing (e.g. after container restart).
- Path from dist: `path.resolve(__dirname, "../binaries/naabu.zip")` — `__dirname` is dist dir.
- esbuild banner polyfills `__dirname` via `globalThis.__dirname`.

## Pipeline integration
- `pipelineScans.ts` imports `scanPorts` and runs it unconditionally for every scan asset (Phase 2 block, no gate).
- `needsNmap` variable still declared but is dead code — Phase 2 no longer guarded by it.
- Shodan data pushed into `geoIntel` as items with `type: "Shodan"` — visible in Intelligence tab.
- Raw output includes all three sections (Naabu, Nmap, Shodan) for Raw Output tab.

## UI
- `ScanReportPage.tsx` Ports tab: shows Shodan InternetDB panel at top (tags, CVEs as NVD links, CPEs).
- `PortRow` component: expandable rows with banner, NSE script output, CPEs.
- `scanMethod` badge (naabu+nmap or nmap-only) shown in Shodan panel header.

**Why:** User required Naabu for full-port discovery, Nmap for NSE scripts/banners, Shodan for passive intel — all auto-running on every scan.
