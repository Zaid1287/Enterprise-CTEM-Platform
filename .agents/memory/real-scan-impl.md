---
name: Real scan implementation
description: How pipelineScans.ts executes real live security scans (not simulated)
---

## Key facts

- **nmap**: TCP connect scan (`-sT --open --top-ports 1000 -T4 --max-rtt-timeout 2s --host-timeout 40s`). No `-sV` needed — service names come from nmap output naturally. Parse lines matching `/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/`.
- **DNS recon**: Node.js `dns/promises` module (resolve4, resolve6, resolveMx, resolveNs, resolveTxt, resolveSoa, resolveCname). Subdomain brute-force via 30-word wordlist with Promise.allSettled.
- **HTTP probe**: `fetch()` with AbortController(12s timeout). Detects tech from headers/body, WAF from cf-ray/x-iinfo/x-amz-cf-id.
- **SSL cert**: `tls.connect({ port: 443, rejectUnauthorized: false })` → `getPeerCertificate(true)`. Returns issuer, subject, valid_from, valid_to, SANs, serialNumber, bits.
- **GeoIP**: `ip-api.com` (free, 45 req/min, no key) with ipapi.co as fallback. Field `status === "success"` to detect success.
- **WHOIS**: `whois` binary (Nix: `whois` package). Extracts Registrar, Registrant Org, Created, Expires, Updated, DNSSEC.
- **CVE matching**: Against real services from nmap ports + HTTP tech stack.

## Architecture

- Scan runs **async in background** via `setImmediate` — HTTP endpoint returns 201 immediately with `status: "running"`.
- Frontend already polls `/scans/:id` every 4s and updates when `status === "completed"`.
- `activeScanKillers` Map (module-level) tracks per-scan nmap process kill functions; the Stop endpoint calls `killer()`.
- All underlying scans for an asset run **concurrently** via `Promise.allSettled` — so DNS + HTTP + nmap + SSL + GeoIP all fire in parallel.
- Results stored per-tool per-asset (one `scan_asset_results` row per tool).

## OpenAPI field name

- Request body field is `assetToolConfig` (no 's') per OpenAPI spec → generated Zod schema.
- Route handler reads: `body.assetToolConfig ?? body.assetToolConfigs` (fallback for safety).

## What works in Replit environment

- nmap TCP connect scans work (no raw sockets needed)
- Outbound DNS, HTTPS, TLS all work
- ip-api.com free GeoIP works (no key needed)
- whois binary works after Nix install of `whois` package
- bind/dig Nix package installs `dig` but not in PATH; use Node dns module instead

**Why:** Previous implementation was fully simulated with seeded random data. Real scans required careful tool selection (nmap -sT not -sS, Node.js dns over dig binary, ip-api.com over ipapi.co which rate-limits).
