---
name: dnstwist DNS resolver sandboxed
description: dnstwist binary generates permutations correctly but its DNS resolver is network-sandboxed in Replit — all returned records are empty. Node.js dns.resolve4 works normally.
---

## The rule

After calling `runDnstwistBinary(domain)`, always enrich zero-DNS results with Node.js `checkDNSFull()` before returning from `scanPermutations()`.

**Why:** dnstwist uses its own DNS resolver (likely raw sockets or a custom resolver) which is blocked by Replit's network sandbox. Node.js dns module uses the system resolver (libuv → /etc/resolv.conf) which works correctly. Without enrichment, all 2000+ permutations have empty dns_a, dns_mx, dns_ns — causing liveCount=0, phishingCount=0, and all detail page stats to show zero.

**How to apply:** In `brandThreatRunner.ts` → `scanPermutations()`:
- Filter `results` where all DNS arrays are empty
- Run `checkDNSFull(item.permutation)` in a 20-worker concurrent queue
- Mutate dnsA/dnsAaaa/dnsMx/dnsNs in place before returning
- Existing scans with stale zero-DNS data can be fixed via the Re-scan button (POST /api/brand-threats/:id/rescan)

**Verified:** Node.js `dns.resolve4('deltin.net')` → `66.39.159.31` works; dnstwist DNS for same domain → empty.
