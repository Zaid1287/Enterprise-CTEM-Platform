---
name: Security tool binary integration
description: Patterns and gotchas for integrating Nix-installed security tool binaries into the pipeline
---

## Confirmed binaries in PATH (all via Nix)
naabu, subfinder, dnsx, nuclei, katana, nikto, dalfox, rustscan, ffuf, gobuster, feroxbuster, whatweb, wafw00f, wapiti, trufflehog

## Key integration patterns

### Checking system binary before self-download
```ts
const sys = execSync("which <tool> 2>/dev/null", { timeout: 3000 }).toString().trim();
if (sys) { /* use it */ } else { /* fall back to download/zip */ }
```
Used in: portScanner.ts (naabu), subdomainScanner.ts (subfinder/dnsx/amass), portScanner.ts (rustscan).

### VulnFinding interface field
Use `cve` (not `cveId`). Full shape: `{ cve, title, severity, cvss, cwe, remediation, source? }`.
Findings MUST be pushed into explicit `for (const v of xyzFindings)` loops → `findingInserts.push(...)` to persist to DB.
`allVulns` is a diagnostic aggregate, NOT auto-persisted.

### ffuf JSON output
```
ffuf -u "https://HOST/FUZZ" -w /home/runner/workspace/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 -t 40 -timeout 10 -of json -o /tmp/ffuf-HOST.json -s
```
Output goes to FILE (not stdout). `-of json -o FILE` is mandatory — stdout only gets progress output.

### whatweb JSON output
```
whatweb --log-json=- --no-errors -q https://TARGET 2>/dev/null
```
`--log-json=-` outputs JSON lines to stdout. Parse each line separately (multiple JSON objects, not array).

### nikto CSV output
```
nikto -host TARGET -port 443 -ssl -Format csv -nointeractive -timeout 10 2>/dev/null
```
CSV columns: id, ip, port, uri, osvdb, method, description. Field 6 (index) is description; field 4 is CVE ref.

### dalfox XSS detection
```
dalfox url TARGET --silence --skip-bav --no-spinner 2>/dev/null
```
XSS confirmed when output line contains `[V]` or `PoC`. Each confirmed line = one finding.

### rustscan port output
```
rustscan -a HOST --range 1-65535 --ulimit 5000 --no-nmap --timeout 3000 2>/dev/null
```
Parse: `Open IPADDR:PORT` lines. Regex: `/Open\s+[^:]+:(\d+)/i`

**Why:** These patterns took multiple attempts to get right — stdout vs file, field indices, parser edge cases.
**How to apply:** When adding a new binary scanner, pick the right output format flag first, then write a typed parser before wiring into the pipeline.
