import https from "https";

export interface CpeMatch {
  vendor: string;
  product: string;
  exactVersion?: string;   // set when the CPE names a single version (criteria != "*")
  startIncluding?: string;
  startExcluding?: string;
  endIncluding?: string;
  endExcluding?: string;
}

export interface NvdCve {
  cve: string;
  title: string;
  description: string;
  cvss: number | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  cwe: string | null;
  remediation: string;
  published: string;
  isKev: boolean;
  // Vulnerable-CPE matches from NVD configurations — used to confirm a CVE
  // actually affects a detected product+version (drops cross-product noise
  // like Shodan listing a Ragnarok CVE just because Apache is present).
  cpeMatches: CpeMatch[];
}

// Parse a CPE URI (either cpe:/a:vendor:product:version or
// cpe:2.3:a:vendor:product:version:...) into its parts.
export function parseCpe(cpe: string): { vendor: string; product: string; version: string } | null {
  const s = String(cpe ?? "").toLowerCase();
  let parts: string[];
  if (s.startsWith("cpe:2.3:")) parts = s.split(":").slice(2);         // [part, vendor, product, version, ...]
  else if (s.startsWith("cpe:/")) parts = s.slice(5).split(":");       // [part, vendor, product, version, ...]
  else return null;
  const vendor = parts[1] ?? "", product = parts[2] ?? "", version = parts[3] ?? "";
  if (!vendor || !product) return null;
  return { vendor, product, version };
}

// Numeric version compare that tolerates suffixes like "6.6.1p1" → [6,6,1].
function cmpVersion(a: string, b: string): number {
  const na = a.split(/[^0-9]+/).filter(Boolean).map(Number);
  const nb = b.split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const x = na[i] ?? 0, y = nb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// True if `version` falls inside a CpeMatch's range / equals its exact version.
function versionInMatch(version: string, m: CpeMatch): boolean {
  if (!version || version === "*" || version === "-") return true;
  if (m.startIncluding && cmpVersion(version, m.startIncluding) < 0) return false;
  if (m.startExcluding && cmpVersion(version, m.startExcluding) <= 0) return false;
  if (m.endIncluding && cmpVersion(version, m.endIncluding) > 0) return false;
  if (m.endExcluding && cmpVersion(version, m.endExcluding) >= 0) return false;
  const hasRange = m.startIncluding || m.startExcluding || m.endIncluding || m.endExcluding;
  if (!hasRange && m.exactVersion && m.exactVersion !== "*" && m.exactVersion !== "-") {
    return cmpVersion(version, m.exactVersion) === 0;
  }
  return true;
}

// Does this CVE actually affect one of the products detected on the host?
// `detected` comes from real CPEs (nmap / Shodan). Returns false when no
// vulnerable CPE matches a detected vendor+product at the detected version —
// which is how cross-product and version-mismatch false positives get dropped.
export function cveAffectsProducts(
  cve: NvdCve,
  detected: { vendor: string; product: string; version: string }[],
): boolean {
  if (cve.cpeMatches.length === 0) return false; // no CPE data → cannot confirm → drop
  for (const m of cve.cpeMatches) {
    for (const d of detected) {
      if (d.vendor === m.vendor && d.product === m.product && versionInMatch(d.version, m)) {
        return true;
      }
    }
  }
  return false;
}

// ── Module-level NVD API key (set from pipeline on each run) ─────────────────
let nvdApiKey: string | null = null;
export function setNvdApiKey(key: string | null): void { nvdApiKey = key; }

// ── Severity from CVSS score ──────────────────────────────────────────────────
function severityFromCvss(score: number): NvdCve["severity"] {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0)   return "low";
  return "info";
}

// ── Parse NVD CVE item → NvdCve ──────────────────────────────────────────────
function parseNvdItem(item: any): NvdCve | null {
  try {
    const cveId: string = item.cve?.id ?? "";
    if (!cveId.startsWith("CVE-")) return null;

    const descriptions: any[] = item.cve?.descriptions ?? [];
    const desc = (descriptions.find((d: any) => d.lang === "en")?.value ?? "").slice(0, 500);

    let cvssScore: number | null = null;
    const metrics = item.cve?.metrics ?? {};
    const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
    const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
    const v2  = metrics.cvssMetricV2?.[0]?.cvssData;
    if (v31?.baseScore != null)       cvssScore = v31.baseScore;
    else if (v30?.baseScore != null)  cvssScore = v30.baseScore;
    else if (v2?.baseScore != null)   cvssScore = v2.baseScore;

    const weaknesses: any[] = item.cve?.weaknesses ?? [];
    const cweRaw = weaknesses[0]?.description?.find((d: any) => d.lang === "en")?.value ?? null;
    const cwe = cweRaw && cweRaw !== "NVD-CWE-noinfo" && cweRaw !== "NVD-CWE-Other" ? cweRaw : null;

    const published = item.cve?.published ?? new Date().toISOString();
    const severity = cvssScore != null ? severityFromCvss(cvssScore) : "info";

    // Collect the CVE's vulnerable-CPE matches (vendor/product + version range).
    const cpeMatches: CpeMatch[] = [];
    for (const cfg of item.cve?.configurations ?? []) {
      for (const node of cfg.nodes ?? []) {
        for (const cm of node.cpeMatch ?? []) {
          if (cm.vulnerable === false) continue;               // skip "running-on" platform CPEs
          const parsed = parseCpe(cm.criteria ?? "");
          if (!parsed || parsed.product === "*") continue;
          cpeMatches.push({
            vendor: parsed.vendor,
            product: parsed.product,
            exactVersion: parsed.version && parsed.version !== "*" ? parsed.version : undefined,
            startIncluding: cm.versionStartIncluding,
            startExcluding: cm.versionStartExcluding,
            endIncluding: cm.versionEndIncluding,
            endExcluding: cm.versionEndExcluding,
          });
        }
      }
    }

    return {
      cve: cveId,
      title: desc.split(". ")[0]?.slice(0, 120) || cveId,
      description: desc,
      cvss: cvssScore,
      severity,
      cwe,
      remediation: "Apply vendor security patches and follow NVD advisory recommendations.",
      published,
      isKev: false,
      cpeMatches,
    };
  } catch {
    return null;
  }
}

// ── Fetch with retry + 429 back-off ──────────────────────────────────────────
// Passes apiKey header when available for 10× higher rate limit (50/30s vs 5/30s)
async function fetchNvd(url: string, retries = 6): Promise<any> {
  for (let attempt = 0; attempt < retries; attempt++) {
    let waitMs = 2000 * (attempt + 1); // network-error backoff
    try {
      const data = await new Promise<any>((resolve, reject) => {
        const reqHeaders: Record<string, string> = {
          "User-Agent": "SentinelwareCTEM/1.0",
          "Accept": "application/json",
        };
        if (nvdApiKey) reqHeaders["apiKey"] = nvdApiKey;

        const req = https.get(url, {
          headers: reqHeaders,
          timeout: 20000,
        }, (res) => {
          // 429 = rate limited. RETRY it (don't drop the CVE) — dropping here was
          // the source of non-deterministic results across scans: a rate-limited
          // lookup vanished on one run and succeeded on the next.
          if (res.statusCode === 429) {
            const retryAfter = parseInt(res.headers["retry-after"] ?? "6", 10);
            res.resume();
            waitMs = (retryAfter + 1) * 1000;
            reject(new Error("rate-limited"));
            return;
          }
          if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
          let body = "";
          res.on("data", (c: string) => { body += c; });
          res.on("end", () => {
            try { resolve(JSON.parse(body)); } catch { resolve(null); }
          });
        });
        req.on("error", reject);
        req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
      });
      if (data !== null) return data;
      return null; // genuine non-200 (e.g. 404) — not retryable
    } catch {
      if (attempt < retries - 1) await sleep(waitMs);
    }
  }
  return null;
}

function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// Rate limit spacing:
//   Without API key: 5 req/30s  → ~6500ms between requests
//   With API key:    50 req/30s → ~650ms between requests
function nvdDelay(): number { return nvdApiKey ? 650 : 6500; }

// ── Look up CVEs for a single CVE ID ─────────────────────────────────────────
// Cache successful NVD lookups for the server's lifetime. NVD records for a
// published CVE are stable, so this both cuts rate-limit pressure and makes
// repeated scans deterministic — every scan sees the same parsed record.
const cveByIdCache = new Map<string, NvdCve>();

export async function lookupCveById(cveId: string): Promise<NvdCve | null> {
  const key = cveId.toUpperCase();
  const hit = cveByIdCache.get(key);
  if (hit) return hit;
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const data = await fetchNvd(url);
  const item = data?.vulnerabilities?.[0];
  const parsed = item ? parseNvdItem(item) : null;
  if (parsed) cveByIdCache.set(key, parsed);   // cache successes only; failures retry next time
  return parsed;
}

// ── Look up CVEs for a CPE string (returns top results by CVSS) ──────────────
export async function lookupCvesByCpe(cpe: string, maxResults = 10): Promise<NvdCve[]> {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpe)}&resultsPerPage=${maxResults}`;
  const data = await fetchNvd(url);
  const vulns: any[] = data?.vulnerabilities ?? [];
  return vulns.map(parseNvdItem).filter((v): v is NvdCve => v !== null)
    .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
}

// ── Enrich a list of Shodan CVE IDs with full NVD metadata ───────────────────
// Rate: 5 req/30s without key (6.5s delay), 50 req/30s with key (650ms delay)
export async function enrichShodanCves(cveIds: string[]): Promise<NvdCve[]> {
  const results: NvdCve[] = [];
  // Sort + dedupe before capping so the same 20 CVEs are always processed
  // regardless of the order Shodan returns them in — otherwise repeat scans
  // pick different subsets and produce different results.
  const ordered = [...new Set(cveIds.map(c => c.toUpperCase()))].sort();
  for (const id of ordered.slice(0, 20)) {
    try {
      const cve = await lookupCveById(id);
      if (cve) results.push(cve);
    } catch { }
    await sleep(nvdDelay());
  }
  return results;
}

// ── Bulk CPE lookup with rate limiting ────────────────────────────────────────
// Collects unique CPEs from all ports, queries NVD, deduplicates results
export async function lookupCvesFromCpes(cpes: string[]): Promise<NvdCve[]> {
  const uniqueCpes = [...new Set(cpes)].slice(0, 8);
  const allCves = new Map<string, NvdCve>();

  for (const cpe of uniqueCpes) {
    try {
      const found = await lookupCvesByCpe(cpe, 8);
      for (const c of found) {
        if (!allCves.has(c.cve)) allCves.set(c.cve, c);
      }
    } catch { }
    await sleep(nvdDelay());
  }

  return [...allCves.values()].sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
}
