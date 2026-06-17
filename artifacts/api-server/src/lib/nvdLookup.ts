import https from "https";

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
    };
  } catch {
    return null;
  }
}

// ── Fetch with retry + 429 back-off ──────────────────────────────────────────
// Passes apiKey header when available for 10× higher rate limit (50/30s vs 5/30s)
async function fetchNvd(url: string, retries = 3): Promise<any> {
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const data = await new Promise<any>((resolve, reject) => {
        const reqHeaders: Record<string, string> = {
          "User-Agent": "SentinelwareCTEM/1.0",
          "Accept": "application/json",
        };
        if (nvdApiKey) reqHeaders["apiKey"] = nvdApiKey;

        const req = https.get(url, {
          headers: reqHeaders,
          timeout: 15000,
        }, (res) => {
          if (res.statusCode === 429) {
            const retryAfter = parseInt(res.headers["retry-after"] ?? "6", 10);
            setTimeout(() => resolve(null), (retryAfter + 1) * 1000);
            res.resume();
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
    } catch {
      if (attempt < retries - 1) await sleep(2000 * (attempt + 1));
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
export async function lookupCveById(cveId: string): Promise<NvdCve | null> {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const data = await fetchNvd(url);
  const item = data?.vulnerabilities?.[0];
  return item ? parseNvdItem(item) : null;
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
  for (const id of cveIds.slice(0, 20)) {
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
