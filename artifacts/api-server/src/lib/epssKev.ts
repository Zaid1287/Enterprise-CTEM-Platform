/**
 * EPSS (Exploit Prediction Scoring System) + CISA KEV (Known Exploited Vulnerabilities)
 * Free APIs — no auth required.
 *
 * EPSS: https://api.first.org/data/v1/epss
 * KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 */

import { logger } from "./logger";

const EPSS_BATCH_SIZE  = 100;
const EPSS_API         = "https://api.first.org/data/v1/epss";
const KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_TTL_MS       = 24 * 60 * 60 * 1000; // 24 hours

interface EpssEntry {
  cve:        string;
  epss:       number;   // 0-1 probability of exploitation
  percentile: number;   // 0-1 rank among all CVEs
}

// Module-level in-process cache (refreshed each deployment restart)
let kevCache: Set<string> | null = null;
let kevCacheTs = 0;
const epssCache = new Map<string, EpssEntry>();

// ── EPSS ─────────────────────────────────────────────────────────────────────

export async function fetchEpssScores(cveIds: string[]): Promise<Map<string, EpssEntry>> {
  const realCves = [...new Set(
    cveIds.map(c => c.toUpperCase()).filter(c => /^CVE-\d{4}-\d+$/.test(c))
  )];
  if (realCves.length === 0) return new Map();

  const result = new Map<string, EpssEntry>();

  // Return cached entries and collect uncached ones
  const uncached: string[] = [];
  for (const cve of realCves) {
    const hit = epssCache.get(cve);
    if (hit) result.set(cve, hit);
    else uncached.push(cve);
  }
  if (uncached.length === 0) return result;

  for (let i = 0; i < uncached.length; i += EPSS_BATCH_SIZE) {
    const batch = uncached.slice(i, i + EPSS_BATCH_SIZE);
    try {
      const ctrl = new AbortController();
      const t    = setTimeout(() => ctrl.abort(), 15000);
      const res  = await fetch(`${EPSS_API}?cve=${batch.join(",")}`, {
        signal: ctrl.signal,
        headers: { Accept: "application/json" },
      });
      clearTimeout(t);
      if (!res.ok) continue;
      const data: any = await res.json().catch(() => null);
      for (const entry of data?.data ?? []) {
        const cveUp: string = String(entry.cve ?? "").toUpperCase();
        const e: EpssEntry = {
          cve:        cveUp,
          epss:       parseFloat(entry.epss       ?? "0"),
          percentile: parseFloat(entry.percentile ?? "0"),
        };
        epssCache.set(cveUp, e);
        result.set(cveUp, e);
      }
    } catch (err) {
      logger.warn({ err, batch: batch.slice(0, 5) }, "EPSS batch fetch failed (non-fatal)");
    }
  }
  return result;
}

// ── KEV ──────────────────────────────────────────────────────────────────────

export async function fetchKevSet(): Promise<Set<string>> {
  const now = Date.now();
  if (kevCache && now - kevCacheTs < KEV_TTL_MS) return kevCache;

  try {
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), 20000);
    const res  = await fetch(KEV_URL, {
      signal: ctrl.signal,
      headers: { Accept: "application/json" },
    });
    clearTimeout(t);
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const data: any = await res.json().catch(() => null);
    const kev = new Set<string>(
      (data?.vulnerabilities ?? []).map((v: any) => String(v.cveID ?? "").toUpperCase()).filter(Boolean)
    );
    logger.info({ count: kev.size }, "KEV catalog refreshed");
    kevCache   = kev;
    kevCacheTs = now;
    return kev;
  } catch (err) {
    logger.warn({ err }, "KEV fetch failed — using cached/empty set (non-fatal)");
    return kevCache ?? new Set();
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

type FindingLike = {
  cve?: string | null;
  epss?: number | null;
  isKev?: boolean;
  [key: string]: unknown;
};

/**
 * Enriches a list of findings with real EPSS scores and KEV status.
 * Non-CVE findings (synthetic IDs like VT-*, CLOUD-*, SEC-*) are returned unchanged.
 */
export async function enrichFindingsWithEpssKev<T extends FindingLike>(findings: T[]): Promise<T[]> {
  const realCveFindings = findings.filter(f => f.cve && /^CVE-\d{4}-\d+$/i.test(f.cve));
  if (realCveFindings.length === 0) return findings;

  const cveIds = realCveFindings.map(f => f.cve as string);

  const [epssMap, kevSet] = await Promise.all([
    fetchEpssScores(cveIds),
    fetchKevSet(),
  ]);

  let enrichedCount = 0;
  const enriched = findings.map(f => {
    if (!f.cve || !/^CVE-/i.test(f.cve)) return f;
    const key       = f.cve.toUpperCase();
    const epssEntry = epssMap.get(key);
    const isKev     = kevSet.has(key);
    const epssVal   = epssEntry?.epss ?? null;
    if (epssVal !== null || isKev) enrichedCount++;
    return { ...f, epss: epssVal, isKev };
  });

  logger.info({ total: findings.length, realCves: realCveFindings.length, enriched: enrichedCount }, "EPSS+KEV enrichment complete");
  return enriched;
}
