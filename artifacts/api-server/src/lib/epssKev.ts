/**
 * EPSS (Exploit Prediction Scoring System) + CISA KEV (Known Exploited Vulnerabilities)
 * Free APIs — no auth required.
 *
 * EPSS: https://api.first.org/data/v1/epss
 * KEV:  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *
 * Issue 6: EPSS partial-failure logging + enrichedCount tracking
 * Issue 7: DB-backed KEV cache (persists across server restarts)
 */

import { eq, sql } from "drizzle-orm";
import { db, platformSettingsTable } from "@workspace/db";
import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";

const EPSS_BATCH_SIZE  = 100;
const EPSS_API         = "https://api.first.org/data/v1/epss";
const KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const KEV_TTL_MS       = 24 * 60 * 60 * 1000; // 24 hours

// Platform settings keys for DB-backed KEV cache (Issue 7)
const KEV_CACHE_KEY    = "cisa_kev_cache";
const KEV_CACHE_AT_KEY = "cisa_kev_cache_at";

interface EpssEntry {
  cve:        string;
  epss:       number;   // 0-1 probability of exploitation
  percentile: number;   // 0-1 rank among all CVEs
}

// Module-level in-process cache (fast layer)
let kevCache: Set<string> | null = null;
let kevCacheTs = 0;
const epssCache = new Map<string, EpssEntry>();

// ── DB-backed KEV cache helpers (Issue 7) ─────────────────────────────────────

async function readKevFromDb(): Promise<{ data: Set<string>; ts: number } | null> {
  try {
    const [dataRow] = await db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, KEV_CACHE_KEY));
    const [atRow] = await db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, KEV_CACHE_AT_KEY));

    if (!dataRow?.value || !atRow?.value) return null;

    const ts = Date.parse(atRow.value);
    if (isNaN(ts)) return null;

    const ids: string[] = JSON.parse(dataRow.value);
    return { data: new Set(ids), ts };
  } catch {
    return null;
  }
}

async function writeKevToDb(kevSet: Set<string>): Promise<void> {
  try {
    const now = new Date().toISOString();
    const json = JSON.stringify(Array.from(kevSet));

    await db.insert(platformSettingsTable).values({
      key: KEV_CACHE_KEY,
      value: json,
      label: "CISA KEV Cache",
      description: "Cached CISA Known Exploited Vulnerabilities catalog (auto-updated every 24h)",
      category: "cache",
    }).onConflictDoUpdate({
      target: platformSettingsTable.key,
      set: { value: json },
    });

    await db.insert(platformSettingsTable).values({
      key: KEV_CACHE_AT_KEY,
      value: now,
      label: "CISA KEV Cache Timestamp",
      description: "Timestamp of last CISA KEV cache update",
      category: "cache",
    }).onConflictDoUpdate({
      target: platformSettingsTable.key,
      set: { value: now },
    });
  } catch (err) {
    logger.warn({ err }, "Failed to persist KEV cache to DB (non-fatal)");
  }
}

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

  let fetchedCount = 0;
  let failedBatches = 0;

  for (let i = 0; i < uncached.length; i += EPSS_BATCH_SIZE) {
    const batch = uncached.slice(i, i + EPSS_BATCH_SIZE);
    try {
      const ctrl = new AbortController();
      const t    = setTimeout(() => ctrl.abort(), 15000);
      const res  = await orchestratedFetch(`${EPSS_API}?cve=${batch.join(",")}`, {
        signal: ctrl.signal,
        headers: { Accept: "application/json" },
      }, { intensity: "passive" });
      clearTimeout(t);
      if (!res.ok) {
        failedBatches++;
        logger.warn({ status: res.status, batchSize: batch.length }, "EPSS batch returned non-OK status");
        continue;
      }
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
        fetchedCount++;
      }
    } catch (err) {
      failedBatches++;
      logger.warn({ err, batch: batch.slice(0, 5) }, "EPSS batch fetch failed (non-fatal)");
    }
  }

  // Issue 6: warn when enrichment is significantly incomplete
  const expectedFromApi = uncached.length;
  if (failedBatches > 0 || fetchedCount < expectedFromApi * 0.5) {
    logger.warn(
      { requested: expectedFromApi, fetched: fetchedCount, failedBatches, missing: expectedFromApi - fetchedCount },
      "EPSS enrichment partially failed — missing CVEs will use epss=0, understating risk",
    );
  }

  return result;
}

// ── KEV ──────────────────────────────────────────────────────────────────────

export async function fetchKevSet(): Promise<Set<string>> {
  const now = Date.now();

  // In-memory cache is fresh
  if (kevCache && now - kevCacheTs < KEV_TTL_MS) return kevCache;

  // Issue 7: Try DB-backed cache before hitting CISA API
  if (!kevCache) {
    const dbCache = await readKevFromDb();
    if (dbCache && now - dbCache.ts < KEV_TTL_MS) {
      logger.info({ count: dbCache.data.size, source: "db" }, "KEV catalog loaded from DB cache");
      kevCache   = dbCache.data;
      kevCacheTs = dbCache.ts;
      return kevCache;
    }
  }

  // Fetch fresh from CISA
  try {
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), 20000);
    const res  = await orchestratedFetch(KEV_URL, {
      signal: ctrl.signal,
      headers: { Accept: "application/json" },
    }, { intensity: "passive" });
    clearTimeout(t);
    if (!res.ok) throw new Error(`KEV HTTP ${res.status}`);
    const data: any = await res.json().catch(() => null);
    const kev = new Set<string>(
      (data?.vulnerabilities ?? []).map((v: any) => String(v.cveID ?? "").toUpperCase()).filter(Boolean)
    );
    logger.info({ count: kev.size, source: "cisa" }, "KEV catalog refreshed from CISA");
    kevCache   = kev;
    kevCacheTs = now;

    // Issue 7: persist to DB so next restart gets it without a CISA round-trip
    await writeKevToDb(kev);

    return kev;
  } catch (err) {
    logger.warn({ err }, "KEV fetch from CISA failed — trying DB cache as fallback");

    // Fallback: try DB cache even if stale
    const dbCache = await readKevFromDb();
    if (dbCache) {
      const ageHours = Math.round((now - dbCache.ts) / 3600000);
      logger.warn({ count: dbCache.data.size, ageHours }, "Using stale DB KEV cache as fallback");
      kevCache   = dbCache.data;
      kevCacheTs = dbCache.ts;
      return kevCache;
    }

    logger.warn("No KEV data available (no memory cache, no DB cache, CISA fetch failed) — KEV bonus will be 0");
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

export interface EnrichmentResult<T> {
  findings: T[];
  totalCveFindigs: number;
  enrichedWithEpss: number;
  epssEnriched: boolean; // Issue 6: flag for callers to detect partial failure
}

/**
 * Enriches a list of findings with real EPSS scores and KEV status.
 * Non-CVE findings (synthetic IDs like VT-*, CLOUD-*, EXP-PORT-*) are returned unchanged.
 *
 * Returns enrichment stats so callers can detect and surface partial failures.
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

  const epssEnriched = enrichedCount > 0 || realCveFindings.length === 0;
  if (!epssEnriched) {
    logger.warn({ totalCves: realCveFindings.length }, "EPSS enrichment returned no data for any CVE — epss=0 will be used for all findings");
  } else {
    logger.info(
      { total: findings.length, realCves: realCveFindings.length, enriched: enrichedCount, epssEnriched },
      "EPSS+KEV enrichment complete",
    );
  }

  return enriched;
}
