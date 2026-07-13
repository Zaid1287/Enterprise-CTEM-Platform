/**
 * CVE Intelligence Engine
 * Fetches recent CVEs from NVD API v2, enriches with EPSS scores and
 * CISA KEV status (reusing existing epssKev.ts), and upserts into ti_cve_intel.
 * Also populates linkedActors/linkedCampaigns/linkedMalware by cross-referencing
 * with existing ti_threat_actors/ti_campaigns/ti_malware data.
 */
import { eq, sql, inArray } from "drizzle-orm";
import {
  db,
  tiCveIntelTable,
  tiThreatActorsTable,
  tiCampaignsTable,
  tiMalwareTable,
  platformSettingsTable,
} from "@workspace/db";
import { fetchEpssScores, fetchKevSet } from "../epssKev";
import { logger } from "../logger";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const RESULTS_PER_PAGE = 2000;
const UA = "Sentinelware-CTEM-TI/1.0";

async function getPlatformSetting(key: string): Promise<string | null> {
  try {
    const [row] = await db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable)
      .where(eq(platformSettingsTable.key, key));
    return row?.value ?? null;
  } catch {
    return null;
  }
}

function severityFromCvss(cvss: number | null): string {
  if (cvss === null) return "medium";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

function extractCvssV3(cve: any): { score: number | null; vector: string | null } {
  const metrics = cve?.metrics;
  const v31 = metrics?.cvssMetricV31?.[0];
  const v30 = metrics?.cvssMetricV30?.[0];
  const v2  = metrics?.cvssMetricV2?.[0];
  const m = v31 ?? v30 ?? v2;
  if (!m) return { score: null, vector: null };
  const score = m.cvssData?.baseScore ?? m.cvssData?.score ?? null;
  const vector = m.cvssData?.vectorString ?? null;
  return { score: score !== undefined && score !== null ? parseFloat(String(score)) : null, vector };
}

function extractCwe(cve: any): string | null {
  return cve?.weaknesses?.[0]?.description?.[0]?.value ?? null;
}

function extractAffectedProducts(cve: any): string[] {
  const products = new Set<string>();
  for (const cfg of cve?.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        const parts = (m.criteria ?? "").split(":");
        if (parts.length >= 5) {
          const prod = `${parts[3]}:${parts[4]}`.replace(/\*/g, "").trim();
          if (prod && prod !== ":") products.add(prod);
        }
      }
    }
  }
  return [...products].slice(0, 20);
}

function extractAffectedVendors(cve: any): string[] {
  const vendors = new Set<string>();
  for (const cfg of cve?.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        const parts = (m.criteria ?? "").split(":");
        if (parts.length >= 5 && parts[3] && parts[3] !== "*") vendors.add(parts[3]);
      }
    }
  }
  return [...vendors].slice(0, 10);
}

function extractReferences(cve: any): string[] {
  return (cve?.references ?? []).map((r: any) => r.url as string).filter(Boolean).slice(0, 10);
}

// ── CVE → Actor/Campaign/Malware linking ──────────────────────────────────────

/**
 * After ingesting CVEs, cross-reference with existing ti_threat_actors,
 * ti_campaigns, ti_malware to populate linkedActors/Campaigns/Malware.
 *
 * Matching strategy (keyword-based):
 *  - Actor's targetIndustries overlap with CVE's affectedVendors
 *  - Campaign/malware descriptions mention the CVE ID
 *  - If a campaign has a known CVE reference in its description/name
 */
async function linkCvesToActors(cveIds: string[]): Promise<void> {
  if (cveIds.length === 0) return;

  // Load all actors/campaigns/malware for keyword matching (these are bounded in count)
  const [actors, campaigns, malware] = await Promise.all([
    db.select({ id: tiThreatActorsTable.id, name: tiThreatActorsTable.name, description: tiThreatActorsTable.description }).from(tiThreatActorsTable),
    db.select({ id: tiCampaignsTable.id, name: tiCampaignsTable.name, description: tiCampaignsTable.description }).from(tiCampaignsTable),
    db.select({ id: tiMalwareTable.id, name: tiMalwareTable.name, description: tiMalwareTable.description }).from(tiMalwareTable),
  ]);

  // Build a map of CVE-ID → {actors, campaigns, malware} based on keyword matches
  // Only process CVEs that exist in our DB already (from NVD ingest or CISA KEV)
  const existingRows = await db.select({ cveId: tiCveIntelTable.cveId, description: tiCveIntelTable.description })
    .from(tiCveIntelTable)
    .where(inArray(tiCveIntelTable.cveId, cveIds.slice(0, 2000)));

  const BATCH = 100;
  for (let i = 0; i < existingRows.length; i += BATCH) {
    const batch = existingRows.slice(i, i + BATCH);
    await Promise.all(batch.map(async row => {
      const cveId = row.cveId;
      const desc = (row.description ?? "").toLowerCase();

      // Find actors whose description or mitreId references this CVE
      const linkedActors: string[] = actors
        .filter(a => a.description?.toLowerCase().includes(cveId.toLowerCase()))
        .map(a => a.name)
        .slice(0, 5);

      // Find campaigns that mention the CVE
      const linkedCampaigns: string[] = campaigns
        .filter(c => c.description?.toLowerCase().includes(cveId.toLowerCase()))
        .map(c => c.name)
        .slice(0, 5);

      // Find malware with CVE references in description
      const linkedMalware: string[] = malware
        .filter(m => m.description?.toLowerCase().includes(cveId.toLowerCase()))
        .map(m => m.name)
        .slice(0, 5);

      if (linkedActors.length === 0 && linkedCampaigns.length === 0 && linkedMalware.length === 0) return;

      await db.update(tiCveIntelTable)
        .set({
          linkedActors:    sql`(SELECT array(SELECT DISTINCT UNNEST(ti_cve_intel.linked_actors || ${linkedActors}::text[])))`,
          linkedCampaigns: sql`(SELECT array(SELECT DISTINCT UNNEST(ti_cve_intel.linked_campaigns || ${linkedCampaigns}::text[])))`,
          linkedMalware:   sql`(SELECT array(SELECT DISTINCT UNNEST(ti_cve_intel.linked_malware || ${linkedMalware}::text[])))`,
          updatedAt:       sql`NOW()`,
        })
        .where(eq(tiCveIntelTable.cveId, cveId))
        .catch(() => {});
    }));
  }

  logger.info({ cves: existingRows.length }, "CVE → actor/campaign/malware links computed");
}

// ── Main ingest ───────────────────────────────────────────────────────────────

export interface CveIntelResult {
  added: number;
  updated: number;
  total: number;
}

export async function runCveIntelIngest(): Promise<CveIntelResult> {
  const nvdApiKey = await getPlatformSetting("nvd_api_key");
  const delayMs = nvdApiKey ? 650 : 6500;

  const pubEnd   = new Date();
  const pubStart = new Date(Date.now() - 30 * 86_400_000);
  const fmt = (d: Date) => d.toISOString().split(".")[0] + "+00:00";

  const headers: Record<string, string> = { "User-Agent": UA };
  if (nvdApiKey) headers.apiKey = nvdApiKey;

  let startIndex = 0;
  const allCves: any[] = [];
  let totalResults = 1;

  while (startIndex < totalResults && allCves.length < 10_000) {
    const url = `${NVD_BASE}?resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}&pubStartDate=${encodeURIComponent(fmt(pubStart))}&pubEndDate=${encodeURIComponent(fmt(pubEnd))}`;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 30_000);
      const res = await fetch(url, { headers, signal: ctrl.signal });
      clearTimeout(t);
      if (!res.ok) { logger.warn({ status: res.status, url }, "NVD API returned error"); break; }
      const data: any = await res.json();
      totalResults = data.totalResults ?? 0;
      allCves.push(...(data.vulnerabilities ?? []).map((v: any) => v.cve));
      startIndex += RESULTS_PER_PAGE;
      if (startIndex < totalResults) {
        await new Promise(r => setTimeout(r, delayMs));
      }
    } catch (err) {
      logger.warn({ err, startIndex }, "NVD CVE fetch error");
      break;
    }
  }

  if (allCves.length === 0) {
    logger.info("NVD CVE ingest: no CVEs fetched");
    return { added: 0, updated: 0, total: 0 };
  }

  const cveIds = allCves.map(c => c.id as string).filter(Boolean);
  const [epssMap, kevSet] = await Promise.all([
    fetchEpssScores(cveIds),
    fetchKevSet(),
  ]);

  let added = 0;
  const BATCH_SIZE = 500;

  for (let i = 0; i < allCves.length; i += BATCH_SIZE) {
    const batch = allCves.slice(i, i + BATCH_SIZE);
    const rows = batch.map(cve => {
      const cveId: string = cve.id ?? "";
      const { score: cvss, vector: cvssVector } = extractCvssV3(cve);
      const epssEntry = epssMap.get(cveId);
      const epss = epssEntry?.epss ?? null;
      const isKev = kevSet.has(cveId);
      const severity = severityFromCvss(cvss);
      const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value ?? null;
      const affectedProducts = extractAffectedProducts(cve);
      const affectedVendors = extractAffectedVendors(cve);
      const referenceUrls = extractReferences(cve);
      const cwe = extractCwe(cve);

      let exploitationStatus = "unknown";
      if (isKev)              exploitationStatus = "active";
      else if (epss && epss > 0.7)  exploitationStatus = "probable";
      else if (epss && epss > 0.3)  exploitationStatus = "possible";

      return {
        cveId,
        cvss: cvss ?? null,
        cvssVector: cvssVector ?? null,
        epss: epss ?? null,
        isKev,
        severity,
        description: desc,
        publishedDate: cve.published ? String(cve.published).slice(0, 10) : null,
        modifiedDate: cve.lastModified ? String(cve.lastModified).slice(0, 10) : null,
        affectedProducts,
        affectedVendors,
        exploitationStatus,
        exploitationEvidence: isKev ? "Listed in CISA Known Exploited Vulnerabilities catalog" : null,
        patchAvailable: false,
        pocPublic: (epss ?? 0) > 0.5,
        referenceUrls,
        cwe: cwe ?? null,
        rawData: { id: cveId, epss, isKev },
        updatedAt: new Date(),
      };
    }).filter(r => r.cveId);

    try {
      const result = await db.insert(tiCveIntelTable)
        .values(rows)
        .onConflictDoUpdate({
          target: tiCveIntelTable.cveId,
          set: {
            cvss:                 sql`excluded.cvss`,
            cvssVector:           sql`excluded.cvss_vector`,
            epss:                 sql`excluded.epss`,
            isKev:                sql`excluded.is_kev`,
            severity:             sql`excluded.severity`,
            description:          sql`excluded.description`,
            modifiedDate:         sql`excluded.modified_date`,
            affectedProducts:     sql`excluded.affected_products`,
            affectedVendors:      sql`excluded.affected_vendors`,
            exploitationStatus:   sql`excluded.exploitation_status`,
            exploitationEvidence: sql`excluded.exploitation_evidence`,
            pocPublic:            sql`excluded.poc_public`,
            referenceUrls:        sql`excluded.reference_urls`,
            updatedAt:            sql`NOW()`,
          },
        })
        .returning({ id: tiCveIntelTable.id });
      added += result.length;
    } catch (err) {
      logger.warn({ err, batchSize: batch.length }, "CVE Intel batch upsert error");
    }
  }

  // Cross-reference with existing ATT&CK actor/campaign/malware data
  await linkCvesToActors(cveIds.slice(0, 2000));

  logger.info({ added, total: allCves.length }, "CVE Intel ingest complete");
  return { added, updated: 0, total: allCves.length };
}
