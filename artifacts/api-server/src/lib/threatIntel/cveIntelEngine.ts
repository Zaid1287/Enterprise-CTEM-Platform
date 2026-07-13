/**
 * CVE Intelligence Engine
 * Fetches recent CVEs from NVD API v2, enriches with EPSS scores and
 * CISA KEV status (reusing existing epssKev.ts), and upserts into ti_cve_intel.
 */
import { eq, sql } from "drizzle-orm";
import { db, tiCveIntelTable, platformSettingsTable } from "@workspace/db";
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
  // Prefer CVSSv3.1 then 3.0 then 2.0
  const v31 = metrics?.cvssMetricV31?.[0];
  const v30 = metrics?.cvssMetricV30?.[0];
  const v2 = metrics?.cvssMetricV2?.[0];
  const m = v31 ?? v30 ?? v2;
  if (!m) return { score: null, vector: null };
  const score = m.cvssData?.baseScore ?? m.cvssData?.score ?? null;
  const vector = m.cvssData?.vectorString ?? null;
  return { score: score !== undefined && score !== null ? parseFloat(String(score)) : null, vector };
}

function extractCwe(cve: any): string | null {
  const weakness = cve?.weaknesses?.[0]?.description?.[0]?.value;
  return weakness ?? null;
}

function extractAffectedProducts(cve: any): string[] {
  const products = new Set<string>();
  const configs = cve?.configurations ?? [];
  for (const cfg of configs) {
    for (const node of cfg.nodes ?? []) {
      for (const cpeMatch of node.cpeMatch ?? []) {
        const uri: string = cpeMatch.criteria ?? "";
        // Parse CPE URI: cpe:2.3:a:vendor:product:version...
        const parts = uri.split(":");
        if (parts.length >= 5) {
          const product = `${parts[3]}:${parts[4]}`;
          if (product && product !== "*:*") products.add(product.replace(/\*/g, "").trim());
        }
      }
    }
  }
  return [...products].slice(0, 20);
}

function extractAffectedVendors(cve: any): string[] {
  const vendors = new Set<string>();
  const configs = cve?.configurations ?? [];
  for (const cfg of configs) {
    for (const node of cfg.nodes ?? []) {
      for (const cpeMatch of node.cpeMatch ?? []) {
        const uri: string = cpeMatch.criteria ?? "";
        const parts = uri.split(":");
        if (parts.length >= 5 && parts[3] && parts[3] !== "*") {
          vendors.add(parts[3]);
        }
      }
    }
  }
  return [...vendors].slice(0, 10);
}

function extractReferences(cve: any): string[] {
  return (cve?.references ?? []).map((r: any) => r.url as string).filter(Boolean).slice(0, 10);
}

export interface CveIntelResult {
  added: number;
  updated: number;
  total: number;
}

export async function runCveIntelIngest(): Promise<CveIntelResult> {
  const nvdApiKey = await getPlatformSetting("nvd_api_key");
  const delayMs = nvdApiKey ? 650 : 6500;

  // Fetch CVEs published or modified in the last 30 days
  const pubEnd = new Date();
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
      if (!res.ok) {
        logger.warn({ status: res.status, url }, "NVD API returned error");
        break;
      }
      const data: any = await res.json();
      totalResults = data.totalResults ?? 0;
      const vulnerabilities: any[] = data.vulnerabilities ?? [];
      allCves.push(...vulnerabilities.map((v: any) => v.cve));
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

  // Extract CVE IDs for EPSS + KEV enrichment
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
      const publishedDate = cve.published ? String(cve.published).slice(0, 10) : null;
      const modifiedDate = cve.lastModified ? String(cve.lastModified).slice(0, 10) : null;
      const affectedProducts = extractAffectedProducts(cve);
      const affectedVendors = extractAffectedVendors(cve);
      const referenceUrls = extractReferences(cve);
      const cwe = extractCwe(cve);

      // Mark exploitation status based on EPSS + KEV
      let exploitationStatus = "unknown";
      if (isKev) exploitationStatus = "active";
      else if (epss && epss > 0.7) exploitationStatus = "probable";
      else if (epss && epss > 0.3) exploitationStatus = "possible";

      return {
        cveId,
        cvss: cvss ?? null,
        cvssVector: cvssVector ?? null,
        epss: epss ?? null,
        isKev,
        severity,
        description: desc,
        publishedDate,
        modifiedDate,
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
            cvss:                sql`excluded.cvss`,
            cvssVector:          sql`excluded.cvss_vector`,
            epss:                sql`excluded.epss`,
            isKev:               sql`excluded.is_kev`,
            severity:            sql`excluded.severity`,
            description:         sql`excluded.description`,
            modifiedDate:        sql`excluded.modified_date`,
            affectedProducts:    sql`excluded.affected_products`,
            affectedVendors:     sql`excluded.affected_vendors`,
            exploitationStatus:  sql`excluded.exploitation_status`,
            exploitationEvidence: sql`excluded.exploitation_evidence`,
            pocPublic:           sql`excluded.poc_public`,
            referenceUrls:       sql`excluded.reference_urls`,
            updatedAt:           sql`NOW()`,
          },
        })
        .returning({ id: tiCveIntelTable.id });
      added += result.length;
    } catch (err) {
      logger.warn({ err, batchSize: batch.length }, "CVE Intel batch upsert error");
    }
  }

  logger.info({ added, total: allCves.length }, "CVE Intel ingest complete");
  return { added, updated: 0, total: allCves.length };
}
