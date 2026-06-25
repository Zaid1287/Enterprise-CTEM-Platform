import { logger } from "./logger";

export interface VtDomainResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  lastAnalysisDate: string | null;
  permalink: string;
  tags: string[];
  categories: string[];
  reputation: number | null;
}

const VT_BASE = "https://www.virustotal.com/api/v3";

export async function vtDomainLookup(domain: string, apiKey: string): Promise<VtDomainResult | null> {
  if (!apiKey) return null;
  try {
    const res = await fetch(
      `${VT_BASE}/domains/${encodeURIComponent(domain)}`,
      {
        headers: { "x-apikey": apiKey },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (res.status === 429) {
      logger.warn(`VT rate limit hit for ${domain}`);
      return null;
    }
    if (!res.ok) return null;
    const json = await res.json() as any;
    const attr = json?.data?.attributes ?? {};
    const stats = attr.last_analysis_stats ?? {};
    const dateEpoch: number | null = attr.last_analysis_date ?? null;

    return {
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      lastAnalysisDate: dateEpoch ? new Date(dateEpoch * 1000).toISOString() : null,
      permalink: `https://www.virustotal.com/gui/domain/${domain}`,
      tags: attr.tags ?? [],
      categories: Object.values(attr.categories ?? {}) as string[],
      reputation: attr.reputation ?? null,
    };
  } catch (e: any) {
    logger.warn(`VT lookup failed for ${domain}: ${e.message}`);
    return null;
  }
}

/**
 * Submit a URL to VirusTotal for analysis (POST /urls) then poll for the result
 * (GET /analyses/{id}). Falls back to GET-only for URLs already known to VT.
 */
export async function vtUrlScan(url: string, apiKey: string): Promise<VtDomainResult | null> {
  if (!apiKey) return null;
  try {
    // ── Step 1: Submit URL for scanning ──────────────────────────────────────
    const submitRes = await fetch(`${VT_BASE}/urls`, {
      method: "POST",
      headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
      signal: AbortSignal.timeout(15_000),
    });

    let analysisId: string | null = null;
    if (submitRes.ok) {
      const submitJson = await submitRes.json() as any;
      analysisId = submitJson?.data?.id ?? null;
    }

    // ── Step 2: Fetch analysis result (poll once after short delay) ───────────
    if (analysisId) {
      await new Promise(r => setTimeout(r, 8_000)); // wait 8s for VT to analyse
      const analysisRes = await fetch(`${VT_BASE}/analyses/${encodeURIComponent(analysisId)}`, {
        headers: { "x-apikey": apiKey },
        signal: AbortSignal.timeout(12_000),
      });
      if (analysisRes.ok) {
        const analysisJson = await analysisRes.json() as any;
        const attr = analysisJson?.data?.attributes ?? {};
        const stats = attr.stats ?? {};
        const dateEpoch: number | null = attr.date ?? null;
        const encoded = Buffer.from(url).toString("base64url");
        return {
          malicious: stats.malicious ?? 0,
          suspicious: stats.suspicious ?? 0,
          harmless: stats.harmless ?? 0,
          undetected: stats.undetected ?? 0,
          lastAnalysisDate: dateEpoch ? new Date(dateEpoch * 1000).toISOString() : null,
          permalink: `https://www.virustotal.com/gui/url/${encoded}`,
          tags: [],
          categories: [],
          reputation: null,
        };
      }
    }

    // ── Fallback: GET-only for already-known URLs ─────────────────────────────
    const encoded = Buffer.from(url).toString("base64url");
    const getRes = await fetch(`${VT_BASE}/urls/${encoded}`, {
      headers: { "x-apikey": apiKey },
      signal: AbortSignal.timeout(12_000),
    });
    if (!getRes.ok) return null;
    const json = await getRes.json() as any;
    const attr = json?.data?.attributes ?? {};
    const stats = attr.last_analysis_stats ?? {};
    const dateEpoch: number | null = attr.last_analysis_date ?? null;

    return {
      malicious: stats.malicious ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless: stats.harmless ?? 0,
      undetected: stats.undetected ?? 0,
      lastAnalysisDate: dateEpoch ? new Date(dateEpoch * 1000).toISOString() : null,
      permalink: `https://www.virustotal.com/gui/url/${encoded}`,
      tags: attr.tags ?? [],
      categories: [],
      reputation: null,
    };
  } catch (e: any) {
    logger.warn(`VT URL scan failed for ${url}: ${e.message}`);
    return null;
  }
}
