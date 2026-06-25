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

export async function vtUrlScan(url: string, apiKey: string): Promise<VtDomainResult | null> {
  if (!apiKey) return null;
  try {
    const encoded = Buffer.from(url).toString("base64url");
    const res = await fetch(
      `${VT_BASE}/urls/${encoded}`,
      {
        headers: { "x-apikey": apiKey },
        signal: AbortSignal.timeout(12_000),
      },
    );
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
      permalink: `https://www.virustotal.com/gui/url/${encoded}`,
      tags: attr.tags ?? [],
      categories: [],
      reputation: null,
    };
  } catch (e: any) {
    logger.warn(`VT URL scan failed: ${e.message}`);
    return null;
  }
}
