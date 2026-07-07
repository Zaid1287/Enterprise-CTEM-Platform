import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";

export interface ShodanFaviconMatch {
  ip: string;
  hostnames: string[];
  org: string | null;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  port: number | null;
  timestamp: string | null;
}

interface ShodanSearchResult {
  matches?: Array<{
    ip_str?: string;
    hostnames?: string[];
    org?: string;
    location?: {
      country_name?: string;
      country_code?: string;
      city?: string;
    };
    port?: number;
    timestamp?: string;
  }>;
  total?: number;
  error?: string;
}

export async function searchShodanByFaviconHash(
  mmh3: number,
  apiKey: string,
  maxResults = 20,
): Promise<ShodanFaviconMatch[]> {
  const results: ShodanFaviconMatch[] = [];
  if (!apiKey || !mmh3) return results;

  try {
    const query = encodeURIComponent(`http.favicon.hash:${mmh3}`);
    const url = `https://api.shodan.io/shodan/host/search?query=${query}&key=${encodeURIComponent(apiKey)}&facets=org,country`;

    const res = await orchestratedFetch(url, { signal: AbortSignal.timeout(15_000) }, { intensity: "passive" });

    if (!res.ok) {
      logger.warn({ status: res.status, mmh3 }, "Shodan favicon search returned non-OK status");
      return results;
    }

    const data = await res.json() as ShodanSearchResult;

    if (data.error) {
      logger.warn({ error: data.error, mmh3 }, "Shodan favicon search API error");
      return results;
    }

    const matches = data.matches ?? [];
    logger.info({ mmh3, total: data.total, returned: matches.length }, "Shodan favicon search results");

    for (const m of matches.slice(0, maxResults)) {
      results.push({
        ip:          m.ip_str ?? "unknown",
        hostnames:   m.hostnames ?? [],
        org:         m.org ?? null,
        country:     m.location?.country_name ?? null,
        countryCode: m.location?.country_code ?? null,
        city:        m.location?.city ?? null,
        port:        m.port ?? null,
        timestamp:   m.timestamp ?? null,
      });
    }
  } catch (err: unknown) {
    logger.warn({ err, mmh3 }, "Shodan favicon search failed");
  }

  return results;
}
