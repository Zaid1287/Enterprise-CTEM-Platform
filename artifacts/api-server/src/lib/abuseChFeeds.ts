import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";

export interface AbuseChPhishingResult {
  url: string;
  threat: string;
  source: "URLhaus" | "ThreatFox";
  addedAt: string | null;
  tags: string[];
  reporter: string | null;
}

export async function queryUrlhaus(domain: string): Promise<AbuseChPhishingResult[]> {
  const results: AbuseChPhishingResult[] = [];
  try {
    const res = await orchestratedFetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ host: domain }).toString(),
      signal: AbortSignal.timeout(12_000),
    }, { intensity: "passive" });

    if (!res.ok) return results;

    const data = await res.json() as {
      query_status: string;
      urls?: Array<{
        id: string;
        url: string;
        url_status: string;
        dateadded: string;
        threat: string;
        tags: string[] | null;
        reporter: string | null;
      }>;
    };

    if (data.query_status !== "is_host" || !data.urls) return results;

    for (const entry of data.urls) {
      if (entry.url_status === "offline") continue;
      results.push({
        url: entry.url,
        threat: entry.threat ?? "malware_download",
        source: "URLhaus",
        addedAt: entry.dateadded ?? null,
        tags: entry.tags ?? [],
        reporter: entry.reporter ?? null,
      });
    }
  } catch (err) {
    logger.warn({ err, domain }, "URLhaus query failed");
  }
  return results;
}

export async function queryThreatFox(domain: string): Promise<AbuseChPhishingResult[]> {
  const results: AbuseChPhishingResult[] = [];
  try {
    const res = await orchestratedFetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "search_ioc", search_term: domain }),
      signal: AbortSignal.timeout(12_000),
    }, { intensity: "passive" });

    if (!res.ok) return results;

    const data = await res.json() as {
      query_status: string;
      data?: Array<{
        id: string;
        ioc: string;
        ioc_type: string;
        threat_type: string;
        first_seen: string;
        last_seen: string | null;
        tags: string[] | null;
        reporter: string | null;
      }>;
    };

    if (data.query_status !== "ok" || !data.data) return results;

    for (const entry of data.data) {
      results.push({
        url: entry.ioc.startsWith("http") ? entry.ioc : `http://${entry.ioc}`,
        threat: entry.threat_type ?? "unknown",
        source: "ThreatFox",
        addedAt: entry.first_seen ?? null,
        tags: entry.tags ?? [],
        reporter: entry.reporter ?? null,
      });
    }
  } catch (err) {
    logger.warn({ err, domain }, "ThreatFox query failed");
  }
  return results;
}

export async function queryAbuseChFeeds(domain: string): Promise<AbuseChPhishingResult[]> {
  const [urlhausResults, threatfoxResults] = await Promise.all([
    queryUrlhaus(domain),
    queryThreatFox(domain),
  ]);
  const all = [...urlhausResults, ...threatfoxResults];
  const seen = new Set<string>();
  return all.filter(r => {
    if (seen.has(r.url)) return false;
    seen.add(r.url);
    return true;
  });
}
