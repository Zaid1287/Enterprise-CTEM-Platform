/**
 * C2 Server Intelligence Engine
 * Extracts Command & Control server indicators from ThreatFox and AbuseIPDB,
 * enriches with ip-api.com geolocation, and upserts into ti_c2_servers.
 */
import { sql } from "drizzle-orm";
import { db, tiC2ServersTable } from "@workspace/db";
import { logger } from "../logger";

const UA = "Sentinelware-CTEM-TI/1.0";
const TIMEOUT_MS = 20_000;

async function safeFetch(url: string, init: RequestInit = {}): Promise<Response | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    const res = await fetch(url, { ...init, signal: ctrl.signal, headers: { "User-Agent": UA, ...(init.headers as Record<string, string> ?? {}) } });
    clearTimeout(t);
    return res;
  } catch {
    return null;
  }
}

// ── Geolocation via ip-api.com (free) ────────────────────────────────────────

interface GeoInfo {
  country?: string;
  countryCode?: string;
  asn?: string;
  org?: string;
  isp?: string;
  city?: string;
  lat?: number;
  lng?: number;
}

async function geoLookup(ip: string): Promise<GeoInfo> {
  try {
    const res = await safeFetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,org,isp,as,lat,lon`);
    if (!res?.ok) return {};
    const d: any = await res.json();
    if (d.status !== "success") return {};
    return {
      country: d.country,
      countryCode: d.countryCode,
      asn: d.as,
      org: d.org,
      isp: d.isp,
      city: d.city,
      lat: d.lat,
      lng: d.lon,
    };
  } catch {
    return {};
  }
}

// Determine cloud provider from org/ISP string
function detectCloudProvider(org: string, isp: string): string | null {
  const s = `${org} ${isp}`.toLowerCase();
  if (s.includes("amazon") || s.includes("aws"))    return "AWS";
  if (s.includes("google"))                         return "GCP";
  if (s.includes("microsoft") || s.includes("azure")) return "Azure";
  if (s.includes("digitalocean"))                   return "DigitalOcean";
  if (s.includes("linode") || s.includes("akamai")) return "Linode";
  if (s.includes("vultr"))                          return "Vultr";
  if (s.includes("hetzner"))                        return "Hetzner";
  if (s.includes("cloudflare"))                     return "Cloudflare";
  return null;
}

// ── ThreatFox C2 extraction ───────────────────────────────────────────────────

interface ThreatFoxC2Row {
  ip: string;
  port?: number;
  domain?: string;
  malwareFamily: string;
  confidence: number;
  tags: string[];
  rawData: Record<string, unknown>;
}

async function fetchThreatFoxC2(): Promise<ThreatFoxC2Row[]> {
  const results: ThreatFoxC2Row[] = [];
  try {
    const res = await safeFetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query: "get_iocs", days: 7 }),
    });
    if (!res?.ok) return [];
    const data: any = await res.json();
    if (data.query_status !== "ok" || !Array.isArray(data.data)) return [];

    for (const item of data.data) {
      const iocType: string = item.ioc_type ?? "";
      // C2-specific IOC types from ThreatFox
      if (iocType !== "ip:port" && iocType !== "domain" && iocType !== "url") continue;

      const malwareName: string = (item.malware ?? "").toLowerCase();
      if (!malwareName || malwareName === "unknown") continue;

      let ip = "";
      let port: number | undefined;
      let domain: string | undefined;

      if (iocType === "ip:port") {
        const parts = (item.ioc ?? "").split(":");
        ip = parts[0] ?? "";
        port = parts[1] ? parseInt(parts[1], 10) : undefined;
        if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) continue;
      } else if (iocType === "domain") {
        domain = item.ioc as string;
        continue; // Skip domain-only C2s (no IP to look up)
      } else {
        continue;
      }

      results.push({
        ip,
        port,
        domain,
        malwareFamily: item.malware_printable ?? item.malware ?? "",
        confidence: Math.round((item.confidence_level ?? 50)),
        tags: (item.tags ?? []).filter(Boolean),
        rawData: {
          id: item.id,
          threat_type: item.threat_type,
          reporter: item.reporter,
          first_seen: item.first_seen,
          last_seen: item.last_seen,
        },
      });
    }
  } catch (err) {
    logger.warn({ err }, "ThreatFox C2 fetch error (non-fatal)");
  }
  return results;
}

// ── AbuseIPDB C2 extraction ───────────────────────────────────────────────────

async function fetchAbuseIpdbC2(apiKey: string): Promise<ThreatFoxC2Row[]> {
  const results: ThreatFoxC2Row[] = [];
  try {
    // Fetch top abusive IPs — many are C2 or botnet nodes
    const res = await safeFetch("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=500", {
      headers: { Key: apiKey, Accept: "application/json" },
    });
    if (!res?.ok) return [];
    const data: any = await res.json();
    if (!Array.isArray(data.data)) return [];

    for (const item of data.data) {
      const ip: string = item.ipAddress ?? "";
      if (!ip) continue;
      // Only include IPs that have been reported for botnet/C2 activity
      const categories: number[] = item.abuseCategories ?? [];
      // Category 18 = Exploited Host, 14 = DDoS Attack, 17 = IoT Targeted, 20 = Brute-Force
      if (!categories.includes(18) && !categories.includes(14) && !categories.includes(19)) continue;

      results.push({
        ip,
        malwareFamily: "botnet",
        confidence: Math.min(100, item.abuseConfidenceScore ?? 90),
        tags: ["abuseipdb", "botnet"],
        rawData: {
          totalReports: item.totalReports,
          lastReportedAt: item.lastReportedAt,
          categories,
          countryCode: item.countryCode,
        },
      });
    }
  } catch (err) {
    logger.warn({ err }, "AbuseIPDB C2 fetch error (non-fatal)");
  }
  return results;
}

// ── Main C2 ingest ────────────────────────────────────────────────────────────

export interface C2IngestResult {
  added: number;
  updated: number;
  sources: { threatfox: number; abuseipdb: number };
}

export async function runC2ServerIngest(abuseipdbKey?: string | null): Promise<C2IngestResult> {
  const [tfRows, abRows] = await Promise.all([
    fetchThreatFoxC2(),
    abuseipdbKey ? fetchAbuseIpdbC2(abuseipdbKey) : Promise.resolve([]),
  ]);

  const allRows = [...tfRows, ...abRows];
  if (allRows.length === 0) return { added: 0, updated: 0, sources: { threatfox: 0, abuseipdb: 0 } };

  // Geo-enrich — sample at most 50 IPs to avoid rate-limiting ip-api.com
  const uniqueIps = [...new Set(allRows.map(r => r.ip))].slice(0, 50);
  const geoMap = new Map<string, GeoInfo>();
  const GEO_CONCURRENCY = 5;
  for (let i = 0; i < uniqueIps.length; i += GEO_CONCURRENCY) {
    const batch = uniqueIps.slice(i, i + GEO_CONCURRENCY);
    const geos = await Promise.all(batch.map(ip => geoLookup(ip)));
    batch.forEach((ip, j) => geoMap.set(ip, geos[j] ?? {}));
    if (i + GEO_CONCURRENCY < uniqueIps.length) {
      await new Promise(r => setTimeout(r, 1200)); // ip-api.com free: 45/min
    }
  }

  let added = 0;

  const BATCH_SIZE = 100;
  for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
    const batch = allRows.slice(i, i + BATCH_SIZE);
    const insertRows = batch.map(row => {
      const geo = geoMap.get(row.ip) ?? {};
      return {
        ip: row.ip,
        port: row.port ?? null,
        domain: row.domain ?? null,
        country: geo.country ?? null,
        countryCode: geo.countryCode ?? null,
        asn: geo.asn ?? null,
        asnOrg: geo.org ?? null,
        isp: geo.isp ?? null,
        city: geo.city ?? null,
        lat: geo.lat ?? null,
        lng: geo.lng ?? null,
        malwareFamily: row.malwareFamily,
        tags: row.tags,
        confidence: row.confidence,
        isActive: true,
        cloudProvider: geo.org ? detectCloudProvider(geo.org, geo.isp ?? "") : null,
        source: row.rawData.reporter ? "threatfox" : "abuseipdb",
        rawData: row.rawData,
        discoveredAt: new Date(),
        lastSeenAt: new Date(),
      };
    });

    try {
      const result = await db.insert(tiC2ServersTable)
        .values(insertRows)
        .onConflictDoUpdate({
          target: [tiC2ServersTable.ip, tiC2ServersTable.source],
          set: {
            confidence: sql`GREATEST(ti_c2_servers.confidence, excluded.confidence)`,
            tags: sql`(SELECT array(SELECT DISTINCT UNNEST(ti_c2_servers.tags || excluded.tags)))`,
            lastSeenAt: sql`NOW()`,
            isActive: sql`true`,
            rawData: sql`excluded.raw_data`,
          },
        })
        .returning({ id: tiC2ServersTable.id });
      added += result.length;
    } catch (err) {
      logger.warn({ err, batchSize: batch.length }, "C2 batch upsert error");
    }
  }

  return {
    added,
    updated: 0,
    sources: { threatfox: tfRows.length, abuseipdb: abRows.length },
  };
}
