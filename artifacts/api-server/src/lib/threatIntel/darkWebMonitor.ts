/**
 * Dark Web Monitor
 * Scans all tenant assets against free intelligence sources:
 *   1. HIBP (Have I Been Pwned) — public breach list, no API key needed
 *   2. URLScan.io              — malicious URL/domain detection
 *   3. ThreatFox               — malware IOC database (free API)
 *   4. crt.sh lookalikes       — typosquatting / impersonation domains
 *
 * Results are written to ti_dark_web_mentions with breach_key deduplication.
 * Designed to be invoked manually (POST /threat-intel/dark-web/scan) or
 * by the beat scheduler for continuous monitoring.
 */

import { db, assetsTable, tenantsTable, tiDarkWebMentionsTable, tiFeedRunsTable } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { logger } from "../logger.js";
import { checkHibpBreaches, checkUrlScanThreats, detectLookalikeDomains } from "../tprmBreachIntel.js";

const FETCH_TIMEOUT_MS = 15_000;
const UA = "Sentinelware-CTEM-DWM/1.0";

// ── Domain utilities ──────────────────────────────────────────────────────────

function extractApex(domain: string): string {
  try {
    const h = domain.startsWith("http") ? new URL(domain).hostname : domain;
    const parts = h.replace(/^www\./, "").split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : h;
  } catch {
    return domain;
  }
}

function extractDomainFromAsset(asset: { type: string; value: string | null; ip_address?: string | null }): string | null {
  const val = (asset.value ?? "").trim();
  if (!val) return null;
  const t = (asset.type ?? "").toLowerCase();
  switch (t) {
    case "domain":
    case "subdomain":
      return extractApex(val);
    case "url":
      try { return extractApex(new URL(val).hostname); } catch { return null; }
    case "ssl_certificate":
      return extractApex(val.replace(/^\*\./, ""));
    case "host":
      // If it looks like a domain, extract apex; else fall through to IP
      if (/^[a-z][\w.-]*\.[a-z]{2,}$/i.test(val)) return extractApex(val);
      return null;
    case "ip":
      return null; // Handle via IP check instead
    default:
      // Try to extract domain if value looks like one
      if (/^([a-z0-9][\w-]*\.)+[a-z]{2,}$/i.test(val)) return extractApex(val);
      return null;
  }
}

function extractIpFromAsset(asset: { type: string; value: string | null; ip_address?: string | null }): string | null {
  const ip = (asset as any).ip_address;
  if (ip && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return ip;
  const val = (asset.value ?? "").trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) return val;
  return null;
}

// ── ThreatFox IOC check ───────────────────────────────────────────────────────

interface ThreatFoxResult {
  ioc_type: string;
  ioc: string;
  threat_type: string;
  malware_alias: string;
  confidence_level: number;
  first_seen: string;
  tags: string[];
}

async function checkThreatFox(term: string): Promise<ThreatFoxResult[]> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const resp = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      signal: ctrl.signal,
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify({ query: "search_ioc", search_term: term }),
    });
    clearTimeout(timer);
    if (!resp.ok) return [];
    const data = await resp.json() as { query_status: string; data?: ThreatFoxResult[] };
    if (data.query_status !== "ok" || !Array.isArray(data.data)) return [];
    return data.data.slice(0, 10);
  } catch {
    return [];
  }
}

// ── URLHaus host check ────────────────────────────────────────────────────────

interface UrlHausResult {
  query_status: string;
  host: string;
  urls?: Array<{ url: string; url_status: string; threat: string; tags: string[] | null; date_added: string }>;
}

async function checkUrlHaus(host: string): Promise<UrlHausResult | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const resp = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      signal: ctrl.signal,
      headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": UA },
      body: `host=${encodeURIComponent(host)}`,
    });
    clearTimeout(timer);
    if (!resp.ok) return null;
    const data = await resp.json() as UrlHausResult;
    return data.query_status === "is_host" ? data : null;
  } catch {
    return null;
  }
}

// ── Main upsert logic ─────────────────────────────────────────────────────────

async function upsertMention(mention: {
  tenantId: number | null;
  title: string;
  content: string;
  source: string;
  sourceUrl: string | null;
  severity: string;
  keywords: string[];
  isVerified: boolean;
  assetDomain: string;
  breachKey: string;
  detectedAt: Date;
  rawData?: any;
}): Promise<boolean> {
  const key = mention.breachKey;
  const tid = mention.tenantId ?? 0;

  // Check for existing mention via breach_key + tenant
  const existing = await db.select({ id: tiDarkWebMentionsTable.id })
    .from(tiDarkWebMentionsTable)
    .where(
      sql`COALESCE(${tiDarkWebMentionsTable.tenantId}, 0) = ${tid} AND ${tiDarkWebMentionsTable.breachKey} = ${key}`
    )
    .limit(1);

  if (existing.length > 0) {
    // Update in case new details arrived
    await db.update(tiDarkWebMentionsTable)
      .set({ title: mention.title, content: mention.content, severity: mention.severity, keywords: mention.keywords, isVerified: mention.isVerified })
      .where(eq(tiDarkWebMentionsTable.id, existing[0]!.id));
    return false; // not new
  }

  await db.insert(tiDarkWebMentionsTable).values({
    tenantId: mention.tenantId,
    mentionType: mention.source.startsWith("HIBP") ? "data_breach" : mention.source.startsWith("ThreatFox") ? "malware_ioc" : mention.source.startsWith("URLHaus") ? "malicious_host" : mention.source.startsWith("URLScan") ? "malicious_url" : mention.source.startsWith("crtsh") ? "lookalike_domain" : "general",
    title: mention.title,
    content: mention.content,
    source: mention.source,
    sourceUrl: mention.sourceUrl,
    severity: mention.severity,
    keywords: mention.keywords,
    actors: [],
    isVerified: mention.isVerified,
    assetDomain: mention.assetDomain,
    breachKey: mention.breachKey,
    rawData: mention.rawData ?? null,
    detectedAt: mention.detectedAt,
  });
  return true; // new mention
}

// ── Per-asset scanner ─────────────────────────────────────────────────────────

export interface AssetScanResult {
  assetId: number;
  tenantId: number | null;
  domain: string | null;
  ip: string | null;
  added: number;
  updated: number;
  sources: string[];
}

async function scanAsset(asset: {
  id: number;
  tenantId: number | null;
  type: string;
  value: string | null;
  ip_address: string | null;
}): Promise<AssetScanResult> {
  const domain = extractDomainFromAsset(asset);
  const ip = extractIpFromAsset(asset);
  let added = 0, updated = 0;
  const sources: string[] = [];

  // ── HIBP domain breach check ──────────────────────────────────────────────
  if (domain) {
    try {
      const breaches = await checkHibpBreaches(domain);
      for (const b of breaches) {
        const key = `hibp::${domain}::${b.breachName.toLowerCase().replace(/\s+/g, "_")}`;
        const severity = b.isSensitive ? "critical" : b.dataClasses.some(d => ["Passwords", "Password hints"].includes(d)) ? "high" : b.pwnCount > 1_000_000 ? "high" : "medium";
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: `Data Breach: ${b.breachName} (${domain})`,
          content: `${domain} appeared in the "${b.breachName}" data breach affecting ${b.pwnCount.toLocaleString()} accounts. Exposed data: ${b.dataClasses.slice(0, 6).join(", ")}. ${b.description ? b.description.slice(0, 200) : ""}`,
          source: "HIBP",
          sourceUrl: `https://haveibeenpwned.com/`,
          severity,
          keywords: b.dataClasses.slice(0, 10),
          isVerified: b.isVerified && !b.isFabricated,
          assetDomain: domain,
          breachKey: key,
          detectedAt: b.breachDate ? new Date(b.breachDate) : new Date(),
          rawData: { pwnCount: b.pwnCount, dataClasses: b.dataClasses, breachDate: b.breachDate },
        });
        if (isNew) { added++; if (!sources.includes("HIBP")) sources.push("HIBP"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] HIBP check failed for ${domain}: ${e.message}`);
    }

    // ── URLScan.io malicious scan check ────────────────────────────────────
    try {
      const urlscanHits = await checkUrlScanThreats(domain);
      for (const hit of urlscanHits) {
        const key = `urlscan::${domain}::${hit.breachName.toLowerCase().replace(/\s+/g, "_").slice(0, 60)}`;
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: hit.breachName,
          content: hit.description ?? `Malicious activity detected on ${domain} via URLScan.io analysis.`,
          source: "URLScan",
          sourceUrl: `https://urlscan.io/search/#domain:${encodeURIComponent(domain)}`,
          severity: "high",
          keywords: hit.dataClasses,
          isVerified: true,
          assetDomain: domain,
          breachKey: key,
          detectedAt: hit.breachDate ? new Date(hit.breachDate) : new Date(),
          rawData: null,
        });
        if (isNew) { added++; if (!sources.includes("URLScan")) sources.push("URLScan"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] URLScan check failed for ${domain}: ${e.message}`);
    }

    // ── ThreatFox IOC lookup ──────────────────────────────────────────────────
    try {
      const tfHits = await checkThreatFox(domain);
      for (const hit of tfHits) {
        const key = `threatfox::${hit.ioc}::${hit.threat_type}`;
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: `Malware IOC: ${hit.malware_alias || hit.threat_type} (${domain})`,
          content: `Domain "${domain}" flagged as a malware IOC (${hit.ioc_type}) on ThreatFox. Malware family: ${hit.malware_alias || "Unknown"}. Threat type: ${hit.threat_type}. Confidence: ${hit.confidence_level}%.`,
          source: "ThreatFox",
          sourceUrl: `https://threatfox.abuse.ch/browse/?search=ioc:${encodeURIComponent(domain)}`,
          severity: hit.confidence_level >= 75 ? "critical" : "high",
          keywords: [...(hit.tags ?? []), hit.threat_type, hit.malware_alias].filter(Boolean),
          isVerified: hit.confidence_level >= 75,
          assetDomain: domain,
          breachKey: key,
          detectedAt: hit.first_seen ? new Date(hit.first_seen) : new Date(),
          rawData: hit,
        });
        if (isNew) { added++; if (!sources.includes("ThreatFox")) sources.push("ThreatFox"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] ThreatFox check failed for ${domain}: ${e.message}`);
    }

    // ── URLHaus host check ────────────────────────────────────────────────────
    try {
      const uhResult = await checkUrlHaus(domain);
      if (uhResult && (uhResult.urls?.length ?? 0) > 0) {
        const key = `urlhaus::${domain}::host`;
        const threats = [...new Set((uhResult.urls ?? []).map(u => u.threat).filter(Boolean))];
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: `Malicious Host on URLHaus: ${domain}`,
          content: `Host "${domain}" is flagged on URLHaus malware tracking. ${uhResult.urls?.length} malicious URL(s) found. Threat types: ${threats.join(", ") || "malware"}.`,
          source: "URLHaus",
          sourceUrl: `https://urlhaus.abuse.ch/host/${encodeURIComponent(domain)}/`,
          severity: "critical",
          keywords: threats,
          isVerified: true,
          assetDomain: domain,
          breachKey: key,
          detectedAt: uhResult.urls?.[0]?.date_added ? new Date(uhResult.urls[0].date_added) : new Date(),
          rawData: { urlCount: uhResult.urls?.length, threats },
        });
        if (isNew) { added++; if (!sources.includes("URLHaus")) sources.push("URLHaus"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] URLHaus check failed for ${domain}: ${e.message}`);
    }

    // ── crt.sh lookalike domain detection ────────────────────────────────────
    try {
      const lookalikes = await detectLookalikeDomains(domain);
      for (const lk of lookalikes.slice(0, 5)) {
        const key = `crtsh::${domain}::${lk.domain}`;
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: `Lookalike Domain Detected: ${lk.domain}`,
          content: `A certificate for "${lk.domain}" was found in Certificate Transparency logs — ${lk.similarity}% similar to your domain "${domain}". Threat type: ${lk.threatType}. Issued by: ${lk.issuerCN ?? "unknown CA"}.`,
          source: "crt.sh",
          sourceUrl: `https://crt.sh/?q=%25${encodeURIComponent(domain.split(".")[0] ?? domain)}%25`,
          severity: lk.similarity >= 90 ? "high" : "medium",
          keywords: [lk.threatType, "lookalike", "typosquatting", "brand impersonation"],
          isVerified: true,
          assetDomain: domain,
          breachKey: key,
          detectedAt: lk.firstSeen ? new Date(lk.firstSeen) : new Date(),
          rawData: lk,
        });
        if (isNew) { added++; if (!sources.includes("crt.sh")) sources.push("crt.sh"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] crt.sh lookalike check failed for ${domain}: ${e.message}`);
    }
  }

  // ── ThreatFox IP check ────────────────────────────────────────────────────
  if (ip) {
    try {
      const tfHits = await checkThreatFox(ip);
      for (const hit of tfHits) {
        const key = `threatfox::${hit.ioc}::ip::${hit.threat_type}`;
        const isNew = await upsertMention({
          tenantId: asset.tenantId,
          title: `Malware IOC: IP ${ip} flagged as ${hit.malware_alias || hit.threat_type}`,
          content: `IP address "${ip}" is flagged as a malware IOC on ThreatFox. Malware: ${hit.malware_alias || "Unknown"}. Threat type: ${hit.threat_type}. Confidence: ${hit.confidence_level}%.`,
          source: "ThreatFox",
          sourceUrl: `https://threatfox.abuse.ch/browse/?search=ioc:${encodeURIComponent(ip)}`,
          severity: hit.confidence_level >= 75 ? "critical" : "high",
          keywords: [...(hit.tags ?? []), hit.threat_type, hit.malware_alias].filter(Boolean),
          isVerified: hit.confidence_level >= 75,
          assetDomain: domain ?? ip,
          breachKey: key,
          detectedAt: hit.first_seen ? new Date(hit.first_seen) : new Date(),
          rawData: hit,
        });
        if (isNew) { added++; if (!sources.includes("ThreatFox")) sources.push("ThreatFox"); }
        else updated++;
      }
    } catch (e: any) {
      logger.warn(`[dark-web] ThreatFox IP check failed for ${ip}: ${e.message}`);
    }
  }

  return { assetId: asset.id, tenantId: asset.tenantId, domain, ip, added, updated, sources };
}

// ── Public entry point ────────────────────────────────────────────────────────

export interface DarkWebScanOptions {
  tenantId?: number;          // scan only this tenant's assets
  assetId?: number;           // scan only this specific asset
  maxAssets?: number;         // cap total assets scanned (default 200)
}

export async function runDarkWebMonitor(opts: DarkWebScanOptions = {}): Promise<void> {
  const { tenantId, assetId, maxAssets = 200 } = opts;

  // Record the feed run
  const [feedRun] = await db.insert(tiFeedRunsTable).values({
    source: "dark_web_monitor",
    status: "running",
    recordsAdded: 0,
    recordsUpdated: 0,
  }).returning();

  let totalAdded = 0, totalUpdated = 0;

  try {
    // Load assets — global (all tenants) or scoped
    const query = db.select({
      id: assetsTable.id,
      tenantId: assetsTable.tenantId,
      type: assetsTable.type,
      value: assetsTable.value,
      ip_address: assetsTable.ipAddress,
    }).from(assetsTable);

    // Filter conditions
    const conditions: any[] = [];
    if (tenantId) conditions.push(eq(assetsTable.tenantId, tenantId));
    if (assetId)  conditions.push(eq(assetsTable.id, assetId));

    const rawAssets = await (conditions.length
      ? query.where(conditions.length === 1 ? conditions[0] : sql`${conditions[0]} AND ${conditions[1]}`)
      : query
    ).limit(maxAssets);

    // Filter to assets that have a domain or IP to search
    const assets = rawAssets.filter(a => {
      const d = extractDomainFromAsset({ type: a.type, value: a.value, ip_address: a.ip_address });
      const i = extractIpFromAsset({ type: a.type, value: a.value, ip_address: a.ip_address });
      return !!(d || i);
    });

    logger.info(`[dark-web] Scanning ${assets.length} assets across ${new Set(assets.map(a => a.tenantId)).size} tenants`);

    // Scan each asset sequentially (rate-limit-friendly)
    for (const asset of assets) {
      try {
        const result = await scanAsset(asset);
        totalAdded += result.added;
        totalUpdated += result.updated;
        if (result.added > 0 || result.updated > 0) {
          logger.info(`[dark-web] ${result.domain ?? result.ip}: +${result.added} new, ~${result.updated} updated (${result.sources.join(", ")})`);
        }
        // Small delay between assets to be respectful to APIs
        await new Promise(r => setTimeout(r, 300));
      } catch (e: any) {
        logger.warn(`[dark-web] Asset ${asset.id} scan failed: ${e.message}`);
      }
    }

    await db.update(tiFeedRunsTable).set({
      status: "completed",
      recordsAdded: totalAdded,
      recordsUpdated: totalUpdated,
      completedAt: new Date(),
    }).where(eq(tiFeedRunsTable.id, feedRun.id));

    logger.info(`[dark-web] Scan complete: +${totalAdded} new, ~${totalUpdated} updated`);
  } catch (err: any) {
    await db.update(tiFeedRunsTable).set({
      status: "failed",
      error: err.message,
      completedAt: new Date(),
    }).where(eq(tiFeedRunsTable.id, feedRun.id));
    logger.warn(`[dark-web] Scan failed: ${err.message}`);
    throw err;
  }
}

/** Returns the latest dark web scan run */
export async function getLastDarkWebScanRun(): Promise<any | null> {
  const [row] = await db.select().from(tiFeedRunsTable)
    .where(eq(tiFeedRunsTable.source, "dark_web_monitor"))
    .orderBy(sql`started_at DESC`)
    .limit(1);
  return row ?? null;
}
