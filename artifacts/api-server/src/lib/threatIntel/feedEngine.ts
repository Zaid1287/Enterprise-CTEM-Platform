/**
 * Threat Intelligence Feed Engine
 * Orchestrates all TI feed fetchers, records runs in ti_feed_runs, and
 * exports runThreatIntelFeedRefresh() for both scheduled and manual invocation.
 *
 * Feed data is GLOBAL (not tenant-scoped). The same MITRE ATT&CK actors,
 * IOCs, CVEs etc. are shared across all tenants. Only ti_asset_correlations
 * and ti_reports are tenant-scoped. The beat scheduler skips the refresh
 * when no tenant has the TI module enabled.
 *
 * Sources:
 *  - AlienVault OTX     (free pulses API; optional key for higher limits)
 *  - ThreatFox          (free, no key)
 *  - MalwareBazaar      (free, no key)
 *  - URLHaus            (free, no key)
 *  - PhishTank          (free public JSON feed)
 *  - CISA KEV           (free, no key — CVE-type IOCs)
 *  - MITRE ATT&CK       (free, no key — actors/campaigns/malware/TTPs)
 *  - NVD CVE            (free; optional nvd_api_key in platform settings)
 *  - AbuseIPDB          (requires ti_abuseipdb_key)
 *  - GreyNoise          (requires ti_greynoise_key)
 */
import { eq } from "drizzle-orm";
import { db, platformSettingsTable, tiFeedRunsTable } from "@workspace/db";
import { logger } from "../logger";
import { upsertIocs, calculateThreatScore, type NormalizedIoc } from "./iocEngine";
import { runC2ServerIngest } from "./c2Engine";
import { runMitreAttackIngest } from "./threatActorEngine";
import { runCveIntelIngest } from "./cveIntelEngine";

const UA = "Sentinelware-CTEM-TI/1.0";
const FETCH_TIMEOUT = 30_000;

// ── Per-source run dedup ──────────────────────────────────────────────────────
// Prevents re-running a source more than once per 5-minute window even if
// runThreatIntelFeedRefresh() is called multiple times (e.g. once per TI-enabled
// tenant by the beat scheduler). Global data feeds should not be duplicated.
const SOURCE_DEDUP_WINDOW_MS = 5 * 60 * 1_000; // 5 minutes
const _sourceLastRunMs = new Map<string, number>();

function isSourceDue(source: string): boolean {
  const last = _sourceLastRunMs.get(source) ?? 0;
  return Date.now() - last >= SOURCE_DEDUP_WINDOW_MS;
}

function markSourceRan(source: string): void {
  _sourceLastRunMs.set(source, Date.now());
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

async function safeFetch(url: string, init: RequestInit = {}): Promise<Response | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT);
    const res = await fetch(url, {
      ...init,
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...(init.headers as Record<string, string> ?? {}) },
    });
    clearTimeout(t);
    return res;
  } catch {
    return null;
  }
}

// ── Feed run tracking ─────────────────────────────────────────────────────────

async function startFeedRun(source: string): Promise<{ id: number; startMs: number }> {
  const [row] = await db.insert(tiFeedRunsTable)
    .values({ source, status: "running", startedAt: new Date() })
    .returning({ id: tiFeedRunsTable.id });
  return { id: row.id, startMs: Date.now() };
}

async function completeFeedRun(id: number, added: number, updated: number, startMs: number): Promise<void> {
  const durationMs = Date.now() - startMs;
  await db.update(tiFeedRunsTable)
    .set({ status: "completed", recordsAdded: added, recordsUpdated: updated, durationMs, completedAt: new Date() })
    .where(eq(tiFeedRunsTable.id, id));
}

async function failFeedRun(id: number, error: string, startMs: number): Promise<void> {
  const durationMs = Date.now() - startMs;
  await db.update(tiFeedRunsTable)
    .set({ status: "failed", error: error.slice(0, 500), durationMs, completedAt: new Date() })
    .where(eq(tiFeedRunsTable.id, id));
}

async function withFeedRun<T extends { added: number; updated: number }>(
  source: string,
  fn: () => Promise<T>,
): Promise<T | null> {
  // Per-source dedup: skip if this source ran within the last 5 minutes.
  // Ensures that N-tenant scheduler calls don't re-execute the same global source N times.
  if (!isSourceDue(source)) {
    logger.debug({ source }, "TI feed source skipped — ran recently (dedup window active)");
    return null;
  }
  // Mark ran *before* executing so concurrent calls from other tenants skip it
  markSourceRan(source);

  const { id: runId, startMs } = await startFeedRun(source);
  try {
    const result = await fn();
    await completeFeedRun(runId, result.added, result.updated, startMs);
    logger.info({ source, added: result.added, updated: result.updated, durationMs: Date.now() - startMs }, "TI feed run completed");
    return result;
  } catch (err: any) {
    const msg = err?.message ?? String(err);
    await failFeedRun(runId, msg, startMs);
    logger.warn({ source, err: msg, durationMs: Date.now() - startMs }, "TI feed run failed");
    // Reset dedup so a failed source can be retried after the window
    _sourceLastRunMs.delete(source);
    return null;
  }
}

// ── AlienVault OTX ────────────────────────────────────────────────────────────

function mapOtxType(otxType: string): string | null {
  const map: Record<string, string> = {
    "IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain",
    "URL": "url", "URI": "url", "email": "email",
    "FileHash-MD5": "hash_md5", "FileHash-SHA1": "hash_sha1",
    "FileHash-SHA256": "hash_sha256", "CIDR": "cidr",
  };
  return map[otxType] ?? null;
}

async function fetchAlienVaultOtx(apiKey?: string | null): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const headers: Record<string, string> = {};
  if (apiKey) headers["X-OTX-API-KEY"] = apiKey;

  const url = apiKey
    ? "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50"
    : "https://otx.alienvault.com/api/v1/pulses/activity?limit=20";

  const res = await safeFetch(url, { headers });
  if (!res?.ok) return [];
  const data: any = await res.json().catch(() => null);
  if (!data?.results) return [];

  for (const pulse of data.results.slice(0, 50)) {
    const pulseName: string = pulse.name ?? "";
    const tags: string[] = (pulse.tags ?? []).slice(0, 10);
    const malwareFamilies: string[] = (pulse.malware_families ?? []).map((m: any) => String(m.display_name ?? m)).filter(Boolean);
    const adversary: string = pulse.adversary ?? "";
    const pulseModified = pulse.modified ? new Date(pulse.modified) : undefined;

    for (const indicator of (pulse.indicators ?? []).slice(0, 200)) {
      const type = mapOtxType(indicator.type as string);
      if (!type) continue;
      const value = String(indicator.indicator ?? "").toLowerCase().trim();
      if (!value) continue;
      const indicatorCreated = indicator.created ? new Date(indicator.created) : pulseModified;

      iocs.push({
        type,
        value,
        source: "alienvault_otx",
        sourceUrl: `https://otx.alienvault.com/pulse/${pulse.id}`,
        tlp: "white",
        confidence: 70,
        severity: "medium",
        tags: [...new Set([...tags, "alienvault"])],
        malwareFamilies,
        threatActors: adversary ? [adversary] : [],
        description: pulseName,
        firstSeen: indicatorCreated,
        rawData: { pulseId: pulse.id, pulseName, modified: pulse.modified },
      });
    }
  }
  return iocs;
}

// ── ThreatFox ────────────────────────────────────────────────────────────────

function mapThreatFoxType(t: string): string | null {
  if (t === "ip:port")    return "ip";
  if (t === "domain")     return "domain";
  if (t === "url")        return "url";
  if (t === "md5_hash")   return "hash_md5";
  if (t === "sha256_hash") return "hash_sha256";
  return null;
}

function malwareSeverity(malware: string): string {
  const m = malware.toLowerCase();
  const critical = ["ransomware", "ryuk", "conti", "lockbit", "blackcat", "revil", "darkside"];
  const high = ["rat", "backdoor", "rootkit", "banker", "stealer", "cobalt strike", "metasploit"];
  if (critical.some(c => m.includes(c))) return "critical";
  if (high.some(h => m.includes(h))) return "high";
  return "medium";
}

async function fetchThreatFox(): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query: "get_iocs", days: 1 }),
  });
  if (!res?.ok) return [];
  const data: any = await res.json().catch(() => null);
  if (data?.query_status !== "ok" || !Array.isArray(data.data)) return [];

  for (const item of data.data.slice(0, 1000)) {
    const type = mapThreatFoxType(item.ioc_type as string);
    if (!type) continue;
    let value = String(item.ioc ?? "").toLowerCase().trim();
    if (item.ioc_type === "ip:port") value = value.split(":")[0] ?? value;
    if (!value) continue;

    const severity = malwareSeverity(item.malware ?? "");
    const firstSeen = item.first_seen ? new Date(item.first_seen) : undefined;

    iocs.push({
      type,
      value,
      source: "threatfox",
      sourceUrl: `https://threatfox.abuse.ch/ioc/${item.id}`,
      tlp: "white",
      confidence: Math.min(100, item.confidence_level ?? 70),
      severity,
      tags: ["threatfox", ...(item.tags ?? []).filter(Boolean)],
      malwareFamilies: item.malware ? [item.malware_printable ?? item.malware] : [],
      description: item.malware_printable ?? item.malware ?? "",
      firstSeen,
      rawData: {
        id: item.id,
        threat_type: item.threat_type,
        ioc_type: item.ioc_type,
        reporter: item.reporter,
        first_seen: item.first_seen,
        last_seen: item.last_seen,
      },
    });
  }
  return iocs;
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────

async function fetchMalwareBazaar(): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://mb-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "query=get_recent&selector=100",
  });
  if (!res?.ok) return [];
  const data: any = await res.json().catch(() => null);
  if (data?.query_status !== "ok" || !Array.isArray(data.data)) return [];

  for (const sample of data.data.slice(0, 100)) {
    const sha256: string = sample.sha256_hash ?? "";
    if (!sha256) continue;
    const malwareFamily: string = sample.signature ?? sample.tags?.[0] ?? "unknown";
    const severity = malwareSeverity(malwareFamily);
    const firstSeen = sample.first_seen ? new Date(sample.first_seen) : undefined;

    iocs.push({
      type: "hash_sha256",
      value: sha256.toLowerCase(),
      source: "malwarebazaar",
      sourceUrl: `https://bazaar.abuse.ch/sample/${sha256}`,
      tlp: "white",
      confidence: 85,
      severity,
      tags: ["malwarebazaar", ...(sample.tags ?? []).filter(Boolean).slice(0, 5)],
      malwareFamilies: malwareFamily !== "unknown" ? [malwareFamily] : [],
      description: `${sample.file_type ?? "unknown"} malware sample`,
      firstSeen,
      rawData: {
        md5: sample.md5_hash,
        sha1: sample.sha1_hash,
        file_type: sample.file_type,
        file_size: sample.file_size,
        reporter: sample.reporter,
        first_seen: sample.first_seen,
      },
    });

    if (sample.md5_hash) {
      iocs.push({
        type: "hash_md5",
        value: (sample.md5_hash as string).toLowerCase(),
        source: "malwarebazaar",
        tlp: "white",
        confidence: 80,
        severity,
        tags: ["malwarebazaar"],
        malwareFamilies: malwareFamily !== "unknown" ? [malwareFamily] : [],
        description: `${sample.file_type ?? "unknown"} malware sample`,
        firstSeen,
      });
    }
  }
  return iocs;
}

// ── URLHaus ───────────────────────────────────────────────────────────────────

async function fetchURLHaus(): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://urlhaus.abuse.ch/downloads/csv_recent/");
  if (!res?.ok) return [];
  const text = await res.text().catch(() => "");
  const lines = text.split("\n").filter(l => !l.startsWith("#") && l.trim());

  for (const line of lines.slice(0, 500)) {
    const parts = line.split(",");
    if (parts.length < 5) continue;
    const url = (parts[2] ?? "").replace(/^"|"$/g, "").trim();
    const urlStatus = (parts[3] ?? "").replace(/^"|"$/g, "").toLowerCase();
    const tags = (parts[5] ?? "").replace(/^"|"$/g, "").split(" ").filter(Boolean);
    const malwareFamily = (parts[4] ?? "").replace(/^"|"$/g, "");
    const addedAt = (parts[1] ?? "").replace(/^"|"$/g, "").trim();

    if (!url || !url.startsWith("http")) continue;
    if (urlStatus !== "online") continue;

    let domain = "";
    try { domain = new URL(url).hostname; } catch { continue; }

    const severity = malwareSeverity(malwareFamily || tags.join(" "));
    const firstSeen = addedAt ? new Date(addedAt) : undefined;

    iocs.push({
      type: "url",
      value: url.toLowerCase(),
      source: "urlhaus",
      sourceUrl: `https://urlhaus.abuse.ch/url/${parts[0] ?? ""}`,
      tlp: "white",
      confidence: 80,
      severity,
      tags: ["urlhaus", ...tags.slice(0, 5)],
      malwareFamilies: malwareFamily ? [malwareFamily] : [],
      description: `Active malware distribution URL (${malwareFamily || "unknown"})`,
      firstSeen,
      rawData: { domain, urlStatus, addedAt },
    });
  }
  return iocs;
}

// ── PhishTank ─────────────────────────────────────────────────────────────────

async function fetchPhishTank(): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://data.phishtank.com/data/online-valid.json", {
    headers: { "Accept": "application/json" },
  });
  if (!res?.ok) return [];
  const text = await res.text().catch(() => "");
  if (!text || text.length < 10) return [];

  let entries: any[];
  try { entries = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(entries)) return [];

  for (const entry of entries.slice(0, 300)) {
    const url: string = entry.url ?? "";
    if (!url || !url.startsWith("http")) continue;
    let domain = "";
    try { domain = new URL(url).hostname; } catch { continue; }
    const firstSeen = entry.submission_time ? new Date(entry.submission_time) : undefined;

    iocs.push({
      type: "url",
      value: url.toLowerCase().slice(0, 2048),
      source: "phishtank",
      sourceUrl: entry.phish_detail_url,
      tlp: "white",
      confidence: entry.verified === "yes" ? 95 : 75,
      severity: "high",
      tags: ["phishtank", "phishing"],
      description: `Verified phishing URL targeting ${entry.target ?? "unknown"} (PhishTank #${entry.phish_id})`,
      firstSeen,
      rawData: {
        phish_id: entry.phish_id,
        target: entry.target,
        verified: entry.verified,
        verified_at: entry.verification_time,
        online: entry.online,
        domain,
      },
    });
  }
  return iocs;
}

// ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async function fetchAbuseIPDB(apiKey: string): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://api.abuseipdb.com/api/v2/blacklist?confidenceMinimum=90&limit=500", {
    headers: { Key: apiKey, Accept: "application/json" },
  });
  if (!res?.ok) return [];
  const data: any = await res.json().catch(() => null);
  if (!Array.isArray(data?.data)) return [];

  for (const item of data.data.slice(0, 500)) {
    const ip: string = item.ipAddress ?? "";
    if (!ip) continue;
    const lastReported = item.lastReportedAt ? new Date(item.lastReportedAt) : undefined;
    iocs.push({
      type: "ip",
      value: ip,
      source: "abuseipdb",
      sourceUrl: `https://www.abuseipdb.com/check/${ip}`,
      tlp: "white",
      confidence: Math.min(100, item.abuseConfidenceScore ?? 90),
      severity: "high",
      country: item.countryCode ?? null,
      tags: ["abuseipdb", "malicious-ip"],
      description: `IP with ${item.totalReports} abuse reports (AbuseIPDB confidence: ${item.abuseConfidenceScore}%)`,
      firstSeen: lastReported,
      rawData: {
        totalReports: item.totalReports,
        lastReportedAt: item.lastReportedAt,
        countryCode: item.countryCode,
        abuseConfidenceScore: item.abuseConfidenceScore,
      },
    });
  }
  return iocs;
}

// ── GreyNoise ─────────────────────────────────────────────────────────────────

async function fetchGreyNoise(apiKey: string): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  const res = await safeFetch("https://api.greynoise.io/v2/experimental/gnql?query=classification%3Amalicious&size=500&scroll=false", {
    headers: { key: apiKey, Accept: "application/json" },
  });
  if (!res?.ok) return [];
  const data: any = await res.json().catch(() => null);
  if (!Array.isArray(data?.data)) return [];

  for (const item of data.data.slice(0, 500)) {
    const ip: string = item.ip ?? "";
    if (!ip) continue;
    const lastSeen = item.last_seen ? new Date(item.last_seen) : undefined;
    iocs.push({
      type: "ip",
      value: ip,
      source: "greynoise",
      sourceUrl: `https://viz.greynoise.io/ip/${ip}`,
      tlp: "white",
      confidence: 80,
      severity: "medium",
      country: item.metadata?.country ?? null,
      asn: item.metadata?.asn ?? null,
      tags: ["greynoise", ...(item.tags ?? []).slice(0, 5)],
      description: item.raw_data?.scan?.[0]?.flag ?? item.actor ?? "GreyNoise malicious scanner",
      firstSeen: lastSeen,
      rawData: {
        noise: item.noise,
        riot: item.riot,
        classification: item.classification,
        name: item.name,
        seen: item.last_seen,
        actor: item.actor,
      },
    });
  }
  return iocs;
}

// ── CISA KEV as IOCs ──────────────────────────────────────────────────────────

async function fetchCisaKevAsIocs(): Promise<NormalizedIoc[]> {
  const iocs: NormalizedIoc[] = [];
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20_000);
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", {
      signal: ctrl.signal, headers: { "User-Agent": UA },
    });
    clearTimeout(t);
    if (!res.ok) return [];
    const data: any = await res.json().catch(() => null);
    for (const vuln of (data?.vulnerabilities ?? []).slice(0, 500)) {
      const cveId: string = vuln.cveID ?? "";
      if (!cveId) continue;
      const firstSeen = vuln.dateAdded ? new Date(vuln.dateAdded) : undefined;
      iocs.push({
        type: "cve",
        value: cveId.toUpperCase(),
        source: "cisa_kev",
        sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        tlp: "white",
        confidence: 100,
        severity: "critical",
        exploitationStatus: "active",
        tags: ["cisa", "kev", "actively-exploited"],
        malwareFamilies: vuln.knownRansomwareCampaignUse === "Known" ? ["ransomware"] : [],
        description: `${vuln.vulnerabilityName} — ${vuln.shortDescription}`,
        firstSeen,
        rawData: {
          vendorProject: vuln.vendorProject,
          product: vuln.product,
          dateAdded: vuln.dateAdded,
          dueDate: vuln.dueDate,
          requiredAction: vuln.requiredAction,
          ransomware: vuln.knownRansomwareCampaignUse,
        },
      });
    }
  } catch (err) {
    logger.warn({ err }, "CISA KEV IOC fetch failed (non-fatal)");
  }
  return iocs;
}

// ── Main coordinator ──────────────────────────────────────────────────────────

const KNOWN_SOURCES = [
  "alienvault_otx", "threatfox", "malwarebazaar", "urlhaus", "phishtank",
  "cisa_kev", "abuseipdb", "greynoise", "mitre_attack", "nvd_cve",
] as const;

type KnownSource = typeof KNOWN_SOURCES[number];

async function runSingleFeed(source: KnownSource, keys: Record<string, string | null>): Promise<{ added: number; updated: number }> {
  switch (source) {
    case "alienvault_otx": {
      const iocs = await fetchAlienVaultOtx(keys.ti_alienvault_key);
      const result = await upsertIocs(iocs);
      return { added: result.added, updated: result.updated };
    }
    case "threatfox": {
      const result = await upsertIocs(await fetchThreatFox());
      return { added: result.added, updated: result.updated };
    }
    case "malwarebazaar": {
      const result = await upsertIocs(await fetchMalwareBazaar());
      return { added: result.added, updated: result.updated };
    }
    case "urlhaus": {
      const result = await upsertIocs(await fetchURLHaus());
      return { added: result.added, updated: result.updated };
    }
    case "phishtank": {
      const result = await upsertIocs(await fetchPhishTank());
      return { added: result.added, updated: result.updated };
    }
    case "cisa_kev": {
      const result = await upsertIocs(await fetchCisaKevAsIocs());
      return { added: result.added, updated: result.updated };
    }
    case "abuseipdb": {
      if (!keys.ti_abuseipdb_key) {
        logger.info("AbuseIPDB skipped (ti_abuseipdb_key not configured)");
        return { added: 0, updated: 0 };
      }
      const result = await upsertIocs(await fetchAbuseIPDB(keys.ti_abuseipdb_key));
      return { added: result.added, updated: result.updated };
    }
    case "greynoise": {
      if (!keys.ti_greynoise_key) {
        logger.info("GreyNoise skipped (ti_greynoise_key not configured)");
        return { added: 0, updated: 0 };
      }
      const result = await upsertIocs(await fetchGreyNoise(keys.ti_greynoise_key));
      return { added: result.added, updated: result.updated };
    }
    case "mitre_attack": {
      const mitreResult = await runMitreAttackIngest();
      // Also run C2 ingest alongside MITRE (ThreatFox C2 + AbuseIPDB C2)
      await runC2ServerIngest(keys.ti_abuseipdb_key);
      return {
        added: mitreResult.actors + mitreResult.campaigns + mitreResult.malware + mitreResult.ttps,
        updated: 0,
      };
    }
    case "nvd_cve": {
      const cveResult = await runCveIntelIngest();
      return { added: cveResult.added, updated: cveResult.updated };
    }
    default:
      return { added: 0, updated: 0 };
  }
}

/**
 * Main entry point for TI feed refresh.
 * @param tenantId - The tenant context triggering this refresh (for audit/logging).
 *                   Feed data is stored in global tables shared across all tenants.
 *                   The scheduler iterates TI-enabled tenants and calls this per tenant,
 *                   but a global dedup in beatScheduler prevents redundant concurrent runs.
 * @param specificSource - Optionally limit to one feed source.
 */
export async function runThreatIntelFeedRefresh(tenantId?: number, specificSource?: string): Promise<void> {
  logger.info({ tenantId, specificSource: specificSource ?? "all" }, "TI feed refresh started");

  const keys: Record<string, string | null> = {};
  const keyNames = ["ti_alienvault_key", "ti_abuseipdb_key", "ti_greynoise_key", "ti_virustotal_key", "ti_threatfox_key"];
  await Promise.all(keyNames.map(async k => { keys[k] = await getPlatformSetting(k); }));

  const sourcesToRun: KnownSource[] = specificSource
    ? ([specificSource] as KnownSource[]).filter(s => (KNOWN_SOURCES as readonly string[]).includes(s))
    : [...KNOWN_SOURCES];

  if (sourcesToRun.length === 0) {
    logger.warn({ specificSource }, "No valid TI sources to run");
    return;
  }

  // IOC-type sources run in parallel (fast external APIs)
  const parallelSources: KnownSource[] = ["alienvault_otx", "threatfox", "malwarebazaar", "urlhaus", "phishtank", "cisa_kev", "abuseipdb", "greynoise"];
  // Heavy sources run sequentially to avoid large memory spikes and API throttling
  const sequentialSources: KnownSource[] = ["mitre_attack", "nvd_cve"];

  const parallelToRun = parallelSources.filter(s => sourcesToRun.includes(s));
  if (parallelToRun.length > 0) {
    await Promise.all(parallelToRun.map(source =>
      withFeedRun(source, () => runSingleFeed(source, keys)).catch(err =>
        logger.warn({ source, err }, "Feed run error (non-fatal)")
      )
    ));
  }

  const sequentialToRun = sequentialSources.filter(s => sourcesToRun.includes(s));
  for (const source of sequentialToRun) {
    await withFeedRun(source, () => runSingleFeed(source, keys)).catch(err =>
      logger.warn({ source, err }, "Feed run error (non-fatal)")
    );
  }

  logger.info({ sources: sourcesToRun.length }, "TI feed refresh completed");
}
