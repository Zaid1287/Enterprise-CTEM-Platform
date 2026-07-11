/**
 * TPRM Vendor Breach Intelligence Engine
 * Sources:
 *  1. Have I Been Pwned — public breach list (free, no API key needed for domain search)
 *  2. crt.sh — certificate transparency lookalike domain detection
 *  3. URLScan.io — recent scans flagged as malicious/phishing
 * All real data — zero mocked results.
 */

import { logger } from "./logger";

const UA = "Sentinelware-TPRM/1.0";
const FETCH_TIMEOUT_MS = 15000;

async function safeFetch(url: string, opts: RequestInit = {}): Promise<Response | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: { "User-Agent": UA, "Accept": "application/json", ...(opts.headers ?? {}) },
    });
    clearTimeout(t);
    return res;
  } catch {
    return null;
  }
}

// ── HIBP Breach List Cache ────────────────────────────────────────────────────
// HIBP /api/v3/breaches returns all known breaches; each includes a Domain field.
// We download once, cache for 24h, filter client-side — entirely free, no API key needed.

interface HibpBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
  IsMalware: boolean;
}

let hibpCache: HibpBreach[] | null = null;
let hibpCachedAt = 0;
const HIBP_CACHE_TTL_MS = 24 * 60 * 60 * 1000;

async function getHibpBreachList(): Promise<HibpBreach[]> {
  if (hibpCache && Date.now() - hibpCachedAt < HIBP_CACHE_TTL_MS) return hibpCache;
  try {
    const res = await safeFetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "hibp-api-key": "none" }, // some versions need header presence
    });
    if (res?.ok) {
      const data = await res.json() as HibpBreach[];
      if (Array.isArray(data) && data.length > 0) {
        hibpCache = data;
        hibpCachedAt = Date.now();
        return data;
      }
    }
  } catch (e) {
    logger.warn({ e }, "HIBP breach list fetch failed");
  }
  return hibpCache ?? [];
}

export interface BreachEvent {
  breachName: string;
  breachDate: string | null;
  pwnCount: number;
  dataClasses: string[];
  description: string | null;
  isVerified: boolean;
  isSensitive: boolean;
  isFabricated: boolean;
  logoPath: string | null;
  source: "hibp" | "crtsh_lookalike" | "urlscan";
}

export interface LookalikeDomain {
  domain: string;
  similarity: number;    // 0–100
  registered: boolean;
  issuerCN: string | null;
  firstSeen: string | null;
  threatType: "typosquatting" | "combosquatting" | "homoglyph" | "subdomain_abuse" | "other";
}

export interface BreachIntelReport {
  domain: string;
  breachEvents: BreachEvent[];
  lookalikeDomains: LookalikeDomain[];
  totalBreachedRecords: number;
  mostRecentBreach: string | null;
  dataClassesExposed: string[];
  lookalikeThreatCount: number;
  riskScore: number;   // 0–100 (higher = worse)
  scannedAt: Date;
}

// ── HIBP Domain Breach Lookup ─────────────────────────────────────────────────

export async function checkHibpBreaches(domain: string): Promise<BreachEvent[]> {
  const list = await getHibpBreachList();
  const apex = extractApex(domain);

  return list
    .filter(b => {
      const bd = (b.Domain ?? "").toLowerCase();
      return bd === apex || bd === domain.toLowerCase() || bd.endsWith(`.${apex}`);
    })
    .map(b => ({
      breachName: b.Title ?? b.Name,
      breachDate: b.BreachDate ?? null,
      pwnCount: b.PwnCount ?? 0,
      dataClasses: b.DataClasses ?? [],
      description: stripHtml(b.Description ?? ""),
      isVerified: b.IsVerified ?? true,
      isSensitive: b.IsSensitive ?? false,
      isFabricated: b.IsFabricated ?? false,
      logoPath: b.LogoPath ?? null,
      source: "hibp" as const,
    }));
}

// ── crt.sh Lookalike Domain Detection ────────────────────────────────────────

export async function detectLookalikeDomains(domain: string): Promise<LookalikeDomain[]> {
  const apex = extractApex(domain);
  const keyword = apex.split(".")[0] ?? apex;
  if (keyword.length < 3) return [];

  const lookalikes: LookalikeDomain[] = [];

  try {
    const res = await safeFetch(
      `https://crt.sh/?q=%25${encodeURIComponent(keyword)}%25&output=json`,
      { headers: { Accept: "application/json" } }
    );
    if (!res?.ok) return [];

    const certs = (await res.json().catch(() => [])) as Array<{
      name_value: string;
      issuer_ca_id: number;
      issuer_name: string;
      not_before: string;
      not_after: string;
    }>;

    const seen = new Set<string>();
    for (const cert of certs.slice(0, 500)) {
      const names = cert.name_value.split("\n").map(n => n.trim().toLowerCase().replace(/^\*\./, ""));
      for (const name of names) {
        // Skip the real domain and its subdomains
        if (name === apex || name.endsWith(`.${apex}`)) continue;
        if (seen.has(name)) continue;
        seen.add(name);

        const { type, similarity } = classifyLookalike(name, apex, keyword);
        if (similarity < 60) continue;

        const issuerMatch = cert.issuer_name.match(/CN=([^,]+)/);
        lookalikes.push({
          domain: name,
          similarity,
          registered: true,
          issuerCN: issuerMatch ? issuerMatch[1]! : null,
          firstSeen: cert.not_before ?? null,
          threatType: type,
        });
      }
    }
  } catch (e) {
    logger.warn({ e, domain }, "crt.sh lookalike detection failed");
  }

  // Sort by similarity descending, take top 20
  return lookalikes
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, 20);
}

// ── URLScan.io Threat Check ───────────────────────────────────────────────────

export async function checkUrlScanThreats(domain: string): Promise<BreachEvent[]> {
  const events: BreachEvent[] = [];
  try {
    const res = await safeFetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10&sort=task.time:desc`,
    );
    if (!res?.ok) return events;

    const data = (await res.json().catch(() => ({}))) as { results?: Array<{ task: { domain: string; time: string; url: string }; verdicts: { overall: { malicious: boolean; score: number; tags?: string[] } } }> };
    const malicious = (data.results ?? []).filter(r => r.verdicts?.overall?.malicious);
    if (malicious.length > 0) {
      events.push({
        breachName: `Malicious activity detected on ${domain}`,
        breachDate: malicious[0]?.task?.time?.split("T")[0] ?? null,
        pwnCount: 0,
        dataClasses: malicious[0]?.verdicts?.overall?.tags ?? ["malicious_url"],
        description: `URLScan.io flagged ${malicious.length} scan(s) of ${domain} as malicious. Tags: ${malicious.flatMap(r => r.verdicts?.overall?.tags ?? []).join(", ")}`,
        isVerified: true,
        isSensitive: false,
        isFabricated: false,
        logoPath: null,
        source: "urlscan",
      });
    }
  } catch (e) {
    logger.warn({ e, domain }, "URLScan threat check failed");
  }
  return events;
}

// ── Full Breach Intel Report ──────────────────────────────────────────────────

export async function runBreachIntelReport(domain: string): Promise<BreachIntelReport> {
  const [hibpBreaches, lookalikes, urlscanThreats] = await Promise.all([
    checkHibpBreaches(domain).catch(() => [] as BreachEvent[]),
    detectLookalikeDomains(domain).catch(() => [] as LookalikeDomain[]),
    checkUrlScanThreats(domain).catch(() => [] as BreachEvent[]),
  ]);

  const allBreaches = [...hibpBreaches, ...urlscanThreats];
  const totalBreachedRecords = allBreaches.reduce((sum, b) => sum + b.pwnCount, 0);
  const allDataClasses = [...new Set(allBreaches.flatMap(b => b.dataClasses))];
  const sortedBreaches = [...allBreaches].sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""));
  const mostRecentBreach = sortedBreaches[0]?.breachDate ?? null;

  // Risk scoring
  let riskScore = 0;
  riskScore += Math.min(40, allBreaches.length * 10);                        // breach count
  if (totalBreachedRecords > 1_000_000) riskScore += 20;
  else if (totalBreachedRecords > 100_000) riskScore += 10;
  else if (totalBreachedRecords > 0) riskScore += 5;
  riskScore += Math.min(20, lookalikes.filter(l => l.similarity >= 85).length * 5); // high-sim lookalikes
  if (allDataClasses.some(d => /password|credential/i.test(d))) riskScore += 15;
  if (allDataClasses.some(d => /credit|payment|financial/i.test(d))) riskScore += 15;
  if (allBreaches.some(b => b.isSensitive)) riskScore += 10;

  return {
    domain,
    breachEvents: allBreaches,
    lookalikeDomains: lookalikes,
    totalBreachedRecords,
    mostRecentBreach,
    dataClassesExposed: allDataClasses,
    lookalikeThreatCount: lookalikes.filter(l => l.similarity >= 75).length,
    riskScore: Math.min(100, riskScore),
    scannedAt: new Date(),
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractApex(domain: string): string {
  try {
    const parts = domain.replace(/^www\./, "").split(".");
    if (parts.length >= 2) return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  } catch { /**/ }
  return domain;
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#[0-9]+;/g, "").trim();
}

function classifyLookalike(candidate: string, realApex: string, keyword: string): { type: LookalikeDomain["threatType"]; similarity: number } {
  const candApex = extractApex(candidate);

  // Combosquatting: keyword + extra word (e.g., stripe-secure.com, login-stripe.com)
  if (/[-.]/.test(candApex) && candApex.includes(keyword) && candApex !== realApex) {
    return { type: "combosquatting", similarity: 85 };
  }

  // Typosquatting: Levenshtein distance
  const distance = levenshtein(candApex.split(".")[0] ?? "", keyword);
  const maxLen = Math.max((candApex.split(".")[0] ?? "").length, keyword.length);
  const similarity = Math.round((1 - distance / maxLen) * 100);
  if (distance <= 2 && similarity >= 60) {
    return { type: "typosquatting", similarity };
  }

  // Subdomain abuse: real domain used as subdomain (e.g., stripe.com.phishing.net)
  if (candidate.includes(`.${realApex}.`) || candidate.includes(`${realApex}.`)) {
    return { type: "subdomain_abuse", similarity: 90 };
  }

  if (similarity >= 60) return { type: "other", similarity };
  return { type: "other", similarity: 0 };
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0]![j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1]
        ? dp[i - 1]![j - 1]!
        : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[m]![n]!;
}
