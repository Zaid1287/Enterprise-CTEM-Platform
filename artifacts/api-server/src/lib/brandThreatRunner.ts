import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import dns from "node:dns/promises";
import { eq, and, gt, gte, isNotNull, isNull, lt, desc, sql } from "drizzle-orm";
import {
  db,
  brandThreatScansTable, brandThreatResultsTable,
  dataLeakResultsTable, phishingDetectionsTable, brandAbuseResultsTable,
  adMonitoringResultsTable,
  brandWatchlistItemsTable,
  cdnWhitelistTable,
} from "@workspace/db";
import { scanMetaAds } from "./metaAdsClient";
import { queryAbuseChFeeds } from "./abuseChFeeds";
import { logger } from "./logger";
import { rdapLookup } from "./rdapClient";
import { geoIpBatch } from "./geoIpClient";
import { checkPhishingFeed, setPhishTankKey } from "./phishFeedClient";
import { checkGoogleSafeBrowsing } from "./googleSafeBrowsing";
import { hibpDomainLookup, severityFromBreach } from "./hibpClient";
import { vtDomainLookup, vtUrlScan } from "./vtDomainClient";
import { scanBrandAbuse } from "./brandAbuseScanner";
import { intelxSearch, intelxTypeToBucket } from "./intelxClient";
import { searchShodanByFaviconHash } from "./shodanFaviconClient";
import { getPlatformSetting } from "../routes/platformSettings";
import { dispatchNotifications } from "./notifier";

const execFileAsync = promisify(execFile);

// Works in both tsx (dev) and esbuild dist (prod) because process.cwd()
// is always the artifact root (/home/runner/workspace/artifacts/api-server).
const WRAPPER_SCRIPT = path.join(process.cwd(), "scripts/favihunter_wrapper.py");

// ── Favihunter integration ─────────────────────────────────────────────────────

interface FaviHunterResult {
  faviconUrl: string;
  hashes: {
    mmh3: number;
    mmh3Hex: string;
    md5: string;
    sha256: string;
  };
  searchUrls: Record<string, { url: string; hash_type: string }>;
}

async function runFaviHunter(domain: string): Promise<FaviHunterResult | null> {
  try {
    const { stdout, stderr } = await execFileAsync(
      "python3",
      [WRAPPER_SCRIPT, domain],
      {
        timeout: 60_000,
        maxBuffer: 2 * 1024 * 1024,
        env: process.env,
      },
    );
    if (stderr) logger.debug({ domain, stderr }, "favihunter stderr");

    const raw = JSON.parse(stdout.trim()) as {
      error?: string;
      favicon_url?: string;
      hashes?: FaviHunterResult["hashes"];
      search_urls?: FaviHunterResult["searchUrls"];
    };
    if (raw.error) {
      logger.warn({ domain, error: raw.error }, "favihunter reported no favicon or error");
      return null;
    }
    if (!raw.favicon_url || !raw.hashes || !raw.search_urls) return null;
    return { faviconUrl: raw.favicon_url, hashes: raw.hashes, searchUrls: raw.search_urls };
  } catch (err: unknown) {
    logger.warn({ err, domain, wrapper: WRAPPER_SCRIPT }, "favihunter subprocess failed");
    return null;
  }
}

// ── dnstwist binary runner ─────────────────────────────────────────────────────

export interface PermResult {
  permutation: string;
  fuzzer: string;
  dnsA: string[];
  dnsAaaa: string[];
  dnsMx: string[];
  dnsNs: string[];
}

async function runDnstwistBinary(domain: string): Promise<PermResult[]> {
  const { stdout } = await execFileAsync(
    "dnstwist",
    ["--format", "json", "--threads", "20", domain],
    { timeout: 60_000, maxBuffer: 20 * 1024 * 1024 },
  );
  const raw = JSON.parse(stdout) as Array<{
    fuzzer: string;
    domain: string;
    "dns-a"?: string[];
    "dns-aaaa"?: string[];
    "dns-mx"?: string[];
    "dns-ns"?: string[];
  }>;

  return raw
    .filter(r => r.fuzzer !== "original")
    .map(r => ({
      permutation: r.domain,
      fuzzer: r.fuzzer,
      dnsA: r["dns-a"] ?? [],
      dnsAaaa: r["dns-aaaa"] ?? [],
      dnsMx: (r["dns-mx"] ?? []).map(mx => {
        const parts = mx.trim().split(/\s+/);
        return parts.length >= 2 ? parts.slice(1).join(" ") : mx;
      }),
      dnsNs: r["dns-ns"] ?? [],
    }));
}

// ── Built-in Node.js fallback engine ──────────────────────────────────────────

const KEYBOARD_ADJACENT: Record<string, string[]> = {
  a:["q","w","s","z"], b:["v","g","h","n"], c:["x","d","f","v"],
  d:["s","e","r","f","c","x"], e:["w","s","d","r"], f:["d","r","t","g","v","c"],
  g:["f","t","y","h","b","v"], h:["g","y","u","j","n","b"], i:["u","o","k","j"],
  j:["h","u","i","k","n","m"], k:["j","i","o","l","m"], l:["k","o","p"],
  m:["n","j","k"], n:["b","h","j","m"], o:["i","p","l","k"],
  p:["o","l"], q:["w","a"], r:["e","d","f","t"],
  s:["a","w","e","d","x","z"], t:["r","f","g","y"],
  u:["y","h","j","i"], v:["c","f","g","b"],
  w:["q","a","s","e"], x:["z","s","d","c"],
  y:["t","g","h","u"], z:["a","s","x"],
};

const HOMOGLYPHS: Record<string, string[]> = {
  a:["4"], e:["3"], i:["1","l"], l:["1","i"],
  o:["0"], s:["5"], t:["7"], b:["6"], g:["9"], q:["9"],
};

const COMMON_TLDS = [
  "com","net","org","io","co","info","biz","us","de","fr",
  "club","shop","online","site","store","app","live","pro",
];

function parseDomain(domain: string): { sld: string; tld: string } {
  const clean = domain.toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
  const parts = clean.split(".");
  if (parts.length < 2) return { sld: clean, tld: "com" };
  return { sld: parts[0]!, tld: parts.slice(1).join(".") };
}

function isValidSld(sld: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(sld) && sld.length >= 2 && sld.length <= 63;
}

function generatePermutations(domain: string): Array<{ permutation: string; fuzzer: string }> {
  const { sld, tld } = parseDomain(domain);
  const results: Array<{ permutation: string; fuzzer: string }> = [];
  const seen = new Set<string>([domain.toLowerCase()]);

  function add(s: string, fuzzer: string) {
    if (!isValidSld(s)) return;
    const p = `${s}.${tld}`;
    if (!seen.has(p)) { seen.add(p); results.push({ permutation: p, fuzzer }); }
  }
  function addFull(p: string, fuzzer: string) {
    if (seen.has(p)) return;
    const [s] = p.split(".");
    if (!isValidSld(s ?? "")) return;
    seen.add(p); results.push({ permutation: p, fuzzer });
  }

  for (const t of COMMON_TLDS) {
    if (t !== tld) addFull(`${sld}.${t}`, "tld-swap");
  }
  for (let i = 0; i < sld.length; i++) add(sld.slice(0, i) + sld.slice(i + 1), "omission");
  for (let i = 0; i < sld.length; i++) add(sld.slice(0, i) + sld[i]! + sld[i]! + sld.slice(i + 1), "repetition");
  for (let i = 0; i < sld.length - 1; i++) add(sld.slice(0, i) + sld[i + 1]! + sld[i]! + sld.slice(i + 2), "transposition");
  for (let i = 0; i < sld.length; i++) {
    for (const adj of KEYBOARD_ADJACENT[sld[i]!] ?? []) {
      add(sld.slice(0, i) + adj + sld.slice(i + 1), "replacement");
    }
  }
  for (let i = 0; i <= sld.length; i++) {
    for (const ch of ["a","e","i","o","u","s","r","n"]) {
      add(sld.slice(0, i) + ch + sld.slice(i), "insertion");
    }
  }
  const vowels = ["a","e","i","o","u"];
  for (let i = 0; i < sld.length; i++) {
    if (vowels.includes(sld[i]!)) {
      for (const v of vowels) {
        if (v !== sld[i]) add(sld.slice(0, i) + v + sld.slice(i + 1), "vowel-swap");
      }
    }
  }
  for (let i = 1; i < sld.length; i++) add(sld.slice(0, i) + "-" + sld.slice(i), "hyphenation");
  for (let i = 0; i < sld.length; i++) {
    for (const g of HOMOGLYPHS[sld[i]!] ?? []) {
      if (/^[a-z0-9]$/.test(g)) add(sld.slice(0, i) + g + sld.slice(i + 1), "homoglyph");
    }
  }
  const SUBDOMS = ["secure","login","mail","support","account","verify","update","web"];
  for (const sub of SUBDOMS) {
    add(`${sub}-${sld}`, "subdomain");
    add(`${sld}-${sub}`, "subdomain");
  }
  for (const ch of ["s","e","r","1","2","3"]) {
    add(ch + sld, "addition");
    add(sld + ch, "addition");
  }
  return results;
}

async function checkDNSFull(domain: string): Promise<{
  dnsA: string[]; dnsAaaa: string[]; dnsMx: string[]; dnsNs: string[];
}> {
  const [a, aaaa, mx, ns] = await Promise.all([
    dns.resolve4(domain).catch(() => [] as string[]),
    dns.resolve6(domain).catch(() => [] as string[]),
    dns.resolveMx(domain).catch(() => [] as { exchange: string; priority: number }[]),
    dns.resolveNs(domain).catch(() => [] as string[]),
  ]);
  return {
    dnsA: a as string[],
    dnsAaaa: aaaa as string[],
    dnsMx: (mx as { exchange: string }[]).map(m => m.exchange),
    dnsNs: ns as string[],
  };
}

async function runBuiltinEngine(domain: string): Promise<PermResult[]> {
  const permutations = generatePermutations(domain);
  const results: PermResult[] = [];
  const queue = [...permutations];

  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      const { permutation, fuzzer } = item;
      const resolved = await checkDNSFull(permutation);
      results.push({ permutation, fuzzer, ...resolved });
    }
  }

  await Promise.all(Array.from({ length: 20 }, () => worker()));
  return results;
}

async function scanPermutations(domain: string): Promise<PermResult[]> {
  let results: PermResult[];
  try {
    logger.info({ domain }, "Running dnstwist binary for brand threat scan");
    results = await runDnstwistBinary(domain);
    logger.info({ domain, count: results.length }, "dnstwist permutations done, enriching DNS via Node.js");
  } catch (err) {
    logger.warn({ err, domain }, "dnstwist binary unavailable — falling back to built-in engine");
    return runBuiltinEngine(domain);
  }

  // dnstwist's own DNS resolver is blocked in this environment.
  // Re-resolve every permutation that came back empty using the Node.js dns module
  // (which uses the system resolver and works correctly).
  const toEnrich = results.filter(r =>
    r.dnsA.length === 0 && r.dnsAaaa.length === 0 && r.dnsMx.length === 0 && r.dnsNs.length === 0,
  );
  if (toEnrich.length > 0) {
    logger.info({ domain, count: toEnrich.length }, "Node.js DNS enrichment starting");
    const queue = [...toEnrich];
    async function enrichWorker() {
      while (queue.length > 0) {
        const item = queue.shift();
        if (!item) break;
        const resolved = await checkDNSFull(item.permutation);
        item.dnsA    = resolved.dnsA;
        item.dnsAaaa = resolved.dnsAaaa;
        item.dnsMx   = resolved.dnsMx;
        item.dnsNs   = resolved.dnsNs;
      }
    }
    await Promise.all(Array.from({ length: 20 }, () => enrichWorker()));
    const live = results.filter(r => r.dnsA.length > 0).length;
    logger.info({ domain, live }, "Node.js DNS enrichment complete");
  }
  return results;
}

// ── Risk scoring ───────────────────────────────────────────────────────────────

// High-risk GeoIP country codes (known phishing/cybercrime hotspots).
// Deliberately excludes legitimate large-internet nations like IN, BR, TR, PL.
const HIGH_RISK_COUNTRIES = new Set([
  "RU", "CN", "KP", "IR", "NG", "UA", "PK", "BD", "VN", "ID", "TH", "BY",
]);

// ── CDN / parking IP detection ────────────────────────────────────────────────

function ip2int(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

// Built-in CDN / domain-parking IP ranges used as a seed and fallback.
// The canonical source of truth is the cdn_whitelist_entries DB table,
// loaded fresh at the start of each scan via loadCdnRangesFromDb().
const BUILTIN_CDN_RANGES: Array<{ start: number; end: number; label: string }> = [
  // Cloudflare
  { start: ip2int("104.16.0.0"),   end: ip2int("104.31.255.255"),  label: "Cloudflare" },
  { start: ip2int("172.64.0.0"),   end: ip2int("172.71.255.255"),  label: "Cloudflare" },
  { start: ip2int("162.158.0.0"),  end: ip2int("162.159.255.255"), label: "Cloudflare" },
  { start: ip2int("190.93.240.0"), end: ip2int("190.93.255.255"),  label: "Cloudflare" },
  // Akamai Technologies
  { start: ip2int("23.32.0.0"),    end: ip2int("23.63.255.255"),   label: "Akamai" },
  { start: ip2int("23.192.0.0"),   end: ip2int("23.223.255.255"),  label: "Akamai" },
  { start: ip2int("72.246.0.0"),   end: ip2int("72.247.255.255"),  label: "Akamai" },
  { start: ip2int("96.6.0.0"),     end: ip2int("96.7.255.255"),    label: "Akamai" },
  // AWS CloudFront
  { start: ip2int("13.32.0.0"),    end: ip2int("13.35.255.255"),   label: "CloudFront" },
  { start: ip2int("13.224.0.0"),   end: ip2int("13.227.255.255"),  label: "CloudFront" },
  { start: ip2int("52.84.0.0"),    end: ip2int("52.87.255.255"),   label: "CloudFront" },
  { start: ip2int("54.182.0.0"),   end: ip2int("54.185.255.255"),  label: "CloudFront" },
  { start: ip2int("99.84.0.0"),    end: ip2int("99.87.255.255"),   label: "CloudFront" },
  { start: ip2int("130.176.0.0"),  end: ip2int("130.176.255.255"), label: "CloudFront" },
  { start: ip2int("143.204.0.0"),  end: ip2int("143.204.255.255"), label: "CloudFront" },
  { start: ip2int("205.251.192.0"),end: ip2int("205.251.255.255"), label: "CloudFront" },
  // Domain parking providers
  { start: ip2int("184.168.0.0"),  end: ip2int("184.168.255.255"), label: "GoDaddy" },
  { start: ip2int("198.54.117.0"), end: ip2int("198.54.117.255"),  label: "Namecheap" },
  { start: ip2int("199.102.0.0"),  end: ip2int("199.102.127.255"), label: "Namecheap" },
  { start: ip2int("185.53.178.0"), end: ip2int("185.53.178.255"),  label: "Sedo" },
  { start: ip2int("50.63.202.0"),  end: ip2int("50.63.202.255"),   label: "Bodis" },
  { start: ip2int("80.244.75.0"),  end: ip2int("80.244.75.255"),   label: "Dan.com" },
];

/** Load active CDN ranges from the DB; falls back to hardcoded list if empty or on error. */
async function loadCdnRangesFromDb(): Promise<Array<{ start: number; end: number; label: string }>> {
  try {
    const rows = await db.select({
      ipStart: cdnWhitelistTable.ipStart,
      ipEnd:   cdnWhitelistTable.ipEnd,
      label:   cdnWhitelistTable.label,
    }).from(cdnWhitelistTable).where(eq(cdnWhitelistTable.isActive, true));
    if (rows.length === 0) return BUILTIN_CDN_RANGES;
    return rows.map(r => ({ start: ip2int(r.ipStart), end: ip2int(r.ipEnd), label: r.label }));
  } catch {
    return BUILTIN_CDN_RANGES;
  }
}

function isInCdnOrParkingRange(ip: string, ranges: Array<{ start: number; end: number }>): boolean {
  try {
    const n = ip2int(ip);
    return ranges.some(r => n >= r.start && n <= r.end);
  } catch {
    return false;
  }
}

function computeRisk(
  dnsA: string[],
  dnsMx: string[],
  dnsNs: string[],
  fuzzer: string,
  vtMalicious: number,
  vtSuspicious: number,
  isPhishing: boolean,
  phishingSource: string | null,
  whoisAgeDays: number | null,
  geoCountry: string | null,
  geoCountryCode: string | null,
  cdnRanges: Array<{ start: number; end: number }>,
): number {
  let score = 0;

  // Base: active DNS
  if (dnsA.length > 0) score += 45;       // A record active — live domain
  if (dnsMx.length > 0) score += 35;      // MX active — phishing-ready

  // NS parked-domain signal: has NS but no A record
  if (dnsNs.length > 0 && dnsA.length === 0) score += 15;

  // Fuzzer deceptiveness weighting
  if (["homoglyph","bitsquatting"].includes(fuzzer)) score += 20;
  else if (["replacement","transposition"].includes(fuzzer)) score += 15;
  else if (["subdomain","hyphenation"].includes(fuzzer)) score += 10;

  // WHOIS age signals
  if (whoisAgeDays !== null) {
    if (whoisAgeDays < 30) score += 25;   // brand-new domain — strong phishing signal
    else if (whoisAgeDays < 90) score += 10;
  }

  // VirusTotal
  if (vtMalicious >= 1) score += 40;
  else if (vtSuspicious >= 3) score += 20;

  // Phishing feed matches
  if (isPhishing) {
    if (phishingSource === "Google Safe Browsing") score += 45;
    else score += 50; // PhishTank / OpenPhish
  }

  // GeoIP high-risk country (match against ISO country code, not full name)
  if (geoCountryCode && HIGH_RISK_COUNTRIES.has(geoCountryCode)) score += 10;

  // CDN / domain-parking deduction — these domains are typically not actively
  // abusing the brand; reduce risk to avoid alert fatigue.
  const inCdn = dnsA.length > 0 && dnsA.some(ip => isInCdnOrParkingRange(ip, cdnRanges));
  if (inCdn) score -= 20;

  return Math.min(100, Math.max(0, score));
}

// ── Phase helpers ─────────────────────────────────────────────────────────────

async function runRdapEnrichment(
  allResults: PermResult[],
): Promise<Map<string, Awaited<ReturnType<typeof rdapLookup>>>> {
  const rdapMap = new Map<string, Awaited<ReturnType<typeof rdapLookup>>>();
  const RDAP_CONCURRENCY = 5;
  const queue = [...allResults];

  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      const result = await rdapLookup(item.permutation);
      if (result) rdapMap.set(item.permutation, result);
    }
  }

  await Promise.all(Array.from({ length: RDAP_CONCURRENCY }, () => worker()));
  return rdapMap;
}

async function runVtEnrichment(
  liveResults: PermResult[],
  vtApiKey: string,
): Promise<Map<string, NonNullable<Awaited<ReturnType<typeof vtDomainLookup>>>>> {
  const vtMap = new Map<string, NonNullable<Awaited<ReturnType<typeof vtDomainLookup>>>>();
  if (!vtApiKey) return vtMap;

  // VT free-tier limit: 4 req/min → 15 000 ms inter-request delay, single worker
  // to guarantee we never exceed the quota regardless of queue length.
  const VT_DELAY_MS = 15_000;
  const queue = [...liveResults];

  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      const result = await vtDomainLookup(item.permutation, vtApiKey);
      if (result) vtMap.set(item.permutation, result);
      if (queue.length > 0) await new Promise(r => setTimeout(r, VT_DELAY_MS));
    }
  }

  await worker(); // single worker — strict 4 req/min
  return vtMap;
}

async function runPhishingChecks(
  liveResults: PermResult[],
  gsbKey: string | null,
): Promise<Map<string, { isPhishing: boolean; source: string | null; threatType: string | null }>> {
  const phishMap = new Map<string, { isPhishing: boolean; source: string | null; threatType: string | null }>();

  const feedResults = await Promise.allSettled(
    liveResults.map(r => checkPhishingFeed(r.permutation)),
  );
  for (let i = 0; i < liveResults.length; i++) {
    const r = liveResults[i]!;
    const result = feedResults[i];
    if (result?.status === "fulfilled" && result.value.isPhishing) {
      phishMap.set(r.permutation, { isPhishing: true, source: result.value.source, threatType: null });
    }
  }

  if (gsbKey) {
    const urls = liveResults.map(r => `http://${r.permutation}`);
    const gsbResults = await checkGoogleSafeBrowsing(urls, gsbKey).catch(() => new Map());
    for (const [url, result] of gsbResults) {
      const domain = url.replace("http://", "");
      phishMap.set(domain, { isPhishing: true, source: "Google Safe Browsing", threatType: result.threatType });
    }
  }

  return phishMap;
}

// ── Core scan executor ────────────────────────────────────────────────────────

async function captureHighRiskScreenshots(
  scanId: number,
  targets: Array<{ id: number; permutation: string }>,
): Promise<void> {
  if (targets.length === 0) return;
  const { captureScreenshots } = await import("./screenshotEngine");
  const CONCURRENCY = 3;
  const TIMEOUT_MS = 20_000;
  const queue = [...targets.slice(0, 10)]; // cap at 10 screenshots per scan

  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      try {
        const shots = await captureScreenshots(`https://${item.permutation}`, TIMEOUT_MS);
        const shot = shots[0];
        if (shot?.screenshotData) {
          await db.update(brandThreatResultsTable)
            .set({ screenshot: shot.screenshotData })
            .where(eq(brandThreatResultsTable.id, item.id));
        }
      } catch (err) {
        logger.warn({ err, domain: item.permutation }, "brand threat screenshot failed");
      }
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
  logger.info({ scanId, count: targets.length }, "brand threat screenshots captured");
}

export interface PrevScanSnapshot {
  permutations?: Set<string>;
  phishingUrls?: Set<string>;
  dataLeakKeys?: Set<string>;
  brandAbuseKeys?: Set<string>;
  adKeys?: Set<string>;
}

export async function runBrandThreatScan(scanId: number, domain: string, resumeFromPhase1Cache?: PermResult[], prevPermutations?: Set<string>, prevSnapshot?: PrevScanSnapshot): Promise<void> {
  try {
    const [vtApiKey, gsbKey, hibpKey, phishTankKey, shodanKey, cdnRanges] = await Promise.all([
      getPlatformSetting("virustotal_api_key"),
      getPlatformSetting("google_safe_browsing_key"),
      getPlatformSetting("hibp_api_key"),
      getPlatformSetting("phishtank_api_key"),
      getPlatformSetting("shodan_api_key"),
      loadCdnRangesFromDb(),
    ]);

    // Propagate PhishTank API key to feed client (invalidates cache if key changed)
    setPhishTankKey(phishTankKey ?? null);

    let permResults: PermResult[];
    let faviResult: FaviHunterResult | null = null;

    if (resumeFromPhase1Cache) {
      // ── RESUME: Phase 1 completed before restart — use cached permutations ───
      permResults = resumeFromPhase1Cache;
      logger.info({ scanId, domain, count: permResults.length }, "Resuming brand threat scan from Phase 1 checkpoint");

      // Recover favicon data from DB (was persisted before server restarted)
      const [scanRow] = await db.select({
        faviconMd5:        brandThreatScansTable.faviconMd5,
        faviconUrl:        brandThreatScansTable.faviconUrl,
        faviconMmh3:       brandThreatScansTable.faviconMmh3,
        faviconMmh3Hex:    brandThreatScansTable.faviconMmh3Hex,
        faviconSha256:     brandThreatScansTable.faviconSha256,
        faviconSearchUrls: brandThreatScansTable.faviconSearchUrls,
      }).from(brandThreatScansTable).where(eq(brandThreatScansTable.id, scanId));
      if (scanRow?.faviconMd5) {
        faviResult = {
          faviconUrl:  scanRow.faviconUrl ?? "",
          hashes: {
            mmh3:    scanRow.faviconMmh3 ?? 0,
            mmh3Hex: scanRow.faviconMmh3Hex ?? "",
            md5:     scanRow.faviconMd5,
            sha256:  scanRow.faviconSha256 ?? "",
          },
          searchUrls: (scanRow.faviconSearchUrls ?? {}) as FaviHunterResult["searchUrls"],
        };
      }

      // Reset status + progress to Phase 1 completion level
      await db.update(brandThreatScansTable)
        .set({ status: "running", progress: 20 })
        .where(eq(brandThreatScansTable.id, scanId));

      // Clear any partial secondary data written before the server was restarted.
      // Use isNull(archivedAt) so we only remove the new partial rows, never the
      // archived rows from the previous scan run on the same scanId.
      await Promise.all([
        db.delete(brandThreatResultsTable).where(and(eq(brandThreatResultsTable.scanId, scanId), isNull(brandThreatResultsTable.archivedAt))),
        db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, scanId)),
        db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, scanId)),
        db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, scanId)),
        db.delete(adMonitoringResultsTable).where(eq(adMonitoringResultsTable.scanId, scanId)),
      ]);
    } else {
      // ── FRESH START ────────────────────────────────────────────────────────────
      await db.update(brandThreatScansTable)
        .set({ status: "running", favihunterStatus: "running" })
        .where(eq(brandThreatScansTable.id, scanId));

      logger.info({ scanId, domain }, "Starting advanced brand threat scan");

      // ── Phase 1: Permutations + favihunter in parallel ────────────────────────
      const [permRes, faviRes] = await Promise.all([
        scanPermutations(domain),
        runFaviHunter(domain).then(async result => {
          if (result) {
            await db.update(brandThreatScansTable).set({
              favihunterStatus: "done",
              faviconUrl: result.faviconUrl,
              faviconMmh3: result.hashes.mmh3,
              faviconMmh3Hex: result.hashes.mmh3Hex,
              faviconMd5: result.hashes.md5,
              faviconSha256: result.hashes.sha256,
              faviconSearchUrls: result.searchUrls as unknown as Record<string, unknown>,
            }).where(eq(brandThreatScansTable.id, scanId));
          } else {
            await db.update(brandThreatScansTable).set({
              favihunterStatus: "skipped",
            }).where(eq(brandThreatScansTable.id, scanId));
          }
          return result;
        }).catch(async (err: unknown) => {
          await db.update(brandThreatScansTable).set({
            favihunterStatus: "error",
            favihunterError: String(err),
          }).where(eq(brandThreatScansTable.id, scanId));
          return null;
        }),
      ]);

      permResults = permRes;
      faviResult = faviRes;

      // ── Phase 1b: Shodan favicon clone detection ──────────────────────────────
      if (faviResult && shodanKey && faviResult.hashes.mmh3) {
        try {
          const shodanMatches = await searchShodanByFaviconHash(faviResult.hashes.mmh3, shodanKey, 20);
          if (shodanMatches.length > 0) {
            await db.update(brandThreatScansTable)
              .set({ faviconShodanMatches: shodanMatches as unknown as Record<string, unknown>[] })
              .where(eq(brandThreatScansTable.id, scanId));
            logger.info({ scanId, domain, shodanCount: shodanMatches.length }, "Shodan favicon clone hosts found");
          }
        } catch (err) {
          logger.warn({ err, scanId }, "Shodan favicon search failed (non-fatal)");
        }
      }

      // ── Phase 1 checkpoint ─────────────────────────────────────────────────────
      // Persist permutations to DB so a server restart can resume from Phase 2
      // instead of re-running the full ~60s dnstwist scan.
      await db.update(brandThreatScansTable)
        .set({
          totalPermutations: permResults.length,
          progress: 20,
          checkpoint: "phase1_done",
          permutationsCache: permResults as unknown as Record<string, unknown>[],
        })
        .where(eq(brandThreatScansTable.id, scanId));
    }

    // Separate live (A-record) results for enrichment that needs IPs
    const liveResults = permResults.filter(r => r.dnsA.length > 0);
    // Resolved = any domain with at least one DNS record (A, AAAA, MX, or NS).
    // RDAP only runs on these — running it on all 300+ permutations is too slow.
    const resolvedResults = permResults.filter(r =>
      r.dnsA.length > 0 || r.dnsAaaa.length > 0 || r.dnsMx.length > 0 || r.dnsNs.length > 0,
    );

    logger.info({ scanId, domain, total: permResults.length, live: liveResults.length, resolved: resolvedResults.length }, "Permutation phase done; starting enrichment");

    // ── Phase 2: RDAP (resolved only) + GeoIP/VT/Phishing (live only) ──────────
    const allIps = [...new Set(liveResults.flatMap(r => r.dnsA))];

    const [rdapMap, geoMap, vtMap, phishMap] = await Promise.all([
      runRdapEnrichment(resolvedResults),        // RDAP only on domains with DNS records
      geoIpBatch(allIps),
      vtApiKey ? runVtEnrichment(liveResults, vtApiKey) : Promise.resolve(new Map()),
      runPhishingChecks(liveResults, gsbKey),
    ]);

    await db.update(brandThreatScansTable).set({ progress: 40 }).where(eq(brandThreatScansTable.id, scanId));

    // ── Phase 3: Insert permutation results ──────────────────────────────────
    let liveCount = 0;
    let registeredCount = 0;
    let phishingCount = 0;
    const fuzzerBreakdown: Record<string, number> = {};
    const pendingInserts: Array<typeof brandThreatResultsTable.$inferInsert> = [];

    async function flushBatch() {
      if (!pendingInserts.length) return;
      const batch = pendingInserts.splice(0, pendingInserts.length);
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(brandThreatResultsTable).values(batch.slice(i, i + 50));
      }
    }

    for (const r of permResults) {
      fuzzerBreakdown[r.fuzzer] = (fuzzerBreakdown[r.fuzzer] ?? 0) + 1;

      const rdap = rdapMap.get(r.permutation);
      const geoIpKey = r.dnsA[0];
      const geo = geoIpKey ? geoMap.get(geoIpKey) : undefined;
      const vt = vtMap.get(r.permutation);
      const phish = phishMap.get(r.permutation);

      const vtMalicious = vt?.malicious ?? 0;
      const vtSuspicious = vt?.suspicious ?? 0;
      const isPhishing = phish?.isPhishing ?? false;
      const phishSource = phish?.source ?? null;

      const riskScore = computeRisk(
        r.dnsA, r.dnsMx, r.dnsNs, r.fuzzer,
        vtMalicious, vtSuspicious,
        isPhishing, phishSource,
        rdap?.ageDays ?? null,
        geo?.country ?? null,
        geo?.countryCode ?? null,
        cdnRanges,
      );
      const isSuspicious = riskScore >= 60;

      if (r.dnsA.length > 0) liveCount++;
      if (r.dnsA.length > 0 || r.dnsMx.length > 0) registeredCount++;
      if (isPhishing) phishingCount++;

      // Normalised registration status enum: registered | unregistered | active | parked
      const registrationStatus =
        r.dnsA.length > 0 ? "active" :
        (r.dnsNs.length > 0 && r.dnsA.length === 0) ? "parked" :
        (rdap?.createdDate || rdap?.status?.includes("clientDeleteProhibited")) ? "registered" :
        "unregistered";

      pendingInserts.push({
        scanId,
        permutation: r.permutation,
        fuzzer: r.fuzzer,
        dnsA: r.dnsA.length ? r.dnsA : undefined,
        dnsAaaa: r.dnsAaaa.length ? r.dnsAaaa : undefined,
        dnsMx: r.dnsMx.length ? r.dnsMx : undefined,
        dnsNs: r.dnsNs.length ? r.dnsNs : undefined,
        whoisRegistrar: rdap?.registrar ?? undefined,
        whoisCreated: rdap?.createdDate ?? undefined,
        whoisExpires: rdap?.expiresDate ?? undefined,
        whoisUpdated: rdap?.updatedDate ?? undefined,
        whoisCountry: rdap?.registrantCountry ?? undefined,
        whoisAbuseContact: rdap?.abuseContact ?? undefined,
        whoisAgeDays: rdap?.ageDays ?? undefined,
        whoisRegistrantOrg: rdap?.registrantOrg ?? undefined,
        geoCountry: geo?.country ?? undefined,
        geoCity: geo?.city ?? undefined,
        geoAsn: geo?.asn ?? undefined,
        geoOrg: geo?.org ?? undefined,
        vtMalicious: vt?.malicious ?? undefined,
        vtSuspicious: vt?.suspicious ?? undefined,
        vtLastAnalysisDate: vt?.lastAnalysisDate ?? undefined,
        vtPermalink: vt?.permalink ?? undefined,
        isPhishing,
        phishingSource: phish?.source ?? undefined,
        registrationStatus,
        riskScore,
        isSuspicious,
        isNew: prevPermutations ? !prevPermutations.has(r.permutation) : false,
      });

      if (pendingInserts.length >= 50) await flushBatch();
    }
    await flushBatch();

    // ── Archived-row guard: recompute live/registered/phishing counts from DB ──
    // We derive final counts from a DB query filtered by archivedAt IS NULL so
    // that any archived rows from a previous run of the same scan are explicitly
    // excluded, even if a race condition left them in the table.
    {
      const insertedRows = await db
        .select({
          dnsA:       brandThreatResultsTable.dnsA,
          dnsMx:      brandThreatResultsTable.dnsMx,
          isPhishing: brandThreatResultsTable.isPhishing,
        })
        .from(brandThreatResultsTable)
        .where(and(
          eq(brandThreatResultsTable.scanId, scanId),
          isNull(brandThreatResultsTable.archivedAt),
        ));
      liveCount       = insertedRows.filter(r => r.dnsA && r.dnsA.length > 0).length;
      registeredCount = insertedRows.filter(r => (r.dnsA && r.dnsA.length > 0) || (r.dnsMx && r.dnsMx.length > 0)).length;
      phishingCount   = insertedRows.filter(r => r.isPhishing).length;
    }

    // Save partial counts immediately after Phase 3 so that even if the scan
    // errors in a later phase, the card shows real live/registered/phishing data
    // rather than staying at 0.
    await db.update(brandThreatScansTable).set({
      progress:        65,
      liveCount:       liveCount,
      registeredCount: registeredCount,
      phishingCount:   phishingCount,
    }).where(eq(brandThreatScansTable.id, scanId));

    // ── Phase 3b: Screenshots for high-risk domains (score ≥ 70) ─────────────
    try {
      const highRiskRows = await db
        .select({ id: brandThreatResultsTable.id, permutation: brandThreatResultsTable.permutation })
        .from(brandThreatResultsTable)
        .where(and(
          eq(brandThreatResultsTable.scanId, scanId),
          gte(brandThreatResultsTable.riskScore, 70),
          isNotNull(brandThreatResultsTable.dnsA),
          isNull(brandThreatResultsTable.archivedAt),
        ));
      if (highRiskRows.length > 0) {
        await captureHighRiskScreenshots(scanId, highRiskRows);
      }
    } catch (err) {
      logger.warn({ err, scanId }, "Screenshot phase failed (non-fatal)");
    }

    await db.update(brandThreatScansTable).set({ progress: 80 }).where(eq(brandThreatScansTable.id, scanId));

    // ── Phase 4 pre-fetch: abuse.ch feeds (URLhaus + ThreatFox) ──────────────
    // Query each live permutation domain — no API key required
    const ABUSE_CH_CONCURRENCY = 5;
    const abuseChList: Awaited<ReturnType<typeof queryAbuseChFeeds>> = [];
    const livePermDomains = liveResults.map(r => r.permutation);
    for (let i = 0; i < livePermDomains.length; i += ABUSE_CH_CONCURRENCY) {
      const batch = livePermDomains.slice(i, i + ABUSE_CH_CONCURRENCY);
      const batchResults = await Promise.all(batch.map(d => queryAbuseChFeeds(d).catch(() => [])));
      for (const hits of batchResults) abuseChList.push(...hits);
    }

    // ── Phase 4: Phishing detections from live domains ───────────────────────
    // 4a) Phishing feed results (PhishTank / OpenPhish / GSB)
    const phishingInserts: typeof phishingDetectionsTable.$inferInsert[] = [];
    const phishTenantId = (await db.select({ tenantId: brandThreatScansTable.tenantId })
      .from(brandThreatScansTable).where(eq(brandThreatScansTable.id, scanId)))[0]?.tenantId ?? 0;

    for (const [domainKey, phish] of phishMap) {
      if (!phish.isPhishing) continue;
      phishingInserts.push({
        tenantId: phishTenantId,
        scanId,
        url: `http://${domainKey}`,
        source: phish.source ?? "Unknown",
        verified: true,
        targetBrand: domain,
        threatType: phish.threatType ?? "SOCIAL_ENGINEERING",
        submittedAt: new Date().toISOString(),
      });
    }

    // 4b) VirusTotal URL scan for live permutations — adds malicious URL hits to phishing_detections
    if (vtApiKey && liveResults.length > 0) {
      const VT_URL_CONCURRENCY = 2;
      const VT_URL_DELAY = 2000;
      const vtUrlQueue = liveResults.filter(r => !phishMap.get(r.permutation)?.isPhishing).slice(0, 30);

      async function vtUrlWorker() {
        while (vtUrlQueue.length > 0) {
          const item = vtUrlQueue.shift();
          if (!item) break;
          await new Promise(r => setTimeout(r, VT_URL_DELAY));
          const scanUrl = `https://${item.permutation}`;
          const vtResult = await vtUrlScan(scanUrl, vtApiKey as string).catch(() => null);
          if (vtResult && vtResult.malicious >= 1) {
            phishingInserts.push({
              tenantId: phishTenantId,
              scanId,
              url: scanUrl,
              source: "VirusTotal URL",
              verified: true,
              targetBrand: domain,
              threatType: "MALICIOUS_URL",
              submittedAt: new Date().toISOString(),
            });
          }
        }
      }
      await Promise.all(Array.from({ length: VT_URL_CONCURRENCY }, () => vtUrlWorker()));
    }

    // 4c) abuse.ch feeds (URLhaus + ThreatFox) — no API key required, always runs
    for (const entry of abuseChList) {
      phishingInserts.push({
        tenantId: phishTenantId,
        scanId,
        url: entry.url,
        source: entry.source,
        verified: true,
        targetBrand: domain,
        threatType: entry.threat.toUpperCase().replace(/[^A-Z0-9_]/g, "_"),
        submittedAt: entry.addedAt ?? new Date().toISOString(),
      });
    }

    if (phishingInserts.length > 0) {
      // Mark newly-discovered phishing URLs (not seen in previous scan)
      if (prevSnapshot?.phishingUrls) {
        for (const p of phishingInserts) {
          (p as any).isNew = !prevSnapshot.phishingUrls.has(p.url as string);
        }
      }
      for (let i = 0; i < phishingInserts.length; i += 50) {
        await db.insert(phishingDetectionsTable).values(phishingInserts.slice(i, i + 50));
      }
      const uniqueSources = [...new Set(phishingInserts.map(p => p.source).filter(Boolean))];
      void dispatchNotifications({
        tenantId: phishTenantId,
        eventType: "phishing_detected",
        title: `Phishing Detected: ${domain}`,
        message: `${phishingInserts.length} confirmed phishing URL${phishingInserts.length > 1 ? "s" : ""} detected targeting your brand "${domain}".`,
        severity: "critical",
        scanId,
        domain,
        sourceFeed: uniqueSources.join(", "),
        findingsCount: phishingInserts.length,
      });
    }

    // ── Phase 5: Data leaks (HIBP + IntelX + watchlist) + Brand abuse ─────────
    const [tenantRow] = await db.select({ tenantId: brandThreatScansTable.tenantId })
      .from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.id, scanId));
    const tenantId = tenantRow?.tenantId ?? 0;

    // Load watchlist items to cross-reference in scans
    const watchlistItems = await db.select()
      .from(brandWatchlistItemsTable)
      .where(eq(brandWatchlistItemsTable.tenantId, tenantId));

    const intelxKey = await getPlatformSetting("intelx_api_key");
    const brandName = domain.split(".")[0] ?? domain;

    // Build IntelX query terms: domain + brand name + all watchlist item values
    // Covers: email, domain, keyword, social_handle, mobile_app, logo_url, ip
    const intelxTerms = [domain, brandName];
    for (const item of watchlistItems) {
      if (!item.value) continue;
      if (["email", "domain", "keyword", "mobile_app", "social_handle"].includes(item.type)) {
        intelxTerms.push(item.value);
      } else if (item.type === "logo_url") {
        // Extract host from logo URL so IntelX can find paste/forum references to the CDN domain
        try { intelxTerms.push(new URL(item.value).hostname); } catch { /* ignore malformed URLs */ }
      }
      // ip watchlist items are handled separately (cross-reference against live permutation A records)
    }
    const uniqueTerms = [...new Set(intelxTerms)].slice(0, 5);

    const [youtubeApiKey, metaAdsToken, twitterBearerToken, instagramGraphToken, tiktokResearchToken] = await Promise.all([
      getPlatformSetting("youtube_api_key"),
      getPlatformSetting("meta_ads_access_token"),
      getPlatformSetting("twitter_x_bearer_token"),
      getPlatformSetting("instagram_graph_api_token"),
      getPlatformSetting("tiktok_research_api_token"),
    ]);

    const [hibpResult, brandAbuseData, metaAdsList] = await Promise.all([
      hibpDomainLookup(domain, hibpKey ?? undefined),  // always runs; without key uses public /breaches fallback
      scanBrandAbuse(
        brandName,
        domain,
        watchlistItems.filter(w => w.type === "social_handle").map(w => w.value),
        {
          youtubeApiKey: youtubeApiKey ?? undefined,
          twitterBearerToken: twitterBearerToken ?? undefined,
          instagramGraphToken: instagramGraphToken ?? undefined,
          tiktokResearchToken: tiktokResearchToken ?? undefined,
        },
      ),
      metaAdsToken ? scanMetaAds(brandName, domain, metaAdsToken) : Promise.resolve([]),
    ]);
    const brandAbuseList = brandAbuseData.results;
    const socialWarnings = brandAbuseData.warnings;
    const intelxResultArrays = intelxKey
      ? await Promise.all(uniqueTerms.map(term => intelxSearch(term, intelxKey, 10)))
      : [];

    let dataLeakCount = 0;
    const leakInserts: typeof dataLeakResultsTable.$inferInsert[] = [];

    if (hibpResult && hibpResult.breaches.length > 0) {
      for (const b of hibpResult.breaches) {
        leakInserts.push({
          tenantId,
          scanId,
          source: "HIBP",
          title: b.title,
          breachDate: b.breachDate,
          description: b.description?.replace(/<[^>]+>/g, "").slice(0, 500) ?? null,
          exposedData: b.dataClasses,
          domainMatch: b.domain,
          severity: severityFromBreach(b),
          url: `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(b.name)}`,
        });
      }
    }

    // IntelX results → route by bucket:
    //   darkweb / credential / leaks / pastes → data_leak_results
    //   forum / reddit / twitter / linkedin / documents → brand_abuse_results
    const intelxAbuseInserts: typeof brandAbuseResultsTable.$inferInsert[] = [];
    if (intelxKey && intelxResultArrays.length > 0) {
      const seenNames = new Set<string>();
      for (const results of intelxResultArrays) {
        if (!results) continue;
        for (const r of results) {
          if (seenNames.has(r.name)) continue;
          seenNames.add(r.name);
          const bucket = intelxTypeToBucket(r.type);
          const url = r.storageid
            ? `https://intelx.io/?did=${encodeURIComponent(r.storageid)}`
            : "https://intelx.io";

          const isBrandAbuseBucket = ["forum", "reddit", "twitter", "linkedin", "documents"].includes(bucket);
          if (isBrandAbuseBucket) {
            // Forum / social / document mentions go to brand abuse pillar
            intelxAbuseInserts.push({
              tenantId,
              scanId,
              type: bucket === "forum" ? "impersonation" : "fake_social",
              platform: bucket.charAt(0).toUpperCase() + bucket.slice(1),
              url,
              title: r.name || `IntelX ${bucket} mention`,
              description: r.preview ?? `Brand mention found in ${bucket} via IntelX intelligence`,
              evidenceSnippet: r.preview ?? undefined,
              risk: bucket === "forum" ? "high" : "medium",
            });
          } else {
            // Dark web / credential / paste / leak hits go to data leaks
            leakInserts.push({
              tenantId,
              scanId,
              source: bucket === "darkweb" ? "IntelX-DarkWeb" : bucket === "pastes" ? "IntelX-Paste" : "IntelX",
              title: r.name || "IntelX match",
              breachDate: r.date ? r.date.slice(0, 10) : null,
              description: r.preview ?? `Dark/deep web mention found via IntelX (bucket: ${bucket})`,
              exposedData: [],
              domainMatch: domain,
              severity: bucket === "darkweb" ? "critical" : bucket === "credential" ? "high" : "medium",
              url,
            });
          }
        }
      }
    }

    if (leakInserts.length > 0) {
      // Mark newly-discovered leaks (keyed by title+source — not seen in previous scan)
      if (prevSnapshot?.dataLeakKeys) {
        for (const l of leakInserts) {
          const key = `${l.title}::${l.source}`;
          (l as any).isNew = !prevSnapshot.dataLeakKeys.has(key);
        }
      }
      for (let i = 0; i < leakInserts.length; i += 50) {
        await db.insert(dataLeakResultsTable).values(leakInserts.slice(i, i + 50));
      }
      dataLeakCount = leakInserts.length;
      const worstSeverity = leakInserts.some(l => l.severity === "critical") ? "critical"
        : leakInserts.some(l => l.severity === "high") ? "high" : "medium";
      const uniqueLeakSources = [...new Set(leakInserts.map(l => l.source).filter(Boolean))];
      void dispatchNotifications({
        tenantId,
        eventType: "data_leak_found",
        title: `Data Leak Detected: ${domain}`,
        message: `${leakInserts.length} data leak record${leakInserts.length > 1 ? "s" : ""} found for "${domain}" — credentials or sensitive data may be exposed.`,
        severity: worstSeverity,
        scanId,
        domain,
        sourceFeed: uniqueLeakSources.join(", "),
        findingsCount: leakInserts.length,
      });
    }

    // Cross-reference watchlist items: flag any domain-type items found in results
    const watchlistDomains = watchlistItems.filter(w => w.type === "domain").map(w => w.value.toLowerCase());
    const watchlistIps    = watchlistItems.filter(w => w.type === "ip").map(w => w.value.toLowerCase());

    // Collect all A-record IPs exposed by live permutations for IP watchlist matching
    const livePermutationIps = new Set<string>();
    for (const r of liveResults) {
      for (const ip of (r.dnsA ?? [])) livePermutationIps.add(ip.toLowerCase());
    }

    let brandAbuseCount = 0;
    {
      const abuseInserts: typeof brandAbuseResultsTable.$inferInsert[] = brandAbuseList.map(a => ({
        tenantId,
        scanId,
        type: a.type,
        platform: a.platform ?? undefined,
        url: a.url ?? undefined,
        title: a.title ?? undefined,
        description: a.description ?? undefined,
        evidenceSnippet: a.evidenceSnippet ?? undefined,
        installCount: a.installCount ?? undefined,
        iconUrl: a.iconUrl ?? undefined,
        risk: a.risk,
      }));

      // Merge IntelX forum/social/document brand-abuse hits
      abuseInserts.push(...intelxAbuseInserts);

      // Watchlist domain cross-reference: flag domains found in live permutation results
      for (const wdomain of watchlistDomains) {
        const hit = liveResults.find(r => r.permutation.toLowerCase().includes(wdomain));
        if (hit) {
          abuseInserts.push({
            tenantId,
            scanId,
            type: "fake_domain",
            platform: "DNS",
            url: `http://${hit.permutation}`,
            title: `Watchlist match: ${hit.permutation}`,
            description: `Domain from your brand watchlist (${wdomain}) found as a live permutation`,
            risk: "high",
          });
        }
      }

      // Watchlist IP cross-reference: flag monitored IPs hosting lookalike domains
      for (const wip of watchlistIps) {
        if (livePermutationIps.has(wip)) {
          const hits = liveResults.filter(r => (r.dnsA ?? []).some(ip => ip.toLowerCase() === wip));
          for (const hit of hits) {
            abuseInserts.push({
              tenantId,
              scanId,
              type: "infrastructure_reuse",
              platform: "DNS",
              url: `http://${hit.permutation}`,
              title: `Watchlist IP hosting lookalike: ${hit.permutation}`,
              description: `Monitored IP address ${wip} is resolving lookalike domain ${hit.permutation} — possible shared infrastructure abuse`,
              risk: "critical",
            });
          }
        }
      }

      // Watchlist mobile_app names: flag permutation domains that match app name patterns
      const watchlistApps = watchlistItems.filter(w => w.type === "mobile_app").map(w => w.value.toLowerCase());
      for (const appName of watchlistApps) {
        const appSlug = appName.replace(/\s+/g, "").toLowerCase();
        const hit = liveResults.find(r => r.permutation.toLowerCase().includes(appSlug));
        if (hit) {
          abuseInserts.push({
            tenantId,
            scanId,
            type: "fake_app",
            platform: "App Store",
            url: `http://${hit.permutation}`,
            title: `Mobile app name match: ${hit.permutation}`,
            description: `Watchlist mobile app "${appName}" name pattern found in live lookalike domain ${hit.permutation}`,
            risk: "high",
          });
        }
      }

      if (abuseInserts.length > 0) {
        // Mark newly-discovered brand abuse items (keyed by title+type — not seen in previous scan)
        if (prevSnapshot?.brandAbuseKeys) {
          for (const a of abuseInserts) {
            const key = `${a.title ?? ""}::${a.type}`;
            (a as any).isNew = !prevSnapshot.brandAbuseKeys.has(key);
          }
        }
        for (let i = 0; i < abuseInserts.length; i += 50) {
          await db.insert(brandAbuseResultsTable).values(abuseInserts.slice(i, i + 50));
        }
        brandAbuseCount = abuseInserts.length;

        // ── Lookalike live count + abuse.ch phishing check ──────────────────
        // Brand-abuse "lookalike_domain" entries are CONFIRMED live domains
        // (discovered via direct DNS resolution in brandAbuseScanner). Add them
        // to liveCount so the scan summary reflects the true threat count.
        // Also query abuse.ch (URLhaus + ThreatFox, no API key) for each one.
        const lookalikeDomainEntries = abuseInserts.filter(a => a.type === "lookalike_domain");
        if (lookalikeDomainEntries.length > 0) {
          liveCount += lookalikeDomainEntries.length;
          const lookalikeDomains = lookalikeDomainEntries
            .map(a => String(a.url ?? "").replace(/^https?:\/\//, "").split("/")[0]!)
            .filter(Boolean);
          const abusechHits: Awaited<ReturnType<typeof queryAbuseChFeeds>> = [];
          for (const dom of lookalikeDomains) {
            const hits = await queryAbuseChFeeds(dom).catch(() => []);
            abusechHits.push(...hits);
          }
          if (abusechHits.length > 0) {
            const extraPhishInserts: typeof phishingDetectionsTable.$inferInsert[] = abusechHits.map(entry => ({
              tenantId,
              scanId,
              url: entry.url,
              source: entry.source,
              verified: true as boolean,
              targetBrand: domain,
              threatType: entry.threat.toUpperCase().replace(/[^A-Z0-9_]/g, "_"),
              submittedAt: entry.addedAt ?? new Date().toISOString(),
            }));
            for (let i = 0; i < extraPhishInserts.length; i += 50) {
              await db.insert(phishingDetectionsTable).values(extraPhishInserts.slice(i, i + 50));
            }
            phishingCount += abusechHits.length;
            logger.info({ scanId, domain, count: abusechHits.length }, "abuse.ch hits on lookalike_domain brand abuse entries");
          }
        }

        const worstAbuseRisk = abuseInserts.some(a => a.risk === "critical") ? "critical"
          : abuseInserts.some(a => a.risk === "high") ? "high" : "medium";
        const uniquePlatforms = [...new Set(abuseInserts.map(a => a.platform).filter(Boolean))];
        void dispatchNotifications({
          tenantId,
          eventType: "brand_abuse_found",
          title: `Brand Abuse Detected: ${domain}`,
          message: `${abuseInserts.length} brand abuse instance${abuseInserts.length > 1 ? "s" : ""} found targeting "${domain}" across ${uniquePlatforms.length > 0 ? uniquePlatforms.join(", ") : "multiple platforms"}.`,
          severity: worstAbuseRisk,
          scanId,
          domain,
          sourceFeed: uniquePlatforms.join(", "),
          findingsCount: abuseInserts.length,
        });
      }
    }

    // ── Phase 6: Malicious ad monitoring (Meta Ads Library) ──────────────────
    let adMonitoringCount = 0;
    if (metaAdsList.length > 0) {
      const adInserts: typeof adMonitoringResultsTable.$inferInsert[] = metaAdsList.map(ad => ({
        tenantId,
        scanId,
        platform: "Meta Ads",
        adId: ad.adId ?? undefined,
        adType: ad.adType ?? undefined,
        title: ad.title ?? undefined,
        body: ad.body ?? undefined,
        advertiserName: ad.advertiserName ?? undefined,
        advertiserPage: ad.advertiserPage ?? undefined,
        impressions: ad.impressions ?? undefined,
        spend: ad.spend ?? undefined,
        currency: ad.currency ?? undefined,
        startDate: ad.startDate ?? undefined,
        endDate: ad.endDate ?? undefined,
        deliveryCountries: ad.deliveryCountries?.length ? ad.deliveryCountries : undefined,
        snapshotUrl: ad.snapshotUrl ?? undefined,
        risk: ad.risk,
        // Mark as new if the adId or title+platform key wasn't in the previous scan
        isNew: prevSnapshot?.adKeys
          ? !prevSnapshot.adKeys.has(ad.adId ?? `${ad.title ?? ""}::Meta Ads`)
          : false,
      }));
      for (let i = 0; i < adInserts.length; i += 50) {
        await db.insert(adMonitoringResultsTable).values(adInserts.slice(i, i + 50));
      }
      adMonitoringCount = adInserts.length;
      logger.info({ scanId, domain, adMonitoringCount }, "Meta Ads monitoring results inserted");
    }

    await db.update(brandThreatScansTable).set({ progress: 95 }).where(eq(brandThreatScansTable.id, scanId));

    // ── Final update ─────────────────────────────────────────────────────────
    const phishingRisk =
      phishingCount > 5 || liveCount > 20 ? "critical" :
      phishingCount > 2 || liveCount > 10 ? "high" :
      liveCount > 3 ? "medium" : "low";

    await db.update(brandThreatScansTable).set({
      status: "done",
      progress: 100,
      liveCount,
      registeredCount,
      phishingRisk,
      fuzzerBreakdown,
      dataLeakCount,
      phishingCount,
      brandAbuseCount,
      adMonitoringCount,
      completedAt: new Date(),
      lastScannedAt: new Date(),
      checkpoint: null,
      permutationsCache: null,
      scanWarnings: socialWarnings.length > 0 ? (socialWarnings as any) : null,
    }).where(eq(brandThreatScansTable.id, scanId));

    // ── Scan completion notification (fires alert rules with triggerType "brand_threat") ──
    const totalFindings = liveCount + phishingCount + dataLeakCount + (brandAbuseCount + adMonitoringCount);
    void dispatchNotifications({
      tenantId,
      eventType: "brand_threat",
      title: `Brand Threat Scan Complete: ${domain}`,
      message: totalFindings > 0
        ? `Scan for "${domain}" complete — ${liveCount} live lookalike${liveCount !== 1 ? "s" : ""}${phishingCount ? `, ${phishingCount} phishing URL${phishingCount !== 1 ? "s" : ""}` : ""}${dataLeakCount ? `, ${dataLeakCount} data leak${dataLeakCount !== 1 ? "s" : ""}` : ""}${brandAbuseCount + adMonitoringCount ? `, ${brandAbuseCount + adMonitoringCount} brand abuse instance${brandAbuseCount + adMonitoringCount !== 1 ? "s" : ""}` : ""} detected.`
        : `Scan for "${domain}" complete — no active threats detected.`,
      severity: phishingRisk as "critical" | "high" | "medium" | "low",
      scanId,
      domain,
      findingsCount: totalFindings,
    });

    logger.info(
      { scanId, domain, liveCount, registeredCount, phishingCount, dataLeakCount, brandAbuseCount, faviconFound: !!faviResult },
      "Advanced brand threat scan completed",
    );
  } catch (err) {
    logger.error({ err, scanId }, "Brand threat scan failed");
    await db.update(brandThreatScansTable).set({
      status: "error",
      error: String(err),
      completedAt: new Date(),
    }).where(eq(brandThreatScansTable.id, scanId));
  }
}

// ── Auto-trigger helper (used by pipeline scans & asset scans) ────────────────

const STUCK_SCAN_THRESHOLD_MS = 120 * 60 * 1000; // 2 hours — brand threat scans for large domains can take 40–90 min

// ── Subdomain takeover fingerprints ──────────────────────────────────────────
const TAKEOVER_FINGERPRINTS: Record<string, string> = {
  "github.io":              "GitHub Pages",
  "githubusercontent.com":  "GitHub Pages",
  "herokuapp.com":          "Heroku",
  "s3.amazonaws.com":       "AWS S3",
  "s3-website":             "AWS S3",
  "cloudfront.net":         "AWS CloudFront",
  "azurewebsites.net":      "Azure Web Apps",
  "cloudapp.net":           "Azure Cloud",
  "trafficmanager.net":     "Azure Traffic Manager",
  "azureedge.net":          "Azure CDN",
  "azurefd.net":            "Azure Front Door",
  "webflow.io":             "Webflow",
  "ghost.io":               "Ghost",
  "tumblr.com":             "Tumblr",
  "zendesk.com":            "Zendesk",
  "helpscoutdocs.com":      "HelpScout",
  "netlify.app":            "Netlify",
  "netlify.com":            "Netlify",
  "vercel.app":             "Vercel",
  "vercel.com":             "Vercel",
  "shopify.com":            "Shopify",
  "myshopify.com":          "Shopify",
  "hubspot.com":            "HubSpot",
  "hubspotpagebuilder.com": "HubSpot",
  "bitbucket.io":           "Bitbucket",
  "cargo.site":             "Cargo",
  "fastly.net":             "Fastly",
  "squarespace.com":        "Squarespace",
  "strikingly.com":         "Strikingly",
  "surge.sh":               "Surge",
  "wordpress.com":          "WordPress",
  "gitbook.io":             "GitBook",
  "readme.io":              "ReadMe",
  "acquia-sites.com":       "Acquia",
  "pantheonsite.io":        "Pantheon",
  "kinsta.cloud":           "Kinsta",
  "render.com":             "Render",
  "fly.dev":                "Fly.io",
  "pages.dev":              "Cloudflare Pages",
  "workers.dev":            "Cloudflare Workers",
  "wixsite.com":            "Wix",
  "weebly.com":             "Weebly",
  "freshdesk.com":          "Freshdesk",
  "helpjuice.com":          "Helpjuice",
  "smugmug.com":            "SmugMug",
  "statuspage.io":          "Statuspage",
  "pingdom.com":            "Pingdom",
};

/** High-value subdomain prefixes — more attractive targets for squatting / impersonation */
const HIGH_VALUE_PREFIXES = new Set([
  "login", "auth", "sso", "secure", "admin", "portal", "account",
  "payment", "pay", "billing", "checkout", "mail", "email",
  "vpn", "remote", "api", "app", "dashboard", "console",
  "signup", "register", "support", "help", "helpdesk",
]);

export interface SubdomainThreat {
  name:             string;
  takeoverRisk:     "high" | "medium" | "none";
  takeoverService?: string;
  cnameTarget?:     string;
  highValueTarget:  boolean;
  squattingNote?:   string;
}

/**
 * Analyse discovered subdomains for takeover risk and squatting exposure.
 * Uses CNAME data from the scan (already captured) and does a quick DNS
 * CNAME lookup for any subdomain that lacks CNAME data.
 * Results are intended to be cached in brand_threat_scans.subdomain_threats.
 */
export async function detectSubdomainThreats(
  subdomains: Array<{ name: string; ip?: string; cname?: string; status?: string }>,
  _rootDomain: string,
): Promise<SubdomainThreat[]> {
  const threats: SubdomainThreat[] = [];

  // Run CNAME lookups in parallel with a per-host timeout
  const withCnames = await Promise.all(
    subdomains.map(async sub => {
      let cnameTarget = sub.cname ?? null;
      if (!cnameTarget) {
        try {
          const cnames = await Promise.race([
            dns.resolveCname(sub.name),
            new Promise<string[]>((_, reject) => setTimeout(() => reject(new Error("timeout")), 1500)),
          ]) as string[];
          if (cnames.length > 0) cnameTarget = cnames[0]!;
        } catch {
          // No CNAME or timed out — skip DNS-based detection
        }
      }
      return { ...sub, resolvedCname: cnameTarget };
    }),
  );

  for (const sub of withCnames) {
    let takeoverRisk: "high" | "medium" | "none" = "none";
    let takeoverService: string | undefined;
    const cnameTarget = sub.resolvedCname ?? undefined;

    if (cnameTarget) {
      const lower = cnameTarget.toLowerCase();
      for (const [pattern, service] of Object.entries(TAKEOVER_FINGERPRINTS)) {
        if (lower.includes(pattern)) {
          takeoverRisk = "high";
          takeoverService = service;
          break;
        }
      }
      // CNAME to something not in our fingerprints but also not self — medium risk
      if (takeoverRisk === "none") {
        takeoverRisk = "medium";
        takeoverService = cnameTarget;
      }
    }

    // Check if this is a high-value squatting target
    const prefix = sub.name.split(".")[0]?.toLowerCase() ?? "";
    const highValueTarget = HIGH_VALUE_PREFIXES.has(prefix);
    const squattingNote = highValueTarget
      ? `"${prefix}" subdomains are high-value phishing targets — monitor for lookalike registrations like ${prefix}-${_rootDomain.split(".")[0]}.com`
      : undefined;

    threats.push({
      name:            sub.name,
      takeoverRisk,
      takeoverService: takeoverRisk !== "none" ? takeoverService : undefined,
      cnameTarget:     takeoverRisk !== "none" ? cnameTarget : undefined,
      highValueTarget,
      squattingNote,
    });
  }

  return threats;
}

/**
 * Upsert brand threat scan: reuse the existing row for this tenant+domain
 * (archiving old results for history) instead of creating a new row each time.
 * Returns null when a scan is already actively running.
 */
export async function triggerBrandThreatScan(
  tenantId: number,
  domain: string,
  pipelineScanId?: number,
): Promise<typeof brandThreatScansTable.$inferSelect | null> {
  // Find the most recent scan for this tenant+domain
  const [latest] = await db
    .select()
    .from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.tenantId, tenantId), eq(brandThreatScansTable.domain, domain)))
    .orderBy(desc(brandThreatScansTable.id))
    .limit(1);

  if (latest) {
    if (latest.status === "running" || latest.status === "pending") {
      const ageMs = Date.now() - new Date(latest.createdAt).getTime();
      if (latest.status === "running" && ageMs > STUCK_SCAN_THRESHOLD_MS) {
        logger.warn(
          { tenantId, domain, stuckScanId: latest.id, ageMinutes: Math.round(ageMs / 60_000) },
          "Brand threat scan stuck for >30 min — resetting to error and allowing rescan",
        );
        await db.update(brandThreatScansTable)
          .set({ status: "error", error: "Scan timed out: automatically reset after 30 minutes of inactivity", completedAt: new Date() })
          .where(eq(brandThreatScansTable.id, latest.id));
        // Fall through — run fresh scan on same ID
      } else {
        logger.info({ tenantId, domain, activeScanId: latest.id }, "Brand threat scan already in progress — skipping");
        return null;
      }
    }

    // Reuse existing scan row — archive live results to preserve history
    const now = new Date();
    await db.update(brandThreatResultsTable)
      .set({ archivedAt: now })
      .where(and(eq(brandThreatResultsTable.scanId, latest.id), isNull(brandThreatResultsTable.archivedAt)));
    await Promise.all([
      db.delete(phishingDetectionsTable).where(eq(phishingDetectionsTable.scanId, latest.id)),
      db.delete(dataLeakResultsTable).where(eq(dataLeakResultsTable.scanId, latest.id)),
      db.delete(brandAbuseResultsTable).where(eq(brandAbuseResultsTable.scanId, latest.id)),
      db.delete(adMonitoringResultsTable).where(eq(adMonitoringResultsTable.scanId, latest.id)),
    ]);
    // Reset createdAt to NOW so the watchdog calculates age from this restart,
    // not from the original scan creation time (which could be hours ago).
    await db.update(brandThreatScansTable).set({
      status:            "pending",
      progress:          0,
      error:             null,
      checkpoint:        null,
      permutationsCache: null,
      completedAt:       null,
      subdomainThreats:  null,
      liveCount:         0,
      registeredCount:   0,
      phishingCount:     0,
      dataLeakCount:     0,
      brandAbuseCount:   0,
      scanCount:         sql`scan_count + 1`,
      pipelineScanId:    pipelineScanId ?? latest.pipelineScanId,
      createdAt:         new Date(),
    }).where(eq(brandThreatScansTable.id, latest.id));

    logger.info(
      { scanId: latest.id, domain, scanCount: (latest.scanCount ?? 1) + 1, pipelineScanId },
      "Reusing existing brand threat scan row — old results archived for history",
    );
    setImmediate(() => { void runBrandThreatScan(latest.id, domain); });
    const [updated] = await db.select().from(brandThreatScansTable).where(eq(brandThreatScansTable.id, latest.id));
    return updated!;
  }

  // No existing scan — insert new row
  const [scan] = await db.insert(brandThreatScansTable).values({
    tenantId,
    domain,
    status:    "pending",
    scanCount: 1,
    pipelineScanId: pipelineScanId ?? null,
  }).returning();

  logger.info({ scanId: scan!.id, domain, pipelineScanId }, "New brand threat scan created");
  setImmediate(() => { void runBrandThreatScan(scan!.id, domain); });
  return scan!;
}

// ── Brand threat watchdog ──────────────────────────────────────────────────────

const WATCHDOG_POLL_INTERVAL_MS  = 5  * 60 * 1000;  // 5 minutes
const WATCHDOG_STUCK_THRESHOLD_MS = 120 * 60 * 1000; // 2 hours — brand threat scans for large domains can take 40–90 min

/**
 * Startup enrichment that runs three passes over brand threat scan data:
 *
 * Phase A — DNS backfill: finds "done" scans whose live_count is 0 (because
 * dnstwist's internal DNS resolver was blocked at scan time) and re-resolves
 * every result row using Node.js dns, then recalculates liveCount / registeredCount
 * / phishingRisk.
 *
 * Phase B — Phishing checks: for every "done" scan that now has live domains
 * (liveCount > 0) but whose phishingCount is still 0, runs PhishTank /
 * abuse.ch feed checks against the live permutations and updates phishingCount
 * (including any lookalike-domain brandAbuse entries that count as phishing
 * infrastructure).
 *
 * Phase C — Auto-rescan: for every "error" scan that has permutations in the
 * scan record but zero brand_threat_results rows (i.e. the scan crashed before
 * writing results), triggers a fresh rescan automatically.
 *
 * Runs entirely in the background — never blocks startup.
 */
export async function enrichStaleScans(): Promise<void> {
  try {

    // ── Phase A: DNS enrichment for done scans with liveCount = 0 ─────────────
    const staleScans = await db
      .select({
        id:                brandThreatScansTable.id,
        domain:            brandThreatScansTable.domain,
        phishingCount:     brandThreatScansTable.phishingCount,
        dataLeakCount:     brandThreatScansTable.dataLeakCount,
        brandAbuseCount:   brandThreatScansTable.brandAbuseCount,
        adMonitoringCount: brandThreatScansTable.adMonitoringCount,
      })
      .from(brandThreatScansTable)
      .where(
        and(
          eq(brandThreatScansTable.status, "done"),
          gt(brandThreatScansTable.totalPermutations, 0),
          eq(brandThreatScansTable.liveCount, 0),
        ),
      );

    if (staleScans.length > 0) {
      logger.info({ count: staleScans.length }, "Brand threat enrichment: Phase A — DNS backfill starting");

      for (const scan of staleScans) {
        try {
          const emptyRows = await db
            .select({
              id:              brandThreatResultsTable.id,
              permutation:     brandThreatResultsTable.permutation,
              fuzzer:          brandThreatResultsTable.fuzzer,
              vtMalicious:     brandThreatResultsTable.vtMalicious,
              vtSuspicious:    brandThreatResultsTable.vtSuspicious,
              isPhishing:      brandThreatResultsTable.isPhishing,
              phishingSource:  brandThreatResultsTable.phishingSource,
              whoisAgeDays:    brandThreatResultsTable.whoisAgeDays,
              geoCountry:      brandThreatResultsTable.geoCountry,
            })
            .from(brandThreatResultsTable)
            .where(and(
              eq(brandThreatResultsTable.scanId, scan.id),
              isNull(brandThreatResultsTable.dnsA),
              isNull(brandThreatResultsTable.archivedAt),
            ));

          if (emptyRows.length === 0) {
            logger.info({ scanId: scan.id }, "Brand threat enrichment: Phase A — no empty-DNS rows, skipping");
            continue;
          }

          logger.info({ scanId: scan.id, domain: scan.domain, rowCount: emptyRows.length },
            "Brand threat enrichment: Phase A — resolving DNS for empty rows");

          const dnsQueue = [...emptyRows];
          async function dnsWorker() {
            while (dnsQueue.length > 0) {
              const row = dnsQueue.shift();
              if (!row) break;
              const resolved = await checkDNSFull(row.permutation);
              if (resolved.dnsA.length === 0 && resolved.dnsAaaa.length === 0 &&
                  resolved.dnsMx.length === 0 && resolved.dnsNs.length === 0) continue;

              const registrationStatus =
                resolved.dnsA.length > 0  ? "active"     :
                resolved.dnsNs.length > 0 ? "parked"     :
                resolved.dnsMx.length > 0 ? "registered" : "unregistered";

              const riskScore = computeRisk(
                resolved.dnsA, resolved.dnsMx, resolved.dnsNs,
                row.fuzzer ?? "original", row.vtMalicious ?? 0, row.vtSuspicious ?? 0,
                row.isPhishing ?? false, row.phishingSource ?? null,
                row.whoisAgeDays ?? null, row.geoCountry ?? null, null, [],
              );

              await db.update(brandThreatResultsTable)
                .set({
                  dnsA:               resolved.dnsA.length    ? resolved.dnsA    : undefined,
                  dnsAaaa:            resolved.dnsAaaa.length  ? resolved.dnsAaaa : undefined,
                  dnsMx:              resolved.dnsMx.length    ? resolved.dnsMx   : undefined,
                  dnsNs:              resolved.dnsNs.length    ? resolved.dnsNs   : undefined,
                  registrationStatus, riskScore,
                  isSuspicious: riskScore >= 60,
                })
                .where(eq(brandThreatResultsTable.id, row.id));
            }
          }
          await Promise.all(Array.from({ length: 20 }, () => dnsWorker()));

          const updatedRows = await db
            .select({ dnsA: brandThreatResultsTable.dnsA, dnsMx: brandThreatResultsTable.dnsMx })
            .from(brandThreatResultsTable)
            .where(and(eq(brandThreatResultsTable.scanId, scan.id), isNull(brandThreatResultsTable.archivedAt)));

          const newLiveCount       = updatedRows.filter(r => r.dnsA && r.dnsA.length > 0).length;
          const newRegisteredCount = updatedRows.filter(r =>
            (r.dnsA && r.dnsA.length > 0) || (r.dnsMx && r.dnsMx.length > 0)).length;
          const storedPhishing     = scan.phishingCount ?? 0;
          const phishingRisk =
            storedPhishing > 5 || newLiveCount > 20 ? "critical" :
            storedPhishing > 2 || newLiveCount > 10 ? "high"     :
            newLiveCount > 3                         ? "medium"   : "low";

          await db.update(brandThreatScansTable)
            .set({ liveCount: newLiveCount, registeredCount: newRegisteredCount, phishingRisk })
            .where(eq(brandThreatScansTable.id, scan.id));

          logger.info({ scanId: scan.id, domain: scan.domain, newLiveCount, newRegisteredCount, phishingRisk },
            "Brand threat enrichment: Phase A — scan updated");
        } catch (scanErr) {
          logger.warn({ err: scanErr, scanId: scan.id }, "Brand threat enrichment: Phase A — failed for scan, skipping");
        }
      }
    } else {
      logger.info("Brand threat enrichment: Phase A — no stale scans found");
    }

    // ── Phase B: Phishing checks for live scans whose phishingCount is still 0 ─
    // These are scans where liveCount > 0 but runPhishingChecks() never ran
    // for the live domains (because they were all dnsA=null during the original
    // scan). Also updates phishingCount to include lookalike-domain brandAbuse entries.
    const scansForPhishCheck = await db
      .select({
        id:       brandThreatScansTable.id,
        tenantId: brandThreatScansTable.tenantId,
        domain:   brandThreatScansTable.domain,
      })
      .from(brandThreatScansTable)
      .where(and(
        eq(brandThreatScansTable.status, "done"),
        gt(brandThreatScansTable.liveCount, 0),
        eq(brandThreatScansTable.phishingCount, 0),
      ));

    if (scansForPhishCheck.length > 0) {
      logger.info({ count: scansForPhishCheck.length }, "Brand threat enrichment: Phase B — phishing checks starting");

      for (const scan of scansForPhishCheck) {
        try {
          // Fetch live result rows (dnsA IS NOT NULL means at least one IP resolved)
          const liveRows = await db
            .select({ id: brandThreatResultsTable.id, permutation: brandThreatResultsTable.permutation })
            .from(brandThreatResultsTable)
            .where(and(
              eq(brandThreatResultsTable.scanId, scan.id),
              isNotNull(brandThreatResultsTable.dnsA),
              isNull(brandThreatResultsTable.archivedAt),
            ));

          const phishingInserts: typeof phishingDetectionsTable.$inferInsert[] = [];
          const PHISH_CONCURRENCY = 5;
          const phishQueue = [...liveRows];

          async function phishWorker() {
            while (phishQueue.length > 0) {
              const row = phishQueue.shift();
              if (!row) break;

              // PhishTank / OpenPhish check
              const feedResult = await checkPhishingFeed(row.permutation).catch(() => null);
              if (feedResult?.isPhishing) {
                phishingInserts.push({
                  tenantId: scan.tenantId,
                  scanId:   scan.id,
                  url:      `http://${row.permutation}`,
                  source:   feedResult.source ?? "PhishTank",
                  verified: true,
                  targetBrand: scan.domain,
                  threatType:  "SOCIAL_ENGINEERING",
                  submittedAt: new Date().toISOString(),
                });
                await db.update(brandThreatResultsTable)
                  .set({ isPhishing: true, phishingSource: feedResult.source ?? "PhishTank" })
                  .where(eq(brandThreatResultsTable.id, row.id));
              }

              // abuse.ch URLhaus + ThreatFox check
              const abuseHits = await queryAbuseChFeeds(row.permutation).catch(() => []);
              for (const hit of abuseHits) {
                phishingInserts.push({
                  tenantId: scan.tenantId,
                  scanId:   scan.id,
                  url:      hit.url,
                  source:   hit.source,
                  verified: true,
                  targetBrand: scan.domain,
                  threatType:  hit.threat.toUpperCase().replace(/[^A-Z0-9_]/g, "_"),
                  submittedAt: hit.addedAt ?? new Date().toISOString(),
                });
              }
            }
          }
          await Promise.all(Array.from({ length: PHISH_CONCURRENCY }, () => phishWorker()));

          // Insert confirmed phishing detections (if any)
          if (phishingInserts.length > 0) {
            for (let i = 0; i < phishingInserts.length; i += 50) {
              await db.insert(phishingDetectionsTable).values(phishingInserts.slice(i, i + 50));
            }
            logger.info({ scanId: scan.id, domain: scan.domain, count: phishingInserts.length },
              "Brand threat enrichment: Phase B — phishing detections inserted");
          }

          // Count lookalike-domain brandAbuse entries — these represent live domains that
          // impersonate the brand and count toward the phishing threat picture
          const lookalikeDomains = await db
            .select({ id: brandAbuseResultsTable.id })
            .from(brandAbuseResultsTable)
            .where(and(
              eq(brandAbuseResultsTable.scanId, scan.id),
              eq(brandAbuseResultsTable.type, "lookalike_domain"),
            ));

          const newPhishingCount = phishingInserts.length + lookalikeDomains.length;
          if (newPhishingCount > 0) {
            // Recompute phishingRisk with updated phishing count
            const [scanRow] = await db
              .select({ liveCount: brandThreatScansTable.liveCount })
              .from(brandThreatScansTable)
              .where(eq(brandThreatScansTable.id, scan.id));
            const liveCount = scanRow?.liveCount ?? 0;
            const phishingRisk =
              newPhishingCount > 5 || liveCount > 20 ? "critical" :
              newPhishingCount > 2 || liveCount > 10 ? "high"     :
              liveCount > 3                           ? "medium"   : "low";

            await db.update(brandThreatScansTable)
              .set({ phishingCount: newPhishingCount, phishingRisk })
              .where(eq(brandThreatScansTable.id, scan.id));
            logger.info({ scanId: scan.id, domain: scan.domain, newPhishingCount, phishingRisk },
              "Brand threat enrichment: Phase B — phishingCount updated");
          } else {
            logger.info({ scanId: scan.id, domain: scan.domain },
              "Brand threat enrichment: Phase B — no phishing found (correct: not in feeds)");
          }
        } catch (scanErr) {
          logger.warn({ err: scanErr, scanId: scan.id }, "Brand threat enrichment: Phase B — failed for scan, skipping");
        }
      }
    } else {
      logger.info("Brand threat enrichment: Phase B — no live scans need phishing checks");
    }

    // ── Phase C: Auto-rescan error scans that have permutations but no results ─
    // This happens when the scan was killed mid-run (e.g. server restart) before
    // Phase 3 (bulk INSERT brand_threat_results). The permutation count is stored
    // on the scan record but no rows were ever written.
    const errorScans = await db
      .select({
        id:       brandThreatScansTable.id,
        tenantId: brandThreatScansTable.tenantId,
        domain:   brandThreatScansTable.domain,
      })
      .from(brandThreatScansTable)
      .where(and(
        eq(brandThreatScansTable.status, "error"),
        gt(brandThreatScansTable.totalPermutations, 0),
      ));

    let autoRescanned = 0;
    for (const scan of errorScans) {
      try {
        // Check if any ACTIVE (non-archived) brand_threat_results rows exist.
        // Archived rows from a previous scan run don't count — those were
        // preserved for history but aren't shown to the user.
        const [firstResult] = await db
          .select({ id: brandThreatResultsTable.id })
          .from(brandThreatResultsTable)
          .where(and(
            eq(brandThreatResultsTable.scanId, scan.id),
            isNull(brandThreatResultsTable.archivedAt),
          ))
          .limit(1);

        if (!firstResult) {
          // No results — trigger a fresh rescan automatically
          logger.info({ scanId: scan.id, domain: scan.domain },
            "Brand threat enrichment: Phase C — auto-rescanning error scan with no results");
          await triggerBrandThreatScan(scan.tenantId, scan.domain);
          autoRescanned++;
          // Brief pause between triggers to avoid flooding the scan queue
          await new Promise(r => setTimeout(r, 2000));
        }
      } catch (scanErr) {
        logger.warn({ err: scanErr, scanId: scan.id }, "Brand threat enrichment: Phase C — failed for scan, skipping");
      }
    }
    if (autoRescanned > 0) {
      logger.info({ count: autoRescanned }, "Brand threat enrichment: Phase C — auto-rescanned error scans");
    } else {
      logger.info("Brand threat enrichment: Phase C — no error scans need rescanning");
    }

    logger.info("Brand threat enrichment: all phases completed");

    // ── Phase D: DNS backfill for archived results missing registration data ──
    // Runs fire-and-forget so it doesn't block startup or the main phases.
    // Finds archived rows with no dns_a and no registration_status and re-resolves
    // DNS to populate registration_status, risk_score, and is_phishing so that
    // the "Previous Scan Rounds" history table shows accurate Registered / High
    // Risk / Phishing counts instead of all dashes.
    setImmediate(() => { void backfillArchivedDns(); });

  } catch (err) {
    logger.warn({ err }, "Brand threat enrichment: failed (non-fatal)");
  }
}

/**
 * Phase D — retroactive DNS backfill for archived brand_threat_results rows
 * that have no dns_a and no registration_status.  These rows were written by
 * older scan runs before DNS enrichment was reliable.  Re-resolving DNS now
 * lets the "Previous Scan Rounds" history card show real Registered / High Risk
 * / Phishing counts.
 *
 * Processes up to MAX_BACKFILL rows per run with 20 concurrent DNS workers.
 * Runs entirely in the background — never blocks startup.
 */
async function backfillArchivedDns(): Promise<void> {
  const MAX_BACKFILL = 5000;
  const DNS_CONCURRENCY = 20;
  try {
    // Find archived rows that have no dns_a AND no registration_status.
    // We include vtMalicious/vtSuspicious/isPhishing/fuzzer/whoisAgeDays so
    // we can recompute a proper risk score after DNS resolves.
    // Target archived rows from old scans where DNS resolution was broken:
    // these have dns_a = NULL (no IP ever resolved) AND registration_status =
    // 'unregistered' (set by old code that couldn't reach external DNS).
    // We only re-enrich rows from scan rounds where ZERO domains are registered —
    // a statistical impossibility for a real domain, meaning DNS was fully blocked.
    // To avoid unbounded work, cap at MAX_BACKFILL rows and limit to 200 per scan.
    // Find scan IDs that have archived rounds where EVERY domain is 'unregistered'
    // and has no DNS A record — this indicates the DNS resolver was blocked during
    // that old scan run (a statistical impossibility for real domain portfolios).
    const corruptRounds = await db.execute<{ scanId: number }>(sql`
      SELECT DISTINCT rounds.scan_id AS "scanId"
      FROM (
        SELECT scan_id,
               date_trunc('minute', archived_at) AS bucket,
               COUNT(*)                                                                                 AS total,
               COUNT(CASE WHEN dns_a IS NULL OR cardinality(dns_a) = 0 THEN 1 END)                    AS no_dns_a,
               COUNT(CASE WHEN registration_status IN ('active','parked','registered') THEN 1 END)     AS registered_cnt
        FROM brand_threat_results
        WHERE archived_at IS NOT NULL
        GROUP BY scan_id, bucket
      ) rounds
      WHERE rounds.total > 50
        AND rounds.registered_cnt = 0
        AND rounds.no_dns_a > 0
    `);

    if (corruptRounds.rows.length === 0) {
      logger.info("Brand threat enrichment: Phase D — no archived rows need DNS backfill");
      return;
    }

    // Now find the exact (scan_id, bucket) pairs that are corrupt so we can
    // sample up to ROWS_PER_ROUND rows from EACH corrupt round independently.
    // This prevents all 200-per-scan rows from landing in a single bucket.
    const corruptBuckets = await db.execute<{ scanId: number; bucket: Date }>(sql`
      SELECT scan_id AS "scanId", bucket
      FROM (
        SELECT scan_id,
               date_trunc('minute', archived_at) AS bucket,
               COUNT(*)                                                                             AS total,
               COUNT(CASE WHEN dns_a IS NULL OR cardinality(dns_a) = 0 THEN 1 END)                AS no_dns_a,
               COUNT(CASE WHEN registration_status IN ('active','parked','registered') THEN 1 END) AS registered_cnt
        FROM brand_threat_results
        WHERE archived_at IS NOT NULL
        GROUP BY scan_id, bucket
      ) rounds
      WHERE rounds.total > 50
        AND rounds.registered_cnt = 0
        AND rounds.no_dns_a > 0
    `);

    const ROWS_PER_ROUND = 200;
    logger.info(
      { bucketCount: corruptBuckets.rows.length },
      "Brand threat enrichment: Phase D — found corrupt archived rounds to backfill",
    );

    // Collect up to ROWS_PER_ROUND rows from EACH corrupt round
    const allRows: Array<{
      id: number; permutation: string; fuzzer: string | null;
      vtMalicious: number | null; vtSuspicious: number | null;
      isPhishing: boolean | null; phishingSource: string | null;
      whoisAgeDays: number | null; geoCountry: string | null;
    }> = [];

    for (const { scanId, bucket } of corruptBuckets.rows) {
      const bucketRows = await db
        .select({
          id:             brandThreatResultsTable.id,
          permutation:    brandThreatResultsTable.permutation,
          fuzzer:         brandThreatResultsTable.fuzzer,
          vtMalicious:    brandThreatResultsTable.vtMalicious,
          vtSuspicious:   brandThreatResultsTable.vtSuspicious,
          isPhishing:     brandThreatResultsTable.isPhishing,
          phishingSource: brandThreatResultsTable.phishingSource,
          whoisAgeDays:   brandThreatResultsTable.whoisAgeDays,
          geoCountry:     brandThreatResultsTable.geoCountry,
        })
        .from(brandThreatResultsTable)
        .where(and(
          eq(brandThreatResultsTable.scanId, scanId),
          isNotNull(brandThreatResultsTable.archivedAt),
          sql`date_trunc('minute', ${brandThreatResultsTable.archivedAt}) = ${bucket}`,
          isNull(brandThreatResultsTable.dnsA),
        ))
        .limit(ROWS_PER_ROUND);
      allRows.push(...bucketRows);
      if (allRows.length >= MAX_BACKFILL) break;
    }

    const rows = allRows.slice(0, MAX_BACKFILL);

    if (rows.length === 0) {
      logger.info("Brand threat enrichment: Phase D — no archived rows need DNS backfill");
      return;
    }

    logger.info({ count: rows.length }, "Brand threat enrichment: Phase D — starting DNS backfill for archived rows");

    // Load CDN ranges once for risk score computation
    const cdnRanges = await loadCdnRangesFromDb().catch(() => [] as Array<{ start: number; end: number; label: string }>);

    let updated = 0;
    let skipped = 0;
    const queue = [...rows];

    async function worker(): Promise<void> {
      while (queue.length > 0) {
        const row = queue.shift();
        if (!row) break;
        try {
          const resolved = await checkDNSFull(row.permutation);

          // If still no DNS response, mark as unregistered so we don't retry
          // every startup (set registration_status = 'unregistered', keep dns_a null).
          if (
            resolved.dnsA.length === 0 &&
            resolved.dnsAaaa.length === 0 &&
            resolved.dnsMx.length === 0 &&
            resolved.dnsNs.length === 0
          ) {
            await db.update(brandThreatResultsTable)
              .set({ registrationStatus: "unregistered" })
              .where(eq(brandThreatResultsTable.id, row.id));
            skipped++;
            continue;
          }

          const registrationStatus =
            resolved.dnsA.length > 0  ? "active"     :
            resolved.dnsNs.length > 0 ? "parked"     :
            resolved.dnsMx.length > 0 ? "registered" : "unregistered";

          const riskScore = computeRisk(
            resolved.dnsA,
            resolved.dnsMx,
            resolved.dnsNs,
            row.fuzzer ?? "original",
            row.vtMalicious ?? 0,
            row.vtSuspicious ?? 0,
            row.isPhishing ?? false,
            row.phishingSource ?? null,
            row.whoisAgeDays ?? null,
            row.geoCountry ?? null,
            null,
            cdnRanges,
          );

          await db.update(brandThreatResultsTable)
            .set({
              dnsA:               resolved.dnsA.length    ? resolved.dnsA    : undefined,
              dnsAaaa:            resolved.dnsAaaa.length ? resolved.dnsAaaa : undefined,
              dnsMx:              resolved.dnsMx.length   ? resolved.dnsMx   : undefined,
              dnsNs:              resolved.dnsNs.length   ? resolved.dnsNs   : undefined,
              registrationStatus,
              riskScore,
              isSuspicious:       riskScore >= 60,
            })
            .where(eq(brandThreatResultsTable.id, row.id));
          updated++;
        } catch {
          // Skip individual failures silently — DNS lookups can time out
          skipped++;
        }
      }
    }

    await Promise.all(Array.from({ length: DNS_CONCURRENCY }, () => worker()));

    logger.info(
      { updated, skipped, total: rows.length },
      "Brand threat enrichment: Phase D — archived DNS backfill complete",
    );

    // If we hit the MAX_BACKFILL cap, schedule another pass after 30s
    if (rows.length >= MAX_BACKFILL) {
      logger.info("Brand threat enrichment: Phase D — more rows remain, scheduling follow-up pass");
      setTimeout(() => { void backfillArchivedDns(); }, 30_000);
    }
  } catch (err) {
    logger.warn({ err }, "Brand threat enrichment: Phase D — backfill failed (non-fatal)");
  }
}

/**
 * Periodic watchdog that catches brand threat scans stuck in "running" state
 * mid-run (e.g. dnstwist subprocess hang, VT API timeout) without requiring
 * a server restart.
 *
 * Every 5 minutes it queries for scans in "running" state whose `createdAt`
 * is older than 30 minutes and resets them to "error" with `completedAt` set.
 *
 * Returns a cleanup function that clears the interval (call on SIGTERM/SIGINT).
 */
export function startBrandThreatWatchdog(): () => void {
  async function tick(): Promise<void> {
    try {
      const threshold = new Date(Date.now() - WATCHDOG_STUCK_THRESHOLD_MS);
      const stuckScans = await db
        .select({ id: brandThreatScansTable.id, domain: brandThreatScansTable.domain, createdAt: brandThreatScansTable.createdAt })
        .from(brandThreatScansTable)
        .where(
          and(
            eq(brandThreatScansTable.status, "running"),
            lt(brandThreatScansTable.createdAt, threshold),
          ),
        );

      if (stuckScans.length === 0) return;

      logger.warn({ count: stuckScans.length }, "Brand threat watchdog: found stuck scans — resetting to error");

      for (const scan of stuckScans) {
        const ageMinutes = Math.round((Date.now() - new Date(scan.createdAt).getTime()) / 60_000);
        logger.warn(
          { scanId: scan.id, domain: scan.domain, ageMinutes },
          "Brand threat watchdog: scan stuck >30 min — marking as error",
        );
        await db
          .update(brandThreatScansTable)
          .set({
            status: "error",
            error: `Scan timed out: still in 'running' state after ${ageMinutes} minutes (watchdog)`,
            completedAt: new Date(),
          })
          .where(
            and(
              eq(brandThreatScansTable.id, scan.id),
              eq(brandThreatScansTable.status, "running"),
            ),
          );
      }
    } catch (err) {
      logger.warn({ err }, "Brand threat watchdog tick failed (non-fatal)");
    }
  }

  const handle = setInterval(() => { void tick(); }, WATCHDOG_POLL_INTERVAL_MS);

  logger.info(
    { intervalMinutes: WATCHDOG_POLL_INTERVAL_MS / 60_000, thresholdMinutes: WATCHDOG_STUCK_THRESHOLD_MS / 60_000 },
    "Brand threat watchdog started",
  );

  return () => {
    clearInterval(handle);
    logger.info("Brand threat watchdog stopped");
  };
}
