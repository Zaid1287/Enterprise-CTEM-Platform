import { execFile } from "child_process";
import { promisify } from "util";
import path from "path";
import dns from "node:dns/promises";
import { eq, and, gte, isNotNull } from "drizzle-orm";
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
  try {
    logger.info({ domain }, "Running dnstwist binary for brand threat scan");
    const results = await runDnstwistBinary(domain);
    logger.info({ domain, count: results.length }, "dnstwist completed");
    return results;
  } catch (err) {
    logger.warn({ err, domain }, "dnstwist binary unavailable — falling back to built-in engine");
    return runBuiltinEngine(domain);
  }
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

export async function runBrandThreatScan(scanId: number, domain: string, resumeFromPhase1Cache?: PermResult[]): Promise<void> {
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

      // Clear any partial secondary data written before the server was restarted
      await Promise.all([
        db.delete(brandThreatResultsTable).where(eq(brandThreatResultsTable.scanId, scanId)),
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
      });

      if (pendingInserts.length >= 50) await flushBatch();
    }
    await flushBatch();

    await db.update(brandThreatScansTable).set({ progress: 65 }).where(eq(brandThreatScansTable.id, scanId));

    // ── Phase 3b: Screenshots for high-risk domains (score ≥ 70) ─────────────
    try {
      const highRiskRows = await db
        .select({ id: brandThreatResultsTable.id, permutation: brandThreatResultsTable.permutation })
        .from(brandThreatResultsTable)
        .where(and(
          eq(brandThreatResultsTable.scanId, scanId),
          gte(brandThreatResultsTable.riskScore, 70),
          isNotNull(brandThreatResultsTable.dnsA),
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

    const youtubeApiKey  = await getPlatformSetting("youtube_api_key");
    const metaAdsToken   = await getPlatformSetting("meta_ads_access_token");

    const [hibpResult, brandAbuseList, metaAdsList] = await Promise.all([
      hibpDomainLookup(domain, hibpKey ?? undefined),  // always runs; without key uses public /breaches fallback
      scanBrandAbuse(brandName, domain, watchlistItems.filter(w => w.type === "social_handle").map(w => w.value), youtubeApiKey ?? undefined),
      metaAdsToken ? scanMetaAds(brandName, domain, metaAdsToken) : Promise.resolve([]),
    ]);
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
        for (let i = 0; i < abuseInserts.length; i += 50) {
          await db.insert(brandAbuseResultsTable).values(abuseInserts.slice(i, i + 50));
        }
        brandAbuseCount = abuseInserts.length;
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
      brandAbuseCount: brandAbuseCount + adMonitoringCount,
      completedAt: new Date(),
      checkpoint: null,
      permutationsCache: null,
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

export async function triggerBrandThreatScan(
  tenantId: number,
  domain: string,
  pipelineScanId?: number,
): Promise<typeof brandThreatScansTable.$inferSelect | null> {
  const existing = await db
    .select({ id: brandThreatScansTable.id, status: brandThreatScansTable.status })
    .from(brandThreatScansTable)
    .where(and(
      eq(brandThreatScansTable.tenantId, tenantId),
      eq(brandThreatScansTable.domain, domain),
    ));

  const active = existing.find(s => s.status === "running" || s.status === "pending");
  if (active) {
    logger.info({ tenantId, domain, activeScanId: active.id }, "Brand threat scan already in progress — skipping auto-trigger");
    return null;
  }

  const [scan] = await db.insert(brandThreatScansTable).values({
    tenantId,
    domain,
    status: "pending",
    pipelineScanId: pipelineScanId ?? null,
  }).returning();

  logger.info({ scanId: scan!.id, domain, pipelineScanId }, "Auto-triggered brand threat scan from pipeline");
  setImmediate(() => { void runBrandThreatScan(scan!.id, domain); });
  return scan!;
}
