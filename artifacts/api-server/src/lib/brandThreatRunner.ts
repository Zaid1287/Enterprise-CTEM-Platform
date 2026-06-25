import { execFile } from "child_process";
import { promisify } from "util";
import { fileURLToPath } from "url";
import path from "path";
import dns from "node:dns/promises";
import { eq, and } from "drizzle-orm";
import {
  db,
  brandThreatScansTable, brandThreatResultsTable,
  dataLeakResultsTable, phishingDetectionsTable, brandAbuseResultsTable,
} from "@workspace/db";
import { logger } from "./logger";
import { rdapLookup } from "./rdapClient";
import { geoIpBatch } from "./geoIpClient";
import { checkPhishingFeed } from "./phishFeedClient";
import { checkGoogleSafeBrowsing } from "./googleSafeBrowsing";
import { hibpDomainLookup, severityFromBreach } from "./hibpClient";
import { vtDomainLookup } from "./vtDomainClient";
import { scanBrandAbuse } from "./brandAbuseScanner";
import { getPlatformSetting } from "../routes/platformSettings";

const execFileAsync = promisify(execFile);

const WRAPPER_SCRIPT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "../scripts/favihunter_wrapper.py",
);

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

interface PermResult {
  permutation: string;
  fuzzer: string;
  dnsA: string[];
  dnsAaaa: string[];
  dnsMx: string[];
  dnsNs: string[];
}

async function runDnstwistBinary(domain: string): Promise<PermResult[]> {
  const cp = await import("child_process");
  const { stdout } = await promisify(cp.exec)(
    `dnstwist --format json --threads 20 ${domain}`,
    { timeout: 180_000, maxBuffer: 20 * 1024 * 1024 },
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

function computeRisk(
  dnsA: string[],
  dnsMx: string[],
  fuzzer: string,
  vtMalicious: number,
  isPhishing: boolean,
  whoisAgeDays: number | null,
): number {
  let score = 0;
  if (dnsA.length > 0) score += 35;
  if (dnsMx.length > 0) score += 25;
  if (isPhishing) score += 30;
  if (vtMalicious > 0) score += Math.min(20, vtMalicious * 3);
  if (["homoglyph","replacement","transposition","bitsquatting"].includes(fuzzer)) score += 10;
  if (["subdomain","hyphenation"].includes(fuzzer)) score += 5;
  if (whoisAgeDays !== null && whoisAgeDays < 90) score += 10;
  return Math.min(100, score);
}

// ── Phase helpers ─────────────────────────────────────────────────────────────

async function runRdapEnrichment(
  liveResults: PermResult[],
): Promise<Map<string, Awaited<ReturnType<typeof rdapLookup>>>> {
  const rdapMap = new Map<string, Awaited<ReturnType<typeof rdapLookup>>>();
  const RDAP_CONCURRENCY = 5;
  const queue = [...liveResults];

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

  const VT_CONCURRENCY = 4;
  const VT_DELAY_MS = 1500;
  const queue = [...liveResults];

  async function worker() {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) break;
      await new Promise(r => setTimeout(r, VT_DELAY_MS));
      const result = await vtDomainLookup(item.permutation, vtApiKey);
      if (result) vtMap.set(item.permutation, result);
    }
  }

  await Promise.all(Array.from({ length: VT_CONCURRENCY }, () => worker()));
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

export async function runBrandThreatScan(scanId: number, domain: string): Promise<void> {
  try {
    await db.update(brandThreatScansTable)
      .set({ status: "running", favihunterStatus: "running" })
      .where(eq(brandThreatScansTable.id, scanId));

    logger.info({ scanId, domain }, "Starting advanced brand threat scan");

    const [vtApiKey, gsbKey, hibpKey] = await Promise.all([
      getPlatformSetting("virustotal_api_key"),
      getPlatformSetting("google_safe_browsing_key"),
      getPlatformSetting("hibp_api_key"),
    ]);

    // ── Phase 1: Permutations + favihunter in parallel ────────────────────────
    const [permResults, faviResult] = await Promise.all([
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

    await db.update(brandThreatScansTable)
      .set({ totalPermutations: permResults.length })
      .where(eq(brandThreatScansTable.id, scanId));

    // Only enrich domains that are actually live (have A records)
    const liveResults = permResults.filter(r => r.dnsA.length > 0);

    logger.info({ scanId, domain, total: permResults.length, live: liveResults.length }, "Permutation phase done; starting enrichment");

    // ── Phase 2: RDAP + GeoIP + VT + Phishing checks in parallel ─────────────
    const allIps = [...new Set(liveResults.flatMap(r => r.dnsA))];

    const [rdapMap, geoMap, vtMap, phishMap] = await Promise.all([
      runRdapEnrichment(liveResults),
      geoIpBatch(allIps),
      vtApiKey ? runVtEnrichment(liveResults, vtApiKey) : Promise.resolve(new Map()),
      runPhishingChecks(liveResults, gsbKey),
    ]);

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
      const isPhishing = phish?.isPhishing ?? false;

      const riskScore = computeRisk(r.dnsA, r.dnsMx, r.fuzzer, vtMalicious, isPhishing, rdap?.ageDays ?? null);
      const isSuspicious = riskScore >= 40;

      if (r.dnsA.length > 0) liveCount++;
      if (r.dnsA.length > 0 || r.dnsMx.length > 0) registeredCount++;
      if (isPhishing) phishingCount++;

      const registrationStatus =
        rdap?.status.includes("clientDeleteProhibited") ? "protected" :
        rdap?.createdDate ? "registered" :
        (r.dnsA.length > 0 || r.dnsMx.length > 0) ? "active" :
        "unresolved";

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

    // ── Phase 4: Phishing detections from live domains ───────────────────────
    const phishingInserts: typeof phishingDetectionsTable.$inferInsert[] = [];
    for (const [domainKey, phish] of phishMap) {
      if (!phish.isPhishing) continue;
      phishingInserts.push({
        tenantId: (await db.select({ tenantId: brandThreatScansTable.tenantId })
          .from(brandThreatScansTable).where(eq(brandThreatScansTable.id, scanId)))[0]?.tenantId ?? 0,
        scanId,
        url: `http://${domainKey}`,
        source: phish.source ?? "Unknown",
        verified: true,
        targetBrand: domain,
        threatType: phish.threatType ?? "SOCIAL_ENGINEERING",
        submittedAt: new Date().toISOString(),
      });
    }
    if (phishingInserts.length > 0) {
      for (let i = 0; i < phishingInserts.length; i += 50) {
        await db.insert(phishingDetectionsTable).values(phishingInserts.slice(i, i + 50));
      }
    }

    // ── Phase 5: Data leak check (HIBP) + Brand abuse scan in parallel ────────
    const [tenantRow] = await db.select({ tenantId: brandThreatScansTable.tenantId })
      .from(brandThreatScansTable)
      .where(eq(brandThreatScansTable.id, scanId));
    const tenantId = tenantRow?.tenantId ?? 0;

    const [hibpResult, brandAbuseList] = await Promise.all([
      hibpKey ? hibpDomainLookup(domain, hibpKey) : Promise.resolve(null),
      scanBrandAbuse(domain.split(".")[0] ?? domain, domain),
    ]);

    let dataLeakCount = 0;
    if (hibpResult && hibpResult.breaches.length > 0) {
      const leakInserts: typeof dataLeakResultsTable.$inferInsert[] = hibpResult.breaches.map(b => ({
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
      }));
      for (let i = 0; i < leakInserts.length; i += 50) {
        await db.insert(dataLeakResultsTable).values(leakInserts.slice(i, i + 50));
      }
      dataLeakCount = leakInserts.length;
    }

    let brandAbuseCount = 0;
    if (brandAbuseList.length > 0) {
      const abuseInserts: typeof brandAbuseResultsTable.$inferInsert[] = brandAbuseList.map(a => ({
        tenantId,
        scanId,
        type: a.type,
        platform: a.platform ?? undefined,
        url: a.url ?? undefined,
        title: a.title ?? undefined,
        description: a.description ?? undefined,
        evidenceSnippet: a.evidenceSnippet ?? undefined,
        risk: a.risk,
      }));
      for (let i = 0; i < abuseInserts.length; i += 50) {
        await db.insert(brandAbuseResultsTable).values(abuseInserts.slice(i, i + 50));
      }
      brandAbuseCount = abuseInserts.length;
    }

    // ── Final update ─────────────────────────────────────────────────────────
    const phishingRisk =
      phishingCount > 5 || liveCount > 20 ? "critical" :
      phishingCount > 2 || liveCount > 10 ? "high" :
      liveCount > 3 ? "medium" : "low";

    await db.update(brandThreatScansTable).set({
      status: "done",
      liveCount,
      registeredCount,
      phishingRisk,
      fuzzerBreakdown,
      dataLeakCount,
      phishingCount,
      brandAbuseCount,
      completedAt: new Date(),
    }).where(eq(brandThreatScansTable.id, scanId));

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
): Promise<void> {
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
    return;
  }

  const [scan] = await db.insert(brandThreatScansTable).values({
    tenantId,
    domain,
    status: "pending",
    pipelineScanId: pipelineScanId ?? null,
  }).returning();

  logger.info({ scanId: scan!.id, domain, pipelineScanId }, "Auto-triggered brand threat scan from pipeline");
  setImmediate(() => { void runBrandThreatScan(scan!.id, domain); });
}
