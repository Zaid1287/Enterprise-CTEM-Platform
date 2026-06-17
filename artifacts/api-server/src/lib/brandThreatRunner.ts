import { exec } from "child_process";
import { promisify } from "util";
import dns from "node:dns/promises";
import { eq, and } from "drizzle-orm";
import { db, brandThreatScansTable, brandThreatResultsTable } from "@workspace/db";
import { logger } from "./logger";

const execAsync = promisify(exec);

// ── dnstwist binary runner ─────────────────────────────────────────────────────

interface PermResult {
  permutation: string;
  fuzzer: string;
  dnsA: string[];
  dnsMx: string[];
}

async function runDnstwistBinary(domain: string): Promise<PermResult[]> {
  const { stdout } = await execAsync(
    `dnstwist --format json --threads 20 ${domain}`,
    { timeout: 180_000, maxBuffer: 20 * 1024 * 1024 },
  );
  const raw = JSON.parse(stdout) as Array<{
    fuzzer: string;
    domain: string;
    "dns-a"?: string[];
    "dns-aaaa"?: string[];
    "dns-mx"?: string[];
  }>;

  return raw
    .filter(r => r.fuzzer !== "original")
    .map(r => ({
      permutation: r.domain,
      fuzzer: r.fuzzer,
      dnsA: r["dns-a"] ?? [],
      dnsMx: (r["dns-mx"] ?? []).map(mx => {
        const parts = mx.trim().split(/\s+/);
        return parts.length >= 2 ? parts.slice(1).join(" ") : mx;
      }),
    }));
}

// ── Built-in Node.js fallback engine (equivalent algorithms) ──────────────────

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
  return { sld: parts[0], tld: parts.slice(1).join(".") };
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
  for (let i = 0; i < sld.length; i++) {
    add(sld.slice(0, i) + sld.slice(i + 1), "omission");
  }
  for (let i = 0; i < sld.length; i++) {
    add(sld.slice(0, i) + sld[i]! + sld[i]! + sld.slice(i + 1), "repetition");
  }
  for (let i = 0; i < sld.length - 1; i++) {
    add(sld.slice(0, i) + sld[i + 1]! + sld[i]! + sld.slice(i + 2), "transposition");
  }
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
  for (let i = 1; i < sld.length; i++) {
    add(sld.slice(0, i) + "-" + sld.slice(i), "hyphenation");
  }
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

async function checkDNS(domain: string): Promise<{ dnsA: string[]; dnsMx: string[] }> {
  const [a, mx] = await Promise.all([
    dns.resolve4(domain).catch(() => [] as string[]),
    dns.resolveMx(domain).catch(() => [] as { exchange: string; priority: number }[]),
  ]);
  return {
    dnsA: a as string[],
    dnsMx: (mx as any[]).map((m: any) => String(m.exchange)),
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
      const { dnsA, dnsMx } = await checkDNS(permutation);
      results.push({ permutation, fuzzer, dnsA, dnsMx });
    }
  }

  await Promise.all(Array.from({ length: 20 }, () => worker()));
  return results;
}

// ── Unified scanner: tries dnstwist binary, falls back to built-in ─────────────

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

function computeRisk(dnsA: string[], dnsMx: string[], fuzzer: string): number {
  let score = 0;
  if (dnsA.length > 0) score += 45;
  if (dnsMx.length > 0) score += 35;
  if (["homoglyph","replacement","transposition","bitsquatting"].includes(fuzzer)) score += 12;
  if (["subdomain","hyphenation"].includes(fuzzer)) score += 5;
  return Math.min(100, score);
}

// ── Core scan executor ────────────────────────────────────────────────────────

export async function runBrandThreatScan(scanId: number, domain: string): Promise<void> {
  try {
    await db.update(brandThreatScansTable)
      .set({ status: "running" })
      .where(eq(brandThreatScansTable.id, scanId));

    const permResults = await scanPermutations(domain);

    await db.update(brandThreatScansTable)
      .set({ totalPermutations: permResults.length })
      .where(eq(brandThreatScansTable.id, scanId));

    let liveCount = 0;
    let registeredCount = 0;
    const fuzzerBreakdown: Record<string, number> = {};
    const pendingInserts: Array<typeof brandThreatResultsTable.$inferInsert> = [];

    async function flushBatch() {
      if (pendingInserts.length === 0) return;
      const batch = pendingInserts.splice(0, pendingInserts.length);
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(brandThreatResultsTable).values(batch.slice(i, i + 50));
      }
    }

    for (const { permutation, fuzzer, dnsA, dnsMx } of permResults) {
      fuzzerBreakdown[fuzzer] = (fuzzerBreakdown[fuzzer] ?? 0) + 1;
      const riskScore = computeRisk(dnsA, dnsMx, fuzzer);
      const isSuspicious = riskScore >= 40;
      if (dnsA.length > 0) liveCount++;
      if (dnsA.length > 0 || dnsMx.length > 0) registeredCount++;
      pendingInserts.push({
        scanId, permutation, fuzzer,
        dnsA: dnsA.length ? dnsA : undefined,
        dnsMx: dnsMx.length ? dnsMx : undefined,
        riskScore, isSuspicious,
      });
      if (pendingInserts.length >= 50) await flushBatch();
    }
    await flushBatch();

    const phishingRisk =
      liveCount > 20 ? "critical" :
      liveCount > 10 ? "high" :
      liveCount > 3  ? "medium" : "low";

    await db.update(brandThreatScansTable).set({
      status: "done",
      liveCount,
      registeredCount,
      phishingRisk,
      fuzzerBreakdown,
      completedAt: new Date(),
    }).where(eq(brandThreatScansTable.id, scanId));

    logger.info({ scanId, domain, liveCount, registeredCount }, "Brand threat scan completed");
  } catch (err) {
    logger.error({ err, scanId }, "Brand threat scan failed");
    await db.update(brandThreatScansTable).set({
      status: "error",
      error: String(err),
      completedAt: new Date(),
    }).where(eq(brandThreatScansTable.id, scanId));
  }
}

// ── Auto-trigger helper (used by pipeline scans) ──────────────────────────────

export async function triggerBrandThreatScan(
  tenantId: number,
  domain: string,
  pipelineScanId?: number,
): Promise<void> {
  const existing = await db.select({ id: brandThreatScansTable.id, status: brandThreatScansTable.status })
    .from(brandThreatScansTable)
    .where(
      and(
        eq(brandThreatScansTable.tenantId, tenantId),
        eq(brandThreatScansTable.domain, domain),
      )
    );

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

  logger.info({ scanId: scan.id, domain, pipelineScanId }, "Auto-triggered brand threat scan from pipeline");
  setImmediate(() => { void runBrandThreatScan(scan.id, domain); });
}
