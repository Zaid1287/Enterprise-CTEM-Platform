import { Router } from "express";
import { eq, and, desc } from "drizzle-orm";
import dns from "node:dns/promises";
import { db, brandThreatScansTable, brandThreatResultsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logger } from "../lib/logger";

const router = Router();

// ── Domain permutation engine (dnstwist-equivalent) ──────────────────────────

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
  const clean = domain.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
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

  // TLD swap
  for (const t of COMMON_TLDS) {
    if (t !== tld) addFull(`${sld}.${t}`, "tld-swap");
  }

  // Omission — remove one char at a time
  for (let i = 0; i < sld.length; i++) {
    add(sld.slice(0, i) + sld.slice(i + 1), "omission");
  }

  // Repetition — double one char
  for (let i = 0; i < sld.length; i++) {
    add(sld.slice(0, i) + sld[i] + sld[i] + sld.slice(i + 1), "repetition");
  }

  // Transposition — swap adjacent chars
  for (let i = 0; i < sld.length - 1; i++) {
    add(sld.slice(0, i) + sld[i + 1] + sld[i] + sld.slice(i + 2), "transposition");
  }

  // Replacement — keyboard-adjacent key substitution
  for (let i = 0; i < sld.length; i++) {
    for (const adj of KEYBOARD_ADJACENT[sld[i]] ?? []) {
      add(sld.slice(0, i) + adj + sld.slice(i + 1), "replacement");
    }
  }

  // Insertion — insert char between each position
  for (let i = 0; i <= sld.length; i++) {
    for (const ch of ["a","e","i","o","u","s","r","n"]) {
      add(sld.slice(0, i) + ch + sld.slice(i), "insertion");
    }
  }

  // Vowel swap
  const vowels = ["a","e","i","o","u"];
  for (let i = 0; i < sld.length; i++) {
    if (vowels.includes(sld[i])) {
      for (const v of vowels) {
        if (v !== sld[i]) add(sld.slice(0, i) + v + sld.slice(i + 1), "vowel-swap");
      }
    }
  }

  // Hyphenation — insert hyphen between positions
  for (let i = 1; i < sld.length; i++) {
    add(sld.slice(0, i) + "-" + sld.slice(i), "hyphenation");
  }

  // Homoglyph — visually similar character substitution
  for (let i = 0; i < sld.length; i++) {
    for (const g of HOMOGLYPHS[sld[i]] ?? []) {
      if (/^[a-z0-9]$/.test(g)) add(sld.slice(0, i) + g + sld.slice(i + 1), "homoglyph");
    }
  }

  // Subdomain prefix/suffix confusion
  const SUBDOMS = ["secure","login","mail","support","account","verify","update","web"];
  for (const sub of SUBDOMS) {
    add(`${sub}-${sld}`, "subdomain");
    add(`${sld}-${sub}`, "subdomain");
  }

  // Addition — prepend/append common chars
  for (const ch of ["s","e","r","1","2","3"]) {
    add(ch + sld, "addition");
    add(sld + ch, "addition");
  }

  return results;
}

// ── DNS checks ────────────────────────────────────────────────────────────────

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

// ── Risk scoring per permutation ──────────────────────────────────────────────

function computeRisk(dnsA: string[], dnsMx: string[], fuzzer: string): number {
  let score = 0;
  if (dnsA.length > 0) score += 45;
  if (dnsMx.length > 0) score += 35;
  if (["homoglyph","replacement","transposition"].includes(fuzzer)) score += 12;
  if (["subdomain","hyphenation"].includes(fuzzer)) score += 5;
  return Math.min(100, score);
}

// ── Background scan executor ──────────────────────────────────────────────────

async function runBrandThreatScan(scanId: number, domain: string): Promise<void> {
  try {
    const permutations = generatePermutations(domain);
    await db.update(brandThreatScansTable)
      .set({ status: "running", totalPermutations: permutations.length })
      .where(eq(brandThreatScansTable.id, scanId));

    let liveCount = 0;
    let registeredCount = 0;
    const fuzzerBreakdown: Record<string, number> = {};
    const queue = [...permutations];
    const pendingInserts: Array<typeof brandThreatResultsTable.$inferInsert> = [];

    async function flushBatch() {
      if (pendingInserts.length === 0) return;
      const batch = pendingInserts.splice(0, pendingInserts.length);
      for (let i = 0; i < batch.length; i += 50) {
        await db.insert(brandThreatResultsTable).values(batch.slice(i, i + 50));
      }
    }

    async function worker() {
      while (queue.length > 0) {
        const item = queue.shift();
        if (!item) break;
        const { permutation, fuzzer } = item;
        fuzzerBreakdown[fuzzer] = (fuzzerBreakdown[fuzzer] ?? 0) + 1;
        const { dnsA, dnsMx } = await checkDNS(permutation);
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
    }

    const CONCURRENCY = 20;
    await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, () => worker()));
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
  } catch (err) {
    logger.error({ err, scanId }, "Brand threat scan failed");
    await db.update(brandThreatScansTable).set({
      status: "error",
      error: String(err),
      completedAt: new Date(),
    }).where(eq(brandThreatScansTable.id, scanId));
  }
}

function toScanResponse(s: typeof brandThreatScansTable.$inferSelect) {
  return {
    ...s,
    createdAt: s.createdAt.toISOString(),
    completedAt: s.completedAt ? s.completedAt.toISOString() : null,
  };
}

// ── GET /brand-threats ────────────────────────────────────────────────────────
router.get("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scans = await db.select().from(brandThreatScansTable)
    .where(eq(brandThreatScansTable.tenantId, req.user!.tenantId))
    .orderBy(desc(brandThreatScansTable.createdAt));
  res.json(scans.map(toScanResponse));
});

// ── POST /brand-threats ───────────────────────────────────────────────────────
router.post("/brand-threats", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const raw = String(req.body?.domain ?? "").trim().toLowerCase()
    .replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0].split("?")[0];
  if (!raw || !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/.test(raw)) {
    res.status(400).json({ error: "Invalid domain. Expected format: example.com" }); return;
  }
  const [scan] = await db.insert(brandThreatScansTable).values({
    tenantId: req.user!.tenantId,
    domain: raw,
    status: "pending",
  }).returning();
  setImmediate(() => { void runBrandThreatScan(scan.id, raw); });
  res.json(toScanResponse(scan));
});

// ── GET /brand-threats/:id ────────────────────────────────────────────────────
router.get("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [scan] = await db.select().from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  const results = await db.select().from(brandThreatResultsTable)
    .where(eq(brandThreatResultsTable.scanId, id))
    .orderBy(desc(brandThreatResultsTable.riskScore));
  res.json({
    ...toScanResponse(scan),
    results: results.map(r => ({ ...r, createdAt: r.createdAt.toISOString() })),
  });
});

// ── DELETE /brand-threats/:id ─────────────────────────────────────────────────
router.delete("/brand-threats/:id", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const id = parseInt(String(req.params.id), 10);
  if (isNaN(id)) { res.status(400).json({ error: "Invalid ID" }); return; }
  const [existing] = await db.select({ id: brandThreatScansTable.id }).from(brandThreatScansTable)
    .where(and(eq(brandThreatScansTable.id, id), eq(brandThreatScansTable.tenantId, req.user!.tenantId)));
  if (!existing) { res.status(404).json({ error: "Scan not found" }); return; }
  await db.delete(brandThreatScansTable).where(eq(brandThreatScansTable.id, id));
  res.json({ success: true });
});

export default router;
