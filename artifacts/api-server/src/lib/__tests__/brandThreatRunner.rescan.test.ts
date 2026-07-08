/**
 * Runner-level test: liveCount recomputation uses archivedAt IS NULL.
 *
 * Directly invokes runBrandThreatScan and asserts that the final
 * update(brandThreatScansTable).set({liveCount, registeredCount, phishingCount})
 * reflects only non-archived rows — never old archived rows from a prior run.
 *
 * This covers the "archived-row guard" block in brandThreatRunner.ts (the
 * liveCount recomputation query that explicitly filters WHERE archivedAt IS NULL).
 *
 * Why a dedicated file: the mock here needs a select queue that distinguishes
 * the liveCount recomputation query (fields: {dnsA, dnsMx, isPhishing}) from
 * all other select calls in the runner. A field-signature-based detector is
 * used for this — see makeSmartSelect() below.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── vi.hoisted: tracking bags ─────────────────────────────────────────────────

const { runnerMocks } = vi.hoisted(() => {
  const runnerMocks = {
    updateSetCalls: [] as Array<Record<string, unknown>>,
    livenessRows:   [] as Array<{ dnsA: string[] | null; dnsMx: string[] | null; isPhishing: boolean }>,
    reset() {
      this.updateSetCalls = [];
      this.livenessRows   = [];
    },
  };
  return { runnerMocks };
});

// ── DB mock ───────────────────────────────────────────────────────────────────
//
// makeSmartSelect inspects the fields argument to decide which rows to return.
// The liveCount recomputation query is the ONLY call with fields {dnsA, dnsMx, isPhishing}.
// All other selects fall through to MOCK_SCAN_ROW (enough for the runner to proceed).

const MOCK_SCAN_ROW = {
  id: 42, tenantId: 1, domain: "acme.com", status: "running", progress: 0,
  faviconMd5: null, faviconUrl: null, faviconMmh3: null, faviconMmh3Hex: null,
  faviconSha256: null, faviconSearchUrls: null,
};

function makeThenable<T>(value: T) {
  const p = Promise.resolve(value) as Promise<T> & Record<string, unknown>;
  const chain: Record<string, unknown> = {
    where:   () => makeThenable(value),
    orderBy: () => makeThenable(value),
    limit:   (n: number) => makeThenable(Array.isArray(value) ? (value as unknown[]).slice(0, n) : value),
    from:    () => makeThenable(value),
  };
  return Object.assign(p, chain);
}

function makeSmartSelect(fields?: unknown) {
  // Detect the liveCount recomputation query by its unique field signature.
  // The runner calls: db.select({ dnsA: brandThreatResultsTable.dnsA, dnsMx: ..., isPhishing: ... })
  // With the column-string table mock below, those resolve to:
  //   fields = { dnsA: "dnsA", dnsMx: "dnsMx", isPhishing: "isPhishing" }
  const fieldKeys = fields && typeof fields === "object" ? Object.keys(fields) : [];
  const isLivenessQuery =
    fieldKeys.length === 3 &&
    fieldKeys.includes("dnsA") &&
    fieldKeys.includes("dnsMx") &&
    fieldKeys.includes("isPhishing");

  // Secondary screenshot query: { id: "id", permutation: "permutation" }
  // We return [] so no screenshots are attempted.
  const isScreenshotQuery =
    fieldKeys.length === 2 &&
    fieldKeys.includes("id") &&
    fieldKeys.includes("permutation");

  if (isLivenessQuery) return makeThenable(runnerMocks.livenessRows);
  if (isScreenshotQuery) return makeThenable([]);
  // Default: generic scan row (suitable for all other selects in the runner)
  return makeThenable([MOCK_SCAN_ROW]);
}

vi.mock("@workspace/db", () => {
  const makeUpdate = () => ({
    set: (data: Record<string, unknown>) => {
      runnerMocks.updateSetCalls.push(data);
      return { where: () => Promise.resolve() };
    },
  });

  const makeInsert = () => ({
    values: (rows: unknown) => {
      const arr = Array.isArray(rows) ? rows : [rows];
      void arr; // insertion tracked if needed; not required for liveCount test
      return Promise.resolve([]);
    },
  });

  return {
    db: {
      update:  (_table: unknown) => makeUpdate(),
      insert:  (_table: unknown) => makeInsert(),
      select:  (fields?: unknown) => makeSmartSelect(fields),
      delete:  (_table: unknown) => ({ where: () => Promise.resolve() }),
    },
    // Column strings so drizzle-orm predicates/fields use them as property keys
    brandThreatScansTable: {
      id: "id", tenantId: "tenantId", domain: "domain",
      status: "status", progress: "progress",
      faviconMd5: "faviconMd5", faviconUrl: "faviconUrl",
      faviconMmh3: "faviconMmh3", faviconMmh3Hex: "faviconMmh3Hex",
      faviconSha256: "faviconSha256", faviconSearchUrls: "faviconSearchUrls",
      checkpoint: "checkpoint", permutationsCache: "permutationsCache",
      favihunterStatus: "favihunterStatus",
      _: { name: "brand_threat_scans" },
    },
    brandThreatResultsTable: {
      id: "id", scanId: "scanId", permutation: "permutation",
      dnsA: "dnsA", dnsAaaa: "dnsAaaa", dnsMx: "dnsMx", dnsNs: "dnsNs",
      isPhishing: "isPhishing", riskScore: "riskScore",
      archivedAt: "archivedAt",
      _: { name: "brand_threat_results" },
    },
    dataLeakResultsTable:    { _: { name: "data_leak_results" } },
    phishingDetectionsTable: { _: { name: "phishing_detections" } },
    brandAbuseResultsTable:  { _: { name: "brand_abuse_results" } },
    adMonitoringResultsTable:{ _: { name: "ad_monitoring_results" } },
    brandWatchlistItemsTable:{ _: { name: "brand_watchlist_items" }, tenantId: "tenantId" },
    cdnWhitelistTable:       { _: { name: "cdn_whitelist_entries" }, isActive: "isActive" },
  };
});

// ── drizzle-orm mock ──────────────────────────────────────────────────────────

vi.mock("drizzle-orm", async (importOriginal) => {
  const orig = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...orig,
    eq:        vi.fn((col: unknown, val: unknown) => ({ _type: "eq", col, val })),
    and:       vi.fn((...args: unknown[])          => ({ _type: "and", args })),
    isNull:    vi.fn((col: unknown)               => ({ _type: "isNull", col })),
    isNotNull: vi.fn((col: unknown)               => ({ _type: "isNotNull", col })),
    gte:       vi.fn((col: unknown, val: unknown)  => ({ _type: "gte", col, val })),
    lt:        vi.fn(),
    desc:      vi.fn(),
    inArray:   vi.fn(),
  };
});

// ── External service mocks (same as brandThreatRunner.test.ts) ────────────────

vi.mock("../metaAdsClient",        () => ({ scanMetaAds: vi.fn().mockResolvedValue([]) }));
vi.mock("../abuseChFeeds",         () => ({ queryAbuseChFeeds: vi.fn().mockResolvedValue([]) }));
vi.mock("../logger",               () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("../rdapClient",           () => ({ rdapLookup: vi.fn().mockResolvedValue(null) }));
vi.mock("../geoIpClient",          () => ({ geoIpBatch: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../phishFeedClient",      () => ({
  checkPhishingFeed: vi.fn().mockResolvedValue({ isPhishing: false, source: null }),
  setPhishTankKey: vi.fn(),
}));
vi.mock("../googleSafeBrowsing",   () => ({ checkGoogleSafeBrowsing: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../hibpClient",           () => ({
  hibpDomainLookup: vi.fn().mockResolvedValue(null),
  severityFromBreach: vi.fn().mockReturnValue("medium"),
}));
vi.mock("../vtDomainClient",       () => ({
  vtDomainLookup: vi.fn().mockResolvedValue(null),
  vtUrlScan: vi.fn().mockResolvedValue(null),
}));
vi.mock("../brandAbuseScanner",    () => ({ scanBrandAbuse: vi.fn().mockResolvedValue([]) }));
vi.mock("../intelxClient",         () => ({
  intelxSearch: vi.fn().mockResolvedValue([]),
  intelxTypeToBucket: vi.fn().mockReturnValue("pastes"),
}));
vi.mock("../shodanFaviconClient",  () => ({ searchShodanByFaviconHash: vi.fn().mockResolvedValue([]) }));
vi.mock("../notifier",             () => ({ dispatchNotifications: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../../routes/platformSettings", () => ({
  getPlatformSetting: vi.fn().mockResolvedValue(null),
}));
vi.mock("../screenshotEngine",     () => ({ captureScreenshots: vi.fn().mockResolvedValue([]) }));

// DNS: all permutations fail to resolve (no live results from the runner's own DNS work)
vi.mock("node:dns/promises", () => ({
  default: {
    resolve4:  vi.fn().mockResolvedValue([]),
    resolve6:  vi.fn().mockResolvedValue([]),
    resolveMx: vi.fn().mockResolvedValue([]),
    resolveNs: vi.fn().mockResolvedValue([]),
  },
}));

// dnstwist unavailable → built-in engine runs (and produces permutations)
vi.mock("child_process", () => ({
  execFile: (_cmd: string, _args: string[], _opts: unknown, cb: (err: Error | null) => void) => {
    cb(new Error("dnstwist not found"));
  },
  promisify: (fn: Function) => (...args: unknown[]) =>
    new Promise((_resolve, reject) => fn(...args, reject)),
}));

vi.mock("util", async (importOriginal) => {
  const orig = await importOriginal<typeof import("util")>();
  return {
    ...orig,
    promisify: (_fn: unknown) => (_cmd: string, _args: string[], _opts: unknown) =>
      Promise.reject(new Error("dnstwist not found")),
  };
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("runBrandThreatScan — liveCount recomputation uses archivedAt IS NULL", () => {
  beforeEach(() => runnerMocks.reset());
  afterEach(() => vi.clearAllMocks());

  it("final liveCount = 1 when DB returns 1 live non-archived row (3 archived rows excluded)", async () => {
    // Seed: the liveCount recomputation query will return only 1 non-archived live row.
    // The 3 archived rows from the prior run have already been excluded by the DB-level
    // WHERE archivedAt IS NULL filter; the runner sees only what the DB returns.
    runnerMocks.livenessRows = [
      { dnsA: ["5.6.7.8"], dnsMx: ["mail.acme-login.com"], isPhishing: true },
      // 3 old archived rows are NOT here — they were filtered by the DB predicate
    ];

    const { runBrandThreatScan } = await import("../brandThreatRunner");
    await runBrandThreatScan(42, "acme.com");

    // Find the final update call that sets liveCount (the archived-row guard block)
    const calls = runnerMocks.updateSetCalls;
    const liveCountUpdate = calls.find(
      c => typeof c.liveCount === "number",
    );

    expect(liveCountUpdate).toBeDefined();
    // Must be 1 (only the new live row), not 4 (old 3 + new 1)
    expect(liveCountUpdate!.liveCount).toBe(1);
    expect(liveCountUpdate!.registeredCount).toBe(1); // dnsA OR dnsMx
    expect(liveCountUpdate!.phishingCount).toBe(1);
  });

  it("final liveCount = 0 when the liveCount query returns only archived rows (empty after filter)", async () => {
    // Simulates: re-scan found no new live domains; old archived rows are excluded by the DB.
    runnerMocks.livenessRows = []; // DB returns empty after WHERE archivedAt IS NULL

    const { runBrandThreatScan } = await import("../brandThreatRunner");
    await runBrandThreatScan(42, "acme.com");

    const liveCountUpdate = runnerMocks.updateSetCalls.find(
      c => typeof c.liveCount === "number",
    );

    expect(liveCountUpdate).toBeDefined();
    expect(liveCountUpdate!.liveCount).toBe(0);
    expect(liveCountUpdate!.registeredCount).toBe(0);
    expect(liveCountUpdate!.phishingCount).toBe(0);
  });

  it("liveCount counts only dnsA rows; registeredCount includes dnsA OR dnsMx", async () => {
    // 2 with dnsA+dnsMx (live+registered), 1 with only dnsMx (registered, not live)
    runnerMocks.livenessRows = [
      { dnsA: ["1.1.1.1"], dnsMx: ["mx.a.com"],  isPhishing: false },
      { dnsA: ["2.2.2.2"], dnsMx: ["mx.b.com"],  isPhishing: true  },
      { dnsA: [],          dnsMx: ["mx.c.com"],  isPhishing: false },
    ];

    const { runBrandThreatScan } = await import("../brandThreatRunner");
    await runBrandThreatScan(42, "acme.com");

    const liveCountUpdate = runnerMocks.updateSetCalls.find(
      c => typeof c.liveCount === "number",
    );

    expect(liveCountUpdate).toBeDefined();
    expect(liveCountUpdate!.liveCount).toBe(2);       // only dnsA rows
    expect(liveCountUpdate!.registeredCount).toBe(3); // dnsA OR dnsMx
    expect(liveCountUpdate!.phishingCount).toBe(1);
  });

  it("isNull() is called with the archivedAt column ref in the liveCount recomputation query", async () => {
    runnerMocks.livenessRows = [];

    const { runBrandThreatScan } = await import("../brandThreatRunner");
    await runBrandThreatScan(42, "acme.com");

    const { isNull } = await import("drizzle-orm");
    // The runner must call isNull(brandThreatResultsTable.archivedAt).
    // With the column-string mock: brandThreatResultsTable.archivedAt === "archivedAt"
    expect(vi.mocked(isNull)).toHaveBeenCalledWith("archivedAt");
  });

  it("scan reaches status='done' even when no live results are found", async () => {
    runnerMocks.livenessRows = [];

    const { runBrandThreatScan } = await import("../brandThreatRunner");
    await runBrandThreatScan(42, "acme.com");

    const finalUpdate = runnerMocks.updateSetCalls.find(
      c => c.status === "done" && c.progress === 100,
    );
    expect(finalUpdate).toBeDefined();
  });
});
