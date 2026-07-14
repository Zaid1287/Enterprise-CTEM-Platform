/**
 * Integration tests for the runBrandThreatScan resume path.
 *
 * These tests call the REAL runBrandThreatScan function (not a mock) with a
 * mocked database and mocked external clients, so every DB operation the
 * function issues is recorded and can be asserted.
 *
 * The crash scenario under test:
 *   1. Server dies after Phase 3 inserts brandThreatResults rows but before
 *      the final liveCount UPDATE on the scan row.
 *   2. On the next startup, recoverStaleBrandThreatScans() detects the scan
 *      has checkpoint="phase1_done" and calls runBrandThreatScan(id, domain,
 *      permutationsCache) — the resume path.
 *   3. The resume path MUST:
 *      a) DELETE all brandThreatResults rows WHERE archivedAt IS NULL
 *         (wipes partial state from the crashed run).
 *      b) Re-derive liveCount from a fresh DB SELECT WHERE archivedAt IS NULL
 *         after Phase 3 re-inserts (not from the in-memory running counter).
 *      c) Write the DB-derived liveCount in the final scan UPDATE — not the
 *         stale in-memory value that accumulated during the previous crashed run.
 *
 * Verifying all three steps together proves that a stuck mid-run scan cannot
 * leave a permanently wrong liveCount in the scan row.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ── vi.hoisted state bags ────────────────────────────────────────────────────

const { dbState } = vi.hoisted(() => {
  // Names assigned to the mocked table objects so we can identify them in assertions.
  const BRAND_THREAT_SCANS    = "brandThreatScansTable";
  const BRAND_THREAT_RESULTS  = "brandThreatResultsTable";
  const PHISHING_DETECTIONS   = "phishingDetectionsTable";
  const DATA_LEAK_RESULTS     = "dataLeakResultsTable";
  const BRAND_ABUSE_RESULTS   = "brandAbuseResultsTable";
  const AD_MONITORING         = "adMonitoringResultsTable";
  const WATCHLIST             = "brandWatchlistItemsTable";
  const CDN_WHITELIST         = "cdnWhitelistTable";

  type DeleteCall = { tableName: string; cond: unknown };
  type SelectCall = { tableName: string; cond: unknown };
  type UpdateCall = { tableName: string; set: Record<string, unknown>; where: unknown };

  const dbState = {
    NAMES: { BRAND_THREAT_SCANS, BRAND_THREAT_RESULTS, PHISHING_DETECTIONS, DATA_LEAK_RESULTS, BRAND_ABUSE_RESULTS, AD_MONITORING, WATCHLIST, CDN_WHITELIST },
    deleteCalls: [] as DeleteCall[],
    selectCalls: [] as SelectCall[],
    updateCalls: [] as UpdateCall[],
    selectResults: [] as unknown[][],
    selectIdx: 0,
    reset() {
      this.deleteCalls = [];
      this.selectCalls = [];
      this.updateCalls = [];
      this.selectResults = [];
      this.selectIdx = 0;
    },
  };
  return { dbState };
});

// ── Mock @workspace/db ────────────────────────────────────────────────────────

vi.mock("@workspace/db", () => {
  // Each table object has a _name property so assertions can identify it.
  const makeTable = (name: string) => ({
    _name: name,
    id: `${name}.id`, scanId: `${name}.scanId`, tenantId: `${name}.tenantId`,
    domain: `${name}.domain`, status: `${name}.status`, progress: `${name}.progress`,
    checkpoint: `${name}.checkpoint`, permutationsCache: `${name}.permutationsCache`,
    faviconMd5: `${name}.faviconMd5`, faviconUrl: `${name}.faviconUrl`,
    faviconMmh3: `${name}.faviconMmh3`, faviconMmh3Hex: `${name}.faviconMmh3Hex`,
    faviconSha256: `${name}.faviconSha256`, faviconSearchUrls: `${name}.faviconSearchUrls`,
    faviconShodanMatches: `${name}.faviconShodanMatches`,
    archivedAt: `${name}.archivedAt`, dnsA: `${name}.dnsA`, dnsMx: `${name}.dnsMx`,
    isPhishing: `${name}.isPhishing`, riskScore: `${name}.riskScore`,
    permutation: `${name}.permutation`, value: `${name}.value`, type: `${name}.type`,
    isActive: `${name}.isActive`, ipStart: `${name}.ipStart`, ipEnd: `${name}.ipEnd`,
    label: `${name}.label`, error: `${name}.error`, completedAt: `${name}.completedAt`,
    liveCount: `${name}.liveCount`, registeredCount: `${name}.registeredCount`,
    lastScannedAt: `${name}.lastScannedAt`,
    totalPermutations: `${name}.totalPermutations`, favihunterStatus: `${name}.favihunterStatus`,
    screenshot: `${name}.screenshot`, source: `${name}.source`,
    $inferInsert: {} as unknown,
  });

  const brandThreatScansTable    = makeTable(dbState.NAMES.BRAND_THREAT_SCANS);
  const brandThreatResultsTable  = makeTable(dbState.NAMES.BRAND_THREAT_RESULTS);
  const phishingDetectionsTable  = makeTable(dbState.NAMES.PHISHING_DETECTIONS);
  const dataLeakResultsTable     = makeTable(dbState.NAMES.DATA_LEAK_RESULTS);
  const brandAbuseResultsTable   = makeTable(dbState.NAMES.BRAND_ABUSE_RESULTS);
  const adMonitoringResultsTable = makeTable(dbState.NAMES.AD_MONITORING);
  const brandWatchlistItemsTable = makeTable(dbState.NAMES.WATCHLIST);
  const cdnWhitelistTable        = makeTable(dbState.NAMES.CDN_WHITELIST);

  const tableNameOf = (t: { _name?: string }) => t?._name ?? "unknown";

  const db = {
    select: (_fields?: unknown) => ({
      from: (table: { _name?: string }) => ({
        where: (cond: unknown) => {
          const tableName = tableNameOf(table);
          dbState.selectCalls.push({ tableName, cond });
          const rows = dbState.selectResults[dbState.selectIdx++] ?? [];
          return Promise.resolve(rows);
        },
      }),
    }),
    delete: (table: { _name?: string }) => ({
      where: (cond: unknown) => {
        dbState.deleteCalls.push({ tableName: tableNameOf(table), cond });
        return Promise.resolve();
      },
    }),
    insert: (_table: unknown) => ({
      values: (_data: unknown) => Promise.resolve(),
    }),
    update: (table: { _name?: string }) => ({
      set: (payload: Record<string, unknown>) => ({
        where: (cond: unknown) => {
          dbState.updateCalls.push({ tableName: tableNameOf(table), set: payload, where: cond });
          return Promise.resolve();
        },
      }),
    }),
  };

  return {
    db,
    brandThreatScansTable,
    brandThreatResultsTable,
    phishingDetectionsTable,
    dataLeakResultsTable,
    brandAbuseResultsTable,
    adMonitoringResultsTable,
    brandWatchlistItemsTable,
    cdnWhitelistTable,
  };
});

// ── Mock drizzle-orm ──────────────────────────────────────────────────────────

vi.mock("drizzle-orm", () => ({
  eq:         vi.fn((col: unknown, val: unknown)     => ({ _type: "eq",         col, val })),
  and:        vi.fn((...args: unknown[])             => ({ _type: "and",        args })),
  or:         vi.fn((...args: unknown[])             => ({ _type: "or",         args })),
  gte:        vi.fn((col: unknown, val: unknown)     => ({ _type: "gte",        col, val })),
  gt:         vi.fn((col: unknown, val: unknown)     => ({ _type: "gt",         col, val })),
  lt:         vi.fn((col: unknown, val: unknown)     => ({ _type: "lt",         col, val })),
  lte:        vi.fn((col: unknown, val: unknown)     => ({ _type: "lte",        col, val })),
  isNull:     vi.fn((col: unknown)                  => ({ _type: "isNull",     col })),
  isNotNull:  vi.fn((col: unknown)                  => ({ _type: "isNotNull",  col })),
  desc:       vi.fn((col: unknown)                  => ({ _type: "desc",       col })),
  asc:        vi.fn((col: unknown)                  => ({ _type: "asc",        col })),
  inArray:    vi.fn((col: unknown, vals: unknown)   => ({ _type: "inArray",    col, vals })),
  notInArray: vi.fn((col: unknown, vals: unknown)   => ({ _type: "notInArray", col, vals })),
  sql:        vi.fn((parts: unknown, ...vals: unknown[]) => ({ _type: "sql", parts, vals })),
  ne:         vi.fn((col: unknown, val: unknown)    => ({ _type: "ne",         col, val })),
  like:       vi.fn((col: unknown, val: unknown)    => ({ _type: "like",       col, val })),
}));

// ── Mock all external service clients ────────────────────────────────────────

vi.mock("../../lib/metaAdsClient",        () => ({ scanMetaAds:                 vi.fn().mockResolvedValue([]) }));
vi.mock("../../lib/abuseChFeeds",         () => ({ queryAbuseChFeeds:           vi.fn().mockResolvedValue([]) }));
vi.mock("../../lib/logger",               () => ({ logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() } }));
vi.mock("../../lib/rdapClient",           () => ({ rdapLookup:                  vi.fn().mockResolvedValue(null) }));
vi.mock("../../lib/geoIpClient",          () => ({ geoIpBatch:                  vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../../lib/phishFeedClient",      () => ({ checkPhishingFeed:           vi.fn().mockResolvedValue({ isPhishing: false }), setPhishTankKey: vi.fn() }));
vi.mock("../../lib/googleSafeBrowsing",   () => ({ checkGoogleSafeBrowsing:     vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../../lib/hibpClient",           () => ({ hibpDomainLookup:            vi.fn().mockResolvedValue({ breaches: [] }), severityFromBreach: vi.fn().mockReturnValue("low") }));
vi.mock("../../lib/vtDomainClient",       () => ({ vtDomainLookup:              vi.fn().mockResolvedValue(null), vtUrlScan: vi.fn().mockResolvedValue(null) }));
vi.mock("../../lib/brandAbuseScanner",    () => ({ scanBrandAbuse:              vi.fn().mockResolvedValue({ results: [], warnings: [] }) }));
vi.mock("../../lib/intelxClient",         () => ({ intelxSearch:                vi.fn().mockResolvedValue([]), intelxTypeToBucket: vi.fn().mockReturnValue("unknown") }));
vi.mock("../../lib/shodanFaviconClient",  () => ({ searchShodanByFaviconHash:   vi.fn().mockResolvedValue([]) }));
vi.mock("../../lib/notifier",             () => ({ dispatchNotifications:       vi.fn().mockResolvedValue(undefined) }));
vi.mock("../../lib/screenshotEngine",     () => ({ captureScreenshots:          vi.fn().mockResolvedValue([]) }));

vi.mock("../../routes/platformSettings", () => ({
  getPlatformSetting: vi.fn().mockResolvedValue(null),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

/** A minimal permutation entry representing a live domain (has an A record). */
const LIVE_PERM = {
  permutation: "acme-live.com",
  fuzzer: "repetition",
  dnsA:    ["1.2.3.4"],
  dnsAaaa: [],
  dnsMx:   [],
  dnsNs:   [],
};

/** A minimal permutation entry for a registered-but-not-live domain. */
const REG_ONLY_PERM = {
  permutation: "acme-mx.com",
  fuzzer: "homoglyph",
  dnsA:    [],
  dnsAaaa: [],
  dnsMx:   ["mx.acme-mx.com"],
  dnsNs:   [],
};

/**
 * Arrange the sequential select results that runBrandThreatScan will consume
 * when called with a permutationsCache (resume path), using an empty permutation
 * list or a minimal one.
 *
 * SELECT call order in resume path (see brandThreatRunner.ts):
 *   0  loadCdnRangesFromDb  → cdnWhitelistTable           → [] (use builtins)
 *   1  favicon recovery     → brandThreatScansTable        → [{ faviconMd5: null }]
 *   2  liveCount derivation → brandThreatResultsTable      → <injected rows>
 *   3  high-risk screenshot → brandThreatResultsTable      → []
 *   4  phishing tenantId   → brandThreatScansTable        → [{ tenantId: 1 }]
 *   5  data-leak tenantId  → brandThreatScansTable        → [{ tenantId: 1 }]
 *   6  watchlist items      → brandWatchlistItemsTable     → []
 */
function arrangeSelectResults(liveCountRows: unknown[]) {
  dbState.selectResults = [
    [],                         // 0: cdnWhitelistTable → empty → builtins used
    [{ faviconMd5: null }],     // 1: favicon recovery → no favicon to restore
    liveCountRows,              // 2: liveCount derivation (KEY SELECT)
    [],                         // 3: high-risk screenshot rows → none
    [{ tenantId: 1 }],          // 4: phishing phase tenantId
    [{ tenantId: 1 }],          // 5: data-leak phase tenantId
    [],                         // 6: watchlist items → none
  ];
  dbState.selectIdx = 0;
}

/** Returns true if a condition object (or its nested args) contains an isNull node. */
function containsIsNull(cond: unknown): boolean {
  if (!cond || typeof cond !== "object") return false;
  const c = cond as Record<string, unknown>;
  if (c._type === "isNull") return true;
  if (Array.isArray(c.args)) return (c.args as unknown[]).some(containsIsNull);
  return false;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("runBrandThreatScan — resume path liveCount safety", () => {
  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
  });

  // ── Assertion A: DELETE uses isNull(archivedAt) ───────────────────────────

  it("deletes partial brandThreatResults rows WHERE archivedAt IS NULL on resume", async () => {
    arrangeSelectResults([]);

    const { runBrandThreatScan } = await import("../../lib/brandThreatRunner");
    await runBrandThreatScan(42, "acme.com", []);

    // Find the DELETE call targeting brandThreatResultsTable
    const deleteCall = dbState.deleteCalls.find(
      d => d.tableName === dbState.NAMES.BRAND_THREAT_RESULTS,
    );
    expect(deleteCall, "expected a DELETE on brandThreatResultsTable during resume").toBeDefined();

    // Its WHERE condition must include isNull (mirrors the `isNull(archivedAt)` guard)
    expect(
      containsIsNull(deleteCall!.cond),
      "DELETE on brandThreatResultsTable must use isNull(archivedAt) to avoid wiping archived history",
    ).toBe(true);
  });

  // ── Assertion B: liveCount SELECT uses isNull(archivedAt) ─────────────────

  it("re-derives liveCount from brandThreatResultsTable WHERE archivedAt IS NULL after Phase 3", async () => {
    arrangeSelectResults([]);

    const { runBrandThreatScan } = await import("../../lib/brandThreatRunner");
    await runBrandThreatScan(42, "acme.com", []);

    // Find SELECT calls targeting brandThreatResultsTable
    const resultSelects = dbState.selectCalls.filter(
      s => s.tableName === dbState.NAMES.BRAND_THREAT_RESULTS,
    );
    // There are two: the liveCount derivation and the high-risk screenshot query
    expect(resultSelects.length).toBeGreaterThanOrEqual(1);

    // At least one SELECT on brandThreatResultsTable must use isNull(archivedAt)
    const hasIsNullSelect = resultSelects.some(s => containsIsNull(s.cond));
    expect(hasIsNullSelect, "liveCount SELECT must include isNull(archivedAt) to exclude archived rows").toBe(true);
  });

  // ── Assertion C: liveCount in final UPDATE matches DB SELECT, not in-memory counter ──
  //
  // The in-memory counter starts at 0 after each resume (reset by `let liveCount = 0`).
  // If the permutations cache has NO live entries (dnsA=[]), the in-memory counter stays 0.
  // But the DB SELECT mock returns 2 live rows.
  //
  // Expected final UPDATE: liveCount=2 (DB-derived).
  // If the code accidentally used the in-memory counter, liveCount would be 0.
  it("writes DB-derived liveCount into final scan UPDATE (not in-memory counter)", async () => {
    // Two rows with dnsA non-empty → liveCount should be 2
    const dbLiveRows = [
      { dnsA: ["1.2.3.4"], dnsMx: [],            isPhishing: false },
      { dnsA: ["5.6.7.8"], dnsMx: [],            isPhishing: false },
    ];
    // permutationsCache has only non-live entries (dnsA=[]) so in-memory liveCount stays 0
    arrangeSelectResults(dbLiveRows);

    const { runBrandThreatScan } = await import("../../lib/brandThreatRunner");
    await runBrandThreatScan(42, "acme.com", [REG_ONLY_PERM]);

    // Final UPDATE: status "done"
    const finalUpdate = dbState.updateCalls.find(
      u => u.tableName === dbState.NAMES.BRAND_THREAT_SCANS && u.set.status === "done",
    );
    expect(finalUpdate, "expected a final UPDATE with status=done").toBeDefined();

    // liveCount must equal the DB SELECT result (2), not the in-memory counter (0)
    expect(finalUpdate!.set.liveCount).toBe(2);
  });

  // ── Assertion D: full round-trip with live permutations ───────────────────
  //
  // When the permutations cache has a live entry, the in-memory counter also
  // increments to 1. After Phase 3 the DB SELECT is queried and OVERWRITES the
  // counter. Confirm liveCount=1 matches the DB SELECT row count.
  it("correctly writes liveCount=1 when both in-memory counter and DB SELECT agree", async () => {
    const dbLiveRows = [
      { dnsA: ["1.2.3.4"], dnsMx: [], isPhishing: false },
    ];
    arrangeSelectResults(dbLiveRows);

    const { runBrandThreatScan } = await import("../../lib/brandThreatRunner");
    await runBrandThreatScan(42, "acme.com", [LIVE_PERM]);

    const finalUpdate = dbState.updateCalls.find(
      u => u.tableName === dbState.NAMES.BRAND_THREAT_SCANS && u.set.status === "done",
    );
    expect(finalUpdate).toBeDefined();
    expect(finalUpdate!.set.liveCount).toBe(1);
  });

  // ── Assertion E: archived rows are never touched by the resume DELETE ──────
  //
  // Proves the isNull(archivedAt) guard on the DELETE is necessary: if the
  // function deleted ALL rows (regardless of archivedAt), historical data
  // from prior runs would be silently destroyed.  The function MUST only
  // delete archivedAt IS NULL rows.
  it("does NOT issue a DELETE on brandThreatResultsTable without the isNull(archivedAt) guard", async () => {
    arrangeSelectResults([]);

    const { runBrandThreatScan } = await import("../../lib/brandThreatRunner");
    await runBrandThreatScan(42, "acme.com", []);

    // Any DELETE on brandThreatResultsTable must include isNull in its condition.
    // A DELETE without isNull would destroy archived historical rows.
    const unguardedDelete = dbState.deleteCalls.find(
      d => d.tableName === dbState.NAMES.BRAND_THREAT_RESULTS && !containsIsNull(d.cond),
    );
    expect(unguardedDelete).toBeUndefined();
  });
});
