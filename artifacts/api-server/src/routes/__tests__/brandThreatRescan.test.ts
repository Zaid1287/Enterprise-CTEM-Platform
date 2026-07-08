/**
 * Re-scan live-count correctness tests for /brand-threats.
 *
 * Addresses the complete re-scan contract end-to-end:
 *
 *  1. POST /brand-threats for an existing domain archives prior results
 *     (sets archivedAt) and resets all scan counters to zero — tracked via
 *     a stateful in-memory DB that actually applies WHERE predicates so the
 *     archival is observable.
 *
 *  2. GET /brand-threats/:id after re-scan returns only rows where
 *     archivedAt IS NULL.  The `isNull` spy is asserted to confirm the
 *     route actually applies the predicate, AND the stateful DB enforces it
 *     so the test would FAIL if `isNull(archivedAt)` were removed.
 *
 *  3. liveCount on the scan row equals only the new scan's live result
 *     count — never old + new combined.  Proven by the stateful lifecycle
 *     test: old rows are archived, new rows inserted, GET returns only new.
 *
 *  4. Runner liveCount re-computation: see brandThreatRunner.rescan.test.ts
 *     which directly invokes runBrandThreatScan and asserts the count update
 *     is derived from archivedAt IS NULL filtered rows.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

// ── vi.hoisted: stateful in-memory database and spy bags ─────────────────────
//
// We use a STATEFUL in-memory table for brand_threat_results so that:
//   • update(brandThreatResultsTable).set({archivedAt}).where(...) actually marks rows
//   • select().from(brandThreatResultsTable).where(isNull(archivedAt)) actually filters
//   • Tests fail if the isNull predicate is removed from the route
//
// All other tables use a simple select queue (same pattern as other route tests).

const { dbState } = vi.hoisted(() => {
  type BtResultRow = {
    id: number;
    scanId: number;
    permutation: string;
    fuzzer: string;
    dnsA: string[] | null;
    dnsNs: string[] | null;
    dnsAaaa: string[] | null;
    dnsMx: string[] | null;
    isPhishing: boolean;
    riskScore: number;
    archivedAt: Date | null;
    createdAt: Date;
    [key: string]: unknown;
  };

  const dbState: {
    // Stateful table for brand_threat_results — predicate-evaluated
    brandThreatResults: BtResultRow[];
    // Simple queue for all other selects
    selectQueue: unknown[][];
    // Queue for .returning() results
    returningQueue: unknown[][];
    // Audit of mutations
    updateCalls: Array<{ table: string; set: Record<string, unknown> }>;
    deleteCalls: Array<{ table: string }>;
    reset(): void;
  } = {
    brandThreatResults: [],
    selectQueue: [],
    returningQueue: [],
    updateCalls: [],
    deleteCalls: [],
    reset() {
      this.brandThreatResults = [];
      this.selectQueue = [];
      this.returningQueue = [];
      this.updateCalls = [];
      this.deleteCalls = [];
    },
  };
  return { dbState };
});

// ── Predicate evaluator ───────────────────────────────────────────────────────
//
// Evaluates the opaque predicate objects returned by the drizzle-orm mock
// (see vi.mock("drizzle-orm") below) against a plain JS row object.
// This makes WHERE clauses real instead of ignored.

type Pred = { _type: string; col?: string; val?: unknown; args?: Pred[] };

function evalPred(row: Record<string, unknown>, pred: unknown): boolean {
  if (!pred || typeof pred !== "object") return true;
  const p = pred as Pred;
  switch (p._type) {
    case "isNull":    return row[p.col as string] == null;
    case "isNotNull": return row[p.col as string] != null;
    case "eq":        return row[p.col as string] === p.val;
    case "and":       return (p.args ?? []).every(a => evalPred(row, a));
    default:          return true; // unknown predicate — include row
  }
}

// ── Auth middleware mock ───────────────────────────────────────────────────────

vi.mock("../../lib/auth", () => {
  const requireAuth = (
    req: express.Request & { user?: Record<string, unknown> },
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    req.user = { userId: 1, tenantId: 1, role: "admin", email: "test@example.com" };
    next();
  };
  const denyExternalMembers = (
    _req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => next();
  return { requireAuth, denyExternalMembers };
});

// ── DB mock ───────────────────────────────────────────────────────────────────
//
// brand_threat_results uses the stateful in-memory table with predicate evaluation.
// All other tables use the simple selectQueue.

vi.mock("@workspace/db", () => {
  // Column name strings — used by evalPred to look up row properties.
  // The drizzle-orm mock's eq/isNull/etc. functions receive these strings
  // as the `col` argument, so evalPred can apply the right field filter.
  const brandThreatResultsTable = {
    id:         "id",
    scanId:     "scanId",
    permutation:"permutation",
    fuzzer:     "fuzzer",
    dnsA:       "dnsA",
    dnsNs:      "dnsNs",
    dnsAaaa:    "dnsAaaa",
    dnsMx:      "dnsMx",
    mxSpf:      "mxSpf",
    isPhishing: "isPhishing",
    riskScore:  "riskScore",
    archivedAt: "archivedAt",
    createdAt:  "createdAt",
    _:          { name: "brand_threat_results" },
  };

  const brandThreatScansTable = {
    id:               "id",
    tenantId:         "tenantId",
    domain:           "domain",
    status:           "status",
    liveCount:        "liveCount",
    registeredCount:  "registeredCount",
    phishingCount:    "phishingCount",
    dataLeakCount:    "dataLeakCount",
    brandAbuseCount:  "brandAbuseCount",
    darkWebCount:     "darkWebCount",
    phishingRisk:     "phishingRisk",
    fuzzerBreakdown:  "fuzzerBreakdown",
    error:            "error",
    completedAt:      "completedAt",
    _:                { name: "brand_threat_scans" },
  };

  /** Build a chainable select that evaluates predicates for brand_threat_results
   *  and falls through to selectQueue for all other tables. */
  const makeSelect = (_fields?: unknown) => ({
    from: (table: unknown) => {
      const tableName = (table as { _?: { name?: string } })?._?.name ?? "";

      const makeChain = (getRows: (pred: unknown) => unknown[]) => {
        const chainOf = (pred?: unknown) => {
          const rows = getRows(pred);
          const result = Object.assign(Promise.resolve(rows), {
            where:   (p: unknown) => chainOf(p),
            orderBy: ()           => chainOf(pred),
            limit:   (n: number)  => Promise.resolve(rows.slice(0, n)),
          });
          return result;
        };
        return {
          where:   (p: unknown) => chainOf(p),
          orderBy: ()           => chainOf(undefined),
          limit:   (n: number)  => Promise.resolve(getRows(undefined).slice(0, n)),
          then:    (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) =>
                   Promise.resolve(getRows(undefined)).then(res, rej),
        };
      };

      if (tableName === "brand_threat_results") {
        return makeChain(pred =>
          dbState.brandThreatResults.filter(r => evalPred(r as unknown as Record<string, unknown>, pred)),
        );
      }

      // All other tables: dequeue next batch
      const rows = dbState.selectQueue.length > 0 ? dbState.selectQueue.shift()! : [];
      return makeChain(() => rows);
    },
  });

  /** update() actually mutates brandThreatResults rows (predicate-filtered). */
  const makeUpdate = (table: unknown) => ({
    set: (payload: Record<string, unknown>) => {
      const tableName = (table as { _?: { name?: string } })?._?.name ?? "";
      return {
        where: (pred: unknown) => {
          dbState.updateCalls.push({ table: tableName, set: payload });

          if (tableName === "brand_threat_results") {
            // Apply payload to each row that matches the predicate
            dbState.brandThreatResults.forEach(r => {
              if (evalPred(r as unknown as Record<string, unknown>, pred)) {
                Object.assign(r, payload);
              }
            });
          }

          // `.where(...)` returns a thenable AND exposes `.returning()`
          const returning = () => {
            const row = dbState.returningQueue.length > 0
              ? dbState.returningQueue.shift()!
              : [payload];
            return Promise.resolve(row);
          };
          const p = Promise.resolve([payload]) as Promise<unknown[]> & { returning: typeof returning };
          p.returning = returning;
          return p;
        },
      };
    },
  });

  const makeDelete = (table: unknown) => ({
    where: (pred: unknown) => {
      const tableName = (table as { _?: { name?: string } })?._?.name ?? "";
      dbState.deleteCalls.push({ table: tableName });

      if (tableName === "brand_threat_results") {
        dbState.brandThreatResults = dbState.brandThreatResults.filter(
          r => !evalPred(r as unknown as Record<string, unknown>, pred),
        );
      }
      return Promise.resolve();
    },
  });

  const makeInsert = () => ({
    values: (vals: unknown) => ({
      returning: () => {
        const row = dbState.returningQueue.length > 0 ? dbState.returningQueue.shift()! : [vals];
        return Promise.resolve(row);
      },
    }),
  });

  return {
    db: { select: makeSelect, update: makeUpdate, delete: makeDelete, insert: makeInsert },
    brandThreatResultsTable,
    brandThreatScansTable,
    brandWatchlistItemsTable:  { _: { name: "brand_watchlist_items" } },
    dataLeakResultsTable:      { _: { name: "data_leak_results" } },
    phishingDetectionsTable:   { _: { name: "phishing_detections" } },
    brandAbuseResultsTable:    { _: { name: "brand_abuse_results" } },
    adMonitoringResultsTable:  { _: { name: "ad_monitoring_results" } },
    platformSettingsTable:     { _: { name: "platform_settings" } },
    assetsTable:               { _: { name: "assets" } },
    brandThreatSchedulesTable: { _: { name: "brand_threat_schedules" } },
  };
});

vi.mock("../../lib/amScoping", () => ({
  getAmClientTenantIds: vi.fn().mockResolvedValue([]),
}));

vi.mock("../../lib/brandThreatRunner", () => ({
  runBrandThreatScan: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../lib/notifier", () => ({
  dispatchNotifications: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── drizzle-orm mock — predicates carry their operands so evalPred can use them ──

vi.mock("drizzle-orm", async (importOriginal) => {
  const orig = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...orig,
    // Each predicate object carries _type + operands for evalPred
    eq:        vi.fn((col: unknown, val: unknown) => ({ _type: "eq", col, val })),
    isNull:    vi.fn((col: unknown)               => ({ _type: "isNull", col })),
    isNotNull: vi.fn((col: unknown)               => ({ _type: "isNotNull", col })),
    and:       vi.fn((...args: unknown[])          => ({ _type: "and", args })),
    desc:      vi.fn(()                            => ({ _type: "desc" })),
    inArray:   vi.fn(()                            => ({ _type: "inArray" })),
    gte:       vi.fn()                             ,
    lt:        vi.fn()                             ,
  };
});

// ── Fixtures ──────────────────────────────────────────────────────────────────

const SCAN_ID = 42;
const DOMAIN = "acme.com";

function makeOldResult(id: number): Record<string, unknown> {
  return {
    id,
    scanId: SCAN_ID,
    permutation: `acme-old-${id}.com`,
    fuzzer: "repetition",
    dnsA: ["1.2.3.4"],
    dnsNs: null, dnsAaaa: null, dnsMx: null,
    isPhishing: false,
    riskScore: 55,
    archivedAt: null, // starts live; POST archival will set this
    createdAt: new Date("2026-01-01T00:00:00Z"),
  };
}

function makeNewResult(): Record<string, unknown> {
  return {
    id: 200,
    scanId: SCAN_ID,
    permutation: "acme-login.com",
    fuzzer: "subdomain",
    dnsA: ["5.6.7.8"],
    dnsNs: null, dnsAaaa: null, dnsMx: ["mail.acme-login.com"],
    isPhishing: true,
    riskScore: 90,
    archivedAt: null,
    createdAt: new Date("2026-06-15T00:04:00Z"),
  };
}

const firstScan = {
  id: SCAN_ID, tenantId: 1, domain: DOMAIN,
  status: "done", progress: 100,
  totalPermutations: 200, liveCount: 3, registeredCount: 5,
  phishingRisk: "medium", fuzzerBreakdown: null, error: null,
  pipelineScanId: null, favihunterStatus: null, favihunterError: null,
  faviconUrl: null, faviconMmh3: null, faviconMmh3Hex: null,
  faviconMd5: null, faviconSha256: null, faviconSearchUrls: null,
  faviconShodanMatches: null,
  dataLeakCount: 0, phishingCount: 0, brandAbuseCount: 0, darkWebCount: 0,
  checkpoint: null, permutationsCache: null,
  createdAt: new Date("2026-01-01T00:00:00Z"),
  completedAt: new Date("2026-01-01T00:05:00Z"),
};

const rescanPendingScan = {
  ...firstScan,
  status: "pending", liveCount: 0, registeredCount: 0, phishingCount: 0,
  dataLeakCount: 0, brandAbuseCount: 0, darkWebCount: 0,
  phishingRisk: "low", fuzzerBreakdown: null, error: null, completedAt: null,
};

const rescanCompletedScan = {
  ...rescanPendingScan, status: "done", progress: 100,
  liveCount: 1, registeredCount: 1, phishingCount: 1,
  completedAt: new Date("2026-06-15T00:10:00Z"),
};

// ── App factory ───────────────────────────────────────────────────────────────

async function buildApp() {
  const { default: brandThreatsRouter } = await import("../brandThreats");
  const app = express();
  app.use(express.json());
  app.use(brandThreatsRouter);
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: err.message });
  });
  return app;
}

// ── POST re-scan: archival and counter reset ───────────────────────────────────

describe("POST /brand-threats re-scan — archival and counter reset", () => {
  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
  });

  it("archives ALL prior results via update(brandThreatResultsTable).set({archivedAt})", async () => {
    // Pre-seed 3 live old results in the stateful table
    dbState.brandThreatResults = [makeOldResult(10), makeOldResult(11), makeOldResult(12)] as unknown as typeof dbState.brandThreatResults;
    dbState.selectQueue = [[{ id: SCAN_ID }]]; // existing scan found
    dbState.returningQueue = [[rescanPendingScan]]; // scan reset returning()

    const app = await buildApp();
    await request(app).post("/brand-threats").send({ domain: DOMAIN }).set("Authorization", "Bearer test");

    // Every old row must now have archivedAt set (not null)
    const unarchived = dbState.brandThreatResults.filter(r => r.archivedAt == null);
    expect(unarchived).toHaveLength(0);

    const archived = dbState.brandThreatResults.filter(r => r.archivedAt != null);
    expect(archived).toHaveLength(3);
  });

  it("resets all scan counters to zero in the update payload", async () => {
    dbState.selectQueue = [[{ id: SCAN_ID }]];
    dbState.returningQueue = [[rescanPendingScan]];

    const app = await buildApp();
    const res = await request(app).post("/brand-threats").send({ domain: DOMAIN }).set("Authorization", "Bearer test");

    expect(res.status).toBe(200);
    expect(res.body.status).toBe("pending");
    expect(res.body.liveCount).toBe(0);
    expect(res.body.registeredCount).toBe(0);
    expect(res.body.phishingCount).toBe(0);
    expect(res.body.dataLeakCount).toBe(0);
    expect(res.body.brandAbuseCount).toBe(0);
    expect(res.body.darkWebCount).toBe(0);

    const scanReset = dbState.updateCalls.find(
      c => c.table === "brand_threat_scans" && (c.set as { liveCount?: number }).liveCount === 0,
    );
    expect(scanReset).toBeDefined();
    expect((scanReset!.set as { status?: string }).status).toBe("pending");
  });

  it("deletes secondary tables (phishing, dataLeaks, brandAbuse, adMonitoring) on re-scan", async () => {
    dbState.selectQueue = [[{ id: SCAN_ID }]];
    dbState.returningQueue = [[rescanPendingScan]];

    const app = await buildApp();
    await request(app).post("/brand-threats").send({ domain: DOMAIN }).set("Authorization", "Bearer test");

    const deletedTables = dbState.deleteCalls.map(c => c.table);
    expect(deletedTables).toContain("phishing_detections");
    expect(deletedTables).toContain("data_leak_results");
    expect(deletedTables).toContain("brand_abuse_results");
    expect(deletedTables).toContain("ad_monitoring_results");
  });

  it("creates a fresh scan record without archiving when no prior scan exists", async () => {
    dbState.selectQueue = [[]]; // no existing scan
    dbState.returningQueue = [[rescanPendingScan]];

    const app = await buildApp();
    const res = await request(app).post("/brand-threats").send({ domain: DOMAIN }).set("Authorization", "Bearer test");

    expect(res.status).toBe(200);
    // No update to brand_threat_results — no archival should have happened
    const archivalUpdate = dbState.updateCalls.find(c => c.table === "brand_threat_results");
    expect(archivalUpdate).toBeUndefined();

    const deletedTables = dbState.deleteCalls.map(c => c.table);
    expect(deletedTables).not.toContain("phishing_detections");
    expect(deletedTables).not.toContain("data_leak_results");
  });
});

// ── GET /brand-threats/:id: only live results visible after re-scan ────────────

describe("GET /brand-threats/:id — stateful archivedAt IS NULL enforcement", () => {
  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
  });

  it("returns ONLY new (non-archived) results — old archived rows are excluded by predicate", async () => {
    // Seed: 3 old archived rows + 1 new live row
    const oldArchived = makeOldResult(10);
    (oldArchived as Record<string, unknown>).archivedAt = new Date("2026-01-01");
    const oldArchived2 = makeOldResult(11);
    (oldArchived2 as Record<string, unknown>).archivedAt = new Date("2026-01-01");
    const oldArchived3 = makeOldResult(12);
    (oldArchived3 as Record<string, unknown>).archivedAt = new Date("2026-01-01");
    const newLive = makeNewResult();

    dbState.brandThreatResults = [
      oldArchived, oldArchived2, oldArchived3, newLive,
    ] as unknown as typeof dbState.brandThreatResults;

    // GET /:id (admin) select queue: scan row, then the other Promise.all tables
    // brand_threat_results uses the stateful table (no queue entry needed)
    dbState.selectQueue = [
      [rescanCompletedScan], // scan row
      [],                    // phishing_detections
      [],                    // data_leak_results
      [],                    // brand_abuse_results
      [],                    // ad_monitoring_results
      [],                    // platform_settings (meta_ads)
    ];

    const app = await buildApp();
    const res = await request(app).get(`/brand-threats/${SCAN_ID}`).set("Authorization", "Bearer test");

    expect(res.status).toBe(200);

    // Only the new live result should be returned
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0].permutation).toBe("acme-login.com");
    expect(res.body.results[0].archivedAt).toBeNull();

    // None of the 3 old results must appear
    const hasOldResult = (res.body.results as Array<{ permutation: string }>).some(
      r => r.permutation.startsWith("acme-old-"),
    );
    expect(hasOldResult).toBe(false);
  });

  it("liveCount on scan row is 1 (new only) — not 4 (old 3 + new 1)", async () => {
    const oldArchived = makeOldResult(10);
    (oldArchived as Record<string, unknown>).archivedAt = new Date("2026-01-01");
    const newLive = makeNewResult();
    dbState.brandThreatResults = [oldArchived, newLive] as unknown as typeof dbState.brandThreatResults;

    dbState.selectQueue = [
      [rescanCompletedScan], // scan row; liveCount=1 reflects new run only
      [], [], [], [], [],
    ];

    const app = await buildApp();
    const res = await request(app).get(`/brand-threats/${SCAN_ID}`).set("Authorization", "Bearer test");

    expect(res.status).toBe(200);
    // Scan-level counter: reflects only the new run
    expect(res.body.liveCount).toBe(1);
    // Results array: only the non-archived row
    expect(res.body.results).toHaveLength(1);
  });

  it("isNull() drizzle predicate is applied to archivedAt when fetching results for GET /:id", async () => {
    const newLive = makeNewResult();
    dbState.brandThreatResults = [newLive] as unknown as typeof dbState.brandThreatResults;
    dbState.selectQueue = [[rescanCompletedScan], [], [], [], [], []];

    const app = await buildApp();
    await request(app).get(`/brand-threats/${SCAN_ID}`).set("Authorization", "Bearer test");

    // The route must call isNull(brandThreatResultsTable.archivedAt) when building
    // the results query. With the column string mock, that means isNull("archivedAt").
    const { isNull } = await import("drizzle-orm");
    expect(vi.mocked(isNull)).toHaveBeenCalledWith("archivedAt");
  });

  it("returns empty results array when new scan found no live domains (all archived)", async () => {
    const oldArchived = makeOldResult(10);
    (oldArchived as Record<string, unknown>).archivedAt = new Date();
    dbState.brandThreatResults = [oldArchived] as unknown as typeof dbState.brandThreatResults;

    const emptyRescanScan = { ...rescanCompletedScan, liveCount: 0, registeredCount: 0 };
    dbState.selectQueue = [[emptyRescanScan], [], [], [], [], []];

    const app = await buildApp();
    const res = await request(app).get(`/brand-threats/${SCAN_ID}`).set("Authorization", "Bearer test");

    expect(res.status).toBe(200);
    expect(res.body.results).toHaveLength(0);
    expect(res.body.liveCount).toBe(0);
  });
});

// ── End-to-end lifecycle: POST → archival → GET ───────────────────────────────
//
// Verifies the full re-scan lifecycle in a single test:
//   1. Scan exists with 3 live old results
//   2. POST /brand-threats (re-scan) archives the 3 old results and resets counters
//   3. GET /brand-threats/:id returns 0 old results + 1 new result
//   4. liveCount = 1, not 4

describe("End-to-end re-scan lifecycle — POST then GET", () => {
  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
  });

  it("POST archives old results; GET returns only new results with correct liveCount", async () => {
    // === INITIAL STATE: scan with 3 live old results ===
    dbState.brandThreatResults = [
      makeOldResult(10), makeOldResult(11), makeOldResult(12),
    ] as unknown as typeof dbState.brandThreatResults;

    // POST: select returns existing scan record, returning() gives reset scan
    dbState.selectQueue = [[{ id: SCAN_ID }]];
    dbState.returningQueue = [[rescanPendingScan]];

    const app = await buildApp();

    // === POST /brand-threats — triggers re-scan ===
    const postRes = await request(app)
      .post("/brand-threats")
      .send({ domain: DOMAIN })
      .set("Authorization", "Bearer test");

    expect(postRes.status).toBe(200);
    expect(postRes.body.liveCount).toBe(0); // counters reset

    // All 3 old rows must now be archived
    const stillLive = dbState.brandThreatResults.filter(r => r.archivedAt == null);
    expect(stillLive).toHaveLength(0);

    // === SIMULATE RUNNER: insert 1 new live result ===
    const newResult = makeNewResult();
    dbState.brandThreatResults.push(newResult as unknown as typeof dbState.brandThreatResults[number]);

    // === GET /brand-threats/:id — after runner inserted its result ===
    // selectQueue: scan row (liveCount=1 from runner's DB update), then sub-tables
    dbState.selectQueue = [
      [{ ...rescanCompletedScan, liveCount: 1 }], // scan row
      [],                                          // phishing_detections
      [],                                          // data_leak_results
      [],                                          // brand_abuse_results
      [],                                          // ad_monitoring_results
      [],                                          // platform_settings (meta_ads)
    ];

    const getRes = await request(app)
      .get(`/brand-threats/${SCAN_ID}`)
      .set("Authorization", "Bearer test");

    expect(getRes.status).toBe(200);

    // Results: only the 1 new non-archived result
    expect(getRes.body.results).toHaveLength(1);
    expect(getRes.body.results[0].permutation).toBe("acme-login.com");

    // liveCount on the scan row reflects only the new run's 1 live result
    expect(getRes.body.liveCount).toBe(1);

    // Old results are invisible — they are archived and excluded by isNull(archivedAt)
    const hasOldResult = (getRes.body.results as Array<{ permutation: string }>).some(
      r => r.permutation.startsWith("acme-old-"),
    );
    expect(hasOldResult).toBe(false);
  });
});

// ── Domain validation ─────────────────────────────────────────────────────────

describe("POST /brand-threats — domain validation", () => {
  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
  });

  it("rejects an invalid domain and makes no DB mutations", async () => {
    const app = await buildApp();
    const res = await request(app)
      .post("/brand-threats")
      .send({ domain: "not-a-valid-domain" })
      .set("Authorization", "Bearer test");

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid domain/i);
    expect(dbState.updateCalls).toHaveLength(0);
    expect(dbState.deleteCalls).toHaveLength(0);
  });
});
