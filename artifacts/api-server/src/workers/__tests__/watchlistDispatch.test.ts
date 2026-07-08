/**
 * Unit tests for dispatchDueWatchlistDomains() and computeWatchlistNextScanAt()
 * in beatScheduler.ts.
 *
 * Key invariants:
 *  1. After dispatch, lastScanAt and lastScanId are written to the watchlist item.
 *  2. nextScanAt is advanced to the correct next interval (daily / weekly / monthly).
 *  3. A scan-runner failure does NOT leave nextScanAt stuck — the DB update happens
 *     synchronously before the setImmediate callback, so the watchlist item is always
 *     rescheduled even when runBrandThreatScan throws.
 *  4. Concurrency guard: if an existing scan is still "running" or "pending",
 *     only nextScanAt is rescheduled (lastScanAt / lastScanId are NOT overwritten).
 *  5. computeWatchlistNextScanAt returns the correct future timestamp for each
 *     supported frequency, and null for "none".
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── vi.hoisted ─────────────────────────────────────────────────────────────────
// State bags must be declared via vi.hoisted so they are accessible inside mock
// factory closures (which are hoisted above ordinary imports).

const { dbState } = vi.hoisted(() => {
  const dbState = {
    selectQueue:  [] as unknown[][],
    updateCalls:  [] as Array<{ table: string; set: Record<string, unknown>; where: unknown }>,
    insertCalls:  [] as Array<{ table: string; row: Record<string, unknown> }>,
    deleteCalls:  [] as Array<{ table: string; where: unknown }>,
    nextInsertId: 100,
    reset() {
      this.selectQueue  = [];
      this.updateCalls  = [];
      this.insertCalls  = [];
      this.deleteCalls  = [];
      this.nextInsertId = 100;
    },
  };
  return { dbState };
});

const { runnerState } = vi.hoisted(() => {
  const runnerState = {
    calls:       [] as unknown[][],
    shouldThrow: false,
    reset() {
      this.calls       = [];
      this.shouldThrow = false;
    },
  };
  return { runnerState };
});

// ── Mock @workspace/db ────────────────────────────────────────────────────────
// Provides a lightweight query-builder stub.  Each db.select() dequeues the next
// response from dbState.selectQueue; db.update/insert/delete record their calls
// for assertion.

vi.mock("@workspace/db", () => {
  const makeTable = (name: string) => ({
    _tableName: name,
    id: name + ".id",
    tenantId: name + ".tenantId",
    domain: name + ".domain",
    status: name + ".status",
    value: name + ".value",
    type: name + ".type",
    frequency: name + ".frequency",
    scanTime: name + ".scanTime",
    dayOfWeek: name + ".dayOfWeek",
    dayOfMonth: name + ".dayOfMonth",
    nextScanAt: name + ".nextScanAt",
    lastScanAt: name + ".lastScanAt",
    lastScanId: name + ".lastScanId",
    scanId: name + ".scanId",
    archivedAt: name + ".archivedAt",
  });

  const db = {
    select: (_fields?: unknown) => {
      const rows = dbState.selectQueue.shift() ?? [];
      return {
        from: (_table: unknown) => ({
          where: (_cond: unknown) => Promise.resolve(rows),
          orderBy: (_col: unknown) => ({
            limit: (_n: number) => Promise.resolve((rows as unknown[]).slice(0, _n)),
          }),
        }),
      };
    },
    update: (table: { _tableName: string }) => ({
      set: (payload: Record<string, unknown>) => ({
        where: (cond: unknown) => {
          dbState.updateCalls.push({ table: table._tableName, set: payload, where: cond });
          return Promise.resolve([]);
        },
      }),
    }),
    insert: (table: { _tableName: string }) => ({
      values: (vals: Record<string, unknown>) => ({
        returning: () => {
          const id = dbState.nextInsertId++;
          const row = { id, ...vals };
          dbState.insertCalls.push({ table: table._tableName, row });
          return Promise.resolve([row]);
        },
      }),
    }),
    delete: (table: { _tableName: string }) => ({
      where: (cond: unknown) => {
        dbState.deleteCalls.push({ table: table._tableName, where: cond });
        return Promise.resolve([]);
      },
    }),
  };

  return {
    db,
    brandWatchlistItemsTable:   makeTable("brandWatchlistItems"),
    brandThreatScansTable:      makeTable("brandThreatScans"),
    brandThreatResultsTable:    makeTable("brandThreatResults"),
    phishingDetectionsTable:    makeTable("phishingDetections"),
    dataLeakResultsTable:       makeTable("dataLeakResults"),
    brandAbuseResultsTable:     makeTable("brandAbuseResults"),
    adMonitoringResultsTable:   makeTable("adMonitoringResults"),
    assetsTable:                makeTable("assets"),
    scansTable:                 makeTable("scans"),
    scanJobsTable:              makeTable("scanJobs"),
    scanSchedulesTable:         makeTable("scanSchedules"),
    securityToolsTable:         makeTable("securityTools"),
    toolPipelineStepsTable:     makeTable("toolPipelineSteps"),
    alertsTable:                makeTable("alerts"),
    platformSettingsTable:      makeTable("platformSettings"),
    brandThreatSchedulesTable:  makeTable("brandThreatSchedules"),
    aiMapperScanSchedulesTable: makeTable("aiMapperScanSchedules"),
    aiMapperScansTable:         makeTable("aiMapperScans"),
    assetGroupMembersTable:     makeTable("assetGroupMembers"),
  };
});

// ── Mock drizzle-orm ──────────────────────────────────────────────────────────

vi.mock("drizzle-orm", () => ({
  and:      vi.fn((...args: unknown[]) => ({ _type: "and", args })),
  eq:       vi.fn((col: unknown, val: unknown) => ({ _type: "eq", col, val })),
  ne:       vi.fn((col: unknown, val: unknown) => ({ _type: "ne", col, val })),
  lt:       vi.fn((col: unknown, val: unknown) => ({ _type: "lt", col, val })),
  lte:      vi.fn((col: unknown, val: unknown) => ({ _type: "lte", col, val })),
  isNotNull:vi.fn((col: unknown) => ({ _type: "isNotNull", col })),
  isNull:   vi.fn((col: unknown) => ({ _type: "isNull", col })),
  inArray:  vi.fn((col: unknown, arr: unknown) => ({ _type: "inArray", col, arr })),
  desc:     vi.fn((col: unknown) => ({ _type: "desc", col })),
  sql:      Object.assign(
    vi.fn((_tpl: TemplateStringsArray, ..._vals: unknown[]) => ({ _type: "sql" })),
    { placeholder: vi.fn() },
  ),
}));

// ── Mock logger ───────────────────────────────────────────────────────────────

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── Mock brandThreatRunner (dynamically imported inside the function) ─────────

vi.mock("../../lib/brandThreatRunner", () => ({
  runBrandThreatScan: (...args: unknown[]) => {
    runnerState.calls.push(args);
    if (runnerState.shouldThrow) {
      return Promise.reject(new Error("Simulated scan failure"));
    }
    return Promise.resolve(undefined);
  },
  triggerBrandThreatScan: vi.fn().mockResolvedValue(undefined),
}));

// ── Mock other beatScheduler dependencies ────────────────────────────────────

vi.mock("../../lib/redis",              () => ({ makeBullConnection: vi.fn() }));
vi.mock("../../queues/scanQueue",       () => ({ getScanQueue: vi.fn().mockReturnValue(null) }));
vi.mock("../../lib/githubVersionChecker", () => ({ fetchLatestVersion: vi.fn() }));
vi.mock("../../lib/sseManager",         () => ({ pushSseEvent: vi.fn() }));
vi.mock("../../routes/platformSettings", () => ({ getPlatformSetting: vi.fn().mockResolvedValue(null) }));
vi.mock("../../lib/intelxClient",        () => ({ intelxSearch: vi.fn(), intelxTypeToBucket: vi.fn() }));
vi.mock("../../lib/brandAbuseScanner",  () => ({ scanBrandAbuse: vi.fn() }));

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeDueItem(overrides: Record<string, unknown> = {}) {
  return {
    id:          1,
    tenantId:    10,
    type:        "domain",
    value:       "example.com",
    frequency:   "daily",
    scanTime:    "03:00",
    dayOfWeek:   null,
    dayOfMonth:  null,
    nextScanAt:  new Date(Date.now() - 60_000),
    lastScanAt:  null,
    lastScanId:  null,
    prevScanSummary: null,
    ...overrides,
  };
}

/** Drain all pending setImmediate callbacks. */
async function flushSetImmediate() {
  await new Promise<void>(resolve => setImmediate(resolve));
}

// ── computeWatchlistNextScanAt — direct unit tests ────────────────────────────

describe("computeWatchlistNextScanAt", () => {
  it('returns null for frequency "none"', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    const from = new Date();
    const result = computeWatchlistNextScanAt("none", from);
    expect(result).toBeNull();
  });

  it('returns null for empty string frequency', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    const result = computeWatchlistNextScanAt("", new Date());
    expect(result).toBeNull();
  });

  it('advances by ~24 h for "daily"', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    const from = new Date("2026-07-08T12:00:00Z");
    const next  = computeWatchlistNextScanAt("daily", from, "03:00");
    expect(next).not.toBeNull();
    // Should be the next day at 03:00 UTC
    expect(next!.getUTCDate()).toBe(9);
    expect(next!.getUTCHours()).toBe(3);
    expect(next!.getUTCMinutes()).toBe(0);
  });

  it('advances to the next occurrence of the given day-of-week for "weekly"', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    // 2026-07-08 is a Wednesday (day 3)
    const from = new Date("2026-07-08T12:00:00Z");
    // Request next Monday (day 1)
    const next = computeWatchlistNextScanAt("weekly", from, "03:00", 1);
    expect(next).not.toBeNull();
    expect(next!.getUTCDay()).toBe(1);  // Monday
    // It should be at least 1 day ahead (never in the past or same-day same-time)
    expect(next!.getTime()).toBeGreaterThan(from.getTime());
  });

  it('does not return same day when "weekly" and same dow is requested', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    // 2026-07-08 is a Wednesday (day 3) at 12:00 UTC — "now" is past 03:00
    const from = new Date("2026-07-08T12:00:00Z");
    const next = computeWatchlistNextScanAt("weekly", from, "03:00", 3); // same Wednesday
    expect(next).not.toBeNull();
    // Must be the NEXT Wednesday, not today
    expect(next!.getTime()).toBeGreaterThan(from.getTime());
    expect(next!.getUTCDay()).toBe(3);
  });

  it('advances to next month for "monthly" when the dom has already passed this month', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    // from = July 8; dayOfMonth = 1 (already past)
    const from = new Date("2026-07-08T12:00:00Z");
    const next = computeWatchlistNextScanAt("monthly", from, "03:00", null, 1);
    expect(next).not.toBeNull();
    expect(next!.getUTCMonth()).toBe(7); // August
    expect(next!.getUTCDate()).toBe(1);
  });

  it('stays in the current month for "monthly" when the dom is still in the future', async () => {
    const { computeWatchlistNextScanAt } = await import("../beatScheduler");
    // from = July 8; dayOfMonth = 15 (still ahead)
    const from = new Date("2026-07-08T12:00:00Z");
    const next = computeWatchlistNextScanAt("monthly", from, "03:00", null, 15);
    expect(next).not.toBeNull();
    expect(next!.getUTCMonth()).toBe(6); // still July
    expect(next!.getUTCDate()).toBe(15);
  });
});

// ── dispatchDueWatchlistDomains ───────────────────────────────────────────────

describe("dispatchDueWatchlistDomains", () => {
  beforeEach(() => {
    dbState.reset();
    runnerState.reset();
    vi.clearAllMocks();
  });

  // Drain any setImmediate callbacks scheduled by the previous test so they
  // cannot bleed into the next test's runnerState.calls.
  afterEach(async () => {
    await flushSetImmediate();
  });

  // ── Invariant 1 + 2: lastScanAt, lastScanId, and nextScanAt are updated ─────

  it("updates lastScanAt, lastScanId, and nextScanAt on the watchlist item after dispatch", async () => {
    const before = Date.now();

    // First select: the due watchlist item
    // Second select: no existing brand threat scan for this domain
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily" })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const watchlistUpdate = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    expect(watchlistUpdate, "watchlist item must be updated").toBeDefined();

    const { lastScanAt, lastScanId, nextScanAt } = watchlistUpdate!.set as {
      lastScanAt: Date;
      lastScanId: number;
      nextScanAt: Date | null;
    };

    expect(lastScanAt, "lastScanAt must be set to approximately now").toBeInstanceOf(Date);
    expect(lastScanAt.getTime()).toBeGreaterThanOrEqual(before);

    expect(typeof lastScanId).toBe("number");
    expect(lastScanId).toBeGreaterThan(0);

    expect(nextScanAt, "nextScanAt must be scheduled in the future").toBeInstanceOf(Date);
    expect(nextScanAt!.getTime()).toBeGreaterThan(Date.now());
  });

  it("creates a new brandThreatScans row when no prior scan exists", async () => {
    dbState.selectQueue = [
      [makeDueItem()],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const scanInsert = dbState.insertCalls.find(c => c.table === "brandThreatScans");
    expect(scanInsert, "a new scan row must be inserted").toBeDefined();
    expect(scanInsert!.row.domain).toBe("example.com");
    expect(scanInsert!.row.status).toBe("pending");
  });

  it("sets lastScanId to the newly inserted scan's id", async () => {
    dbState.selectQueue = [
      [makeDueItem()],
      [],
    ];
    dbState.nextInsertId = 77;

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const watchlistUpdate = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    expect(watchlistUpdate).toBeDefined();
    expect((watchlistUpdate!.set as { lastScanId: number }).lastScanId).toBe(77);
  });

  // ── Invariant 2: nextScanAt interval correctness ───────────────────────────

  it('nextScanAt is ~24 h ahead for frequency "daily"', async () => {
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily", scanTime: "03:00" })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const update = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    const { nextScanAt } = update!.set as { nextScanAt: Date };

    const hoursAhead = (nextScanAt.getTime() - Date.now()) / 3_600_000;
    expect(hoursAhead).toBeGreaterThan(0);    // in the future
    expect(hoursAhead).toBeLessThan(48);      // but not more than 2 days
  });

  it('nextScanAt is ~7 days ahead for frequency "weekly"', async () => {
    dbState.selectQueue = [
      [makeDueItem({ frequency: "weekly", scanTime: "03:00", dayOfWeek: 1 })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const update = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    const { nextScanAt } = update!.set as { nextScanAt: Date };

    const daysAhead = (nextScanAt.getTime() - Date.now()) / 86_400_000;
    expect(daysAhead).toBeGreaterThan(0);
    expect(daysAhead).toBeLessThanOrEqual(8);
    expect(nextScanAt.getUTCDay()).toBe(1); // Monday
  });

  it('nextScanAt falls on the correct day of month for frequency "monthly"', async () => {
    dbState.selectQueue = [
      [makeDueItem({ frequency: "monthly", scanTime: "03:00", dayOfMonth: 1 })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const update = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    const { nextScanAt } = update!.set as { nextScanAt: Date };

    expect(nextScanAt.getUTCDate()).toBe(1);
    expect(nextScanAt.getTime()).toBeGreaterThan(Date.now());
  });

  // ── Invariant 3: failure does NOT leave nextScanAt stuck ──────────────────

  it("nextScanAt is set before the scan runner fires — failure cannot un-schedule it", async () => {
    runnerState.shouldThrow = true;

    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily" })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    // The watchlist DB update MUST have already happened before we let
    // setImmediate fire (the update is synchronous relative to the dispatch call).
    const updatesBefore = dbState.updateCalls.filter(c => c.table === "brandWatchlistItems").length;
    expect(updatesBefore, "watchlist update must happen before scan runner").toBe(1);

    const { nextScanAt } = dbState.updateCalls.find(c => c.table === "brandWatchlistItems")!.set as {
      nextScanAt: Date;
    };
    expect(nextScanAt, "nextScanAt must be a future Date even before scan runs").toBeInstanceOf(Date);
    expect(nextScanAt.getTime()).toBeGreaterThan(Date.now());

    // Now let the scan runner fire and throw
    await flushSetImmediate();

    // No additional watchlist update should have been triggered by the failure —
    // nextScanAt remains exactly as set above (not nulled, not reset).
    const updatesAfter = dbState.updateCalls.filter(c => c.table === "brandWatchlistItems").length;
    expect(updatesAfter, "failure must not cause an extra watchlist update").toBe(1);
  });

  it("runBrandThreatScan is still invoked even after the watchlist update", async () => {
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily" })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();
    await flushSetImmediate();

    expect(runnerState.calls).toHaveLength(1);
    const [scanId, domain] = runnerState.calls[0]!;
    expect(typeof scanId).toBe("number");
    expect(domain).toBe("example.com");
  });

  // ── Invariant 4: concurrency guard ───────────────────────────────────────

  it("does NOT overwrite lastScanAt / lastScanId when existing scan is still running", async () => {
    const existingRunning = {
      id:     55,
      domain: "example.com",
      status: "running",
      tenantId: 10,
    };
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily", lastScanId: 55 })],
      [existingRunning],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const watchlistUpdates = dbState.updateCalls.filter(c => c.table === "brandWatchlistItems");
    // There must be exactly one update (the rescheduling update)
    expect(watchlistUpdates).toHaveLength(1);

    const { nextScanAt, lastScanAt, lastScanId } = watchlistUpdates[0]!.set as {
      nextScanAt?: Date;
      lastScanAt?: Date;
      lastScanId?: number;
    };

    // nextScanAt IS updated (re-queue to the next slot)
    expect(nextScanAt, "nextScanAt must be rescheduled by the concurrency guard").toBeInstanceOf(Date);
    expect(nextScanAt!.getTime()).toBeGreaterThan(Date.now());

    // lastScanAt and lastScanId must NOT be overwritten while a scan is running
    expect(lastScanAt,  "lastScanAt must not be overwritten during in-progress scan").toBeUndefined();
    expect(lastScanId,  "lastScanId must not be overwritten during in-progress scan").toBeUndefined();
  });

  it("does NOT overwrite lastScanAt / lastScanId when existing scan is still pending", async () => {
    const existingPending = {
      id:       66,
      domain:   "example.com",
      status:   "pending",
      tenantId: 10,
    };
    dbState.selectQueue = [
      [makeDueItem({ frequency: "weekly", dayOfWeek: 1 })],
      [existingPending],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const watchlistUpdates = dbState.updateCalls.filter(c => c.table === "brandWatchlistItems");
    expect(watchlistUpdates).toHaveLength(1);

    const { lastScanAt, lastScanId } = watchlistUpdates[0]!.set as {
      lastScanAt?: Date;
      lastScanId?: number;
    };
    expect(lastScanAt).toBeUndefined();
    expect(lastScanId).toBeUndefined();
  });

  it("does nothing when no due items are found", async () => {
    dbState.selectQueue = [[]];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();
    await flushSetImmediate();

    expect(dbState.updateCalls).toHaveLength(0);
    expect(dbState.insertCalls).toHaveLength(0);
    expect(runnerState.calls).toHaveLength(0);
  });

  // ── Re-scan of an existing completed scan ────────────────────────────────

  it("resets an existing completed scan and archives its prior results", async () => {
    const existingDone = {
      id:                  42,
      domain:              "example.com",
      status:              "done",
      tenantId:            10,
      totalPermutations:   50,
      liveCount:           5,
      registeredCount:     20,
      phishingCount:       2,
      dataLeakCount:       1,
      brandAbuseCount:     0,
    };
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily" })],
      [existingDone],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    // No new scan should be inserted — the existing one is reused
    const scanInsert = dbState.insertCalls.find(c => c.table === "brandThreatScans");
    expect(scanInsert, "must NOT insert a new scan row when reusing an existing one").toBeUndefined();

    // The existing scan must be reset to "pending"
    const scanReset = dbState.updateCalls.find(
      c => c.table === "brandThreatScans" && (c.set as { status?: string }).status === "pending",
    );
    expect(scanReset, "existing scan must be reset to pending").toBeDefined();

    // Prior results must be archived (soft-delete)
    const archival = dbState.updateCalls.find(
      c => c.table === "brandThreatResults" && (c.set as { archivedAt?: unknown }).archivedAt,
    );
    expect(archival, "prior brand threat results must be archived").toBeDefined();

    // watchlist item must be updated with the reused scanId
    const watchlistUpdate = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    expect(watchlistUpdate).toBeDefined();
    expect((watchlistUpdate!.set as { lastScanId: number }).lastScanId).toBe(42);
  });

  it("stores the previous scan summary as prevScanSummary before overwriting", async () => {
    const existingDone = {
      id:                42,
      domain:            "example.com",
      status:            "done",
      tenantId:          10,
      totalPermutations: 100,
      liveCount:         10,
      registeredCount:   40,
      phishingCount:     3,
      dataLeakCount:     2,
      brandAbuseCount:   1,
    };
    dbState.selectQueue = [
      [makeDueItem({ frequency: "daily" })],
      [existingDone],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();

    const watchlistUpdate = dbState.updateCalls.find(c => c.table === "brandWatchlistItems");
    expect(watchlistUpdate).toBeDefined();

    const { prevScanSummary } = watchlistUpdate!.set as { prevScanSummary: Record<string, number> | null | undefined };
    expect(prevScanSummary, "prevScanSummary must be populated from the prior scan").toBeTruthy();
    expect(typeof prevScanSummary).toBe("object");
    const summary = prevScanSummary as Record<string, number>;
    expect(summary.totalPermutations).toBe(100);
    expect(summary.phishingCount).toBe(3);
  });

  // ── Domain normalisation ───────────────────────────────────────────────────

  it("normalises the domain before scanning (strips https:// and www.)", async () => {
    dbState.selectQueue = [
      [makeDueItem({ value: "https://www.Example.COM/path?q=1" })],
      [],
    ];

    const { dispatchDueWatchlistDomains } = await import("../beatScheduler");
    await dispatchDueWatchlistDomains();
    await flushSetImmediate();

    expect(runnerState.calls).toHaveLength(1);
    const [, domain] = runnerState.calls[0]!;
    expect(domain).toBe("example.com");
  });
});
