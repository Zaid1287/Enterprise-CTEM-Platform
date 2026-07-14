/**
 * Unit tests for startBrandThreatWatchdog() — the periodic watchdog that
 * catches brand threat scans stuck in "running" state mid-run (e.g. a
 * dnstwist subprocess hang or a VT API timeout without a server restart).
 *
 * Key invariants tested:
 *  1. A scan older than 30 minutes is reset to status="error" with
 *     completedAt set and an informative error message.
 *  2. Scans younger than 30 minutes are left completely untouched
 *     (no update calls are issued).
 *  3. The watchdog tick fires on the correct 5-minute setInterval cadence.
 *  4. The cleanup function returned by startBrandThreatWatchdog() stops
 *     the interval so no further ticks occur.
 *  5. When the DB returns multiple stuck scans, every one of them is reset.
 *  6. A tick that encounters a DB error is swallowed (non-fatal) — the
 *     watchdog must not crash or leave the interval stopped.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── vi.hoisted — state bags accessible inside mock factories ──────────────────

const { dbState } = vi.hoisted(() => {
  const dbState = {
    selectResults: [] as unknown[][],
    selectIdx: 0,
    updateCalls: [] as { set: unknown; where: unknown }[],
    shouldSelectThrow: false,
    reset() {
      this.selectResults = [];
      this.selectIdx = 0;
      this.updateCalls = [];
      this.shouldSelectThrow = false;
    },
  };
  return { dbState };
});

// ── Mock @workspace/db ────────────────────────────────────────────────────────

vi.mock("@workspace/db", () => {
  const makeSelect = (_fields?: unknown) => {
    return {
      from: (_table: unknown) => ({
        where: (_cond: unknown) => {
          if (dbState.shouldSelectThrow) return Promise.reject(new Error("DB unavailable"));
          const rows = dbState.selectResults[dbState.selectIdx++] ?? [];
          return Promise.resolve(rows);
        },
      }),
    };
  };

  const makeUpdate = (_table: unknown) => ({
    set: (payload: unknown) => ({
      where: (cond: unknown) => {
        dbState.updateCalls.push({ set: payload, where: cond });
        return Promise.resolve();
      },
    }),
  });

  return {
    db: { select: makeSelect, update: makeUpdate },
    brandThreatScansTable: {
      id: "id",
      tenantId: "tenantId",
      domain: "domain",
      status: "status",
      createdAt: "createdAt",
      error: "error",
      completedAt: "completedAt",
      checkpoint: "checkpoint",
      permutationsCache: "permutationsCache",
    },
    brandThreatResultsTable: { _: { name: "brand_threat_results" } },
    dataLeakResultsTable:    { _: { name: "data_leak_results" } },
    phishingDetectionsTable: { _: { name: "phishing_detections" } },
    brandAbuseResultsTable:  { _: { name: "brand_abuse_results" } },
    adMonitoringResultsTable:{ _: { name: "ad_monitoring_results" } },
    brandWatchlistItemsTable:{ _: { name: "brand_watchlist_items" } },
    cdnWhitelistTable:       { _: { name: "cdn_whitelist_entries" } },
  };
});

// ── Mock drizzle-orm ──────────────────────────────────────────────────────────

vi.mock("drizzle-orm", () => ({
  and:       vi.fn((...args: unknown[]) => ({ _type: "and", args })),
  eq:        vi.fn((col: unknown, val: unknown) => ({ _type: "eq", col, val })),
  lt:        vi.fn((col: unknown, val: unknown) => ({ _type: "lt", col, val })),
  gte:       vi.fn((col: unknown, val: unknown) => ({ _type: "gte", col, val })),
  isNotNull: vi.fn((col: unknown) => ({ _type: "isNotNull", col })),
  isNull:    vi.fn((col: unknown) => ({ _type: "isNull", col })),
  desc:      vi.fn((col: unknown) => ({ _type: "desc", col })),
  sql:       vi.fn(),
}));

// ── Mock logger ───────────────────────────────────────────────────────────────

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── Mock all other brandThreatRunner.ts dependencies ─────────────────────────

vi.mock("../metaAdsClient", () => ({ scanMetaAds: vi.fn().mockResolvedValue([]) }));
vi.mock("../abuseChFeeds",  () => ({ queryAbuseChFeeds: vi.fn().mockResolvedValue([]) }));
vi.mock("../rdapClient",          () => ({ rdapLookup: vi.fn().mockResolvedValue(null) }));
vi.mock("../geoIpClient",         () => ({ geoIpBatch: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../phishFeedClient",     () => ({
  checkPhishingFeed: vi.fn().mockResolvedValue({ isPhishing: false, source: null }),
  setPhishTankKey:   vi.fn(),
}));
vi.mock("../googleSafeBrowsing",  () => ({ checkGoogleSafeBrowsing: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../hibpClient",          () => ({
  hibpDomainLookup:   vi.fn().mockResolvedValue(null),
  severityFromBreach: vi.fn().mockReturnValue("medium"),
}));
vi.mock("../vtDomainClient",      () => ({
  vtDomainLookup: vi.fn().mockResolvedValue(null),
  vtUrlScan:      vi.fn().mockResolvedValue(null),
}));
vi.mock("../brandAbuseScanner",   () => ({ scanBrandAbuse: vi.fn().mockResolvedValue([]) }));
vi.mock("../intelxClient",        () => ({
  intelxSearch:        vi.fn().mockResolvedValue([]),
  intelxTypeToBucket:  vi.fn().mockReturnValue("pastes"),
}));
vi.mock("../shodanFaviconClient", () => ({ searchShodanByFaviconHash: vi.fn().mockResolvedValue([]) }));
vi.mock("../notifier",            () => ({ dispatchNotifications: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../../routes/platformSettings", () => ({
  getPlatformSetting: vi.fn().mockResolvedValue(null),
}));
vi.mock("../screenshotEngine",    () => ({ captureScreenshots: vi.fn().mockResolvedValue([]) }));
vi.mock("node:dns/promises", () => ({
  default: {
    resolve4:  vi.fn().mockResolvedValue([]),
    resolve6:  vi.fn().mockResolvedValue([]),
    resolveMx: vi.fn().mockResolvedValue([]),
    resolveNs: vi.fn().mockResolvedValue([]),
  },
}));
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/** A scan that has been running for 45 minutes — well past the 30-min threshold. */
function makeStuckScan(id = 1, overrideAgeMs = 45 * 60 * 1_000) {
  return {
    id,
    domain: "example.com",
    createdAt: new Date(Date.now() - overrideAgeMs),
  };
}

/** Advance fake timers by exactly 5 minutes and flush all pending microtasks. */
async function advanceOneWatchdogTick() {
  await vi.advanceTimersByTimeAsync(5 * 60 * 1_000);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("startBrandThreatWatchdog", () => {
  let cleanup: (() => void) | undefined;

  beforeEach(() => {
    dbState.reset();
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    cleanup?.();
    cleanup = undefined;
    vi.useRealTimers();
  });

  // ── Invariant 1: stuck scans are reset to "error" ─────────────────────────

  it("resets a scan older than 30 minutes to status='error' with completedAt", async () => {
    dbState.selectResults = [[makeStuckScan(42)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(1);
    const { set } = dbState.updateCalls[0]! as { set: Record<string, unknown> };
    expect(set.status).toBe("error");
    expect(set.completedAt).toBeInstanceOf(Date);
    expect(typeof set.error).toBe("string");
    expect((set.error as string).length).toBeGreaterThan(0);
  });

  it("includes the scan age in the error message", async () => {
    dbState.selectResults = [[makeStuckScan(7, 90 * 60 * 1_000)]]; // 90-min-old scan

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    const { set } = dbState.updateCalls[0]! as { set: Record<string, unknown> };
    // The error message should mention the approximate age (90 minutes)
    expect(set.error as string).toMatch(/\d+\s*(minute|min)/i);
  });

  it("sets completedAt to a recent Date (within a few seconds of now)", async () => {
    const before = Date.now();
    dbState.selectResults = [[makeStuckScan(9)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();
    const after = Date.now();

    const { set } = dbState.updateCalls[0]! as { set: Record<string, unknown> };
    const completedAt = set.completedAt as Date;
    expect(completedAt.getTime()).toBeGreaterThanOrEqual(before);
    expect(completedAt.getTime()).toBeLessThanOrEqual(after + 5 * 60 * 1_000); // allow fake-timer offset
  });

  // ── Invariant 2: young scans are untouched ────────────────────────────────

  it("does not call update when no stuck scans are returned (young scans excluded by lt filter)", async () => {
    // DB returns empty array — simulates the production case where the lt(createdAt, threshold)
    // predicate excludes all scans younger than 30 minutes.
    dbState.selectResults = [[]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(0);
  });

  it("does not issue any update when the DB returns an empty result set", async () => {
    dbState.selectResults = [[], [], []]; // multiple ticks, all empty

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    // Advance through 3 full ticks
    await advanceOneWatchdogTick();
    await advanceOneWatchdogTick();
    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(0);
  });

  // ── Invariant 3: correct interval cadence ────────────────────────────────

  it("does not fire before 5 minutes have elapsed", async () => {
    dbState.selectResults = [[makeStuckScan(1)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    // Advance only 4 minutes 59 seconds — should not trigger
    await vi.advanceTimersByTimeAsync(4 * 60 * 1_000 + 59 * 1_000);

    expect(dbState.updateCalls).toHaveLength(0);
  });

  it("fires exactly once after the first 5-minute tick", async () => {
    dbState.selectResults = [[makeStuckScan(1)], [makeStuckScan(2)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    // Exactly one tick → one select call → one update
    expect(dbState.updateCalls).toHaveLength(1);
  });

  it("fires twice after two 5-minute intervals", async () => {
    // Two ticks each return one stuck scan
    dbState.selectResults = [[makeStuckScan(1)], [makeStuckScan(2)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();
    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(2);
  });

  // ── Invariant 4: cleanup stops the interval ───────────────────────────────

  it("stops firing after the cleanup function is called", async () => {
    dbState.selectResults = [[makeStuckScan(1)], [makeStuckScan(2)], [makeStuckScan(3)]];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    // First tick fires normally
    await advanceOneWatchdogTick();
    expect(dbState.updateCalls).toHaveLength(1);

    // Stop the watchdog
    cleanup();
    cleanup = undefined;

    // Second and third ticks should not fire
    await advanceOneWatchdogTick();
    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(1); // unchanged
  });

  // ── Invariant 5: multiple stuck scans in one tick ─────────────────────────

  it("resets all stuck scans found in a single tick — not just the first one", async () => {
    dbState.selectResults = [
      [makeStuckScan(10), makeStuckScan(11), makeStuckScan(12)],
    ];

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(3);
    for (const call of dbState.updateCalls) {
      const { set } = call as { set: Record<string, unknown> };
      expect(set.status).toBe("error");
      expect(set.completedAt).toBeInstanceOf(Date);
    }
  });

  // ── Invariant 6: DB errors are swallowed (non-fatal) ─────────────────────

  it("does not throw or stop the interval when the DB select throws", async () => {
    dbState.shouldSelectThrow = true;

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    // Should not throw
    await expect(advanceOneWatchdogTick()).resolves.toBeUndefined();

    // Interval is still alive — reset state and verify next tick works
    dbState.shouldSelectThrow = false;
    dbState.selectResults = [[makeStuckScan(99)]];

    await advanceOneWatchdogTick();

    expect(dbState.updateCalls).toHaveLength(1);
  });

  // ── Threshold boundary: exactly 30 minutes ────────────────────────────────

  it("uses a 30-minute threshold — lt() is called with a date 30 min before now", async () => {
    dbState.selectResults = [[]];

    const drizzle = await import("drizzle-orm");
    const ltSpy = vi.spyOn(drizzle, "lt");

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    const beforeTick = Date.now();
    await advanceOneWatchdogTick();
    const afterTick = Date.now();

    expect(ltSpy).toHaveBeenCalled();

    // The second argument to lt() should be a Date ~30 minutes in the past
    const ltCall = ltSpy.mock.calls[0]!;
    const thresholdDate = ltCall[1] as Date;
    expect(thresholdDate).toBeInstanceOf(Date);

    const thresholdMs = thresholdDate.getTime();
    const expectedMin = beforeTick - 30 * 60 * 1_000 - 1_000; // 1s slack
    const expectedMax = afterTick  - 30 * 60 * 1_000 + 5 * 60 * 1_000 + 1_000; // fake-timer offset

    expect(thresholdMs).toBeGreaterThanOrEqual(expectedMin);
    expect(thresholdMs).toBeLessThanOrEqual(expectedMax);
  });

  // ── Query shape: only "running" scans are targeted ────────────────────────

  it("queries only scans with status='running' — eq() is called with 'running'", async () => {
    dbState.selectResults = [[]];

    const drizzle = await import("drizzle-orm");
    const eqSpy = vi.spyOn(drizzle, "eq");

    const { startBrandThreatWatchdog } = await import("../../lib/brandThreatRunner");
    cleanup = startBrandThreatWatchdog();

    await advanceOneWatchdogTick();

    const eqValues = eqSpy.mock.calls.map(c => c[1]);
    expect(eqValues).toContain("running");
  });
});
