/**
 * Tests for brandThreatRunner.ts
 *
 * 1. Integration: runBrandThreatScan completes with progress = 100 and saves ≥ 1 result row.
 * 2. Unit: DNS resolution failures do not produce unhandled rejections — scan still finishes.
 * 3. Error resilience: unexpected errors set status to "error" without throwing.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── vi.hoisted: tracking variables initialised before vi.mock factories run ──

const { updateSetMock, insertValuesMock, dnsMockFns } = vi.hoisted(() => {
  const updateSetMock = vi.fn();
  const insertValuesMock = vi.fn();

  const dnsMockFns = {
    resolve4: vi.fn<(domain: string) => Promise<string[]>>(),
    resolve6: vi.fn<(domain: string) => Promise<string[]>>(),
    resolveMx: vi.fn<(domain: string) => Promise<Array<{ exchange: string; priority: number }>>>(),
    resolveNs: vi.fn<(domain: string) => Promise<string[]>>(),
  };

  return { updateSetMock, insertValuesMock, dnsMockFns };
});

// ── DB mock ───────────────────────────────────────────────────────────────────

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

const MOCK_SCAN_ROW = {
  id: 42,
  tenantId: 1,
  domain: "example.com",
  status: "running",
  progress: 0,
  faviconMd5: null,
  faviconUrl: null,
  faviconMmh3: null,
  faviconMmh3Hex: null,
  faviconSha256: null,
  faviconSearchUrls: null,
};

vi.mock("@workspace/db", () => {
  const makeUpdate = () => ({
    set: (data: Record<string, unknown>) => {
      updateSetMock(data);
      return { where: () => Promise.resolve() };
    },
  });

  const makeInsert = () => ({
    values: (rows: unknown) => {
      const arr = Array.isArray(rows) ? rows : [rows];
      insertValuesMock(arr);
      return Promise.resolve([]);
    },
  });

  return {
    db: {
      update:  (_table: unknown) => makeUpdate(),
      insert:  (_table: unknown) => makeInsert(),
      select:  (_fields?: unknown) => makeThenable([MOCK_SCAN_ROW]),
      delete:  (_table: unknown) => ({ where: () => Promise.resolve() }),
    },
    brandThreatScansTable:   { _: { name: "brand_threat_scans" } },
    brandThreatResultsTable: { _: { name: "brand_threat_results" } },
    dataLeakResultsTable:    { _: { name: "data_leak_results" } },
    phishingDetectionsTable: { _: { name: "phishing_detections" } },
    brandAbuseResultsTable:  { _: { name: "brand_abuse_results" } },
    adMonitoringResultsTable:{ _: { name: "ad_monitoring_results" } },
    brandWatchlistItemsTable:{ _: { name: "brand_watchlist_items" } },
    cdnWhitelistTable:       { _: { name: "cdn_whitelist_entries" } },
  };
});

// ── External service mocks ─────────────────────────────────────────────────────

vi.mock("../metaAdsClient", () => ({ scanMetaAds: vi.fn().mockResolvedValue([]) }));
vi.mock("../abuseChFeeds",  () => ({ queryAbuseChFeeds: vi.fn().mockResolvedValue([]) }));
vi.mock("../logger",        () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("../rdapClient",          () => ({ rdapLookup: vi.fn().mockResolvedValue(null) }));
vi.mock("../geoIpClient",         () => ({ geoIpBatch: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../phishFeedClient",     () => ({
  checkPhishingFeed: vi.fn().mockResolvedValue({ isPhishing: false, source: null }),
  setPhishTankKey: vi.fn(),
}));
vi.mock("../googleSafeBrowsing",  () => ({ checkGoogleSafeBrowsing: vi.fn().mockResolvedValue(new Map()) }));
vi.mock("../hibpClient",          () => ({
  hibpDomainLookup: vi.fn().mockResolvedValue(null),
  severityFromBreach: vi.fn().mockReturnValue("medium"),
}));
vi.mock("../vtDomainClient",      () => ({
  vtDomainLookup: vi.fn().mockResolvedValue(null),
  vtUrlScan: vi.fn().mockResolvedValue(null),
}));
vi.mock("../brandAbuseScanner",   () => ({ scanBrandAbuse: vi.fn().mockResolvedValue([]) }));
vi.mock("../intelxClient",        () => ({
  intelxSearch: vi.fn().mockResolvedValue([]),
  intelxTypeToBucket: vi.fn().mockReturnValue("pastes"),
}));
vi.mock("../shodanFaviconClient", () => ({ searchShodanByFaviconHash: vi.fn().mockResolvedValue([]) }));
vi.mock("../notifier",            () => ({ dispatchNotifications: vi.fn().mockResolvedValue(undefined) }));
vi.mock("../../routes/platformSettings", () => ({
  getPlatformSetting: vi.fn().mockResolvedValue(null),
}));
vi.mock("../screenshotEngine",    () => ({ captureScreenshots: vi.fn().mockResolvedValue([]) }));

// ── DNS mock — default import (`import dns from "node:dns/promises"`) ──────────
vi.mock("node:dns/promises", () => ({ default: dnsMockFns }));

// ── child_process mock — dnstwist binary unavailable → builtin engine runs ────
vi.mock("child_process", () => ({
  execFile: (
    _cmd: string,
    _args: string[],
    _opts: unknown,
    cb: (err: Error | null) => void,
  ) => { cb(new Error("dnstwist not found")); },
  promisify: (fn: Function) => (...args: unknown[]) =>
    new Promise((_resolve, reject) => fn(...args, reject)),
}));

// We also need to mock "util" since the runner does `promisify(execFile)`
vi.mock("util", async (importOriginal) => {
  const orig = await importOriginal<typeof import("util")>();
  return {
    ...orig,
    promisify: (_fn: unknown) => (_cmd: string, _args: string[], _opts: unknown) =>
      Promise.reject(new Error("dnstwist not found")),
  };
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("runBrandThreatScan", () => {
  beforeEach(() => {
    updateSetMock.mockClear();
    insertValuesMock.mockClear();

    // Default DNS: all permutations fail to resolve (return empty arrays)
    dnsMockFns.resolve4.mockResolvedValue([]);
    dnsMockFns.resolve6.mockResolvedValue([]);
    dnsMockFns.resolveMx.mockResolvedValue([]);
    dnsMockFns.resolveNs.mockResolvedValue([]);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("completes with progress = 100 and saves at least 1 result row (integration)", async () => {
    // Make one permutation resolve with an A record so there's at least one result to insert
    dnsMockFns.resolve4.mockImplementation((domain: string) =>
      domain.includes("examp") && domain !== "example.com"
        ? Promise.resolve(["1.2.3.4"])
        : Promise.resolve([]),
    );

    const { runBrandThreatScan } = await import("../brandThreatRunner");

    await runBrandThreatScan(42, "example.com");

    // Final status update must set progress=100 and status="done"
    const calls = updateSetMock.mock.calls.map((c) => c[0] as Record<string, unknown>);
    const finalUpdate = calls.find((u) => u.progress === 100 && u.status === "done");
    expect(finalUpdate, "Expected a final status update with progress=100 and status='done'").toBeDefined();

    // At least one result row must have been inserted
    expect(
      insertValuesMock.mock.calls.length,
      "Expected at least 1 insert call for brand_threat_results",
    ).toBeGreaterThanOrEqual(1);
  });

  it("advances progress through checkpoints: 20 → … → 100", async () => {
    const { runBrandThreatScan } = await import("../brandThreatRunner");

    await runBrandThreatScan(42, "example.com");

    const progressValues = updateSetMock.mock.calls
      .map((c) => (c[0] as Record<string, unknown>).progress)
      .filter((p): p is number => typeof p === "number");

    expect(progressValues).toContain(20);
    expect(progressValues).toContain(100);

    // Progress must never decrease
    for (let i = 1; i < progressValues.length; i++) {
      expect(progressValues[i]).toBeGreaterThanOrEqual(progressValues[i - 1]!);
    }
  });

  it("handles DNS resolution failures without throwing an unhandled rejection (unit)", async () => {
    // All DNS methods reject — simulates a total network failure
    dnsMockFns.resolve4.mockRejectedValue(new Error("getaddrinfo ENOTFOUND"));
    dnsMockFns.resolve6.mockRejectedValue(new Error("getaddrinfo ENOTFOUND"));
    dnsMockFns.resolveMx.mockRejectedValue(new Error("queryMx ENOTFOUND"));
    dnsMockFns.resolveNs.mockRejectedValue(new Error("queryNs ENOTFOUND"));

    const { runBrandThreatScan } = await import("../brandThreatRunner");

    // Must not throw — all DNS errors are caught in checkDNSFull
    await expect(runBrandThreatScan(42, "example.com")).resolves.toBeUndefined();

    // Scan must still reach a terminal state (done — no live results but still finishes)
    const calls = updateSetMock.mock.calls.map((c) => c[0] as Record<string, unknown>);
    const terminalUpdate = calls.find(
      (u) => u.status === "done" || u.status === "error",
    );
    expect(
      terminalUpdate,
      "Expected scan to reach a terminal status even when all DNS calls fail",
    ).toBeDefined();
  });

  it("sets status to 'error' without throwing when an enrichment step crashes", async () => {
    const { geoIpBatch } = await import("../geoIpClient");
    vi.mocked(geoIpBatch).mockRejectedValueOnce(new Error("GeoIP service crashed"));

    const { runBrandThreatScan } = await import("../brandThreatRunner");

    await expect(runBrandThreatScan(42, "example.com")).resolves.toBeUndefined();

    const calls = updateSetMock.mock.calls.map((c) => c[0] as Record<string, unknown>);
    const errorUpdate = calls.find((u) => u.status === "error");
    expect(errorUpdate).toBeDefined();
    expect(String(errorUpdate?.error)).toContain("GeoIP service crashed");
  });
});
