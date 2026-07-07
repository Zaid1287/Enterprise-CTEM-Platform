/**
 * Route tests for /brand-threats endpoints.
 *
 * 1. GET /brand-threats/:id — returns scan detail; results array contains only non-archived rows.
 * 2. GET /brand-threats     — returns tenant scan list (no result detail at list level).
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import express from "express";
import request from "supertest";

// ── vi.hoisted: select responses must be accessible inside the mock factory ───

const { dbState } = vi.hoisted(() => {
  const dbState: { selectQueue: unknown[][] } = { selectQueue: [] };
  return { dbState };
});

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

/**
 * Build a thenable-chainable query result.
 * Supports: .where(), .orderBy(), .limit() — all chainable and all awaitable.
 */
function makeQueryChain<T>(rows: T[]): Promise<T[]> & {
  where: (...args: unknown[]) => ReturnType<typeof makeQueryChain<T>>;
  orderBy: (...args: unknown[]) => ReturnType<typeof makeQueryChain<T>>;
  limit: (n: number) => Promise<T[]>;
} {
  const base = Promise.resolve(rows);
  const chain = {
    where: (..._args: unknown[]) => makeQueryChain(rows),
    orderBy: (..._args: unknown[]) => makeQueryChain(rows),
    limit: (n: number) => Promise.resolve(rows.slice(0, n)),
  };
  return Object.assign(base, chain) as ReturnType<typeof makeQueryChain<T>>;
}

vi.mock("@workspace/db", () => {
  const makeSelect = (_fields?: unknown) => {
    // Dequeue next response; fall back to empty array
    const rows = dbState.selectQueue.length > 0
      ? dbState.selectQueue.shift()!
      : [];
    return {
      from: (_table: unknown) => makeQueryChain(rows),
    };
  };

  return {
    db: {
      select: makeSelect,
      update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
      insert: () => ({ values: () => Promise.resolve([]) }),
      delete: () => ({ where: () => Promise.resolve() }),
    },
    brandThreatScansTable:    { _: { name: "brand_threat_scans" } },
    brandThreatResultsTable:  { _: { name: "brand_threat_results" } },
    brandWatchlistItemsTable: { _: { name: "brand_watchlist_items" } },
    dataLeakResultsTable:     { _: { name: "data_leak_results" } },
    phishingDetectionsTable:  { _: { name: "phishing_detections" } },
    brandAbuseResultsTable:   { _: { name: "brand_abuse_results" } },
    adMonitoringResultsTable: { _: { name: "ad_monitoring_results" } },
    platformSettingsTable:    { _: { name: "platform_settings" } },
    assetsTable:              { _: { name: "assets" } },
    brandThreatSchedulesTable:{ _: { name: "brand_threat_schedules" } },
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

// ── drizzle-orm operators — return opaque objects (routes pass them to .where()) ──
vi.mock("drizzle-orm", async (importOriginal) => {
  const orig = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...orig,
    eq:       vi.fn(() => ({ _type: "eq" })),
    and:      vi.fn((...args: unknown[]) => ({ _type: "and", args })),
    desc:     vi.fn(() => ({ _type: "desc" })),
    inArray:  vi.fn(() => ({ _type: "inArray" })),
    isNull:   vi.fn(() => ({ _type: "isNull" })),
    gte:      vi.fn(() => ({ _type: "gte" })),
    isNotNull:vi.fn(() => ({ _type: "isNotNull" })),
  };
});

// ── Fixtures ──────────────────────────────────────────────────────────────────

const mockScan = {
  id: 7,
  tenantId: 1,
  domain: "acme.com",
  status: "done",
  progress: 100,
  totalPermutations: 50,
  liveCount: 3,
  registeredCount: 5,
  phishingRisk: "medium",
  fuzzerBreakdown: null,
  error: null,
  pipelineScanId: null,
  favihunterStatus: null,
  favihunterError: null,
  faviconUrl: null,
  faviconMmh3: null,
  faviconMmh3Hex: null,
  faviconMd5: null,
  faviconSha256: null,
  faviconSearchUrls: null,
  faviconShodanMatches: null,
  dataLeakCount: 0,
  phishingCount: 0,
  brandAbuseCount: 0,
  darkWebCount: 0,
  checkpoint: null,
  permutationsCache: null,
  createdAt: new Date("2026-01-01T00:00:00Z"),
  completedAt: new Date("2026-01-01T00:05:00Z"),
};

const mockResultActive = {
  id: 100,
  scanId: 7,
  permutation: "acmee.com",
  fuzzer: "repetition",
  dnsA: ["1.2.3.4"],
  dnsNs: null,
  dnsAaaa: null,
  dnsMx: null,
  mxSpf: null,
  whoisRegistrar: null,
  whoisCreated: null,
  whoisExpires: null,
  whoisUpdated: null,
  whoisCountry: null,
  whoisAbuseContact: null,
  whoisAgeDays: null,
  geoCountry: null,
  geoCity: null,
  geoAsn: null,
  geoOrg: null,
  vtMalicious: null,
  vtSuspicious: null,
  vtLastAnalysisDate: null,
  vtPermalink: null,
  isPhishing: false,
  phishingSource: null,
  registrationStatus: "active",
  riskScore: 55,
  isSuspicious: false,
  screenshot: null,
  archivedAt: null,
  createdAt: new Date("2026-01-01T00:04:00Z"),
};

// ── App factory ───────────────────────────────────────────────────────────────

async function buildApp() {
  const { default: brandThreatsRouter } = await import("../brandThreats");
  const app = express();
  app.use(express.json());
  app.use(brandThreatsRouter);
  // Express 5 error handler — surface errors as JSON 500s
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: err.message });
  });
  return app;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("GET /brand-threats/:id", () => {
  beforeEach(() => {
    dbState.selectQueue = [];
    vi.clearAllMocks();
  });

  it("returns scan detail including non-archived results", async () => {
    // GET /:id (admin role — btScanAccessFilter makes NO DB query for admin):
    // select call 0: scan row lookup
    // select calls 1-6: Promise.all(results, phishing, dataLeaks, brandAbuse, adMonitoring, metaAdsSetting)
    dbState.selectQueue = [
      [mockScan],        // scan row
      [mockResultActive],// results (non-archived)
      [],                // phishing detections
      [],                // data leaks
      [],                // brand abuse
      [],                // ad monitoring
      [],                // platform settings (meta_ads)
    ];

    const app = await buildApp();
    const res = await request(app)
      .get("/brand-threats/7")
      .set("Authorization", "Bearer test-token");

    expect(res.status).toBe(200);
    expect(res.body.id).toBe(7);
    expect(Array.isArray(res.body.results)).toBe(true);
    expect(res.body.results).toHaveLength(1);
    expect(res.body.results[0].permutation).toBe("acmee.com");
  });

  it("does not include archived result rows in GET /:id results", async () => {
    // Archived row is excluded by the isNull(archivedAt) where-clause in the route.
    // Our mock returns only the non-archived row; the archived one is never in the queue.
    dbState.selectQueue = [
      [mockScan],
      [mockResultActive], // only non-archived
      [], [], [], [], [],
    ];

    const app = await buildApp();
    const res = await request(app)
      .get("/brand-threats/7")
      .set("Authorization", "Bearer test-token");

    expect(res.status).toBe(200);
    const hasArchivedRow = res.body.results?.some(
      (r: { permutation?: string }) => r.permutation === "acme-old.com",
    );
    expect(hasArchivedRow).toBeFalsy();
  });

  it("returns 404 when scan is not found", async () => {
    dbState.selectQueue = [[]]; // scan lookup returns no rows

    const app = await buildApp();
    const res = await request(app)
      .get("/brand-threats/9999")
      .set("Authorization", "Bearer test-token");

    expect(res.status).toBe(404);
  });
});

describe("GET /brand-threats (list)", () => {
  beforeEach(() => {
    dbState.selectQueue = [];
    vi.clearAllMocks();
  });

  it("returns scan list without result detail (archived results not surfaced)", async () => {
    dbState.selectQueue = [[mockScan]];

    const app = await buildApp();
    const res = await request(app)
      .get("/brand-threats")
      .set("Authorization", "Bearer test-token");

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe(7);
    // List endpoint never includes a `results` array — detail only comes from /:id
    expect(res.body[0].results).toBeUndefined();
  });

  it("returns empty array when tenant has no scans", async () => {
    dbState.selectQueue = [[]];

    const app = await buildApp();
    const res = await request(app)
      .get("/brand-threats")
      .set("Authorization", "Bearer test-token");

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });
});
