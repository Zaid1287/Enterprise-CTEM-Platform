/**
 * Route tests for GET /platform/social-source-status
 *
 * Uses the REAL requireAuth and denyExternalMembers middleware (not mocked) so
 * that a future middleware change that starts rejecting admin/manager roles
 * will cause these tests to fail — fulfilling the regression-protection goal.
 *
 * Real JWTs are signed with the default JWT_SECRET used in development
 * ("ctem-dev-secret-change-in-production") so signature verification passes.
 * The DB mock serves two selects per request:
 *   1. usersTable lookup inside requireAuth (isActive, requiresPasswordReset)
 *   2. platformSettingsTable lookup inside the route handler
 *
 * Coverage:
 *  1. admin role      → 200 with { twitter_x, instagram, tiktok, youtube } booleans
 *  2. manager role    → 200 with the same shape (not a 403)
 *  3. super_admin role → 200 with the same shape
 *  4. No token        → 401
 *  5. Boolean values correctly reflect which platform_settings keys are
 *     configured (truthy value) vs absent/falsy in the DB.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import jwt from "jsonwebtoken";
import express from "express";
import request from "supertest";

// ── JWT secret — must match whatever auth.ts resolves at runtime ──────────────
// auth.ts: const JWT_SECRET = process.env.SESSION_SECRET ?? "ctem-dev-secret-change-in-production"
const JWT_SECRET = process.env.SESSION_SECRET ?? "ctem-dev-secret-change-in-production";

function makeToken(role: string, userId = 1, tenantId = 1): string {
  return jwt.sign({ userId, tenantId, role, email: "test@example.com" }, JWT_SECRET, {
    expiresIn: "8h",
  });
}

// ── vi.hoisted: mutable select queue for all DB calls ────────────────────────

const { dbState } = vi.hoisted(() => {
  const dbState: { selectQueue: unknown[][] } = { selectQueue: [] };
  return { dbState };
});

// ── DB mock — dequeues one row-set per select() call ─────────────────────────
//
// requireAuth does: db.select({...}).from(usersTable).where(...)
// The route does:   db.select().from(platformSettingsTable).where(...)
//
// Each test must enqueue:
//   [0] usersTable rows  { isActive: true, requiresPasswordReset: false }
//   [1] platformSettingsTable rows (the social key rows for that test)

vi.mock("@workspace/db", () => {
  function makeChain(rows: unknown[]) {
    const p = Promise.resolve(rows);
    const chain = {
      where: (..._args: unknown[]) => p,
    };
    return Object.assign(p, chain);
  }

  return {
    db: {
      select: (_fields?: unknown) => {
        const rows = dbState.selectQueue.length > 0 ? dbState.selectQueue.shift()! : [];
        return {
          from: (_table: unknown) => makeChain(rows),
        };
      },
    },
    usersTable: { id: "id", _: { name: "users" } },
    platformSettingsTable: {
      key: "key",
      value: "value",
      _: { name: "platform_settings" },
    },
  };
});

// ── drizzle-orm operators — opaque stubs (DB mock ignores them) ───────────────

vi.mock("drizzle-orm", async (importOriginal) => {
  const orig = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...orig,
    eq:      vi.fn(() => ({ _type: "eq" })),
    inArray: vi.fn(() => ({ _type: "inArray" })),
    and:     vi.fn((...args: unknown[]) => ({ _type: "and", args })),
  };
});

// ── Mocks for side-effect modules imported by platformSettings.ts ─────────────

vi.mock("../../lib/redis", () => ({
  reinitRedis: vi.fn(),
  setRuntimeRedisUrl: vi.fn(),
}));

vi.mock("../../workers/scanWorker", () => ({
  restartScanWorker: vi.fn(),
}));

vi.mock("../../workers/alertWorker", () => ({
  restartAlertWorker: vi.fn(),
}));

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── App factory (real auth middleware, mocked DB) ─────────────────────────────

async function buildApp() {
  const { default: platformSettingsRouter } = await import("../platformSettings");
  const app = express();
  app.use(express.json());
  app.use(platformSettingsRouter);
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: err.message });
  });
  return app;
}

// ── Active user row returned by requireAuth's usersTable lookup ───────────────
const ACTIVE_USER = { isActive: true, requiresPasswordReset: false };

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeSettingRow(key: string, value: string) {
  return { key, value };
}

// ── Tests: role access via real middleware ────────────────────────────────────

describe("GET /platform/social-source-status — role access (real auth middleware)", () => {
  let app: express.Express;

  beforeEach(async () => {
    vi.clearAllMocks();
    dbState.selectQueue = [];
    app = await buildApp();
  });

  it("returns 200 for admin role", async () => {
    dbState.selectQueue = [[ACTIVE_USER], []];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("admin")}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      twitter_x: expect.any(Boolean),
      instagram:  expect.any(Boolean),
      tiktok:     expect.any(Boolean),
      youtube:    expect.any(Boolean),
    });
  });

  it("returns 200 for manager role", async () => {
    dbState.selectQueue = [[ACTIVE_USER], []];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("manager")}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      twitter_x: expect.any(Boolean),
      instagram:  expect.any(Boolean),
      tiktok:     expect.any(Boolean),
      youtube:    expect.any(Boolean),
    });
  });

  it("returns 200 for super_admin role", async () => {
    dbState.selectQueue = [[ACTIVE_USER], []];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("super_admin")}`);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      twitter_x: expect.any(Boolean),
      instagram:  expect.any(Boolean),
      tiktok:     expect.any(Boolean),
      youtube:    expect.any(Boolean),
    });
  });

  it("returns 401 when no token is provided", async () => {
    const res = await request(app)
      .get("/platform/social-source-status");

    expect(res.status).toBe(401);
  });

  it("returns 401 for a tampered / invalid token", async () => {
    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", "Bearer not.a.real.token");

    expect(res.status).toBe(401);
  });
});

// ── Tests: value correctness ──────────────────────────────────────────────────

describe("GET /platform/social-source-status — value correctness", () => {
  let app: express.Express;

  beforeEach(async () => {
    vi.clearAllMocks();
    dbState.selectQueue = [];
    app = await buildApp();
  });

  it("returns all false when no social keys are configured", async () => {
    dbState.selectQueue = [[ACTIVE_USER], []]; // no platform_settings rows

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("admin")}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      twitter_x: false,
      instagram:  false,
      tiktok:     false,
      youtube:    false,
    });
  });

  it("returns true only for keys that are configured", async () => {
    dbState.selectQueue = [
      [ACTIVE_USER],
      [
        makeSettingRow("twitter_x_bearer_token",   "some-bearer-token"),
        makeSettingRow("tiktok_research_api_token", "some-tiktok-token"),
      ],
    ];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("admin")}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      twitter_x: true,
      instagram:  false,
      tiktok:     true,
      youtube:    false,
    });
  });

  it("returns true for all keys when all four social API keys are configured", async () => {
    dbState.selectQueue = [
      [ACTIVE_USER],
      [
        makeSettingRow("twitter_x_bearer_token",    "tok1"),
        makeSettingRow("instagram_graph_api_token", "tok2"),
        makeSettingRow("tiktok_research_api_token", "tok3"),
        makeSettingRow("youtube_api_key",            "tok4"),
      ],
    ];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("manager")}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      twitter_x: true,
      instagram:  true,
      tiktok:     true,
      youtube:    true,
    });
  });

  it("treats an empty string value as false (key not configured)", async () => {
    dbState.selectQueue = [
      [ACTIVE_USER],
      [
        makeSettingRow("twitter_x_bearer_token",    ""),
        makeSettingRow("instagram_graph_api_token", "valid-token"),
      ],
    ];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("admin")}`);

    expect(res.status).toBe(200);
    expect(res.body.twitter_x).toBe(false);
    expect(res.body.instagram).toBe(true);
    expect(res.body.tiktok).toBe(false);
    expect(res.body.youtube).toBe(false);
  });

  it("ignores unrelated platform_settings keys — they do not appear in the response", async () => {
    dbState.selectQueue = [
      [ACTIVE_USER],
      [
        makeSettingRow("instagram_graph_api_token", "tok"),
        makeSettingRow("shodan_api_key",             "ignored"),
        makeSettingRow("redis_url",                  "ignored"),
      ],
    ];

    const res = await request(app)
      .get("/platform/social-source-status")
      .set("Authorization", `Bearer ${makeToken("admin")}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      twitter_x: false,
      instagram:  true,
      tiktok:     false,
      youtube:    false,
    });
    expect(res.body).not.toHaveProperty("shodan_api_key");
    expect(res.body).not.toHaveProperty("redis_url");
  });
});
