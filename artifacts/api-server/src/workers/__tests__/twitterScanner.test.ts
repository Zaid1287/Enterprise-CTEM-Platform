/**
 * Unit tests for twitterScanner.ts — scanTwitterBrandAbuse()
 *
 * Invariants tested:
 *  1. Valid bearer token + impersonating account → result returned with correct fields
 *  2. Non-OK HTTP response → graceful empty return (no throw)
 *  3. Missing/empty bearer token emulating a 401 response → graceful empty return
 *  4. Scam signal detection: claimsOfficial → "high" risk
 *  5. riskFromSignals: usernameContainsBrand + hasScam → "high"; only one → "medium"; neither → "low"
 *  6. Exact-match brand username is skipped (may be the official account)
 *  7. High-follower account with no brand/scam/official signal is filtered out
 *  8. Valid scam tweet → result returned with correct fields
 *  9. Deduplication: same author + same text prefix yields only one scam tweet result
 * 10. High-engagement tweet → "high" risk; low-engagement → "medium" risk
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mock logger ────────────────────────────────────────────────────────────────

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

function makeUser(overrides: Record<string, unknown> = {}) {
  return {
    id: "u1",
    username: "acmescam",
    name: "Acme Official",
    description: "Crypto giveaway for Acme holders",
    verified: false,
    public_metrics: { followers_count: 500, tweet_count: 100 },
    profile_image_url: "https://pbs.twimg.com/u1.jpg",
    ...overrides,
  };
}

function makeTweet(overrides: Record<string, unknown> = {}) {
  return {
    id: "t1",
    author_id: "u1",
    text: "Acme is running a scam giveaway! Click here.",
    created_at: "2026-07-01T00:00:00Z",
    public_metrics: { retweet_count: 10, like_count: 20 },
    entities: {},
    ...overrides,
  };
}

function makeIncludesUser(overrides: Record<string, unknown> = {}) {
  return {
    id: "u1",
    username: "acmescam",
    name: "Acme Scammer",
    description: "Fake Acme account",
    public_metrics: { followers_count: 200 },
    profile_image_url: "https://pbs.twimg.com/u1.jpg",
    ...overrides,
  };
}

/** Create a mock Response that returns the given JSON payload. */
function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  } as unknown as Response;
}

function errorResponse(status: number): Response {
  return {
    ok: false,
    status,
    json: () => Promise.reject(new Error("bad response")),
    text: () => Promise.resolve("Unauthorized"),
  } as unknown as Response;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("scanTwitterBrandAbuse — account search", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a fake_social result when an impersonating account is found", async () => {
    const user = makeUser({ username: "acmeofficial", name: "Acme Official Giveaway" });

    // First call: user search; second call: tweet search (return empty)
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [user], meta: { result_count: 1 } }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const acct = results.find(r => r.platform === "Twitter/X" && r.type === "fake_social");
    expect(acct).toBeDefined();
    expect(acct!.url).toBe("https://twitter.com/acmeofficial");
    expect(acct!.title).toContain("@acmeofficial");
    expect(acct!.risk).toBe("high"); // claimsOfficial via "official" in username
  });

  it("sets Authorization header correctly with the provided bearer token", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    await scanTwitterBrandAbuse("Acme", "my-secret-bearer-token");

    const firstCallHeaders = fetchMock.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(firstCallHeaders?.Authorization).toBe("Bearer my-secret-bearer-token");
  });

  it("returns empty when the API responds with a non-OK status", async () => {
    fetchMock
      .mockResolvedValueOnce(errorResponse(401))
      .mockResolvedValueOnce(errorResponse(401));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "bad-token");

    expect(results).toEqual([]);
  });

  it("returns empty when fetch rejects (network error)", async () => {
    fetchMock.mockRejectedValue(new Error("Network failure"));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "any-token");

    expect(results).toEqual([]);
  });

  it("skips accounts whose username exactly equals the brand (official account guard)", async () => {
    const user = makeUser({ username: "acme" }); // exactly the brand name

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [user], meta: {} }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    expect(results.filter(r => r.url?.includes("twitter.com/acme"))).toHaveLength(0);
  });

  it("filters out high-follower accounts that lack brand/scam/official signal", async () => {
    // name contains brand but username doesn't; no scam signal; 100k followers
    const user = makeUser({
      username: "randomuser",
      name: "Acme Partner Blog",
      description: "We write about technology",
      public_metrics: { followers_count: 100_000 },
    });

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [user], meta: {} }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    expect(results).toHaveLength(0);
  });

  it("assigns medium risk when only one of usernameContainsBrand or hasScam is true", async () => {
    // Username contains brand but bio has no scam keywords
    const user = makeUser({
      username: "acmesupport",
      name: "Acme Support Team",
      description: "We help customers with their accounts",
    });

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [user], meta: {} }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const acct = results.find(r => r.url?.includes("acmesupport"));
    expect(acct).toBeDefined();
    expect(acct!.risk).toBe("medium");
  });

  it("assigns high risk when username contains brand AND bio has scam keyword", async () => {
    const user = makeUser({
      username: "acmegiveaway",
      name: "Acme Giveaway",
      description: "Win free Acme crypto airdrop! Join now.",
    });

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [user], meta: {} }))
      .mockResolvedValueOnce(jsonResponse({ data: [], includes: { users: [] } }));

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const acct = results.find(r => r.url?.includes("acmegiveaway"));
    expect(acct).toBeDefined();
    expect(acct!.risk).toBe("high");
  });
});

describe("scanTwitterBrandAbuse — scam tweet search", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a brand_abuse result for a matching scam tweet", async () => {
    const tweet = makeTweet();
    const includesUser = makeIncludesUser();

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} })) // user search
      .mockResolvedValueOnce(
        jsonResponse({ data: [tweet], includes: { users: [includesUser] } }),
      );

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const tw = results.find(r => r.type === "brand_abuse" && r.platform === "Twitter/X");
    expect(tw).toBeDefined();
    expect(tw!.url).toContain("twitter.com/acmescam/status/t1");
    expect(tw!.evidenceSnippet).toContain("Acme is running a scam giveaway");
  });

  it("deduplicates tweets with the same author and identical text prefix", async () => {
    const text = "Acme is running a scam giveaway — do not fall for it";
    const tweet1 = makeTweet({ id: "t1", text });
    const tweet2 = makeTweet({ id: "t2", text }); // same author + same text → duplicate
    const includesUser = makeIncludesUser();

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} }))
      .mockResolvedValueOnce(
        jsonResponse({ data: [tweet1, tweet2], includes: { users: [includesUser] } }),
      );

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const abuseTweets = results.filter(r => r.type === "brand_abuse" && r.platform === "Twitter/X");
    expect(abuseTweets).toHaveLength(1);
  });

  it("assigns high risk when engagement > 100", async () => {
    const tweet = makeTweet({
      public_metrics: { retweet_count: 60, like_count: 60 }, // 120 total
    });
    const includesUser = makeIncludesUser();

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} }))
      .mockResolvedValueOnce(
        jsonResponse({ data: [tweet], includes: { users: [includesUser] } }),
      );

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const tw = results.find(r => r.type === "brand_abuse");
    expect(tw).toBeDefined();
    expect(tw!.risk).toBe("high");
  });

  it("assigns medium risk when engagement ≤ 100", async () => {
    const tweet = makeTweet({
      public_metrics: { retweet_count: 5, like_count: 10 }, // 15 total
    });
    const includesUser = makeIncludesUser();

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} }))
      .mockResolvedValueOnce(
        jsonResponse({ data: [tweet], includes: { users: [includesUser] } }),
      );

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    const tw = results.find(r => r.type === "brand_abuse");
    expect(tw).toBeDefined();
    expect(tw!.risk).toBe("medium");
  });

  it("filters out tweets whose text does not contain the brand name", async () => {
    // Tweet from scam search but text doesn't mention the brand
    const tweet = makeTweet({ text: "Big giveaway happening now — click here!" });
    const includesUser = makeIncludesUser();

    fetchMock
      .mockResolvedValueOnce(jsonResponse({ data: [], meta: {} }))
      .mockResolvedValueOnce(
        jsonResponse({ data: [tweet], includes: { users: [includesUser] } }),
      );

    const { scanTwitterBrandAbuse } = await import("../../lib/twitterScanner");
    const results = await scanTwitterBrandAbuse("Acme", "valid-bearer-token");

    expect(results.filter(r => r.type === "brand_abuse")).toHaveLength(0);
  });
});
