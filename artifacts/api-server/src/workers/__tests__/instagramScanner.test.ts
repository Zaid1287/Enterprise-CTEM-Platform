/**
 * Unit tests for instagramScanner.ts — scanInstagramBrandAbuse()
 *
 * IMPORTANT: The 6 hashtag scans run in parallel via Promise.allSettled.
 * This means all 6 getHashtagId fetch calls are dispatched before any of
 * them resolves, so mock call order is:
 *   Call 1:   GET /me
 *   Calls 2–7: getHashtagId for each of the 6 hashtags (in array order)
 *   Calls 8+:  recent_media for any hashtag that received an ID
 *
 * Invariants tested:
 *  1. Valid access token + brand signal in caption → result returned
 *  2. getIgUserId failure (non-OK /me) → graceful empty return
 *  3. Network error during /me → graceful empty return
 *  4. Hashtag search non-OK response → skips that hashtag
 *  5. Posts without a scam signal in the caption are filtered out
 *  6. Posts without the brand name in the caption are filtered out
 *  7. High-risk hashtag (#acmescam, #acmefake) → "high" risk result
 *  8. Non-high-risk hashtag + "official" in caption → "medium" risk
 *  9. Per-platform cap of 10 results is respected
 * 10. Uses IG Business Account ID when present in /me response
 * 11. Falls back to page/user ID when no IG Business Account is linked
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mock logger ────────────────────────────────────────────────────────────────

vi.mock("../../lib/logger", () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// ── Helpers ────────────────────────────────────────────────────────────────────

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
    text: () => Promise.resolve("Error"),
  } as unknown as Response;
}

function meResponse(igBusinessId?: string) {
  return {
    id: "page_123",
    ...(igBusinessId ? { instagram_business_account: { id: igBusinessId } } : {}),
  };
}

function hashtagIdResponse(id: string) {
  return { data: [{ id }] };
}

function emptyHashtagResponse() {
  return { data: [] };
}

function mediaResponse(caption: string, permalink = "https://www.instagram.com/p/ABC/") {
  return {
    data: [
      {
        id: "post_1",
        caption,
        permalink,
        timestamp: "2026-07-01T00:00:00Z",
        media_type: "IMAGE",
      },
    ],
  };
}

/**
 * Build a full mock sequence for the scanner.
 *
 * The scanner produces 6 hashtag names (all run in parallel):
 *   ["acme", "acmeofficial", "acmereal", "acmescam", "acmefake", "acmegiveaway"]
 *
 * The `hashtagIdByIndex` map controls which hashtag gets an ID (and therefore
 * triggers a recent_media call).  Key is 0-based index into the 6-hashtag list.
 * Value is the hashtag ID string to return.
 *
 * All hashtags NOT listed in `hashtagIdByIndex` receive an empty response.
 *
 * The `mediaByHashtagId` map provides the media response for each hashtag ID.
 */
function buildMockSequence(
  fetchMock: ReturnType<typeof vi.fn>,
  igUserId: string,
  hashtagIdByIndex: Record<number, string>,
  mediaByHashtagId: Record<string, unknown>,
) {
  // 1. /me response
  fetchMock.mockResolvedValueOnce(jsonResponse(meResponse(igUserId)));

  // 2–7. getHashtagId responses for each of the 6 hashtags (in order)
  const hashtagIds: Array<string | null> = [];
  for (let i = 0; i < 6; i++) {
    const id = hashtagIdByIndex[i] ?? null;
    hashtagIds.push(id);
    fetchMock.mockResolvedValueOnce(
      id ? jsonResponse(hashtagIdResponse(id)) : jsonResponse(emptyHashtagResponse()),
    );
  }

  // 8+. recent_media responses for hashtags that got an ID
  for (const id of hashtagIds) {
    if (id === null) continue;
    const media = mediaByHashtagId[id];
    fetchMock.mockResolvedValueOnce(
      media ? jsonResponse(media) : jsonResponse({ data: [] }),
    );
  }
}

// ── Shared fetch mock ─────────────────────────────────────────────────────────

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("scanInstagramBrandAbuse — happy path", () => {
  it("returns a fake_social result for a post under a brand hashtag with a scam signal", async () => {
    buildMockSequence(
      fetchMock,
      "ig_biz_456",
      { 0: "ht_acme" }, // #acme (index 0) gets an ID
      { ht_acme: mediaResponse("Acme official giveaway! Free crypto airdrop today") },
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-access-token");

    expect(results.length).toBeGreaterThan(0);
    const r = results[0]!;
    expect(r.platform).toBe("Instagram");
    expect(r.type).toBe("fake_social");
    expect(r.url).toBe("https://www.instagram.com/p/ABC/");
    expect(r.evidenceSnippet).toContain("Caption excerpt:");
    expect(r.risk).toMatch(/^(high|medium)$/);
  });

  it("uses the IG Business Account ID in subsequent API calls", async () => {
    buildMockSequence(fetchMock, "ig_biz_789", {}, {});

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    await scanInstagramBrandAbuse("Acme", "valid-access-token");

    const hashtagSearchCall = fetchMock.mock.calls.find(
      call => typeof call[0] === "string" && (call[0] as string).includes("ig_hashtag_search"),
    );
    expect(hashtagSearchCall).toBeDefined();
    expect(hashtagSearchCall![0]).toContain("user_id=ig_biz_789");
  });

  it("falls back to the page/user ID when no IG Business Account is linked", async () => {
    // /me without instagram_business_account
    fetchMock.mockResolvedValueOnce(jsonResponse(meResponse()));
    // 6 empty hashtag id responses
    for (let i = 0; i < 6; i++) {
      fetchMock.mockResolvedValueOnce(jsonResponse(emptyHashtagResponse()));
    }

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    await scanInstagramBrandAbuse("Acme", "valid-access-token");

    const hashtagSearchCall = fetchMock.mock.calls.find(
      call => typeof call[0] === "string" && (call[0] as string).includes("ig_hashtag_search"),
    );
    expect(hashtagSearchCall).toBeDefined();
    expect(hashtagSearchCall![0]).toContain("user_id=page_123");
  });
});

describe("scanInstagramBrandAbuse — error cases", () => {
  it("returns empty when /me returns a non-OK status", async () => {
    fetchMock.mockResolvedValueOnce(errorResponse(403));

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "bad-token");

    expect(results).toEqual([]);
  });

  it("returns empty when fetch throws a network error during /me", async () => {
    fetchMock.mockRejectedValueOnce(new Error("Network failure"));

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "any-token");

    expect(results).toEqual([]);
  });

  it("continues scanning other hashtags when one hashtag's recent_media call fails", async () => {
    // Give 2 hashtags IDs: index 0 (#acme) and index 1 (#acmeofficial)
    // One media call fails; both are still attempted.
    fetchMock.mockResolvedValueOnce(jsonResponse(meResponse("ig_biz_1"))); // /me
    // 6 getHashtagId responses (parallel order: acme, acmeofficial, acmereal, acmescam, acmefake, acmegiveaway)
    fetchMock.mockResolvedValueOnce(jsonResponse(hashtagIdResponse("ht_1"))); // #acme
    fetchMock.mockResolvedValueOnce(jsonResponse(hashtagIdResponse("ht_2"))); // #acmeofficial
    for (let i = 2; i < 6; i++) {
      fetchMock.mockResolvedValueOnce(jsonResponse(emptyHashtagResponse()));
    }
    // recent_media for both IDs that were returned (order follows getHashtagId resolution)
    fetchMock.mockResolvedValueOnce(errorResponse(500)); // one fails
    fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] })); // other returns empty

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");

    // Key invariant: the function completes without throwing even when a media call fails.
    // Both media endpoints (9 total fetch calls) must be attempted.
    let caughtError: unknown;
    try {
      await scanInstagramBrandAbuse("Acme", "valid-token");
    } catch (e) {
      caughtError = e;
    }

    expect(caughtError).toBeUndefined();
    expect(fetchMock.mock.calls.length).toBe(9);
  });
});

describe("scanInstagramBrandAbuse — signal filtering", () => {
  it("filters out posts whose caption does not contain the brand name", async () => {
    buildMockSequence(
      fetchMock,
      "ig_biz_1",
      { 0: "ht_1" },
      { ht_1: mediaResponse("Big giveaway! Win free crypto airdrop today") }, // no "acme"
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-token");

    expect(results).toHaveLength(0);
  });

  it("filters out posts that have the brand name but no scam signal", async () => {
    buildMockSequence(
      fetchMock,
      "ig_biz_1",
      { 0: "ht_1" },
      { ht_1: mediaResponse("Acme just released a new product this week") },
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-token");

    expect(results).toHaveLength(0);
  });

  it("assigns high risk for posts under scam/fake hashtags (index 3 = #acmescam)", async () => {
    // Hashtag indices: 0=#acme, 1=#acmeofficial, 2=#acmereal, 3=#acmescam, 4=#acmefake, 5=#acmegiveaway
    buildMockSequence(
      fetchMock,
      "ig_biz_1",
      { 3: "ht_scam" }, // only #acmescam gets an ID
      { ht_scam: mediaResponse("Acme is a total scam! Fake giveaway fraud") },
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-token");

    expect(results.length).toBeGreaterThan(0);
    const highRisk = results.find(r => r.risk === "high");
    expect(highRisk).toBeDefined();
  });

  it("assigns medium risk for posts under non-scam hashtags with 'official' in caption", async () => {
    // #acme (index 0) is not a scam/fake hashtag, so risk = medium
    buildMockSequence(
      fetchMock,
      "ig_biz_1",
      { 0: "ht_acme" },
      { ht_acme: mediaResponse("Acme official account — visit our verified site now") },
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-token");

    const r = results.find(r => r.platform === "Instagram");
    expect(r).toBeDefined();
    expect(r!.risk).toBe("medium");
  });

  it("caps results at 10 per platform", async () => {
    // 12 posts under #acme — should be capped at 10
    const posts = Array.from({ length: 12 }, (_, i) => ({
      id: `post_${i}`,
      caption: `Acme official giveaway scam #${i} — free crypto airdrop`,
      permalink: `https://www.instagram.com/p/${i}/`,
      timestamp: "2026-07-01T00:00:00Z",
      media_type: "IMAGE",
    }));

    buildMockSequence(
      fetchMock,
      "ig_biz_1",
      { 0: "ht_acme" },
      { ht_acme: { data: posts } },
    );

    const { scanInstagramBrandAbuse } = await import("../../lib/instagramScanner");
    const results = await scanInstagramBrandAbuse("Acme", "valid-token");

    expect(results.filter(r => r.platform === "Instagram").length).toBeLessThanOrEqual(10);
  });
});
