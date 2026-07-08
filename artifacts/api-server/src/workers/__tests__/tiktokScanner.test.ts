/**
 * Unit tests for tiktokScanner.ts — scanTikTokBrandAbuse()
 *
 * Invariants tested:
 *  1. Valid API token + scam video with brand name → result returned with correct fields
 *  2. Non-OK HTTP response → graceful empty return (no throw)
 *  3. API returns non-"ok" error code in body → graceful empty return
 *  4. Videos missing the brand name in description are filtered out (scam search)
 *  5. Videos without a scam keyword in description are filtered out (scam search)
 *  6. Deduplication: same video URL not added twice across scam + hashtag searches
 *  7. Dedup within scam search: same video ID only added once
 *  8. High-engagement video (likes+shares > 500) → "high" risk
 *  9. Scam signal in description + brand name → "high" risk
 * 10. Low-engagement, no scam signal in description → "medium" risk
 * 11. Per-platform scam-search cap (8) and hashtag-search cap (12) are respected
 * 12. Authorization header sent as Bearer token
 * 13. POST method used for Research API calls
 * 14. Date range formatted as YYYYMMDD in request body
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
    text: () => Promise.resolve("Unauthorized"),
  } as unknown as Response;
}

function makeVideo(overrides: Partial<{
  id: string;
  username: string;
  display_name: string;
  description: string;
  view_count: number;
  like_count: number;
  share_count: number;
  hashtag_names: string[];
}> = {}) {
  return {
    id: overrides.id ?? "vid_1",
    author_info: {
      username: overrides.username ?? "scammer_user",
      display_name: overrides.display_name ?? "Scammer",
    },
    video_description: overrides.description ?? "Acme scam giveaway — free crypto airdrop!",
    create_time: 1751500000,
    view_count: overrides.view_count ?? 1000,
    like_count: overrides.like_count ?? 50,
    share_count: overrides.share_count ?? 10,
    hashtag_names: overrides.hashtag_names ?? ["acmescam", "giveaway"],
    region_code: "US",
  };
}

function tiktokSuccess(videos: ReturnType<typeof makeVideo>[]) {
  return jsonResponse({
    data: { videos, cursor: 0, has_more: false },
    error: { code: "ok", message: "" },
  });
}

function tiktokApiError(code: string, message: string) {
  return jsonResponse({
    data: null,
    error: { code, message },
  });
}

// ── Shared fetch mock ─────────────────────────────────────────────────────────

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ── Tests ─────────────────────────────────────────────────────────────────────

describe("scanTikTokBrandAbuse — happy path", () => {
  it("returns a fake_social result for a matching scam video", async () => {
    const video = makeVideo();
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video])) // scam video search
      .mockResolvedValueOnce(tiktokSuccess([]));      // hashtag search

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-api-token");

    expect(results.length).toBeGreaterThan(0);
    const r = results[0]!;
    expect(r.platform).toBe("TikTok");
    expect(r.type).toBe("fake_social");
    expect(r.url).toContain("tiktok.com/@scammer_user/video/vid_1");
    expect(r.title).toContain("@scammer_user");
    expect(r.title).toContain("Acme");
    expect(r.evidenceSnippet).toContain("Author: @scammer_user");
    expect(r.evidenceSnippet).toContain("Caption:");
    expect(r.evidenceSnippet).toContain("Views:");
    expect(r.installCount).toBeNull();
  });

  it("sends Authorization header with Bearer token", async () => {
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    await scanTikTokBrandAbuse("Acme", "my-research-token");

    const headers = fetchMock.mock.calls[0]![1]?.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer my-research-token");
  });

  it("uses POST method for the Research API", async () => {
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    await scanTikTokBrandAbuse("Acme", "any-token");

    expect(fetchMock.mock.calls[0]![1]?.method).toBe("POST");
  });

  it("includes a date range in YYYYMMDD format in the request body", async () => {
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    await scanTikTokBrandAbuse("Acme", "any-token");

    const body = JSON.parse(fetchMock.mock.calls[0]![1]?.body as string);
    expect(body.start_date).toMatch(/^\d{8}$/);
    expect(body.end_date).toMatch(/^\d{8}$/);
    expect(Number(body.end_date)).toBeGreaterThan(Number(body.start_date));
  });

  it("includes brand + scam keywords in the scam video query field_values", async () => {
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    await scanTikTokBrandAbuse("Acme", "any-token");

    const body = JSON.parse(fetchMock.mock.calls[0]![1]?.body as string);
    const fieldValues: string[] = body.query?.and?.[0]?.field_values ?? [];
    const hasBrandScam = fieldValues.some((v: string) => v.includes("Acme") && v.includes("scam"));
    expect(hasBrandScam).toBe(true);
  });
});

describe("scanTikTokBrandAbuse — error cases", () => {
  it("returns empty when both search calls return non-OK HTTP status", async () => {
    fetchMock
      .mockResolvedValueOnce(errorResponse(401))
      .mockResolvedValueOnce(errorResponse(401));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "bad-token");

    expect(results).toEqual([]);
  });

  it("returns empty when the API body contains a non-ok error code", async () => {
    fetchMock
      .mockResolvedValueOnce(tiktokApiError("invalid_token", "Token invalid"))
      .mockResolvedValueOnce(tiktokApiError("invalid_token", "Token invalid"));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "bad-token");

    expect(results).toEqual([]);
  });

  it("returns empty when fetch throws (network error)", async () => {
    fetchMock.mockRejectedValue(new Error("ECONNREFUSED"));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "any-token");

    expect(results).toEqual([]);
  });

  it("continues to hashtag search even when scam video search fails", async () => {
    const video = makeVideo({ hashtag_names: ["acmescam"] });
    fetchMock
      .mockResolvedValueOnce(errorResponse(500))    // scam search fails
      .mockResolvedValueOnce(tiktokSuccess([video])); // hashtag search succeeds

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    expect(results.filter(r => r.platform === "TikTok").length).toBeGreaterThan(0);
  });
});

describe("scanTikTokBrandAbuse — signal filtering", () => {
  it("filters out scam-search videos whose description does not contain the brand name", async () => {
    const video = makeVideo({ description: "Big scam giveaway — free crypto airdrop!" }); // no "acme"
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    expect(results.filter(r => r.platform === "TikTok" && r.type === "fake_social")).toHaveLength(0);
  });

  it("filters out scam-search videos without a scam keyword in description", async () => {
    const video = makeVideo({ description: "Acme just launched a new feature" });
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    // Scam search produces nothing (no scam keyword); hashtag search is also empty
    expect(results.filter(r => r.type === "fake_social")).toHaveLength(0);
  });
});

describe("scanTikTokBrandAbuse — risk scoring", () => {
  it("assigns high risk when description has scam signal AND contains brand name", async () => {
    const video = makeVideo({
      description: "Acme scam giveaway — free crypto airdrop!",
      like_count: 5,
      share_count: 5,
    });
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    const r = results.find(r => r.platform === "TikTok");
    expect(r).toBeDefined();
    expect(r!.risk).toBe("high");
  });

  it("assigns high risk when engagement (likes + shares) > 500", async () => {
    // Use the hashtag search path (no scam keyword filter) to keep description neutral
    const video = makeVideo({
      description: "Acme product video watch now",
      like_count: 400,
      share_count: 200, // 600 total
    });
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([video]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    const r = results.find(r => r.platform === "TikTok");
    expect(r).toBeDefined();
    expect(r!.risk).toBe("high");
  });

  it("assigns medium risk when engagement ≤ 500 and no scam signal in description", async () => {
    const video = makeVideo({
      description: "Acme product review",
      like_count: 50,
      share_count: 20, // 70 total
    });
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess([video]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    const r = results.find(r => r.platform === "TikTok");
    expect(r).toBeDefined();
    expect(r!.risk).toBe("medium");
  });
});

describe("scanTikTokBrandAbuse — deduplication", () => {
  it("does not include the same video URL twice when it appears in both searches", async () => {
    const video = makeVideo({ id: "vid_dup", hashtag_names: ["acmescam"] });

    // Same video returned by scam search and hashtag search
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video]))
      .mockResolvedValueOnce(tiktokSuccess([video]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    const dupUrl = `https://www.tiktok.com/@scammer_user/video/vid_dup`;
    const matchingUrls = results.map(r => r.url).filter(u => u === dupUrl);
    expect(matchingUrls.length).toBeLessThanOrEqual(1);
  });

  it("counts unique results when the same scam video appears twice in the API response", async () => {
    const video = makeVideo({ id: "vid_same" });

    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([video, video]))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    // The scanner should deduplicate by video ID — total TikTok results must be ≤ 1
    expect(results.filter(r => r.platform === "TikTok").length).toBeLessThanOrEqual(1);
    // And if a result is present, it must have the expected URL
    const withId = results.find(r => r.url?.includes("vid_same"));
    if (results.filter(r => r.platform === "TikTok").length > 0) {
      expect(withId).toBeDefined();
    }
  });
});

describe("scanTikTokBrandAbuse — result caps", () => {
  it("caps scam-search results at 8 TikTok entries", async () => {
    const videos = Array.from({ length: 15 }, (_, i) =>
      makeVideo({ id: `v${i}`, description: `Acme scam giveaway crypto airdrop #${i}` }),
    );
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess(videos))
      .mockResolvedValueOnce(tiktokSuccess([]));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    expect(results.filter(r => r.platform === "TikTok").length).toBeLessThanOrEqual(8);
  });

  it("caps hashtag-search results so total TikTok results do not exceed 12", async () => {
    const hashtagVideos = Array.from({ length: 20 }, (_, i) =>
      makeVideo({ id: `h${i}`, description: `Acme product review #${i}` }),
    );
    fetchMock
      .mockResolvedValueOnce(tiktokSuccess([]))
      .mockResolvedValueOnce(tiktokSuccess(hashtagVideos));

    const { scanTikTokBrandAbuse } = await import("../../lib/tiktokScanner");
    const results = await scanTikTokBrandAbuse("Acme", "valid-token");

    expect(results.filter(r => r.platform === "TikTok").length).toBeLessThanOrEqual(12);
  });
});
