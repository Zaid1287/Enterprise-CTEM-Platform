import { logger } from "./logger";
import type { BrandAbuseResult } from "./brandAbuseScanner";

const TIKTOK_RESEARCH_BASE = "https://open.tiktokapis.com/v2/research";

const SCAM_KEYWORDS = ["scam", "fraud", "fake", "phishing", "giveaway", "airdrop", "official", "real", "verify", "crypto"];

function hasScamSignal(text: string): boolean {
  const lower = text.toLowerCase();
  return SCAM_KEYWORDS.some(k => lower.includes(k));
}

function formatDate(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

/**
 * Scan TikTok via the Research API for brand impersonation.
 *
 * Two queries are performed:
 *  1. Videos mentioning the brand name alongside scam/fraud keywords
 *  2. Videos using brand-related hashtags (#brandofficial, #brandfake, etc.)
 *
 * The TikTok Research API token must be a valid Research API bearer token
 * (approved through the TikTok Developer Portal Research program).
 */
export async function scanTikTokBrandAbuse(
  brand: string,
  apiToken: string,
): Promise<BrandAbuseResult[]> {
  const results: BrandAbuseResult[] = [];
  const brandLower = brand.toLowerCase();

  // Search window: last 30 days (Research API requires date range)
  const endDate = new Date();
  const startDate = new Date(endDate);
  startDate.setDate(startDate.getDate() - 30);
  const startDateStr = formatDate(startDate);
  const endDateStr = formatDate(endDate);

  await Promise.allSettled([
    searchBrandScamVideos(brand, brandLower, apiToken, startDateStr, endDateStr, results),
    searchBrandHashtagVideos(brand, brandLower, apiToken, startDateStr, endDateStr, results),
  ]);

  return results;
}

async function researchPost(
  path: string,
  body: object,
  apiToken: string,
): Promise<Response> {
  return fetch(`${TIKTOK_RESEARCH_BASE}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
      "User-Agent": "SentinelwareBrandMonitor/1.0",
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
}

interface TikTokVideo {
  id?: string;
  author_info?: { display_name?: string; username?: string };
  video_description?: string;
  create_time?: number;
  view_count?: number;
  like_count?: number;
  share_count?: number;
  hashtag_names?: string[];
  region_code?: string;
}

function buildAbuseResult(
  video: TikTokVideo,
  brand: string,
  brandLower: string,
  reason: string,
): BrandAbuseResult {
  const authorName = video.author_info?.display_name ?? video.author_info?.username ?? "unknown";
  const authorHandle = video.author_info?.username ?? "unknown";
  const description = video.video_description ?? "";
  const views = video.view_count ?? 0;
  const engagement = (video.like_count ?? 0) + (video.share_count ?? 0);
  const isHighRisk = hasScamSignal(description) && description.toLowerCase().includes(brandLower);

  return {
    type: "fake_social",
    platform: "TikTok",
    url: video.id ? `https://www.tiktok.com/@${authorHandle}/video/${video.id}` : `https://www.tiktok.com/search?q=${encodeURIComponent(brand)}`,
    title: `TikTok video by @${authorHandle} referencing "${brand}"`,
    description: `TikTok video by @${authorName} (${views.toLocaleString()} views) ${reason}. May indicate a scam or impersonation campaign targeting the brand.`,
    evidenceSnippet: [
      `Author: @${authorHandle}`,
      `Caption: ${description.slice(0, 200)}`,
      `Views: ${views.toLocaleString()}`,
      video.hashtag_names?.length ? `Hashtags: ${video.hashtag_names.slice(0, 5).map(h => `#${h}`).join(", ")}` : null,
    ].filter(Boolean).join("; "),
    installCount: null,
    iconUrl: null,
    risk: isHighRisk || engagement > 500 ? "high" : "medium",
  };
}

async function searchBrandScamVideos(
  brand: string,
  brandLower: string,
  apiToken: string,
  startDate: string,
  endDate: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const body = {
      query: {
        and: [
          {
            field_name: "keyword",
            operation: "IN",
            field_values: [`${brand} scam`, `${brand} fake`, `${brand} giveaway`, `${brand} official`],
          },
        ],
      },
      start_date: startDate,
      end_date: endDate,
      max_count: 20,
      fields: "id,author_info,video_description,create_time,view_count,like_count,share_count,hashtag_names,region_code",
    };

    const res = await researchPost("/video/query/", body, apiToken);
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      logger.warn({ status: res.status, brand, body: text.slice(0, 300) }, "TikTok Research video/query failed");
      return;
    }

    const data = await res.json() as {
      data?: { videos?: TikTokVideo[]; cursor?: number; has_more?: boolean };
      error?: { code?: string; message?: string };
    };

    if (data.error?.code && data.error.code !== "ok") {
      logger.warn({ brand, error: data.error }, "TikTok Research API returned error in scam video search");
      return;
    }

    const seen = new Set<string>();
    for (const video of (data.data?.videos ?? [])) {
      const desc = (video.video_description ?? "").toLowerCase();
      if (!desc.includes(brandLower)) continue;
      if (!hasScamSignal(desc)) continue;

      const key = video.id ?? desc.slice(0, 60);
      if (seen.has(key)) continue;
      seen.add(key);

      out.push(buildAbuseResult(video, brand, brandLower, "contains brand name alongside scam/fraud keyword signals"));

      if (out.filter(r => r.platform === "TikTok").length >= 8) return;
    }
  } catch (e: any) {
    logger.debug({ brand, err: e.message }, "TikTok scam video search failed");
  }
}

async function searchBrandHashtagVideos(
  brand: string,
  brandLower: string,
  apiToken: string,
  startDate: string,
  endDate: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandSlug = brandLower.replace(/\s+/g, "");
    const abuseHashtags = [
      `${brandSlug}official`,
      `${brandSlug}fake`,
      `${brandSlug}scam`,
      `${brandSlug}giveaway`,
      `fake${brandSlug}`,
    ];

    const body = {
      query: {
        and: [
          {
            field_name: "hashtag_name",
            operation: "IN",
            field_values: abuseHashtags,
          },
        ],
      },
      start_date: startDate,
      end_date: endDate,
      max_count: 20,
      fields: "id,author_info,video_description,create_time,view_count,like_count,share_count,hashtag_names,region_code",
    };

    const res = await researchPost("/video/query/", body, apiToken);
    if (!res.ok) return;

    const data = await res.json() as {
      data?: { videos?: TikTokVideo[] };
      error?: { code?: string; message?: string };
    };

    if (data.error?.code && data.error.code !== "ok") {
      logger.warn({ brand, error: data.error }, "TikTok Research API returned error in hashtag video search");
      return;
    }

    const seen = new Set<string>(out.map(r => r.url ?? ""));
    for (const video of (data.data?.videos ?? [])) {
      const key = video.id ? `https://www.tiktok.com/@${video.author_info?.username}/video/${video.id}` : "";
      if (key && seen.has(key)) continue;
      if (key) seen.add(key);

      const usedHashtags = video.hashtag_names ?? [];
      const matchedHashtag = usedHashtags.find(h => abuseHashtags.includes(h.toLowerCase()));

      out.push(buildAbuseResult(
        video,
        brand,
        brandLower,
        `uses hashtag #${matchedHashtag ?? abuseHashtags[0]} — commonly associated with brand impersonation`,
      ));

      if (out.filter(r => r.platform === "TikTok").length >= 12) return;
    }
  } catch (e: any) {
    logger.debug({ brand, err: e.message }, "TikTok hashtag video search failed");
  }
}
