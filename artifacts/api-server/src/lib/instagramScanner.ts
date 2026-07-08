import { logger } from "./logger";
import type { BrandAbuseResult } from "./brandAbuseScanner";
import type { ScanWarning } from "./brandAbuseScanner";

const GRAPH_API_BASE = "https://graph.facebook.com/v19.0";

const IMPERSONATION_HASHTAGS = (brand: string) => [
  brand,
  `${brand}official`,
  `${brand}real`,
  `${brand}scam`,
  `${brand}fake`,
  `${brand}giveaway`,
];

/**
 * Scan Instagram via the Graph API for brand impersonation.
 *
 * Strategy:
 *  1. Get the IG user ID associated with the access token (required for hashtag search)
 *  2. Search brand-related hashtags (official, real, scam, fake, giveaway)
 *  3. Retrieve recent media for each hashtag
 *  4. Flag posts that contain brand impersonation signals in their captions
 *
 * Rate-limit responses (HTTP 429) are detected and recorded as structured
 * warnings so the caller can persist them and surface them in the UI.
 */
export async function scanInstagramBrandAbuse(
  brand: string,
  accessToken: string,
  warnings: ScanWarning[],
): Promise<BrandAbuseResult[]> {
  const results: BrandAbuseResult[] = [];

  let igUserId: string | null = null;
  try {
    igUserId = await getIgUserId(accessToken, warnings);
  } catch (e: any) {
    logger.warn({ brand, err: e.message }, "Instagram: could not retrieve IG user ID — skipping scan");
    return results;
  }

  if (!igUserId) return results;

  const brandLower = brand.toLowerCase();
  const hashtags = IMPERSONATION_HASHTAGS(brandLower.replace(/\s+/g, ""));

  const hashtagScans = hashtags.map(tag =>
    scanHashtag(tag, brand, brandLower, igUserId!, accessToken, results, warnings),
  );
  await Promise.allSettled(hashtagScans);

  return results;
}

async function graphFetch(url: string): Promise<Response> {
  return fetch(url, {
    headers: { "User-Agent": "SentinelwareBrandMonitor/1.0" },
    signal: AbortSignal.timeout(15_000),
  });
}

async function getIgUserId(accessToken: string, warnings: ScanWarning[]): Promise<string | null> {
  const res = await graphFetch(
    `${GRAPH_API_BASE}/me?access_token=${accessToken}&fields=id,instagram_business_account`,
  );
  if (!res.ok) {
    if (res.status === 429) {
      const msg = "Instagram Graph API rate limit hit during authentication — results may be incomplete.";
      logger.warn({ status: 429 }, "Instagram /me rate-limited (429)");
      warnings.push({ platform: "Instagram", code: "rate_limited", message: msg, timestamp: new Date().toISOString() });
    }
    const body = await res.text().catch(() => "");
    throw new Error(`Graph API /me returned ${res.status}: ${body.slice(0, 200)}`);
  }
  const data = await res.json() as {
    id?: string;
    instagram_business_account?: { id: string };
  };
  // Prefer the linked IG Business Account ID; fall back to the user/page ID
  return data.instagram_business_account?.id ?? data.id ?? null;
}

async function getHashtagId(
  tag: string,
  igUserId: string,
  accessToken: string,
): Promise<string | null> {
  const res = await graphFetch(
    `${GRAPH_API_BASE}/ig_hashtag_search?user_id=${igUserId}&q=${encodeURIComponent(tag)}&access_token=${accessToken}`,
  );
  if (!res.ok) return null;
  const data = await res.json() as { data?: Array<{ id: string }> };
  return data.data?.[0]?.id ?? null;
}

async function scanHashtag(
  tag: string,
  brand: string,
  brandLower: string,
  igUserId: string,
  accessToken: string,
  out: BrandAbuseResult[],
  warnings: ScanWarning[],
): Promise<void> {
  try {
    const hashtagId = await getHashtagId(tag, igUserId, accessToken);
    if (!hashtagId) return;

    const mediaRes = await graphFetch(
      `${GRAPH_API_BASE}/${hashtagId}/recent_media?user_id=${igUserId}&access_token=${accessToken}&fields=id,caption,permalink,timestamp,media_type&limit=20`,
    );
    if (!mediaRes.ok) {
      if (mediaRes.status === 429) {
        const msg = `Instagram Graph API rate limit hit while scanning hashtag #${tag} — results may be incomplete.`;
        logger.warn({ status: 429, brand, tag }, "Instagram hashtag media fetch rate-limited (429)");
        if (!warnings.some(w => w.platform === "Instagram" && w.code === "rate_limited")) {
          warnings.push({ platform: "Instagram", code: "rate_limited", message: msg, timestamp: new Date().toISOString() });
        }
      }
      return;
    }
    const mediaData = await mediaRes.json() as {
      data?: Array<{
        id: string;
        caption?: string;
        permalink?: string;
        timestamp?: string;
        media_type?: string;
      }>;
    };

    const scamTags = ["official", "real", "verified", "giveaway", "scam", "fake", "phishing", "crypto", "airdrop"];

    for (const post of (mediaData.data ?? [])) {
      const captionLower = (post.caption ?? "").toLowerCase();
      if (!captionLower.includes(brandLower)) continue;

      const hasScamSignal = scamTags.some(s => captionLower.includes(s));
      const isHighRisk = tag.includes("scam") || tag.includes("fake") ||
        (tag.includes("giveaway") && captionLower.includes(brandLower));

      if (!hasScamSignal && !isHighRisk) continue;

      const risk: BrandAbuseResult["risk"] = isHighRisk ? "high" : "medium";

      out.push({
        type: "fake_social",
        platform: "Instagram",
        url: post.permalink ?? `https://www.instagram.com/explore/tags/${encodeURIComponent(tag)}/`,
        title: `Instagram post under #${tag} mentions "${brand}"`,
        description: `Instagram post found under hashtag #${tag} that references brand "${brand}" alongside ${isHighRisk ? "high-risk" : "suspicious"} signals — possible impersonation or scam campaign.`,
        evidenceSnippet: `Hashtag: #${tag}; Caption excerpt: ${(post.caption ?? "").slice(0, 200)}; Type: ${post.media_type ?? "unknown"}`,
        installCount: null,
        iconUrl: null,
        risk,
      });

      if (out.filter(r => r.platform === "Instagram").length >= 10) return;
    }
  } catch (e: any) {
    logger.debug({ brand, tag, err: e.message }, "Instagram hashtag scan failed");
  }
}
