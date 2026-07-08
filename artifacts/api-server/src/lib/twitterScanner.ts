import { logger } from "./logger";
import type { BrandAbuseResult } from "./brandAbuseScanner";
import type { ScanWarning } from "./brandAbuseScanner";

const TWITTER_API_BASE = "https://api.twitter.com/2";

const SCAM_KEYWORDS = ["scam", "fake", "fraud", "phishing", "impersonat", "giveaway", "crypto", "airdrop"];

function hasScamSignal(text: string): boolean {
  const lower = text.toLowerCase();
  return SCAM_KEYWORDS.some(k => lower.includes(k));
}

function riskFromSignals(usernameContainsBrand: boolean, hasScam: boolean, followerCount: number): "high" | "medium" | "low" {
  if (usernameContainsBrand && hasScam) return "high";
  if (usernameContainsBrand || hasScam) return "medium";
  return "low";
}

/**
 * Scan Twitter/X for brand impersonation using the v2 API.
 *
 * Two searches are performed:
 *  1. Recent tweets containing the brand name alongside scam/fraud signals
 *  2. User accounts whose username or display name contains the brand name
 *
 * Rate-limit responses (HTTP 429) are detected and recorded as structured
 * warnings so the caller can persist them and surface them in the UI.
 */
export async function scanTwitterBrandAbuse(
  brand: string,
  bearerToken: string,
  warnings: ScanWarning[],
): Promise<BrandAbuseResult[]> {
  const results: BrandAbuseResult[] = [];
  const brandLower = brand.toLowerCase();

  await Promise.allSettled([
    searchImpersonatingAccounts(brand, brandLower, bearerToken, results, warnings),
    searchScamTweets(brand, brandLower, bearerToken, results, warnings),
  ]);

  return results;
}

async function twitterFetch(url: string, bearerToken: string): Promise<Response> {
  return fetch(url, {
    headers: {
      Authorization: `Bearer ${bearerToken}`,
      "User-Agent": "SentinelwareBrandMonitor/1.0",
    },
    signal: AbortSignal.timeout(15_000),
  });
}

async function searchImpersonatingAccounts(
  brand: string,
  brandLower: string,
  bearerToken: string,
  out: BrandAbuseResult[],
  warnings: ScanWarning[],
): Promise<void> {
  try {
    // Twitter v2 user search — finds users whose name or bio contains the brand
    const query = encodeURIComponent(brand);
    const fields = "username,name,description,verified,public_metrics,profile_image_url";
    const url = `${TWITTER_API_BASE}/users/search?query=${query}&max_results=10&user.fields=${fields}`;

    const res = await twitterFetch(url, bearerToken);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      if (res.status === 429) {
        const retryAfter = res.headers.get("x-rate-limit-reset") ?? res.headers.get("retry-after");
        const msg = `Twitter/X API rate limit hit during user search — results may be incomplete.${retryAfter ? ` Retry after: ${new Date(Number(retryAfter) * 1000).toISOString()}` : ""}`;
        logger.warn({ status: 429, brand, retryAfter }, "Twitter user search rate-limited (429)");
        warnings.push({ platform: "Twitter/X", code: "rate_limited", message: msg, timestamp: new Date().toISOString() });
      } else {
        logger.warn({ status: res.status, brand, body: body.slice(0, 200) }, "Twitter user search failed");
      }
      return;
    }

    const data = await res.json() as {
      data?: Array<{
        id: string;
        username: string;
        name: string;
        description?: string;
        verified?: boolean;
        public_metrics?: { followers_count?: number; tweet_count?: number };
        profile_image_url?: string;
      }>;
      meta?: { result_count?: number };
    };

    for (const user of (data.data ?? [])) {
      const usernameLower = user.username.toLowerCase();
      const nameLower = user.name.toLowerCase();
      const bioLower = (user.description ?? "").toLowerCase();

      // Skip accounts that are exactly the brand (may be the official account)
      if (usernameLower === brandLower) continue;

      const usernameContainsBrand = usernameLower.includes(brandLower);
      const nameContainsBrand = nameLower.includes(brandLower);
      const bioMentionsBrand = bioLower.includes(brandLower);

      // Must have at least one brand signal
      if (!usernameContainsBrand && !nameContainsBrand && !bioMentionsBrand) continue;

      const claimsOfficial =
        usernameLower.includes("official") || usernameLower.includes("real") ||
        nameLower.includes("official") || nameLower.includes("real") ||
        bioLower.includes("official") || bioLower.includes("this is the real");

      const followers = user.public_metrics?.followers_count ?? 0;
      const hasScam = hasScamSignal(user.description ?? "");
      const risk = claimsOfficial ? "high" : riskFromSignals(usernameContainsBrand, hasScam, followers);

      // Low-signal accounts with very high followers are likely legitimate businesses
      if (!usernameContainsBrand && !claimsOfficial && !hasScam && followers > 50_000) continue;

      out.push({
        type: "fake_social",
        platform: "Twitter/X",
        url: `https://twitter.com/${user.username}`,
        title: `@${user.username} on Twitter/X`,
        description: `Twitter/X account @${user.username} ("${user.name}") ${usernameContainsBrand ? "uses brand name in handle" : "references brand in bio"}${claimsOfficial ? " and claims to be the official account" : ""}. ${followers.toLocaleString()} followers.`,
        evidenceSnippet: [
          `Handle: @${user.username}`,
          `Display name: ${user.name}`,
          user.description ? `Bio: ${user.description.slice(0, 150)}` : null,
          `Followers: ${followers.toLocaleString()}`,
          user.verified ? "Verified: true" : null,
        ].filter(Boolean).join("; "),
        installCount: null,
        iconUrl: user.profile_image_url ?? null,
        risk,
      });
    }
  } catch (e: any) {
    logger.debug({ brand, err: e.message }, "Twitter account search failed");
  }
}

async function searchScamTweets(
  brand: string,
  brandLower: string,
  bearerToken: string,
  out: BrandAbuseResult[],
  warnings: ScanWarning[],
): Promise<void> {
  try {
    // Recent tweet search: brand + scam/fraud signals, exclude retweets, last 7 days
    const scamQuery = encodeURIComponent(
      `"${brand}" (scam OR fraud OR fake OR phishing OR giveaway) -is:retweet lang:en`,
    );
    const tweetFields = "author_id,created_at,text,public_metrics,entities";
    const userFields = "username,name,description,public_metrics,profile_image_url";
    const url = `${TWITTER_API_BASE}/tweets/search/recent?query=${scamQuery}&max_results=10&tweet.fields=${tweetFields}&expansions=author_id&user.fields=${userFields}`;

    const res = await twitterFetch(url, bearerToken);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      if (res.status === 429) {
        const retryAfter = res.headers.get("x-rate-limit-reset") ?? res.headers.get("retry-after");
        const msg = `Twitter/X API rate limit hit during tweet search — results may be incomplete.${retryAfter ? ` Retry after: ${new Date(Number(retryAfter) * 1000).toISOString()}` : ""}`;
        logger.warn({ status: 429, brand, retryAfter }, "Twitter tweet search rate-limited (429)");
        // Only push one Twitter/X warning total (user-search warning may already exist)
        if (!warnings.some(w => w.platform === "Twitter/X" && w.code === "rate_limited")) {
          warnings.push({ platform: "Twitter/X", code: "rate_limited", message: msg, timestamp: new Date().toISOString() });
        }
      } else {
        logger.warn({ status: res.status, brand, body: body.slice(0, 200) }, "Twitter tweet search failed");
      }
      return;
    }

    const data = await res.json() as {
      data?: Array<{
        id: string;
        author_id: string;
        text: string;
        created_at?: string;
        public_metrics?: { retweet_count?: number; like_count?: number };
        entities?: { urls?: Array<{ expanded_url?: string }> };
      }>;
      includes?: {
        users?: Array<{
          id: string;
          username: string;
          name: string;
          description?: string;
          public_metrics?: { followers_count?: number };
          profile_image_url?: string;
        }>;
      };
    };

    const userMap = new Map(
      (data.includes?.users ?? []).map(u => [u.id, u]),
    );

    const seen = new Set<string>();
    for (const tweet of (data.data ?? [])) {
      const textLower = tweet.text.toLowerCase();
      if (!textLower.includes(brandLower)) continue;

      const author = userMap.get(tweet.author_id);
      const authorHandle = author?.username ?? tweet.author_id;
      const dedupeKey = `${authorHandle}-${tweet.text.slice(0, 80)}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const tweetUrl = `https://twitter.com/${authorHandle}/status/${tweet.id}`;
      const likes = tweet.public_metrics?.like_count ?? 0;
      const retweets = tweet.public_metrics?.retweet_count ?? 0;
      const engagement = likes + retweets;

      out.push({
        type: "brand_abuse",
        platform: "Twitter/X",
        url: tweetUrl,
        title: `Brand abuse tweet by @${authorHandle}`,
        description: `Tweet by @${authorHandle} uses "${brand}" with scam/fraud signals — may indicate an active impersonation or phishing campaign. ${engagement} engagements.`,
        evidenceSnippet: tweet.text.slice(0, 280),
        installCount: null,
        iconUrl: author?.profile_image_url ?? null,
        risk: engagement > 100 ? "high" : "medium",
      });

      if (out.filter(r => r.type === "brand_abuse" && r.platform === "Twitter/X").length >= 5) break;
    }
  } catch (e: any) {
    logger.debug({ brand, err: e.message }, "Twitter scam tweet search failed");
  }
}
