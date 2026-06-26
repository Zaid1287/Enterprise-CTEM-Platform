import { logger } from "./logger";

export interface BrandAbuseResult {
  type: string;
  platform: string | null;
  url: string | null;
  title: string | null;
  description: string | null;
  evidenceSnippet: string | null;
  risk: string;
}

export async function scanBrandAbuse(
  brand: string,
  domain: string,
  socialHandles: string[] = [],
  youtubeApiKey?: string,
): Promise<BrandAbuseResult[]> {
  const results: BrandAbuseResult[] = [];

  await Promise.allSettled([
    checkCertTransparencyAbuse(brand, domain, results),
    checkDNSTwistLookalikePatterns(brand, domain, results),
    checkAppleAppStore(brand, results),
    checkGooglePlayStore(brand, results),
    checkYouTubeAbuse(brand, results, youtubeApiKey),
    checkRedditAbuse(brand, domain, results),
    ...socialHandles.map(handle => checkSocialHandle(handle, brand, results)),
  ]);

  return results;
}

/**
 * Check if a watchlist social handle appears on major platforms AND contains
 * impersonation signals. Mere profile existence is NOT flagged — we require that
 * the handle contains the brand name as a substring (suggesting impersonation)
 * or that the page title/content references the brand while using a handle that
 * is NOT exactly the brand name (brand-adjacent squatting).
 *
 * False-positive prevention:
 *  - Skip if handle is identical to brand (may be the legitimate official account)
 *  - Require handle to contain brand name or brand name to appear in page body
 *  - Use GET (not HEAD) so we can inspect the page title for brand mentions
 */
async function checkSocialHandle(
  handle: string,
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  const handleLower = handle.toLowerCase();
  const brandLower  = brand.toLowerCase();

  // If the handle is exactly the brand name, it may be the official account — skip
  if (handleLower === brandLower) return;

  // Impersonation signal: handle contains brand as a substring (e.g. "brand_official", "real_brand")
  const handleContainsBrand = handleLower.includes(brandLower);

  const platforms = [
    { name: "Twitter/X",  url: `https://twitter.com/${encodeURIComponent(handle)}` },
    { name: "Instagram",  url: `https://instagram.com/${encodeURIComponent(handle)}` },
    { name: "TikTok",     url: `https://www.tiktok.com/@${encodeURIComponent(handle)}` },
    { name: "Facebook",   url: `https://www.facebook.com/${encodeURIComponent(handle)}` },
    { name: "YouTube",    url: `https://www.youtube.com/@${encodeURIComponent(handle)}` },
  ];

  for (const p of platforms) {
    try {
      const res = await fetch(p.url, {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        signal: AbortSignal.timeout(8_000),
        redirect: "follow",
      });

      if (!res.ok) continue;

      // Parse body for secondary impersonation signal: page mentions brand name
      const body = await res.text();
      const bodyLower = body.toLowerCase();
      const titleMatch = bodyLower.match(/<title[^>]*>([^<]+)<\/title>/i);
      const pageTitle  = titleMatch ? titleMatch[1] ?? "" : "";
      const bodyMentionsBrand = bodyLower.includes(brandLower) ||
                                pageTitle.toLowerCase().includes(brandLower);

      // Flag only when there is at least one concrete impersonation signal
      if (!handleContainsBrand && !bodyMentionsBrand) continue;

      const risk = handleContainsBrand ? "high" : "medium";
      out.push({
        type: "fake_social",
        platform: p.name,
        url: p.url,
        title: `@${handle} on ${p.name}`,
        description: `Watchlist handle @${handle} found on ${p.name} with brand name "${brand}" in ${handleContainsBrand ? "handle" : "page content"} — possible impersonation`,
        evidenceSnippet: `Page title: ${pageTitle || "(none)"}; handle contains brand: ${handleContainsBrand}; page mentions brand: ${bodyMentionsBrand}`,
        risk,
      });
    } catch {
      // Network error — handle likely doesn't exist or platform blocked the request
    }
  }
}

async function checkCertTransparencyAbuse(
  brand: string,
  domain: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const res = await fetch(
      `https://crt.sh/?q=%25${encodeURIComponent(brand)}%25&output=json`,
      { signal: AbortSignal.timeout(12_000) },
    );
    if (!res.ok) return;
    const certs = await res.json() as any[];

    const seen = new Set<string>();
    for (const cert of certs.slice(0, 300)) {
      const cn: string = (cert.common_name ?? cert.name_value ?? "").toLowerCase();
      if (!cn.includes(brand.toLowerCase())) continue;
      if (cn.endsWith(`.${domain}`) || cn === domain) continue;
      if (seen.has(cn)) continue;
      seen.add(cn);

      out.push({
        type: "suspicious_certificate",
        platform: "Certificate Transparency",
        url: `https://crt.sh/?q=${encodeURIComponent(cn)}`,
        title: `Suspicious cert CN: ${cn}`,
        description: `SSL certificate issued for '${cn}' may impersonate ${domain}. Issued: ${cert.not_before ?? "unknown"}.`,
        evidenceSnippet: `CN=${cn}, issuer=${cert.issuer_name ?? "unknown"}`,
        risk: "medium",
      });

      if (out.length >= 30) break;
    }
  } catch (e: any) {
    logger.warn(`CT abuse check failed: ${e.message}`);
  }
}

async function checkDNSTwistLookalikePatterns(
  brand: string,
  _domain: string,
  out: BrandAbuseResult[],
): Promise<void> {
  const lookalikePrefixes = [
    `${brand}-login`, `${brand}-secure`, `${brand}-support`, `${brand}-verify`,
    `${brand}-update`, `${brand}-account`, `${brand}-portal`, `${brand}-help`,
    `login-${brand}`, `secure-${brand}`, `support-${brand}`, `verify-${brand}`,
  ];
  const tlds = [".com", ".net", ".org", ".info", ".co", ".online", ".site"];

  const checks = lookalikePrefixes.slice(0, 8).map(async (prefix) => {
    for (const tld of tlds.slice(0, 3)) {
      const candidate = `${prefix}${tld}`;
      try {
        const { Resolver } = await import("dns/promises");
        const resolver = new Resolver();
        resolver.setServers(["8.8.8.8", "1.1.1.1"]);
        const addrs = await resolver.resolve4(candidate).catch(() => null);
        if (addrs && addrs.length > 0) {
          out.push({
            type: "lookalike_domain",
            platform: "DNS",
            url: `http://${candidate}`,
            title: `Active lookalike: ${candidate}`,
            description: `Domain '${candidate}' is live and mimics brand '${brand}'. Resolves to: ${addrs.join(", ")}`,
            evidenceSnippet: `A records: ${addrs.join(", ")}`,
            risk: "high",
          });
        }
      } catch {
        // expected for non-existent domains
      }
    }
  });

  await Promise.allSettled(checks);
}

async function checkAppleAppStore(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const res = await fetch(
      `https://itunes.apple.com/search?term=${encodeURIComponent(brand)}&entity=software&limit=50`,
      { signal: AbortSignal.timeout(8_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;

    for (const app of (data.results ?? []) as any[]) {
      const appName: string = (app.trackName ?? "").toLowerCase();
      const sellerName: string = (app.sellerName ?? "").toLowerCase();
      const brandLower = brand.toLowerCase();

      if (!appName.includes(brandLower)) continue;

      const isSuspicious =
        !sellerName.includes(brandLower) &&
        !sellerName.includes(brandLower.replace(/\s+/g, "")) &&
        (app.userRatingCountForCurrentVersion ?? 0) < 10;

      if (isSuspicious) {
        out.push({
          type: "rogue_app",
          platform: "Apple App Store",
          url: app.trackViewUrl ?? null,
          title: `Potential rogue iOS app: ${app.trackName}`,
          description: `App '${app.trackName}' by '${app.sellerName}' uses brand name but doesn't appear official. ${app.userRatingCountForCurrentVersion ?? 0} reviews.`,
          evidenceSnippet: `App ID: ${app.trackId}, Developer: ${app.sellerName}`,
          risk: "medium",
        });
      }
    }
  } catch {
    // App Store check is best-effort
  }
}

async function checkGooglePlayStore(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    // Google Play Store public search (web scrape of play.google.com search results)
    const searchUrl = `https://play.google.com/store/search?q=${encodeURIComponent(brand)}&c=apps&hl=en`;
    const res = await fetch(searchUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return;

    const html = await res.text();
    const brandLower = brand.toLowerCase();

    // Extract app package IDs and titles from the Play Store HTML
    const escapedBrand = brandLower.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const appPattern = new RegExp(`\\["(com\\.[a-z0-9._]+)"[,\\]].*?"([^"]*?(?:${escapedBrand})[^"]*?)"`, "gi");
    const appMatches = html.matchAll(appPattern);

    const seen = new Set<string>();
    for (const match of appMatches) {
      const packageId = match[1];
      const appTitle = match[2];

      if (seen.has(packageId)) continue;
      seen.add(packageId);

      // Flag apps that mention the brand but whose package ID doesn't contain expected org name
      const brandSlug = brandLower.replace(/\s+/g, "");
      const isOfficialPackage = packageId.includes(brandSlug) ||
        packageId.split(".").some(part => part === brandSlug || part.startsWith(brandSlug));

      if (!isOfficialPackage) {
        out.push({
          type: "rogue_app",
          platform: "Google Play Store",
          url: `https://play.google.com/store/apps/details?id=${packageId}`,
          title: `Potential rogue Android app: ${appTitle || packageId}`,
          description: `Android app package '${packageId}' uses brand '${brand}' in its name but doesn't appear to be the official publisher package.`,
          evidenceSnippet: `Package ID: ${packageId}`,
          risk: "medium",
        });

        if (out.filter(r => r.platform === "Google Play Store").length >= 10) break;
      }
    }

    // Fallback: search for brand-impersonation keywords in the HTML
    if (out.filter(r => r.platform === "Google Play Store").length === 0) {
      const fraudPatterns = [
        `${brand} - Official`, `${brand} App`, `${brand} Mobile`,
        `Fake ${brand}`, `${brand} Clone`, `${brand} Premium`,
      ];
      for (const pattern of fraudPatterns) {
        if (html.toLowerCase().includes(pattern.toLowerCase())) {
          out.push({
            type: "rogue_app",
            platform: "Google Play Store",
            url: searchUrl,
            title: `Potential brand abuse: "${pattern}" on Play Store`,
            description: `Google Play Store search for '${brand}' returned results matching '${pattern}', which may indicate brand impersonation.`,
            evidenceSnippet: `Pattern '${pattern}' found in Play Store search results`,
            risk: "low",
          });
          break;
        }
      }
    }
  } catch (e: any) {
    logger.debug(`Play Store check failed for ${brand}: ${e.message}`);
  }
}

async function checkYouTubeAbuse(
  brand: string,
  out: BrandAbuseResult[],
  apiKey?: string,
): Promise<void> {
  if (!apiKey) return;
  try {
    const brandLower = brand.toLowerCase();

    // Step 1: Search for channels matching the brand name (channel-focused)
    const searchParams = new URLSearchParams({
      part: "snippet",
      q: brand,
      type: "channel",
      maxResults: "25",
      key: apiKey,
    });
    const searchRes = await fetch(
      `https://www.googleapis.com/youtube/v3/search?${searchParams.toString()}`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!searchRes.ok) {
      logger.warn({ status: searchRes.status }, "YouTube API non-OK response");
      return;
    }
    const searchData = await searchRes.json() as {
      items?: Array<{
        id: { kind: string; channelId?: string };
        snippet: { title?: string; description?: string; thumbnails?: { default?: { url?: string } } };
      }>;
      error?: { message: string };
    };
    if (searchData.error) {
      logger.warn({ error: searchData.error }, "YouTube API error");
      return;
    }

    // Collect channel IDs for suspect channels
    const suspectChannels: Array<{ channelId: string; title: string; description: string; thumbnailUrl: string | null }> = [];
    for (const item of searchData.items ?? []) {
      if (item.id.kind !== "youtube#channel" || !item.id.channelId) continue;
      const title = item.snippet.title ?? "";
      const titleLower = title.toLowerCase();
      const desc = (item.snippet.description ?? "").toLowerCase();
      // Flag channels whose title contains brand name but also contains impersonation signals
      if (!titleLower.includes(brandLower)) continue;
      const hasImpersonationSignal =
        titleLower.includes("official") ||
        titleLower.includes("real") ||
        titleLower.includes("scam") ||
        titleLower.includes("fake") ||
        desc.includes("official") ||
        (titleLower !== brandLower && titleLower.includes(brandLower));
      if (!hasImpersonationSignal) continue;
      suspectChannels.push({
        channelId: item.id.channelId,
        title,
        description: item.snippet.description ?? "",
        thumbnailUrl: item.snippet.thumbnails?.default?.url ?? null,
      });
    }
    if (suspectChannels.length === 0) return;

    // Step 2: Fetch subscriber counts for suspect channels (channels.list)
    const channelIds = suspectChannels.map(c => c.channelId).join(",");
    const statsParams = new URLSearchParams({
      part: "statistics,snippet",
      id: channelIds,
      key: apiKey,
    });
    const statsRes = await fetch(
      `https://www.googleapis.com/youtube/v3/channels?${statsParams.toString()}`,
      { signal: AbortSignal.timeout(10_000) },
    );
    const statsMap = new Map<string, { subscriberCount: string; viewCount: string }>();
    if (statsRes.ok) {
      const statsData = await statsRes.json() as {
        items?: Array<{ id: string; statistics: { subscriberCount?: string; viewCount?: string } }>;
      };
      for (const ch of statsData.items ?? []) {
        statsMap.set(ch.id, {
          subscriberCount: ch.statistics.subscriberCount ?? "0",
          viewCount: ch.statistics.viewCount ?? "0",
        });
      }
    }

    for (const ch of suspectChannels) {
      const stats = statsMap.get(ch.channelId);
      const subscriberCount = parseInt(stats?.subscriberCount ?? "0", 10);
      const titleLower = ch.title.toLowerCase();
      const descLower = ch.description.toLowerCase();
      const isScam = titleLower.includes("scam") || titleLower.includes("fake") || descLower.includes("scam");
      const claimsOfficial = titleLower.includes("official") || titleLower.includes("real") || descLower.includes("official");
      const risk = isScam || (claimsOfficial && subscriberCount < 10_000) ? "high" : "medium";
      out.push({
        type: "fake_social",
        platform: "YouTube",
        url: `https://www.youtube.com/channel/${ch.channelId}`,
        title: ch.title,
        description: `YouTube channel "${ch.title}" uses brand name "${brand}" and may be impersonating the official channel. Subscriber count: ${subscriberCount.toLocaleString()}${claimsOfficial ? " — claims to be official" : ""}`,
        evidenceSnippet: `Channel ID: ${ch.channelId}; subscribers: ${subscriberCount.toLocaleString()}; thumbnail: ${ch.thumbnailUrl ?? "none"}`,
        risk,
      });
    }
  } catch (err: any) {
    logger.warn({ err }, `YouTube abuse check failed for ${brand}`);
  }
}

async function checkRedditAbuse(
  brand: string,
  domain: string,
  out: BrandAbuseResult[],
): Promise<void> {
  const brandLower = brand.toLowerCase();
  const domainLower = domain.toLowerCase();
  // Subreddits with <1 000 subscribers that contain the brand name are squatting suspects.
  // Large well-established communities (>1 000 subs) whose name exactly equals the brand
  // are more likely the legitimate community, so we skip them.
  const SQUATTING_SUBSCRIBER_MAX = 1_000;

  // Step 1: Search for subreddits whose name contains the brand (community squatting)
  try {
    const srRes = await fetch(
      `https://www.reddit.com/subreddits/search.json?q=${encodeURIComponent(brand)}&type=sr&limit=25`,
      {
        headers: { "User-Agent": "SentinelwareBrandMonitor/1.0" },
        signal: AbortSignal.timeout(8_000),
      },
    );
    if (srRes.ok) {
      const srData = await srRes.json() as {
        data?: { children?: Array<{ data: {
          display_name: string;
          title: string;
          public_description: string;
          subscribers: number;
          url: string;
        } }> };
      };
      for (const child of srData.data?.children ?? []) {
        const sr = child.data;
        const nameLower = sr.display_name.toLowerCase();
        const titleLower = (sr.title ?? "").toLowerCase();
        const descLower = (sr.public_description ?? "").toLowerCase();
        // Only flag subreddits whose name contains the brand name
        if (!nameLower.includes(brandLower)) continue;
        // Skip established communities (exact brand name match + >1 000 subscribers)
        if (nameLower === brandLower && sr.subscribers > SQUATTING_SUBSCRIBER_MAX) continue;
        // Must have at least 1 subscriber to avoid ghost subreddits
        if (sr.subscribers < 1) continue;
        const claimsOfficial =
          nameLower.includes("official") ||
          nameLower.includes("real") ||
          titleLower.includes("official") ||
          descLower.includes("official") ||
          descLower.includes("this is the official");
        // Flag if: subscriber count is low (<1 000) OR explicitly claims to be official
        const isSquatting = sr.subscribers < SQUATTING_SUBSCRIBER_MAX || claimsOfficial;
        if (!isSquatting) continue;
        const risk = claimsOfficial ? "high" : "medium";
        out.push({
          type: "fake_social",
          platform: "Reddit",
          url: `https://www.reddit.com${sr.url}`,
          title: `r/${sr.display_name}`,
          description: `Subreddit r/${sr.display_name} uses brand name "${brand}" in its community name${claimsOfficial ? " and claims to be official" : ""} — possible brand-squatting community. ${sr.subscribers.toLocaleString()} subscribers.`,
          evidenceSnippet: `subscribers: ${sr.subscribers}; title: "${sr.title}"; official claim: ${claimsOfficial}`,
          risk,
        });
      }
    }
  } catch {
    // Reddit subreddit search is best-effort
  }

  // Step 2: Search for posts with brand-related abuse signals (scam, fake, phishing)
  const queries = [`${brand} scam`, `${brand} fake`, `${brand} fraud`];
  for (const q of queries) {
    try {
      const res = await fetch(
        `https://www.reddit.com/search.json?q=${encodeURIComponent(q)}&type=link,sr&sort=new&limit=10`,
        {
          headers: { "User-Agent": "SentinelwareBrandMonitor/1.0" },
          signal: AbortSignal.timeout(8_000),
        },
      );
      if (!res.ok) continue;
      const data = await res.json() as {
        data?: { children?: Array<{ kind: string; data: { title: string; url: string; selftext: string; subreddit: string; permalink: string; score: number } }> };
      };
      for (const child of data.data?.children ?? []) {
        if (child.kind !== "t3") continue; // only posts, not subreddits
        const p = child.data;
        const titleLower = p.title.toLowerCase();
        const textLower = p.selftext.toLowerCase();
        if (!titleLower.includes(brandLower) && !textLower.includes(brandLower)) continue;
        const isAbuse = titleLower.includes("scam") || titleLower.includes("fake") ||
          titleLower.includes("phish") || titleLower.includes("fraud") ||
          textLower.includes("scam") || textLower.includes("fraud") ||
          (p.url.includes(domainLower) && (titleLower.includes("fake") || titleLower.includes("fraud")));
        if (!isAbuse) continue;
        // Deduplicate by URL
        if (out.some(r => r.url === `https://www.reddit.com${p.permalink}`)) continue;
        out.push({
          type: "brand_abuse",
          platform: "Reddit",
          url: `https://www.reddit.com${p.permalink}`,
          title: p.title,
          description: `Reddit post in r/${p.subreddit} discussing "${brand}" with scam/fraud signals — may indicate active abuse campaign`,
          evidenceSnippet: p.selftext?.slice(0, 200) || null,
          risk: p.score > 50 ? "high" : "medium",
        });
      }
    } catch {
      // Reddit is best-effort
    }
  }
}
