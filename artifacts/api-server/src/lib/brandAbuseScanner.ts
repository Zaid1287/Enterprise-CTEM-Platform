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
    const params = new URLSearchParams({
      part: "snippet",
      q: `${brand} official scam fake`,
      type: "video,channel",
      maxResults: "20",
      key: apiKey,
    });
    const res = await fetch(
      `https://www.googleapis.com/youtube/v3/search?${params.toString()}`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) {
      logger.warn({ status: res.status }, "YouTube API non-OK response");
      return;
    }
    const data = await res.json() as {
      items?: Array<{
        id: { kind: string; videoId?: string; channelId?: string };
        snippet: {
          title?: string;
          description?: string;
          channelTitle?: string;
          publishedAt?: string;
        };
      }>;
      error?: { message: string };
    };
    if (data.error) {
      logger.warn({ error: data.error }, "YouTube API error");
      return;
    }
    const brandLower = brand.toLowerCase();
    for (const item of data.items ?? []) {
      const title = (item.snippet.title ?? "").toLowerCase();
      const desc = (item.snippet.description ?? "").toLowerCase();
      const channel = (item.snippet.channelTitle ?? "").toLowerCase();
      if (!title.includes(brandLower) && !channel.includes(brandLower)) continue;
      const isScam = title.includes("scam") || title.includes("fake") || title.includes("official") || desc.includes("scam");
      const isImpersonation = channel.includes(brandLower) && !channel.startsWith(brandLower);
      if (!isScam && !isImpersonation) continue;
      const isVideo = item.id.kind === "youtube#video";
      const url = isVideo
        ? `https://www.youtube.com/watch?v=${item.id.videoId}`
        : `https://www.youtube.com/channel/${item.id.channelId}`;
      out.push({
        type: isImpersonation ? "fake_social" : "brand_abuse",
        platform: "YouTube",
        url,
        title: item.snippet.title ?? null,
        description: `YouTube ${isVideo ? "video" : "channel"} with brand name "${brand}" in ${isImpersonation ? "channel title" : "content"} — possible impersonation or scam`,
        evidenceSnippet: item.snippet.description?.slice(0, 200) ?? null,
        risk: isScam ? "high" : "medium",
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
  const queries = [brand, `${brand} scam`, `${brand} fake`];
  for (const q of queries) {
    try {
      const res = await fetch(
        `https://www.reddit.com/search.json?q=${encodeURIComponent(q)}&type=link&sort=new&limit=15`,
        {
          headers: { "User-Agent": "SentinelwareBrandMonitor/1.0" },
          signal: AbortSignal.timeout(8_000),
        },
      );
      if (!res.ok) continue;
      const data = await res.json() as {
        data?: { children?: Array<{ data: { title: string; url: string; selftext: string; subreddit: string; permalink: string; score: number } }> };
      };
      const brandLower = brand.toLowerCase();
      const domainLower = domain.toLowerCase();
      for (const post of data.data?.children ?? []) {
        const p = post.data;
        const titleLower = p.title.toLowerCase();
        const textLower = p.selftext.toLowerCase();
        if (!titleLower.includes(brandLower) && !textLower.includes(brandLower)) continue;
        const isAbuse = titleLower.includes("scam") || titleLower.includes("fake") ||
          titleLower.includes("phish") || textLower.includes("scam") ||
          (p.url.includes(domainLower) && (titleLower.includes("fake") || titleLower.includes("fraud")));
        if (!isAbuse) continue;
        out.push({
          type: "brand_abuse",
          platform: "Reddit",
          url: `https://www.reddit.com${p.permalink}`,
          title: p.title,
          description: `Reddit post in r/${p.subreddit} discussing "${brand}" with abuse signals — may indicate active scam campaign`,
          evidenceSnippet: p.selftext?.slice(0, 200) || null,
          risk: p.score > 50 ? "high" : "medium",
        });
      }
    } catch {
      // Reddit is best-effort
    }
  }
}
