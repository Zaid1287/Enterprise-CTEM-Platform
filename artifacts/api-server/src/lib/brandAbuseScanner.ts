import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";
// @ts-ignore — google-play-scraper ships CJS; the types are bundled
import gplay from "google-play-scraper";
import { scanTwitterBrandAbuse } from "./twitterScanner";
import { scanInstagramBrandAbuse } from "./instagramScanner";
import { scanTikTokBrandAbuse } from "./tiktokScanner";

export interface BrandAbuseResult {
  type: string;
  platform: string | null;
  url: string | null;
  title: string | null;
  description: string | null;
  evidenceSnippet: string | null;
  installCount: string | null;
  iconUrl: string | null;
  risk: string;
}

/**
 * A structured warning recorded when a social media API returns a rate-limit
 * response (HTTP 429) or otherwise cannot complete the scan. These are stored
 * in the brand_threat_scans.scan_warnings jsonb column so the UI can surface
 * "Twitter/X rate limited — results may be incomplete" banners.
 */
export interface ScanWarning {
  platform: string;
  code: "rate_limited" | "api_error" | "no_credentials";
  message: string;
  timestamp: string;
}

export interface BrandAbuseScanOptions {
  youtubeApiKey?: string;
  twitterBearerToken?: string;
  instagramGraphToken?: string;
  tiktokResearchToken?: string;
}

export interface BrandAbuseScanResult {
  results: BrandAbuseResult[];
  warnings: ScanWarning[];
}

export async function scanBrandAbuse(
  brand: string,
  domain: string,
  socialHandles: string[] = [],
  youtubeApiKeyOrOptions?: string | BrandAbuseScanOptions,
): Promise<BrandAbuseScanResult> {
  const results: BrandAbuseResult[] = [];
  const warnings: ScanWarning[] = [];

  // Accept both legacy positional string arg and new options object
  const opts: BrandAbuseScanOptions =
    typeof youtubeApiKeyOrOptions === "string"
      ? { youtubeApiKey: youtubeApiKeyOrOptions }
      : (youtubeApiKeyOrOptions ?? {});

  const tasks: Promise<unknown>[] = [
    checkCertTransparencyAbuse(brand, domain, results),
    checkDNSTwistLookalikePatterns(brand, domain, results),
    checkAppleAppStore(brand, results),
    checkGooglePlayStore(brand, results),
    checkAPKPure(brand, results),
    checkAptoide(brand, results),
    checkSamsungGalaxyStore(brand, results),
    checkHuaweiAppGallery(brand, results),
    checkAmazonAppstore(brand, results),
    checkJailbreakRepos(brand, results),
    checkYouTubeAbuse(brand, results, opts.youtubeApiKey),
    checkRedditAbuse(brand, domain, results),
    ...socialHandles.map(handle => checkSocialHandle(handle, brand, results)),
  ];

  if (opts.twitterBearerToken) {
    tasks.push(
      scanTwitterBrandAbuse(brand, opts.twitterBearerToken, warnings)
        .then(r => results.push(...r))
        .catch(e => logger.debug({ brand, err: String(e) }, "Twitter scanner failed")),
    );
  }

  if (opts.instagramGraphToken) {
    tasks.push(
      scanInstagramBrandAbuse(brand, opts.instagramGraphToken, warnings)
        .then(r => results.push(...r))
        .catch(e => logger.debug({ brand, err: String(e) }, "Instagram scanner failed")),
    );
  }

  if (opts.tiktokResearchToken) {
    tasks.push(
      scanTikTokBrandAbuse(brand, opts.tiktokResearchToken, warnings)
        .then(r => results.push(...r))
        .catch(e => logger.debug({ brand, err: String(e) }, "TikTok scanner failed")),
    );
  }

  await Promise.allSettled(tasks);

  return { results, warnings };
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
      const res = await orchestratedFetch(p.url, {
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
        installCount: null,
        iconUrl: null,
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
    const res = await orchestratedFetch(
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
        installCount: null,
        iconUrl: null,
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
            installCount: null,
            iconUrl: null,
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
    const res = await orchestratedFetch(
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
          installCount: null,
          iconUrl: (app.artworkUrl60 ?? app.artworkUrl100 ?? null) as string | null,
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
    const brandLower = brand.toLowerCase();
    const brandSlug  = brandLower.replace(/\s+/g, "");

    const apps = await (gplay as any).search({
      term: brand,
      num: 30,
      lang: "en",
      country: "us",
    }) as any[];

    for (const app of apps) {
      const titleLower: string = (app.title ?? "").toLowerCase();
      const descLower: string  = (app.summary ?? app.description ?? "").toLowerCase();
      const devLower: string   = (app.developer ?? "").toLowerCase();
      const pkgId: string      = (app.appId ?? app.packageName ?? "");

      // Flag if brand appears in title OR description (required detection predicate)
      if (!titleLower.includes(brandLower) && !descLower.includes(brandLower)) continue;

      // Heuristic: skip if developer name contains brand (likely official)
      if (devLower.includes(brandLower) || devLower.includes(brandSlug)) continue;

      // Heuristic: skip if package org segment matches brand (e.g. com.brand.app)
      const pkgOrgSegment = pkgId.split(".")[1] ?? "";
      if (pkgOrgSegment === brandSlug || pkgId.includes(`.${brandSlug}.`) || pkgId.endsWith(`.${brandSlug}`)) continue;

      out.push({
        type: "rogue_app",
        platform: "Google Play Store",
        url: app.url ?? `https://play.google.com/store/apps/details?id=${pkgId}`,
        title: `Potential rogue Android app: ${app.title}`,
        description: `Android app '${app.title}' by '${app.developer}' uses brand name '${brand}' but developer doesn't appear to be the official publisher. ${app.ratings ? `${app.ratings.toLocaleString()} ratings.` : ""}`,
        evidenceSnippet: `Package: ${pkgId}, Developer: ${app.developer}, Score: ${app.score ?? "N/A"}`,
        installCount: app.installs ?? null,
        iconUrl: app.icon ?? null,
        risk: "medium",
      });

      if (out.filter(r => r.platform === "Google Play Store").length >= 10) break;
    }
  } catch (e: any) {
    logger.debug(`Play Store check failed for ${brand}: ${e.message}`);
  }
}

async function checkAPKPure(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();
    const brandSlug  = brandLower.replace(/\s+/g, "-");

    const res = await orchestratedFetch(
      `https://apkpure.com/search?q=${encodeURIComponent(brand)}`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
          "Accept-Language": "en-US,en;q=0.9",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (!res.ok) return;
    const html = await res.text();

    // Split into individual app cards — APKPure wraps each result in <li class="search-res ...">
    const cards = html.match(/<li[^>]*class="[^"]*search-res[^"]*"[\s\S]*?<\/li>/gi) ?? [];

    // Per-card extraction patterns
    const namePattern    = /<p[^>]*class="[^"]*search-title[^"]*"[^>]*>\s*([^<]+?)\s*<\/p>/i;
    const developerPattern = /<p[^>]*class="[^"]*developer[^"]*"[^>]*>\s*([^<]+?)\s*<\/p>/i;
    const urlPattern     = /href="(\/[a-zA-Z0-9._%-]+(?:\/[a-zA-Z0-9._%-]+)+)"/i;
    const iconPattern    = /<img[^>]+src="(https:\/\/(?:image\.winudf|cdn[^"]+apkpure)[^"]+)"[^>]*>/i;
    // Per-card download count: "1,000,000 downloads", "1M+ Downloads", "500K+"
    const installPattern = /([\d,.]+(?:\.\d+)?[KMB]?\+?)\s*(?:downloads?|installs?)/i;
    // Version pattern: "Version: 1.2.3" or "v1.2.3"
    const versionPattern = /(?:version:|v)\s*([\d.]+(?:[-_]\w+)?)/i;

    for (const card of cards.slice(0, 25)) {
      const nameMatch = card.match(namePattern);
      const appName = (nameMatch?.[1] ?? "").trim();
      if (!appName.toLowerCase().includes(brandLower)) continue;

      const devMatch = card.match(developerPattern);
      const devName  = (devMatch?.[1] ?? "").replace(/^by\s+/i, "").trim().toLowerCase();
      if (devName && devName.includes(brandLower)) continue;

      const urlMatch     = card.match(urlPattern);
      const iconMatch    = card.match(iconPattern);
      // Extract install count and version FROM THIS CARD specifically
      const installMatch = card.match(installPattern);
      const versionMatch = card.match(versionPattern);
      const appUrl = urlMatch ? `https://apkpure.com${urlMatch[1]}` : `https://apkpure.com/search?q=${encodeURIComponent(brand)}`;

      out.push({
        type: "rogue_app",
        platform: "APKPure",
        url: appUrl,
        title: `Potential rogue APK: ${appName}`,
        description: `App '${appName}' by '${devName || "unknown developer"}' found on APKPure (unofficial APK distribution) using brand name '${brand}'. Third-party APK stores carry higher risk of repackaged malware.`,
        evidenceSnippet: [
          `Developer: ${devName || "unknown"}`,
          versionMatch ? `Version: ${versionMatch[1]}` : null,
          `Source: APKPure (third-party store)`,
        ].filter(Boolean).join("; "),
        installCount: installMatch ? installMatch[1]! : null,
        iconUrl: iconMatch?.[1] ?? null,
        risk: "high",
      });

      if (out.filter(r => r.platform === "APKPure").length >= 5) break;
    }

    // Fallback: brand-slug URL probe when search returned no cards
    if (out.filter(r => r.platform === "APKPure").length === 0) {
      const probeRes = await orchestratedFetch(
        `https://apkpure.com/${brandSlug}`,
        { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(6_000) },
      ).catch(() => null);
      if (probeRes?.ok) {
        const probeHtml = await probeRes.text().catch(() => "");
        const titleMatch = probeHtml.match(/<title[^>]*>([^<]+)<\/title>/i);
        const pageTitle  = (titleMatch?.[1] ?? "").toLowerCase();
        if (pageTitle.includes(brandLower) || probeHtml.toLowerCase().includes(`"${brandLower}"`)) {
          const probeIconMatch = probeHtml.match(/<img[^>]+src="(https:\/\/(?:image\.winudf|cdn[^"]+apkpure)[^"]+)"[^>]*>/i);
          const probeInstallMatch = probeHtml.match(installPattern);
          out.push({
            type: "rogue_app",
            platform: "APKPure",
            url: `https://apkpure.com/${brandSlug}`,
            title: `Brand-name APK page on APKPure: ${brand}`,
            description: `A page for '${brand}' exists on APKPure, a third-party Android APK distribution site. Verify this is the official publisher before trusting downloads.`,
            evidenceSnippet: `URL: https://apkpure.com/${brandSlug}; Page title: ${pageTitle || "(none)"}`,
            installCount: probeInstallMatch ? probeInstallMatch[1]! : null,
            iconUrl: probeIconMatch?.[1] ?? null,
            risk: "medium",
          });
        }
      }
    }
  } catch (e: any) {
    logger.debug(`APKPure check failed for ${brand}: ${e.message}`);
  }
}

async function checkAptoide(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();

    // Aptoide public REST API v7 — path-style parameters on ws2 host
    // Correct format: /api/7/apps/search/query/{TERM}/limit/{N}[/sort/{field}]
    const searchUrl = `https://ws2.aptoide.com/api/7/apps/search/query/${encodeURIComponent(brand)}/limit/25`;
    const res = await orchestratedFetch(searchUrl, {
      headers: {
        "User-Agent": "Aptoide/9.20.6.1 (Linux; Android 12)",
        "Accept": "application/json",
      },
      signal: AbortSignal.timeout(12_000),
    });
    if (!res.ok) return;
    const data = await res.json() as any;

    // API v7 returns { datalist: { list: [...] } }
    const apps: any[] = data?.datalist?.list ?? data?.list ?? [];

    const brandSlugAptoide = brandLower.replace(/\s+/g, "");

    for (const app of apps) {
      const appName: string = (app.name ?? app.package ?? "").toLowerCase();
      const pkgId: string = app.package ?? "";

      if (!appName.includes(brandLower)) continue;

      // Required predicate: exclude when package ID contains brand slug (likely official app)
      const pkgLower = pkgId.toLowerCase();
      if (pkgLower.includes(brandSlugAptoide) || pkgLower.includes(brandLower.replace(/\s+/g, "."))) continue;

      const downloads: number | undefined = app.stats?.downloads ?? app.stats?.pdownloads;
      const rating: number | undefined = app.stats?.rating?.avg;
      const appUrl = app.urls?.w ?? (pkgId ? `https://aptoide.com/app/${pkgId}` : `https://aptoide.com/apps/search?q=${encodeURIComponent(brand)}`);

      out.push({
        type: "rogue_app",
        platform: "Aptoide",
        url: appUrl,
        title: `Potential rogue Aptoide app: ${app.name ?? pkgId}`,
        description: `App '${app.name ?? pkgId}' by '${app.developer?.name ?? "unknown"}' found on Aptoide (community APK store) using brand name '${brand}'. Aptoide apps bypass Google Play review and may be repackaged.`,
        evidenceSnippet: [
          `Package: ${pkgId}`,
          downloads != null ? `Downloads: ${downloads.toLocaleString()}` : null,
          rating != null ? `Rating: ${rating.toFixed(1)}` : null,
        ].filter(Boolean).join(", "),
        installCount: downloads != null ? downloads.toLocaleString() : null,
        iconUrl: app.icon ?? app.graphic?.url ?? null,
        risk: "high",
      });

      if (out.filter(r => r.platform === "Aptoide").length >= 5) break;
    }
  } catch (e: any) {
    logger.debug(`Aptoide check failed for ${brand}: ${e.message}`);
  }
}

async function checkSamsungGalaxyStore(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();

    // Samsung Galaxy Store — keyword search endpoint used by the web portal
    const res = await orchestratedFetch(
      `https://galaxystore.samsung.com/api/detail/getSearchKeywordContent?searchTxt=${encodeURIComponent(brand)}&contentType=app&cpStatus=0&startIndex=0&endIndex=20&language=EN&country=US`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",
          "Accept": "application/json, text/plain, */*",
          "Referer": "https://galaxystore.samsung.com/",
        },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (!res.ok) return;

    const data = await res.json() as any;
    // Galaxy Store search response uses contentList as the primary key
    const apps: any[] = data?.contentList ?? data?.list ?? data?.content ?? data?.contents ?? (Array.isArray(data) ? data : []);

    for (const app of apps.slice(0, 20)) {
      // Field names vary across store API versions
      const appName: string = (
        app.appTitle ?? app.contentName ?? app.name ?? ""
      ).toLowerCase();
      const seller: string = (
        app.sellerName ?? app.developerName ?? app.publisherName ?? app.developer ?? ""
      ).toLowerCase();

      if (!appName.includes(brandLower)) continue;
      if (seller.includes(brandLower)) continue;

      const contentId = app.contentId ?? app.id ?? app.packageName ?? "";
      const iconUrl   = app.iconImgUrl ?? app.iconUrl ?? app.imageUrl ?? null;
      const dlCount   = app.downloadCount ?? app.installCount;

      out.push({
        type: "rogue_app",
        platform: "Samsung Galaxy Store",
        url: contentId
          ? `https://galaxystore.samsung.com/detail/${contentId}`
          : `https://galaxystore.samsung.com/search/apps?searchTxt=${encodeURIComponent(brand)}`,
        title: `Potential rogue Samsung Galaxy Store app: ${app.appTitle ?? app.contentName ?? contentId}`,
        description: `App '${app.appTitle ?? app.contentName}' by '${app.sellerName ?? app.developerName ?? "unknown"}' found on Samsung Galaxy Store using brand name '${brand}'. Galaxy Store is pre-installed on all Samsung devices.`,
        evidenceSnippet: [
          contentId ? `Content ID: ${contentId}` : null,
          `Seller: ${app.sellerName ?? app.developerName ?? "unknown"}`,
          app.averageRating != null ? `Rating: ${app.averageRating}` : null,
        ].filter(Boolean).join(", "),
        installCount: dlCount != null ? Number(dlCount).toLocaleString() : null,
        iconUrl,
        risk: "medium",
      });

      if (out.filter(r => r.platform === "Samsung Galaxy Store").length >= 5) break;
    }
  } catch (e: any) {
    logger.debug(`Samsung Galaxy Store check failed for ${brand}: ${e.message}`);
  }
}

async function checkHuaweiAppGallery(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();

    // Huawei AppGallery — apigw search endpoint used by the web portal
    // Response shape: { layoutData: [{ dataList: [...] }] } or fallback shapes
    const hwRes = await orchestratedFetch(
      `https://appgallery.cloud.huawei.com/apigw/search/keyword?keyword=${encodeURIComponent(brand)}&pageIndex=0&pageSize=20`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12; HarmonyOS) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
          "Accept": "application/json, text/plain, */*",
          "Origin": "https://appgallery.cloud.huawei.com",
          "Referer": "https://appgallery.cloud.huawei.com/",
        },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (!hwRes.ok) return;

    const rawText = await hwRes.text();
    let apps: any[] = [];

    // Parse response as JSON if possible
    const contentType = hwRes.headers.get("content-type") ?? "";
    if (contentType.includes("application/json") || rawText.trimStart().startsWith("{") || rawText.trimStart().startsWith("[")) {
      try {
        const data = JSON.parse(rawText) as any;
        // Primary shape: { layoutData: [{ dataList: [...] }] }
        // Fallback shapes: { data: { apps: [...] } } | { apps: [...] } | { list: [...] }
        apps = data?.layoutData?.[0]?.dataList ?? data?.data?.apps ?? data?.apps ?? data?.list ?? (Array.isArray(data) ? data : []);
      } catch {
        apps = [];
      }
    }

    for (const app of apps.slice(0, 20)) {
      const appName: string = (app.appName ?? app.name ?? "").toLowerCase();
      const devName: string = (
        app.developer ?? app.developerName ?? app.sellerName ?? ""
      ).toLowerCase();

      if (!appName.includes(brandLower)) continue;
      if (devName.includes(brandLower)) continue;

      const appId   = app.appid ?? app.id ?? app.packageName ?? "";
      const iconUrl = app.iconUri ?? app.icon ?? app.iconUrl ?? null;
      const dlCount = app.downloadCount ?? app.downloads;

      out.push({
        type: "rogue_app",
        platform: "Huawei AppGallery",
        url: appId
          ? `https://appgallery.huawei.com/app/${appId}`
          : `https://appgallery.huawei.com/#/search/${encodeURIComponent(brand)}`,
        title: `Potential rogue Huawei AppGallery app: ${app.appName ?? app.name}`,
        description: `App '${app.appName ?? app.name}' by '${app.developer ?? "unknown"}' found on Huawei AppGallery using brand name '${brand}'. AppGallery is the default and only store on Huawei/Honor devices (no Google Play).`,
        evidenceSnippet: [
          appId ? `App ID: ${appId}` : null,
          `Developer: ${app.developer ?? "unknown"}`,
          dlCount != null ? `Downloads: ${dlCount}` : null,
        ].filter(Boolean).join(", "),
        installCount: dlCount != null ? String(dlCount) : null,
        iconUrl,
        risk: "medium",
      });

      if (out.filter(r => r.platform === "Huawei AppGallery").length >= 5) break;
    }
  } catch (e: any) {
    logger.debug(`Huawei AppGallery check failed for ${brand}: ${e.message}`);
  }
}

async function checkAmazonAppstore(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();

    const res = await orchestratedFetch(
      `https://www.amazon.com/s?k=${encodeURIComponent(brand)}&i=mobile-apps`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12; Fire HD 10) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
          "Accept-Language": "en-US,en;q=0.9",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const html = await res.text();

    // Extract app results from Amazon search HTML
    const appPattern = /data-asin="([A-Z0-9]{10})"[^>]*>[\s\S]*?<span[^>]*class="[^"]*a-text-normal[^"]*"[^>]*>([\s\S]*?)<\/span>/gi;
    const developerPattern = /<span[^>]*class="[^"]*a-size-base[^"]*"[^>]*>by ([^<]+)<\/span>/gi;

    const asinTitles: Array<{ asin: string; title: string }> = [];
    let m: RegExpExecArray | null;
    while ((m = appPattern.exec(html)) !== null && asinTitles.length < 20) {
      asinTitles.push({ asin: m[1] ?? "", title: (m[2] ?? "").replace(/<[^>]+>/g, "").trim() });
    }

    for (const { asin, title } of asinTitles) {
      if (!title.toLowerCase().includes(brandLower)) continue;

      // Try to find developer for this ASIN
      let devName = "";
      const devCtx = html.slice(html.indexOf(asin), html.indexOf(asin) + 2000);
      const devM = /by ([A-Z][^<\n]{1,60})/.exec(devCtx);
      devName = (devM?.[1] ?? "").trim().toLowerCase();

      if (devName.includes(brandLower)) continue;

      out.push({
        type: "rogue_app",
        platform: "Amazon Appstore",
        url: `https://www.amazon.com/dp/${asin}`,
        title: `Potential rogue Fire/Android app: ${title}`,
        description: `App '${title}' found on Amazon Appstore${devName ? ` by '${devName}'` : ""} using brand name '${brand}'. Amazon Appstore is pre-installed on Fire tablets and sideloaded on Android.`,
        evidenceSnippet: `ASIN: ${asin}${devName ? `, Developer: ${devName}` : ""}`,
        installCount: null,
        iconUrl: null,
        risk: "medium",
      });

      if (out.filter(r => r.platform === "Amazon Appstore").length >= 5) break;
    }
  } catch (e: any) {
    logger.debug(`Amazon Appstore check failed for ${brand}: ${e.message}`);
  }
}

/**
 * Parse a Debian APT control-file block (key: value pairs) into a plain object.
 * Fields are separated from each other by a blank line.
 */
function parseAptBlock(block: string): Record<string, string> {
  const obj: Record<string, string> = {};
  let currentKey = "";
  for (const line of block.split("\n")) {
    if (/^\s/.test(line)) {
      // Continuation line
      if (currentKey) obj[currentKey] += "\n" + line.trim();
    } else {
      const colon = line.indexOf(":");
      if (colon > 0) {
        currentKey = line.slice(0, colon).trim().toLowerCase();
        obj[currentKey] = line.slice(colon + 1).trim();
      }
    }
  }
  return obj;
}

async function checkJailbreakRepos(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  const brandLower = brand.toLowerCase();

  // ── 1. BigBoss (largest Cydia repo) ──────────────────────────────────────
  // BigBoss publishes a plain-text APT Packages index we can download and grep.
  // We limit the body read to 2 MB to stay within budget.
  try {
    const bbRes = await orchestratedFetch(
      "http://apt.thebigboss.org/repofiles/cydia/dists/stable/main/binary-iphoneos-arm/Packages",
      {
        headers: {
          "User-Agent": "Cydia/1.1.32 CFNetwork/1325.0.1 Darwin/21.1.0",
          "Accept-Encoding": "identity", // request plain text, not compressed
        },
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (bbRes.ok) {
      // Read up to 2 MB then drop the rest
      const reader = bbRes.body?.getReader();
      let raw = "";
      let bytes = 0;
      const MAX_BYTES = 2 * 1024 * 1024;
      if (reader) {
        const decoder = new TextDecoder();
        while (bytes < MAX_BYTES) {
          const { done, value } = await reader.read();
          if (done) break;
          raw += decoder.decode(value, { stream: true });
          bytes += value?.length ?? 0;
        }
        reader.cancel().catch(() => undefined);
      }
      // Split on double newline — each block is one package
      const blocks = raw.split(/\n\n+/);
      let bbCount = 0;
      for (const block of blocks) {
        if (bbCount >= 5) break;
        const pkg = parseAptBlock(block);
        const pkgName   = (pkg["name"] ?? pkg["package"] ?? "").toLowerCase();
        const pkgId     = pkg["package"] ?? "";
        const author    = (pkg["author"] ?? pkg["maintainer"] ?? "").toLowerCase();
        const desc      = (pkg["description"] ?? "").toLowerCase();

        // Match brand name in package name or description
        if (!pkgName.includes(brandLower) && !desc.includes(brandLower)) continue;
        if (pkgName.includes(brandLower) && author.includes(brandLower)) continue;

        out.push({
          type: "rogue_app",
          platform: "Cydia/Sileo (BigBoss)",
          url: pkg["depiction"] ?? `https://apt.thebigboss.org/onepackage.php?bundleid=${encodeURIComponent(pkgId)}`,
          title: `Jailbreak package using brand name: ${pkg["name"] ?? pkgId}`,
          description: `Package '${pkg["name"] ?? pkgId}' found in the BigBoss Cydia repository using brand name '${brand}'. BigBoss is the largest Cydia/Sileo repo, with hundreds of thousands of installs. Unsigned packages can modify app behaviour or steal credentials.`,
          evidenceSnippet: `Package ID: ${pkgId}, Author: ${pkg["author"] ?? pkg["maintainer"] ?? "unknown"}, Version: ${pkg["version"] ?? "unknown"}, Section: ${pkg["section"] ?? "unknown"}`,
          installCount: null,
          iconUrl: null,
          risk: "high",
        });
        bbCount++;
      }
    }
  } catch (e: any) {
    logger.debug(`BigBoss jailbreak check failed for ${brand}: ${e.message}`);
  }

  // ── 2. Chariz (modern premium Cydia/Sileo repo) ───────────────────────────
  // Chariz exposes a packages.json listing all packages; we filter by brand name.
  // Their search API endpoint is also available at /api/search.
  try {
    // Try the native search API first (faster), fall back to full packages.json
    let charizPkgs: any[] = [];
    const searchRes = await orchestratedFetch(
      `https://repo.chariz.com/api/search?q=${encodeURIComponent(brand)}`,
      {
        headers: { "User-Agent": "Sileo/2.4 Darwin/21.0.0" },
        signal: AbortSignal.timeout(8_000),
      },
    ).catch(() => null);

    if (searchRes?.ok) {
      const searchData: any = await searchRes.json().catch(() => null);
      // Response: { packages: [...] } or top-level array
      charizPkgs = searchData?.packages ?? (Array.isArray(searchData) ? searchData : []);
    }

    // Fallback: full packages.json (filter client-side)
    if (charizPkgs.length === 0) {
      const listRes = await orchestratedFetch("https://repo.chariz.com/packages.json", {
        headers: { "User-Agent": "Sileo/2.4 Darwin/21.0.0" },
        signal: AbortSignal.timeout(10_000),
      }).catch(() => null);
      if (listRes?.ok) {
        const listData = await listRes.json().catch(() => []);
        charizPkgs = Array.isArray(listData)
          ? listData.filter((p: any) =>
              (p.name ?? p.id ?? "").toLowerCase().includes(brandLower),
            )
          : [];
      }
    }

    let charizCount = 0;
    for (const pkg of charizPkgs.slice(0, 200)) {
      if (charizCount >= 3) break;
      const pkgName: string = (pkg.name ?? pkg.id ?? "").toLowerCase();
      const pkgId: string   = pkg.id ?? "";
      const author: string  = (pkg.author?.name ?? pkg.maintainer ?? "").toLowerCase();

      if (!pkgName.includes(brandLower)) continue;
      if (author.includes(brandLower)) continue;

      out.push({
        type: "rogue_app",
        platform: "Cydia/Sileo (Chariz)",
        url: pkg.depiction ?? `https://repo.chariz.com/package/${pkgId}`,
        title: `Jailbreak tweak using brand name: ${pkg.name ?? pkgId}`,
        description: `Package '${pkg.name ?? pkgId}' found in the Chariz jailbreak repository using brand name '${brand}'. Chariz is a curated premium Cydia/Sileo repo. Unsigned packages can modify or impersonate apps.`,
        evidenceSnippet: `Package ID: ${pkgId}, Author: ${pkg.author?.name ?? "unknown"}, Version: ${pkg.latestVersion ?? "unknown"}`,
        installCount: null,
        iconUrl: pkg.headerURL ?? pkg.icon ?? null,
        risk: "high",
      });
      charizCount++;
    }
  } catch (e: any) {
    logger.debug(`Chariz jailbreak check failed for ${brand}: ${e.message}`);
  }

  // ── 3. Sileo — Canister.me search API ────────────────────────────────────
  // Canister.me is the official Sileo community package search service,
  // indexing the repos that Sileo itself queries. Response:
  //   { status: "Successful", data: [{ package, name, author, latestVersion, repository, ... }] }
  try {
    const canisterRes = await orchestratedFetch(
      `https://api.canister.me/v1/community/packages/search?q=${encodeURIComponent(brand)}&count=25`,
      {
        headers: {
          "User-Agent": "Sileo/2.4 Darwin/21.0.0",
          "Accept": "application/json",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (canisterRes.ok) {
      const canisterData = await canisterRes.json() as any;
      // Response: { status: "Successful", data: [...] }
      const packages: any[] = canisterData?.data ?? (Array.isArray(canisterData) ? canisterData : []);

      let sileoCount = 0;
      for (const pkg of packages.slice(0, 50)) {
        if (sileoCount >= 3) break;
        const pkgName: string  = (pkg.name ?? pkg.package ?? "").toLowerCase();
        const pkgId: string    = pkg.package ?? pkg.id ?? "";
        const author: string   = (pkg.author ?? pkg.maintainer ?? "").toLowerCase();
        const repoName: string = pkg.repository?.name ?? pkg.repositorySlug ?? "Sileo repo";

        if (!pkgName.includes(brandLower)) continue;
        if (author.includes(brandLower)) continue;

        out.push({
          type: "rogue_app",
          platform: "Cydia/Sileo",
          url: pkg.depiction ?? `https://canister.me/package/${encodeURIComponent(pkgId)}`,
          title: `Jailbreak package using brand name: ${pkg.name ?? pkgId}`,
          description: `Package '${pkg.name ?? pkgId}' found in the '${repoName}' Sileo repository via Canister.me search using brand name '${brand}'. Jailbreak packages are not code-signed and can modify or impersonate official apps.`,
          evidenceSnippet: `Package ID: ${pkgId}, Repo: ${repoName}, Author: ${pkg.author ?? "unknown"}, Version: ${pkg.latestVersion ?? "unknown"}`,
          installCount: null,
          iconUrl: pkg.icon ?? null,
          risk: "high",
        });
        sileoCount++;
      }
    }
  } catch (e: any) {
    logger.debug(`Sileo (Canister) check failed for ${brand}: ${e.message}`);
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
    const searchRes = await orchestratedFetch(
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
    const statsRes = await orchestratedFetch(
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
        installCount: null,
        iconUrl: ch.thumbnailUrl ?? null,
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
    const srRes = await orchestratedFetch(
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
          installCount: null,
          iconUrl: null,
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
      const res = await orchestratedFetch(
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
          installCount: null,
          iconUrl: null,
          risk: p.score > 50 ? "high" : "medium",
        });
      }
    } catch {
      // Reddit is best-effort
    }
  }
}
