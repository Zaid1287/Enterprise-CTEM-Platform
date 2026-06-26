import { logger } from "./logger";
// @ts-ignore — google-play-scraper ships CJS; the types are bundled
import gplay from "google-play-scraper";

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
    checkAPKPure(brand, results),
    checkAptoide(brand, results),
    checkSamsungGalaxyStore(brand, results),
    checkHuaweiAppGallery(brand, results),
    checkAmazonAppstore(brand, results),
    checkJailbreakRepos(brand, results),
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
      const devLower: string   = (app.developer ?? "").toLowerCase();
      const pkgId: string      = (app.appId ?? app.packageName ?? "");

      if (!titleLower.includes(brandLower)) continue;

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

    const res = await fetch(
      `https://apkpure.com/search?q=${encodeURIComponent(brand)}`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
          "Accept-Language": "en-US,en;q=0.9",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const html = await res.text();

    // Extract app cards from APKPure HTML
    const appCardPattern = /<div[^>]*class="[^"]*search-dl[^"]*"[^>]*>[\s\S]*?<\/div>/gi;
    const namePattern = /<p[^>]*class="[^"]*search-title[^"]*"[^>]*>([^<]+)<\/p>/i;
    const developerPattern = /<p[^>]*class="[^"]*developer[^"]*"[^>]*>([^<]+)<\/p>/i;
    const urlPattern = /href="(\/[a-z0-9._-]+\/[a-z0-9._-]+)"/i;
    const iconPattern = /<img[^>]*src="(https:\/\/image\.winudf[^"]+)"[^>]*>/i;
    const installPattern = /(\d[\d,.]+[KMB]?\+?\s*(?:downloads|installs))/i;

    const cards = html.match(/<li[^>]*class="[^"]*search-res[^"]*"[\s\S]*?<\/li>/gi) ?? [];

    for (const card of cards.slice(0, 20)) {
      const nameMatch = card.match(namePattern);
      const appName = (nameMatch?.[1] ?? "").trim();
      if (!appName.toLowerCase().includes(brandLower)) continue;

      const devMatch = card.match(developerPattern);
      const devName  = (devMatch?.[1] ?? "").trim().toLowerCase();
      if (devName.includes(brandLower)) continue;

      const urlMatch  = card.match(urlPattern);
      const iconMatch = card.match(iconPattern);
      const installMatch = html.match(installPattern);

      out.push({
        type: "rogue_app",
        platform: "APKPure",
        url: urlMatch ? `https://apkpure.com${urlMatch[1]}` : `https://apkpure.com/search?q=${encodeURIComponent(brand)}`,
        title: `Potential rogue APK: ${appName}`,
        description: `App '${appName}' by '${devName || "unknown developer"}' found on APKPure (unofficial APK distribution) using brand name '${brand}'. Third-party APK stores carry higher risk of repackaging.`,
        evidenceSnippet: `Developer: ${devName || "unknown"}; source: APKPure (third-party store)`,
        installCount: installMatch?.[1] ?? null,
        iconUrl: iconMatch?.[1] ?? null,
        risk: "high",
      });

      if (out.filter(r => r.platform === "APKPure").length >= 5) break;
    }

    // Fallback: simple brand-slug URL probe
    if (out.filter(r => r.platform === "APKPure").length === 0) {
      const probeRes = await fetch(
        `https://apkpure.com/${brandSlug}`,
        { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(6_000) },
      ).catch(() => null);
      if (probeRes?.ok && probeRes.status === 200) {
        const probeHtml = await probeRes.text().catch(() => "");
        if (probeHtml.toLowerCase().includes(brandLower)) {
          out.push({
            type: "rogue_app",
            platform: "APKPure",
            url: `https://apkpure.com/${brandSlug}`,
            title: `Brand-name APK page on APKPure: ${brand}`,
            description: `A page for '${brand}' exists on APKPure, a third-party Android APK distribution site. Verify this is the official publisher before trusting downloads.`,
            evidenceSnippet: `URL probe: https://apkpure.com/${brandSlug} returned 200 OK`,
            installCount: null,
            iconUrl: null,
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

    const res = await fetch(
      `https://ws75.aptoide.com/api/7/apps/search/query=${encodeURIComponent(brand)}/limit=20/sort=downloads`,
      {
        headers: { "User-Agent": "Aptoide/9.0 (Android)" },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    const apps: any[] = data?.datalist?.list ?? [];

    for (const app of apps) {
      const appName: string  = (app.name ?? app.package ?? "").toLowerCase();
      const devName: string  = (app.developer?.name ?? app.store?.name ?? "").toLowerCase();
      const pkgId: string    = app.package ?? "";

      if (!appName.includes(brandLower)) continue;
      if (devName.includes(brandLower)) continue;

      out.push({
        type: "rogue_app",
        platform: "Aptoide",
        url: app.urls?.w ?? `https://aptoide.com/app/${pkgId}`,
        title: `Potential rogue Aptoide app: ${app.name ?? pkgId}`,
        description: `App '${app.name}' by '${app.developer?.name ?? "unknown"}' found on Aptoide (community APK store) using brand name '${brand}'. Aptoide apps bypass Google Play review.`,
        evidenceSnippet: `Package: ${pkgId}, Downloads: ${app.stats?.downloads ?? "unknown"}, Rating: ${app.stats?.rating?.avg ?? "N/A"}`,
        installCount: app.stats?.downloads ? `${app.stats.downloads.toLocaleString()}` : null,
        iconUrl: app.icon ?? app.graphic ?? null,
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

    // Samsung Galaxy Store public search API (unofficial)
    const res = await fetch(
      `https://galaxystore.samsung.com/api/search?searchTxt=${encodeURIComponent(brand)}&contentType=app`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36",
          "Accept": "application/json",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    const apps: any[] = data?.contents ?? data?.list ?? data?.data ?? [];

    for (const app of apps.slice(0, 20)) {
      const appName: string  = (app.appTitle ?? app.name ?? app.contentName ?? "").toLowerCase();
      const seller: string   = (app.sellerName ?? app.developerName ?? app.developer ?? "").toLowerCase();

      if (!appName.includes(brandLower)) continue;
      if (seller.includes(brandLower)) continue;

      const appId   = app.contentId ?? app.id ?? "";
      const iconUrl = app.iconUrl ?? app.imageUrl ?? app.thumbnail ?? null;

      out.push({
        type: "rogue_app",
        platform: "Samsung Galaxy Store",
        url: appId ? `https://galaxystore.samsung.com/detail/${appId}` : `https://galaxystore.samsung.com/search?searchTxt=${encodeURIComponent(brand)}`,
        title: `Potential rogue Samsung app: ${app.appTitle ?? app.name}`,
        description: `App '${app.appTitle ?? app.name}' by '${app.sellerName ?? app.developerName ?? "unknown"}' found on Samsung Galaxy Store using brand name '${brand}'.`,
        evidenceSnippet: `Content ID: ${appId}, Seller: ${app.sellerName ?? "unknown"}`,
        installCount: app.downloadCount ? `${Number(app.downloadCount).toLocaleString()}` : null,
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

    const res = await fetch(
      `https://appgallery.huawei.com/bo/search/freeKeywordSearch?keyword=${encodeURIComponent(brand)}&pageIndex=0&pageSize=20`,
      {
        headers: {
          "User-Agent": "Mozilla/5.0 (Linux; Android 12; HarmonyOS) AppleWebKit/537.36",
          "Accept": "application/json",
          "Origin": "https://appgallery.huawei.com",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    const apps: any[] = data?.data?.apps ?? data?.apps ?? data?.list ?? [];

    for (const app of apps.slice(0, 20)) {
      const appName: string  = (app.appName ?? app.name ?? "").toLowerCase();
      const devName: string  = (app.developer ?? app.developerName ?? app.sellerName ?? "").toLowerCase();

      if (!appName.includes(brandLower)) continue;
      if (devName.includes(brandLower)) continue;

      const appId   = app.appid ?? app.id ?? app.packageName ?? "";
      const iconUrl = app.iconUri ?? app.icon ?? app.iconUrl ?? null;

      out.push({
        type: "rogue_app",
        platform: "Huawei AppGallery",
        url: appId ? `https://appgallery.huawei.com/app/${appId}` : `https://appgallery.huawei.com/#/search/${encodeURIComponent(brand)}`,
        title: `Potential rogue Huawei app: ${app.appName ?? app.name}`,
        description: `App '${app.appName ?? app.name}' by '${app.developer ?? "unknown"}' found on Huawei AppGallery using brand name '${brand}'. AppGallery is the default store on Huawei/Honor devices.`,
        evidenceSnippet: `App ID: ${appId}, Developer: ${app.developer ?? "unknown"}, Downloads: ${app.downloadCount ?? "unknown"}`,
        installCount: app.downloadCount ? `${app.downloadCount}` : null,
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

    const res = await fetch(
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

async function checkJailbreakRepos(
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  try {
    const brandLower = brand.toLowerCase();

    // Well-known Cydia/Sileo-compatible repositories with searchable package indexes
    const repos = [
      { name: "Chariz",       url: `https://repo.chariz.com/packages.json` },
      { name: "BigBoss",      url: `http://apt.thebigboss.org/repofiles/cydia/dists/stable/main/binary-iphoneos-arm/Packages.bz2` },
      { name: "Havoc",        url: `https://havoc.app/depiction.php?&package=${encodeURIComponent(brand)}` },
    ];

    // Chariz has a JSON API
    try {
      const res = await fetch(repos[0]!.url, {
        headers: { "User-Agent": "Sileo/2.4 Darwin/21.0.0" },
        signal: AbortSignal.timeout(8_000),
      });
      if (res.ok) {
        const data = await res.json() as any[];
        for (const pkg of (Array.isArray(data) ? data : []).slice(0, 200)) {
          const pkgName: string = (pkg.name ?? pkg.id ?? "").toLowerCase();
          const pkgId: string   = pkg.id ?? "";
          const devName: string = (pkg.author?.name ?? pkg.maintainer ?? "").toLowerCase();
          if (!pkgName.includes(brandLower)) continue;
          if (devName.includes(brandLower)) continue;
          out.push({
            type: "rogue_app",
            platform: "Cydia/Sileo (Chariz)",
            url: pkg.depiction ?? `https://repo.chariz.com/package/${pkgId}`,
            title: `Jailbreak tweak using brand name: ${pkg.name ?? pkgId}`,
            description: `Package '${pkg.name ?? pkgId}' found in the Chariz jailbreak repository using brand name '${brand}'. Jailbreak tweaks are unsigned and can modify/intercept app behaviour.`,
            evidenceSnippet: `Package ID: ${pkgId}, Author: ${pkg.author?.name ?? "unknown"}, Version: ${pkg.latestVersion ?? "unknown"}`,
            installCount: null,
            iconUrl: pkg.headerURL ?? pkg.icon ?? null,
            risk: "high",
          });
          if (out.filter(r => r.type === "rogue_app" && r.platform?.startsWith("Cydia")).length >= 3) break;
        }
      }
    } catch {
      // Chariz is best-effort
    }

    // Havoc probe: any HTTP 200 for brand-name package URL is suspicious
    try {
      const havocRes = await fetch(
        `https://havoc.app/package/${brandLower.replace(/\s+/g, "-")}`,
        {
          headers: { "User-Agent": "Sileo/2.4 Darwin/21.0.0" },
          signal: AbortSignal.timeout(6_000),
        },
      );
      if (havocRes.ok) {
        const html = await havocRes.text();
        if (html.toLowerCase().includes(brandLower)) {
          out.push({
            type: "rogue_app",
            platform: "Cydia/Sileo (Havoc)",
            url: `https://havoc.app/package/${brandLower.replace(/\s+/g, "-")}`,
            title: `Brand-name jailbreak package on Havoc: ${brand}`,
            description: `A jailbreak package for '${brand}' exists on the Havoc repository. Jailbreak tweaks may inject code into the legitimate app or impersonate it.`,
            evidenceSnippet: `Havoc package URL probe returned 200 OK for brand name`,
            installCount: null,
            iconUrl: null,
            risk: "high",
          });
        }
      }
    } catch {
      // Havoc is best-effort
    }
  } catch (e: any) {
    logger.debug(`Jailbreak repo check failed for ${brand}: ${e.message}`);
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
