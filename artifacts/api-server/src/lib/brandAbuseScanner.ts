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
): Promise<BrandAbuseResult[]> {
  const results: BrandAbuseResult[] = [];

  await Promise.allSettled([
    checkCertTransparencyAbuse(brand, domain, results),
    checkDNSTwistLookalikePatterns(brand, domain, results),
    checkAppleAppStore(brand, results),
    checkGooglePlayStore(brand, results),
    ...socialHandles.map(handle => checkSocialHandle(handle, brand, results)),
  ]);

  return results;
}

async function checkSocialHandle(
  handle: string,
  brand: string,
  out: BrandAbuseResult[],
): Promise<void> {
  const platforms = [
    { name: "Twitter/X",  url: `https://twitter.com/${encodeURIComponent(handle)}` },
    { name: "Instagram",  url: `https://instagram.com/${encodeURIComponent(handle)}` },
    { name: "LinkedIn",   url: `https://www.linkedin.com/in/${encodeURIComponent(handle)}` },
    { name: "TikTok",     url: `https://www.tiktok.com/@${encodeURIComponent(handle)}` },
    { name: "Facebook",   url: `https://www.facebook.com/${encodeURIComponent(handle)}` },
    { name: "YouTube",    url: `https://www.youtube.com/@${encodeURIComponent(handle)}` },
  ];
  for (const p of platforms) {
    try {
      const res = await fetch(p.url, {
        method: "HEAD",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" },
        signal: AbortSignal.timeout(6_000),
        redirect: "follow",
      });
      if (res.ok || res.status === 200 || res.status === 301 || res.status === 302) {
        out.push({
          type: "fake_social",
          platform: p.name,
          url: p.url,
          title: `@${handle} on ${p.name}`,
          description: `Watchlist social handle @${handle} found on ${p.name} — may be impersonating ${brand}`,
          evidenceSnippet: `HTTP ${res.status} response from ${p.url}`,
          risk: "medium",
        });
      }
    } catch {
      // Network error — handle likely doesn't exist
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
