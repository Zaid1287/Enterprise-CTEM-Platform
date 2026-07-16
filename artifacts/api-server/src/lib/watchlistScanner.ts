/**
 * watchlistScanner.ts — Type-specific OSINT scanners for brand watchlist items.
 *
 * Each function returns real data from live APIs. No simulation or mock data.
 *
 * Exports:
 *   scanSocialHandleOSINT(handle, opts)  → social handle across platforms + impersonation
 *   scanEmailOSINT(email, opts)          → breach lookup, paste search, OSINT
 *   scanLogoOSINT(logoUrl, brand, opts)  → logo metadata, ad libraries, reverse search
 *   scanKeywordOSINT(keyword, opts)      → Reddit, crt.sh, lookalike DNS, ad libraries
 *   scanMobileAppOSINT(packageId, opts)  → Google Play by ID, store abuse search
 *   extractBrandFromPackageId(pkgId)     → "com.deltinone.customer" → "deltinone"
 */

import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";
// @ts-ignore — google-play-scraper ships CJS; types bundled
import gplay from "google-play-scraper";

export interface WatchlistScanResult {
  type: string;
  category: "brand_abuse" | "data_leak" | "ad_monitoring";
  platform: string | null;
  url: string | null;
  title: string;
  description: string;
  evidenceSnippet?: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  risk: string;
  installCount?: string | null;
  iconUrl?: string | null;
  source?: string;
  breachDate?: string | null;
  emailMatch?: string;
  domainMatch?: string;
  // Ad-specific fields (populated for real Meta Ads results)
  adId?: string | null;
  adType?: string | null;
  advertiserName?: string | null;
  advertiserPage?: string | null;
  impressions?: string | null;
  spend?: string | null;
  currency?: string | null;
  startDate?: string | null;
  endDate?: string | null;
  snapshotUrl?: string | null;
  deliveryCountries?: string[];
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOCIAL HANDLE OSINT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Checks a social handle directly across 10+ platforms (no false-positive skip —
 * we are TRACKING this specific handle), plus impersonation variations.
 */
export async function scanSocialHandleOSINT(
  handle: string,
  opts: { googleSearchKey?: string | null; googleSearchCx?: string | null } = {},
): Promise<WatchlistScanResult[]> {
  const results: WatchlistScanResult[] = [];
  const cleanHandle = handle.replace(/^@/, "");

  await Promise.allSettled([
    checkHandleAcrossPlatforms(cleanHandle, results),
    checkHandleImpersonationVariations(cleanHandle, results),
    searchRedditForHandle(cleanHandle, results),
    checkCertsForBrand(cleanHandle.replace(/_/g, ""), results, "social handle"),
    opts.googleSearchKey && opts.googleSearchCx
      ? googleDorkSocialHandle(cleanHandle, opts.googleSearchKey, opts.googleSearchCx, results)
      : Promise.resolve(),
  ]);

  return results;
}

async function checkHandleAcrossPlatforms(handle: string, out: WatchlistScanResult[]): Promise<void> {
  const platforms = [
    { name: "Twitter/X",   url: `https://twitter.com/${encodeURIComponent(handle)}`,            checkBody: true },
    { name: "Instagram",   url: `https://instagram.com/${encodeURIComponent(handle)}/`,          checkBody: true },
    { name: "TikTok",      url: `https://www.tiktok.com/@${encodeURIComponent(handle)}`,         checkBody: true },
    { name: "Facebook",    url: `https://www.facebook.com/${encodeURIComponent(handle)}`,        checkBody: true },
    { name: "YouTube",     url: `https://www.youtube.com/@${encodeURIComponent(handle)}`,        checkBody: true },
    { name: "GitHub",      url: `https://github.com/${encodeURIComponent(handle)}`,              checkBody: false },
    { name: "Reddit",      url: `https://www.reddit.com/user/${encodeURIComponent(handle)}`,     checkBody: false },
    { name: "Pinterest",   url: `https://www.pinterest.com/${encodeURIComponent(handle)}/`,      checkBody: false },
    { name: "Telegram",    url: `https://t.me/${encodeURIComponent(handle)}`,                    checkBody: false },
    { name: "Snapchat",    url: `https://www.snapchat.com/add/${encodeURIComponent(handle)}`,    checkBody: false },
  ];

  await Promise.allSettled(platforms.map(async (p) => {
    try {
      const res = await orchestratedFetch(p.url, {
        method: "GET",
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml",
        },
        signal: AbortSignal.timeout(8_000),
        redirect: "follow",
      });

      if (!res.ok || res.status === 404) return;

      let pageTitle = "";
      let isActive = true;

      if (p.checkBody) {
        try {
          const body = await res.text();
          const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
          pageTitle = titleMatch?.[1]?.trim().replace(/\s+/g, " ") ?? "";
          if (/not.found|doesn.t.exist|page not available|sorry.+page|this account|no longer available|account suspended/i.test(pageTitle)) {
            isActive = false;
          }
          if (/error|trouble|unavailable/i.test(pageTitle) && !pageTitle.toLowerCase().includes(handle.toLowerCase())) {
            isActive = false;
          }
        } catch { /* ignore body parse error */ }
      }

      if (!isActive) return;

      out.push({
        type: "social_handle_found",
        category: "brand_abuse",
        platform: p.name,
        url: p.url,
        title: `@${handle} exists on ${p.name}`,
        description: `The handle "@${handle}" has an active profile on ${p.name}. Verify this is a legitimate account associated with your brand or flag for impersonation review.${pageTitle ? ` Page title: "${pageTitle}"` : ""}`,
        evidenceSnippet: `Handle: @${handle} | Platform: ${p.name} | HTTP: ${res.status}${pageTitle ? ` | Title: ${pageTitle}` : ""}`,
        severity: "medium",
        risk: "medium",
      });
    } catch {
      // Network error or platform blocked
    }
  }));
}

async function checkHandleImpersonationVariations(handle: string, out: WatchlistScanResult[]): Promise<void> {
  const variations = [
    `${handle}_official`, `${handle}_real`, `${handle}_original`, `${handle}_backup`,
    `real_${handle}`, `official_${handle}`, `the_real_${handle}`, `real${handle}`,
    `${handle}official`, `${handle}real`, `${handle}_2`, `${handle}2`,
    `${handle}_fan`, `${handle}_news`, `${handle}_support`,
  ];

  const platforms = [
    { name: "Twitter/X",  urlFn: (h: string) => `https://twitter.com/${encodeURIComponent(h)}` },
    { name: "Instagram",  urlFn: (h: string) => `https://instagram.com/${encodeURIComponent(h)}/` },
    { name: "TikTok",     urlFn: (h: string) => `https://www.tiktok.com/@${encodeURIComponent(h)}` },
  ];

  await Promise.allSettled(
    variations.flatMap(variation =>
      platforms.map(async p => {
        try {
          const url = p.urlFn(variation);
          const res = await orchestratedFetch(url, {
            method: "GET",
            headers: { "User-Agent": "Mozilla/5.0" },
            signal: AbortSignal.timeout(5_000),
            redirect: "follow",
          });
          if (!res.ok || res.status === 404) return;

          const body = await res.text().catch(() => "");
          const titleMatch = body.match(/<title[^>]*>([^<]+)<\/title>/i);
          const pageTitle = titleMatch?.[1]?.trim() ?? "";

          if (/not.found|doesn.t.exist|page not available|account suspended/i.test(pageTitle)) return;

          out.push({
            type: "impersonating_handle",
            category: "brand_abuse",
            platform: p.name,
            url,
            title: `Potential impersonating handle: @${variation} on ${p.name}`,
            description: `Handle "@${variation}" exists on ${p.name} and appears to be a variation of "@${handle}". This may be a fan account, clone, or brand impersonator. Verify ownership.`,
            evidenceSnippet: `Original: @${handle} | Variant: @${variation} | Platform: ${p.name}${pageTitle ? ` | Title: ${pageTitle}` : ""}`,
            severity: "high",
            risk: "high",
          });
        } catch { /* ignore */ }
      }),
    ),
  );
}

async function searchRedditForHandle(handle: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://www.reddit.com/search.json?q=${encodeURIComponent(`"${handle}"`)}&sort=new&limit=10&type=link`,
      { headers: { "User-Agent": "SentinelwareCTEM/1.0" }, signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const post of ((data?.data?.children ?? []) as any[]).slice(0, 5)) {
      const p = post.data;
      const isNegative = /scam|fraud|fake|warning|phish|hack|exploit/i.test(p.title ?? "");
      out.push({
        type: isNegative ? "negative_social_mention" : "social_mention",
        category: "brand_abuse",
        platform: "Reddit",
        url: `https://www.reddit.com${p.permalink}`,
        title: `Reddit: "${(p.title ?? "").slice(0, 80)}"`,
        description: `Handle "@${handle}" mentioned in Reddit post. ${isNegative ? "⚠️ Negative/suspicious content detected." : ""} r/${p.subreddit}: ${(p.selftext ?? "").slice(0, 150)}`,
        evidenceSnippet: `r/${p.subreddit} | Score: ${p.score} | Comments: ${p.num_comments} | Author: u/${p.author}`,
        severity: isNegative ? "high" : "low",
        risk: isNegative ? "high" : "low",
      });
    }
  } catch { /* ignore */ }
}

async function googleDorkSocialHandle(
  handle: string,
  key: string,
  cx: string,
  out: WatchlistScanResult[],
): Promise<void> {
  try {
    const q = `"${handle}" site:twitter.com OR site:instagram.com OR site:tiktok.com OR site:facebook.com`;
    const res = await orchestratedFetch(
      `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&q=${encodeURIComponent(q)}&num=5`,
      { signal: AbortSignal.timeout(8_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const item of ((data.items ?? []) as any[]).slice(0, 5)) {
      out.push({
        type: "google_dork_mention",
        category: "brand_abuse",
        platform: "Google Dorking",
        url: item.link,
        title: `Google found @${handle}: ${(item.title ?? "").slice(0, 80)}`,
        description: `Google search found "@${handle}" referenced at ${item.displayLink}. ${(item.snippet ?? "").slice(0, 200)}`,
        evidenceSnippet: `Query: "${q}" | Source: ${item.displayLink}`,
        severity: "info",
        risk: "low",
      });
    }
  } catch { /* ignore */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// EMAIL OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanEmailOSINT(
  email: string,
  opts: { hibpKey?: string | null; googleSearchKey?: string | null; googleSearchCx?: string | null } = {},
): Promise<WatchlistScanResult[]> {
  const results: WatchlistScanResult[] = [];
  const parts = email.split("@");
  const domain = parts[1] ?? "";

  await Promise.allSettled([
    opts.hibpKey ? checkHIBP(email, opts.hibpKey, results) : Promise.resolve(),
    checkEmailDomainMX(domain, email, results),
    searchRedditForEmail(email, results),
    checkLeakCheck(email, results),
    opts.googleSearchKey && opts.googleSearchCx
      ? googleDorkEmail(email, opts.googleSearchKey, opts.googleSearchCx, results)
      : Promise.resolve(),
  ]);

  // Always include a manual OSINT reference card
  results.push({
    type: "osint_reference",
    category: "data_leak",
    platform: "OSINT Tools",
    url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    title: `Manual OSINT: verify ${email}`,
    description: `Manual verification: check ${email} on HaveIBeenPwned, Dehashed, and IntelX for additional breach records. Click the link to check HIBP directly.`,
    evidenceSnippet: `Email: ${email} | Domain: ${domain} | HIBP: haveibeenpwned.com/account/${encodeURIComponent(email)}`,
    severity: "info",
    risk: "low",
    emailMatch: email,
  });

  return results;
}

async function checkHIBP(email: string, apiKey: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: { "hibp-api-key": apiKey, "User-Agent": "Sentinelware-CTEM/1.0" },
        signal: AbortSignal.timeout(15_000),
      },
    );

    if (res.status === 404) {
      out.push({
        type: "no_breach_found",
        category: "data_leak",
        platform: "HaveIBeenPwned",
        url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}`,
        title: `No known HIBP breaches: ${email}`,
        description: `HaveIBeenPwned found no data breaches for ${email}. This is a good sign but does not guarantee the email was never exposed.`,
        evidenceSnippet: "HIBP: 404 Not Found — no breach records",
        severity: "info",
        risk: "low",
        emailMatch: email,
      });
      return;
    }
    if (!res.ok) return;

    const breaches = await res.json() as any[];
    for (const breach of breaches) {
      const classes: string[] = breach.DataClasses ?? [];
      const hasPasswords = classes.some(d => /password/i.test(d));
      const hasFinancial = classes.some(d => /credit|financial|bank|payment/i.test(d));
      const sev = hasFinancial ? "critical" : hasPasswords ? "high" : "medium";

      out.push({
        type: "email_breach",
        category: "data_leak",
        platform: "HaveIBeenPwned",
        url: `https://haveibeenpwned.com/PwnedWebsites#${breach.Name}`,
        title: `Breach: ${breach.Title} (${breach.BreachDate ?? "unknown date"})`,
        description: `${email} was found in the "${breach.Title}" data breach. Exposed: ${classes.join(", ")}.${breach.PwnCount ? ` ~${breach.PwnCount.toLocaleString()} records leaked.` : ""}`,
        evidenceSnippet: `Breach: ${breach.Title} | Date: ${breach.BreachDate} | Records: ${breach.PwnCount?.toLocaleString() ?? "?"} | Verified: ${breach.IsVerified}`,
        severity: sev,
        risk: sev,
        breachDate: breach.BreachDate ?? null,
        emailMatch: email,
      });
    }
  } catch (err: any) {
    logger.debug({ err: String(err) }, "HIBP check error");
  }
}

async function checkEmailDomainMX(domain: string, email: string, out: WatchlistScanResult[]): Promise<void> {
  if (!domain) return;
  try {
    const { Resolver } = await import("dns/promises");
    const resolver = new Resolver();
    resolver.setServers(["8.8.8.8", "1.1.1.1"]);
    const mx = await resolver.resolveMx(domain).catch(() => null);

    if (!mx || mx.length === 0) {
      out.push({
        type: "no_mx_record",
        category: "data_leak",
        platform: "DNS Validation",
        url: null,
        title: `No MX records for ${domain}`,
        description: `The email domain "${domain}" has no MX records — ${email} may be invalid or the domain is misconfigured. Phishing emails often use domains with no mail infrastructure.`,
        evidenceSnippet: `Domain: ${domain} | MX records: none | Status: INVALID`,
        severity: "high",
        risk: "high",
        emailMatch: email,
      });
    } else {
      const exchanges = mx.sort((a, b) => a.priority - b.priority).map(r => r.exchange).join(", ");
      out.push({
        type: "mx_record_found",
        category: "data_leak",
        platform: "DNS Validation",
        url: null,
        title: `Active email domain: ${domain}`,
        description: `Domain "${domain}" has ${mx.length} active MX record(s): ${exchanges}. The email address ${email} can receive mail.`,
        evidenceSnippet: `MX: ${exchanges} | Count: ${mx.length}`,
        severity: "info",
        risk: "low",
        emailMatch: email,
      });
    }
  } catch { /* ignore */ }
}

async function searchRedditForEmail(email: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://www.reddit.com/search.json?q=${encodeURIComponent(`"${email}"`)}&sort=new&limit=5`,
      { headers: { "User-Agent": "SentinelwareCTEM/1.0" }, signal: AbortSignal.timeout(8_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const post of ((data?.data?.children ?? []) as any[]).slice(0, 3)) {
      const p = post.data;
      out.push({
        type: "email_paste_mention",
        category: "data_leak",
        platform: "Reddit",
        url: `https://www.reddit.com${p.permalink}`,
        title: `Email on Reddit: "${(p.title ?? "").slice(0, 60)}"`,
        description: `${email} was found mentioned in a Reddit post in r/${p.subreddit}. This may indicate a data leak or spam list exposure.`,
        evidenceSnippet: `r/${p.subreddit} | Score: ${p.score} | Author: u/${p.author}`,
        severity: "high",
        risk: "high",
        emailMatch: email,
      });
    }
  } catch { /* ignore */ }
}

async function checkLeakCheck(email: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`,
      {
        headers: { "User-Agent": "SentinelwareCTEM/1.0" },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    if (data?.found === true || (data?.sources && data.sources.length > 0)) {
      const sources: string[] = data.sources ?? [];
      out.push({
        type: "email_in_breach_db",
        category: "data_leak",
        platform: "LeakCheck.io",
        url: `https://leakcheck.io/?q=${encodeURIComponent(email)}`,
        title: `Email in leaked databases: ${email}`,
        description: `LeakCheck.io confirms ${email} appears in ${sources.length > 0 ? `${sources.length} known breach source(s)` : "leaked credential databases"}. Immediate password change recommended. Sources: ${sources.join(", ") || "undisclosed (premium detail)"}`,
        evidenceSnippet: `Sources: ${sources.join(", ") || "undisclosed"} | Email: ${email}`,
        severity: "critical",
        risk: "critical",
        emailMatch: email,
      });
    }
  } catch { /* ignore — LeakCheck rate limits aggressively */ }
}

async function googleDorkEmail(
  email: string,
  key: string,
  cx: string,
  out: WatchlistScanResult[],
): Promise<void> {
  try {
    const queries = [
      `"${email}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com OR site:rentry.co`,
      `"${email}" filetype:txt OR filetype:csv`,
    ];
    for (const q of queries) {
      const res = await orchestratedFetch(
        `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&q=${encodeURIComponent(q)}&num=5`,
        { signal: AbortSignal.timeout(8_000) },
      );
      if (!res.ok) continue;
      const data = await res.json() as any;
      for (const item of ((data.items ?? []) as any[]).slice(0, 5)) {
        const isPaste = /pastebin|paste\.ee|ghostbin|rentry|hastebin/i.test(item.link ?? "");
        out.push({
          type: isPaste ? "email_in_paste" : "email_web_exposure",
          category: "data_leak",
          platform: isPaste ? "Paste Site" : "Web Exposure",
          url: item.link,
          title: `${isPaste ? "⚠️ Paste site exposure" : "Web mention"}: ${email}`,
          description: `${email} was found on ${item.displayLink}. ${isPaste ? "Paste sites often contain leaked credential dumps — immediate investigation recommended." : ""} Snippet: ${(item.snippet ?? "").slice(0, 200)}`,
          evidenceSnippet: `Source: ${item.displayLink} | URL: ${item.link}`,
          severity: isPaste ? "critical" : "high",
          risk: isPaste ? "critical" : "high",
          emailMatch: email,
        });
      }
    }
  } catch { /* ignore */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOGO OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanLogoOSINT(
  logoUrl: string,
  brandName: string,
  opts: {
    googleSearchKey?: string | null;
    googleSearchCx?: string | null;
    metaAdsToken?: string | null;
  } = {},
): Promise<WatchlistScanResult[]> {
  const results: WatchlistScanResult[] = [];

  await Promise.allSettled([
    analyzeLogoMetadata(logoUrl, brandName, results),
    checkMetaAdLibrary(brandName, results, opts.metaAdsToken ?? null),
    checkGoogleAdsTransparency(brandName, results, opts.googleSearchKey ?? null, opts.googleSearchCx ?? null),
    addReverseSearchLinks(logoUrl, brandName, results),
    checkCertsForBrand(brandName.toLowerCase().replace(/\s+/g, ""), results, "brand"),
    opts.googleSearchKey && opts.googleSearchCx
      ? googleDorkLogoUrl(logoUrl, brandName, opts.googleSearchKey, opts.googleSearchCx, results)
      : Promise.resolve(),
  ]);

  return results;
}

async function analyzeLogoMetadata(logoUrl: string, brandName: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    let urlObj: URL;
    try { urlObj = new URL(logoUrl); } catch { return; }

    const res = await orchestratedFetch(logoUrl, {
      method: "HEAD",
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(10_000),
    });

    const ct = res.headers.get("content-type") ?? "unknown";
    const cl = res.headers.get("content-length");
    const lm = res.headers.get("last-modified");

    if (res.ok) {
      out.push({
        type: "logo_accessible",
        category: "brand_abuse",
        platform: "Logo Analysis",
        url: logoUrl,
        title: `Logo accessible: ${urlObj.hostname}`,
        description: `Logo for "${brandName}" is publicly accessible at ${logoUrl}. Content-Type: ${ct}${cl ? `, Size: ~${Math.round(parseInt(cl) / 1024)}KB` : ""}${lm ? `, Last-Modified: ${lm}` : ""}. Verify this is the intended hosting location.`,
        evidenceSnippet: `URL: ${logoUrl} | Host: ${urlObj.hostname} | Type: ${ct} | HTTP: ${res.status}`,
        severity: "info",
        risk: "low",
      });
    } else {
      out.push({
        type: "logo_unreachable",
        category: "brand_abuse",
        platform: "Logo Analysis",
        url: logoUrl,
        title: `Logo URL returned HTTP ${res.status}`,
        description: `The logo URL for "${brandName}" returned HTTP ${res.status} — the image is not publicly accessible. This may affect brand visibility or indicate the URL has changed.`,
        evidenceSnippet: `URL: ${logoUrl} | HTTP: ${res.status}`,
        severity: "medium",
        risk: "medium",
      });
    }
  } catch (err: any) {
    out.push({
      type: "logo_fetch_error",
      category: "brand_abuse",
      platform: "Logo Analysis",
      url: logoUrl,
      title: `Logo fetch failed`,
      description: `Could not retrieve logo from ${logoUrl}: ${(err.message ?? "unknown error").slice(0, 100)}. Verify the URL is valid and publicly accessible.`,
      evidenceSnippet: `Error: ${err.message ?? "unknown"}`,
      severity: "medium",
      risk: "medium",
    });
  }
}

async function checkMetaAdLibrary(brandName: string, out: WatchlistScanResult[], accessToken: string | null): Promise<void> {
  // With a real access token: call the Meta Ads Library Graph API and return actual ad findings
  if (accessToken) {
    try {
      const { scanMetaAds } = await import("./metaAdsClient");
      const ads = await scanMetaAds(brandName, brandName.toLowerCase().replace(/\s+/g, ""), accessToken);
      if (ads.length > 0) {
        for (const ad of ads) {
          out.push({
            type: "meta_ad_finding",
            category: "ad_monitoring",
            platform: "Meta Ads Library",
            url: ad.snapshotUrl ?? `https://www.facebook.com/ads/library/?q=${encodeURIComponent(brandName)}`,
            title: ad.title ?? `Meta Ad by ${ad.advertiserName ?? "Unknown Advertiser"}`,
            description: [
              ad.body ? `Ad copy: ${ad.body}` : null,
              ad.advertiserName ? `Advertiser: ${ad.advertiserName}` : null,
              ad.impressions ? `Impressions: ${ad.impressions}` : null,
              ad.spend && ad.currency ? `Spend: ${ad.spend} ${ad.currency}` : null,
              ad.startDate ? `Running since: ${ad.startDate}` : null,
            ].filter(Boolean).join(" | ") || `Active Meta ad using "${brandName}" branding detected via Meta Ads Library API.`,
            evidenceSnippet: `Ad ID: ${ad.adId} | Advertiser: ${ad.advertiserName ?? "Unknown"} | Risk: ${ad.risk}`,
            severity: ad.risk === "critical" ? "critical" : ad.risk === "high" ? "high" : "medium",
            risk: ad.risk,
            adId: ad.adId,
            adType: ad.adType,
            advertiserName: ad.advertiserName,
            advertiserPage: ad.advertiserPage,
            impressions: ad.impressions,
            spend: ad.spend,
            currency: ad.currency,
            startDate: ad.startDate,
            endDate: ad.endDate,
            snapshotUrl: ad.snapshotUrl,
            deliveryCountries: ad.deliveryCountries,
          });
        }
        logger.info({ brandName, count: ads.length }, "Meta Ads Library: real findings returned");
        return;
      }
      // API returned 0 results — brand not found in ads, add informational result
      out.push({
        type: "meta_ad_library_search",
        category: "ad_monitoring",
        platform: "Meta Ads Library",
        url: `https://www.facebook.com/ads/library/?active_status=all&ad_type=all&country=ALL&q=${encodeURIComponent(brandName)}&search_type=keyword_unordered`,
        title: `No active Meta ads found for "${brandName}"`,
        description: `The Meta Ads Library API returned 0 active or inactive ads matching "${brandName}". This indicates no advertisers are currently running ads impersonating this brand on Facebook/Instagram.`,
        evidenceSnippet: `Brand: ${brandName} | API queried | Result: 0 ads found`,
        severity: "info",
        risk: "low",
      });
      return;
    } catch (err) {
      logger.warn({ err, brandName }, "Meta Ads API call failed in logo OSINT, falling back to search link");
    }
  }

  // No token or API error: provide a manual search link
  const searchUrl = `https://www.facebook.com/ads/library/?active_status=all&ad_type=all&country=ALL&q=${encodeURIComponent(brandName)}&search_type=keyword_unordered`;
  out.push({
    type: "meta_ad_library_search",
    category: "ad_monitoring",
    platform: "Meta Ads Library",
    url: searchUrl,
    title: `Meta Ads Library: search "${brandName}"`,
    description: `No Meta Ads API token configured. Open the link to manually search the Meta Ads Library for ads using "${brandName}" branding. Configure a Meta Ads access token in Platform Settings → Brand Intelligence to enable automated scanning.`,
    evidenceSnippet: `Brand: ${brandName} | Manual review URL: ${searchUrl}`,
    severity: "info",
    risk: "low",
  });
}

async function checkGoogleAdsTransparency(
  brandName: string,
  out: WatchlistScanResult[],
  googleSearchKey: string | null,
  googleSearchCx: string | null,
): Promise<void> {
  // With Google Custom Search keys: find pages referencing this brand in advertising context
  if (googleSearchKey && googleSearchCx) {
    try {
      const queries = [
        `"${brandName}" (advertisement OR sponsored OR "ads by") -site:${brandName.toLowerCase().replace(/\s+/g, "")}.com`,
        `site:adstransparency.google.com "${brandName}"`,
      ];
      let foundAny = false;
      for (const q of queries) {
        const res = await orchestratedFetch(
          `https://www.googleapis.com/customsearch/v1?key=${googleSearchKey}&cx=${googleSearchCx}&q=${encodeURIComponent(q)}&num=5`,
          { signal: AbortSignal.timeout(8_000) },
        );
        if (!res.ok) continue;
        const data = await res.json() as any;
        for (const item of ((data.items ?? []) as any[])) {
          const isAdTransparency = (item.link ?? "").includes("adstransparency.google.com");
          out.push({
            type: "google_ads_finding",
            category: "ad_monitoring",
            platform: "Google Ads",
            url: item.link,
            title: (item.title ?? "").slice(0, 100) || `Google Ad reference: ${brandName}`,
            description: `Google search found "${brandName}" in an advertising context at ${item.displayLink ?? item.link}. ${(item.snippet ?? "").slice(0, 200)}`,
            evidenceSnippet: `Query: "${q}" | Source: ${item.displayLink ?? item.link}`,
            severity: isAdTransparency ? "high" : "medium",
            risk: isAdTransparency ? "high" : "medium",
          });
          foundAny = true;
        }
      }
      if (foundAny) return;
    } catch (err) {
      logger.warn({ err, brandName }, "Google Ads Transparency search failed, falling back to manual link");
    }
  }

  // Fallback: manual review link
  const searchUrl = `https://adstransparency.google.com/advertiser/search?query=${encodeURIComponent(brandName)}&region=anywhere`;
  out.push({
    type: "google_ads_transparency_search",
    category: "ad_monitoring",
    platform: "Google Ads Transparency",
    url: searchUrl,
    title: `Google Ads Transparency: "${brandName}"`,
    description: googleSearchKey
      ? `Google Custom Search found no ads referencing "${brandName}". Open the link for manual review of the Google Ads Transparency Center.`
      : `No Google Search API key configured. Open the link to manually check Google Ads Transparency Center for advertisers using "${brandName}". Configure Google Search API keys in Platform Settings to enable automated scanning.`,
    evidenceSnippet: `Brand: ${brandName} | Review URL: ${searchUrl}`,
    severity: "info",
    risk: "low",
  });
}

async function addReverseSearchLinks(logoUrl: string, brandName: string, out: WatchlistScanResult[]): Promise<void> {
  const enc = encodeURIComponent(logoUrl);
  const tineye  = `https://tineye.com/search?url=${enc}`;
  const gLens   = `https://lens.google.com/uploadbyurl?url=${enc}`;
  const yandex  = `https://yandex.com/images/search?url=${enc}&rpt=imageview`;

  out.push({
    type: "reverse_image_search",
    category: "brand_abuse",
    platform: "Reverse Image Search",
    url: tineye,
    title: `Find unauthorized copies of "${brandName}" logo`,
    description: `Use reverse image search to find where the "${brandName}" logo appears across the web, in ads, or on social media. Three search engines are provided.`,
    evidenceSnippet: [
      `TinEye (best for exact copies): ${tineye}`,
      `Google Lens (broadest coverage): ${gLens}`,
      `Yandex (strong for social media): ${yandex}`,
    ].join(" | "),
    severity: "info",
    risk: "low",
  });
}

async function googleDorkLogoUrl(
  logoUrl: string,
  brandName: string,
  key: string,
  cx: string,
  out: WatchlistScanResult[],
): Promise<void> {
  try {
    const q = `"${brandName}" logo OR brand`;
    const res = await orchestratedFetch(
      `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&q=${encodeURIComponent(q)}&num=5`,
      { signal: AbortSignal.timeout(8_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const item of ((data.items ?? []) as any[]).slice(0, 5)) {
      out.push({
        type: "logo_web_reference",
        category: "brand_abuse",
        platform: "Google Dorking",
        url: item.link,
        title: `Brand logo reference: ${(item.title ?? "").slice(0, 80)}`,
        description: `Google found "${brandName}" logo/brand referenced at ${item.displayLink}. ${(item.snippet ?? "").slice(0, 200)}`,
        evidenceSnippet: `Query: "${q}" | Source: ${item.displayLink}`,
        severity: "medium",
        risk: "medium",
      });
    }
  } catch { /* ignore */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD OSINT
// ═══════════════════════════════════════════════════════════════════════════════

export async function scanKeywordOSINT(
  keyword: string,
  opts: {
    googleSearchKey?: string | null;
    googleSearchCx?: string | null;
    youtubeKey?: string | null;
    metaAdsToken?: string | null;
  } = {},
): Promise<WatchlistScanResult[]> {
  const results: WatchlistScanResult[] = [];

  await Promise.allSettled([
    searchRedditForKeyword(keyword, results),
    checkMetaAdLibrary(keyword, results, opts.metaAdsToken ?? null),
    checkGoogleAdsTransparency(keyword, results, opts.googleSearchKey ?? null, opts.googleSearchCx ?? null),
    checkCertsForBrand(keyword.toLowerCase().replace(/\s+/g, ""), results, "keyword"),
    checkDNSLookalikePatterns(keyword, results),
    opts.googleSearchKey && opts.googleSearchCx
      ? googleDorkKeyword(keyword, opts.googleSearchKey, opts.googleSearchCx, results)
      : Promise.resolve(),
    opts.youtubeKey
      ? checkYouTubeKeyword(keyword, opts.youtubeKey, results)
      : Promise.resolve(),
  ]);

  return results;
}

async function searchRedditForKeyword(keyword: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://www.reddit.com/search.json?q=${encodeURIComponent(keyword)}&sort=new&limit=10&type=link`,
      { headers: { "User-Agent": "SentinelwareCTEM/1.0" }, signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const post of ((data?.data?.children ?? []) as any[]).slice(0, 8)) {
      const p = post.data;
      const isNegative = /scam|fraud|fake|warning|phish|exploit|hack|danger/i.test(p.title ?? "");
      out.push({
        type: isNegative ? "negative_brand_mention" : "brand_mention",
        category: "brand_abuse",
        platform: "Reddit",
        url: `https://www.reddit.com${p.permalink}`,
        title: `Reddit${isNegative ? " ⚠️" : ""}: "${(p.title ?? "").slice(0, 80)}"`,
        description: `Keyword "${keyword}" found in Reddit post on r/${p.subreddit}. ${isNegative ? "Negative/suspicious content detected — review immediately." : ""} ${(p.selftext ?? "").slice(0, 150)}`,
        evidenceSnippet: `r/${p.subreddit} | Score: ${p.score} | Comments: ${p.num_comments} | Sentiment: ${isNegative ? "NEGATIVE" : "neutral"}`,
        severity: isNegative ? "high" : "low",
        risk: isNegative ? "high" : "low",
      });
    }
  } catch { /* ignore */ }
}

async function checkCertsForBrand(brandSlug: string, out: WatchlistScanResult[], context: string): Promise<void> {
  if (!brandSlug || brandSlug.length < 3) return;
  try {
    const res = await orchestratedFetch(
      `https://crt.sh/?q=%25${encodeURIComponent(brandSlug)}%25&output=json`,
      { signal: AbortSignal.timeout(12_000) },
    );
    if (!res.ok) return;
    const certs = await res.json() as any[];

    const seen = new Set<string>();
    let count = 0;
    for (const cert of certs.slice(0, 500)) {
      const cn: string = (cert.common_name ?? cert.name_value ?? "").toLowerCase();
      if (!cn.includes(brandSlug.toLowerCase())) continue;
      if (seen.has(cn)) continue;
      seen.add(cn);

      out.push({
        type: "suspicious_certificate",
        category: "brand_abuse",
        platform: "Certificate Transparency",
        url: `https://crt.sh/?q=${encodeURIComponent(cn)}`,
        title: `Brand cert: ${cn}`,
        description: `SSL certificate issued for "${cn}" contains the ${context} "${brandSlug}". This domain may be a phishing site or unauthorized brand use.`,
        evidenceSnippet: `CN=${cn} | Issued: ${cert.not_before ?? "unknown"} | Expires: ${cert.not_after ?? "unknown"} | Issuer: ${cert.issuer_name ?? "unknown"}`,
        severity: "medium",
        risk: "medium",
      });

      if (++count >= 20) break;
    }
  } catch { /* ignore */ }
}

async function checkDNSLookalikePatterns(keyword: string, out: WatchlistScanResult[]): Promise<void> {
  const slug = keyword.toLowerCase().replace(/\s+/g, "");
  const patterns = [
    `${slug}-login`, `${slug}-secure`, `${slug}-support`, `${slug}-verify`,
    `${slug}-official`, `${slug}-shop`, `${slug}-pay`, `${slug}pay`,
    `${slug}shop`, `${slug}app`, `login-${slug}`, `secure-${slug}`,
  ];
  const tlds = [".com", ".net", ".org"];

  const { Resolver } = await import("dns/promises");
  const resolver = new Resolver();
  resolver.setServers(["8.8.8.8", "1.1.1.1"]);

  await Promise.allSettled(
    patterns.slice(0, 8).flatMap(p =>
      tlds.map(async tld => {
        const domain = `${p}${tld}`;
        try {
          const addrs = await resolver.resolve4(domain).catch(() => null);
          if (addrs?.length) {
            out.push({
              type: "lookalike_domain",
              category: "brand_abuse",
              platform: "DNS",
              url: `http://${domain}`,
              title: `Live lookalike domain: ${domain}`,
              description: `Domain "${domain}" is live (resolves to ${addrs.join(", ")}) and contains the keyword "${keyword}". This may be a phishing, scam, or impersonation site.`,
              evidenceSnippet: `Domain: ${domain} | A records: ${addrs.join(", ")} | Keyword: ${keyword}`,
              severity: "high",
              risk: "high",
            });
          }
        } catch { /* expected for non-existent domains */ }
      }),
    ),
  );
}

async function googleDorkKeyword(
  keyword: string,
  key: string,
  cx: string,
  out: WatchlistScanResult[],
): Promise<void> {
  try {
    const queries = [
      `"${keyword}" scam OR fraud OR fake OR phishing`,
      `"${keyword}" site:pastebin.com OR site:paste.ee OR site:ghostbin.com`,
    ];
    for (const q of queries) {
      const res = await orchestratedFetch(
        `https://www.googleapis.com/customsearch/v1?key=${key}&cx=${cx}&q=${encodeURIComponent(q)}&num=5`,
        { signal: AbortSignal.timeout(8_000) },
      );
      if (!res.ok) continue;
      const data = await res.json() as any;
      for (const item of ((data.items ?? []) as any[]).slice(0, 5)) {
        out.push({
          type: "keyword_dork_result",
          category: "brand_abuse",
          platform: "Google Dorking",
          url: item.link,
          title: `Dork: ${(item.title ?? "").slice(0, 80)}`,
          description: `Google dork query found "${keyword}": ${(item.snippet ?? "").slice(0, 200)}`,
          evidenceSnippet: `Query: ${q} | Source: ${item.displayLink}`,
          severity: "medium",
          risk: "medium",
        });
      }
    }
  } catch { /* ignore */ }
}

async function checkYouTubeKeyword(keyword: string, apiKey: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const res = await orchestratedFetch(
      `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(keyword)}&type=video&order=relevance&maxResults=5&key=${apiKey}`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    for (const item of ((data.items ?? []) as any[]).slice(0, 5)) {
      const title = item.snippet?.title ?? "";
      const channel = item.snippet?.channelTitle ?? "";
      const isNegative = /scam|fraud|fake|warning|phish|hack/i.test(title);
      out.push({
        type: isNegative ? "negative_youtube_mention" : "youtube_mention",
        category: "brand_abuse",
        platform: "YouTube",
        url: `https://www.youtube.com/watch?v=${item.id?.videoId}`,
        title: `YouTube${isNegative ? " ⚠️" : ""}: "${title.slice(0, 80)}"`,
        description: `YouTube video mentioning "${keyword}" by "${channel}". ${isNegative ? "Negative/suspicious content detected." : ""}`,
        evidenceSnippet: `Channel: ${channel} | Published: ${(item.snippet?.publishedAt ?? "").slice(0, 10)} | Sentiment: ${isNegative ? "NEGATIVE" : "neutral"}`,
        severity: isNegative ? "high" : "low",
        risk: isNegative ? "high" : "low",
      });
    }
  } catch { /* ignore */ }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MOBILE APP OSINT
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Extracts a human-readable brand name from a package ID.
 * "com.deltinone.customer" → { brandName: "deltinone", appLabel: "customer" }
 * "io.sentinelware.app"   → { brandName: "sentinelware", appLabel: "app" }
 */
export function extractBrandFromPackageId(packageId: string): { brandName: string; appLabel: string; searchName: string } {
  const segments = packageId.split(".");
  const tlds = new Set(["com", "org", "net", "io", "co", "app", "dev", "me", "in", "uk", "au", "eu"]);
  const filtered = segments.filter(s => !tlds.has(s.toLowerCase()) && s.length > 1);
  const brandName = (filtered[0] ?? segments[1] ?? segments[0] ?? packageId)
    .replace(/[^a-z0-9]/gi, " ").trim().toLowerCase();
  const appLabel = (filtered[filtered.length - 1] ?? brandName)
    .replace(/[^a-z0-9]/gi, " ").trim().toLowerCase();
  const searchName = brandName !== appLabel ? `${brandName} ${appLabel}` : brandName;
  return { brandName, appLabel, searchName };
}

export async function scanMobileAppOSINT(
  packageId: string,
  opts: { googleSearchKey?: string | null; googleSearchCx?: string | null } = {},
): Promise<WatchlistScanResult[]> {
  const results: WatchlistScanResult[] = [];
  const { brandName, searchName } = extractBrandFromPackageId(packageId);

  await Promise.allSettled([
    lookupGooglePlayById(packageId, brandName, results),
    searchGooglePlayByBrand(brandName, packageId, results),
    searchAppleAppStore(searchName, packageId, results),
    searchAPKPure(brandName, packageId, results),
    searchAptoide(brandName, packageId, results),
    checkCertsForBrand(brandName.replace(/\s+/g, ""), results, "app brand"),
    addAppDistributionLinks(packageId, brandName, results),
  ]);

  return results;
}

async function lookupGooglePlayById(packageId: string, brandName: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const app = await (gplay as any).app({ appId: packageId, lang: "en", country: "us" }).catch(() => null) as any;

    if (!app) {
      out.push({
        type: "official_app_not_found",
        category: "brand_abuse",
        platform: "Google Play Store",
        url: `https://play.google.com/store/search?q=${encodeURIComponent(brandName)}&c=apps`,
        title: `Package "${packageId}" not found on Google Play`,
        description: `The package ID "${packageId}" was not found on Google Play Store. The app may have been removed, not yet published, or may only exist on unofficial/third-party sources.`,
        evidenceSnippet: `Package: ${packageId} | Brand: ${brandName} | Status: NOT FOUND on Google Play`,
        severity: "high",
        risk: "high",
      });
      return;
    }

    out.push({
      type: "official_app_found",
      category: "brand_abuse",
      platform: "Google Play Store",
      url: app.url ?? `https://play.google.com/store/apps/details?id=${packageId}`,
      title: `Official app: ${app.title} (${packageId})`,
      description: `Found official Google Play listing: "${app.title}" by "${app.developer}". ${app.installs ? `Installs: ${app.installs}.` : ""} Rating: ${app.score?.toFixed(1) ?? "N/A"}/5. This is the verified listing — monitor for clones.`,
      evidenceSnippet: `Package: ${packageId} | Developer: ${app.developer} | Installs: ${app.installs ?? "N/A"} | Score: ${app.score ?? "N/A"} | Updated: ${app.updated ?? "unknown"}`,
      severity: "info",
      risk: "low",
      installCount: app.installs ?? null,
      iconUrl: app.icon ?? null,
    });
  } catch (err: any) {
    logger.debug({ packageId, err: String(err) }, "Google Play direct lookup failed");
  }
}

async function searchGooglePlayByBrand(brandName: string, officialPackageId: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const apps = await (gplay as any).search({ term: brandName, num: 30, lang: "en", country: "us" }).catch(() => null) as any[] | null;
    if (!apps) return;

    const brandLower = brandName.toLowerCase().replace(/\s+/g, "");

    for (const app of apps) {
      const pkgId: string = app.appId ?? app.packageName ?? "";
      if (pkgId === officialPackageId) continue;

      const titleLower: string = (app.title ?? "").toLowerCase();
      const devLower: string   = (app.developer ?? "").toLowerCase().replace(/\s+/g, "");

      if (!titleLower.includes(brandName.toLowerCase()) && !pkgId.toLowerCase().includes(brandLower)) continue;

      const devMatchesBrand = devLower.includes(brandLower);

      out.push({
        type: devMatchesBrand ? "similar_app_same_dev" : "rogue_app",
        category: "brand_abuse",
        platform: "Google Play Store",
        url: app.url ?? `https://play.google.com/store/apps/details?id=${pkgId}`,
        title: devMatchesBrand
          ? `Similar app (same publisher): ${app.title}`
          : `⚠️ Potential rogue app: ${app.title}`,
        description: devMatchesBrand
          ? `"${app.title}" (${pkgId}) by "${app.developer}" also contains the brand name and appears to be from the same publisher.`
          : `"${app.title}" by "${app.developer}" uses brand name "${brandName}" but the developer does not match the official publisher (package: ${pkgId}). This may be a clone or counterfeit app.`,
        evidenceSnippet: `Package: ${pkgId} | Developer: ${app.developer} | Installs: ${app.installs ?? "N/A"} | Score: ${app.score ?? "N/A"}`,
        severity: devMatchesBrand ? "info" : "high",
        risk: devMatchesBrand ? "low" : "high",
        installCount: app.installs ?? null,
        iconUrl: app.icon ?? null,
      });

      if (out.filter(r => r.type === "rogue_app" && r.platform === "Google Play Store").length >= 10) break;
    }
  } catch { /* ignore */ }
}

async function searchAppleAppStore(searchName: string, packageId: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const brandLower = searchName.split(" ")[0]?.toLowerCase() ?? searchName.toLowerCase();
    const res = await orchestratedFetch(
      `https://itunes.apple.com/search?term=${encodeURIComponent(searchName)}&entity=software&limit=20`,
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return;
    const data = await res.json() as any;

    for (const app of ((data.results ?? []) as any[])) {
      const appNameLower: string = (app.trackName ?? "").toLowerCase();
      const sellerLower: string  = (app.sellerName ?? "").toLowerCase().replace(/\s+/g, "");

      if (!appNameLower.includes(brandLower)) continue;

      const isOfficialPublisher = sellerLower.includes(brandLower.replace(/\s+/g, ""));
      out.push({
        type: isOfficialPublisher ? "official_ios_app" : "rogue_app",
        category: "brand_abuse",
        platform: "Apple App Store",
        url: app.trackViewUrl ?? null,
        title: isOfficialPublisher
          ? `Official iOS app: ${app.trackName}`
          : `⚠️ Potential rogue iOS app: ${app.trackName}`,
        description: isOfficialPublisher
          ? `Official iOS app "${app.trackName}" by "${app.sellerName}" found on the Apple App Store.`
          : `iOS app "${app.trackName}" by "${app.sellerName}" uses the brand name "${searchName}" but the publisher doesn't match. This may be a counterfeit or clone app. ${app.averageUserRating ? `Rating: ${app.averageUserRating}/5` : ""}`,
        evidenceSnippet: `App ID: ${app.trackId} | Developer: ${app.sellerName} | Rating: ${app.averageUserRating ?? "N/A"} | Genre: ${app.primaryGenreName ?? "N/A"}`,
        severity: isOfficialPublisher ? "info" : "high",
        risk: isOfficialPublisher ? "low" : "high",
        iconUrl: app.artworkUrl60 ?? app.artworkUrl100 ?? null,
      });

      if (out.filter(r => r.platform === "Apple App Store").length >= 5) break;
    }
  } catch { /* ignore */ }
}

async function searchAPKPure(brandName: string, officialPackageId: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const brandLower = brandName.toLowerCase();

    const res = await orchestratedFetch(
      `https://apkpure.com/search?q=${encodeURIComponent(brandName)}`,
      {
        headers: { "User-Agent": "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36" },
        signal: AbortSignal.timeout(12_000),
      },
    ).catch(() => null);

    if (!res?.ok) return;
    const html = await res.text();
    const cards = html.match(/<li[^>]*class="[^"]*search-res[^"]*"[\s\S]*?<\/li>/gi) ?? [];

    for (const card of cards.slice(0, 10)) {
      const nameMatch = card.match(/<p[^>]*class="[^"]*search-title[^"]*"[^>]*>\s*([^<]+?)\s*<\/p>/i);
      const appName = (nameMatch?.[1] ?? "").trim();
      if (!appName.toLowerCase().includes(brandLower)) continue;

      const urlMatch  = card.match(/href="(\/[a-zA-Z0-9._%-]+(?:\/[a-zA-Z0-9._%-]+)+)"/i);
      const iconMatch = card.match(/<img[^>]+src="(https:\/\/(?:image\.winudf|cdn[^"]+apkpure)[^"]+)"[^>]*>/i);
      const instMatch = card.match(/([\d,.]+(?:\.\d+)?[KMB]?\+?)\s*(?:downloads?|installs?)/i);
      const appUrl    = urlMatch ? `https://apkpure.com${urlMatch[1]}` : `https://apkpure.com/search?q=${encodeURIComponent(brandName)}`;

      out.push({
        type: "rogue_app",
        category: "brand_abuse",
        platform: "APKPure",
        url: appUrl,
        title: `APKPure: ${appName}`,
        description: `"${appName}" found on APKPure (unofficial Android APK distribution). Third-party APK stores carry high risk of repackaged/malware-injected APKs for "${brandName}" brand.`,
        evidenceSnippet: `App: ${appName} | Source: APKPure (unofficial) | Brand keyword: ${brandName}`,
        severity: "high",
        risk: "high",
        installCount: instMatch?.[1] ?? null,
        iconUrl: iconMatch?.[1] ?? null,
      });

      if (out.filter(r => r.platform === "APKPure").length >= 5) break;
    }

    // Also check direct package page on APKPure
    const pkgProbe = await orchestratedFetch(
      `https://apkpure.com/${brandName.replace(/\s+/g, "-")}/${officialPackageId}`,
      { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(6_000) },
    ).catch(() => null);

    if (pkgProbe?.ok && pkgProbe.status !== 404) {
      out.push({
        type: "official_app_on_apkpure",
        category: "brand_abuse",
        platform: "APKPure",
        url: `https://apkpure.com/${brandName.replace(/\s+/g, "-")}/${officialPackageId}`,
        title: `"${officialPackageId}" available on APKPure`,
        description: `The package "${officialPackageId}" has a listing on APKPure. Users downloading from here may get unverified, modified, or outdated APKs with potential malware injection.`,
        evidenceSnippet: `Package: ${officialPackageId} | APKPure URL checked | HTTP: ${pkgProbe.status}`,
        severity: "high",
        risk: "high",
      });
    }
  } catch { /* ignore */ }
}

async function searchAptoide(brandName: string, officialPackageId: string, out: WatchlistScanResult[]): Promise<void> {
  try {
    const brandLower = brandName.toLowerCase();
    const res = await orchestratedFetch(
      `https://ws2.aptoide.com/api/7/apps/search/query/${encodeURIComponent(brandName)}/limit/10`,
      {
        headers: { "User-Agent": "Aptoide/9.20.6.1 (Linux; Android 12)", "Accept": "application/json" },
        signal: AbortSignal.timeout(12_000),
      },
    );
    if (!res.ok) return;
    const data = await res.json() as any;
    const apps: any[] = data?.datalist?.list ?? [];

    for (const app of apps) {
      const appNameLower: string = (app.name ?? "").toLowerCase();
      const pkgId: string = app.package ?? "";
      if (!appNameLower.includes(brandLower)) continue;
      if (pkgId === officialPackageId) continue;

      out.push({
        type: "rogue_app",
        category: "brand_abuse",
        platform: "Aptoide",
        url: app.urls?.w ?? `https://aptoide.com/en/${pkgId}`,
        title: `Aptoide: ${app.name}`,
        description: `"${app.name}" by "${app.developer?.name ?? "unknown"}" found on Aptoide (unofficial store) using brand name "${brandName}". Package: ${pkgId}.`,
        evidenceSnippet: `Package: ${pkgId} | Developer: ${app.developer?.name ?? "unknown"} | Downloads: ${app.stats?.downloads ?? "N/A"}`,
        severity: "high",
        risk: "high",
        installCount: app.stats?.downloads?.toString() ?? null,
      });

      if (out.filter(r => r.platform === "Aptoide").length >= 3) break;
    }
  } catch { /* ignore */ }
}

async function addAppDistributionLinks(packageId: string, brandName: string, out: WatchlistScanResult[]): Promise<void> {
  const slug = brandName.replace(/\s+/g, "-");
  const sites = [
    { name: "APKMirror",  url: `https://www.apkmirror.com/?s=${encodeURIComponent(brandName)}` },
    { name: "Uptodown",   url: `https://${slug}.en.uptodown.com/android` },
    { name: "SoftGoza",   url: `https://softgoza.com/search/${encodeURIComponent(packageId)}` },
  ];

  await Promise.allSettled(sites.map(async site => {
    try {
      const res = await orchestratedFetch(site.url, {
        method: "HEAD",
        headers: { "User-Agent": "Mozilla/5.0" },
        signal: AbortSignal.timeout(6_000),
      });
      if (res.ok || res.status === 405) {
        out.push({
          type: "apk_distribution_link",
          category: "brand_abuse",
          platform: site.name,
          url: site.url,
          title: `Check ${site.name} for "${brandName}" APKs`,
          description: `Manual review: ${site.name} may host unofficial versions of "${packageId}". Click to check for repackaged or modified APKs.`,
          evidenceSnippet: `Package: ${packageId} | Site: ${site.name} | HTTP: ${res.status}`,
          severity: "info",
          risk: "low",
        });
      }
    } catch { /* ignore */ }
  }));
}
