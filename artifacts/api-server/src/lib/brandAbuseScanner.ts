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
    checkMaliciousAppStorePatterns(brand, domain, results),
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
    { name: "Twitter/X", url: `https://twitter.com/${encodeURIComponent(handle)}` },
    { name: "Instagram", url: `https://instagram.com/${encodeURIComponent(handle)}` },
  ];
  for (const p of platforms) {
    try {
      const res = await fetch(p.url, {
        method: "HEAD",
        headers: { "User-Agent": "Mozilla/5.0" },
        signal: AbortSignal.timeout(5_000),
        redirect: "follow",
      });
      if (res.ok || res.status === 200 || res.status === 301 || res.status === 302) {
        out.push({
          type: "fake_social",
          platform: p.name,
          url: p.url,
          title: `@${handle} on ${p.name}`,
          description: `Watchlist social handle @${handle} found on ${p.name} — may be a brand impersonator for ${brand}`,
          evidenceSnippet: `HTTP ${res.status} response from ${p.url}`,
          risk: "medium",
        });
      }
    } catch {
      // Network error is fine — handle doesn't exist
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
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return;
    const certs = await res.json() as any[];

    const seen = new Set<string>();
    for (const cert of certs.slice(0, 200)) {
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
        description: `SSL certificate issued for '${cn}' which may be impersonating ${domain}. Issued: ${cert.not_before ?? "unknown"}.`,
        evidenceSnippet: `CN=${cn}, issuer=${cert.issuer_name ?? "unknown"}`,
        risk: "medium",
      });

      if (out.length >= 25) break;
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

  const checks = lookalikePrefixes.slice(0, 6).map(async (prefix) => {
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
            description: `Domain '${candidate}' is live and mimics brand name '${brand}'. Resolves to: ${addrs.join(", ")}`,
            evidenceSnippet: `A records: ${addrs.join(", ")}`,
            risk: "high",
          });
        }
      } catch {
        // expected — domain not found
      }
    }
  });

  await Promise.allSettled(checks);
}

async function checkMaliciousAppStorePatterns(
  brand: string,
  _domain: string,
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
        !sellerName.includes(brand.toLowerCase().replace(/\s+/g, "")) &&
        app.userRatingCountForCurrentVersion < 10;

      if (isSuspicious) {
        out.push({
          type: "rogue_app",
          platform: "Apple App Store",
          url: app.trackViewUrl ?? null,
          title: `Potential rogue app: ${app.trackName}`,
          description: `App '${app.trackName}' by '${app.sellerName}' uses brand name but doesn't appear to be official. Low ratings (${app.userRatingCountForCurrentVersion ?? 0} reviews).`,
          evidenceSnippet: `App ID: ${app.trackId}, Developer: ${app.sellerName}`,
          risk: "medium",
        });
      }
    }
  } catch {
    // App Store check is best-effort
  }
}
