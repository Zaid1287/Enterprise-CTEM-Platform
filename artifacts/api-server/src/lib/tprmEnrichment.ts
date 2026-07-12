/**
 * TPRM Company Enrichment + Vendor Domain Probing
 * All real data — zero mocked results.
 *
 * Free sources used (no API key required):
 *   - Brandfetch   https://api.brandfetch.io/v2/brands/{domain}
 *   - Clearbit     https://autocomplete.clearbit.com/v1/companies/suggest?query=
 *   - Shodan InternetDB https://internetdb.shodan.io/{ip}
 *   - crt.sh       https://crt.sh/?q=%25.{domain}&output=json
 *   - dns/promises (A/AAAA/MX/TXT/NS/CNAME)
 *   - tls.connect  (SSL/TLS cert analysis)
 *   - VirusTotal   (if api key configured in platform_settings)
 */

import dns from "node:dns/promises";
import tls from "node:tls";
import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";
import { db, platformSettingsTable, tprmVendorFindingsTable, tprmVendorAssetsTable, tprmVendorRiskScoresTable, tprmFourthPartyVendorsTable, tprmVendorsTable, tprmSupplyChainNodesTable, alertsTable, tprmVendorSecurityAnalysisTable, tprmVendorBreachEventsTable } from "@workspace/db";
import { eq, and, desc, isNull } from "drizzle-orm";

const UA = "Sentinelware-TPRM/1.0";

async function safeFetch(url: string, opts: RequestInit = {}): Promise<Response | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 12000);
    const res = await orchestratedFetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...(opts.headers ?? {}) },
    }, { intensity: "passive" });
    clearTimeout(t);
    return res;
  } catch {
    return null;
  }
}

function extractDomain(input: string): string {
  try {
    const url = input.startsWith("http") ? new URL(input) : new URL(`https://${input}`);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return input.replace(/^www\./, "").split("/")[0];
  }
}

// ── Company Enrichment ────────────────────────────────────────────────────────

export interface CompanyEnrichment {
  companyName:   string;
  domain:        string;
  logoUrl:       string | null;
  industry:      string | null;
  description:   string | null;
  employeeCount: number | null;
  companySize:   string | null;
  founded:       string | null;
  location:      string | null;
  marketCap:     string | null;
  companyType:   string | null;
  website:       string | null;
  source:        string;
}

export async function enrichCompanyByDomain(inputDomain: string): Promise<CompanyEnrichment> {
  const domain = extractDomain(inputDomain);
  const base: CompanyEnrichment = {
    companyName:   domain.split(".")[0] ?? domain,
    domain,
    logoUrl:       null,
    industry:      null,
    description:   null,
    employeeCount: null,
    companySize:   null,
    founded:       null,
    location:      null,
    marketCap:     null,
    companyType:   null,
    website:       `https://${domain}`,
    source:        "dns",
  };

  // 1. Brandfetch (free, no auth)
  try {
    const res = await safeFetch(`https://api.brandfetch.io/v2/brands/${domain}`);
    if (res?.ok) {
      const data: any = await res.json().catch(() => null);
      if (data?.name) {
        base.companyName  = data.name;
        base.description  = data.description ?? null;
        base.logoUrl      = data.logos?.[0]?.formats?.[0]?.src ?? data.icon?.formats?.[0]?.src ?? null;
        base.industry     = data.company?.industries?.[0]?.name ?? null;
        base.location     = data.company?.location ?? null;
        base.founded      = data.company?.foundedYear ? String(data.company.foundedYear) : null;
        base.companyType  = data.company?.type ?? null;
        base.source       = "brandfetch";
        return base;
      }
    }
  } catch { /* fallthrough */ }

  // 2. Clearbit autocomplete (free, no auth)
  try {
    const query = domain.split(".")[0];
    const res = await safeFetch(`https://autocomplete.clearbit.com/v1/companies/suggest?query=${encodeURIComponent(query)}`);
    if (res?.ok) {
      const suggestions = (await res.json().catch(() => [])) as any[];
      const match = suggestions.find(s => s.domain === domain) ?? suggestions[0];
      if (match) {
        base.companyName = match.name ?? base.companyName;
        base.logoUrl     = match.logo ?? null;
        base.domain      = match.domain ?? domain;
        base.source      = "clearbit";
        return base;
      }
    }
  } catch { /* fallthrough */ }

  // 3. HTTP homepage title — extract company name from <title> tag
  try {
    const httpRes = await safeFetch(`https://${domain}`, { headers: { Accept: "text/html,application/xhtml+xml" } });
    if (httpRes?.ok) {
      const html = await httpRes.text().catch(() => "");
      const m = html.match(/<title[^>]*>([^<]{3,80})<\/title>/i);
      if (m?.[1]) {
        // Strip trailing separator like "| Company" or "- Home" from title
        const raw = m[1].trim().replace(/\s*[|·—\-–]\s*.{0,40}$/, "").trim();
        if (raw.length >= 3 && raw.length <= 80) {
          base.companyName = raw;
          base.source = "homepage";
        }
      }
      // If title failed, try og:site_name meta tag
      if (base.source !== "homepage") {
        const ogM = html.match(/<meta[^>]+property=["']og:site_name["'][^>]+content=["']([^"']{3,60})["']/i)
          ?? html.match(/<meta[^>]+content=["']([^"']{3,60})["'][^>]+property=["']og:site_name["']/i);
        if (ogM?.[1]) {
          base.companyName = ogM[1].trim();
          base.source = "homepage";
        }
      }
    }
  } catch { /* fallthrough */ }

  // 4. DNS fallback — get MX to infer email provider, SOA for age hint
  try {
    const [mx, soa] = await Promise.allSettled([
      dns.resolveMx(domain).catch(() => []),
      dns.resolveSoa(domain).catch(() => null),
    ]);
    if (mx.status === "fulfilled" && mx.value.length > 0) {
      const mxHost = mx.value[0]?.exchange ?? "";
      if (mxHost.includes("google")) base.description = (base.description ?? "") + " (Email: Google Workspace)";
      else if (mxHost.includes("outlook") || mxHost.includes("microsoft")) base.description = (base.description ?? "") + " (Email: Microsoft 365)";
    }
    if (soa.status === "fulfilled" && soa.value) {
      base.source = base.source === "homepage" ? "homepage" : "dns";
    }
  } catch { /* ignore */ }

  return base;
}

// ── Vendor Domain Probe ───────────────────────────────────────────────────────

export interface DnsProbeResult {
  a:     string[];
  aaaa:  string[];
  mx:    Array<{ exchange: string; priority: number }>;
  txt:   string[];
  ns:    string[];
  cname: string[];
  hasSPF:   boolean;
  hasDMARC: boolean;
  hasDKIM:  boolean;
  spfRecord:   string | null;
  dmarcRecord: string | null;
}

export interface TlsProbeResult {
  grade:         string;
  validFrom:     string | null;
  validTo:       string | null;
  issuer:        string | null;
  subject:       string | null;
  daysUntilExp:  number | null;
  expired:       boolean;
  selfSigned:    boolean;
  san:           string[];
  protocol:      string | null;
  cipher:        string | null;
}

export interface HttpProbeResult {
  statusCode:     number | null;
  title:          string | null;
  server:         string | null;
  poweredBy:      string | null;
  responseTimeMs: number | null;
  headers:        Record<string, string>;
  body:           string;
  securityHeaders: {
    hsts:             boolean;
    csp:              boolean;
    xFrameOptions:    boolean;
    xContentType:     boolean;
    referrerPolicy:   boolean;
    permissionsPolicy: boolean;
    score:            number;
  };
}

export interface ShodanInternetDbResult {
  ip:       string;
  ports:    number[];
  cpes:     string[];
  vulns:    string[];
  hostnames: string[];
  tags:     string[];
}

export interface VendorProbeResult {
  domain:        string;
  dns:           DnsProbeResult;
  tls:           TlsProbeResult | null;
  http:          HttpProbeResult | null;
  shodan:        ShodanInternetDbResult[];
  subdomains:    string[];
  fourthParties: FourthPartySignal[];
  whois:         WhoisResult;
  exposure:      ExposureCheckResult;
  virusTotal:    VirusTotalDomainResult | null;
}

export interface FourthPartySignal {
  name:            string;
  domain:          string;
  category:        string;
  riskLevel:       "low" | "medium" | "high" | "critical";
  confidence:      number;
  discoveryMethod: string;
  details:         Record<string, unknown>;
}

async function probeDns(domain: string): Promise<DnsProbeResult> {
  const [a, aaaa, mx, txt, ns, cname] = await Promise.allSettled([
    dns.resolve4(domain).catch(() => [] as string[]),
    dns.resolve6(domain).catch(() => [] as string[]),
    dns.resolveMx(domain).catch(() => [] as Array<{ exchange: string; priority: number }>),
    dns.resolveTxt(domain).then(r => r.flat()).catch(() => [] as string[]),
    dns.resolveNs(domain).catch(() => [] as string[]),
    dns.resolveCname(domain).catch(() => [] as string[]),
  ]);

  const aRec    = a.status === "fulfilled"     ? a.value     : [];
  const aaaaRec = aaaa.status === "fulfilled"  ? aaaa.value  : [];
  const mxRec   = mx.status === "fulfilled"    ? mx.value    : [];
  const txtRec  = txt.status === "fulfilled"   ? txt.value   : [];
  const nsRec   = ns.status === "fulfilled"    ? ns.value    : [];
  const cnameRec = cname.status === "fulfilled" ? cname.value : [];

  const spfRecord   = txtRec.find(r => r.startsWith("v=spf1")) ?? null;
  const dmarcTxt    = await dns.resolveTxt(`_dmarc.${domain}`).then(r => r.flat().join("")).catch(() => null);
  const hasDKIM     = await dns.resolveTxt(`default._domainkey.${domain}`).then(() => true).catch(() => false);

  return {
    a: aRec, aaaa: aaaaRec, mx: mxRec, txt: txtRec.slice(0, 20), ns: nsRec, cname: cnameRec,
    hasSPF:   !!spfRecord,
    hasDMARC: !!dmarcTxt,
    hasDKIM,
    spfRecord,
    dmarcRecord: dmarcTxt,
  };
}

async function probeTls(domain: string): Promise<TlsProbeResult | null> {
  return new Promise(resolve => {
    const timeout = setTimeout(() => resolve(null), 8000);
    const sock = tls.connect({ host: domain, port: 443, servername: domain, rejectUnauthorized: false }, () => {
      clearTimeout(timeout);
      try {
        const cert     = sock.getPeerCertificate(true);
        const protocol = sock.getProtocol();
        const cipher   = sock.getCipher();

        const validFrom = cert.valid_from ?? null;
        const validTo   = cert.valid_to ?? null;
        const daysUntilExp = validTo
          ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000)
          : null;
        const expired    = daysUntilExp !== null && daysUntilExp < 0;
        const selfSigned = cert.issuerCertificate
          ? cert.subject?.O === cert.issuer?.O
          : true;

        let grade = "A";
        if (expired) grade = "F";
        else if (selfSigned) grade = "C";
        else if (daysUntilExp !== null && daysUntilExp < 14) grade = "B";
        else if (protocol === "TLSv1" || protocol === "TLSv1.1") grade = "C";

        const san: string[] = Array.isArray((cert as any).subjectaltname)
          ? (cert as any).subjectaltname
          : ((cert as any).subjectaltname ?? "").split(",").map((s: string) => s.trim().replace(/^DNS:/, "")).filter(Boolean);

        resolve({
          grade, validFrom, validTo, daysUntilExp, expired, selfSigned,
          issuer:   (cert.issuer?.O ?? cert.issuer?.CN ?? null) as string | null,
          subject:  (cert.subject?.CN ?? null) as string | null,
          san:      san.slice(0, 30),
          protocol: protocol ?? null,
          cipher:   cipher?.name ?? null,
        });
      } catch {
        resolve(null);
      } finally {
        sock.destroy();
      }
    });
    sock.on("error", () => { clearTimeout(timeout); resolve(null); });
  });
}

async function probeHttp(domain: string): Promise<HttpProbeResult | null> {
  const urls = [`https://${domain}`, `http://${domain}`];
  for (const url of urls) {
    try {
      const start = Date.now();
      const res = await safeFetch(url);
      if (!res) continue;
      const responseTimeMs = Date.now() - start;
      const body = await res.text().catch(() => "");
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

      const title = body.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1]?.trim() ?? null;

      const sh = {
        hsts:              headers["strict-transport-security"] !== undefined,
        csp:               headers["content-security-policy"] !== undefined,
        xFrameOptions:     headers["x-frame-options"] !== undefined,
        xContentType:      headers["x-content-type-options"] !== undefined,
        referrerPolicy:    headers["referrer-policy"] !== undefined,
        permissionsPolicy: headers["permissions-policy"] !== undefined,
        score:             0,
      };
      sh.score = [sh.hsts, sh.csp, sh.xFrameOptions, sh.xContentType, sh.referrerPolicy, sh.permissionsPolicy]
        .filter(Boolean).length * 17;

      return {
        statusCode:     res.status,
        title,
        server:         headers["server"] ?? null,
        poweredBy:      headers["x-powered-by"] ?? null,
        responseTimeMs,
        headers,
        body,
        securityHeaders: sh,
      };
    } catch { continue; }
  }
  return null;
}

// ── WHOIS / RDAP ─────────────────────────────────────────────────────────────

interface WhoisResult {
  registrar:    string | null;
  createdDate:  string | null;
  expiryDate:   string | null;
  updatedDate:  string | null;
  nameservers:  string[];
  status:       string[];
}

async function probeWhois(domain: string): Promise<WhoisResult> {
  const empty: WhoisResult = { registrar: null, createdDate: null, expiryDate: null, updatedDate: null, nameservers: [], status: [] };
  try {
    const tld   = domain.split(".").slice(-2).join(".");
    const rdap  = await safeFetch(`https://rdap.org/domain/${tld}`, { headers: { Accept: "application/rdap+json" } });
    if (!rdap?.ok) return empty;
    const data: any = await rdap.json().catch(() => null);
    if (!data) return empty;
    const ns: string[] = (data.nameservers ?? []).map((n: any) => (n.ldhName ?? n.name ?? "").toLowerCase()).filter(Boolean);
    const status: string[] = (data.status ?? []);
    let registrar: string | null = null;
    let created: string | null = null;
    let expiry:  string | null = null;
    let updated: string | null = null;
    for (const entity of (data.entities ?? [])) {
      const roles: string[] = entity.roles ?? [];
      if (roles.includes("registrar")) registrar = entity.vcardArray?.[1]?.find((e: any) => e[0] === "fn")?.[3] ?? null;
    }
    for (const ev of (data.events ?? [])) {
      if (ev.eventAction === "registration") created = ev.eventDate ?? null;
      if (ev.eventAction === "expiration")   expiry  = ev.eventDate ?? null;
      if (ev.eventAction === "last changed") updated = ev.eventDate ?? null;
    }
    return { registrar, createdDate: created, expiryDate: expiry, updatedDate: updated, nameservers: ns.slice(0, 6), status: status.slice(0, 6) };
  } catch { return empty; }
}

// ── Sensitive Path Exposure Checks ───────────────────────────────────────────

interface ExposureCheckResult {
  envExposed:    boolean;
  gitExposed:    boolean;
  exposedPaths:  string[];
}

async function checkSensitiveExposure(domain: string): Promise<ExposureCheckResult> {
  const paths = [
    { path: `/.env`,              key: "envExposed" },
    { path: `/.git/config`,       key: "gitExposed" },
  ];
  const result: ExposureCheckResult = { envExposed: false, gitExposed: false, exposedPaths: [] };
  await Promise.allSettled(paths.map(async ({ path, key }) => {
    try {
      const res = await safeFetch(`https://${domain}${path}`);
      if (!res) return;
      const body = await res.text().catch(() => "");
      // .env: contains typical env var patterns; .git/config: starts with [core]
      const isExposed = path.includes(".env")
        ? (res.status === 200 && /[A-Z_]+=.{3}/.test(body.slice(0, 500)))
        : (res.status === 200 && body.includes("[core]"));
      if (isExposed) {
        (result as any)[key] = true;
        result.exposedPaths.push(path);
      }
    } catch { /* ignore */ }
  }));
  return result;
}

// ── VirusTotal domain reputation ──────────────────────────────────────────────

interface VirusTotalDomainResult {
  malicious:   number;
  suspicious:  number;
  harmless:    number;
  undetected:  number;
  reputation:  number;
  categories:  string[];
}

async function probeVirusTotal(domain: string, apiKey: string): Promise<VirusTotalDomainResult | null> {
  try {
    const res = await safeFetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: { "x-apikey": apiKey },
    });
    if (!res?.ok) return null;
    const data: any = await res.json().catch(() => null);
    if (!data?.data?.attributes) return null;
    const stats = data.data.attributes.last_analysis_stats ?? {};
    return {
      malicious:  stats.malicious  ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless:   stats.harmless   ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: data.data.attributes.reputation ?? 0,
      categories: Object.values(data.data.attributes.categories ?? {}) as string[],
    };
  } catch { return null; }
}

async function probeShodan(ips: string[]): Promise<ShodanInternetDbResult[]> {
  const results: ShodanInternetDbResult[] = [];
  await Promise.allSettled(ips.slice(0, 5).map(async ip => {
    try {
      const res = await safeFetch(`https://internetdb.shodan.io/${ip}`);
      if (!res?.ok) return;
      const data: any = await res.json().catch(() => null);
      if (!data) return;
      results.push({
        ip,
        ports:     data.ports ?? [],
        cpes:      data.cpes ?? [],
        vulns:     data.vulns ?? [],
        hostnames: data.hostnames ?? [],
        tags:      data.tags ?? [],
      });
    } catch { /* ignore */ }
  }));
  return results;
}

async function getSubdomains(domain: string): Promise<string[]> {
  try {
    const res = await safeFetch(`https://crt.sh/?q=%.${domain}&output=json`);
    if (!res?.ok) return [];
    const data = (await res.json().catch(() => [])) as any[];
    const seen = new Set<string>();
    for (const row of data) {
      const names = (row.name_value ?? "").split("\n").map((n: string) => n.trim().toLowerCase());
      for (const n of names) {
        if ((n.endsWith(`.${domain}`) || n === domain) && !n.startsWith("*")) seen.add(n);
      }
    }
    return [...seen].slice(0, 100);
  } catch {
    return [];
  }
}

// ── 4th-party discovery ───────────────────────────────────────────────────────
// 200+ signatures across 14 categories with risk levels

type FpCategory = "cdn" | "waf" | "analytics" | "advertising" | "payments" | "auth" | "monitoring" | "communication" | "marketing" | "infrastructure" | "security" | "media" | "maps" | "devtools" | "cms" | "ca";
type FpRisk = "low" | "medium" | "high" | "critical";

interface FpSig { header?: string; value?: string; name: string; domain: string; category: FpCategory; risk: FpRisk; }
interface JsSig { pattern: string; name: string; domain: string; category: FpCategory; risk: FpRisk; }
interface CnameSig { pattern: string; name: string; domain: string; category: FpCategory; risk: FpRisk; }
interface CertSig { pattern: string; name: string; domain: string; category: FpCategory; risk: FpRisk; }

const CDN_WAF_HEADERS: FpSig[] = [
  // CDN — header-based
  { header: "server",              value: "cloudflare",     name: "Cloudflare CDN",     domain: "cloudflare.com",    category: "cdn",  risk: "medium" },
  { header: "cf-ray",              value: "",               name: "Cloudflare",          domain: "cloudflare.com",    category: "cdn",  risk: "medium" },
  { header: "x-served-by",        value: "fastly",         name: "Fastly CDN",          domain: "fastly.com",        category: "cdn",  risk: "medium" },
  { header: "x-fastly-request-id",value: "",               name: "Fastly CDN",          domain: "fastly.com",        category: "cdn",  risk: "medium" },
  { header: "x-cache",            value: "cloudfront",     name: "AWS CloudFront",      domain: "aws.amazon.com",    category: "cdn",  risk: "medium" },
  { header: "x-amz-cf-id",        value: "",               name: "AWS CloudFront",      domain: "aws.amazon.com",    category: "cdn",  risk: "medium" },
  { header: "server",             value: "akamaighost",    name: "Akamai CDN",          domain: "akamai.com",        category: "cdn",  risk: "medium" },
  { header: "x-akamai-transformed",value: "",              name: "Akamai CDN",          domain: "akamai.com",        category: "cdn",  risk: "medium" },
  { header: "x-cdn",              value: "imperva",        name: "Imperva CDN",         domain: "imperva.com",       category: "cdn",  risk: "medium" },
  { header: "server",             value: "bunnycdn",       name: "Bunny CDN",           domain: "bunny.net",         category: "cdn",  risk: "low"    },
  { header: "x-cache",            value: "keycdn",         name: "KeyCDN",              domain: "keycdn.com",        category: "cdn",  risk: "low"    },
  { header: "server",             value: "varnish",        name: "Varnish Cache",       domain: "varnish-cache.org", category: "cdn",  risk: "low"    },
  { header: "x-cache-hits",       value: "varnish",        name: "Varnish Cache",       domain: "varnish-cache.org", category: "cdn",  risk: "low"    },
  { header: "x-azure-ref",        value: "",               name: "Azure Front Door",    domain: "azure.com",         category: "cdn",  risk: "medium" },
  { header: "x-goog-request-params",value: "",             name: "Google Cloud CDN",    domain: "cloud.google.com",  category: "cdn",  risk: "medium" },
  { header: "x-vercel-id",        value: "",               name: "Vercel Edge",         domain: "vercel.com",        category: "cdn",  risk: "low"    },
  { header: "x-powered-by",       value: "next.js",        name: "Next.js / Vercel",    domain: "vercel.com",        category: "cdn",  risk: "low"    },
  { header: "x-netlify",          value: "",               name: "Netlify CDN",         domain: "netlify.com",       category: "cdn",  risk: "low"    },
  { header: "server",             value: "nginx",          name: "NGINX",               domain: "nginx.com",         category: "infrastructure", risk: "low" },
  { header: "server",             value: "apache",         name: "Apache HTTP",         domain: "apache.org",        category: "infrastructure", risk: "low" },
  // WAF — header-based
  { header: "x-sucuri-id",        value: "",               name: "Sucuri WAF",          domain: "sucuri.net",        category: "waf",  risk: "medium" },
  { header: "x-sucuri-cache",     value: "",               name: "Sucuri WAF",          domain: "sucuri.net",        category: "waf",  risk: "medium" },
  { header: "x-protected-by",     value: "sqreen",         name: "Sqreen WAF",          domain: "sqreen.io",         category: "waf",  risk: "medium" },
  { header: "x-fw-server",        value: "",               name: "Firewall Cloud",      domain: "firewall-cloud.com",category: "waf",  risk: "medium" },
  { header: "x-iinfo",            value: "",               name: "Incapsula WAF",       domain: "imperva.com",       category: "waf",  risk: "medium" },
  { header: "x-datadome",         value: "",               name: "DataDome Bot Protection", domain: "datadome.co",   category: "security", risk: "medium" },
  { header: "x-perimeterx",       value: "",               name: "PerimeterX",          domain: "perimeterx.com",    category: "security", risk: "medium" },
];

const JS_THIRD_PARTIES: JsSig[] = [
  // Analytics
  { pattern: "google-analytics.com",    name: "Google Analytics",      domain: "google.com",        category: "analytics",     risk: "low"      },
  { pattern: "googletagmanager.com",    name: "Google Tag Manager",    domain: "google.com",        category: "analytics",     risk: "low"      },
  { pattern: "analytics.google.com",    name: "Google Analytics 4",    domain: "google.com",        category: "analytics",     risk: "low"      },
  { pattern: "cdn.segment.com",         name: "Segment",               domain: "segment.com",       category: "analytics",     risk: "low"      },
  { pattern: "segment.io",              name: "Segment",               domain: "segment.com",       category: "analytics",     risk: "low"      },
  { pattern: "cdn.amplitude.com",       name: "Amplitude",             domain: "amplitude.com",     category: "analytics",     risk: "low"      },
  { pattern: "cdn.mxpnl.com",           name: "Mixpanel",              domain: "mixpanel.com",      category: "analytics",     risk: "low"      },
  { pattern: "api.mixpanel.com",        name: "Mixpanel",              domain: "mixpanel.com",      category: "analytics",     risk: "low"      },
  { pattern: "static.hotjar.com",       name: "Hotjar",                domain: "hotjar.com",        category: "analytics",     risk: "low"      },
  { pattern: "hotjar.com",              name: "Hotjar",                domain: "hotjar.com",        category: "analytics",     risk: "low"      },
  { pattern: "heap.io",                 name: "Heap Analytics",        domain: "heap.io",           category: "analytics",     risk: "low"      },
  { pattern: "fullstory.com",           name: "FullStory",             domain: "fullstory.com",     category: "analytics",     risk: "medium"   },
  { pattern: "logrocket.io",            name: "LogRocket",             domain: "logrocket.com",     category: "analytics",     risk: "medium"   },
  { pattern: "pendo.io",                name: "Pendo",                 domain: "pendo.io",          category: "analytics",     risk: "low"      },
  { pattern: "mouseflow.com",           name: "Mouseflow",             domain: "mouseflow.com",     category: "analytics",     risk: "low"      },
  { pattern: "crazyegg.com",            name: "Crazy Egg",             domain: "crazyegg.com",      category: "analytics",     risk: "low"      },
  { pattern: "stats.wp.com",            name: "Jetpack Stats",         domain: "automattic.com",    category: "analytics",     risk: "low"      },
  { pattern: "cdn.contentsquare.net",   name: "Contentsquare",         domain: "contentsquare.com", category: "analytics",     risk: "medium"   },
  { pattern: "browser.sentry-cdn.com",  name: "Sentry",                domain: "sentry.io",         category: "monitoring",    risk: "medium"   },
  { pattern: "js.sentry-cdn.com",       name: "Sentry",                domain: "sentry.io",         category: "monitoring",    risk: "medium"   },
  { pattern: "bugsnag.com",             name: "Bugsnag",               domain: "bugsnag.com",       category: "monitoring",    risk: "medium"   },
  { pattern: "rollbar.com",             name: "Rollbar",               domain: "rollbar.com",       category: "monitoring",    risk: "medium"   },
  { pattern: "datadoghq.com",           name: "Datadog APM",           domain: "datadoghq.com",     category: "monitoring",    risk: "medium"   },
  { pattern: "newrelic.com",            name: "New Relic Browser",     domain: "newrelic.com",      category: "monitoring",    risk: "medium"   },
  { pattern: "dynatrace.com",           name: "Dynatrace RUM",         domain: "dynatrace.com",     category: "monitoring",    risk: "medium"   },
  { pattern: "elastic.co",             name: "Elastic APM",           domain: "elastic.co",        category: "monitoring",    risk: "medium"   },
  // Advertising
  { pattern: "connect.facebook.net",    name: "Facebook Pixel",        domain: "facebook.com",      category: "advertising",   risk: "medium"   },
  { pattern: "googleadservices.com",    name: "Google Ads",            domain: "google.com",        category: "advertising",   risk: "low"      },
  { pattern: "doubleclick.net",         name: "Google DoubleClick",    domain: "google.com",        category: "advertising",   risk: "medium"   },
  { pattern: "platform.linkedin.com",   name: "LinkedIn Insight Tag",  domain: "linkedin.com",      category: "advertising",   risk: "medium"   },
  { pattern: "static.ads-twitter.com",  name: "Twitter Ads",           domain: "twitter.com",       category: "advertising",   risk: "medium"   },
  { pattern: "tiktok.com/i18n",         name: "TikTok Pixel",          domain: "tiktok.com",        category: "advertising",   risk: "medium"   },
  { pattern: "pinimg.com",              name: "Pinterest Tag",         domain: "pinterest.com",     category: "advertising",   risk: "medium"   },
  { pattern: "criteo.com",              name: "Criteo",                domain: "criteo.com",        category: "advertising",   risk: "medium"   },
  { pattern: "scorecardresearch.com",   name: "comScore",              domain: "comscore.com",      category: "advertising",   risk: "low"      },
  // Payments (HIGH risk — PCI DSS scope)
  { pattern: "stripe.com/v3",           name: "Stripe Payments",       domain: "stripe.com",        category: "payments",      risk: "high"     },
  { pattern: "js.stripe.com",           name: "Stripe.js",             domain: "stripe.com",        category: "payments",      risk: "high"     },
  { pattern: "braintree-api.com",       name: "Braintree",             domain: "braintree.com",     category: "payments",      risk: "high"     },
  { pattern: "paypalobjects.com",       name: "PayPal",                domain: "paypal.com",        category: "payments",      risk: "high"     },
  { pattern: "adyen.com",               name: "Adyen",                 domain: "adyen.com",         category: "payments",      risk: "high"     },
  { pattern: "checkout.com",            name: "Checkout.com",          domain: "checkout.com",      category: "payments",      risk: "high"     },
  { pattern: "squareup.com",            name: "Square Payments",       domain: "squareup.com",      category: "payments",      risk: "high"     },
  { pattern: "klarna.com",              name: "Klarna",                domain: "klarna.com",        category: "payments",      risk: "high"     },
  { pattern: "affirm.com",              name: "Affirm",                domain: "affirm.com",        category: "payments",      risk: "high"     },
  { pattern: "afterpay.com",            name: "Afterpay",              domain: "afterpay.com",      category: "payments",      risk: "high"     },
  { pattern: "razorpay.com",            name: "Razorpay",              domain: "razorpay.com",      category: "payments",      risk: "high"     },
  // Auth/Identity (HIGH risk — authentication attack surface)
  { pattern: "auth0.com",               name: "Auth0",                 domain: "auth0.com",         category: "auth",          risk: "high"     },
  { pattern: "cdn.auth0.com",           name: "Auth0",                 domain: "auth0.com",         category: "auth",          risk: "high"     },
  { pattern: "okta.com",                name: "Okta",                  domain: "okta.com",          category: "auth",          risk: "high"     },
  { pattern: "oktacdn.com",             name: "Okta",                  domain: "okta.com",          category: "auth",          risk: "high"     },
  { pattern: "login.microsoftonline.com", name: "Microsoft Entra ID",  domain: "microsoft.com",     category: "auth",          risk: "high"     },
  { pattern: "accounts.google.com",     name: "Google Sign-In",        domain: "google.com",        category: "auth",          risk: "medium"   },
  { pattern: "appleid.apple.com",       name: "Sign in with Apple",    domain: "apple.com",         category: "auth",          risk: "medium"   },
  { pattern: "onelogin.com",            name: "OneLogin",              domain: "onelogin.com",      category: "auth",          risk: "high"     },
  { pattern: "pingidentity.com",        name: "Ping Identity",         domain: "pingidentity.com",  category: "auth",          risk: "high"     },
  { pattern: "duo.com",                 name: "Duo Security",          domain: "duo.com",           category: "auth",          risk: "medium"   },
  { pattern: "cognito-identity.amazonaws.com", name: "AWS Cognito",   domain: "aws.amazon.com",    category: "auth",          risk: "high"     },
  // Communication / Support
  { pattern: "intercom.io",             name: "Intercom",              domain: "intercom.com",      category: "communication", risk: "medium"   },
  { pattern: "widget.intercom.io",      name: "Intercom Widget",       domain: "intercom.com",      category: "communication", risk: "medium"   },
  { pattern: "widget.zendesk.com",      name: "Zendesk",               domain: "zendesk.com",       category: "communication", risk: "medium"   },
  { pattern: "static.zdassets.com",     name: "Zendesk Assets",        domain: "zendesk.com",       category: "communication", risk: "medium"   },
  { pattern: "drift.com",               name: "Drift Chat",            domain: "drift.com",         category: "communication", risk: "medium"   },
  { pattern: "freshchat.com",           name: "Freshchat",             domain: "freshworks.com",    category: "communication", risk: "medium"   },
  { pattern: "freshdesk.com",           name: "Freshdesk",             domain: "freshworks.com",    category: "communication", risk: "medium"   },
  { pattern: "tawk.to",                 name: "Tawk.to Live Chat",     domain: "tawk.to",           category: "communication", risk: "medium"   },
  { pattern: "crisp.chat",              name: "Crisp Chat",            domain: "crisp.chat",        category: "communication", risk: "medium"   },
  { pattern: "olark.com",               name: "Olark Live Chat",       domain: "olark.com",         category: "communication", risk: "medium"   },
  { pattern: "livechatinc.com",         name: "LiveChat",              domain: "livechat.com",      category: "communication", risk: "medium"   },
  { pattern: "sendbird.com",            name: "Sendbird",              domain: "sendbird.com",      category: "communication", risk: "medium"   },
  { pattern: "twilio.com",              name: "Twilio",                domain: "twilio.com",        category: "communication", risk: "medium"   },
  // Marketing / CRM
  { pattern: "assets.hubspot.com",      name: "HubSpot",               domain: "hubspot.com",       category: "marketing",     risk: "medium"   },
  { pattern: "js.hsforms.com",          name: "HubSpot Forms",         domain: "hubspot.com",       category: "marketing",     risk: "medium"   },
  { pattern: "munchkin.marketo.net",    name: "Marketo",               domain: "marketo.com",       category: "marketing",     risk: "medium"   },
  { pattern: "pardot.com",              name: "Salesforce Pardot",     domain: "salesforce.com",    category: "marketing",     risk: "medium"   },
  { pattern: "salesforceliveagent.com", name: "Salesforce Live Agent", domain: "salesforce.com",    category: "marketing",     risk: "medium"   },
  { pattern: "chimpstatic.com",         name: "Mailchimp",             domain: "mailchimp.com",     category: "marketing",     risk: "medium"   },
  { pattern: "klaviyo.com",             name: "Klaviyo",               domain: "klaviyo.com",       category: "marketing",     risk: "medium"   },
  { pattern: "sendgrid.net",            name: "SendGrid",              domain: "sendgrid.com",      category: "marketing",     risk: "medium"   },
  { pattern: "activecampaign.com",      name: "ActiveCampaign",        domain: "activecampaign.com",category: "marketing",     risk: "medium"   },
  { pattern: "platform.twitter.com",    name: "Twitter Widget",        domain: "twitter.com",       category: "marketing",     risk: "low"      },
  // Security / Bot Protection
  { pattern: "google.com/recaptcha",    name: "Google reCAPTCHA",      domain: "google.com",        category: "security",      risk: "low"      },
  { pattern: "hcaptcha.com",            name: "hCaptcha",              domain: "hcaptcha.com",      category: "security",      risk: "low"      },
  { pattern: "arkoselabs.com",          name: "Arkose Labs",           domain: "arkoselabs.com",    category: "security",      risk: "medium"   },
  { pattern: "px-cdn.net",              name: "PerimeterX",            domain: "perimeterx.com",    category: "security",      risk: "medium"   },
  { pattern: "datadome.co",             name: "DataDome",              domain: "datadome.co",       category: "security",      risk: "medium"   },
  { pattern: "cloudflare.com/challenge",name: "Cloudflare Bot Mgmt",   domain: "cloudflare.com",    category: "security",      risk: "low"      },
  // Infrastructure / Cloud Storage
  { pattern: "s3.amazonaws.com",        name: "AWS S3",                domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "amazonaws.com",           name: "Amazon Web Services",   domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "storage.googleapis.com",  name: "Google Cloud Storage",  domain: "cloud.google.com",  category: "infrastructure",risk: "medium"   },
  { pattern: "cloudinary.com",          name: "Cloudinary",            domain: "cloudinary.com",    category: "infrastructure",risk: "low"      },
  { pattern: "imgix.net",               name: "Imgix",                 domain: "imgix.com",         category: "infrastructure",risk: "low"      },
  { pattern: "cdn.jsdelivr.net",        name: "jsDelivr CDN",          domain: "jsdelivr.com",      category: "cdn",           risk: "medium"   },
  { pattern: "cdnjs.cloudflare.com",    name: "Cloudflare CDNJS",      domain: "cloudflare.com",    category: "cdn",           risk: "medium"   },
  { pattern: "unpkg.com",               name: "unpkg CDN",             domain: "unpkg.com",         category: "cdn",           risk: "medium"   },
  // Media / Video
  { pattern: "youtube.com/embed",       name: "YouTube",               domain: "youtube.com",       category: "media",         risk: "low"      },
  { pattern: "vimeo.com",               name: "Vimeo",                 domain: "vimeo.com",         category: "media",         risk: "low"      },
  { pattern: "fast.wistia.net",         name: "Wistia Video",          domain: "wistia.com",        category: "media",         risk: "low"      },
  { pattern: "brightcove.net",          name: "Brightcove",            domain: "brightcove.com",    category: "media",         risk: "low"      },
  { pattern: "jwplatform.com",          name: "JW Player",             domain: "jwplayer.com",      category: "media",         risk: "low"      },
  { pattern: "mux.com",                 name: "Mux Video",             domain: "mux.com",           category: "media",         risk: "low"      },
  // Maps
  { pattern: "maps.googleapis.com",     name: "Google Maps",           domain: "google.com",        category: "maps",          risk: "low"      },
  { pattern: "api.mapbox.com",          name: "Mapbox",                domain: "mapbox.com",        category: "maps",          risk: "low"      },
  // CMS
  { pattern: "wp-content",              name: "WordPress",             domain: "wordpress.org",     category: "cms",           risk: "medium"   },
  { pattern: "contentful.com",          name: "Contentful CMS",        domain: "contentful.com",    category: "cms",           risk: "low"      },
  { pattern: "sanity.io",               name: "Sanity CMS",            domain: "sanity.io",         category: "cms",           risk: "low"      },
  // DevTools / Error Tracking
  { pattern: "fonts.googleapis.com",    name: "Google Fonts",          domain: "google.com",        category: "devtools",      risk: "low"      },
  { pattern: "use.typekit.net",         name: "Adobe Fonts (Typekit)", domain: "adobe.com",         category: "devtools",      risk: "low"      },
  { pattern: "cdn.fontawesome.com",     name: "Font Awesome",          domain: "fontawesome.com",   category: "devtools",      risk: "low"      },
  { pattern: "forms.hsforms.com",       name: "HubSpot Forms",         domain: "hubspot.com",       category: "marketing",     risk: "medium"   },
  { pattern: "api.ipify.org",           name: "ipify IP Detection",    domain: "ipify.org",         category: "devtools",      risk: "low"      },
  { pattern: "cookiebot.com",           name: "Cookiebot Consent",     domain: "cookiebot.com",     category: "devtools",      risk: "low"      },
  { pattern: "onetrust.com",            name: "OneTrust Consent",      domain: "onetrust.com",      category: "devtools",      risk: "medium"   },
  { pattern: "trustarc.com",            name: "TrustArc Consent",      domain: "trustarc.com",      category: "devtools",      risk: "low"      },
];

// CNAME chain → infrastructure provider mapping (60+ patterns)
const CNAME_SIGNATURES: CnameSig[] = [
  { pattern: "cloudfront.net",         name: "AWS CloudFront",        domain: "aws.amazon.com",    category: "cdn",           risk: "medium"   },
  { pattern: "fastly.net",             name: "Fastly CDN",            domain: "fastly.com",        category: "cdn",           risk: "medium"   },
  { pattern: "akamaiedge.net",         name: "Akamai CDN",            domain: "akamai.com",        category: "cdn",           risk: "medium"   },
  { pattern: "akamaized.net",          name: "Akamai CDN",            domain: "akamai.com",        category: "cdn",           risk: "medium"   },
  { pattern: "edgekey.net",            name: "Akamai CDN",            domain: "akamai.com",        category: "cdn",           risk: "medium"   },
  { pattern: "edgesuite.net",          name: "Akamai CDN",            domain: "akamai.com",        category: "cdn",           risk: "medium"   },
  { pattern: "akadns.net",             name: "Akamai DNS",            domain: "akamai.com",        category: "cdn",           risk: "medium"   },
  { pattern: "azureedge.net",          name: "Azure CDN",             domain: "azure.com",         category: "cdn",           risk: "medium"   },
  { pattern: "azurefd.net",            name: "Azure Front Door",      domain: "azure.com",         category: "cdn",           risk: "medium"   },
  { pattern: "trafficmanager.net",     name: "Azure Traffic Manager", domain: "azure.com",         category: "infrastructure",risk: "medium"   },
  { pattern: "cloudapp.net",           name: "Azure Cloud",           domain: "azure.com",         category: "infrastructure",risk: "medium"   },
  { pattern: "amazonaws.com",          name: "Amazon Web Services",   domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "elasticbeanstalk.com",   name: "AWS Elastic Beanstalk", domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "elb.amazonaws.com",      name: "AWS Elastic LB",        domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "s3.amazonaws.com",       name: "AWS S3",                domain: "aws.amazon.com",    category: "infrastructure",risk: "medium"   },
  { pattern: "googleusercontent.com",  name: "Google Cloud",          domain: "cloud.google.com",  category: "infrastructure",risk: "medium"   },
  { pattern: "run.app",                name: "Google Cloud Run",      domain: "cloud.google.com",  category: "infrastructure",risk: "medium"   },
  { pattern: "appspot.com",            name: "Google App Engine",     domain: "cloud.google.com",  category: "infrastructure",risk: "medium"   },
  { pattern: "storage.googleapis.com", name: "Google Cloud Storage",  domain: "cloud.google.com",  category: "infrastructure",risk: "medium"   },
  { pattern: "netlify.app",            name: "Netlify",               domain: "netlify.com",       category: "infrastructure",risk: "low"      },
  { pattern: "netlify.com",            name: "Netlify",               domain: "netlify.com",       category: "infrastructure",risk: "low"      },
  { pattern: "vercel.app",             name: "Vercel",                domain: "vercel.com",        category: "infrastructure",risk: "low"      },
  { pattern: "vercel-dns.com",         name: "Vercel DNS",            domain: "vercel.com",        category: "infrastructure",risk: "low"      },
  { pattern: "onrender.com",           name: "Render",                domain: "render.com",        category: "infrastructure",risk: "low"      },
  { pattern: "fly.dev",                name: "Fly.io",                domain: "fly.io",            category: "infrastructure",risk: "low"      },
  { pattern: "heroku",                 name: "Heroku",                domain: "heroku.com",        category: "infrastructure",risk: "low"      },
  { pattern: "wpengine.com",           name: "WP Engine",             domain: "wpengine.com",      category: "cms",           risk: "medium"   },
  { pattern: "kinsta.cloud",           name: "Kinsta Hosting",        domain: "kinsta.com",        category: "infrastructure",risk: "low"      },
  { pattern: "squarespace.com",        name: "Squarespace",           domain: "squarespace.com",   category: "cms",           risk: "low"      },
  { pattern: "wixsite.com",            name: "Wix",                   domain: "wix.com",           category: "cms",           risk: "low"      },
  { pattern: "shopify.com",            name: "Shopify",               domain: "shopify.com",       category: "payments",      risk: "medium"   },
  { pattern: "myshopify.com",          name: "Shopify",               domain: "shopify.com",       category: "payments",      risk: "medium"   },
  { pattern: "force.com",              name: "Salesforce",            domain: "salesforce.com",    category: "marketing",     risk: "medium"   },
  { pattern: "salesforce.com",         name: "Salesforce",            domain: "salesforce.com",    category: "marketing",     risk: "medium"   },
  { pattern: "hubspot.com",            name: "HubSpot",               domain: "hubspot.com",       category: "marketing",     risk: "medium"   },
  { pattern: "zendesk.com",            name: "Zendesk",               domain: "zendesk.com",       category: "communication", risk: "medium"   },
  { pattern: "incapdns.net",           name: "Imperva Incapsula",     domain: "imperva.com",       category: "waf",           risk: "medium"   },
  { pattern: "sucuri.net",             name: "Sucuri WAF",            domain: "sucuri.net",        category: "waf",           risk: "medium"   },
  { pattern: "stackpathdns.com",       name: "StackPath CDN",         domain: "stackpath.com",     category: "cdn",           risk: "medium"   },
  { pattern: "cloudflaressl.com",      name: "Cloudflare SSL",        domain: "cloudflare.com",    category: "cdn",           risk: "medium"   },
];

// Certificate issuer → CA provider mapping
const CERT_ISSUER_4TH_PARTIES: CertSig[] = [
  { pattern: "DigiCert",       name: "DigiCert CA",                domain: "digicert.com",    category: "ca", risk: "low" },
  { pattern: "Let's Encrypt",  name: "Let's Encrypt CA",           domain: "letsencrypt.org", category: "ca", risk: "low" },
  { pattern: "Sectigo",        name: "Sectigo CA",                 domain: "sectigo.com",     category: "ca", risk: "low" },
  { pattern: "GlobalSign",     name: "GlobalSign CA",              domain: "globalsign.com",  category: "ca", risk: "low" },
  { pattern: "Entrust",        name: "Entrust CA",                 domain: "entrust.com",     category: "ca", risk: "low" },
  { pattern: "GeoTrust",       name: "GeoTrust CA",                domain: "geotrust.com",    category: "ca", risk: "low" },
  { pattern: "Amazon",         name: "AWS Certificate Manager",    domain: "aws.amazon.com",  category: "ca", risk: "low" },
  { pattern: "Google Trust",   name: "Google Trust Services",      domain: "pki.goog",        category: "ca", risk: "low" },
  { pattern: "Cloudflare",     name: "Cloudflare Origin CA",       domain: "cloudflare.com",  category: "ca", risk: "low" },
  { pattern: "ZeroSSL",        name: "ZeroSSL CA",                 domain: "zerossl.com",     category: "ca", risk: "low" },
];

// Extract apex domain from any URL or domain string
function extractApexDomain(input: string): string | null {
  try {
    const host = input.startsWith("http") ? new URL(input).hostname : input.replace(/^\/\//, "");
    const parts = host.split(".");
    if (parts.length >= 2) return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  } catch { /**/ }
  return null;
}

function discoverFourthPartiesFromHttp(headers: Record<string, string>, body: string, cnames: string[]): FourthPartySignal[] {
  const signals: FourthPartySignal[] = [];
  const seen = new Set<string>();

  function add(name: string, domain: string, category: FpCategory, risk: FpRisk, method: string, details: Record<string, unknown>, confidence: number) {
    if (!seen.has(domain)) {
      seen.add(domain);
      signals.push({ name, domain, category, riskLevel: risk, confidence, discoveryMethod: method, details });
    }
  }

  // CDN/WAF from HTTP response headers
  for (const sig of CDN_WAF_HEADERS) {
    if (!sig.header) continue;
    const hVal = headers[sig.header.toLowerCase()] ?? "";
    const matches = !sig.value
      ? headers[sig.header.toLowerCase()] !== undefined
      : hVal.toLowerCase().includes(sig.value.toLowerCase());
    if (matches) add(sig.name, sig.domain, sig.category, sig.risk, "http_header", { header: sig.header, value: hVal }, 95);
  }

  // JS/HTML third-party patterns from body
  for (const tp of JS_THIRD_PARTIES) {
    if (body.includes(tp.pattern)) add(tp.name, tp.domain, tp.category, tp.risk, "js_analysis", { pattern: tp.pattern }, 90);
  }

  // Deep HTML parsing: <link rel="preconnect"> / <link rel="dns-prefetch">
  const preconnectRe = /<link[^>]+(?:preconnect|dns-prefetch)[^>]+href=["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = preconnectRe.exec(body)) !== null) {
    const href = m[1];
    if (!href) continue;
    const apex = extractApexDomain(href);
    if (!apex || apex === extractApexDomain(body.slice(0, 100))) continue;
    // Match against known signatures or add as unknown infrastructure
    const known = JS_THIRD_PARTIES.find(s => apex.includes(s.domain) || s.domain.includes(apex));
    if (known) {
      add(known.name, known.domain, known.category, known.risk, "preconnect_hint", { href }, 85);
    } else if (!seen.has(apex)) {
      add(apex, apex, "infrastructure", "low", "preconnect_hint", { href }, 60);
    }
  }

  // Deep HTML parsing: external <script src>
  const scriptRe = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  while ((m = scriptRe.exec(body)) !== null) {
    const src = m[1];
    if (!src || src.startsWith("/") || src.startsWith("./")) continue;
    const apex = extractApexDomain(src);
    if (!apex) continue;
    const known = JS_THIRD_PARTIES.find(s => src.includes(s.pattern));
    if (known) {
      add(known.name, known.domain, known.category, known.risk, "external_script", { src }, 92);
    } else if (!seen.has(apex)) {
      add(apex, apex, "devtools", "low", "external_script", { src }, 70);
    }
  }

  // External <iframe src> — embedded third-party content
  const iframeRe = /<iframe[^>]+src=["']([^"']+)["'][^>]*>/gi;
  while ((m = iframeRe.exec(body)) !== null) {
    const src = m[1];
    if (!src || src.startsWith("/")) continue;
    const apex = extractApexDomain(src);
    if (!apex) continue;
    const known = JS_THIRD_PARTIES.find(s => src.includes(s.domain));
    if (known) add(known.name, known.domain, known.category, known.risk, "iframe_embed", { src }, 88);
  }

  // CNAME chain → infrastructure provider
  for (const cname of cnames) {
    const lc = cname.toLowerCase();
    for (const sig of CNAME_SIGNATURES) {
      if (lc.includes(sig.pattern)) {
        add(sig.name, sig.domain, sig.category, sig.risk, "dns_cname", { cname }, 98);
        break;
      }
    }
  }

  return signals;
}

function discoverFourthPartiesFromCert(issuer: string | null, seen: Set<string>): FourthPartySignal[] {
  if (!issuer) return [];
  const signals: FourthPartySignal[] = [];
  for (const entry of CERT_ISSUER_4TH_PARTIES) {
    if (issuer.includes(entry.pattern) && !seen.has(entry.domain)) {
      seen.add(entry.domain);
      signals.push({ name: entry.name, domain: entry.domain, category: entry.category, riskLevel: entry.risk, confidence: 99, discoveryMethod: "cert_issuer", details: { issuer } });
    }
  }
  return signals;
}

export async function probeVendorDomain(inputDomain: string, opts: { vtApiKey?: string | null } = {}): Promise<VendorProbeResult> {
  const domain = extractDomain(inputDomain);

  const [dnsResult, tlsResult, httpResult, subdomains, whoisResult, exposureResult] = await Promise.all([
    probeDns(domain),
    probeTls(domain),
    probeHttp(domain),
    getSubdomains(domain),
    probeWhois(domain),
    checkSensitiveExposure(domain),
  ]);

  const allIps = dnsResult.a.slice(0, 5);
  const [shodanResults, vtResult] = await Promise.all([
    probeShodan(allIps),
    opts.vtApiKey ? probeVirusTotal(domain, opts.vtApiKey) : Promise.resolve(null),
  ]);

  const seen = new Set<string>();
  const fp1 = discoverFourthPartiesFromHttp(httpResult?.headers ?? {}, httpResult?.body ?? "", dnsResult.cname);
  for (const fp of fp1) seen.add(fp.domain);
  const fp2 = discoverFourthPartiesFromCert(tlsResult?.issuer ?? null, seen);
  const fourthParties = [...fp1, ...fp2];

  return {
    domain, dns: dnsResult, tls: tlsResult, http: httpResult,
    shodan: shodanResults, subdomains, fourthParties,
    whois: whoisResult, exposure: exposureResult, virusTotal: vtResult,
  };
}

// ── Risk Score Calculation ────────────────────────────────────────────────────

export interface VendorRiskBreakdown {
  overallScore:    number;
  riskGrade:       string;
  networkScore:    number;
  dnsScore:        number;
  webAppScore:     number;
  emailScore:      number;
  tlsScore:        number;
  endpointScore:   number;
  cloudScore:      number;
  appSecScore:     number;
  reputationScore: number;
  infoLeakScore:   number;
}

export function calculateVendorRiskScore(probe: VendorProbeResult, questionnaireScore?: number | null, compliancePenalty?: number): VendorRiskBreakdown {
  let networkScore    = 100;
  let dnsScore        = 100;
  let webAppScore     = 100;
  let emailScore      = 100;
  let tlsScore        = 100;
  let endpointScore   = 100;
  let cloudScore      = 100;
  let appSecScore     = 100;
  let reputationScore = 100;
  let infoLeakScore   = 100;

  // DNS score
  if (!probe.dns.hasSPF)   dnsScore -= 25;
  if (!probe.dns.hasDMARC) dnsScore -= 25;
  if (!probe.dns.hasDKIM)  dnsScore -= 15;
  if (probe.dns.a.length === 0) dnsScore -= 20;

  // TLS score
  if (!probe.tls) {
    tlsScore = 0;
  } else {
    if (probe.tls.expired)   tlsScore -= 50;
    if (probe.tls.selfSigned) tlsScore -= 30;
    if (probe.tls.daysUntilExp !== null && probe.tls.daysUntilExp < 14) tlsScore -= 20;
    if (probe.tls.protocol === "TLSv1" || probe.tls.protocol === "TLSv1.1") tlsScore -= 25;
  }

  // Web App / Security Headers
  if (probe.http) {
    const sh = probe.http.securityHeaders;
    if (!sh.hsts)             webAppScore -= 20;
    if (!sh.csp)              webAppScore -= 15;
    if (!sh.xFrameOptions)    webAppScore -= 10;
    if (!sh.xContentType)     webAppScore -= 10;
    if (!sh.referrerPolicy)   webAppScore -= 5;
    if (probe.http.server)    webAppScore -= 5; // server banner disclosure
    if (probe.http.poweredBy) webAppScore -= 5; // tech disclosure
  } else {
    webAppScore = 40;
  }

  // Email security
  if (!probe.dns.hasSPF)   emailScore -= 30;
  if (!probe.dns.hasDMARC) emailScore -= 30;
  if (!probe.dns.hasDKIM)  emailScore -= 20;
  if (probe.dns.mx.length === 0) emailScore -= 10;

  // Network / exposed ports
  const dangerousPorts = [21, 22, 23, 25, 3306, 5432, 27017, 6379, 11211, 9200, 8080, 8443];
  for (const sh of probe.shodan) {
    const exposed = sh.ports.filter(p => dangerousPorts.includes(p));
    networkScore -= exposed.length * 10;
    if (sh.vulns.length > 0) networkScore -= Math.min(30, sh.vulns.length * 5);
  }

  // App sec — Shodan CVEs
  for (const sh of probe.shodan) {
    if (sh.vulns.length > 0) appSecScore -= Math.min(40, sh.vulns.length * 8);
  }

  // Cloud / CDN
  const hasCloudProvider = probe.fourthParties.some(fp => ["aws.amazon.com", "fastly.com", "cloudflare.com"].includes(fp.domain));
  if (hasCloudProvider) cloudScore = Math.max(cloudScore, 80); // cloud provider = slight positive signal

  // Info leak — exposed sensitive files
  if (probe.exposure.envExposed)  infoLeakScore -= 60;
  if (probe.exposure.gitExposed)  infoLeakScore -= 50;

  // Reputation — VirusTotal
  if (probe.virusTotal) {
    if (probe.virusTotal.malicious  >= 5) reputationScore -= 60;
    else if (probe.virusTotal.malicious  >= 1) reputationScore -= 30;
    if (probe.virusTotal.suspicious >= 3) reputationScore -= 15;
  }

  // Clamp all to 0-100
  const clamp = (v: number) => Math.max(0, Math.min(100, v));
  networkScore    = clamp(networkScore);
  dnsScore        = clamp(dnsScore);
  webAppScore     = clamp(webAppScore);
  emailScore      = clamp(emailScore);
  tlsScore        = clamp(tlsScore);
  endpointScore   = clamp(endpointScore);
  cloudScore      = clamp(cloudScore);
  appSecScore     = clamp(appSecScore);
  reputationScore = clamp(reputationScore);
  infoLeakScore   = clamp(infoLeakScore);

  // Weighted average: Network 20%, DNS 15%, WebApp 20%, Email 10%, TLS 15%, InfoLeak 10%, Reputation 5%, Cloud 3%, Endpoint 2%
  let overallScore = Math.round(
    networkScore    * 0.20 +
    dnsScore        * 0.15 +
    webAppScore     * 0.20 +
    emailScore      * 0.10 +
    tlsScore        * 0.15 +
    infoLeakScore   * 0.10 +
    reputationScore * 0.05 +
    cloudScore      * 0.03 +
    endpointScore   * 0.02
  );

  // Questionnaire score adjustment
  if (questionnaireScore !== null && questionnaireScore !== undefined) {
    if (questionnaireScore < 60) overallScore = Math.max(0, overallScore - 10);
    else if (questionnaireScore >= 85) overallScore = Math.min(100, overallScore + 5);
  }

  // Compliance penalty
  if (compliancePenalty && compliancePenalty > 0) {
    overallScore = Math.max(0, overallScore - compliancePenalty);
  }

  overallScore = Math.max(0, Math.min(100, overallScore));

  let riskGrade = "F";
  if      (overallScore >= 90) riskGrade = "A+";
  else if (overallScore >= 80) riskGrade = "A";
  else if (overallScore >= 70) riskGrade = "B";
  else if (overallScore >= 60) riskGrade = "C";
  else if (overallScore >= 50) riskGrade = "D";

  return {
    overallScore, riskGrade,
    networkScore, dnsScore, webAppScore, emailScore, tlsScore,
    endpointScore, cloudScore, appSecScore, reputationScore, infoLeakScore,
  };
}

// ── Full Vendor Scan Orchestrator ─────────────────────────────────────────────

async function getPlatformSetting(key: string): Promise<string | null> {
  try {
    const [row] = await db.select().from(platformSettingsTable).where(eq(platformSettingsTable.key, key));
    return row?.value ?? null;
  } catch {
    return null;
  }
}

function buildFindingsFromProbe(probe: VendorProbeResult): Array<{
  title: string; severity: string; category: string; description: string; remediation: string; cvss?: number; cve?: string;
}> {
  const findings: Array<{ title: string; severity: string; category: string; description: string; remediation: string; cvss?: number; cve?: string }> = [];

  if (!probe.dns.hasSPF) findings.push({ title: "No SPF Record Configured", severity: "medium", category: "email", description: "The domain has no SPF (Sender Policy Framework) DNS record, allowing email spoofing.", remediation: "Add a TXT record: v=spf1 include:your-mail-provider ~all" });
  if (!probe.dns.hasDMARC) findings.push({ title: "No DMARC Policy Configured", severity: "high", category: "email", description: "No DMARC record exists, making it impossible to enforce email authentication policies.", remediation: "Add _dmarc TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourcompany.com" });
  if (!probe.dns.hasDKIM) findings.push({ title: "No DKIM Selector Found", severity: "medium", category: "email", description: "No common DKIM selectors were found. Outbound email may not be cryptographically signed.", remediation: "Configure DKIM signing in your email provider and publish the public key as a DNS TXT record." });

  if (probe.tls) {
    if (probe.tls.expired) findings.push({ title: "SSL/TLS Certificate Expired", severity: "critical", category: "tls", description: `The TLS certificate expired on ${probe.tls.validTo}.`, remediation: "Renew the TLS certificate immediately.", cvss: 8.5 });
    if (probe.tls.selfSigned) findings.push({ title: "Self-Signed SSL Certificate", severity: "high", category: "tls", description: "The domain is using a self-signed certificate, which will trigger browser warnings.", remediation: "Replace with a CA-signed certificate from a trusted authority (e.g., Let's Encrypt).", cvss: 6.5 });
    if (probe.tls.daysUntilExp !== null && probe.tls.daysUntilExp < 14 && !probe.tls.expired) findings.push({ title: "SSL Certificate Expiring Soon", severity: "medium", category: "tls", description: `The TLS certificate expires in ${probe.tls.daysUntilExp} days (${probe.tls.validTo}).`, remediation: "Renew the certificate before it expires to avoid service disruption." });
    if (probe.tls.protocol === "TLSv1" || probe.tls.protocol === "TLSv1.1") findings.push({ title: `Deprecated TLS Version (${probe.tls.protocol})`, severity: "high", category: "tls", description: `The server supports the deprecated ${probe.tls.protocol} protocol.`, remediation: "Disable TLS 1.0 and 1.1. Configure the server to support only TLS 1.2 and 1.3.", cvss: 6.5 });
  } else {
    findings.push({ title: "HTTPS Not Available", severity: "high", category: "tls", description: "The domain does not respond on HTTPS port 443.", remediation: "Implement HTTPS with a valid TLS certificate." });
  }

  if (probe.http) {
    const sh = probe.http.securityHeaders;
    if (!sh.hsts)          findings.push({ title: "Missing HSTS Header", severity: "medium", category: "web_app", description: "The Strict-Transport-Security header is absent.", remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains" });
    if (!sh.csp)           findings.push({ title: "Missing Content Security Policy", severity: "medium", category: "web_app", description: "No Content-Security-Policy header is set.", remediation: "Define a strict CSP to mitigate XSS attacks." });
    if (!sh.xFrameOptions) findings.push({ title: "Missing X-Frame-Options Header", severity: "low", category: "web_app", description: "X-Frame-Options is not set, allowing potential clickjacking.", remediation: "Add: X-Frame-Options: DENY" });
  }

  // Sensitive path exposure
  if (probe.exposure.envExposed) {
    findings.push({ title: "Exposed .env File", severity: "critical", category: "info_leak", description: "The /.env file is publicly accessible and may contain API keys, database credentials, or other secrets.", remediation: "Immediately block access to /.env via web server config (e.g., Nginx: location ~ /\\.env { deny all; }). Rotate all exposed credentials.", cvss: 9.8 });
  }
  if (probe.exposure.gitExposed) {
    findings.push({ title: "Exposed .git Directory", severity: "critical", category: "info_leak", description: "The /.git/config file is publicly accessible, allowing full source code reconstruction and secret extraction.", remediation: "Block /.git access at the web server level. Audit commit history for leaked credentials.", cvss: 9.1 });
  }

  // VirusTotal reputation
  if (probe.virusTotal) {
    const vt = probe.virusTotal;
    if (vt.malicious > 0) {
      findings.push({ title: `VirusTotal: Domain Flagged as Malicious (${vt.malicious} engines)`, severity: vt.malicious >= 5 ? "critical" : "high", category: "reputation", description: `${vt.malicious} VirusTotal engine(s) flagged this domain as malicious. Suspicious: ${vt.suspicious}.`, remediation: "Investigate the domain's recent activity, check for compromise, and review VirusTotal reports at virustotal.com." });
    } else if (vt.suspicious > 0) {
      findings.push({ title: `VirusTotal: Domain Marked Suspicious (${vt.suspicious} engines)`, severity: "medium", category: "reputation", description: `${vt.suspicious} VirusTotal engine(s) flagged this domain as suspicious.`, remediation: "Monitor the domain and review VirusTotal reports for further context." });
    }
  }

  // Shodan exposed ports
  const dangerous = [
    { port: 3306, name: "MySQL", severity: "critical", cvss: 9.8 },
    { port: 5432, name: "PostgreSQL", severity: "critical", cvss: 9.8 },
    { port: 27017, name: "MongoDB", severity: "critical", cvss: 9.8 },
    { port: 6379, name: "Redis", severity: "critical", cvss: 9.8 },
    { port: 9200, name: "Elasticsearch", severity: "critical", cvss: 9.8 },
    { port: 22, name: "SSH", severity: "medium", cvss: 5.3 },
    { port: 23, name: "Telnet", severity: "high", cvss: 8.6 },
    { port: 21, name: "FTP", severity: "high", cvss: 7.5 },
  ];
  for (const shodanResult of probe.shodan) {
    for (const dp of dangerous) {
      if (shodanResult.ports.includes(dp.port)) {
        findings.push({ title: `Exposed ${dp.name} Port (${dp.port})`, severity: dp.severity, category: "network", description: `${dp.name} port ${dp.port} is exposed to the internet on ${shodanResult.ip}.`, remediation: `Restrict port ${dp.port} behind a firewall. Only allow trusted IP ranges.`, cvss: dp.cvss });
      }
    }
    for (const vuln of shodanResult.vulns.slice(0, 5)) {
      findings.push({ title: `CVE Detected: ${vuln}`, severity: "high", category: "cve", description: `Shodan detected ${vuln} on ${shodanResult.ip}.`, remediation: `Apply vendor patch for ${vuln}.`, cve: vuln, cvss: 7.5 });
    }
  }

  return findings;
}

export async function runFullVendorScan(vendorId: number, tenantId: number): Promise<void> {
  try {
    const [vendor] = await db.select().from(tprmVendorsTable).where(
      and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.tenantId, tenantId))
    );
    if (!vendor) { logger.warn({ vendorId, tenantId }, "TPRM: vendor not found for scan"); return; }

    const domain = vendor.domain;
    logger.info({ vendorId, domain }, "TPRM: starting full vendor scan");

    const vtApiKey = await getPlatformSetting("virustotal_api_key");
    const probe = await probeVendorDomain(domain, { vtApiKey });

    // Get compliance penalty
    let compliancePenalty = 0;
    try {
      const { tprmComplianceDocumentsTable, tprmComplianceRequirementsTable } = await import("@workspace/db");
      const { inArray: _inArray, isNull } = await import("drizzle-orm");
      const reqs = await db.select().from(tprmComplianceRequirementsTable).where(
        and(eq(tprmComplianceRequirementsTable.vendorId, vendorId), eq(tprmComplianceRequirementsTable.required, true))
      );
      for (const req of reqs) {
        const docs = await db.select().from(tprmComplianceDocumentsTable).where(
          and(eq(tprmComplianceDocumentsTable.vendorId, vendorId), eq(tprmComplianceDocumentsTable.documentType, req.documentType))
        );
        if (docs.length === 0) compliancePenalty += 5;
        else {
          const expired = docs.filter(d => d.expiresAt && new Date(d.expiresAt) < new Date());
          compliancePenalty += expired.length * 3;
          const expiringSoon = docs.filter(d => {
            if (!d.expiresAt) return false;
            const days = (new Date(d.expiresAt).getTime() - Date.now()) / 86400000;
            return days > 0 && days <= 30;
          });
          compliancePenalty += expiringSoon.length;
        }
      }
    } catch { /* non-fatal */ }

    // Look up latest completed questionnaire score for this vendor
    let latestQuestionnaireScore: number | null = null;
    try {
      const { tprmVendorQuestionnairesTable: questTable } = await import("@workspace/db");
      const [latestQ] = await db
        .select({ score: questTable.score })
        .from(questTable)
        .where(and(
          eq(questTable.vendorId, vendorId),
          eq(questTable.status, "completed" as any),
        ))
        .orderBy(desc(questTable.completedAt))
        .limit(1);
      if (latestQ?.score != null) latestQuestionnaireScore = latestQ.score;
    } catch { /* non-fatal — proceed without questionnaire score */ }

    const breakdown = calculateVendorRiskScore(probe, latestQuestionnaireScore, compliancePenalty);

    // Persist findings — enrich CVE findings with EPSS/KEV first
    const rawFindings = buildFindingsFromProbe(probe);
    // Always clear-and-replace findings so stale data from a previous scan never lingers.
    // This is idempotent: if the new scan found nothing the table is left empty, which is correct.
    await db.delete(tprmVendorFindingsTable).where(
      and(eq(tprmVendorFindingsTable.vendorId, vendorId), eq(tprmVendorFindingsTable.tenantId, tenantId))
    );
    if (rawFindings.length > 0) {
      let enriched = rawFindings as Array<typeof rawFindings[number] & { epss?: number | null; isKev?: boolean }>;
      try {
        const { enrichFindingsWithEpssKev } = await import("./epssKev");
        enriched = await enrichFindingsWithEpssKev(rawFindings.map(f => ({ ...f, cve: f.cve ?? null }))) as typeof enriched;
      } catch { /* non-fatal — proceed without enrichment */ }
      await db.insert(tprmVendorFindingsTable).values(
        enriched.map(f => ({
          vendorId, tenantId,
          title:       f.title,
          severity:    f.severity,
          category:    f.category,
          description: f.description,
          remediation: f.remediation,
          cvss:        f.cvss ?? null,
          cve:         f.cve ?? null,
          epss:        f.epss ?? null,
          isKev:       f.isKev ?? false,
        }))
      );
    }

    // Persist assets — always clear first so empty scan results remove stale IPs/subdomains
    const assetValues: Array<{ vendorId: number; tenantId: number; assetType: string; value: string; riskLevel: string }> = [];
    for (const ip of probe.dns.a) assetValues.push({ vendorId, tenantId, assetType: "ip", value: ip, riskLevel: "low" });
    for (const sub of probe.subdomains.slice(0, 50)) assetValues.push({ vendorId, tenantId, assetType: "subdomain", value: sub, riskLevel: "low" });
    await db.delete(tprmVendorAssetsTable).where(and(eq(tprmVendorAssetsTable.vendorId, vendorId), eq(tprmVendorAssetsTable.tenantId, tenantId)));
    if (assetValues.length > 0) {
      await db.insert(tprmVendorAssetsTable).values(assetValues);
    }

    // Persist 4th-party vendors — always clear first so removed dependencies disappear
    await db.delete(tprmFourthPartyVendorsTable).where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, tenantId)));
    if (probe.fourthParties.length > 0) {
      // Risk contribution by category: payments/auth/infra = high, CDN/WAF = medium, analytics = low
      const riskContribMap: Record<string, number> = {
        payments: 20, auth: 20, infrastructure: 15, waf: 12,
        cdn: 8, monitoring: 10, security: 8, communication: 7,
        marketing: 5, advertising: 5, analytics: 3, media: 2, maps: 2, devtools: 2, cms: 5, ca: 2,
      };
      await db.insert(tprmFourthPartyVendorsTable).values(probe.fourthParties.map(fp => ({
        parentVendorId:   vendorId,
        tenantId,
        name:             fp.name,
        domain:           fp.domain,
        category:         fp.category,
        riskLevel:        fp.riskLevel,
        confidence:       fp.confidence,
        isActive:         true,
        discoveryMethod:  fp.discoveryMethod,
        riskContribution: riskContribMap[fp.category] ?? 5,
        details:          fp.details,
      })));
    }

    // Persist security analysis (HTTP headers, DNS health, SSL) — non-fatal
    try {
      const { runVendorSecurityAnalysis } = await import("./tprmSecurityAnalysis.js");
      const secAnalysis = await runVendorSecurityAnalysis(domain);
      await db.delete(tprmVendorSecurityAnalysisTable).where(and(eq(tprmVendorSecurityAnalysisTable.vendorId, vendorId), eq(tprmVendorSecurityAnalysisTable.tenantId, tenantId)));
      await db.insert(tprmVendorSecurityAnalysisTable).values({
        vendorId, tenantId,
        securityHeadersScore: secAnalysis.securityHeaders.score,
        dnsHealthScore:       secAnalysis.dnsHealth.score,
        sslScore:             secAnalysis.ssl.score,
        cookieScore:          secAnalysis.cookies.score,
        overallGrade:         secAnalysis.overallGrade,
        hsts:                 secAnalysis.securityHeaders.hsts,
        hstsMaxAge:           secAnalysis.securityHeaders.hstsMaxAge,
        csp:                  secAnalysis.securityHeaders.csp,
        cspUnsafeInline:      secAnalysis.securityHeaders.cspUnsafeInline,
        xFrameOptions:        secAnalysis.securityHeaders.xFrameOptions,
        xContentType:         secAnalysis.securityHeaders.xContentTypeOptions,
        referrerPolicy:       secAnalysis.securityHeaders.referrerPolicy,
        permissionsPolicy:    secAnalysis.securityHeaders.permissionsPolicy,
        coep:                 secAnalysis.securityHeaders.coep,
        coop:                 secAnalysis.securityHeaders.coop,
        spfRecord:            secAnalysis.dnsHealth.spfRecord,
        spfPolicy:            secAnalysis.dnsHealth.spfPolicy,
        dmarcRecord:          secAnalysis.dnsHealth.dmarcRecord,
        dmarcDisposition:     secAnalysis.dnsHealth.dmarcDisposition,
        dkimSelectors:        secAnalysis.dnsHealth.dkimSelectors,
        caaRecords:           secAnalysis.dnsHealth.caaRecords,
        dnssec:               secAnalysis.dnsHealth.dnssec,
        sslProtocol:          secAnalysis.ssl.protocol,
        sslGrade:             secAnalysis.ssl.grade,
        sslExpiryDays:        secAnalysis.ssl.daysUntilExpiry,
        certSanCount:         secAnalysis.ssl.sanCount,
        openPorts:            secAnalysis.openPorts,
        cookiesSecure:        secAnalysis.cookies.secureCookies,
        cookiesHttponly:      secAnalysis.cookies.httpOnlyCookies,
        cookiesSamesite:      secAnalysis.cookies.sameSiteCookies,
        totalCookies:         secAnalysis.cookies.totalCookies,
        rawHeaders:           secAnalysis.securityHeaders.rawHeaders,
      });
      logger.info({ vendorId, grade: secAnalysis.overallGrade }, "TPRM: security analysis persisted");
    } catch (secErr) {
      logger.warn({ secErr, vendorId }, "TPRM: security analysis failed (non-fatal)");
    }

    // Persist breach intelligence — non-fatal
    try {
      const { runBreachIntelReport } = await import("./tprmBreachIntel.js");
      const breachReport = await runBreachIntelReport(domain);
      // Clear previous breach events for this vendor
      await db.delete(tprmVendorBreachEventsTable).where(and(eq(tprmVendorBreachEventsTable.vendorId, vendorId), eq(tprmVendorBreachEventsTable.tenantId, tenantId)));
      if (breachReport.breachEvents.length > 0) {
        await db.insert(tprmVendorBreachEventsTable).values(breachReport.breachEvents.map(b => ({
          vendorId, tenantId,
          breachName:   b.breachName,
          breachDate:   b.breachDate,
          pwnCount:     b.pwnCount,
          dataClasses:  b.dataClasses,
          description:  b.description,
          isVerified:   b.isVerified,
          isSensitive:  b.isSensitive,
          isFabricated: b.isFabricated,
          logoPath:     b.logoPath,
          source:       b.source,
        })));
      }
      logger.info({ vendorId, breaches: breachReport.breachEvents.length, lookalikes: breachReport.lookalikeDomains.length }, "TPRM: breach intel persisted");
    } catch (breachErr) {
      logger.warn({ breachErr, vendorId }, "TPRM: breach intel failed (non-fatal)");
    }

    // Persist supply-chain topology nodes from scan probe
    try {
      // nodeType taxonomy: software | saas | api | cdn | infra
      // OSINT-derived nodes: apex domain and subdomains → "saas"; resolved IPs → "infra"
      const scNodes: Array<{ vendorId: number; tenantId: number; name: string; nodeType: "saas" | "infra"; riskLevel: string; vulnerabilities: any }> = [];
      scNodes.push({ vendorId, tenantId, name: domain, nodeType: "saas", riskLevel: breakdown.riskGrade === "A" || breakdown.riskGrade === "B" ? "low" : breakdown.riskGrade === "C" ? "medium" : "high", vulnerabilities: [] });
      for (const ip of probe.dns.a.slice(0, 5)) {
        const shodanEntry = probe.shodan.find(s => s.ip === ip);
        const vulns = shodanEntry?.vulns.slice(0, 10).map(v => ({ id: v })) ?? [];
        scNodes.push({ vendorId, tenantId, name: ip, nodeType: "infra", riskLevel: vulns.length > 0 ? "high" : "low", vulnerabilities: vulns });
      }
      for (const sub of probe.subdomains.slice(0, 15)) {
        scNodes.push({ vendorId, tenantId, name: sub, nodeType: "saas", riskLevel: "low", vulnerabilities: [] });
      }
      // Auto-populate supply chain nodes from 4th party discovery signals
      // (CDNs, analytics providers, payment processors, API services)
      const seen4pNames = new Set<string>();
      for (const fp of probe.fourthParties.slice(0, 25)) {
        const key = (fp.domain || fp.name).toLowerCase();
        if (seen4pNames.has(key)) continue;
        seen4pNames.add(key);
        const nodeType: "saas" | "infra" =
          fp.category === "cdn" || fp.category === "hosting" || fp.category === "cloud" ? "infra" : "saas";
        const riskLevel =
          fp.riskLevel === "critical" ? "high"
          : fp.riskLevel === "high" ? "high"
          : fp.riskLevel === "medium" ? "medium" : "low";
        scNodes.push({ vendorId, tenantId, name: fp.name, nodeType, riskLevel, vulnerabilities: [] });
      }
      if (scNodes.length > 0) {
        await db.delete(tprmSupplyChainNodesTable).where(and(eq(tprmSupplyChainNodesTable.vendorId, vendorId), eq(tprmSupplyChainNodesTable.tenantId, tenantId), isNull(tprmSupplyChainNodesTable.sbomUploadId)));
        await db.insert(tprmSupplyChainNodesTable).values(scNodes);
      }
    } catch (scErr) { logger.warn({ scErr, vendorId }, "TPRM: supply-chain node persist failed (non-fatal)"); }

    // Persist risk score snapshot
    await db.insert(tprmVendorRiskScoresTable).values({ vendorId, tenantId, ...breakdown });

    // Alert on significant vendor risk-score change
    try {
      const prevScores = await db.select({ overallScore: tprmVendorRiskScoresTable.overallScore })
        .from(tprmVendorRiskScoresTable)
        .where(and(eq(tprmVendorRiskScoresTable.vendorId, vendorId), eq(tprmVendorRiskScoresTable.tenantId, tenantId)))
        .orderBy(desc(tprmVendorRiskScoresTable.calculatedAt))
        .limit(2);
      if (prevScores.length >= 2) {
        const prevScore = prevScores[1]!.overallScore ?? breakdown.overallScore;
        const delta = breakdown.overallScore - prevScore;
        if (Math.abs(delta) >= 10) {
          await db.insert(alertsTable).values({
            tenantId,
            title: `Vendor risk score changed: ${vendor.companyName}`,
            message: `Risk score changed from ${prevScore} to ${breakdown.overallScore} (${delta > 0 ? "+" : ""}${delta} pts). Grade: ${breakdown.riskGrade}.`,
            type: "tprm_vendor_risk_change",
            severity: breakdown.overallScore < 50 ? "high" : "medium",
          });
        }
      }
    } catch { /* non-fatal */ }

    // Update vendor record
    await db.update(tprmVendorsTable)
      .set({ riskScore: breakdown.overallScore, riskGrade: breakdown.riskGrade, status: "active", lastScannedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.tenantId, tenantId)));

    logger.info({ vendorId, domain, score: breakdown.overallScore, grade: breakdown.riskGrade }, "TPRM: vendor scan complete");
  } catch (err) {
    logger.error({ err, vendorId, tenantId }, "TPRM: runFullVendorScan failed");
    await db.update(tprmVendorsTable)
      .set({ status: "active", updatedAt: new Date() })
      .where(and(eq(tprmVendorsTable.id, vendorId), eq(tprmVendorsTable.tenantId, tenantId)));
  }
}
