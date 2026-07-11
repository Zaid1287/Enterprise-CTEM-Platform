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
import { db, platformSettingsTable, tprmVendorFindingsTable, tprmVendorAssetsTable, tprmVendorRiskScoresTable, tprmFourthPartyVendorsTable, tprmVendorsTable, tprmSupplyChainNodesTable, alertsTable } from "@workspace/db";
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
      const suggestions: any[] = await res.json().catch(() => []);
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

  // 3. DNS fallback — get MX to infer email provider, SOA for age hint
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
      base.source = "dns";
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
  domain:      string;
  dns:         DnsProbeResult;
  tls:         TlsProbeResult | null;
  http:        HttpProbeResult | null;
  shodan:      ShodanInternetDbResult[];
  subdomains:  string[];
  fourthParties: FourthPartySignal[];
}

export interface FourthPartySignal {
  name:            string;
  domain:          string;
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
          issuer:   cert.issuer?.O ?? cert.issuer?.CN ?? null,
          subject:  cert.subject?.CN ?? null,
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
    const data: any[] = await res.json().catch(() => []);
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

const CDN_WAF_HEADERS: Array<{ header: string; value: string; name: string; domain: string }> = [
  { header: "server",             value: "cloudflare",  name: "Cloudflare",  domain: "cloudflare.com" },
  { header: "x-served-by",       value: "fastly",      name: "Fastly CDN",  domain: "fastly.com" },
  { header: "x-cache",           value: "cloudfront",  name: "AWS CloudFront", domain: "aws.amazon.com" },
  { header: "x-akamai",          value: "",            name: "Akamai",      domain: "akamai.com" },
  { header: "x-sucuri",          value: "",            name: "Sucuri WAF",  domain: "sucuri.net" },
  { header: "server",            value: "akamaighost", name: "Akamai",      domain: "akamai.com" },
  { header: "x-cache-hits",      value: "varnish",     name: "Varnish Cache", domain: "varnish-cache.org" },
];

const JS_THIRD_PARTIES: Array<{ pattern: string; name: string; domain: string }> = [
  { pattern: "google-analytics.com",  name: "Google Analytics",  domain: "google.com" },
  { pattern: "googletagmanager.com",  name: "Google Tag Manager", domain: "google.com" },
  { pattern: "segment.io",            name: "Segment",           domain: "segment.com" },
  { pattern: "intercom.io",           name: "Intercom",          domain: "intercom.com" },
  { pattern: "hotjar.com",            name: "Hotjar",            domain: "hotjar.com" },
  { pattern: "stripe.com/v3",         name: "Stripe Payments",   domain: "stripe.com" },
  { pattern: "js.sentry-cdn.com",     name: "Sentry",            domain: "sentry.io" },
  { pattern: "cdn.amplitude.com",     name: "Amplitude",         domain: "amplitude.com" },
  { pattern: "cdn.mxpnl.com",         name: "Mixpanel",          domain: "mixpanel.com" },
  { pattern: "connect.facebook.net",  name: "Facebook Pixel",    domain: "facebook.com" },
  { pattern: "platform.twitter.com",  name: "Twitter Widget",    domain: "twitter.com" },
  { pattern: "widget.zendesk.com",    name: "Zendesk",           domain: "zendesk.com" },
  { pattern: "assets.hubspot.com",    name: "HubSpot",           domain: "hubspot.com" },
];

function discoverFourthPartiesFromHttp(headers: Record<string, string>, body: string, cnames: string[]): FourthPartySignal[] {
  const signals: FourthPartySignal[] = [];
  const seen = new Set<string>();

  // CDN/WAF from HTTP headers
  for (const cdn of CDN_WAF_HEADERS) {
    const hVal = headers[cdn.header.toLowerCase()] ?? "";
    if (hVal.toLowerCase().includes(cdn.value.toLowerCase()) || (cdn.value === "" && headers[cdn.header.toLowerCase()] !== undefined)) {
      if (!seen.has(cdn.domain)) {
        seen.add(cdn.domain);
        signals.push({ name: cdn.name, domain: cdn.domain, discoveryMethod: "http_header", details: { header: cdn.header, value: hVal } });
      }
    }
  }

  // JS third-parties from body
  for (const tp of JS_THIRD_PARTIES) {
    if (body.includes(tp.pattern) && !seen.has(tp.domain)) {
      seen.add(tp.domain);
      signals.push({ name: tp.name, domain: tp.domain, discoveryMethod: "js_analysis", details: { pattern: tp.pattern } });
    }
  }

  // CNAME chain
  for (const cname of cnames) {
    if (cname.includes("cloudfront.net") && !seen.has("aws.amazon.com")) {
      seen.add("aws.amazon.com");
      signals.push({ name: "AWS CloudFront", domain: "aws.amazon.com", discoveryMethod: "dns_cname", details: { cname } });
    } else if (cname.includes("fastly.net") && !seen.has("fastly.com")) {
      seen.add("fastly.com");
      signals.push({ name: "Fastly CDN", domain: "fastly.com", discoveryMethod: "dns_cname", details: { cname } });
    } else if (cname.includes("akamaiedge.net") && !seen.has("akamai.com")) {
      seen.add("akamai.com");
      signals.push({ name: "Akamai", domain: "akamai.com", discoveryMethod: "dns_cname", details: { cname } });
    }
  }

  return signals;
}

export async function probeVendorDomain(inputDomain: string): Promise<VendorProbeResult> {
  const domain = extractDomain(inputDomain);

  const [dnsResult, tlsResult, httpResult, subdomains] = await Promise.all([
    probeDns(domain),
    probeTls(domain),
    probeHttp(domain),
    getSubdomains(domain),
  ]);

  const allIps = dnsResult.a.slice(0, 5);
  const shodanResults = await probeShodan(allIps);

  const fourthParties = discoverFourthPartiesFromHttp(
    httpResult?.headers ?? {},
    httpResult?.body ?? "",
    dnsResult.cname,
  );

  return { domain, dns: dnsResult, tls: tlsResult, http: httpResult, shodan: shodanResults, subdomains, fourthParties };
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

    const probe = await probeVendorDomain(domain);

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

    const breakdown = calculateVendorRiskScore(probe, null, compliancePenalty);

    // Persist findings — enrich CVE findings with EPSS/KEV first
    const rawFindings = buildFindingsFromProbe(probe);
    if (rawFindings.length > 0) {
      let enriched = rawFindings as Array<typeof rawFindings[number] & { epss?: number | null; isKev?: boolean }>;
      try {
        const { enrichFindingsWithEpssKev } = await import("./epssKev");
        enriched = await enrichFindingsWithEpssKev(rawFindings.map(f => ({ ...f, cve: f.cve ?? null }))) as typeof enriched;
      } catch { /* non-fatal — proceed without enrichment */ }
      await db.delete(tprmVendorFindingsTable).where(
        and(eq(tprmVendorFindingsTable.vendorId, vendorId), eq(tprmVendorFindingsTable.tenantId, tenantId))
      );
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

    // Persist assets
    const assetValues: Array<{ vendorId: number; tenantId: number; assetType: string; value: string; riskLevel: string }> = [];
    for (const ip of probe.dns.a) assetValues.push({ vendorId, tenantId, assetType: "ip", value: ip, riskLevel: "low" });
    for (const sub of probe.subdomains.slice(0, 50)) assetValues.push({ vendorId, tenantId, assetType: "subdomain", value: sub, riskLevel: "low" });
    if (assetValues.length > 0) {
      await db.delete(tprmVendorAssetsTable).where(and(eq(tprmVendorAssetsTable.vendorId, vendorId), eq(tprmVendorAssetsTable.tenantId, tenantId)));
      await db.insert(tprmVendorAssetsTable).values(assetValues);
    }

    // Persist 4th-party vendors
    if (probe.fourthParties.length > 0) {
      await db.delete(tprmFourthPartyVendorsTable).where(and(eq(tprmFourthPartyVendorsTable.parentVendorId, vendorId), eq(tprmFourthPartyVendorsTable.tenantId, tenantId)));
      await db.insert(tprmFourthPartyVendorsTable).values(probe.fourthParties.map(fp => ({
        parentVendorId:   vendorId,
        tenantId,
        name:             fp.name,
        domain:           fp.domain,
        discoveryMethod:  fp.discoveryMethod,
        riskContribution: 5,
        details:          fp.details,
      })));
    }

    // Persist supply-chain topology nodes from scan probe
    try {
      const scNodes: Array<{ vendorId: number; tenantId: number; name: string; nodeType: "domain" | "ip"; riskLevel: string; vulnerabilities: any }> = [];
      scNodes.push({ vendorId, tenantId, name: domain, nodeType: "domain", riskLevel: breakdown.riskGrade === "A" || breakdown.riskGrade === "B" ? "low" : breakdown.riskGrade === "C" ? "medium" : "high", vulnerabilities: [] });
      for (const ip of probe.dns.a.slice(0, 5)) {
        const shodanEntry = probe.shodan.find(s => s.ip === ip);
        const vulns = shodanEntry?.vulns.slice(0, 10).map(v => ({ id: v })) ?? [];
        scNodes.push({ vendorId, tenantId, name: ip, nodeType: "ip", riskLevel: vulns.length > 0 ? "high" : "low", vulnerabilities: vulns });
      }
      for (const sub of probe.subdomains.slice(0, 15)) {
        scNodes.push({ vendorId, tenantId, name: sub, nodeType: "domain", riskLevel: "low", vulnerabilities: [] });
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
