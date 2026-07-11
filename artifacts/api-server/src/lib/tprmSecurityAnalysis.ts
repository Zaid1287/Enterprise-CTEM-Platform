/**
 * TPRM Vendor Security Analysis Engine
 * Deep HTTP headers, DNS health, SSL/TLS, and cookie analysis.
 * All data sourced from live probes — zero mocked results.
 */

import dns from "node:dns/promises";
import tls from "node:tls";
import { logger } from "./logger";

const UA = "Sentinelware-TPRM/1.0";
const FETCH_TIMEOUT_MS = 15000;

async function safeFetch(url: string, opts: RequestInit = {}): Promise<Response | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: { "User-Agent": UA, ...(opts.headers ?? {}) },
    });
    clearTimeout(t);
    return res;
  } catch {
    return null;
  }
}

// ── Interfaces ────────────────────────────────────────────────────────────────

export interface SecurityHeadersAnalysis {
  score: number;          // 0–100
  grade: string;          // A+, A, B, C, D, F
  hsts: boolean;
  hstsMaxAge: number | null;
  hstsIncludeSubdomains: boolean;
  hstsPreload: boolean;
  csp: boolean;
  cspUnsafeInline: boolean;
  cspUnsafeEval: boolean;
  xFrameOptions: string | null;
  xContentTypeOptions: boolean;
  referrerPolicy: string | null;
  permissionsPolicy: boolean;
  coep: boolean;         // Cross-Origin-Embedder-Policy
  coop: boolean;         // Cross-Origin-Opener-Policy
  corp: boolean;         // Cross-Origin-Resource-Policy
  serverBannerLeaked: string | null;
  poweredByLeaked: string | null;
  findings: Array<{ severity: "high" | "medium" | "low" | "info"; message: string }>;
  rawHeaders: Record<string, string>;
}

export interface DnsHealthAnalysis {
  score: number;
  grade: string;
  hasSPF: boolean;
  spfRecord: string | null;
  spfPolicy: string | null;          // e.g. "-all", "~all", "+all", "?all"
  hasDMARC: boolean;
  dmarcRecord: string | null;
  dmarcDisposition: string | null;   // none, quarantine, reject
  dmarcPct: number | null;
  hasDKIM: boolean;
  dkimSelectors: string[];           // found selectors
  hasCAA: boolean;
  caaRecords: string[];
  dnssec: boolean;
  mxCount: number;
  hasIPv6: boolean;
  findings: Array<{ severity: "high" | "medium" | "low" | "info"; message: string }>;
}

export interface SslAnalysis {
  score: number;
  grade: string;
  protocol: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: Date | null;
  validTo: Date | null;
  daysUntilExpiry: number | null;
  expired: boolean;
  selfSigned: boolean;
  sanCount: number;
  sanDomains: string[];
  wildcardCert: boolean;
  findings: Array<{ severity: "high" | "medium" | "low" | "info"; message: string }>;
}

export interface CookieAnalysis {
  score: number;
  totalCookies: number;
  secureCookies: number;
  httpOnlyCookies: number;
  sameSiteCookies: number;
  findings: Array<{ severity: "high" | "medium" | "low" | "info"; message: string }>;
}

export interface VendorSecurityAnalysis {
  domain: string;
  overallScore: number;
  overallGrade: string;
  securityHeaders: SecurityHeadersAnalysis;
  dnsHealth: DnsHealthAnalysis;
  ssl: SslAnalysis;
  cookies: CookieAnalysis;
  openPorts: number[];
  scannedAt: Date;
}

// ── Security Headers Analysis ─────────────────────────────────────────────────

export async function analyzeSecurityHeaders(domain: string): Promise<SecurityHeadersAnalysis> {
  const findings: SecurityHeadersAnalysis["findings"] = [];
  const result: SecurityHeadersAnalysis = {
    score: 100,
    grade: "A+",
    hsts: false,
    hstsMaxAge: null,
    hstsIncludeSubdomains: false,
    hstsPreload: false,
    csp: false,
    cspUnsafeInline: false,
    cspUnsafeEval: false,
    xFrameOptions: null,
    xContentTypeOptions: false,
    referrerPolicy: null,
    permissionsPolicy: false,
    coep: false,
    coop: false,
    corp: false,
    serverBannerLeaked: null,
    poweredByLeaked: null,
    findings,
    rawHeaders: {},
  };

  const res = await safeFetch(`https://${domain}`, { method: "GET", redirect: "follow" });
  if (!res) {
    result.score = 0;
    result.grade = "F";
    findings.push({ severity: "high", message: "Could not connect to HTTPS endpoint" });
    return result;
  }

  const headers: Record<string, string> = {};
  res.headers.forEach((val, key) => { headers[key.toLowerCase()] = val; });
  result.rawHeaders = headers;

  // HSTS
  const hsts = headers["strict-transport-security"];
  if (hsts) {
    result.hsts = true;
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    result.hstsMaxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]!, 10) : null;
    result.hstsIncludeSubdomains = /includeSubDomains/i.test(hsts);
    result.hstsPreload = /preload/i.test(hsts);
    if (result.hstsMaxAge !== null && result.hstsMaxAge < 15552000) {
      findings.push({ severity: "medium", message: `HSTS max-age is too short (${result.hstsMaxAge}s). Recommended: ≥15552000s (180 days)` });
      result.score -= 5;
    }
  } else {
    findings.push({ severity: "high", message: "Missing Strict-Transport-Security (HSTS) header" });
    result.score -= 20;
  }

  // CSP
  const csp = headers["content-security-policy"] ?? headers["content-security-policy-report-only"];
  if (csp) {
    result.csp = true;
    result.cspUnsafeInline = csp.includes("'unsafe-inline'");
    result.cspUnsafeEval = csp.includes("'unsafe-eval'");
    if (result.cspUnsafeInline) {
      findings.push({ severity: "medium", message: "Content-Security-Policy contains 'unsafe-inline' — weakens XSS protection" });
      result.score -= 5;
    }
    if (result.cspUnsafeEval) {
      findings.push({ severity: "medium", message: "Content-Security-Policy contains 'unsafe-eval' — allows JavaScript code injection" });
      result.score -= 5;
    }
  } else {
    findings.push({ severity: "high", message: "Missing Content-Security-Policy (CSP) header" });
    result.score -= 15;
  }

  // X-Frame-Options
  result.xFrameOptions = headers["x-frame-options"] ?? null;
  if (!result.xFrameOptions) {
    if (!csp || !csp.includes("frame-ancestors")) {
      findings.push({ severity: "medium", message: "Missing X-Frame-Options header (no frame-ancestors in CSP either) — clickjacking risk" });
      result.score -= 10;
    }
  }

  // X-Content-Type-Options
  result.xContentTypeOptions = headers["x-content-type-options"]?.toLowerCase() === "nosniff";
  if (!result.xContentTypeOptions) {
    findings.push({ severity: "medium", message: "Missing X-Content-Type-Options: nosniff header — MIME sniffing attack risk" });
    result.score -= 10;
  }

  // Referrer-Policy
  result.referrerPolicy = headers["referrer-policy"] ?? null;
  if (!result.referrerPolicy) {
    findings.push({ severity: "low", message: "Missing Referrer-Policy header — may leak sensitive URLs to third parties" });
    result.score -= 5;
  }

  // Permissions-Policy
  result.permissionsPolicy = !!headers["permissions-policy"];
  if (!result.permissionsPolicy) {
    findings.push({ severity: "low", message: "Missing Permissions-Policy header — browser features not explicitly restricted" });
    result.score -= 5;
  }

  // Cross-Origin headers
  result.coep = !!headers["cross-origin-embedder-policy"];
  result.coop = !!headers["cross-origin-opener-policy"];
  result.corp = !!headers["cross-origin-resource-policy"];
  if (!result.coep || !result.coop) {
    findings.push({ severity: "low", message: "Missing Cross-Origin isolation headers (COEP/COOP) — Spectre attack risk in modern browsers" });
    result.score -= 3;
  }

  // Server banner leakage
  const server = headers["server"];
  if (server && /apache|nginx|iis|lighttpd|jetty|tomcat|jboss|weblogic|gunicorn/i.test(server)) {
    result.serverBannerLeaked = server;
    findings.push({ severity: "low", message: `Server header discloses server software: "${server}" — aids fingerprinting attacks` });
    result.score -= 5;
  }

  const poweredBy = headers["x-powered-by"];
  if (poweredBy) {
    result.poweredByLeaked = poweredBy;
    findings.push({ severity: "low", message: `X-Powered-By header discloses technology: "${poweredBy}" — aids fingerprinting attacks` });
    result.score -= 5;
  }

  result.score = Math.max(0, result.score);
  result.grade = scoreToGrade(result.score);
  return result;
}

// ── DNS Health Analysis ───────────────────────────────────────────────────────

const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2",
  "dkim", "mail", "email", "smtp", "s1", "s2",
  "20150623", "20161025", "20200601", "20210112",
  "protonmail", "zoho", "mimecast", "barracuda",
  "sendgrid", "mailgun", "amazonses", "mandrill", "postmark",
];

export async function analyzeDnsHealth(domain: string): Promise<DnsHealthAnalysis> {
  const findings: DnsHealthAnalysis["findings"] = [];
  const result: DnsHealthAnalysis = {
    score: 100,
    grade: "A+",
    hasSPF: false,
    spfRecord: null,
    spfPolicy: null,
    hasDMARC: false,
    dmarcRecord: null,
    dmarcDisposition: null,
    dmarcPct: null,
    hasDKIM: false,
    dkimSelectors: [],
    hasCAA: false,
    caaRecords: [],
    dnssec: false,
    mxCount: 0,
    hasIPv6: false,
    findings,
  };

  // Parallel DNS lookups
  const [txtRecords, mxRecords, dmarcTxt, caaRecords, aaaaRecords] = await Promise.all([
    dns.resolveTxt(domain).catch(() => [] as string[][]),
    dns.resolveMx(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]),
    dns.resolveCaa(domain).catch(() => [] as { critical: boolean; issue: string; issuewild?: string; tag: string; value: string }[]),
    dns.resolve6(domain).catch(() => [] as string[]),
  ]);

  // SPF
  const spfRecord = txtRecords.flat().find(r => r.startsWith("v=spf1"));
  if (spfRecord) {
    result.hasSPF = true;
    result.spfRecord = spfRecord;
    const allMatch = spfRecord.match(/([+-~?])all/);
    result.spfPolicy = allMatch ? allMatch[0] : null;
    if (result.spfPolicy === "+all") {
      findings.push({ severity: "high", message: "SPF policy uses '+all' — allows ANY server to send email as this domain (open relay)" });
      result.score -= 30;
    } else if (result.spfPolicy === "?all") {
      findings.push({ severity: "medium", message: "SPF policy uses '?all' (neutral) — provides minimal protection against spoofing" });
      result.score -= 15;
    } else if (result.spfPolicy === "~all") {
      findings.push({ severity: "low", message: "SPF policy uses '~all' (softfail) — consider upgrading to '-all' for strict enforcement" });
      result.score -= 5;
    }
    if (spfRecord.includes("ptr")) {
      findings.push({ severity: "medium", message: "SPF record includes 'ptr' mechanism — deprecated and causes excessive DNS lookups" });
      result.score -= 5;
    }
  } else {
    findings.push({ severity: "high", message: "Missing SPF record — domain is vulnerable to email spoofing attacks" });
    result.score -= 25;
  }

  // DMARC
  const dmarcRecord = dmarcTxt.flat().find(r => r.startsWith("v=DMARC1"));
  if (dmarcRecord) {
    result.hasDMARC = true;
    result.dmarcRecord = dmarcRecord;
    const pMatch = dmarcRecord.match(/p=([^;]+)/i);
    result.dmarcDisposition = pMatch ? pMatch[1]!.toLowerCase().trim() : null;
    const pctMatch = dmarcRecord.match(/pct=(\d+)/i);
    result.dmarcPct = pctMatch ? parseInt(pctMatch[1]!, 10) : 100;

    if (result.dmarcDisposition === "none") {
      findings.push({ severity: "medium", message: "DMARC policy is 'none' — monitoring only, emails not rejected/quarantined on failure" });
      result.score -= 15;
    } else if (result.dmarcDisposition === "quarantine") {
      findings.push({ severity: "low", message: "DMARC policy is 'quarantine' — consider upgrading to 'reject' for full protection" });
      result.score -= 5;
    }
    if (result.dmarcPct !== null && result.dmarcPct < 100 && result.dmarcDisposition !== "none") {
      findings.push({ severity: "low", message: `DMARC pct=${result.dmarcPct} — policy only applied to ${result.dmarcPct}% of failing emails` });
      result.score -= 5;
    }
  } else {
    findings.push({ severity: "high", message: "Missing DMARC record — domain unprotected against email phishing/spoofing" });
    result.score -= 25;
  }

  // DKIM — probe common selectors
  const dkimChecks = await Promise.all(
    DKIM_SELECTORS.map(sel =>
      dns.resolveTxt(`${sel}._domainkey.${domain}`)
        .then(r => r.flat().some(v => v.includes("v=DKIM1")) ? sel : null)
        .catch(() => null)
    )
  );
  result.dkimSelectors = dkimChecks.filter((s): s is string => s !== null);
  result.hasDKIM = result.dkimSelectors.length > 0;
  if (!result.hasDKIM) {
    findings.push({ severity: "medium", message: "No DKIM records found for common selectors — email authentication incomplete" });
    result.score -= 15;
  }

  // CAA
  if (caaRecords.length > 0) {
    result.hasCAA = true;
    result.caaRecords = caaRecords.map(r => `${(r as any).tag ?? "issue"} ${(r as any).value ?? (r as any).issue ?? ""}`);

  } else {
    findings.push({ severity: "low", message: "No CAA records — any CA can issue certificates for this domain" });
    result.score -= 5;
  }

  // MX
  result.mxCount = mxRecords.length;
  if (mxRecords.length === 0) {
    findings.push({ severity: "low", message: "No MX records found — domain does not appear to receive email" });
  }

  // IPv6
  result.hasIPv6 = aaaaRecords.length > 0;

  result.score = Math.max(0, result.score);
  result.grade = scoreToGrade(result.score);
  return result;
}

// ── SSL/TLS Analysis ──────────────────────────────────────────────────────────

export async function analyzeSsl(domain: string): Promise<SslAnalysis> {
  const findings: SslAnalysis["findings"] = [];
  const result: SslAnalysis = {
    score: 100,
    grade: "A+",
    protocol: null,
    subject: null,
    issuer: null,
    validFrom: null,
    validTo: null,
    daysUntilExpiry: null,
    expired: false,
    selfSigned: false,
    sanCount: 0,
    sanDomains: [],
    wildcardCert: false,
    findings,
  };

  return new Promise<SslAnalysis>((resolve) => {
    const timeout = setTimeout(() => {
      findings.push({ severity: "high", message: "TLS connection timed out" });
      result.score = 20;
      result.grade = "F";
      resolve(result);
    }, 10000);

    try {
      const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 8000, rejectUnauthorized: false }, () => {
        clearTimeout(timeout);
        try {
          const cert = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();
          result.protocol = protocol ?? null;

          if (cert && cert.subject) {
            result.subject = (cert.subject.CN ?? null) as string | null;
            result.issuer = (cert.issuer?.CN ?? cert.issuer?.O ?? null) as string | null;
            result.validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
            result.validTo = cert.valid_to ? new Date(cert.valid_to) : null;
            result.selfSigned = cert.issuer?.CN === cert.subject?.CN;

            if (result.validTo) {
              const now = Date.now();
              const expiry = result.validTo.getTime();
              result.daysUntilExpiry = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
              result.expired = expiry < now;
            }

            // SANs
            const san = (cert as any).subjectaltname as string | undefined;
            if (san) {
              const sanList = san.split(",").map(s => s.trim().replace(/^DNS:/, ""));
              result.sanDomains = sanList;
              result.sanCount = sanList.length;
              result.wildcardCert = sanList.some(s => s.startsWith("*."));
            }
          }

          // Protocol scoring
          if (protocol === "TLSv1" || protocol === "TLSv1.1") {
            findings.push({ severity: "high", message: `TLS ${protocol} is deprecated and vulnerable (POODLE, BEAST attacks)` });
            result.score -= 40;
          } else if (protocol === "TLSv1.2") {
            findings.push({ severity: "low", message: "TLS 1.2 is supported — consider enabling TLS 1.3 for improved security" });
            result.score -= 5;
          }

          if (result.expired) {
            findings.push({ severity: "high", message: "SSL certificate has expired — browser will show security warning" });
            result.score -= 50;
          } else if (result.daysUntilExpiry !== null && result.daysUntilExpiry < 14) {
            findings.push({ severity: "high", message: `SSL certificate expires in ${result.daysUntilExpiry} days — renewal urgent` });
            result.score -= 20;
          } else if (result.daysUntilExpiry !== null && result.daysUntilExpiry < 30) {
            findings.push({ severity: "medium", message: `SSL certificate expires in ${result.daysUntilExpiry} days` });
            result.score -= 10;
          }

          if (result.selfSigned) {
            findings.push({ severity: "high", message: "Self-signed certificate — not trusted by browsers, potential MITM risk" });
            result.score -= 30;
          }
        } catch (certErr) {
          findings.push({ severity: "medium", message: "Could not parse certificate details" });
        }
        socket.end();
        result.score = Math.max(0, result.score);
        result.grade = scoreToGrade(result.score);
        resolve(result);
      });

      socket.on("error", () => {
        clearTimeout(timeout);
        findings.push({ severity: "high", message: "TLS handshake failed — HTTPS may not be configured" });
        result.score = 0;
        result.grade = "F";
        resolve(result);
      });
    } catch {
      clearTimeout(timeout);
      findings.push({ severity: "high", message: "Could not initiate TLS connection" });
      result.score = 0;
      result.grade = "F";
      resolve(result);
    }
  });
}

// ── Cookie Analysis ───────────────────────────────────────────────────────────

export async function analyzeCookies(domain: string): Promise<CookieAnalysis> {
  const findings: CookieAnalysis["findings"] = [];
  const result: CookieAnalysis = {
    score: 100,
    totalCookies: 0,
    secureCookies: 0,
    httpOnlyCookies: 0,
    sameSiteCookies: 0,
    findings,
  };

  const res = await safeFetch(`https://${domain}`, { method: "GET", redirect: "follow" });
  if (!res) return result;

  const setCookieHeaders: string[] = [];
  res.headers.forEach((val, key) => {
    if (key.toLowerCase() === "set-cookie") setCookieHeaders.push(val);
  });

  result.totalCookies = setCookieHeaders.length;
  if (result.totalCookies === 0) return result;

  for (const cookie of setCookieHeaders) {
    const lower = cookie.toLowerCase();
    if (lower.includes("; secure")) result.secureCookies++;
    if (lower.includes("; httponly")) result.httpOnlyCookies++;
    if (lower.includes("samesite=")) result.sameSiteCookies++;
  }

  const insecureCount = result.totalCookies - result.secureCookies;
  if (insecureCount > 0) {
    findings.push({ severity: "high", message: `${insecureCount}/${result.totalCookies} cookies missing Secure flag — can be intercepted over HTTP` });
    result.score -= Math.min(40, insecureCount * 15);
  }

  const noHttpOnly = result.totalCookies - result.httpOnlyCookies;
  if (noHttpOnly > 0) {
    findings.push({ severity: "medium", message: `${noHttpOnly}/${result.totalCookies} cookies missing HttpOnly flag — accessible to JavaScript (XSS risk)` });
    result.score -= Math.min(20, noHttpOnly * 8);
  }

  const noSameSite = result.totalCookies - result.sameSiteCookies;
  if (noSameSite > 0) {
    findings.push({ severity: "medium", message: `${noSameSite}/${result.totalCookies} cookies missing SameSite attribute — CSRF risk` });
    result.score -= Math.min(15, noSameSite * 5);
  }

  result.score = Math.max(0, result.score);
  return result;
}

// ── Full Vendor Security Analysis ─────────────────────────────────────────────

export async function runVendorSecurityAnalysis(domain: string): Promise<VendorSecurityAnalysis> {
  const [securityHeaders, dnsHealth, ssl, cookies] = await Promise.all([
    analyzeSecurityHeaders(domain).catch(e => {
      logger.warn({ e, domain }, "securityHeaders analysis failed");
      return null;
    }),
    analyzeDnsHealth(domain).catch(e => {
      logger.warn({ e, domain }, "dnsHealth analysis failed");
      return null;
    }),
    analyzeSsl(domain).catch(e => {
      logger.warn({ e, domain }, "SSL analysis failed");
      return null;
    }),
    analyzeCookies(domain).catch(e => {
      logger.warn({ e, domain }, "cookie analysis failed");
      return null;
    }),
  ]);

  const hScore = securityHeaders?.score ?? 0;
  const dScore = dnsHealth?.score ?? 0;
  const sScore = ssl?.score ?? 0;
  const cScore = cookies?.score ?? 100;

  const overallScore = Math.round(hScore * 0.35 + dScore * 0.30 + sScore * 0.25 + cScore * 0.10);

  return {
    domain,
    overallScore,
    overallGrade: scoreToGrade(overallScore),
    securityHeaders: securityHeaders ?? blankSecurityHeaders(),
    dnsHealth: dnsHealth ?? blankDnsHealth(),
    ssl: ssl ?? blankSsl(),
    cookies: cookies ?? blankCookies(),
    openPorts: [],
    scannedAt: new Date(),
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreToGrade(score: number): string {
  if (score >= 97) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

function blankSecurityHeaders(): SecurityHeadersAnalysis {
  return { score: 0, grade: "F", hsts: false, hstsMaxAge: null, hstsIncludeSubdomains: false, hstsPreload: false, csp: false, cspUnsafeInline: false, cspUnsafeEval: false, xFrameOptions: null, xContentTypeOptions: false, referrerPolicy: null, permissionsPolicy: false, coep: false, coop: false, corp: false, serverBannerLeaked: null, poweredByLeaked: null, findings: [{ severity: "high", message: "Analysis unavailable" }], rawHeaders: {} };
}
function blankDnsHealth(): DnsHealthAnalysis {
  return { score: 0, grade: "F", hasSPF: false, spfRecord: null, spfPolicy: null, hasDMARC: false, dmarcRecord: null, dmarcDisposition: null, dmarcPct: null, hasDKIM: false, dkimSelectors: [], hasCAA: false, caaRecords: [], dnssec: false, mxCount: 0, hasIPv6: false, findings: [{ severity: "high", message: "Analysis unavailable" }] };
}
function blankSsl(): SslAnalysis {
  return { score: 0, grade: "F", protocol: null, subject: null, issuer: null, validFrom: null, validTo: null, daysUntilExpiry: null, expired: false, selfSigned: false, sanCount: 0, sanDomains: [], wildcardCert: false, findings: [{ severity: "high", message: "Analysis unavailable" }] };
}
function blankCookies(): CookieAnalysis {
  return { score: 100, totalCookies: 0, secureCookies: 0, httpOnlyCookies: 0, sameSiteCookies: 0, findings: [] };
}
