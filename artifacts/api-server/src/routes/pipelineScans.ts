import { Router } from "express";
import { exec } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";
import tls from "tls";
import { eq, and, inArray } from "drizzle-orm";
import { db, scansTable, scanAssetResultsTable, assetsTable, findingsTable, securityToolsTable, toolPipelineStepsTable, scanSchedulesTable, technologyDetectionsTable, screenshotsTable } from "@workspace/db";
import { detectTechnologies, type DetectedTechnology } from "../lib/techDetector";
import { captureScreenshots, type PageScreenshot } from "../lib/screenshotEngine";
import { scanPorts, type PortScanReport } from "../lib/portScanner";
import { scanSubdomains, type SubdomainScanReport } from "../lib/subdomainScanner";
import { RunPipelineScanBody, GetScanAssetReportParams, CreateScanScheduleBody, UpdateScanScheduleBody, UpdateScanScheduleParams, RunScheduleNowParams, StopScanParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const execAsync = promisify(exec);
const router = Router();

// ── Active nmap killers ────────────────────────────────────────────────────────
const activeScanKillers = new Map<number, () => void>();

// ── In-memory live progress tracker (per scan) ─────────────────────────────────
export interface ToolProgress {
  toolName: string;
  toolCategory: string;
  phase: number;
  status: "queued" | "running" | "done" | "failed";
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  findingsCount: number;
  detail: string;
}

interface AssetProgress {
  assetId: number;
  assetName: string;
  assetValue: string;
  tools: ToolProgress[];
}

const scanProgressMap = new Map<number, AssetProgress[]>();

// Tool → pentesting phase mapping
const TOOL_PHASE: Record<string, number> = {
  subfinder: 1, dnsx: 1, shuffledns: 1, amass: 1, mapcidr: 1, tldfinder: 1,
  gau: 1, asnmap: 1, cdncheck: 1, uncover: 1, cloud_enum: 1, s3scanner: 1,
  theHarvester: 1, aix: 1, maltego: 1,
  naabu: 2, masscan: 2, rustscan: 2,
  httpx: 3, katana: 3, feroxbuster: 3, gobuster: 3, ffuf: 3,
  whatweb: 3, wafw00f: 3, useragent: 3, wappalyzer: 3, webcheck: 3,
  gowitness: 3, eyewitness: 3, snapback: 3,
  nuclei: 4, nikto: 4, wpscan: 4, trufflehog: 4, wapiti: 4, vulnx: 4, goleak: 4,
  testssl: 5, sslscan: 5,
};
const PHASE_NAMES: Record<number, string> = {
  1: "Reconnaissance", 2: "Port Scanning", 3: "Web Recon",
  4: "Vuln & Secrets", 5: "SSL/TLS Analysis",
};

// ── Secrets patterns (25 patterns) ────────────────────────────────────────────
interface SecretMatch { name: string; severity: "critical" | "high" | "medium" | "low" | "info"; cwe: string; remediation: string; pattern: RegExp; }

const SECRET_PATTERNS: SecretMatch[] = [
  { name: "AWS Access Key ID",       severity: "critical", cwe: "CWE-798", pattern: /AKIA[0-9A-Z]{16}/,                                                                 remediation: "Revoke key immediately in AWS IAM, remove from code, rotate secrets." },
  { name: "AWS Secret Access Key",   severity: "critical", cwe: "CWE-798", pattern: /(?:aws.{0,20}secret|secret.{0,10}key)['\"\s:=]+[A-Za-z0-9/+]{38,42}/i,            remediation: "Revoke AWS credentials and rotate. Never commit secrets to code." },
  { name: "GitHub Personal Token",   severity: "high",     cwe: "CWE-798", pattern: /ghp_[a-zA-Z0-9]{36}/,                                                              remediation: "Revoke in GitHub Settings → Developer Settings → Personal access tokens." },
  { name: "GitHub OAuth Token",      severity: "high",     cwe: "CWE-798", pattern: /gho_[a-zA-Z0-9]{36}/,                                                              remediation: "Revoke the OAuth token and audit associated OAuth applications." },
  { name: "GitHub Actions Token",    severity: "high",     cwe: "CWE-798", pattern: /ghs_[a-zA-Z0-9]{36}/,                                                              remediation: "Actions tokens are short-lived; check workflow for secret exposure." },
  { name: "Stripe Live Secret Key",  severity: "critical", cwe: "CWE-798", pattern: /sk_live_[0-9a-zA-Z]{24,}/,                                                         remediation: "Revoke in Stripe dashboard → API Keys immediately." },
  { name: "Stripe Test Secret Key",  severity: "medium",   cwe: "CWE-798", pattern: /sk_test_[0-9a-zA-Z]{24,}/,                                                         remediation: "Rotate test key. Test keys should not appear in frontend code." },
  { name: "OpenAI API Key",          severity: "high",     cwe: "CWE-798", pattern: /sk-[a-zA-Z0-9]{48}/,                                                               remediation: "Revoke at platform.openai.com/api-keys and regenerate." },
  { name: "Slack Bot Token",         severity: "high",     cwe: "CWE-798", pattern: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}/,                                  remediation: "Revoke in Slack API dashboard under OAuth & Permissions." },
  { name: "Slack Webhook URL",       severity: "medium",   cwe: "CWE-200", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/,     remediation: "Revoke webhook and generate a new one. Restrict webhook usage." },
  { name: "Google API Key",          severity: "high",     cwe: "CWE-798", pattern: /AIza[0-9A-Za-z_-]{35}/,                                                            remediation: "Restrict key in Google Cloud Console and add HTTP referrer restrictions." },
  { name: "RSA/EC Private Key",      severity: "critical", cwe: "CWE-321", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,                           remediation: "Immediately revoke cert/key pair, reissue from CA, rotate all usages." },
  { name: "JWT Token",               severity: "medium",   cwe: "CWE-522", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,               remediation: "Investigate JWT exposure. Ensure secrets signing JWTs are not exposed." },
  { name: "SendGrid API Key",        severity: "high",     cwe: "CWE-798", pattern: /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{40,}/,                                      remediation: "Revoke in SendGrid Settings → API Keys." },
  { name: "Twilio Account SID",      severity: "high",     cwe: "CWE-798", pattern: /AC[a-zA-Z0-9]{32}/,                                                                remediation: "Rotate Twilio credentials in console.twilio.com." },
  { name: "Mailgun API Key",         severity: "high",     cwe: "CWE-798", pattern: /key-[0-9a-zA-Z]{32}/,                                                              remediation: "Revoke key in Mailgun API Keys section." },
  { name: "SQL Connection String",   severity: "critical", cwe: "CWE-312", pattern: /(?:mysql|mssql|postgres(?:ql)?|jdbc):\/\/[^:\s<>"']{2,}:[^@\s<>"']{4,}@\S{4,}/i, remediation: "Remove DB credentials from code. Use environment variables or secrets manager." },
  { name: "MongoDB URI with Creds",  severity: "critical", cwe: "CWE-312", pattern: /mongodb(?:\+srv)?:\/\/[^:\s<>"']+:[^@\s<>"']+@[^\s<>"']{4,}/,                    remediation: "Rotate MongoDB credentials. Use environment variables." },
  { name: "Firebase Private Key",    severity: "high",     cwe: "CWE-798", pattern: /\"private_key\":\s*\"-----BEGIN RSA PRIVATE KEY/,                                  remediation: "Rotate Firebase service account key in Firebase Console." },
  { name: "PayPal Braintree Token",  severity: "critical", cwe: "CWE-798", pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/,                             remediation: "Revoke in Braintree dashboard immediately." },
  { name: "Hardcoded Password",      severity: "high",     cwe: "CWE-259", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([a-zA-Z0-9!@#$%^&*()_+]{8,})['"]/i,        remediation: "Remove hardcoded passwords. Use environment variables or vaults." },
  { name: "Generic API Secret",      severity: "medium",   cwe: "CWE-798", pattern: /(?:api.?secret|client.?secret|auth.?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/i, remediation: "Move secrets to environment variables or a secrets manager." },
  { name: "Basic Auth in URL",       severity: "high",     cwe: "CWE-312", pattern: /https?:\/\/[^:\s<>"']+:[^@\s<>"']{4,}@[a-zA-Z0-9][^\s<>"']{4,}/,               remediation: "Never embed credentials in URLs. Use proper auth headers." },
  { name: "npm Auth Token",          severity: "high",     cwe: "CWE-798", pattern: /\/\/registry\.npmjs\.org\/:_authToken=[a-zA-Z0-9_-]{36}/,                         remediation: "Revoke token at npmjs.com/settings. Never commit .npmrc with tokens." },
  { name: "Docker Config Auth",      severity: "high",     cwe: "CWE-798", pattern: /"auths":\s*\{\s*"[^"]+"\s*:\s*\{\s*"auth":\s*"[A-Za-z0-9+/]{20,}=/,              remediation: "Remove Docker auth from code. Use docker logout and credential stores." },
];

// ── Expanded CVE Pool (40+ entries) ────────────────────────────────────────────
const CVE_POOL = [
  // Web servers
  { cve: "CVE-2023-44487", cvss: 7.5, severity: "high",     title: "HTTP/2 Rapid Reset DoS (Nginx/Apache/IIS)",          cwe: "CWE-400", remediation: "Update web server to patched version.",                                   affected: ["nginx", "apache", "iis", "http2", "h2"] },
  { cve: "CVE-2021-41773", cvss: 9.8, severity: "critical", title: "Apache HTTP Server Path Traversal & RCE",             cwe: "CWE-22",  remediation: "Upgrade Apache to 2.4.50+.",                                              affected: ["apache"] },
  { cve: "CVE-2021-42013", cvss: 9.8, severity: "critical", title: "Apache Path Traversal bypass (Sequel to 41773)",      cwe: "CWE-22",  remediation: "Upgrade Apache to 2.4.51+.",                                              affected: ["apache"] },
  { cve: "CVE-2023-25690", cvss: 9.8, severity: "critical", title: "Apache mod_proxy HTTP Request Smuggling",             cwe: "CWE-444", remediation: "Upgrade Apache to 2.4.56+.",                                              affected: ["apache", "proxy"] },
  { cve: "CVE-2017-7679",  cvss: 9.8, severity: "critical", title: "Apache mod_mime Buffer Overread",                     cwe: "CWE-125", remediation: "Upgrade Apache to 2.2.33+ / 2.4.26+.",                                   affected: ["apache"] },
  // OpenSSH
  { cve: "CVE-2023-38408", cvss: 9.8, severity: "critical", title: "OpenSSH Remote Code Execution via ssh-agent",         cwe: "CWE-122", remediation: "Upgrade OpenSSH to 9.3p2+.",                                              affected: ["ssh", "openssh", "22"] },
  { cve: "CVE-2024-6387",  cvss: 8.1, severity: "high",     title: "OpenSSH regreSSHion Race Condition RCE",              cwe: "CWE-364", remediation: "Update OpenSSH to 9.8p1+.",                                               affected: ["ssh", "openssh", "22"] },
  { cve: "CVE-2021-3156",  cvss: 7.8, severity: "high",     title: "sudo Heap Overflow (Baron Samedit)",                  cwe: "CWE-193", remediation: "Upgrade sudo to 1.9.5p2+.",                                               affected: ["ssh", "22"] },
  { cve: "CVE-2020-15778", cvss: 7.8, severity: "high",     title: "OpenSSH scp Command Injection",                       cwe: "CWE-78",  remediation: "Disable SCP or upgrade to OpenSSH 9.0+.",                                affected: ["ssh", "22", "sftp"] },
  // SSL/TLS
  { cve: "CVE-2014-0160",  cvss: 7.5, severity: "high",     title: "Heartbleed — OpenSSL TLS Memory Disclosure",          cwe: "CWE-125", remediation: "Upgrade OpenSSL to 1.0.1g+, reissue all certificates.",                  affected: ["https", "ssl", "tls", "443"] },
  { cve: "CVE-2022-0778",  cvss: 7.5, severity: "high",     title: "OpenSSL BN_mod_sqrt() Infinite Loop (DoS)",           cwe: "CWE-835", remediation: "Upgrade OpenSSL to 1.0.2zd / 1.1.1n / 3.0.2+.",                         affected: ["ssl", "tls", "https", "openssl"] },
  { cve: "CVE-2024-0727",  cvss: 5.5, severity: "medium",   title: "OpenSSL PKCS12 Null Pointer Dereference",             cwe: "CWE-476", remediation: "Upgrade OpenSSL to 3.2.1+.",                                              affected: ["ssl", "tls", "https", "openssl"] },
  // PHP
  { cve: "CVE-2024-4577",  cvss: 9.8, severity: "critical", title: "PHP CGI Argument Injection RCE",                      cwe: "CWE-88",  remediation: "Update PHP to 8.3.8+ / 8.2.20+ / 8.1.29+.",                              affected: ["http", "https", "php"] },
  { cve: "CVE-2022-31628", cvss: 7.8, severity: "high",     title: "PHP phar Deserialization Arbitrary Code Execution",   cwe: "CWE-502", remediation: "Update PHP to 8.1.12+ / 8.0.25+ / 7.4.33+.",                             affected: ["php", "http"] },
  { cve: "CVE-2019-11043", cvss: 9.8, severity: "critical", title: "PHP-FPM Remote Code Execution via Nginx",             cwe: "CWE-119", remediation: "Upgrade PHP-FPM to 7.3.11+, configure Nginx correctly.",                 affected: ["php-fpm", "nginx", "http"] },
  // Applications
  { cve: "CVE-2022-26134", cvss: 9.8, severity: "critical", title: "Confluence Server OGNL Injection RCE",                cwe: "CWE-74",  remediation: "Upgrade Confluence to 7.4.17+.",                                          affected: ["http", "https", "confluence"] },
  { cve: "CVE-2023-42793", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Authentication Bypass",            cwe: "CWE-288", remediation: "Update TeamCity to 2023.05.4+.",                                           affected: ["http", "https", "8111"] },
  { cve: "CVE-2024-27198", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Auth Bypass (Critical)",           cwe: "CWE-288", remediation: "Upgrade TeamCity to 2023.11.4+.",                                          affected: ["http", "https"] },
  { cve: "CVE-2024-23897", cvss: 9.8, severity: "critical", title: "Jenkins Arbitrary File Read → RCE",                   cwe: "CWE-22",  remediation: "Upgrade Jenkins to 2.442+ / LTS 2.426.3+.",                               affected: ["http", "https", "jenkins", "8080"] },
  { cve: "CVE-2023-46604", cvss: 10.0,severity: "critical", title: "Apache ActiveMQ RCE via ExceptionResponse",           cwe: "CWE-502", remediation: "Upgrade ActiveMQ to 5.15.16+ / 5.16.7+ / 5.18.3+.",                      affected: ["activemq", "61616"] },
  { cve: "CVE-2021-44228", cvss: 10.0,severity: "critical", title: "Log4Shell — Apache Log4j2 JNDI RCE",                  cwe: "CWE-20",  remediation: "Upgrade Log4j to 2.17.1+; set -Dlog4j2.formatMsgNoLookups=true.",        affected: ["http", "https", "java", "8080", "8443"] },
  { cve: "CVE-2022-42889", cvss: 9.8, severity: "critical", title: "Apache Commons Text RCE (Text4Shell)",                cwe: "CWE-94",  remediation: "Upgrade commons-text to 1.10.0+.",                                        affected: ["http", "https", "java"] },
  // WordPress
  { cve: "CVE-2023-2732",  cvss: 9.8, severity: "critical", title: "WordPress MStore API Authentication Bypass",          cwe: "CWE-287", remediation: "Update MStore API plugin to latest.",                                      affected: ["wordpress", "http", "https"] },
  { cve: "CVE-2024-9047",  cvss: 9.8, severity: "critical", title: "WordPress File Manager Pro Arbitrary Upload",         cwe: "CWE-434", remediation: "Update File Manager Pro plugin to latest.",                                affected: ["wordpress", "http"] },
  { cve: "CVE-2023-6553",  cvss: 9.8, severity: "critical", title: "Backup Migration WordPress Plugin RCE",               cwe: "CWE-78",  remediation: "Update Backup Migration to 1.3.8+.",                                      affected: ["wordpress"] },
  // Network / Infrastructure
  { cve: "CVE-2024-3400",  cvss: 10.0,severity: "critical", title: "PAN-OS GlobalProtect Command Injection",              cwe: "CWE-77",  remediation: "Apply PAN-OS hotfix, patch PSIRT-ADV-2024-006.",                          affected: ["https", "vpn", "443"] },
  { cve: "CVE-2023-20198", cvss: 10.0,severity: "critical", title: "Cisco IOS XE Web UI Privilege Escalation",            cwe: "CWE-306", remediation: "Disable HTTP/HTTPS Server or upgrade IOS XE firmware.",                   affected: ["http", "https", "cisco"] },
  { cve: "CVE-2024-21893", cvss: 8.2, severity: "high",     title: "Ivanti Connect Secure SSRF",                         cwe: "CWE-918", remediation: "Apply Ivanti patches from January 2024 advisory.",                        affected: ["https", "vpn", "ssl"] },
  // Databases
  { cve: "CVE-2024-21096", cvss: 4.9, severity: "medium",   title: "MySQL Server Information Disclosure",                 cwe: "CWE-284", remediation: "Upgrade MySQL to 8.0.37+.",                                                affected: ["mysql", "3306"] },
  { cve: "CVE-2023-2454",  cvss: 7.2, severity: "high",     title: "PostgreSQL pg_catalog Privilege Escalation",          cwe: "CWE-20",  remediation: "Upgrade PostgreSQL to 15.3+ / 14.8+.",                                   affected: ["postgresql", "postgres", "5432"] },
  { cve: "CVE-2024-1597",  cvss: 10.0,severity: "critical", title: "PostgreSQL SQL Injection via pg JDBC",                cwe: "CWE-89",  remediation: "Upgrade PostgreSQL JDBC to 42.7.2+.",                                    affected: ["postgresql", "5432"] },
  // Containers
  { cve: "CVE-2024-21626", cvss: 8.6, severity: "high",     title: "runc Container Breakout (Leaky Vessels)",             cwe: "CWE-22",  remediation: "Update runc to v1.1.12+.",                                                affected: ["docker", "http", "2376"] },
  { cve: "CVE-2023-34048", cvss: 9.8, severity: "critical", title: "VMware vCenter DCERPC Out-of-Bounds RCE",             cwe: "CWE-787", remediation: "Apply VMware patch VMSA-2023-0023.",                                       affected: ["https", "vmware", "443"] },
  // FTP
  { cve: "CVE-2024-28995", cvss: 8.6, severity: "high",     title: "SolarWinds Serv-U Path Traversal",                   cwe: "CWE-22",  remediation: "Upgrade Serv-U to 15.4.2.228+.",                                          affected: ["ftp", "sftp", "21", "22"] },
  { cve: "CVE-2023-38035", cvss: 9.8, severity: "critical", title: "Ivanti MobileIron Endpoint Manager SSRF → RCE",       cwe: "CWE-918", remediation: "Apply Ivanti security advisory SA-2023-08-21.",                           affected: ["https", "http", "443"] },
  { cve: "CVE-2024-23334", cvss: 7.5, severity: "high",     title: "aiohttp Path Traversal (Python web apps)",            cwe: "CWE-22",  remediation: "Upgrade aiohttp to 3.9.2+.",                                              affected: ["http", "python", "8080"] },
  { cve: "CVE-2024-9487",  cvss: 8.8, severity: "high",     title: "GitHub Enterprise SAML Authentication Bypass",        cwe: "CWE-347", remediation: "Upgrade GitHub Enterprise Server to 3.14+.",                               affected: ["https", "http"] },
  { cve: "CVE-2024-20767", cvss: 9.8, severity: "critical", title: "Adobe ColdFusion Arbitrary File Read/Exec",           cwe: "CWE-20",  remediation: "Apply ColdFusion security update APSB24-14.",                             affected: ["http", "https", "coldfusion"] },
  { cve: "CVE-2024-37085", cvss: 6.8, severity: "medium",   title: "VMware ESXi AD Integration Auth Bypass",              cwe: "CWE-290", remediation: "Apply VMware VMSA-2024-0013.",                                             affected: ["https", "esxi"] },
  { cve: "CVE-2024-1086",  cvss: 7.8, severity: "high",     title: "Linux nf_tables Use-After-Free Local Privesc",        cwe: "CWE-416", remediation: "Apply kernel patch, update to 6.7.3+.",                                   affected: ["ssh", "22", "ftp"] },
];

// ── Type interfaces ─────────────────────────────────────────────────────────────
interface PortFinding      { port: number; service: string; version: string; protocol: string; state: string; }
interface SubdomainFinding { name: string; ip: string; cname: string | null; status: string; cdnProvider: string | null; sources?: string[]; httpStatus?: number | null; httpTitle?: string | null; redirectTo?: string | null; webServer?: string | null; }
interface EndpointFinding  { url: string; method: string; status: number; title?: string; }
interface HttpInfo         { url: string; status: number; title: string; server: string; contentLength: number; tech: string[]; waf: string; cdn: string | null; headers: Record<string, string>; }
interface DnsRecord        { type: string; value: string; ttl: number; priority?: number; }
interface IntelItem        { type: string; key: string; value: string; severity?: string; }
interface VulnFinding      { cve: string; cvss: number; severity: string; title: string; cwe: string; remediation: string; source?: string; }
interface AssetToolConfigItem { assetId: number; toolIds: number[]; }

// ── Helpers ─────────────────────────────────────────────────────────────────────

function extractDomain(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase().trim();
}

function isIp(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

function maskSecret(s: string): string {
  if (s.length <= 8) return "***";
  return s.slice(0, 6) + "••••••••" + s.slice(-4);
}

// ── Phase 1: DNS + Subdomain Recon ─────────────────────────────────────────────

async function runDnsRecon(target: string): Promise<{ subdomains: SubdomainFinding[]; dnsRecords: DnsRecord[] }> {
  const domain = extractDomain(target);
  if (!domain || isIp(domain)) return { subdomains: [], dnsRecords: [] };

  const dnsRecords: DnsRecord[] = [];
  const subdomains: SubdomainFinding[] = [];

  const [a, aaaa, mx, ns, txt, soa, cname] = await Promise.allSettled([
    dns.resolve4(domain, { ttl: true }),
    dns.resolve6(domain, { ttl: true }),
    dns.resolveMx(domain),
    dns.resolveNs(domain),
    dns.resolveTxt(domain),
    dns.resolveSoa(domain),
    dns.resolveCname(domain).catch(() => [] as string[]),
  ]);

  if (a.status === "fulfilled")    for (const r of a.value)    dnsRecords.push({ type: "A",     value: r.address,                              ttl: r.ttl });
  if (aaaa.status === "fulfilled") for (const r of aaaa.value) dnsRecords.push({ type: "AAAA",  value: r.address,                              ttl: r.ttl });
  if (mx.status === "fulfilled")   for (const r of mx.value)   dnsRecords.push({ type: "MX",    value: r.exchange,                             ttl: 300, priority: r.priority });
  if (ns.status === "fulfilled")   for (const r of ns.value)   dnsRecords.push({ type: "NS",    value: r,                                      ttl: 3600 });
  if (txt.status === "fulfilled")  for (const r of txt.value)  dnsRecords.push({ type: "TXT",   value: r.join(" "),                            ttl: 300 });
  if (soa.status === "fulfilled")  dnsRecords.push({ type: "SOA",  value: `${soa.value.nsname} ${soa.value.hostmaster}`, ttl: soa.value.minttl });
  if (cname.status === "fulfilled" && Array.isArray(cname.value)) for (const r of cname.value) dnsRecords.push({ type: "CNAME", value: r, ttl: 300 });

  // Subdomain brute-force — 50 common prefixes
  const wordlist = [
    "www", "api", "mail", "smtp", "ftp", "vpn", "remote", "dev", "staging", "test",
    "admin", "portal", "cdn", "static", "img", "auth", "sso", "app", "mobile", "beta",
    "docs", "support", "status", "git", "jenkins", "ci", "ops", "grafana", "kibana", "monitor",
    "dashboard", "shop", "store", "blog", "forum", "wiki", "help", "sandbox", "demo", "preview",
    "api2", "v2", "v1", "internal", "intranet", "login", "accounts", "secure", "cloud", "media",
  ];

  await Promise.allSettled(
    wordlist.map(async (prefix) => {
      const full = `${prefix}.${domain}`;
      try {
        const ips = await dns.resolve4(full);
        if (!ips.length) return;
        let cn: string | null = null;
        try { const cns = await dns.resolveCname(full); cn = cns[0] ?? null; } catch {}
        subdomains.push({ name: full, ip: ips[0], cname: cn, status: "active", cdnProvider: detectCdn(cn ?? ips[0]) });
      } catch {}
    }),
  );

  return { subdomains, dnsRecords };
}

function detectCdn(hostOrIp: string): string | null {
  if (/cloudfront\.net/i.test(hostOrIp))     return "AWS CloudFront";
  if (/akamaized\.net/i.test(hostOrIp))      return "Akamai";
  if (/fastly\.net/i.test(hostOrIp))         return "Fastly";
  if (/azureedge\.net/i.test(hostOrIp))      return "Azure CDN";
  if (/cloudflare/i.test(hostOrIp))          return "Cloudflare";
  if (/stackpathcdn\.com/i.test(hostOrIp))   return "StackPath";
  return null;
}

async function runCtLogLookup(domain: string): Promise<SubdomainFinding[]> {
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10000);
    const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, { signal: ctrl.signal });
    if (!res.ok) return [];
    const data: any[] = await res.json().catch(() => []);
    const seen = new Set<string>();
    const subs: SubdomainFinding[] = [];
    for (const entry of data.slice(0, 200)) {
      const names = (entry.name_value ?? "").split("\n");
      for (let name of names) {
        name = name.toLowerCase().replace(/^\*\./, "").trim();
        if (!name || seen.has(name) || !name.endsWith(domain) || name === domain) continue;
        seen.add(name);
        let ip = "";
        try { const ips = await dns.resolve4(name); ip = ips[0] ?? ""; } catch {}
        subs.push({ name, ip, cname: null, status: ip ? "active" : "unresolved", cdnProvider: null });
      }
    }
    return subs;
  } catch { return []; }
}

async function runGeoIntel(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  let ip = domain;
  try { const ips = await dns.resolve4(domain); ip = ips[0] ?? domain; } catch {}
  if (!ip) return [];

  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,org,as,hosting,proxy,isp`, { signal: ctrl.signal });
    if (res.ok) {
      const d: any = await res.json();
      if (d.status === "success") {
        const intel: IntelItem[] = [];
        if (d.country)    intel.push({ type: "GeoIP", key: "Country",      value: d.country });
        if (d.regionName) intel.push({ type: "GeoIP", key: "Region",       value: d.regionName });
        if (d.city)       intel.push({ type: "GeoIP", key: "City",         value: d.city });
        if (d.org)        intel.push({ type: "ASN",   key: "Organization", value: d.org });
        if (d.as)         intel.push({ type: "ASN",   key: "AS Number",    value: d.as });
        if (d.isp)        intel.push({ type: "ASN",   key: "ISP",          value: d.isp });
        if (d.hosting)    intel.push({ type: "Hosting", key: "Hosting",    value: d.hosting ? "Datacenter/Hosting IP" : "Residential IP" });
        if (d.proxy)      intel.push({ type: "Risk",    key: "Proxy/VPN",  value: d.proxy ? "YES — behind proxy/VPN" : "No proxy detected" });
        intel.push({ type: "GeoIP", key: "IP Address", value: ip });
        return intel;
      }
    }
  } catch {}
  return [{ type: "GeoIP", key: "IP Address", value: ip }];
}

async function runWhoisIntel(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  if (!domain || isIp(domain)) return [];
  try {
    const { stdout } = await execAsync(`whois ${domain}`, { timeout: 12000 });
    const intel: IntelItem[] = [];
    const extract = (re: RegExp, type: string, key: string) => {
      const m = stdout.match(re);
      if (m?.[1]?.trim()) intel.push({ type, key, value: m[1].trim() });
    };
    extract(/Registrar:\s*(.+)/i,              "WHOIS", "Registrar");
    extract(/Registrant Organization:\s*(.+)/i, "WHOIS", "Registrant Org");
    extract(/Registrant Country:\s*(.+)/i,      "WHOIS", "Registrant Country");
    extract(/Creation Date:\s*(.+)/i,           "WHOIS", "Domain Created");
    extract(/Registry Expiry Date:\s*(.+)/i,    "WHOIS", "Domain Expires");
    extract(/Updated Date:\s*(.+)/i,            "WHOIS", "Last Updated");
    extract(/DNSSEC:\s*(.+)/i,                  "WHOIS", "DNSSEC");
    extract(/Name Server:\s*(.+)/i,             "WHOIS", "Name Server");
    return intel;
  } catch { return []; }
}

// ── Phase 2: Port Scanning ──────────────────────────────────────────────────────

function parseNmapNormal(output: string): PortFinding[] {
  const ports: PortFinding[] = [];
  for (const line of output.split("\n")) {
    const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
    if (m) {
      ports.push({ port: parseInt(m[1]), protocol: m[2], service: m[3].replace(/\?$/, ""), version: m[4].trim(), state: "open" });
    }
  }
  return ports;
}

async function runNmapScan(target: string, scanId: number): Promise<{ ports: PortFinding[]; raw: string }> {
  const scanTarget = extractDomain(target) || target;
  try {
    const cmd = `nmap -sT --open --top-ports 1000 -T4 -sV --version-intensity 3 --max-rtt-timeout 2s --host-timeout 50s ${scanTarget}`;
    let child: ReturnType<typeof exec> | null = null;
    const promise = new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      child = exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
        if (err && !stdout) reject(err);
        else resolve({ stdout: stdout ?? "", stderr: stderr ?? "" });
      });
    });
    activeScanKillers.set(scanId, () => { try { child?.kill("SIGTERM"); } catch {} });
    const { stdout } = await promise;
    activeScanKillers.delete(scanId);
    return { ports: parseNmapNormal(stdout), raw: stdout };
  } catch (err: any) {
    activeScanKillers.delete(scanId);
    const partial = err?.stdout ?? "";
    return { ports: parseNmapNormal(partial), raw: partial || String(err?.message ?? err) };
  }
}

// ── Phase 3: Web Recon ─────────────────────────────────────────────────────────

async function runHttpProbe(target: string): Promise<HttpInfo | null> {
  const domain = extractDomain(target);
  const candidates = [
    target.startsWith("http") ? target : null,
    `https://${domain}`,
    `http://${domain}`,
  ].filter(Boolean) as string[];

  for (const url of candidates) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), 15000);
      const response = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
      clearTimeout(tid);

      const headers: Record<string, string> = {};
      response.headers.forEach((v, k) => { headers[k] = v; });
      const body = await response.text().catch(() => "");

      const titleM = body.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
      const title = titleM ? titleM[1].trim() : "";

      const tech: string[] = [];
      const server = headers["server"] ?? "";
      const xpb = headers["x-powered-by"] ?? "";
      if (xpb)                                                   tech.push(xpb);
      if (/nginx/i.test(server))                                 tech.push("Nginx");
      if (/apache/i.test(server))                                tech.push("Apache");
      if (/IIS/i.test(server))                                   tech.push("IIS");
      if (/LiteSpeed/i.test(server))                             tech.push("LiteSpeed");
      if (/cloudflare/i.test(server) || headers["cf-ray"])       tech.push("Cloudflare");
      if (headers["x-aspnet-version"])                           tech.push("ASP.NET " + headers["x-aspnet-version"]);
      if (headers["x-drupal-cache"] || body.includes("Drupal.settings")) tech.push("Drupal");
      if (body.includes("wp-content") || body.includes("wp-includes")) tech.push("WordPress");
      if (body.includes("__NEXT_DATA__"))                        tech.push("Next.js");
      if (body.includes("react-root") || body.includes("_reactRootContainer")) tech.push("React");
      if (body.includes("ng-version") || body.includes("angular"))          tech.push("Angular");
      if (body.includes("__vue__") || body.includes("v-app"))   tech.push("Vue.js");
      if (headers["x-generator"]?.includes("Hugo"))              tech.push("Hugo");
      if (headers["x-shopify-stage"])                            tech.push("Shopify");
      if (body.includes("jquery") || body.includes("jQuery"))    tech.push("jQuery");
      if (body.includes("bootstrap"))                            tech.push("Bootstrap");

      let waf = "none";
      if (headers["cf-ray"] || /cloudflare/i.test(server))      waf = "Cloudflare";
      else if (headers["x-iinfo"])                               waf = "Imperva";
      else if (headers["x-amz-cf-id"])                          waf = "AWS WAF/CloudFront";
      else if (headers["x-sucuri-id"])                          waf = "Sucuri";
      else if (headers["x-fw-hash"])                             waf = "Wordfence";
      else if (headers["x-cdn"] === "Incapsula")                 waf = "Imperva Incapsula";
      else if (headers["server"]?.toLowerCase().includes("ddos-guard")) waf = "DDoS-Guard";

      let cdn: string | null = null;
      if (headers["cf-ray"])                                     cdn = "Cloudflare";
      else if (headers["x-amz-cf-id"])                          cdn = "AWS CloudFront";
      else if (headers["x-cache"]?.includes("cloudfront"))      cdn = "AWS CloudFront";
      else if (headers["x-fastly-request-id"])                  cdn = "Fastly";
      else if (/akamai/i.test(headers["server"] ?? ""))          cdn = "Akamai";
      else if (headers["x-azure-ref"])                           cdn = "Azure CDN";

      return { url: response.url ?? url, status: response.status, title, server, contentLength: body.length, tech: [...new Set(tech)], waf, cdn, headers };
    } catch {}
  }
  return null;
}

async function runEndpointProbe(target: string, extraPaths: string[] = []): Promise<EndpointFinding[]> {
  const domain = extractDomain(target);
  const base = `https://${domain}`;
  const paths = [
    "/", "/robots.txt", "/sitemap.xml", "/api", "/api/v1", "/api/v2",
    "/health", "/healthz", "/status", "/ping", "/.well-known/security.txt",
    "/admin", "/admin/login", "/wp-admin", "/login", "/signin",
    "/graphql", "/swagger", "/swagger-ui", "/openapi.json", "/api-docs",
    "/metrics", "/actuator", "/actuator/health", "/actuator/env",
    "/.env", "/.git/HEAD", "/.git/config",
    "/config.json", "/app-config.json", "/settings.json",
    "/debug", "/console", "/phpmyadmin", "/server-status",
    ...extraPaths,
  ];

  const results = await Promise.allSettled(
    paths.map(async (path) => {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 7000);
      const r = await fetch(`${base}${path}`, { signal: ctrl.signal, redirect: "follow" });
      const snippet = r.status === 200 ? await r.text().then(t => t.slice(0, 200)) : "";
      const titleM = snippet.match(/<title[^>]*>([^<]{0,100})<\/title>/i);
      return { url: path, method: "GET", status: r.status, title: titleM?.[1]?.trim() };
    }),
  );
  return results
    .filter(r => r.status === "fulfilled")
    .map(r => (r as PromiseFulfilledResult<EndpointFinding>).value)
    .filter(r => r.status > 0 && r.status !== 404);
}

// ── Phase 4: Secrets Scanning (trufflehog-style) ───────────────────────────────

async function runSecretsScanner(target: string, endpoints: EndpointFinding[], httpInfo: HttpInfo | null): Promise<VulnFinding[]> {
  const domain = extractDomain(target);
  const base = `https://${domain}`;
  const findings: VulnFinding[] = [];

  // Paths to scan for sensitive files
  const sensitivePaths = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.git/config", "/.npmrc", "/.dockerignore",
    "/config.js", "/config.json", "/app-config.js", "/settings.json",
    "/api-config.js", "/credentials.json", "/secrets.json",
    "/.aws/credentials", "/Dockerfile", "/docker-compose.yml", "/docker-compose.prod.yml",
    "/wp-config.php.bak", "/web.config", "/.htpasswd",
  ];

  // Collect JS file URLs from the main page HTML
  const jsUrls: string[] = [];
  if (httpInfo) {
    try {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 8000);
      const res = await fetch(`${base}/`, { signal: ctrl.signal });
      const html = await res.text();
      const matches = [...html.matchAll(/(?:src|href)=['"]([^'"]*\.js(?:\?[^'"]*)?)['"]/gi)];
      for (const m of matches) {
        const u = m[1];
        if (!u || u.includes("node_modules") || /^https?:\/\/(?!.*\.${domain})/i.test(u)) continue;
        const full = u.startsWith("http") ? u : `${base}${u.startsWith("/") ? u : `/${u}`}`;
        jsUrls.push(full);
      }
    } catch {}
  }

  const urlsToScan = [
    ...sensitivePaths.map(p => `${base}${p}`),
    ...jsUrls.slice(0, 15),
  ];

  await Promise.allSettled(
    urlsToScan.map(async (url) => {
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 8000);
        const res = await fetch(url, { signal: ctrl.signal });
        if (!res.ok) return;
        const content = await res.text();
        const path = url.replace(base, "");

        for (const pat of SECRET_PATTERNS) {
          const matches = content.match(pat.pattern);
          if (!matches) continue;
          const raw = matches[0];
          const masked = maskSecret(raw);
          const severityToCvss: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 3.0, info: 1.0 };
          findings.push({
            cve: `SEC-${pat.name.replace(/\s+/g, "-").toUpperCase().slice(0, 20)}`,
            cvss: severityToCvss[pat.severity] ?? 5.0,
            severity: pat.severity,
            title: `${pat.name} exposed in ${path}`,
            cwe: pat.cwe,
            remediation: pat.remediation,
            source: `Credential discovered at ${path}: ${masked}`,
          });
        }
      } catch {}
    })
  );

  return findings;
}

// ── Phase 5: SSL/TLS Analysis ──────────────────────────────────────────────────

async function runSslAnalysis(target: string): Promise<{ intel: IntelItem[]; vulns: VulnFinding[] }> {
  const domain = extractDomain(target);
  if (!domain || isIp(domain)) return { intel: [], vulns: [] };

  return new Promise<{ intel: IntelItem[]; vulns: VulnFinding[] }>((resolve) => {
    const intel: IntelItem[] = [];
    const vulns: VulnFinding[] = [];

    const sock = tls.connect({ host: domain, port: 443, timeout: 10000, rejectUnauthorized: false }, () => {
      try {
        const cert = sock.getPeerCertificate(true);
        if (cert) {
          if (cert.issuer?.O)     intel.push({ type: "Certificate", key: "Issuer",        value: cert.issuer.O });
          if (cert.issuer?.CN)    intel.push({ type: "Certificate", key: "Issuer CN",     value: cert.issuer.CN });
          if (cert.subject?.CN)   intel.push({ type: "Certificate", key: "Subject CN",    value: cert.subject.CN });
          if (cert.subject?.O)    intel.push({ type: "Certificate", key: "Subject Org",   value: cert.subject.O });
          if (cert.valid_from)    intel.push({ type: "Certificate", key: "Valid From",    value: cert.valid_from });
          if (cert.valid_to)      intel.push({ type: "Certificate", key: "Expires",       value: cert.valid_to });
          if (cert.serialNumber)  intel.push({ type: "Certificate", key: "Serial",        value: cert.serialNumber });
          if (cert.subjectaltname)intel.push({ type: "Certificate", key: "SANs",          value: cert.subjectaltname.replace(/DNS:/g, "").slice(0, 200) });
          if (cert.bits)          intel.push({ type: "Certificate", key: "Key Strength",  value: `${cert.bits} bits` });
          if ((cert.bits ?? 4096) < 2048) {
            vulns.push({ cve: "CWE-326", cvss: 6.5, severity: "medium", title: "Weak Certificate Key Size (< 2048 bits)", cwe: "CWE-326", remediation: "Reissue certificate with at least 2048-bit RSA or 256-bit EC key." });
          }
          const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
          if (expiry) {
            const daysLeft = Math.floor((expiry.getTime() - Date.now()) / 86400000);
            intel.push({ type: "Certificate", key: "Days Until Expiry", value: daysLeft < 0 ? `EXPIRED ${-daysLeft} days ago` : `${daysLeft} days` });
            if (daysLeft < 0) vulns.push({ cve: "CWE-298", cvss: 7.5, severity: "high",   title: "SSL Certificate is Expired", cwe: "CWE-298", remediation: "Renew the SSL certificate immediately." });
            else if (daysLeft < 30) vulns.push({ cve: "CWE-298", cvss: 5.0, severity: "medium", title: `SSL Certificate Expiring in ${daysLeft} Days`, cwe: "CWE-298", remediation: "Renew certificate before it expires." });
          }
        }
        const protocol = sock.getProtocol();
        if (protocol) {
          intel.push({ type: "TLS", key: "Protocol", value: protocol });
          if (protocol === "SSLv2" || protocol === "SSLv3" || protocol === "TLSv1" || protocol === "TLSv1.1") {
            vulns.push({ cve: "CVE-2014-3566", cvss: 7.5, severity: "high", title: `Deprecated TLS Protocol in Use (${protocol})`, cwe: "CWE-327", remediation: "Disable SSL/TLS 1.0/1.1 and use TLS 1.2+ only." });
          }
        }
        const cipher = sock.getCipher();
        if (cipher) {
          intel.push({ type: "TLS", key: "Cipher Suite", value: `${cipher.name} (${cipher.version})` });
          if (/RC4|DES|3DES|MD5|NULL|ANON|EXPORT/i.test(cipher.name)) {
            vulns.push({ cve: "CWE-327", cvss: 7.5, severity: "high", title: `Weak/Deprecated Cipher Suite (${cipher.name})`, cwe: "CWE-327", remediation: "Disable weak ciphers and use AES-GCM or ChaCha20-Poly1305." });
          }
        }
      } catch {}
      sock.destroy();
      resolve({ intel, vulns });
    });
    sock.on("error", () => resolve({ intel, vulns }));
    sock.setTimeout(10000, () => { sock.destroy(); resolve({ intel, vulns }); });
  });
}

// ── Security headers analysis ──────────────────────────────────────────────────

function analyzeSecurityHeaders(httpInfo: HttpInfo | null): VulnFinding[] {
  if (!httpInfo) return [];
  const h = httpInfo.headers;
  const vulns: VulnFinding[] = [];

  const check = (condition: boolean, cve: string, cvss: number, severity: string, title: string, cwe: string, remediation: string) => {
    if (condition) vulns.push({ cve, cvss, severity, title, cwe, remediation });
  };

  check(!h["strict-transport-security"],   "HDR-HSTS",   6.5, "medium", "Missing HTTP Strict Transport Security (HSTS)",           "CWE-319", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
  check(!h["content-security-policy"],     "HDR-CSP",    6.1, "medium", "Missing Content Security Policy (CSP) Header",            "CWE-116", "Define a strict Content-Security-Policy to prevent XSS.");
  check(!h["x-frame-options"] && !h["content-security-policy"]?.includes("frame-ancestors"), "HDR-XFRAME", 4.3, "medium", "Missing X-Frame-Options — Clickjacking Vulnerability", "CWE-1021", "Add: X-Frame-Options: DENY");
  check(!h["x-content-type-options"],      "HDR-XCTO",   3.7, "low",    "Missing X-Content-Type-Options — MIME Sniffing Risk",     "CWE-16",  "Add: X-Content-Type-Options: nosniff");
  check(!h["referrer-policy"],             "HDR-RP",     3.1, "low",    "Missing Referrer-Policy — Information Leakage",           "CWE-200", "Add: Referrer-Policy: strict-origin-when-cross-origin");
  check(!h["permissions-policy"],          "HDR-PP",     3.1, "low",    "Missing Permissions-Policy Header",                       "CWE-16",  "Add Permissions-Policy to restrict browser feature access.");
  check(!h["cross-origin-embedder-policy"],"HDR-COEP",   3.1, "low",    "Missing Cross-Origin-Embedder-Policy (COEP)",             "CWE-16",  "Add: Cross-Origin-Embedder-Policy: require-corp");
  check(!h["cross-origin-opener-policy"],  "HDR-COOP",   3.1, "low",    "Missing Cross-Origin-Opener-Policy (COOP)",               "CWE-16",  "Add: Cross-Origin-Opener-Policy: same-origin");

  if (h["server"]?.length) {
    vulns.push({ cve: "HDR-SRV", cvss: 3.7, severity: "low", title: `Server Version Disclosure: ${h["server"]}`, cwe: "CWE-200", remediation: 'Configure server to omit "Server" header or use a generic value.' });
  }
  if (h["x-powered-by"]) {
    vulns.push({ cve: "HDR-XPB", cvss: 3.7, severity: "low", title: `Technology Disclosure via X-Powered-By: ${h["x-powered-by"]}`, cwe: "CWE-200", remediation: "Remove X-Powered-By header." });
  }

  return vulns;
}

// ── Cloud surface scan ────────────────────────────────────────────────────────

async function runCloudSurfaceScan(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  const company = domain.split(".")[0];
  const intel: IntelItem[] = [];

  const buckets = [
    company, `${company}-backup`, `${company}-backups`, `${company}-dev`, `${company}-staging`,
    `${company}-prod`, `${company}-assets`, `${company}-media`, `${company}-files`,
    `${company}-uploads`, `${company}-data`, `${company}-logs`, `${company}-archive`,
    `${company}-public`, `${company}-private`, `${company}-static`,
  ];

  await Promise.allSettled(
    buckets.map(async (bucket) => {
      const url = `https://${bucket}.s3.amazonaws.com`;
      try {
        const ctrl = new AbortController();
        setTimeout(() => ctrl.abort(), 4000);
        const res = await fetch(url, { signal: ctrl.signal });
        const text = await res.text().catch(() => "");
        if (res.status === 200 || text.includes("ListBucketResult")) {
          intel.push({ type: "Cloud", key: "Exposed S3 Bucket", value: `${url} — PUBLICLY ACCESSIBLE`, severity: "critical" });
        } else if (res.status === 403 || text.includes("AccessDenied")) {
          intel.push({ type: "Cloud", key: "S3 Bucket (private)", value: `${bucket}.s3.amazonaws.com — bucket exists but access denied` });
        }
      } catch {}
    })
  );

  return intel;
}

// ── CVE matching from discovered services ─────────────────────────────────────

function matchCvesFromPorts(ports: PortFinding[], httpInfo: HttpInfo | null, tech: string[]): VulnFinding[] {
  const vulns: VulnFinding[] = [];
  const seen = new Set<string>();

  const serviceStr = [
    ...ports.map(p => `${p.service} ${p.version} ${p.port}`),
    httpInfo ? [...httpInfo.tech, httpInfo.server].join(" ") : "",
    ...tech,
  ].join(" ").toLowerCase();

  for (const cve of CVE_POOL) {
    if (seen.has(cve.cve)) continue;
    if (cve.affected.some(a => serviceStr.includes(a.toLowerCase()))) {
      vulns.push({ cve: cve.cve, cvss: cve.cvss, severity: cve.severity, title: cve.title, cwe: cve.cwe, remediation: cve.remediation });
      seen.add(cve.cve);
    }
  }

  return vulns;
}

// ── Build per-tool raw output ─────────────────────────────────────────────────

function buildRawOutput(toolName: string, target: string, phase: string, data: {
  ports?: PortFinding[] | null; nmapRaw?: string; subdomains?: SubdomainFinding[] | null;
  dnsRecords?: DnsRecord[] | null; httpInfo?: HttpInfo | null; endpoints?: EndpointFinding[] | null;
  vulnerabilities?: VulnFinding[] | null; intelligence?: IntelItem[] | null;
  secretsFound?: VulnFinding[] | null; technologies?: DetectedTechnology[] | null;
}): string {
  const ts = new Date().toISOString();
  const lines = [`[${toolName}] Target: ${target}`, `[${toolName}] Phase: ${phase}`, `[${toolName}] Started: ${ts}`, ""];

  if (data.nmapRaw) {
    lines.push("=== NMAP PORT SCAN ==="); lines.push(data.nmapRaw); lines.push("");
  } else if (data.ports?.length) {
    lines.push("=== OPEN PORTS ===");
    lines.push("PORT     PROTO  SERVICE          VERSION");
    for (const p of data.ports) lines.push(`${String(p.port).padEnd(8)} ${p.protocol.padEnd(6)} ${p.service.padEnd(16)} ${p.version}`);
    lines.push("");
  }
  if (data.dnsRecords?.length) {
    lines.push("=== DNS RECORDS ===");
    for (const r of data.dnsRecords) lines.push(`  ${r.type.padEnd(6)} ${r.value}${r.priority ? ` (priority ${r.priority})` : ""} [TTL: ${r.ttl}]`);
    lines.push("");
  }
  if (data.subdomains?.length) {
    lines.push("=== SUBDOMAINS DISCOVERED ===");
    for (const s of data.subdomains) lines.push(`  ${s.name.padEnd(45)} ${s.ip.padEnd(18)} ${s.status}${s.cdnProvider ? ` [${s.cdnProvider}]` : ""}${s.cname ? ` → ${s.cname}` : ""}`);
    lines.push("");
  }
  if (data.httpInfo) {
    const h = data.httpInfo;
    lines.push("=== HTTP/WEB PROBE ===");
    lines.push(`  URL:        ${h.url}`);
    lines.push(`  Status:     ${h.status}`);
    lines.push(`  Title:      ${h.title || "(none)"}`);
    lines.push(`  Server:     ${h.server || "(unknown)"}`);
    lines.push(`  Technology: ${h.tech.join(", ") || "—"}`);
    lines.push(`  WAF:        ${h.waf}`);
    lines.push(`  CDN:        ${h.cdn ?? "none"}`);
    lines.push(`  Body Size:  ${(h.contentLength / 1024).toFixed(1)} KB`);
    lines.push("  Security Headers:");
    const secHeaders = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"];
    for (const sh of secHeaders) lines.push(`    ${sh}: ${h.headers[sh] ?? "MISSING ⚠"}`);
    lines.push("  All Headers:");
    for (const [k, v] of Object.entries(h.headers)) lines.push(`    ${k}: ${v}`);
    lines.push("");
  }
  if (data.endpoints?.length) {
    lines.push("=== ENDPOINTS DISCOVERED ===");
    for (const e of data.endpoints) lines.push(`  [${String(e.status).padEnd(3)}] GET ${e.url}${e.title ? `  — ${e.title}` : ""}`);
    lines.push("");
  }
  if (data.secretsFound?.length) {
    lines.push("=== SECRETS & CREDENTIALS FOUND ===");
    for (const s of data.secretsFound) {
      lines.push(`  [${s.severity.toUpperCase()}] ${s.title}`);
      if (s.source) lines.push(`         → ${s.source}`);
      lines.push(`         Remediation: ${s.remediation}`);
    }
    lines.push("");
  }
  if (data.technologies?.length) {
    lines.push("=== TECHNOLOGIES DETECTED ===");
    lines.push("  TECHNOLOGY                    CATEGORY              VERSION     CONFIDENCE");
    for (const t of data.technologies) {
      const name = t.name.padEnd(29);
      const cat  = t.category.padEnd(21);
      const ver  = (t.version ?? "—").padEnd(11);
      lines.push(`  ${name} ${cat} ${ver} ${t.confidence}%`);
    }
    const categories = [...new Set(data.technologies.map(t => t.category))];
    lines.push("");
    lines.push(`  Summary: ${data.technologies.length} technologies detected across ${categories.length} categories`);
    lines.push(`  Categories: ${categories.join(", ")}`);
    lines.push("");
  }
  if (data.vulnerabilities?.length) {
    lines.push("=== VULNERABILITIES IDENTIFIED ===");
    for (const v of data.vulnerabilities) {
      lines.push(`  [${v.severity.toUpperCase()}] ${v.cve} CVSS:${v.cvss} — ${v.title}`);
      lines.push(`         ${v.cwe} | ${v.remediation}`);
    }
    lines.push("");
  }
  if (data.intelligence?.length) {
    lines.push("=== INTELLIGENCE GATHERED ===");
    for (const i of data.intelligence) lines.push(`  [${i.type}] ${i.key}: ${i.value}`);
    lines.push("");
  }

  lines.push(`[${toolName}] Scan phase complete — ${new Date().toISOString()}`);
  return lines.join("\n");
}

// ── Core pipeline execution ───────────────────────────────────────────────────

async function executePipeline(
  tenantId: number,
  scanId: number,
  assetConfigs: AssetToolConfigItem[],
  allTools: (typeof securityToolsTable.$inferSelect)[],
  enabledTools: (typeof securityToolsTable.$inferSelect)[],
): Promise<{ findingsCount: number }> {
  const assetIds = assetConfigs.map(c => c.assetId);
  const assets = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.tenantId, tenantId), inArray(assetsTable.id, assetIds)));

  // ── Auto-ensure built-in tools exist for this tenant ─────────────────────
  const builtinToolDefs = [
    { name: "wappalyzer", description: "Technology fingerprinting engine — identifies CMS, JS frameworks, CDN, analytics, security products, and 60+ tech categories via HTTP headers, HTML patterns, cookies, and script signatures", category: "web_recon",  githubUrl: "https://github.com/enthec/webappanalyzer", runCommand: "wappalyzer {target}" },
    { name: "webcheck",   description: "Comprehensive web security checker — audits HTTP security headers (HSTS, CSP, X-Frame-Options, CORP, COEP), cookie flags, TLS configuration, and security policy compliance",          category: "web_recon",  githubUrl: "https://github.com/lissy93/web-check",     runCommand: "webcheck {target}" },
    { name: "gowitness",  description: "Web screenshot utility using system Chromium — captures index, login, signup, admin, and API pages with full-page renders and HTTP metadata",                                           category: "screenshot", githubUrl: "https://github.com/sensepost/gowitness",    runCommand: "gowitness single --url https://{target}" },
    { name: "eyewitness", description: "Visual recon tool that captures web screenshots, server headers, and identifies default credentials on web-exposed services",                                                           category: "screenshot", githubUrl: "https://github.com/RedSiege/EyeWitness",    runCommand: "eyewitness --web --single https://{target}" },
    { name: "snapback",   description: "Screenshot and sensitive info disclosure scanner for web pages, detecting hardcoded API keys, tokens, credentials, and internal endpoints",                                            category: "screenshot", githubUrl: "https://github.com/dekz/snapback",          runCommand: "snapback scan {target}" },
    // ── Subdomain enumeration engine tools (auto-run for every domain asset) ─
    { name: "subfinder",  description: "Fast passive subdomain discovery with 40+ data sources (VirusTotal, Chaos, DNSdb, Shodan, etc.) — auto-runs on every domain asset scan",                                             category: "recon",      githubUrl: "https://github.com/projectdiscovery/subfinder", runCommand: "subfinder -d {target} -all -silent" },
    { name: "findomain",  description: "CT-log-based subdomain finder using Certificate Transparency + multiple passive sources — auto-runs on every domain asset scan",                                                      category: "recon",      githubUrl: "https://github.com/Findomain/Findomain",       runCommand: "findomain -t {target} -q" },
    { name: "httpx",      description: "Fast multi-purpose HTTP probing — status codes, tech detection, web server, page titles, redirect chains — probes all discovered subdomains",                                        category: "web_recon",  githubUrl: "https://github.com/projectdiscovery/httpx",    runCommand: "httpx -u {target} -json -status-code -title -tech-detect" },
    { name: "dnsx",       description: "Fast bulk DNS resolver and brute-forcer — resolves all subdomain candidates and active DNS brute-force with built-in wordlist",                                                       category: "recon",      githubUrl: "https://github.com/projectdiscovery/dnsx",     runCommand: "dnsx -d {target} -silent -a" },
    { name: "alterx",     description: "Smart subdomain permutation wordlist generator — creates variations from existing subdomains using customisable patterns for active discovery",                                        category: "recon",      githubUrl: "https://github.com/projectdiscovery/alterx",   runCommand: "alterx -d {target} -silent" },
  ];
  for (const def of builtinToolDefs) {
    const exists = await db.select({ id: securityToolsTable.id })
      .from(securityToolsTable)
      .where(and(eq(securityToolsTable.tenantId, tenantId), eq(securityToolsTable.name, def.name)))
      .then(r => r.length > 0);
    if (!exists) {
      await db.insert(securityToolsTable).values({
        tenantId, name: def.name, description: def.description, category: def.category,
        githubUrl: def.githubUrl, installCommand: "built-in (no install required)",
        updateCommand: "built-in", runCommand: def.runCommand, outputFormat: "json", isActive: true,
      });
    }
  }

  let totalFindings = 0;
  scanProgressMap.set(scanId, []);

  for (const config of assetConfigs) {
    const currentScan = await db.select({ status: scansTable.status }).from(scansTable)
      .where(eq(scansTable.id, scanId)).then(r => r[0]);
    if (currentScan?.status === "cancelled") break;

    const asset = assets.find(a => a.id === config.assetId);
    if (!asset) continue;

    const toolsForAsset = config.toolIds.length > 0
      ? allTools.filter(t => config.toolIds.includes(t.id))
      : enabledTools;
    if (toolsForAsset.length === 0) continue;

    const target = asset.value;
    const domain = extractDomain(target);
    const now = () => new Date().toISOString();
    const ms = (start: number) => Date.now() - start;

    // ── Start subdomain scan early (runs in parallel with all phases) ────────
    // Hard 3-minute outer timeout — binary downloads + passive queries must finish
    // within this window or the scan proceeds without subdomain enrichment.
    const SUBDOMAIN_TIMEOUT_MS = 3 * 60 * 1000;
    const subdomainScanPromise: Promise<SubdomainScanReport | null> =
      domain && !isIp(domain)
        ? Promise.race([
            scanSubdomains(domain).catch(() => null),
            new Promise<null>(resolve => setTimeout(() => resolve(null), SUBDOMAIN_TIMEOUT_MS)),
          ])
        : Promise.resolve(null);

    // ── Init progress for this asset ────────────────────────────────────────
    const toolProgress: ToolProgress[] = toolsForAsset.map(t => ({
      toolName: t.name, toolCategory: t.category ?? "recon",
      phase: TOOL_PHASE[t.name] ?? 1, status: "queued",
      startedAt: null, completedAt: null, durationMs: null,
      findingsCount: 0, detail: `Queued — ${PHASE_NAMES[TOOL_PHASE[t.name] ?? 1]}`,
    }));
    const progress = scanProgressMap.get(scanId)!;
    progress.push({ assetId: asset.id, assetName: asset.name, assetValue: asset.value, tools: toolProgress });

    const updateTool = (toolName: string, upd: Partial<ToolProgress>) => {
      const t = toolProgress.find(t => t.toolName === toolName);
      if (t) Object.assign(t, upd);
    };
    const startTool = (toolName: string, detail: string) => {
      updateTool(toolName, { status: "running", startedAt: now(), detail });
    };
    const doneTool = (toolName: string, findingsCount: number, detail: string, startMs: number) => {
      updateTool(toolName, { status: "done", completedAt: now(), durationMs: ms(startMs), findingsCount, detail });
    };

    // Group tools by phase
    const byPhase = (phase: number) => toolsForAsset.filter(t => (TOOL_PHASE[t.name] ?? 1) === phase);
    const p1 = byPhase(1); const p2 = byPhase(2);
    const p3 = byPhase(3); const p4 = byPhase(4); const p5 = byPhase(5);

    const needsDns    = p1.some(t => ["recon", "osint"].includes(t.category ?? "")) || toolsForAsset.some(t => t.category === "recon");
    const needsGeo    = p1.some(t => t.category === "osint" || ["asnmap", "cdncheck", "uncover", "theHarvester"].includes(t.name));
    const needsWhois  = p1.some(t => t.category === "osint" || ["theHarvester", "maltego"].includes(t.name));
    const needsCt     = p1.some(t => ["amass", "subfinder", "shuffledns"].includes(t.name));
    const needsCloud  = p1.some(t => ["s3scanner", "cloud_enum"].includes(t.name));
    const needsNmap   = p2.length > 0 || toolsForAsset.some(t => t.category === "vuln_scan"); // kept for legacy; port scan now always runs
    const needsHttp   = p3.length > 0;
    const needsSecrets= p4.some(t => t.name === "trufflehog");
    const needsSsl    = p5.length > 0 || toolsForAsset.some(t => t.category === "ssl_check");
    const needsVulns  = p4.length > 0 || toolsForAsset.some(t => t.category === "vuln_scan");

    // ── PHASE 1: Reconnaissance ───────────────────────────────────────────────
    const p1Start = Date.now();
    for (const t of p1) startTool(t.name, `Running ${PHASE_NAMES[1]}…`);

    let dnsResult = { subdomains: [] as SubdomainFinding[], dnsRecords: [] as DnsRecord[] };
    let ctSubdomains: SubdomainFinding[] = [];
    let geoIntel: IntelItem[] = [];
    let whoisIntel: IntelItem[] = [];
    let cloudIntel: IntelItem[] = [];

    await Promise.allSettled([
      needsDns   && (async () => { dnsResult     = await runDnsRecon(target); })(),
      needsCt    && !isIp(domain) && (async () => { ctSubdomains = await runCtLogLookup(domain); })(),
      needsGeo   && (async () => { geoIntel      = await runGeoIntel(target); })(),
      needsWhois && !isIp(domain) && (async () => { whoisIntel   = await runWhoisIntel(target); })(),
      needsCloud && (async () => { cloudIntel    = await runCloudSurfaceScan(target); })(),
    ].filter(Boolean));

    // Merge CT with DNS subdomains
    const seenSubs = new Set(dnsResult.subdomains.map(s => s.name));
    for (const s of ctSubdomains) { if (!seenSubs.has(s.name)) { dnsResult.subdomains.push(s); seenSubs.add(s.name); } }

    for (const t of p1) {
      const cat = t.category ?? "recon";
      const subs = dnsResult.subdomains.length;
      const recs = dnsResult.dnsRecords.length;
      const intel = geoIntel.length + whoisIntel.length;
      let detail = "";
      if (cat === "recon")       detail = `${subs} subdomains, ${recs} DNS records`;
      else if (cat === "osint")  detail = `${intel} intel items, ${cloudIntel.length} cloud assets`;
      else if (t.name === "s3scanner" || t.name === "cloud_enum") detail = `${cloudIntel.length} cloud resources`;
      else if (t.name === "gau") detail = `${dnsResult.subdomains.length} attack surface entries`;
      else                        detail = `${subs} subdomains, ${recs} DNS records`;
      doneTool(t.name, subs + recs, detail, p1Start);
    }

    // ── PHASE 2: Port Scanning — always runs (Naabu + Nmap + Shodan) ──────────
    let realPorts: PortFinding[] = [];
    let nmapRaw = "";
    let portScanReport: PortScanReport | null = null;
    {
      const p2Start = Date.now();
      for (const t of p2) startTool(t.name, `Full-port discovery on ${domain} (Naabu + Nmap + Shodan)…`);

      portScanReport = await scanPorts(target);
      realPorts = portScanReport.ports as PortFinding[];
      nmapRaw = [
        `=== NAABU — Full Port Discovery (${portScanReport.naabuPorts.length} ports found, 1–65535) ===`,
        portScanReport.naabuRaw.slice(0, 3000) || "(no output)",
        "",
        `=== NMAP — Service Detection + NSE Scripts (${portScanReport.scanMethod}) ===`,
        portScanReport.nmapRaw.slice(0, 8000) || "(no output)",
        "",
        portScanReport.shodan
          ? `=== SHODAN InternetDB — ${portScanReport.targetIp ?? "?"} ===\nPorts: ${portScanReport.shodan.ports.join(", ") || "none"}\nTags: ${portScanReport.shodan.tags.join(", ") || "none"}\nCPEs: ${portScanReport.shodan.cpes.slice(0, 5).join(", ") || "none"}\nCVEs: ${portScanReport.shodan.vulns.join(", ") || "none"}\nHostnames: ${portScanReport.shodan.hostnames.join(", ") || "none"}`
          : "=== SHODAN InternetDB — no data available ===",
      ].join("\n");

      // Merge Shodan intelligence into geoIntel for display in Intel tab
      if (portScanReport.shodan) {
        const sh = portScanReport.shodan;
        if (sh.tags.length > 0)      geoIntel.push({ type: "Shodan", key: "Tags",         value: sh.tags.join(", ") });
        if (sh.hostnames.length > 0) geoIntel.push({ type: "Shodan", key: "Hostnames",    value: sh.hostnames.join(", ") });
        if (sh.cpes.length > 0)      geoIntel.push({ type: "Shodan", key: "CPEs",         value: sh.cpes.slice(0, 10).join(", ") });
        if (sh.vulns.length > 0)     geoIntel.push({ type: "Shodan", key: "Known CVEs",   value: sh.vulns.join(", ") });
        if (sh.ports.length > 0)     geoIntel.push({ type: "Shodan", key: "Shodan Ports", value: sh.ports.join(", ") });
        geoIntel.push({ type: "Shodan", key: "Scan Method",  value: portScanReport.scanMethod });
        if (portScanReport.targetIp) geoIntel.push({ type: "Shodan", key: "Resolved IP",  value: portScanReport.targetIp });
      }

      if (p2.length > 0) {
        const shodanSummary = portScanReport.shodan
          ? `Shodan: ${portScanReport.shodan.vulns.length} CVEs, ${portScanReport.shodan.tags.length} tags`
          : "Shodan: no data";
        for (const t of p2) doneTool(t.name, realPorts.length, `${realPorts.length} open ports | ${portScanReport.scanMethod} | ${shodanSummary}`, p2Start);
      }
    }

    // ── PHASE 3: Web Recon ────────────────────────────────────────────────────
    let httpInfo: HttpInfo | null = null;
    let endpoints: EndpointFinding[] = [];
    let detectedTechs: DetectedTechnology[] = [];
    let capturedPages: PageScreenshot[] = [];
    const hasScreenshotTools = toolsForAsset.some(t => t.category === "screenshot");
    // Screenshots + tech detection always run for web asset types regardless of tool pipeline
    const isWebAsset = ["domain", "subdomain", "url", "ip"].includes(asset.type ?? "");
    const shouldScreenshot = isWebAsset; // always capture for web assets
    if (needsHttp || toolsForAsset.some(t => t.category === "web_recon") || hasScreenshotTools || isWebAsset) {
      const p3Start = Date.now();
      for (const t of p3) startTool(t.name, t.category === "screenshot"
        ? `Capturing screenshots of ${domain}…`
        : `Probing web application at ${domain}…`);

      await Promise.allSettled([
        (async () => { httpInfo  = await runHttpProbe(target); })(),
        (async () => { endpoints = await runEndpointProbe(target); })(),
        (async () => { detectedTechs = await detectTechnologies(target); })(),
        shouldScreenshot
          ? (async () => { capturedPages = await captureScreenshots(target, 90000); })()
          : Promise.resolve(),
      ]);

      // ── Auto-store technology detections for this asset ──────────────────
      if (detectedTechs.length > 0) {
        await db.delete(technologyDetectionsTable)
          .where(and(eq(technologyDetectionsTable.tenantId, tenantId), eq(technologyDetectionsTable.assetId, asset.id)));
        await db.insert(technologyDetectionsTable).values(
          detectedTechs.map(t => ({
            tenantId,
            assetId: asset.id,
            scanId,
            technology: t.name,
            slug: t.slug,
            category: t.category,
            version: t.version ?? null,
            confidence: t.confidence,
            website: t.website ?? null,
            cpe: t.cpe ?? null,
            icon: t.icon ?? null,
          }))
        );
      }

      // ── Auto-store screenshots for this asset ─────────────────────────
      if (capturedPages.length > 0) {
        await db.delete(screenshotsTable)
          .where(and(eq(screenshotsTable.tenantId, tenantId), eq(screenshotsTable.assetId, asset.id)));
        await db.insert(screenshotsTable).values(
          capturedPages.map(p => ({
            tenantId,
            assetId: asset.id,
            scanId,
            url:            p.url,
            pageType:       p.pageType,
            screenshotData: p.screenshotData,
            title:          p.title ?? null,
            statusCode:     p.statusCode ?? null,
            findings:       p.findings,
          }))
        );
      }

      const headerVulns = analyzeSecurityHeaders(httpInfo);
      const techList = httpInfo?.tech ?? [];

      for (const t of p3) {
        let detail = "";
        if (t.name === "wappalyzer") {
          detail = `${detectedTechs.length} technologies detected: ${[...new Set(detectedTechs.map(t => t.category))].join(", ")}`;
          doneTool(t.name, detectedTechs.length, detail, p3Start);
        } else if (t.name === "webcheck") {
          detail = `${headerVulns.length} security header issues | WAF: ${httpInfo?.waf ?? "none"} | CDN: ${httpInfo?.cdn ?? "none"}`;
          doneTool(t.name, headerVulns.length, detail, p3Start);
        } else if (t.name === "gowitness") {
          const cnt = capturedPages.length;
          const findings = capturedPages.reduce((n, p) => n + (p.findings?.length ?? 0), 0);
          detail = `${cnt} page${cnt === 1 ? "" : "s"} captured (index, login, signup, admin, api) | ${findings} sensitive findings`;
          doneTool(t.name, cnt, detail, p3Start);
        } else if (t.name === "eyewitness") {
          const cnt = capturedPages.length;
          detail = `${cnt} screenshot${cnt === 1 ? "" : "s"} captured | page types: ${[...new Set(capturedPages.map(p => p.pageType))].join(", ")}`;
          doneTool(t.name, cnt, detail, p3Start);
        } else if (t.name === "snapback") {
          const sensitiveCount = capturedPages.filter(p => (p.findings?.length ?? 0) > 0).length;
          detail = `${capturedPages.length} pages analyzed | ${sensitiveCount} with sensitive disclosures`;
          doneTool(t.name, sensitiveCount, detail, p3Start);
        } else if (["httpx", "whatweb", "wafw00f"].includes(t.name)) {
          detail = `${techList.join(", ") || "no tech"} | WAF: ${httpInfo?.waf ?? "none"}`;
          doneTool(t.name, endpoints.length + headerVulns.length, detail, p3Start);
        } else if (["feroxbuster", "gobuster", "ffuf", "katana"].includes(t.name)) {
          detail = `${endpoints.length} endpoints discovered`;
          doneTool(t.name, endpoints.length, detail, p3Start);
        } else {
          detail = `${endpoints.length} endpoints, ${headerVulns.length} header issues`;
          doneTool(t.name, endpoints.length + headerVulns.length, detail, p3Start);
        }
      }
    }

    // ── PHASE 4: Vuln & Secrets Scanning ─────────────────────────────────────
    let secretFindings: VulnFinding[] = [];
    let cveFindings: VulnFinding[] = [];
    let headerVulnFindings: VulnFinding[] = [];

    if (needsVulns || needsSecrets) {
      const p4Start = Date.now();
      for (const t of p4) startTool(t.name, t.name === "trufflehog" ? `Scanning ${domain} for exposed credentials & secrets…` : `Running vulnerability analysis on ${domain}…`);

      await Promise.allSettled([
        needsSecrets  && (async () => { secretFindings = await runSecretsScanner(target, endpoints, httpInfo); })(),
        (async () => {
          cveFindings = matchCvesFromPorts(realPorts, httpInfo, httpInfo?.tech ?? []);
          headerVulnFindings = analyzeSecurityHeaders(httpInfo);
        })(),
      ].filter(Boolean));

      for (const t of p4) {
        const isSecrets = t.name === "trufflehog";
        const count = isSecrets ? secretFindings.length : cveFindings.length + headerVulnFindings.length;
        doneTool(t.name, count, isSecrets ? `${secretFindings.length} secrets/credentials found` : `${cveFindings.length} CVEs, ${headerVulnFindings.length} header issues`, p4Start);
      }
    }

    // ── PHASE 5: SSL/TLS ──────────────────────────────────────────────────────
    let sslIntel: IntelItem[] = [];
    let sslVulns: VulnFinding[] = [];
    if (needsSsl) {
      const p5Start = Date.now();
      for (const t of p5) startTool(t.name, `Analyzing SSL/TLS configuration of ${domain}…`);
      const sslResult = await runSslAnalysis(target);
      sslIntel = sslResult.intel;
      sslVulns = sslResult.vulns;
      for (const t of p5) doneTool(t.name, sslVulns.length, `${sslIntel.length} cert details, ${sslVulns.length} issues`, p5Start);
    }

    // ── Fallback tech detection (runs when no web_recon phase 3 tools ran) ────
    if (detectedTechs.length === 0 && ["domain", "subdomain", "url"].includes(asset.type ?? "")) {
      detectedTechs = await detectTechnologies(target);
      if (detectedTechs.length > 0) {
        await db.delete(technologyDetectionsTable)
          .where(and(eq(technologyDetectionsTable.tenantId, tenantId), eq(technologyDetectionsTable.assetId, asset.id)));
        await db.insert(technologyDetectionsTable).values(
          detectedTechs.map(t => ({
            tenantId, assetId: asset.id, scanId,
            technology: t.name, slug: t.slug, category: t.category,
            version: t.version ?? null, confidence: t.confidence,
            website: t.website ?? null, cpe: t.cpe ?? null, icon: t.icon ?? null,
          }))
        );
      }
    }

    // ── Await subdomain scan (was running in parallel with all phases) ─────────
    const subdomainScanReport = await subdomainScanPromise;
    if (subdomainScanReport) {
      const seenSubs = new Set(dnsResult.subdomains.map(s => s.name));
      for (const s of subdomainScanReport.all) {
        if (!seenSubs.has(s.name)) {
          dnsResult.subdomains.push({
            name: s.name, ip: s.ip, cname: s.cname,
            status: s.ip ? "active" : "unresolved",
            cdnProvider: s.cdnProvider,
            sources: s.sources, httpStatus: s.httpStatus,
            httpTitle: s.httpTitle, redirectTo: s.redirectTo, webServer: s.webServer,
          });
          seenSubs.add(s.name);
        } else {
          const existing = dnsResult.subdomains.find(x => x.name === s.name);
          if (existing) {
            existing.sources    = s.sources;
            existing.httpStatus = s.httpStatus;
            existing.httpTitle  = s.httpTitle;
            existing.redirectTo = s.redirectTo;
            existing.webServer  = s.webServer;
            if (s.ip && !existing.ip) existing.ip = s.ip;
            if (s.cdnProvider && !existing.cdnProvider) existing.cdnProvider = s.cdnProvider;
          }
        }
      }
    }

    // ── Compile all data and store per-tool results ────────────────────────────
    const allIntel    = [...sslIntel, ...geoIntel, ...whoisIntel, ...cloudIntel];
    const allVulns    = [...cveFindings, ...sslVulns, ...headerVulnFindings, ...secretFindings];
    const allSubdomains = dnsResult.subdomains;
    const allDns      = dnsResult.dnsRecords;

    const results: Array<typeof scanAssetResultsTable.$inferInsert> = [];
    const findingInserts: Array<typeof findingsTable.$inferInsert>   = [];

    // Insert findings once (not per-tool, to avoid duplicates)
    for (const v of cveFindings) {
      if (!v.cve.startsWith("HDR-") && !v.cve.startsWith("SEC-")) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: v.title, cve: v.cve,
          severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
          cvssScore: String(v.cvss), cwe: v.cwe, status: "open",
          description: `${v.title} (${v.cve}) — CVSS ${v.cvss}. Detected on ${asset.name} (${asset.value}).`,
          remediation: v.remediation,
        });
      }
    }

    for (const tool of toolsForAsset) {
      const cat   = tool.category ?? "recon";
      const phase = TOOL_PHASE[tool.name] ?? 1;
      const name  = tool.name;

      let toolPorts:    PortFinding[]        | null = null;
      let toolSubs:     SubdomainFinding[]   | null = null;
      let toolEndpts:   EndpointFinding[]    | null = null;
      let toolHttp:     HttpInfo             | null = null;
      let toolDns:      DnsRecord[]          | null = null;
      let toolIntel:    IntelItem[]          | null = null;
      let toolVulns:    VulnFinding[]        | null = null;
      let toolSecrets:  VulnFinding[]        | null = null;
      let toolTech:     DetectedTechnology[] | null = null;

      if (phase === 1) {
        // ── Subdomain discovery tools ──────────────────────────────────────────
        if (["subfinder", "shuffledns", "tldfinder"].includes(name)) {
          toolSubs = allSubdomains.length ? allSubdomains : null;
        }
        // ── DNS resolution / enumeration ───────────────────────────────────────
        else if (name === "dnsx") {
          toolDns  = allDns.length ? allDns : null;
          toolSubs = allSubdomains.length ? allSubdomains : null;
        }
        // ── Full passive recon (amass covers subs + DNS + OSINT) ───────────────
        else if (name === "amass") {
          toolSubs  = allSubdomains.length ? allSubdomains : null;
          toolDns   = allDns.length ? allDns : null;
          toolIntel = geoIntel.length + whoisIntel.length > 0 ? [...geoIntel, ...whoisIntel] : null;
        }
        // ── Historical URL / passive URL collection ────────────────────────────
        else if (name === "gau" || name === "uncover") {
          toolEndpts = endpoints.length ? endpoints : null;
          toolSubs   = allSubdomains.length ? allSubdomains : null;
        }
        // ── ASN / CIDR / IP intel ──────────────────────────────────────────────
        else if (["asnmap", "mapcidr", "cdncheck"].includes(name)) {
          toolIntel = [...geoIntel, ...whoisIntel].length ? [...geoIntel, ...whoisIntel] : null;
        }
        // ── OSINT / email / breach harvesting ─────────────────────────────────
        else if (["theHarvester", "aix", "maltego"].includes(name) || cat === "osint") {
          toolIntel = allIntel.length ? allIntel : null;
        }
        // ── Cloud / bucket enumeration ─────────────────────────────────────────
        else if (["cloud_enum", "s3scanner"].includes(name)) {
          toolIntel = cloudIntel.length ? cloudIntel : null;
        }
        // ── Default: generic phase-1 tool gets subdomain results ───────────────
        else {
          toolSubs = allSubdomains.length ? allSubdomains : null;
        }
      } else if (phase === 2) {
        // All port scanners get port data
        toolPorts = realPorts.length ? realPorts : null;
      } else if (phase === 3) {
        // ── Screenshot tools: gowitness / eyewitness / snapback ───────────────
        if (["gowitness", "eyewitness", "snapback"].includes(name)) {
          toolHttp  = httpInfo;
          toolTech  = detectedTechs.length ? detectedTechs : null;
          // screenshots stored separately in screenshotsTable; no per-tool rawOutput needed
        }
        // ── Wappalyzer: technology fingerprinting ─────────────────────────────
        else if (name === "wappalyzer") {
          toolTech  = detectedTechs.length ? detectedTechs : null;
          toolHttp  = httpInfo;
        }
        // ── Webcheck: security headers & policy audit ─────────────────────────
        else if (name === "webcheck") {
          toolHttp  = httpInfo;
          toolVulns = headerVulnFindings.length ? headerVulnFindings : null;
        }
        // ── HTTP probing / web fingerprinting ──────────────────────────────────
        else if (["httpx", "whatweb", "wafw00f", "useragent"].includes(name)) {
          toolHttp  = httpInfo;
          if (name === "httpx") toolVulns = headerVulnFindings.length ? headerVulnFindings : null;
        }
        // ── Web crawlers / directory fuzzers (endpoints only) ─────────────────
        else if (["katana", "feroxbuster", "gobuster", "ffuf"].includes(name)) {
          toolEndpts = endpoints.length ? endpoints : null;
        }
        // ── Default phase-3: HTTP + endpoints ─────────────────────────────────
        else {
          toolHttp   = httpInfo;
          toolEndpts = endpoints.length ? endpoints : null;
        }
      } else if (phase === 4) {
        // ── Secrets / credential scanning ─────────────────────────────────────
        if (name === "trufflehog" || name === "goleak") {
          toolSecrets = secretFindings.length ? secretFindings : null;
          toolVulns   = secretFindings.length ? secretFindings : null;
        }
        // ── WordPress-specific scanner ─────────────────────────────────────────
        else if (name === "wpscan") {
          toolVulns = cveFindings.length ? cveFindings : null;
        }
        // ── General vuln scanners (nuclei, nikto, wapiti, vulnx) ──────────────
        else {
          toolVulns  = cveFindings.length ? cveFindings : null;
          toolHttp   = httpInfo;
          toolEndpts = endpoints.length ? endpoints : null;
        }
      } else if (phase === 5) {
        // ── SSL/TLS analysis ──────────────────────────────────────────────────
        toolIntel = sslIntel.length ? sslIntel : null;
        toolVulns = sslVulns.length ? sslVulns : null;
        toolHttp  = httpInfo;
      }

      results.push({
        tenantId, scanId, assetId: asset.id,
        toolName: name, toolCategory: cat,
        rawOutput: buildRawOutput(name, target, PHASE_NAMES[phase] ?? "Recon", {
          ports: toolPorts, nmapRaw: phase === 2 ? nmapRaw : undefined,
          subdomains: toolSubs, dnsRecords: toolDns,
          httpInfo: toolHttp, endpoints: toolEndpts,
          vulnerabilities: toolVulns, intelligence: toolIntel,
          secretsFound: toolSecrets, technologies: toolTech,
        }),
        ports:           toolPorts   as any,
        subdomains:      toolSubs    as any,
        endpoints:       toolEndpts  as any,
        httpInfo:        toolHttp    as any,
        dnsRecords:      toolDns     as any,
        intelligence:    toolIntel   as any,
        vulnerabilities: toolVulns   as any,
      });
    }

    // Batch-insert results
    for (let i = 0; i < results.length; i += 50) {
      await db.insert(scanAssetResultsTable).values(results.slice(i, i + 50));
    }

    // Deduplicate and insert findings
    const uniqueFindings = new Map<string, typeof findingInserts[0]>();
    for (const f of findingInserts) {
      const key = `${f.cve ?? ""}-${f.assetId}`;
      if (!uniqueFindings.has(key)) uniqueFindings.set(key, f);
    }
    const deduped = Array.from(uniqueFindings.values());
    for (let i = 0; i < deduped.length; i += 50) {
      await db.insert(findingsTable).values(deduped.slice(i, i + 50));
    }
    totalFindings += deduped.length;

    // Mark all tools done in case any got stuck
    for (const t of toolProgress) {
      if (t.status === "running" || t.status === "queued") {
        Object.assign(t, { status: "done", completedAt: now(), detail: "Complete" });
      }
    }
  }

  return { findingsCount: totalFindings };
}

// ── Schedule helpers ──────────────────────────────────────────────────────────

function computeNextRunAt(frequency: string, runTime: string, dayOfWeek?: number | null, dayOfMonth?: number | null): Date {
  const now = new Date();
  const [hours, minutes] = runTime.split(":").map(Number);
  const next = new Date(now);
  next.setHours(hours ?? 9, minutes ?? 0, 0, 0);
  if (frequency === "daily") {
    if (next <= now) next.setDate(next.getDate() + 1);
  } else if (frequency === "weekly") {
    const target = dayOfWeek ?? 1;
    let days = (target - next.getDay() + 7) % 7;
    if (days === 0 && next <= now) days = 7;
    next.setDate(next.getDate() + days);
  } else if (frequency === "monthly") {
    const target = dayOfMonth ?? 1;
    next.setDate(target);
    if (next <= now) { next.setMonth(next.getMonth() + 1); next.setDate(target); }
  } else {
    if (next <= now) next.setDate(next.getDate() + 1);
  }
  return next;
}

function toScheduleResponse(s: typeof scanSchedulesTable.$inferSelect) {
  return {
    id: s.id, name: s.name, assetToolConfig: s.assetToolConfig,
    frequency: s.frequency, runTime: s.runTime,
    dayOfWeek: s.dayOfWeek, dayOfMonth: s.dayOfMonth, status: s.status,
    lastRunAt: s.lastRunAt?.toISOString() ?? null, nextRunAt: s.nextRunAt?.toISOString() ?? null,
    lastScanId: s.lastScanId, createdAt: s.createdAt.toISOString(),
  };
}

// ── IMPORTANT: static sub-paths BEFORE param routes ───────────────────────────

// ── GET /scans/:scanId/progress — live tool progress ──────────────────────────
router.get("/scans/:scanId/progress", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scanId = Number(req.params.scanId);
  if (isNaN(scanId)) { res.status(400).json({ error: "Invalid scan ID" }); return; }
  const scan = await db.select({ tenantId: scansTable.tenantId }).from(scansTable)
    .where(eq(scansTable.id, scanId)).then(r => r[0]);
  if (!scan || scan.tenantId !== req.user!.tenantId) { res.status(404).json({ error: "Scan not found" }); return; }
  res.json(scanProgressMap.get(scanId) ?? []);
});

// ── POST /scans/pipeline-run ───────────────────────────────────────────────────
router.post("/scans/pipeline-run", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = RunPipelineScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const body = parsed.data as any;
  const assetToolConfigs = body.assetToolConfig ?? body.assetToolConfigs;
  const { assetIds, name } = body;
  const tenantId = req.user!.tenantId;
  const userId   = req.user!.userId;

  let configs: AssetToolConfigItem[] = [];
  if (Array.isArray(assetToolConfigs) && assetToolConfigs.length > 0) {
    configs = assetToolConfigs as AssetToolConfigItem[];
  } else if (Array.isArray(assetIds) && assetIds.length > 0) {
    configs = (assetIds as number[]).map(id => ({ assetId: id, toolIds: [] }));
  }
  if (configs.length === 0) { res.status(400).json({ error: "At least one asset is required" }); return; }

  const allTools = await db.select().from(securityToolsTable).where(eq(securityToolsTable.tenantId, tenantId));
  const pipelineSteps = await db.select({ tool: securityToolsTable })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
    .where(and(eq(toolPipelineStepsTable.tenantId, tenantId), eq(toolPipelineStepsTable.isEnabled, true)))
    .orderBy(toolPipelineStepsTable.stepOrder);
  const enabledTools = pipelineSteps.map(p => p.tool);

  if (enabledTools.length === 0 && configs.every(c => c.toolIds.length === 0)) {
    res.status(400).json({ error: "No pipeline tools enabled. Configure pipeline steps first." }); return;
  }

  const [scan] = await db.insert(scansTable).values({
    tenantId, name: name ?? `Pipeline Scan — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: "running", assetIds: configs.map(c => c.assetId), startedAt: new Date(), findingsCount: 0,
  }).returning();

  res.status(201).json({ scanId: scan.id, status: "running", assetCount: configs.length, findingsCount: 0 });

  setImmediate(async () => {
    try {
      const { findingsCount } = await executePipeline(tenantId, scan.id, configs, allTools, enabledTools);
      const current = await db.select({ status: scansTable.status }).from(scansTable)
        .where(eq(scansTable.id, scan.id)).then(r => r[0]);
      if (current?.status !== "cancelled") {
        await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
          .where(eq(scansTable.id, scan.id));
      }
      await logAudit(tenantId, userId as any, "scan.pipeline_run", "scan", scan.id, { assetCount: configs.length, findingsCount });
    } catch {
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
        .where(eq(scansTable.id, scan.id)).catch(() => {});
    }
  });
});

// ── POST /scans/:scanId/stop ──────────────────────────────────────────────────
router.post("/scans/:scanId/stop", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = StopScanParams.safeParse({ scanId: Number(req.params.scanId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }
  const { scanId } = parsed.data;
  const tenantId = req.user!.tenantId;
  const scan = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, tenantId))).then(r => r[0]);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }
  if (scan.status === "completed" || scan.status === "cancelled") {
    res.status(400).json({ error: `Scan is already ${scan.status}` }); return;
  }
  const killer = activeScanKillers.get(scanId);
  if (killer) { killer(); activeScanKillers.delete(scanId); }
  const [updated] = await db.update(scansTable).set({ status: "cancelled", completedAt: new Date() })
    .where(eq(scansTable.id, scanId)).returning();
  res.json({
    id: updated.id, tenantId: updated.tenantId, name: updated.name, type: updated.type,
    status: updated.status, schedule: updated.schedule, assetIds: updated.assetIds ?? [],
    findingsCount: updated.findingsCount,
    startedAt: updated.startedAt?.toISOString() ?? null, completedAt: updated.completedAt?.toISOString() ?? null,
    createdAt: updated.createdAt.toISOString(),
  });
});

// ── GET /scans/:scanId/asset-report ──────────────────────────────────────────
router.get("/scans/:scanId/asset-report", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = GetScanAssetReportParams.safeParse({ scanId: Number(req.params.scanId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }
  const { scanId } = parsed.data;
  const tenantId = req.user!.tenantId;

  const scan = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, tenantId))).then(r => r[0]);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  // Fetch all enabled tools for this tenant so we know which tools were configured
  const enabledToolRecords = await db
    .select({ name: securityToolsTable.name, category: securityToolsTable.category })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(toolPipelineStepsTable.toolId, securityToolsTable.id))
    .where(and(eq(toolPipelineStepsTable.tenantId, tenantId), eq(toolPipelineStepsTable.isEnabled, true)));
  const configuredTools = enabledToolRecords.map(t => ({
    name: t.name,
    phase: TOOL_PHASE[t.name] ?? 1,
    phaseName: PHASE_NAMES[TOOL_PHASE[t.name] ?? 1] ?? "Recon",
    category: t.category ?? "recon",
  })).sort((a, b) => a.phase - b.phase);

  const scanResults = await db.select().from(scanAssetResultsTable)
    .where(and(eq(scanAssetResultsTable.scanId, scanId), eq(scanAssetResultsTable.tenantId, tenantId)));
  if (scanResults.length === 0) { res.json([]); return; }

  const aIds = [...new Set(scanResults.map(r => r.assetId))];
  const assets = await db.select().from(assetsTable).where(inArray(assetsTable.id, aIds));
  const assetMap = new Map(assets.map(a => [a.id, a]));

  const assetReports = aIds.map(assetId => {
    const asset = assetMap.get(assetId);
    const assetResults = scanResults.filter(r => r.assetId === assetId);

    const allPorts: unknown[] = [], allSubdomains: unknown[] = [], allEndpoints: unknown[] = [];
    const allVulns: unknown[] = [], allDns: unknown[] = [], allIntel: unknown[] = [];
    let httpInfo: unknown = null;

    const toolResults = assetResults.map(r => {
      const tr: Record<string, unknown> = {
        toolName: r.toolName, toolCategory: r.toolCategory, rawOutput: r.rawOutput,
        phase: TOOL_PHASE[r.toolName] ?? 1, phaseName: PHASE_NAMES[TOOL_PHASE[r.toolName] ?? 1] ?? "Recon",
      };
      if (r.ports)           { tr.ports           = r.ports;           allPorts.push(...(r.ports as unknown[])); }
      if (r.subdomains)      { tr.subdomains       = r.subdomains;      allSubdomains.push(...(r.subdomains as unknown[])); }
      if (r.endpoints)       { tr.endpoints        = r.endpoints;       allEndpoints.push(...(r.endpoints as unknown[])); }
      if (r.httpInfo)        { tr.httpInfo         = r.httpInfo;        httpInfo = r.httpInfo; }
      if (r.dnsRecords)      { tr.dnsRecords       = r.dnsRecords;      allDns.push(...(r.dnsRecords as unknown[])); }
      if (r.intelligence)    { tr.intelligence     = r.intelligence;    allIntel.push(...(r.intelligence as unknown[])); }
      if (r.vulnerabilities) { tr.vulnerabilities  = r.vulnerabilities; allVulns.push(...(r.vulnerabilities as unknown[])); }
      return tr;
    });

    const dedup = <T extends Record<string, unknown>>(arr: T[], key: string) => {
      const seen = new Set<string>();
      return arr.filter(i => { const k = String(i[key] ?? JSON.stringify(i)); return seen.has(k) ? false : (seen.add(k), true); });
    };

    const ports  = dedup(allPorts as any[], "port");
    const vulns  = dedup(allVulns as any[], "cve");
    const subs   = dedup(allSubdomains as any[], "name");
    const dns    = dedup(allDns as any[], "value");
    const eps    = dedup(allEndpoints as any[], "url");
    const intel  = dedup(allIntel as any[], "key");
    const secrets = vulns.filter((v: any) => v.cve?.startsWith("SEC-") || v.cve?.startsWith("CRED-"));
    const cves    = vulns.filter((v: any) => !v.cve?.startsWith("SEC-") && !v.cve?.startsWith("HDR-") && !v.cve?.startsWith("CWE-") && !v.cve?.startsWith("CRED-"));
    const headerIssues = vulns.filter((v: any) => v.cve?.startsWith("HDR-") || v.cve?.startsWith("CWE-"));

    const critCount = cves.filter((v: any) => v.severity === "critical").length;
    const highCount  = cves.filter((v: any) => v.severity === "high").length;

    return {
      assetId, assetName: asset?.name ?? String(assetId), assetValue: asset?.value ?? "", assetType: asset?.type ?? "unknown",
      scanStatus: scan.status,
      summary: {
        openPorts: ports.length, vulnerabilities: vulns.length, criticalVulns: critCount, highVulns: highCount,
        subdomains: subs.length, endpoints: eps.length, dnsRecords: dns.length, intelItems: intel.length,
        secretsFound: secrets.length, headerIssues: headerIssues.length, cves: cves.length,
        toolsRun: assetResults.length, waf: httpInfo ? (httpInfo as HttpInfo).waf : null, cdn: (httpInfo as any)?.cdn ?? null,
      },
      ports, subdomains: subs, endpoints: eps, httpInfo, dnsRecords: dns,
      intelligence: intel, vulnerabilities: vulns, secrets, cves, headerIssues,
      toolResults: toolResults.sort((a, b) => ((a.phase as number) - (b.phase as number))),
      configuredTools,
    };
  });

  res.json(assetReports);
});

// ── Schedule CRUD ─────────────────────────────────────────────────────────────

router.get("/scans/schedules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const schedules = await db.select().from(scanSchedulesTable).where(eq(scanSchedulesTable.tenantId, tenantId));
  res.json(schedules.map(toScheduleResponse));
});

router.post("/scans/schedules", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateScanScheduleBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }
  const tenantId = req.user!.tenantId;
  const userId   = req.user!.userId;
  const { name, assetToolConfig, frequency, runTime, dayOfWeek, dayOfMonth } = parsed.data as any;
  const nextRunAt = computeNextRunAt(frequency ?? "once", runTime ?? "09:00", dayOfWeek, dayOfMonth);
  const [schedule] = await db.insert(scanSchedulesTable).values({
    tenantId, name, assetToolConfig, frequency: frequency ?? "once",
    runTime: runTime ?? "09:00", dayOfWeek, dayOfMonth, status: "active", nextRunAt, createdBy: userId as any,
  }).returning();
  await logAudit(tenantId, userId as any, "schedule.create", "scan_schedule", schedule.id, { name });
  res.status(201).json(toScheduleResponse(schedule));
});

router.get("/scans/schedules/:scheduleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scheduleId = Number(req.params.scheduleId);
  const tenantId   = req.user!.tenantId;
  const schedule   = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }
  res.json(toScheduleResponse(schedule));
});

router.patch("/scans/schedules/:scheduleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const paramsP = UpdateScanScheduleParams.safeParse({ scheduleId: Number(req.params.scheduleId) });
  if (!paramsP.success) { res.status(400).json({ error: "Invalid schedule ID" }); return; }
  const bodyP = UpdateScanScheduleBody.safeParse(req.body);
  if (!bodyP.success) { res.status(400).json({ error: bodyP.error.message }); return; }
  const tenantId = req.user!.tenantId;
  const { scheduleId } = paramsP.data;
  const existing = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!existing) { res.status(404).json({ error: "Schedule not found" }); return; }
  const updates: Record<string, unknown> = { ...bodyP.data };
  updates.nextRunAt = computeNextRunAt(
    (updates.frequency as string) ?? existing.frequency,
    (updates.runTime as string) ?? existing.runTime,
    (updates.dayOfWeek as number | undefined) ?? existing.dayOfWeek,
    (updates.dayOfMonth as number | undefined) ?? existing.dayOfMonth,
  );
  const [updated] = await db.update(scanSchedulesTable).set(updates as any)
    .where(eq(scanSchedulesTable.id, scheduleId)).returning();
  res.json(toScheduleResponse(updated));
});

router.delete("/scans/schedules/:scheduleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scheduleId = Number(req.params.scheduleId);
  const tenantId   = req.user!.tenantId;
  const schedule   = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }
  await db.delete(scanSchedulesTable).where(eq(scanSchedulesTable.id, scheduleId));
  res.status(204).send();
});

router.post("/scans/schedules/:scheduleId/run-now", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = RunScheduleNowParams.safeParse({ scheduleId: Number(req.params.scheduleId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid schedule ID" }); return; }
  const tenantId = req.user!.tenantId;
  const userId   = req.user!.userId;
  const { scheduleId } = parsed.data;
  const schedule = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }
  const configs        = schedule.assetToolConfig as AssetToolConfigItem[];
  const allTools = await db.select().from(securityToolsTable).where(eq(securityToolsTable.tenantId, tenantId));
  const pipelineSteps = await db.select({ tool: securityToolsTable })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
    .where(and(eq(toolPipelineStepsTable.tenantId, tenantId), eq(toolPipelineStepsTable.isEnabled, true)));
  const enabledTools = pipelineSteps.map(p => p.tool);
  const [scan] = await db.insert(scansTable).values({
    tenantId, name: `${schedule.name} — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: "running", assetIds: configs.map(c => c.assetId), startedAt: new Date(), findingsCount: 0,
  }).returning();
  res.status(201).json({ scanId: scan.id, status: "running", assetCount: configs.length, findingsCount: 0 });
  setImmediate(async () => {
    try {
      const { findingsCount } = await executePipeline(tenantId, scan.id, configs, allTools, enabledTools);
      const current = await db.select({ status: scansTable.status }).from(scansTable)
        .where(eq(scansTable.id, scan.id)).then(r => r[0]);
      if (current?.status !== "cancelled") {
        await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
          .where(eq(scansTable.id, scan.id));
      }
      await db.update(scanSchedulesTable).set({ lastRunAt: new Date(), lastScanId: scan.id })
        .where(eq(scanSchedulesTable.id, scheduleId));
    } catch {
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
        .where(eq(scansTable.id, scan.id)).catch(() => {});
    }
  });
});

export default router;
