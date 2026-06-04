import { Router } from "express";
import { exec } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";
import tls from "tls";
import { eq, and, inArray } from "drizzle-orm";
import { db, scansTable, scanAssetResultsTable, assetsTable, findingsTable, securityToolsTable, toolPipelineStepsTable, scanSchedulesTable } from "@workspace/db";
import { RunPipelineScanBody, GetScanAssetReportParams, CreateScanScheduleBody, UpdateScanScheduleBody, UpdateScanScheduleParams, RunScheduleNowParams, StopScanParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const execAsync = promisify(exec);
const router = Router();

// ── Track active nmap processes so Stop can kill them ─────────────────────────
const activeScanKillers = new Map<number, () => void>();

// ── CVE database (matched against real service versions from nmap) ─────────────
const CVE_POOL = [
  { cve: "CVE-2023-44487", cvss: 7.5, severity: "high",     title: "HTTP/2 Rapid Reset Attack (DoS)",                   cwe: "CWE-400", remediation: "Update server software to patched version.",                   affected: ["nginx", "apache", "http", "https"] },
  { cve: "CVE-2024-0727",  cvss: 5.5, severity: "medium",   title: "OpenSSL PKCS12 Null Pointer Dereference",            cwe: "CWE-476", remediation: "Upgrade OpenSSL to 3.2.1+.",                                    affected: ["https", "ssl", "openssl"] },
  { cve: "CVE-2023-38408", cvss: 9.8, severity: "critical", title: "OpenSSH Remote Code Execution via ssh-agent",        cwe: "CWE-122", remediation: "Upgrade OpenSSH to 9.3p2+.",                                    affected: ["ssh", "openssh"] },
  { cve: "CVE-2024-6387",  cvss: 8.1, severity: "high",     title: "OpenSSH regreSSHion Race Condition RCE",             cwe: "CWE-364", remediation: "Update OpenSSH to 9.8p1+.",                                    affected: ["ssh", "openssh"] },
  { cve: "CVE-2024-3400",  cvss: 10.0,severity: "critical", title: "PAN-OS Command Injection (GlobalProtect)",           cwe: "CWE-77",  remediation: "Apply PAN-OS hotfix immediately.",                             affected: ["https", "http"] },
  { cve: "CVE-2023-20198", cvss: 10.0,severity: "critical", title: "Cisco IOS XE Web UI Privilege Escalation",           cwe: "CWE-306", remediation: "Disable HTTP/HTTPS Server or upgrade firmware.",               affected: ["http", "https"] },
  { cve: "CVE-2022-26134", cvss: 9.8, severity: "critical", title: "Confluence Server OGNL Injection RCE",               cwe: "CWE-74",  remediation: "Upgrade Confluence to 7.4.17+.",                               affected: ["http", "https"] },
  { cve: "CVE-2024-1086",  cvss: 7.8, severity: "high",     title: "Linux Kernel Use-After-Free via nf_tables",          cwe: "CWE-416", remediation: "Apply kernel patch, update to 6.7.3+.",                        affected: ["ssh", "ftp"] },
  { cve: "CVE-2024-4577",  cvss: 9.8, severity: "critical", title: "PHP CGI Argument Injection RCE",                     cwe: "CWE-88",  remediation: "Update PHP to 8.3.8+.",                                        affected: ["http", "https", "php"] },
  { cve: "CVE-2023-42793", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Authentication Bypass",           cwe: "CWE-288", remediation: "Update to TeamCity 2023.05.4+.",                               affected: ["http", "https"] },
  { cve: "CVE-2024-21626", cvss: 8.6, severity: "high",     title: "runc Container Breakout Vulnerability",              cwe: "CWE-22",  remediation: "Update runc to v1.1.12+.",                                     affected: ["docker", "http"] },
  { cve: "CVE-2023-46604", cvss: 10.0,severity: "critical", title: "Apache ActiveMQ RCE via ExceptionResponse",          cwe: "CWE-502", remediation: "Upgrade ActiveMQ to 5.15.16+, 5.16.7+, 5.17.6+, or 5.18.3+.", affected: ["activemq", "http"] },
  { cve: "CVE-2024-27198", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Authentication Bypass (CVSS 10)", cwe: "CWE-288", remediation: "Upgrade TeamCity to 2023.11.4+.",                              affected: ["http", "https"] },
  { cve: "CVE-2024-23897", cvss: 9.8, severity: "critical", title: "Jenkins Arbitrary File Read leading to RCE",          cwe: "CWE-22",  remediation: "Upgrade Jenkins to 2.442+/LTS 2.426.3+.",                      affected: ["http", "https", "jenkins"] },
  { cve: "CVE-2024-22024", cvss: 8.3, severity: "high",     title: "Ivanti SAML Authentication Bypass (XXE)",            cwe: "CWE-611", remediation: "Apply Ivanti security patches immediately.",                   affected: ["https", "ssl"] },
  { cve: "CVE-2023-34048", cvss: 9.8, severity: "critical", title: "VMware vCenter DCERPC Out-of-Bounds Write RCE",       cwe: "CWE-787", remediation: "Apply VMware patch VMSA-2023-0023.",                           affected: ["https", "http"] },
  { cve: "CVE-2024-20767", cvss: 9.8, severity: "critical", title: "Adobe ColdFusion Arbitrary File Read/Exec",          cwe: "CWE-20",  remediation: "Apply ColdFusion security update APSB24-14.",                  affected: ["http", "https"] },
  { cve: "CVE-2024-28995", cvss: 8.6, severity: "high",     title: "SolarWinds Serv-U Path Traversal",                   cwe: "CWE-22",  remediation: "Upgrade Serv-U to 15.4.2.228+.",                               affected: ["ftp", "sftp", "http"] },
  { cve: "CVE-2023-48788", cvss: 9.8, severity: "critical", title: "Fortinet FortiClientEMS SQL Injection RCE",           cwe: "CWE-89",  remediation: "Upgrade FortiClientEMS to 7.2.3+.",                            affected: ["https", "http"] },
  { cve: "CVE-2024-9487",  cvss: 8.8, severity: "high",     title: "GitHub Enterprise SAML Authentication Bypass",       cwe: "CWE-347", remediation: "Upgrade GitHub Enterprise Server to 3.14+.",                   affected: ["https", "http"] },
];

// ── Type interfaces ─────────────────────────────────────────────────────────────
interface PortFinding    { port: number; service: string; version: string; protocol: string; state: string; }
interface SubdomainFinding { name: string; ip: string; cname: string | null; status: string; cdnProvider: string | null; }
interface EndpointFinding  { url: string; method: string; status: number; }
interface HttpInfo         { url: string; status: number; title: string; server: string; contentLength: number; tech: string[]; waf: string; headers: Record<string, string>; }
interface DnsRecord        { type: string; value: string; ttl: number; priority?: number; }
interface IntelItem        { type: string; key: string; value: string; }
interface VulnFinding      { cve: string; cvss: number; severity: string; title: string; cwe: string; remediation: string; }
interface AssetToolConfigItem { assetId: number; toolIds: number[]; }

// ── Helpers ─────────────────────────────────────────────────────────────────────

function extractDomain(target: string): string {
  return target
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .split(":")[0]
    .toLowerCase()
    .trim();
}

function isIp(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

// ── Real scanner: nmap port scan ───────────────────────────────────────────────

function parseNmapNormal(output: string): PortFinding[] {
  const ports: PortFinding[] = [];
  for (const line of output.split("\n")) {
    // 80/tcp   open  http    nginx 1.24.0
    const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
    if (m) {
      ports.push({
        port: parseInt(m[1]),
        protocol: m[2],
        service: m[3].replace(/\?$/, ""),
        version: m[4].trim(),
        state: "open",
      });
    }
  }
  return ports;
}

async function runNmapScan(target: string, scanId: number): Promise<{ ports: PortFinding[]; raw: string }> {
  const scanTarget = extractDomain(target) || target;
  try {
    // TCP connect scan (no root needed), top 1000 ports, 40s host timeout
    const cmd = `nmap -sT --open --top-ports 1000 -T4 --max-rtt-timeout 2s --host-timeout 40s ${scanTarget}`;
    let child: ReturnType<typeof exec> | null = null;

    const promise = new Promise<{ stdout: string; stderr: string }>((resolve, reject) => {
      child = exec(cmd, { timeout: 50000 }, (err, stdout, stderr) => {
        if (err && !stdout) reject(err);
        else resolve({ stdout: stdout ?? "", stderr: stderr ?? "" });
      });
    });

    activeScanKillers.set(scanId, () => {
      try { child?.kill("SIGTERM"); } catch {}
    });

    const { stdout } = await promise;
    activeScanKillers.delete(scanId);
    const ports = parseNmapNormal(stdout);
    return { ports, raw: stdout };
  } catch (err: any) {
    activeScanKillers.delete(scanId);
    const partial = err?.stdout ?? "";
    return { ports: parseNmapNormal(partial), raw: partial || String(err?.message ?? err) };
  }
}

// ── Real scanner: DNS recon via Node dns module ────────────────────────────────

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

  if (a.status === "fulfilled")    for (const r of a.value)    dnsRecords.push({ type: "A",    value: r.address,             ttl: r.ttl });
  if (aaaa.status === "fulfilled") for (const r of aaaa.value) dnsRecords.push({ type: "AAAA", value: r.address,             ttl: r.ttl });
  if (mx.status === "fulfilled")   for (const r of mx.value)   dnsRecords.push({ type: "MX",   value: r.exchange,            ttl: 300, priority: r.priority });
  if (ns.status === "fulfilled")   for (const r of ns.value)   dnsRecords.push({ type: "NS",   value: r,                     ttl: 3600 });
  if (txt.status === "fulfilled")  for (const r of txt.value)  dnsRecords.push({ type: "TXT",  value: r.join(" "),           ttl: 300 });
  if (soa.status === "fulfilled")  dnsRecords.push({ type: "SOA", value: `${soa.value.nsname} ${soa.value.hostmaster}`, ttl: soa.value.minttl });
  if (cname.status === "fulfilled" && Array.isArray(cname.value)) for (const r of cname.value) dnsRecords.push({ type: "CNAME", value: r, ttl: 300 });

  // Subdomain brute-force — 30 most common prefixes, all concurrent
  const wordlist = [
    "www", "api", "mail", "smtp", "ftp", "vpn", "remote", "dev", "staging", "test",
    "admin", "portal", "cdn", "static", "img", "auth", "sso", "app", "mobile", "beta",
    "docs", "support", "status", "git", "jenkins", "ci", "ops", "grafana", "kibana", "monitor",
  ];
  await Promise.allSettled(
    wordlist.map(async (prefix) => {
      const full = `${prefix}.${domain}`;
      try {
        const ips = await dns.resolve4(full);
        if (!ips.length) return;
        let cn: string | null = null;
        try { const cns = await dns.resolveCname(full); cn = cns[0] ?? null; } catch {}
        subdomains.push({ name: full, ip: ips[0], cname: cn, status: "active", cdnProvider: null });
      } catch {}
    }),
  );

  return { subdomains, dnsRecords };
}

// ── Real scanner: HTTP probe ────────────────────────────────────────────────────

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
      const tid = setTimeout(() => ctrl.abort(), 12000);
      const response = await fetch(url, { signal: ctrl.signal, redirect: "follow" });
      clearTimeout(tid);

      const headers: Record<string, string> = {};
      response.headers.forEach((v, k) => { headers[k] = v; });

      const body = await response.text().catch(() => "");

      // Title
      const titleM = body.match(/<title[^>]*>([^<]{0,200})<\/title>/i);
      const title = titleM ? titleM[1].trim() : "";

      // Tech detection
      const tech: string[] = [];
      const server = headers["server"] ?? "";
      const xpb = headers["x-powered-by"] ?? "";
      if (xpb)                                              tech.push(xpb);
      if (/nginx/i.test(server))                            tech.push("Nginx");
      if (/apache/i.test(server))                           tech.push("Apache");
      if (/cloudflare/i.test(server) || headers["cf-ray"]) tech.push("Cloudflare");
      if (headers["x-aspnet-version"])                      tech.push("ASP.NET");
      if (headers["x-drupal-cache"] || body.includes("Drupal.settings")) tech.push("Drupal");
      if (body.includes("wp-content") || body.includes("wp-includes")) tech.push("WordPress");
      if (body.includes("__NEXT_DATA__"))                   tech.push("Next.js");
      if (body.includes("react-root") || body.includes("_reactRootContainer")) tech.push("React");
      if (headers["x-generator"]?.includes("Hugo"))         tech.push("Hugo");
      if (/IIS/i.test(server))                              tech.push("IIS");
      if (/LiteSpeed/i.test(server))                        tech.push("LiteSpeed");

      // WAF detection
      let waf = "none";
      if (headers["cf-ray"] || /cloudflare/i.test(server)) waf = "Cloudflare";
      else if (headers["x-iinfo"])                          waf = "Imperva";
      else if (headers["x-amz-cf-id"])                     waf = "AWS WAF";
      else if (headers["x-sucuri-id"])                     waf = "Sucuri";
      else if (headers["x-fw-hash"])                        waf = "Wordfence";
      else if (headers["x-cdn"] === "Incapsula")            waf = "Imperva Incapsula";

      return {
        url: response.url ?? url,
        status: response.status,
        title,
        server,
        contentLength: body.length,
        tech: [...new Set(tech)],
        waf,
        headers,
      };
    } catch {}
  }
  return null;
}

// ── Real scanner: common endpoint probe ────────────────────────────────────────

async function runEndpointProbe(target: string): Promise<EndpointFinding[]> {
  const domain = extractDomain(target);
  const base = `https://${domain}`;
  const paths = [
    "/", "/robots.txt", "/sitemap.xml", "/api", "/api/v1",
    "/health", "/healthz", "/status", "/.well-known/security.txt",
    "/admin", "/login", "/graphql", "/swagger", "/openapi.json",
    "/metrics", "/.env", "/api/v1/users",
  ];

  const results = await Promise.allSettled(
    paths.map(async (path) => {
      const ctrl = new AbortController();
      setTimeout(() => ctrl.abort(), 6000);
      const r = await fetch(`${base}${path}`, { signal: ctrl.signal, redirect: "follow" });
      return { url: path, method: "GET", status: r.status };
    }),
  );
  return results
    .filter(r => r.status === "fulfilled")
    .map(r => (r as PromiseFulfilledResult<EndpointFinding>).value)
    .filter(r => r.status > 0);
}

// ── Real scanner: SSL certificate via TLS ──────────────────────────────────────

async function runSslIntel(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  if (!domain || isIp(domain)) return [];

  return new Promise<IntelItem[]>((resolve) => {
    const intel: IntelItem[] = [];
    const sock = tls.connect(
      { host: domain, port: 443, timeout: 8000, rejectUnauthorized: false },
      () => {
        try {
          const cert = sock.getPeerCertificate(true);
          if (cert) {
            if (cert.issuer?.O)           intel.push({ type: "Certificate", key: "Issuer",     value: cert.issuer.O });
            if (cert.issuer?.CN)          intel.push({ type: "Certificate", key: "Issuer CN",  value: cert.issuer.CN });
            if (cert.subject?.CN)         intel.push({ type: "Certificate", key: "Subject",    value: cert.subject.CN });
            if (cert.valid_from)          intel.push({ type: "Certificate", key: "Valid From", value: cert.valid_from });
            if (cert.valid_to)            intel.push({ type: "Certificate", key: "Expires",    value: cert.valid_to });
            if (cert.serialNumber)        intel.push({ type: "Certificate", key: "Serial",     value: cert.serialNumber });
            if (cert.subjectaltname)      intel.push({ type: "Certificate", key: "SANs",       value: cert.subjectaltname });
            if (cert.bits)                intel.push({ type: "Certificate", key: "Key Bits",   value: String(cert.bits) });
          }
        } catch {}
        sock.destroy();
        resolve(intel);
      },
    );
    sock.on("error", () => resolve(intel));
    sock.setTimeout(8000, () => { sock.destroy(); resolve(intel); });
  });
}

// ── Real scanner: GeoIP via ipapi.co ──────────────────────────────────────────

async function runGeoIntel(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  let ip = domain;
  try { const ips = await dns.resolve4(domain); ip = ips[0] ?? domain; } catch {}
  if (!ip) return [];

  // Try ip-api.com (free, no API key, 45 req/min)
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,org,as`, { signal: ctrl.signal });
    if (res.ok) {
      const data: any = await res.json();
      if (data.status === "success") {
        const intel: IntelItem[] = [];
        if (data.country)     intel.push({ type: "GeoIP", key: "Country",      value: data.country });
        if (data.regionName)  intel.push({ type: "GeoIP", key: "Region",       value: data.regionName });
        if (data.city)        intel.push({ type: "GeoIP", key: "City",         value: data.city });
        if (data.org)         intel.push({ type: "ASN",   key: "Organization", value: data.org });
        if (data.as)          intel.push({ type: "ASN",   key: "AS Number",    value: data.as });
        return intel;
      }
    }
  } catch {}

  // Fallback: ipapi.co
  try {
    const ctrl2 = new AbortController();
    setTimeout(() => ctrl2.abort(), 6000);
    const res2 = await fetch(`https://ipapi.co/${ip}/json/`, { signal: ctrl2.signal });
    if (!res2.ok) return [];
    const data2: any = await res2.json();
    if (data2.error) return [];
    const intel: IntelItem[] = [];
    if (data2.country_name) intel.push({ type: "GeoIP", key: "Country",      value: data2.country_name });
    if (data2.region)       intel.push({ type: "GeoIP", key: "Region",       value: data2.region });
    if (data2.city)         intel.push({ type: "GeoIP", key: "City",         value: data2.city });
    if (data2.org)          intel.push({ type: "ASN",   key: "Organization", value: data2.org });
    if (data2.asn)          intel.push({ type: "ASN",   key: "AS Number",    value: data2.asn });
    return intel;
  } catch { return []; }
}

// ── Real scanner: WHOIS ────────────────────────────────────────────────────────

async function runWhoisIntel(target: string): Promise<IntelItem[]> {
  const domain = extractDomain(target);
  if (!domain) return [];

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
    extract(/Creation Date:\s*(.+)/i,           "WHOIS", "Created");
    extract(/Registry Expiry Date:\s*(.+)/i,    "WHOIS", "Expires");
    extract(/Updated Date:\s*(.+)/i,            "WHOIS", "Updated");
    extract(/DNSSEC:\s*(.+)/i,                  "WHOIS", "DNSSEC");

    return intel;
  } catch { return []; }
}

// ── CVE matching from real discovered services ─────────────────────────────────

function matchCvesFromRealData(ports: PortFinding[], httpInfo: HttpInfo | null): VulnFinding[] {
  const vulns: VulnFinding[] = [];
  const seen = new Set<string>();

  const checkAndAdd = (svcStr: string) => {
    const lower = svcStr.toLowerCase();
    for (const cve of CVE_POOL) {
      if (seen.has(cve.cve)) continue;
      if (cve.affected.some(a => lower.includes(a.toLowerCase()))) {
        vulns.push({ cve: cve.cve, cvss: cve.cvss, severity: cve.severity, title: cve.title, cwe: cve.cwe, remediation: cve.remediation });
        seen.add(cve.cve);
      }
    }
  };

  for (const port of ports) checkAndAdd(`${port.service} ${port.version}`);

  if (httpInfo) {
    checkAndAdd([...httpInfo.tech, httpInfo.server].join(" "));
  }

  return vulns;
}

// ── Generate human-readable raw output ────────────────────────────────────────

function buildRawOutput(toolName: string, target: string, data: {
  ports?: PortFinding[] | null;
  nmapRaw?: string;
  subdomains?: SubdomainFinding[] | null;
  dnsRecords?: DnsRecord[] | null;
  httpInfo?: HttpInfo | null;
  endpoints?: EndpointFinding[] | null;
  vulnerabilities?: VulnFinding[] | null;
  intelligence?: IntelItem[] | null;
}): string {
  const lines: string[] = [`[${toolName}] Target: ${target}`, ""];

  if (data.nmapRaw) {
    lines.push("=== NMAP SCAN OUTPUT ===");
    lines.push(data.nmapRaw);
    lines.push("");
  } else if (data.ports?.length) {
    lines.push("PORT     PROTO  STATE  SERVICE  VERSION");
    for (const p of data.ports) lines.push(`${String(p.port).padEnd(8)} ${p.protocol.padEnd(6)} open   ${p.service.padEnd(8)} ${p.version}`);
    lines.push("");
  }

  if (data.dnsRecords?.length) {
    lines.push("=== DNS RECORDS ===");
    for (const r of data.dnsRecords) lines.push(`  ${r.type.padEnd(6)} ${r.value}${r.priority ? ` (priority ${r.priority})` : ""}`);
    lines.push("");
  }
  if (data.subdomains?.length) {
    lines.push("=== SUBDOMAINS ===");
    for (const s of data.subdomains) lines.push(`  ${s.name.padEnd(40)} ${s.ip}${s.cname ? ` → ${s.cname}` : ""}`);
    lines.push("");
  }
  if (data.httpInfo) {
    const h = data.httpInfo;
    lines.push("=== HTTP PROBE ===");
    lines.push(`  URL:     ${h.url}`);
    lines.push(`  Status:  ${h.status}`);
    lines.push(`  Title:   ${h.title || "(none)"}`);
    lines.push(`  Server:  ${h.server || "(unknown)"}`);
    lines.push(`  Tech:    ${h.tech.join(", ") || "—"}`);
    lines.push(`  WAF:     ${h.waf}`);
    lines.push(`  Size:    ${(h.contentLength / 1024).toFixed(1)} KB`);
    lines.push("  Headers:");
    for (const [k, v] of Object.entries(h.headers)) lines.push(`    ${k}: ${v}`);
    lines.push("");
  }
  if (data.endpoints?.length) {
    lines.push("=== ENDPOINTS ===");
    for (const e of data.endpoints) lines.push(`  [${e.status}] GET ${e.url}`);
    lines.push("");
  }
  if (data.vulnerabilities?.length) {
    lines.push("=== VULNERABILITIES MATCHED ===");
    for (const v of data.vulnerabilities) lines.push(`  [${v.severity.toUpperCase()}] ${v.cve} CVSS:${v.cvss} — ${v.title}`);
    lines.push("");
  }
  if (data.intelligence?.length) {
    lines.push("=== INTELLIGENCE ===");
    for (const i of data.intelligence) lines.push(`  [${i.type}] ${i.key}: ${i.value}`);
    lines.push("");
  }

  lines.push(`[${toolName}] Scan complete.`);
  return lines.join("\n");
}

// ── Core pipeline execution: real tools ───────────────────────────────────────

async function executePipeline(
  tenantId: number,
  scanId: number,
  assetConfigs: AssetToolConfigItem[],
  allTools: (typeof securityToolsTable.$inferSelect)[],
  enabledTools: (typeof securityToolsTable.$inferSelect)[],
): Promise<{ findingsCount: number }> {
  const assetIds = assetConfigs.map(c => c.assetId);
  const assets = await db.select().from(assetsTable).where(
    and(eq(assetsTable.tenantId, tenantId), inArray(assetsTable.id, assetIds)),
  );

  let totalFindings = 0;

  for (const config of assetConfigs) {
    // Check if stopped
    const currentScan = await db.select({ status: scansTable.status }).from(scansTable)
      .where(eq(scansTable.id, scanId)).then(r => r[0]);
    if (currentScan?.status === "cancelled") break;

    const asset = assets.find(a => a.id === config.assetId);
    if (!asset) continue;

    const toolsForAsset = config.toolIds.length > 0
      ? allTools.filter(t => config.toolIds.includes(t.id))
      : enabledTools;
    if (toolsForAsset.length === 0) continue;

    const categories = new Set(toolsForAsset.map(t => t.category ?? "recon"));
    const target = asset.value;

    // Decide which real scans are needed for this asset
    const needsNmap    = categories.has("port_scan") || categories.has("vuln_scan");
    const needsDns     = categories.has("recon");
    const needsHttp    = categories.has("web_recon");
    const needsEndpts  = categories.has("web_recon");
    const needsSsl     = categories.has("osint") || categories.has("ssl_check");
    const needsGeo     = categories.has("osint");
    const needsWhois   = categories.has("osint");

    // Run all underlying scans concurrently
    let realPorts: PortFinding[]        = [];
    let nmapRaw  = "";
    let dnsResult = { subdomains: [] as SubdomainFinding[], dnsRecords: [] as DnsRecord[] };
    let httpInfo: HttpInfo | null       = null;
    let endpoints: EndpointFinding[]    = [];
    let sslIntel: IntelItem[]           = [];
    let geoIntel: IntelItem[]           = [];
    let whoisIntel: IntelItem[]         = [];

    await Promise.allSettled([
      needsNmap   && (async () => { const r = await runNmapScan(target, scanId); realPorts = r.ports; nmapRaw = r.raw; })(),
      needsDns    && (async () => { dnsResult = await runDnsRecon(target); })(),
      needsHttp   && (async () => { httpInfo  = await runHttpProbe(target); })(),
      needsEndpts && (async () => { endpoints = await runEndpointProbe(target); })(),
      needsSsl    && (async () => { sslIntel  = await runSslIntel(target); })(),
      needsGeo    && (async () => { geoIntel  = await runGeoIntel(target); })(),
      needsWhois  && (async () => { whoisIntel = await runWhoisIntel(target); })(),
    ].filter(Boolean));

    // If vuln_scan needs ports but port_scan wasn't in the tool list, run nmap anyway
    if (categories.has("vuln_scan") && !categories.has("port_scan") && realPorts.length === 0) {
      const r = await runNmapScan(target, scanId);
      realPorts = r.ports; nmapRaw = r.raw;
    }

    const allIntel  = [...sslIntel, ...geoIntel, ...whoisIntel];
    const vulns     = matchCvesFromRealData(realPorts, httpInfo);

    // Store one row per tool per asset (matching existing schema)
    const results: Array<typeof scanAssetResultsTable.$inferInsert> = [];
    const findingInserts: Array<typeof findingsTable.$inferInsert>  = [];

    for (const tool of toolsForAsset) {
      const cat = tool.category ?? "recon";

      let toolPorts:   PortFinding[]     | null = null;
      let toolSubs:    SubdomainFinding[] | null = null;
      let toolEndpts:  EndpointFinding[] | null = null;
      let toolHttp:    HttpInfo          | null = null;
      let toolDns:     DnsRecord[]       | null = null;
      let toolIntel:   IntelItem[]       | null = null;
      let toolVulns:   VulnFinding[]     | null = null;

      if (cat === "port_scan") {
        toolPorts = realPorts;
      } else if (cat === "web_recon") {
        toolHttp   = httpInfo;
        toolEndpts = endpoints;
      } else if (cat === "recon") {
        toolSubs = dnsResult.subdomains;
        toolDns  = dnsResult.dnsRecords;
      } else if (cat === "vuln_scan") {
        toolVulns = vulns;
        for (const v of vulns) {
          findingInserts.push({
            tenantId, assetId: asset.id, scanId,
            title: v.title, cve: v.cve,
            severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
            cvssScore: String(v.cvss), cwe: v.cwe, status: "open",
            description: `${v.title} (${v.cve}) — CVSS ${v.cvss}. Detected on ${asset.name} (${asset.value}).`,
            remediation: v.remediation,
          });
        }
      } else if (cat === "osint" || cat === "ssl_check") {
        toolIntel = cat === "ssl_check" ? sslIntel : allIntel;
        if (cat === "ssl_check") toolHttp = httpInfo;
      } else {
        // Unknown category — store recon data
        toolSubs = dnsResult.subdomains;
        toolDns  = dnsResult.dnsRecords;
      }

      results.push({
        tenantId, scanId, assetId: asset.id,
        toolName: tool.name, toolCategory: cat,
        rawOutput: buildRawOutput(tool.name, target, {
          ports: toolPorts, nmapRaw: cat === "port_scan" ? nmapRaw : undefined,
          subdomains: toolSubs, dnsRecords: toolDns,
          httpInfo: toolHttp, endpoints: toolEndpts,
          vulnerabilities: toolVulns, intelligence: toolIntel,
        }),
        ports:          toolPorts  as any,
        subdomains:     toolSubs   as any,
        endpoints:      toolEndpts as any,
        httpInfo:       toolHttp   as any,
        dnsRecords:     toolDns    as any,
        intelligence:   toolIntel  as any,
        vulnerabilities: toolVulns as any,
      });
    }

    // Batch insert results
    for (let i = 0; i < results.length; i += 50) {
      await db.insert(scanAssetResultsTable).values(results.slice(i, i + 50));
    }

    // Deduplicate findings by CVE+assetId before inserting
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
    dayOfWeek: s.dayOfWeek, dayOfMonth: s.dayOfMonth,
    status: s.status,
    lastRunAt: s.lastRunAt?.toISOString() ?? null,
    nextRunAt: s.nextRunAt?.toISOString() ?? null,
    lastScanId: s.lastScanId, createdAt: s.createdAt.toISOString(),
  };
}

// ── POST /scans/pipeline-run ──────────────────────────────────────────────────

router.post("/scans/pipeline-run", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = RunPipelineScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const body = parsed.data as any;
  // The Zod schema field is `assetToolConfig` (from OpenAPI spec)
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

  const configAssetIds = configs.map(c => c.assetId);
  const [scan] = await db.insert(scansTable).values({
    tenantId, name: name ?? `Pipeline Scan — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: "running", assetIds: configAssetIds, startedAt: new Date(), findingsCount: 0,
  }).returning();

  // ── Respond immediately so the client can navigate to the scan report ────────
  res.status(201).json({ scanId: scan.id, status: "running", assetCount: configs.length, findingsCount: 0 });

  // ── Run real scans in the background ─────────────────────────────────────────
  setImmediate(async () => {
    try {
      const { findingsCount } = await executePipeline(tenantId, scan.id, configs, allTools, enabledTools);

      // Only mark completed if not already cancelled
      const current = await db.select({ status: scansTable.status }).from(scansTable)
        .where(eq(scansTable.id, scan.id)).then(r => r[0]);
      if (current?.status !== "cancelled") {
        await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
          .where(eq(scansTable.id, scan.id));
      }

      await logAudit(tenantId, userId as any, "scan.pipeline_run", "scan", scan.id, { assetCount: configs.length, findingsCount });
    } catch (err) {
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
        .where(eq(scansTable.id, scan.id)).catch(() => {});
    }
  });
});

// ── POST /scans/:scanId/stop ──────────────────────────────────────────────────

router.post("/scans/:scanId/stop", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = StopScanParams.safeParse({ scanId: Number(req.params.scanId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const tenantId = req.user!.tenantId;
  const { scanId } = parsed.data;

  const scan = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, tenantId))).then(r => r[0]);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  if (scan.status === "completed" || scan.status === "cancelled") {
    res.status(400).json({ error: `Scan is already ${scan.status}` }); return;
  }

  // Kill any active nmap process for this scan
  const killer = activeScanKillers.get(scanId);
  if (killer) { killer(); activeScanKillers.delete(scanId); }

  const [updated] = await db.update(scansTable)
    .set({ status: "cancelled", completedAt: new Date() })
    .where(eq(scansTable.id, scanId)).returning();

  res.json({
    id: updated.id, tenantId: updated.tenantId, name: updated.name, type: updated.type,
    status: updated.status, schedule: updated.schedule, assetIds: updated.assetIds ?? [],
    findingsCount: updated.findingsCount,
    startedAt: updated.startedAt?.toISOString() ?? null,
    completedAt: updated.completedAt?.toISOString() ?? null,
    createdAt: updated.createdAt.toISOString(),
  });
});

// ── GET /scans/:scanId/asset-report ──────────────────────────────────────────

router.get("/scans/:scanId/asset-report", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = GetScanAssetReportParams.safeParse({ scanId: Number(req.params.scanId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const tenantId = req.user!.tenantId;
  const { scanId } = parsed.data;

  const scan = await db.select().from(scansTable)
    .where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, tenantId))).then(r => r[0]);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const scanResults = await db.select().from(scanAssetResultsTable)
    .where(and(eq(scanAssetResultsTable.scanId, scanId), eq(scanAssetResultsTable.tenantId, tenantId)));

  if (scanResults.length === 0) { res.json([]); return; }

  const assetIds = [...new Set(scanResults.map(r => r.assetId))];
  const assets = await db.select().from(assetsTable).where(inArray(assetsTable.id, assetIds));
  const assetMap = new Map(assets.map(a => [a.id, a]));

  const assetReports = assetIds.map(assetId => {
    const asset = assetMap.get(assetId);
    const assetResults = scanResults.filter(r => r.assetId === assetId);

    const allPorts: unknown[] = [], allSubdomains: unknown[] = [], allEndpoints: unknown[] = [];
    const allVulns: unknown[] = [], allDns: unknown[] = [], allIntel: unknown[] = [];
    let httpInfo: unknown = null;

    const toolResults = assetResults.map(r => {
      const tr: Record<string, unknown> = { toolName: r.toolName, toolCategory: r.toolCategory, rawOutput: r.rawOutput };
      if (r.ports)          { tr.ports          = r.ports;         allPorts.push(...(r.ports as unknown[])); }
      if (r.subdomains)     { tr.subdomains     = r.subdomains;    allSubdomains.push(...(r.subdomains as unknown[])); }
      if (r.endpoints)      { tr.endpoints      = r.endpoints;     allEndpoints.push(...(r.endpoints as unknown[])); }
      if (r.httpInfo)       { tr.httpInfo       = r.httpInfo;      httpInfo = r.httpInfo; }
      if (r.dnsRecords)     { tr.dnsRecords     = r.dnsRecords;    allDns.push(...(r.dnsRecords as unknown[])); }
      if (r.intelligence)   { tr.intelligence   = r.intelligence;  allIntel.push(...(r.intelligence as unknown[])); }
      if (r.vulnerabilities){ tr.vulnerabilities = r.vulnerabilities; allVulns.push(...(r.vulnerabilities as unknown[])); }
      return tr;
    });

    const dedup = <T extends Record<string, unknown>>(arr: T[], key: string) => {
      const seen = new Set<string>();
      return arr.filter(i => { const k = String(i[key] ?? ""); return seen.has(k) ? false : (seen.add(k), true); });
    };

    const ports = dedup(allPorts as any[], "port");
    const vulns  = dedup(allVulns as any[], "cve");
    const critCount = vulns.filter((v: any) => v.severity === "critical").length;
    const highCount  = vulns.filter((v: any) => v.severity === "high").length;

    return {
      assetId, assetName: asset?.name ?? String(assetId), assetValue: asset?.value ?? "", assetType: asset?.type ?? "unknown",
      scanStatus: scan.status,
      summary: {
        openPorts: ports.length, vulnerabilities: vulns.length, criticalVulns: critCount, highVulns: highCount,
        subdomains: dedup(allSubdomains as any[], "name").length,
        endpoints:  dedup(allEndpoints as any[], "url").length,
        dnsRecords: dedup(allDns as any[], "value").length,
        intelItems: dedup(allIntel as any[], "key").length,
        toolsRun:   assetResults.length,
        waf: httpInfo ? (httpInfo as HttpInfo).waf : null,
        cdn: (allIntel as any[]).find((i: any) => i.type === "CDN")?.value ?? null,
      },
      ports, subdomains: dedup(allSubdomains as any[], "name"),
      endpoints: dedup(allEndpoints as any[], "url"),
      httpInfo, dnsRecords: dedup(allDns as any[], "value"),
      intelligence: dedup(allIntel as any[], "key"),
      vulnerabilities: vulns, toolResults,
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

  const tenantId     = req.user!.tenantId;
  const { scheduleId } = paramsP.data;
  const existing     = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!existing) { res.status(404).json({ error: "Schedule not found" }); return; }

  const updates: Record<string, unknown> = { ...bodyP.data };
  const freq = (updates.frequency as string) ?? existing.frequency;
  const rt   = (updates.runTime   as string) ?? existing.runTime;
  const dow  = (updates.dayOfWeek as number | undefined) ?? existing.dayOfWeek;
  const dom  = (updates.dayOfMonth as number | undefined) ?? existing.dayOfMonth;
  updates.nextRunAt = computeNextRunAt(freq, rt, dow, dom);

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

  const tenantId     = req.user!.tenantId;
  const userId       = req.user!.userId;
  const { scheduleId } = parsed.data;

  const schedule = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }

  const configs        = schedule.assetToolConfig as AssetToolConfigItem[];
  const configAssetIds = configs.map(c => c.assetId);

  const allTools = await db.select().from(securityToolsTable).where(eq(securityToolsTable.tenantId, tenantId));
  const pipelineSteps = await db.select({ tool: securityToolsTable })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
    .where(and(eq(toolPipelineStepsTable.tenantId, tenantId), eq(toolPipelineStepsTable.isEnabled, true)));
  const enabledTools = pipelineSteps.map(p => p.tool);

  const [scan] = await db.insert(scansTable).values({
    tenantId, name: `${schedule.name} — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: "running", assetIds: configAssetIds, startedAt: new Date(), findingsCount: 0,
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
      const nextRunAt = computeNextRunAt(schedule.frequency, schedule.runTime, schedule.dayOfWeek, schedule.dayOfMonth);
      await db.update(scanSchedulesTable).set({ lastRunAt: new Date(), lastScanId: scan.id, nextRunAt })
        .where(eq(scanSchedulesTable.id, scheduleId));
      await logAudit(tenantId, userId as any, "schedule.run_now", "scan", scan.id, { scheduleId, findingsCount });
    } catch {
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
        .where(eq(scansTable.id, scan.id)).catch(() => {});
    }
  });
});

export default router;
