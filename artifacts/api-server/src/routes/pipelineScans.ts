import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, scansTable, scanAssetResultsTable, assetsTable, findingsTable, securityToolsTable, toolPipelineStepsTable } from "@workspace/db";
import { RunPipelineScanBody, GetScanAssetReportParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

function strHash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) {
    h = ((h * 31) + s.charCodeAt(i)) & 0x7fffffff;
  }
  return h;
}

function seededPick<T>(arr: T[], seed: number, offset = 0): T {
  const idx = ((seed + offset) * 1664525 + 1013904223) & 0x7fffffff;
  return arr[idx % arr.length];
}

function seededInt(seed: number, min: number, max: number, offset = 0): number {
  const n = ((seed + offset) * 1664525 + 1013904223) & 0x7fffffff;
  return min + (n % (max - min + 1));
}

function seededSubset<T>(arr: T[], seed: number, minCount: number, maxCount: number): T[] {
  const count = seededInt(seed, minCount, maxCount);
  const shuffled = [...arr].sort((a, b) => {
    const ha = strHash(String(a) + seed);
    const hb = strHash(String(b) + seed);
    return ha - hb;
  });
  return shuffled.slice(0, count);
}

const PORT_POOL = [
  { port: 22, service: "ssh", version: "OpenSSH_8.9p1" },
  { port: 80, service: "http", version: "nginx/1.24.0" },
  { port: 443, service: "https", version: "nginx/1.24.0" },
  { port: 8080, service: "http-proxy", version: "Apache/2.4.57" },
  { port: 8443, service: "https-alt", version: "nginx/1.20.2" },
  { port: 3000, service: "http", version: "Node.js/20.11.0" },
  { port: 3306, service: "mysql", version: "MySQL/8.0.35" },
  { port: 5432, service: "postgresql", version: "PostgreSQL/15.4" },
  { port: 6379, service: "redis", version: "Redis/7.2.3" },
  { port: 27017, service: "mongodb", version: "MongoDB/7.0.4" },
  { port: 9200, service: "elasticsearch", version: "Elasticsearch/8.11.0" },
  { port: 8888, service: "http", version: "Jupyter/6.5.4" },
  { port: 21, service: "ftp", version: "vsftpd/3.0.5" },
  { port: 25, service: "smtp", version: "Postfix/3.8.0" },
  { port: 53, service: "dns", version: "BIND/9.18.19" },
];

const SUBDOMAIN_PREFIXES = ["api", "app", "mail", "smtp", "vpn", "dev", "staging", "admin", "portal", "cdn", "static", "img", "auth", "sso", "gateway", "internal", "beta", "docs", "support", "status", "monitor", "logs", "metrics", "jenkins", "gitlab", "jira", "confluence", "grafana", "kibana"];

const TECHNOLOGIES = ["React", "Angular", "Vue.js", "Next.js", "Express", "Django", "Laravel", "Spring Boot", "ASP.NET", "Ruby on Rails", "Flask", "FastAPI"];
const SERVERS = ["nginx/1.24.0", "Apache/2.4.57", "cloudflare", "IIS/10.0", "LiteSpeed/6.2", "Caddy/2.7.5"];
const WAFS = ["Cloudflare", "AWS WAF", "ModSecurity", "Imperva", "Akamai Kona", "F5 BIG-IP ASM", "none"];
const CDN_PROVIDERS = ["Cloudflare", "Fastly", "Akamai", "AWS CloudFront", "Azure CDN", "Google CDN"];
const HEADERS = [
  { k: "x-frame-options", v: "SAMEORIGIN" },
  { k: "strict-transport-security", v: "max-age=31536000; includeSubDomains" },
  { k: "x-content-type-options", v: "nosniff" },
  { k: "content-security-policy", v: "default-src 'self'" },
  { k: "x-xss-protection", v: "1; mode=block" },
  { k: "referrer-policy", v: "strict-origin-when-cross-origin" },
  { k: "permissions-policy", v: "geolocation=(), microphone=(), camera=()" },
];
const DNS_TXT_VALUES = [
  "v=spf1 include:_spf.google.com ~all",
  "v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com",
  "google-site-verification=abc123xyz",
  "MS=ms12345678",
  "atlassian-domain-verification=abc123",
];
const ENDPOINTS = [
  { url: "/", method: "GET", status: 200 },
  { url: "/api", method: "GET", status: 200 },
  { url: "/api/v1/health", method: "GET", status: 200 },
  { url: "/api/v1/users", method: "GET", status: 401 },
  { url: "/api/v1/login", method: "POST", status: 200 },
  { url: "/api/v1/products", method: "GET", status: 200 },
  { url: "/admin", method: "GET", status: 403 },
  { url: "/robots.txt", method: "GET", status: 200 },
  { url: "/sitemap.xml", method: "GET", status: 200 },
  { url: "/.env", method: "GET", status: 403 },
  { url: "/wp-admin", method: "GET", status: 404 },
  { url: "/api/v1/settings", method: "GET", status: 401 },
  { url: "/api/v1/reports", method: "GET", status: 200 },
  { url: "/graphql", method: "POST", status: 200 },
  { url: "/metrics", method: "GET", status: 403 },
  { url: "/swagger", method: "GET", status: 200 },
  { url: "/api/v1/files/upload", method: "POST", status: 401 },
];

const CVE_POOL = [
  { cve: "CVE-2023-44487", cvss: 7.5, severity: "high", title: "HTTP/2 Rapid Reset Attack (DoS)", cwe: "CWE-400", remediation: "Update server software to patched version. Limit concurrent streams per connection.", affected: ["nginx", "Apache", "http"] },
  { cve: "CVE-2024-0727", cvss: 5.5, severity: "medium", title: "OpenSSL PKCS12 Parsing Null Pointer Dereference", cwe: "CWE-476", remediation: "Upgrade OpenSSL to 3.2.1 or 1.1.1x.", affected: ["https", "ssl"] },
  { cve: "CVE-2023-38408", cvss: 9.8, severity: "critical", title: "OpenSSH Remote Code Execution via ssh-agent", cwe: "CWE-122", remediation: "Upgrade OpenSSH to 9.3p2 or later. Disable ssh-agent forwarding.", affected: ["ssh"] },
  { cve: "CVE-2023-34362", cvss: 9.8, severity: "critical", title: "MOVEit Transfer SQL Injection RCE", cwe: "CWE-89", remediation: "Apply MOVEit Transfer security patches immediately. Review transfer logs.", affected: ["http", "https"] },
  { cve: "CVE-2024-3400", cvss: 10.0, severity: "critical", title: "PAN-OS Command Injection (GlobalProtect)", cwe: "CWE-77", remediation: "Apply PAN-OS hotfix. Disable GlobalProtect portal if not required.", affected: ["https", "http"] },
  { cve: "CVE-2023-20198", cvss: 10.0, severity: "critical", title: "Cisco IOS XE Web UI Privilege Escalation", cwe: "CWE-306", remediation: "Disable HTTP/HTTPS Server or upgrade firmware. Block access from untrusted networks.", affected: ["http", "https"] },
  { cve: "CVE-2022-26134", cvss: 9.8, severity: "critical", title: "Confluence Server/DC OGNL Injection RCE", cwe: "CWE-74", remediation: "Upgrade to Confluence 7.4.17+ or 7.13.7+. Block external access to server.", affected: ["http", "https"] },
  { cve: "CVE-2023-6553", cvss: 9.8, severity: "critical", title: "Backup Migration Plugin PHP Code Injection", cwe: "CWE-94", remediation: "Update Backup Migration plugin to 1.3.8+. Remove unused plugins.", affected: ["http"] },
  { cve: "CVE-2024-1086", cvss: 7.8, severity: "high", title: "Linux Kernel Use-After-Free via nf_tables", cwe: "CWE-416", remediation: "Apply kernel patch. Update to kernel 6.6.15+ or 6.7.3+.", affected: ["ssh", "ftp"] },
  { cve: "CVE-2023-32315", cvss: 7.5, severity: "high", title: "Openfire XMPP Authentication Bypass", cwe: "CWE-288", remediation: "Upgrade Openfire to 4.7.5+. Restrict admin console access.", affected: ["http", "https"] },
  { cve: "CVE-2024-4577", cvss: 9.8, severity: "critical", title: "PHP CGI Argument Injection RCE", cwe: "CWE-88", remediation: "Update PHP to 8.3.8+, 8.2.20+, or 8.1.29+. Disable PHP CGI.", affected: ["http", "https"] },
  { cve: "CVE-2023-29017", cvss: 9.8, severity: "critical", title: "vm2 Sandbox Escape Remote Code Execution", cwe: "CWE-94", remediation: "Update vm2 to 3.9.19+. Consider using alternative sandboxing.", affected: ["http"] },
  { cve: "CVE-2024-21626", cvss: 8.6, severity: "high", title: "runc Container Breakout (Leaky Vessels)", cwe: "CWE-668", remediation: "Update runc to 1.1.12+. Update container runtime (Docker/Containerd).", affected: ["http", "https"] },
  { cve: "CVE-2023-42793", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Authentication Bypass", cwe: "CWE-288", remediation: "Update to TeamCity 2023.05.4+. Restrict server access to authorized networks.", affected: ["http", "https"] },
  { cve: "CVE-2024-6387", cvss: 8.1, severity: "high", title: "OpenSSH regreSSHion - Race Condition RCE", cwe: "CWE-364", remediation: "Update OpenSSH to 9.8p1+. Set LoginGraceTime=0 as a temporary mitigation.", affected: ["ssh"] },
];

const INTEL_TYPES = [
  { type: "ASN", key: "AS Number", getValue: (seed: number) => `AS${seededInt(seed, 10000, 99999)}` },
  { type: "ASN", key: "Organization", getValue: (seed: number) => seededPick(["Amazon Technologies Inc.", "Google LLC", "Microsoft Corporation", "Cloudflare Inc.", "Akamai Technologies", "Fastly Inc.", "DigitalOcean LLC", "Linode LLC", "OVHcloud", "Hetzner Online GmbH"], seed) },
  { type: "GeoIP", key: "Country", getValue: (seed: number) => seededPick(["United States", "Germany", "Netherlands", "United Kingdom", "France", "Singapore", "Japan", "Canada", "Australia", "Ireland"], seed) },
  { type: "GeoIP", key: "City", getValue: (seed: number) => seededPick(["San Francisco", "New York", "London", "Frankfurt", "Amsterdam", "Singapore", "Tokyo", "Seattle", "Dublin", "Sydney"], seed) },
  { type: "CDN", key: "Provider", getValue: (seed: number) => seededPick(CDN_PROVIDERS, seed) },
  { type: "WHOIS", key: "Registrar", getValue: (seed: number) => seededPick(["GoDaddy LLC", "NameCheap Inc.", "Network Solutions", "Tucows Domains Inc.", "Google Domains", "Cloudflare Registrar"], seed) },
  { type: "WHOIS", key: "Registered", getValue: (seed: number) => `20${seededInt(seed, 10, 23)}-${String(seededInt(seed + 1, 1, 12)).padStart(2, "0")}-${String(seededInt(seed + 2, 1, 28)).padStart(2, "0")}` },
  { type: "Shodan", key: "Exposures", getValue: (seed: number) => `${seededInt(seed, 1, 8)} exposed services indexed` },
  { type: "Certificate", key: "Issuer", getValue: (seed: number) => seededPick(["Let's Encrypt", "DigiCert Inc", "Sectigo Limited", "GlobalSign", "Comodo CA", "Amazon Trust Services"], seed) },
  { type: "Certificate", key: "Expiry", getValue: (seed: number) => `2025-${String(seededInt(seed, 1, 12)).padStart(2, "0")}-${String(seededInt(seed + 1, 1, 28)).padStart(2, "0")}` },
];

interface PortFinding {
  port: number; service: string; version: string; protocol: string; state: string;
}
interface SubdomainFinding {
  name: string; ip: string; cname: string | null; status: string; cdnProvider: string | null;
}
interface EndpointFinding {
  url: string; method: string; status: number;
}
interface HttpInfo {
  url: string; status: number; title: string; server: string; contentLength: number;
  tech: string[]; waf: string; headers: Record<string, string>;
}
interface DnsRecord {
  type: string; value: string; ttl: number; priority?: number;
}
interface IntelItem {
  type: string; key: string; value: string;
}
interface VulnFinding {
  cve: string; cvss: number; severity: string; title: string; cwe: string; remediation: string;
}

function simulatePorts(assetValue: string, toolName: string): PortFinding[] {
  const seed = strHash(assetValue + toolName);
  const selected = seededSubset(PORT_POOL, seed, 2, 6);
  return selected.map(p => ({ ...p, protocol: "tcp", state: "open" }));
}

function simulateSubdomains(assetValue: string): SubdomainFinding[] {
  const seed = strHash(assetValue + "subs");
  const baseDomain = assetValue.replace(/^https?:\/\//, "").split("/")[0].replace(/^\*\./, "");
  const count = seededInt(seed, 4, 12);
  const prefixes = seededSubset(SUBDOMAIN_PREFIXES, seed, count, count);
  const ipBase = `${seededInt(seed, 10, 220)}.${seededInt(seed + 1, 0, 255)}.${seededInt(seed + 2, 0, 255)}`;
  return prefixes.map((prefix, i) => ({
    name: `${prefix}.${baseDomain}`,
    ip: `${ipBase}.${seededInt(seed + i + 10, 1, 254)}`,
    cname: seededInt(seed + i, 0, 3) === 0 ? `${prefix}.${seededPick(["cloudfront.net", "google.com", "azureedge.net", "fastly.net"], seed + i)}` : null,
    status: seededPick(["active", "active", "active", "active", "inactive"], seed + i),
    cdnProvider: seededInt(seed + i, 0, 2) === 0 ? seededPick(CDN_PROVIDERS, seed + i) : null,
  }));
}

function simulateHttpInfo(assetValue: string): HttpInfo {
  const seed = strHash(assetValue + "http");
  const url = assetValue.startsWith("http") ? assetValue : `https://${assetValue}`;
  const server = seededPick(SERVERS, seed);
  const tech = seededSubset(TECHNOLOGIES, seed, 1, 3);
  const headerSubset = seededSubset(HEADERS, seed + 1, 3, 6);
  const headers: Record<string, string> = {};
  for (const h of headerSubset) headers[h.k] = h.v;
  headers["server"] = server;
  const titles = ["Login | Corporate Portal", "Dashboard | Company", "Welcome to our platform", "API Gateway", "Developer Portal", "Authentication Service", "Customer Support", "Internal Tools", "Security Operations Center"];
  return {
    url,
    status: seededPick([200, 200, 200, 200, 301, 302], seed),
    title: seededPick(titles, seed),
    server,
    contentLength: seededInt(seed, 8000, 120000),
    tech,
    waf: seededPick(WAFS, seed + 2),
    headers,
  };
}

function simulateDnsRecords(assetValue: string): DnsRecord[] {
  const seed = strHash(assetValue + "dns");
  const baseDomain = assetValue.replace(/^https?:\/\//, "").split("/")[0];
  const ipBase = `${seededInt(seed, 10, 220)}.${seededInt(seed + 1, 0, 255)}.${seededInt(seed + 2, 0, 255)}`;
  const records: DnsRecord[] = [
    { type: "A", value: `${ipBase}.${seededInt(seed + 3, 1, 254)}`, ttl: seededPick([60, 300, 600, 3600], seed) },
    { type: "A", value: `${ipBase}.${seededInt(seed + 4, 1, 254)}`, ttl: seededPick([60, 300, 600, 3600], seed + 1) },
    { type: "AAAA", value: `2606:4700:${seededInt(seed, 1000, 9999).toString(16)}::1`, ttl: 300 },
    { type: "MX", value: `mail.${baseDomain}`, ttl: 3600, priority: 10 },
    { type: "MX", value: `mail2.${baseDomain}`, ttl: 3600, priority: 20 },
    { type: "NS", value: `ns1.${seededPick(["cloudflare.com", "google.com", "awsdns-01.com", "nsone.net"], seed)}`, ttl: 86400 },
    { type: "TXT", value: seededPick(DNS_TXT_VALUES, seed), ttl: 3600 },
    { type: "CNAME", value: `${baseDomain}.${seededPick(["cdn.cloudflare.net", "edge.fastly.net", "cloudfront.net", "azureedge.net"], seed)}`, ttl: 300 },
  ];
  return records;
}

function simulateEndpoints(assetValue: string): EndpointFinding[] {
  const seed = strHash(assetValue + "endpoints");
  return seededSubset(ENDPOINTS, seed, 5, 12);
}

function simulateVulnerabilities(assetValue: string, ports: PortFinding[]): VulnFinding[] {
  const seed = strHash(assetValue + "vulns");
  const services = ports.map(p => p.service);
  const relevant = CVE_POOL.filter(cve =>
    cve.affected.some(a => services.includes(a))
  );
  const fallback = seededSubset(CVE_POOL, seed, 0, 2);
  const combined = [...new Map([...fallback, ...relevant].map(v => [v.cve, v])).values()];
  return seededSubset(combined, seed, 1, Math.min(4, combined.length));
}

function simulateIntelligence(assetValue: string): IntelItem[] {
  const seed = strHash(assetValue + "intel");
  return INTEL_TYPES.map(t => ({ type: t.type, key: t.key, value: t.getValue(seed) }));
}

function generateRawOutput(toolName: string, assetValue: string, results: Record<string, unknown>): string {
  const lines: string[] = [`[${toolName}] Running against target: ${assetValue}`, ""];
  if (results.ports) {
    const ports = results.ports as PortFinding[];
    lines.push("PORT     STATE  SERVICE   VERSION");
    for (const p of ports) {
      lines.push(`${String(p.port).padEnd(9)}open   ${p.service.padEnd(9)} ${p.version}`);
    }
  }
  if (results.subdomains) {
    lines.push("\nDiscovered Subdomains:");
    for (const s of results.subdomains as SubdomainFinding[]) {
      lines.push(`  ${(s.name as string).padEnd(35)} ${s.ip}`);
    }
  }
  if (results.httpInfo) {
    const h = results.httpInfo as HttpInfo;
    lines.push(`\nHTTP: ${h.url} [${h.status}] [${h.contentLength}] [${h.title}] [${h.server}]`);
    if (h.waf !== "none") lines.push(`WAF Detected: ${h.waf}`);
    lines.push(`Technologies: ${h.tech.join(", ")}`);
  }
  if (results.dnsRecords) {
    lines.push("\nDNS Records:");
    for (const r of results.dnsRecords as DnsRecord[]) {
      lines.push(`  ${r.type.padEnd(6)} ${r.value}`);
    }
  }
  if (results.endpoints) {
    lines.push("\nDiscovered Endpoints:");
    for (const e of results.endpoints as EndpointFinding[]) {
      lines.push(`  [${e.status}] ${e.method.padEnd(5)} ${e.url}`);
    }
  }
  if (results.vulnerabilities) {
    lines.push("\nVulnerabilities Found:");
    for (const v of results.vulnerabilities as VulnFinding[] ) {
      lines.push(`  [${(v.severity as string).toUpperCase()}] ${v.cve} - ${v.title} (CVSS: ${v.cvss})`);
    }
  }
  if (results.intelligence) {
    lines.push("\nIntelligence Gathered:");
    for (const i of results.intelligence as IntelItem[]) {
      lines.push(`  [${i.type}] ${i.key}: ${i.value}`);
    }
  }
  lines.push(`\n[${toolName}] Completed.`);
  return lines.join("\n");
}

router.post("/scans/pipeline-run", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = RunPipelineScanBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: parsed.error.message }); return; }

  const { assetIds, name } = parsed.data;
  if (!assetIds || assetIds.length === 0) {
    res.status(400).json({ error: "At least one asset is required" });
    return;
  }

  const tenantId = req.user!.tenantId;
  const userId = req.user!.userId;

  const assets = await db.select().from(assetsTable).where(
    and(eq(assetsTable.tenantId, tenantId), inArray(assetsTable.id, assetIds))
  );

  if (assets.length === 0) {
    res.status(404).json({ error: "No assets found" });
    return;
  }

  const pipelineSteps = await db.select({
    step: toolPipelineStepsTable,
    tool: securityToolsTable,
  })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
    .where(
      and(
        eq(toolPipelineStepsTable.tenantId, tenantId),
        eq(toolPipelineStepsTable.isEnabled, true),
      )
    )
    .orderBy(toolPipelineStepsTable.stepOrder);

  const enabledTools = pipelineSteps.map(p => p.tool);

  if (enabledTools.length === 0) {
    res.status(400).json({ error: "No pipeline tools enabled. Configure pipeline steps first." });
    return;
  }

  const [scan] = await db.insert(scansTable).values({
    tenantId,
    name: name ?? `Pipeline Scan — ${new Date().toLocaleDateString()}`,
    type: "pipeline",
    status: "running",
    assetIds,
    startedAt: new Date(),
    findingsCount: 0,
  }).returning();

  const results: Array<typeof scanAssetResultsTable.$inferInsert> = [];
  let totalVulns = 0;
  const findingInserts: Array<typeof findingsTable.$inferInsert> = [];

  for (const asset of assets) {
    const ports = simulatePorts(asset.value, "naabu");

    for (const tool of enabledTools) {
      const cat = tool.category ?? "recon";
      let toolPorts = null;
      let subdomains = null;
      let endpoints = null;
      let httpInfo = null;
      let dnsRecords = null;
      let intelligence = null;
      let vulnerabilities = null;

      if (cat === "port_scan") {
        toolPorts = simulatePorts(asset.value, tool.name);
      } else if (cat === "web_recon") {
        httpInfo = simulateHttpInfo(asset.value);
        endpoints = simulateEndpoints(asset.value);
      } else if (cat === "recon") {
        subdomains = simulateSubdomains(asset.value);
        dnsRecords = simulateDnsRecords(asset.value);
      } else if (cat === "vuln_scan") {
        vulnerabilities = simulateVulnerabilities(asset.value, ports);
        totalVulns += vulnerabilities.length;
        for (const v of vulnerabilities) {
          findingInserts.push({
            tenantId,
            assetId: asset.id,
            scanId: scan.id,
            title: v.title,
            cve: v.cve,
            severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
            cvssScore: String(v.cvss),
            cwe: v.cwe,
            status: "open",
            description: `${v.title} (${v.cve}) — CVSS ${v.cvss}`,
            remediation: v.remediation,
          });
        }
      } else if (cat === "osint") {
        intelligence = simulateIntelligence(asset.value);
      } else if (cat === "ssl_check") {
        httpInfo = simulateHttpInfo(asset.value);
        intelligence = simulateIntelligence(asset.value).filter(i => i.type === "Certificate");
      } else {
        subdomains = simulateSubdomains(asset.value);
        dnsRecords = simulateDnsRecords(asset.value);
      }

      const rawObj: Record<string, unknown> = {};
      if (toolPorts) rawObj.ports = toolPorts;
      if (subdomains) rawObj.subdomains = subdomains;
      if (endpoints) rawObj.endpoints = endpoints;
      if (httpInfo) rawObj.httpInfo = httpInfo;
      if (dnsRecords) rawObj.dnsRecords = dnsRecords;
      if (intelligence) rawObj.intelligence = intelligence;
      if (vulnerabilities) rawObj.vulnerabilities = vulnerabilities;

      results.push({
        tenantId,
        scanId: scan.id,
        assetId: asset.id,
        toolName: tool.name,
        toolCategory: cat,
        rawOutput: generateRawOutput(tool.name, asset.value, rawObj),
        ports: toolPorts ?? null,
        subdomains: subdomains ?? null,
        endpoints: endpoints ?? null,
        httpInfo: httpInfo ?? null,
        dnsRecords: dnsRecords ?? null,
        intelligence: intelligence ?? null,
        vulnerabilities: vulnerabilities ?? null,
      });
    }
  }

  if (results.length > 0) {
    for (let i = 0; i < results.length; i += 50) {
      await db.insert(scanAssetResultsTable).values(results.slice(i, i + 50));
    }
  }

  if (findingInserts.length > 0) {
    for (let i = 0; i < findingInserts.length; i += 50) {
      await db.insert(findingsTable).values(findingInserts.slice(i, i + 50));
    }
  }

  const totalFindings = findingInserts.length;

  await db.update(scansTable).set({
    status: "completed",
    completedAt: new Date(),
    findingsCount: totalFindings,
  }).where(eq(scansTable.id, scan.id));

  await logAudit(tenantId, userId, "scan.pipeline_run", "scan", scan.id, {
    assetCount: assets.length,
    toolCount: enabledTools.length,
    findingsCount: totalFindings,
  });

  res.status(201).json({
    scanId: scan.id,
    status: "completed",
    assetCount: assets.length,
    findingsCount: totalFindings,
  });
});

router.get("/scans/:scanId/asset-report", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = GetScanAssetReportParams.safeParse({ scanId: Number(req.params.scanId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid scan ID" }); return; }

  const tenantId = req.user!.tenantId;
  const { scanId } = parsed.data;

  const scan = await db.select().from(scansTable).where(
    and(eq(scansTable.id, scanId), eq(scansTable.tenantId, tenantId))
  ).then(r => r[0]);

  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  const scanResults = await db.select().from(scanAssetResultsTable).where(
    and(eq(scanAssetResultsTable.scanId, scanId), eq(scanAssetResultsTable.tenantId, tenantId))
  );

  if (scanResults.length === 0) {
    res.json([]);
    return;
  }

  const assetIds = [...new Set(scanResults.map(r => r.assetId))];
  const assets = await db.select().from(assetsTable).where(inArray(assetsTable.id, assetIds));
  const assetMap = new Map(assets.map(a => [a.id, a]));

  const assetReports = assetIds.map(assetId => {
    const asset = assetMap.get(assetId);
    const assetResults = scanResults.filter(r => r.assetId === assetId);

    const allPorts: PortFinding[] = [];
    const allSubdomains: SubdomainFinding[] = [];
    const allEndpoints: EndpointFinding[] = [];
    const allVulns: VulnFinding[] = [];
    const allDns: DnsRecord[] = [];
    const allIntel: IntelItem[] = [];
    let httpInfo: HttpInfo | null = null;

    const toolResults = assetResults.map(r => {
      const tr: Record<string, unknown> = {
        toolName: r.toolName,
        toolCategory: r.toolCategory,
        rawOutput: r.rawOutput,
      };
      if (r.ports) { tr.ports = r.ports; allPorts.push(...(r.ports as PortFinding[])); }
      if (r.subdomains) { tr.subdomains = r.subdomains; allSubdomains.push(...(r.subdomains as SubdomainFinding[])); }
      if (r.endpoints) { tr.endpoints = r.endpoints; allEndpoints.push(...(r.endpoints as EndpointFinding[])); }
      if (r.httpInfo) { tr.httpInfo = r.httpInfo; httpInfo = r.httpInfo as HttpInfo; }
      if (r.dnsRecords) { tr.dnsRecords = r.dnsRecords; allDns.push(...(r.dnsRecords as DnsRecord[])); }
      if (r.intelligence) { tr.intelligence = r.intelligence; allIntel.push(...(r.intelligence as IntelItem[])); }
      if (r.vulnerabilities) { tr.vulnerabilities = r.vulnerabilities; allVulns.push(...(r.vulnerabilities as VulnFinding[])); }
      return tr;
    });

    const deduped = (items: { port?: number; name?: string; url?: string; cve?: string; type?: string; key?: string }[], key: string) => {
      const seen = new Set();
      return items.filter(i => {
        const k = String(i[key as keyof typeof i] ?? "");
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      });
    };

    const criticalCount = allVulns.filter(v => v.severity === "critical").length;
    const highCount = allVulns.filter(v => v.severity === "high").length;

    return {
      assetId,
      assetName: asset?.name ?? String(assetId),
      assetValue: asset?.value ?? "",
      assetType: asset?.type ?? "unknown",
      summary: {
        openPorts: deduped(allPorts, "port").length,
        vulnerabilities: allVulns.length,
        criticalVulns: criticalCount,
        highVulns: highCount,
        subdomains: deduped(allSubdomains, "name").length,
        endpoints: deduped(allEndpoints, "url").length,
        dnsRecords: deduped(allDns, "value").length,
        intelItems: deduped(allIntel, "key").length,
        toolsRun: assetResults.length,
        waf: httpInfo ? (httpInfo as HttpInfo).waf : null,
        cdn: allIntel.find(i => i.type === "CDN")?.value ?? null,
      },
      ports: deduped(allPorts, "port"),
      subdomains: deduped(allSubdomains, "name"),
      endpoints: deduped(allEndpoints, "url"),
      httpInfo,
      dnsRecords: deduped(allDns, "value"),
      intelligence: deduped(allIntel, "key"),
      vulnerabilities: deduped(allVulns, "cve"),
      toolResults,
    };
  });

  res.json(assetReports);
});

export default router;
