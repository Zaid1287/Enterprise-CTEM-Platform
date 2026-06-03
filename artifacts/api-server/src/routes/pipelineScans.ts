import { Router } from "express";
import { eq, and, inArray } from "drizzle-orm";
import { db, scansTable, scanAssetResultsTable, assetsTable, findingsTable, securityToolsTable, toolPipelineStepsTable, scanSchedulesTable } from "@workspace/db";
import { RunPipelineScanBody, GetScanAssetReportParams, CreateScanScheduleBody, UpdateScanScheduleBody, UpdateScanScheduleParams, RunScheduleNowParams, StopScanParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();

// ── Simulation helpers ────────────────────────────────────────────────────────

function strHash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 31) + s.charCodeAt(i)) & 0x7fffffff;
  return h;
}

function seededPick<T>(arr: T[], seed: number, offset = 0): T {
  return arr[((seed + offset) * 1664525 + 1013904223) & 0x7fffffff % arr.length];
}

function seededInt(seed: number, min: number, max: number, offset = 0): number {
  return min + (((seed + offset) * 1664525 + 1013904223) & 0x7fffffff) % (max - min + 1);
}

function seededSubset<T>(arr: T[], seed: number, minCount: number, maxCount: number): T[] {
  const count = seededInt(seed, minCount, maxCount);
  return [...arr].sort((a, b) => strHash(String(a) + seed) - strHash(String(b) + seed)).slice(0, count);
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
  { port: 21, service: "ftp", version: "vsftpd/3.0.5" },
  { port: 25, service: "smtp", version: "Postfix/3.8.0" },
  { port: 53, service: "dns", version: "BIND/9.18.19" },
];
const SUBDOMAIN_PREFIXES = ["api", "app", "mail", "smtp", "vpn", "dev", "staging", "admin", "portal", "cdn", "static", "img", "auth", "sso", "gateway", "internal", "beta", "docs", "support", "status", "monitor", "logs", "metrics", "jenkins", "grafana", "kibana"];
const TECHNOLOGIES = ["React", "Angular", "Vue.js", "Next.js", "Express", "Django", "Laravel", "Spring Boot", "ASP.NET", "Flask", "FastAPI"];
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
];
const DNS_TXT_VALUES = [
  "v=spf1 include:_spf.google.com ~all",
  "v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com",
  "google-site-verification=abc123xyz",
  "MS=ms12345678",
];
const ENDPOINTS = [
  { url: "/", method: "GET", status: 200 }, { url: "/api", method: "GET", status: 200 },
  { url: "/api/v1/health", method: "GET", status: 200 }, { url: "/api/v1/users", method: "GET", status: 401 },
  { url: "/api/v1/login", method: "POST", status: 200 }, { url: "/admin", method: "GET", status: 403 },
  { url: "/robots.txt", method: "GET", status: 200 }, { url: "/.env", method: "GET", status: 403 },
  { url: "/graphql", method: "POST", status: 200 }, { url: "/swagger", method: "GET", status: 200 },
  { url: "/metrics", method: "GET", status: 403 }, { url: "/api/v1/settings", method: "GET", status: 401 },
];
const CVE_POOL = [
  { cve: "CVE-2023-44487", cvss: 7.5, severity: "high", title: "HTTP/2 Rapid Reset Attack (DoS)", cwe: "CWE-400", remediation: "Update server software to patched version.", affected: ["nginx", "Apache", "http"] },
  { cve: "CVE-2024-0727", cvss: 5.5, severity: "medium", title: "OpenSSL PKCS12 Null Pointer Dereference", cwe: "CWE-476", remediation: "Upgrade OpenSSL to 3.2.1+.", affected: ["https", "ssl"] },
  { cve: "CVE-2023-38408", cvss: 9.8, severity: "critical", title: "OpenSSH Remote Code Execution via ssh-agent", cwe: "CWE-122", remediation: "Upgrade OpenSSH to 9.3p2+.", affected: ["ssh"] },
  { cve: "CVE-2024-3400", cvss: 10.0, severity: "critical", title: "PAN-OS Command Injection (GlobalProtect)", cwe: "CWE-77", remediation: "Apply PAN-OS hotfix immediately.", affected: ["https", "http"] },
  { cve: "CVE-2023-20198", cvss: 10.0, severity: "critical", title: "Cisco IOS XE Web UI Privilege Escalation", cwe: "CWE-306", remediation: "Disable HTTP/HTTPS Server or upgrade firmware.", affected: ["http", "https"] },
  { cve: "CVE-2022-26134", cvss: 9.8, severity: "critical", title: "Confluence Server OGNL Injection RCE", cwe: "CWE-74", remediation: "Upgrade Confluence to 7.4.17+.", affected: ["http", "https"] },
  { cve: "CVE-2024-1086", cvss: 7.8, severity: "high", title: "Linux Kernel Use-After-Free via nf_tables", cwe: "CWE-416", remediation: "Apply kernel patch, update to 6.7.3+.", affected: ["ssh", "ftp"] },
  { cve: "CVE-2024-4577", cvss: 9.8, severity: "critical", title: "PHP CGI Argument Injection RCE", cwe: "CWE-88", remediation: "Update PHP to 8.3.8+.", affected: ["http", "https"] },
  { cve: "CVE-2024-6387", cvss: 8.1, severity: "high", title: "OpenSSH regreSSHion Race Condition RCE", cwe: "CWE-364", remediation: "Update OpenSSH to 9.8p1+.", affected: ["ssh"] },
  { cve: "CVE-2023-42793", cvss: 9.8, severity: "critical", title: "JetBrains TeamCity Authentication Bypass", cwe: "CWE-288", remediation: "Update to TeamCity 2023.05.4+.", affected: ["http", "https"] },
];
const INTEL_TYPES = [
  { type: "ASN", key: "AS Number", getValue: (s: number) => `AS${seededInt(s, 10000, 99999)}` },
  { type: "ASN", key: "Organization", getValue: (s: number) => seededPick(["Amazon Technologies", "Google LLC", "Microsoft Corp", "Cloudflare Inc.", "Fastly Inc.", "DigitalOcean LLC"], s) },
  { type: "GeoIP", key: "Country", getValue: (s: number) => seededPick(["United States", "Germany", "Netherlands", "United Kingdom", "France", "Singapore", "Japan"], s) },
  { type: "GeoIP", key: "City", getValue: (s: number) => seededPick(["San Francisco", "New York", "London", "Frankfurt", "Amsterdam", "Singapore", "Tokyo"], s) },
  { type: "CDN", key: "Provider", getValue: (s: number) => seededPick(CDN_PROVIDERS, s) },
  { type: "WHOIS", key: "Registrar", getValue: (s: number) => seededPick(["GoDaddy LLC", "NameCheap Inc.", "Google Domains", "Cloudflare Registrar"], s) },
  { type: "Certificate", key: "Issuer", getValue: (s: number) => seededPick(["Let's Encrypt", "DigiCert Inc", "Sectigo Limited", "GlobalSign"], s) },
  { type: "Certificate", key: "Expiry", getValue: (s: number) => `2025-${String(seededInt(s, 1, 12)).padStart(2, "0")}-${String(seededInt(s + 1, 1, 28)).padStart(2, "0")}` },
];

interface PortFinding { port: number; service: string; version: string; protocol: string; state: string; }
interface SubdomainFinding { name: string; ip: string; cname: string | null; status: string; cdnProvider: string | null; }
interface EndpointFinding { url: string; method: string; status: number; }
interface HttpInfo { url: string; status: number; title: string; server: string; contentLength: number; tech: string[]; waf: string; headers: Record<string, string>; }
interface DnsRecord { type: string; value: string; ttl: number; priority?: number; }
interface IntelItem { type: string; key: string; value: string; }
interface VulnFinding { cve: string; cvss: number; severity: string; title: string; cwe: string; remediation: string; }

function simulatePorts(assetValue: string, toolName: string): PortFinding[] {
  const seed = strHash(assetValue + toolName);
  return seededSubset(PORT_POOL, seed, 2, 6).map(p => ({ ...p, protocol: "tcp", state: "open" }));
}

function simulateSubdomains(assetValue: string): SubdomainFinding[] {
  const seed = strHash(assetValue + "subs");
  const base = assetValue.replace(/^https?:\/\//, "").split("/")[0].replace(/^\*\./, "");
  const ipBase = `${seededInt(seed, 10, 220)}.${seededInt(seed + 1, 0, 255)}.${seededInt(seed + 2, 0, 255)}`;
  return seededSubset(SUBDOMAIN_PREFIXES, seed, 4, 12).map((prefix, i) => ({
    name: `${prefix}.${base}`,
    ip: `${ipBase}.${seededInt(seed + i + 10, 1, 254)}`,
    cname: seededInt(seed + i, 0, 3) === 0 ? `${prefix}.${seededPick(["cloudfront.net", "google.com", "fastly.net"], seed + i)}` : null,
    status: seededPick(["active", "active", "active", "inactive"], seed + i),
    cdnProvider: seededInt(seed + i, 0, 2) === 0 ? seededPick(CDN_PROVIDERS, seed + i) : null,
  }));
}

function simulateHttpInfo(assetValue: string): HttpInfo {
  const seed = strHash(assetValue + "http");
  const server = seededPick(SERVERS, seed);
  const tech = seededSubset(TECHNOLOGIES, seed, 1, 3);
  const headers: Record<string, string> = { server };
  for (const h of seededSubset(HEADERS, seed + 1, 3, 5)) headers[h.k] = h.v;
  return {
    url: assetValue.startsWith("http") ? assetValue : `https://${assetValue}`,
    status: seededPick([200, 200, 200, 301, 302], seed),
    title: seededPick(["Login | Corporate Portal", "Dashboard | Company", "API Gateway", "Developer Portal", "Authentication Service", "Security Operations Center"], seed),
    server, contentLength: seededInt(seed, 8000, 120000),
    tech, waf: seededPick(WAFS, seed + 2), headers,
  };
}

function simulateDnsRecords(assetValue: string): DnsRecord[] {
  const seed = strHash(assetValue + "dns");
  const base = assetValue.replace(/^https?:\/\//, "").split("/")[0];
  const ipBase = `${seededInt(seed, 10, 220)}.${seededInt(seed + 1, 0, 255)}.${seededInt(seed + 2, 0, 255)}`;
  return [
    { type: "A", value: `${ipBase}.${seededInt(seed + 3, 1, 254)}`, ttl: seededPick([60, 300, 3600], seed) },
    { type: "AAAA", value: `2606:4700:${seededInt(seed, 1000, 9999).toString(16)}::1`, ttl: 300 },
    { type: "MX", value: `mail.${base}`, ttl: 3600, priority: 10 },
    { type: "NS", value: `ns1.${seededPick(["cloudflare.com", "google.com", "awsdns-01.com"], seed)}`, ttl: 86400 },
    { type: "TXT", value: seededPick(DNS_TXT_VALUES, seed), ttl: 3600 },
    { type: "CNAME", value: `${base}.${seededPick(["cdn.cloudflare.net", "edge.fastly.net", "cloudfront.net"], seed)}`, ttl: 300 },
  ];
}

function simulateEndpoints(assetValue: string): EndpointFinding[] {
  return seededSubset(ENDPOINTS, strHash(assetValue + "endpoints"), 5, 10);
}

function simulateVulnerabilities(assetValue: string, ports: PortFinding[]): VulnFinding[] {
  const seed = strHash(assetValue + "vulns");
  const services = ports.map(p => p.service);
  const relevant = CVE_POOL.filter(c => c.affected.some(a => services.includes(a)));
  const fallback = seededSubset(CVE_POOL, seed, 0, 2);
  const combined = [...new Map([...fallback, ...relevant].map(v => [v.cve, v])).values()];
  return seededSubset(combined, seed, 1, Math.min(4, combined.length));
}

function simulateIntelligence(assetValue: string): IntelItem[] {
  const seed = strHash(assetValue + "intel");
  return INTEL_TYPES.map(t => ({ type: t.type, key: t.key, value: t.getValue(seed) }));
}

function generateRawOutput(toolName: string, assetValue: string, results: Record<string, unknown>): string {
  const lines: string[] = [`[${toolName}] Target: ${assetValue}`, ""];
  if (results.ports) { lines.push("PORT  STATE  SERVICE  VERSION"); for (const p of results.ports as PortFinding[]) lines.push(`${String(p.port).padEnd(6)}open   ${p.service.padEnd(8)} ${p.version}`); }
  if (results.subdomains) { lines.push("\nSubdomains:"); for (const s of results.subdomains as SubdomainFinding[]) lines.push(`  ${(s.name as string).padEnd(32)} ${s.ip}`); }
  if (results.httpInfo) { const h = results.httpInfo as HttpInfo; lines.push(`\nHTTP: ${h.url} [${h.status}] [${h.title}] [${h.server}]`); if (h.waf !== "none") lines.push(`WAF: ${h.waf}`); lines.push(`Tech: ${h.tech.join(", ")}`); }
  if (results.dnsRecords) { lines.push("\nDNS:"); for (const r of results.dnsRecords as DnsRecord[]) lines.push(`  ${r.type.padEnd(6)} ${r.value}`); }
  if (results.endpoints) { lines.push("\nEndpoints:"); for (const e of results.endpoints as EndpointFinding[]) lines.push(`  [${e.status}] ${e.method.padEnd(5)} ${e.url}`); }
  if (results.vulnerabilities) { lines.push("\nVulnerabilities:"); for (const v of results.vulnerabilities as VulnFinding[]) lines.push(`  [${(v.severity as string).toUpperCase()}] ${v.cve} CVSS:${v.cvss} — ${v.title}`); }
  if (results.intelligence) { lines.push("\nIntelligence:"); for (const i of results.intelligence as IntelItem[]) lines.push(`  [${i.type}] ${i.key}: ${i.value}`); }
  lines.push(`\n[${toolName}] Completed.`);
  return lines.join("\n");
}

// ── Core pipeline execution logic ────────────────────────────────────────────

interface AssetToolConfigItem { assetId: number; toolIds: number[]; }

async function executePipeline(
  tenantId: number,
  scanId: number,
  assetConfigs: AssetToolConfigItem[],
  allTools: (typeof securityToolsTable.$inferSelect)[],
  enabledTools: (typeof securityToolsTable.$inferSelect)[],
): Promise<{ findingsCount: number }> {
  const assetIds = assetConfigs.map(c => c.assetId);
  const assets = await db.select().from(assetsTable).where(
    and(eq(assetsTable.tenantId, tenantId), inArray(assetsTable.id, assetIds))
  );

  const results: Array<typeof scanAssetResultsTable.$inferInsert> = [];
  const findingInserts: Array<typeof findingsTable.$inferInsert> = [];

  for (const config of assetConfigs) {
    const asset = assets.find(a => a.id === config.assetId);
    if (!asset) continue;

    const toolsForAsset = config.toolIds.length > 0
      ? allTools.filter(t => config.toolIds.includes(t.id))
      : enabledTools;

    const ports = simulatePorts(asset.value, "naabu");

    for (const tool of toolsForAsset) {
      const cat = tool.category ?? "recon";
      let toolPorts = null, subdomains = null, endpoints = null, httpInfo = null,
        dnsRecords = null, intelligence = null, vulnerabilities = null;

      if (cat === "port_scan") { toolPorts = simulatePorts(asset.value, tool.name); }
      else if (cat === "web_recon") { httpInfo = simulateHttpInfo(asset.value); endpoints = simulateEndpoints(asset.value); }
      else if (cat === "recon") { subdomains = simulateSubdomains(asset.value); dnsRecords = simulateDnsRecords(asset.value); }
      else if (cat === "vuln_scan") {
        vulnerabilities = simulateVulnerabilities(asset.value, ports);
        for (const v of vulnerabilities) {
          findingInserts.push({
            tenantId, assetId: asset.id, scanId,
            title: v.title, cve: v.cve,
            severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
            cvssScore: String(v.cvss), cwe: v.cwe, status: "open",
            description: `${v.title} (${v.cve}) — CVSS ${v.cvss}`,
            remediation: v.remediation,
          });
        }
      } else if (cat === "osint") { intelligence = simulateIntelligence(asset.value); }
      else if (cat === "ssl_check") {
        httpInfo = simulateHttpInfo(asset.value);
        intelligence = simulateIntelligence(asset.value).filter(i => i.type === "Certificate");
      } else { subdomains = simulateSubdomains(asset.value); dnsRecords = simulateDnsRecords(asset.value); }

      const rawObj: Record<string, unknown> = {};
      if (toolPorts) rawObj.ports = toolPorts;
      if (subdomains) rawObj.subdomains = subdomains;
      if (endpoints) rawObj.endpoints = endpoints;
      if (httpInfo) rawObj.httpInfo = httpInfo;
      if (dnsRecords) rawObj.dnsRecords = dnsRecords;
      if (intelligence) rawObj.intelligence = intelligence;
      if (vulnerabilities) rawObj.vulnerabilities = vulnerabilities;

      results.push({
        tenantId, scanId, assetId: asset.id,
        toolName: tool.name, toolCategory: cat,
        rawOutput: generateRawOutput(tool.name, asset.value, rawObj),
        ports: toolPorts, subdomains, endpoints, httpInfo, dnsRecords, intelligence, vulnerabilities,
      });
    }
  }

  for (let i = 0; i < results.length; i += 50) await db.insert(scanAssetResultsTable).values(results.slice(i, i + 50));
  for (let i = 0; i < findingInserts.length; i += 50) await db.insert(findingsTable).values(findingInserts.slice(i, i + 50));

  return { findingsCount: findingInserts.length };
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

  const { assetToolConfig, assetIds, name } = parsed.data as any;
  const tenantId = req.user!.tenantId;
  const userId = req.user!.userId;

  // Determine asset configs
  let configs: AssetToolConfigItem[] = [];
  if (assetToolConfig && Array.isArray(assetToolConfig) && assetToolConfig.length > 0) {
    configs = assetToolConfig as AssetToolConfigItem[];
  } else if (assetIds && Array.isArray(assetIds) && assetIds.length > 0) {
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

  const { findingsCount } = await executePipeline(tenantId, scan.id, configs, allTools, enabledTools);

  await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
    .where(eq(scansTable.id, scan.id));

  await logAudit(tenantId, userId as any, "scan.pipeline_run", "scan", scan.id, { assetCount: configs.length, findingsCount });

  res.status(201).json({ scanId: scan.id, status: "completed", assetCount: configs.length, findingsCount });
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
      if (r.ports) { tr.ports = r.ports; allPorts.push(...(r.ports as unknown[])); }
      if (r.subdomains) { tr.subdomains = r.subdomains; allSubdomains.push(...(r.subdomains as unknown[])); }
      if (r.endpoints) { tr.endpoints = r.endpoints; allEndpoints.push(...(r.endpoints as unknown[])); }
      if (r.httpInfo) { tr.httpInfo = r.httpInfo; httpInfo = r.httpInfo; }
      if (r.dnsRecords) { tr.dnsRecords = r.dnsRecords; allDns.push(...(r.dnsRecords as unknown[])); }
      if (r.intelligence) { tr.intelligence = r.intelligence; allIntel.push(...(r.intelligence as unknown[])); }
      if (r.vulnerabilities) { tr.vulnerabilities = r.vulnerabilities; allVulns.push(...(r.vulnerabilities as unknown[])); }
      return tr;
    });

    const dedup = <T extends Record<string, unknown>>(arr: T[], key: string) => {
      const seen = new Set();
      return arr.filter(i => { const k = String(i[key] ?? ""); return seen.has(k) ? false : (seen.add(k), true); });
    };

    const ports = dedup(allPorts as any[], "port");
    const vulns = dedup(allVulns as any[], "cve");
    const critCount = vulns.filter((v: any) => v.severity === "critical").length;
    const highCount = vulns.filter((v: any) => v.severity === "high").length;

    return {
      assetId, assetName: asset?.name ?? String(assetId), assetValue: asset?.value ?? "", assetType: asset?.type ?? "unknown",
      scanStatus: scan.status,
      summary: {
        openPorts: ports.length, vulnerabilities: vulns.length, criticalVulns: critCount, highVulns: highCount,
        subdomains: dedup(allSubdomains as any[], "name").length,
        endpoints: dedup(allEndpoints as any[], "url").length,
        dnsRecords: dedup(allDns as any[], "value").length,
        intelItems: dedup(allIntel as any[], "key").length,
        toolsRun: assetResults.length,
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
  const userId = req.user!.userId;
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
  const tenantId = req.user!.tenantId;
  const schedule = await db.select().from(scanSchedulesTable)
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
  const freq = (updates.frequency as string) ?? existing.frequency;
  const rt = (updates.runTime as string) ?? existing.runTime;
  const dow = (updates.dayOfWeek as number | undefined) ?? existing.dayOfWeek;
  const dom = (updates.dayOfMonth as number | undefined) ?? existing.dayOfMonth;
  updates.nextRunAt = computeNextRunAt(freq, rt, dow, dom);

  const [updated] = await db.update(scanSchedulesTable).set(updates as any)
    .where(eq(scanSchedulesTable.id, scheduleId)).returning();
  res.json(toScheduleResponse(updated));
});

router.delete("/scans/schedules/:scheduleId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const scheduleId = Number(req.params.scheduleId);
  const tenantId = req.user!.tenantId;
  const schedule = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }
  await db.delete(scanSchedulesTable).where(eq(scanSchedulesTable.id, scheduleId));
  res.status(204).send();
});

router.post("/scans/schedules/:scheduleId/run-now", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = RunScheduleNowParams.safeParse({ scheduleId: Number(req.params.scheduleId) });
  if (!parsed.success) { res.status(400).json({ error: "Invalid schedule ID" }); return; }

  const tenantId = req.user!.tenantId;
  const userId = req.user!.userId;
  const { scheduleId } = parsed.data;

  const schedule = await db.select().from(scanSchedulesTable)
    .where(and(eq(scanSchedulesTable.id, scheduleId), eq(scanSchedulesTable.tenantId, tenantId))).then(r => r[0]);
  if (!schedule) { res.status(404).json({ error: "Schedule not found" }); return; }

  const configs = schedule.assetToolConfig as AssetToolConfigItem[];
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

  const { findingsCount } = await executePipeline(tenantId, scan.id, configs, allTools, enabledTools);

  await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
    .where(eq(scansTable.id, scan.id));

  const nextRunAt = computeNextRunAt(schedule.frequency, schedule.runTime, schedule.dayOfWeek, schedule.dayOfMonth);
  await db.update(scanSchedulesTable).set({ lastRunAt: new Date(), lastScanId: scan.id, nextRunAt })
    .where(eq(scanSchedulesTable.id, scheduleId));

  await logAudit(tenantId, userId as any, "schedule.run_now", "scan", scan.id, { scheduleId, findingsCount });
  res.status(201).json({ scanId: scan.id, status: "completed", assetCount: configs.length, findingsCount });
});

export default router;
