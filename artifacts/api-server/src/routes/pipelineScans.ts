import { Router } from "express";
import { exec } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";
import tls from "tls";
import { eq, and, inArray } from "drizzle-orm";
import { db, scansTable, scanAssetResultsTable, assetsTable, findingsTable, securityToolsTable, toolPipelineStepsTable, toolRunsTable, scanSchedulesTable, technologyDetectionsTable, screenshotsTable, discoveryResultsTable } from "@workspace/db";
import { enrichShodanCves, lookupCvesFromCpes, type NvdCve } from "../lib/nvdLookup";
import { detectTechnologies, type DetectedTechnology } from "../lib/techDetector";
import { captureScreenshots, type PageScreenshot } from "../lib/screenshotEngine";
import { runEndpointDiscovery } from "../lib/endpointDiscovery";
import { runJsAnalysis, type JsAnalysisResult } from "../lib/jsAnalyzer";
import { runParamDiscovery, type ParamDiscoveryResult } from "../lib/paramDiscovery";
import { runCloudRecon, type CloudReconResult } from "../lib/cloudRecon";
import { runSecretsHunt, type SecretsHuntResult } from "../lib/secretsHunter";
import {
  runPassiveDiscovery,
  runDkimCheck, runGithubExposure,
  runFofaSearch, runCensysSearch, runIntelxSearch, runCriminalIpSearch,
  type PassiveDiscoveryOptions,
} from "../lib/passiveDiscovery";
import { runDirFuzz, type DirFuzzResult } from "../lib/dirFuzzer";
import { runNucleiScan, type VulnScanResult } from "../lib/nucleiScanner";
import { scanPorts, type PortScanReport } from "../lib/portScanner";
import { scanSubdomains, type SubdomainScanReport } from "../lib/subdomainScanner";
import { RunPipelineScanBody, GetScanAssetReportParams, CreateScanScheduleBody, UpdateScanScheduleBody, UpdateScanScheduleParams, RunScheduleNowParams, StopScanParams } from "@workspace/api-zod";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";
import { BUILTIN_TOOL_DEFS } from "../lib/seedPlatform";
import { logger } from "../lib/logger";
import { triggerBrandThreatScan } from "../lib/brandThreatRunner";
import { finalizeScannedAssets } from "../lib/scanScheduler";
import { enrichFindingsWithEpssKev } from "../lib/epssKev";
import { getPlatformSetting } from "./platformSettings";
import { setNvdApiKey } from "../lib/nvdLookup";
import { getVirusTotalDomain } from "../lib/virusTotal";
import { hunterDomainSearch } from "../lib/hunterOsint";
import { dispatchMultiTenantNotifications } from "../lib/notifier";

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

// ── Scan execution queue ───────────────────────────────────────────────────────
// MAX_CONCURRENT_SCANS: max number of scans running simultaneously across all tenants.
// MAX_PARALLEL_ASSETS:  max number of assets scanned in parallel within a single scan.
// Raise these only if the host has enough CPU/RAM — each asset spawns multiple child processes.
const MAX_CONCURRENT_SCANS = 5;
const MAX_PARALLEL_ASSETS   = 3;

interface QueueEntry {
  scanId: number;
  tenantId: number;
  userId: number;
  configs: AssetToolConfigItem[];
  allTools: (typeof securityToolsTable.$inferSelect)[];
  enabledTools: (typeof securityToolsTable.$inferSelect)[];
  scheduleId?: number;
  resolve: () => void;
}

const scanQueue: QueueEntry[] = [];
let activeScans = 0;

function queuePosition(scanId: number): number {
  const idx = scanQueue.findIndex(e => e.scanId === scanId);
  return idx === -1 ? 0 : idx + 1;
}

function drainQueue() {
  while (activeScans < MAX_CONCURRENT_SCANS && scanQueue.length > 0) {
    const entry = scanQueue.shift()!;
    activeScans++;
    logger.info({ scanId: entry.scanId, activeScans, remaining: scanQueue.length }, "Scan dequeued — starting");
    db.update(scansTable)
      .set({ status: "running", startedAt: new Date() })
      .where(eq(scansTable.id, entry.scanId))
      .catch(err => logger.error({ err, scanId: entry.scanId }, "Failed to mark scan running"));
    entry.resolve();
  }
}

async function enqueueAndRun(entry: Omit<QueueEntry, "resolve">): Promise<void> {
  return new Promise<void>(resolve => {
    scanQueue.push({ ...entry, resolve });
    logger.info({ scanId: entry.scanId, queueLength: scanQueue.length }, "Scan queued");
    drainQueue();
  }).then(async () => {
    try {
      const { findingsCount } = await executePipeline(
        entry.tenantId, entry.scanId, entry.configs, entry.allTools, entry.enabledTools,
      );
      const current = await db.select({ status: scansTable.status }).from(scansTable)
        .where(eq(scansTable.id, entry.scanId)).then(r => r[0]);
      if (current?.status !== "cancelled") {
        await db.update(scansTable).set({ status: "completed", completedAt: new Date(), findingsCount })
          .where(eq(scansTable.id, entry.scanId));
      }
      if (entry.scheduleId) {
        await db.update(scanSchedulesTable).set({ lastRunAt: new Date(), lastScanId: entry.scanId })
          .where(eq(scanSchedulesTable.id, entry.scheduleId));
      }
      await logAudit(entry.tenantId, entry.userId as any, "scan.pipeline_run", "scan", entry.scanId, {
        assetCount: entry.configs.length, findingsCount,
      });
      logger.info({ scanId: entry.scanId, findingsCount }, "Scan completed");

      // Recompute risk scores and lastScannedAt for all scanned assets (includes businessImpact)
      const pipelineAssetIds = entry.configs.map(c => c.assetId);
      finalizeScannedAssets(pipelineAssetIds).catch(err =>
        logger.warn({ err, scanId: entry.scanId }, "finalizeScannedAssets failed"),
      );

      // ── Auto-trigger brand threat scan for every domain asset ───────────────
      setImmediate(async () => {
        try {
          const assetIds = entry.configs.map(c => c.assetId);
          const assetRows = await db.select({ value: assetsTable.value })
            .from(assetsTable)
            .where(inArray(assetsTable.id, assetIds));
          const uniqueDomains = [...new Set(
            assetRows
              .map(a => extractDomain(a.value))
              .filter(d => d.length > 0 && !isIp(d) && isValidHostname(d)),
          )];
          for (const domain of uniqueDomains) {
            await triggerBrandThreatScan(entry.tenantId, domain, entry.scanId);
          }
        } catch (err) {
          logger.error({ err, scanId: entry.scanId }, "Failed to auto-trigger brand threat scan");
        }
      });

      // ── Dispatch Slack / Discord / email notifications ────────────────────────
      setImmediate(async () => {
        try {
          const pipelineAssetIdsForNotif = entry.configs.map(c => c.assetId);
          const [critRows, highRows, assetTenantRows] = await Promise.all([
            db.select({ id: findingsTable.id }).from(findingsTable)
              .where(and(eq(findingsTable.scanId, entry.scanId), eq(findingsTable.severity, "critical"))),
            db.select({ id: findingsTable.id }).from(findingsTable)
              .where(and(eq(findingsTable.scanId, entry.scanId), eq(findingsTable.severity, "high"))),
            db.select({ tenantId: assetsTable.tenantId }).from(assetsTable)
              .where(inArray(assetsTable.id, pipelineAssetIdsForNotif)),
          ]);
          const criticalCount = critRows.length;
          const highCount = highRows.length;
          const severity = criticalCount > 0 ? "critical" : highCount > 0 ? "high" : "medium";

          // Collect all unique tenant IDs that own assets in this scan — so
          // AM-triggered scans fire rules for client tenants, not just tenant 5.
          const tenantIdsToNotify = new Set<number>([entry.tenantId]);
          for (const row of assetTenantRows) tenantIdsToNotify.add(row.tenantId);

          // dispatchMultiTenantNotifications fires tenant rules for each tenant
          // and platform-level fallbacks exactly ONCE — no duplicates.
          await dispatchMultiTenantNotifications([...tenantIdsToNotify], {
            eventType: criticalCount > 0 ? "critical_finding" : highCount > 0 ? "high_finding" : "scan_complete",
            title: `Scan Complete — ${findingsCount} finding${findingsCount !== 1 ? "s" : ""} detected`,
            message: `Pipeline scan #${entry.scanId} completed across ${entry.configs.length} asset${entry.configs.length !== 1 ? "s" : ""}. ${criticalCount} critical, ${highCount} high severity findings.`,
            severity,
            scanId: entry.scanId,
            findingsCount,
            criticalCount,
            highCount,
          });
        } catch (err) {
          logger.warn({ err, scanId: entry.scanId }, "Notification dispatch failed (non-fatal)");
        }
      });
    } catch (err) {
      logger.error({ err, scanId: entry.scanId }, "Pipeline scan execution failed");
      await db.update(scansTable).set({ status: "failed", completedAt: new Date() })
        .where(eq(scansTable.id, entry.scanId)).catch(() => {});
    } finally {
      activeScans--;
      scanProgressMap.delete(entry.scanId);
      drainQueue();
    }
  });
}

// ── On startup: recover any scans stuck as "running" from a previous crash ────
setImmediate(async () => {
  try {
    const stuckScans = await db.select().from(scansTable)
      .where(eq(scansTable.status, "running" as string));
    if (stuckScans.length > 0) {
      logger.warn({ count: stuckScans.length }, "Recovering scans stuck in running state from crash");
      for (const scan of stuckScans) {
        await db.update(scansTable)
          .set({ status: "failed", completedAt: new Date() })
          .where(eq(scansTable.id, scan.id));
      }
    }
  } catch (err) {
    logger.error({ err }, "Failed to recover stuck scans on startup");
  }
});

// Tool → pentesting phase mapping
const TOOL_PHASE: Record<string, number> = {
  subfinder: 1, dnsx: 1, shuffledns: 1, amass: 1, mapcidr: 1, tldfinder: 1,
  gau: 1, asnmap: 1, cdncheck: 1, uncover: 1, cloud_enum: 1, s3scanner: 1,
  theHarvester: 1, aix: 1, maltego: 1, dnstwist: 1,
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

// CVE_POOL removed — CVEs are now sourced from real APIs:
//   1. Shodan InternetDB  — CVE IDs per IP, enriched with NVD metadata
//   2. NVD CPE lookup     — per service CPE string → authoritative CVEs
//   3. Nuclei scanner     — active template-based detection with real CVE IDs

// ── Type interfaces ─────────────────────────────────────────────────────────────
interface PortFinding      { port: number; service: string; version: string; protocol: string; state: string; }
interface SubdomainFinding { name: string; ip: string; cname: string | null; status: string; cdnProvider: string | null; sources?: string[]; httpStatus?: number | null; httpTitle?: string | null; redirectTo?: string | null; webServer?: string | null; }
interface EndpointFinding  { url: string; method: string; status: number; title?: string; category?: string; source?: string; }
interface CookieFlag       { name: string; secure: boolean; httpOnly: boolean; sameSite: string; raw: string; }
interface HostFingerprint  { host: string; techs: string[]; waf?: string; }
interface WafDetection     { name: string; method: string; confidence: "high" | "medium" | "low"; }
interface OriginIpCandidate { ip: string; method: string; confidence: "high" | "medium" | "low"; reverseDns?: string; org?: string; openPorts?: number[]; }
interface HttpInfo         { url: string; status: number; title: string; server: string; contentLength: number; tech: string[]; waf: string; cdn: string | null; headers: Record<string, string>; cookieFlags?: CookieFlag[]; hostFingerprints?: HostFingerprint[]; wafDetails?: WafDetection; originIps?: OriginIpCandidate[]; }
interface DnsRecord        { type: string; value: string; ttl: number; priority?: number; weight?: number; port?: number; target?: string; notes?: string; }
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

/** Strict hostname validation — only allow RFC-1123 labels; no shell metacharacters. */
function isValidHostname(s: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,63}$/i.test(s);
}

function maskSecret(s: string): string {
  if (s.length <= 8) return "***";
  return s.slice(0, 6) + "••••••••" + s.slice(-4);
}

// ── Phase 1: DNS + Subdomain Recon ─────────────────────────────────────────────

function parseSpfPolicy(spf: string): string {
  const parts = spf.split(/\s+/);
  const includes = parts.filter(p => p.startsWith("include:")).map(p => p.replace("include:", ""));
  const redirectTo = parts.find(p => p.startsWith("redirect="))?.replace("redirect=", "");
  const allMech = parts.find(p => /^[~?+\-]?all$/.test(p));
  const allDesc =
    allMech === "-all" ? "❌ Reject (hard fail)" :
    allMech === "~all" ? "⚠️ Soft fail (mark as spam)" :
    allMech === "?all" ? "❓ Neutral" :
    allMech === "+all" ? "🚨 Pass all — dangerous!" :
    "⚠️ No all policy";
  const parts2: string[] = [`Policy: ${allDesc}`];
  if (includes.length) parts2.push(`Includes: ${includes.join(", ")}`);
  if (redirectTo) parts2.push(`Redirect: ${redirectTo}`);
  const ipMechs = parts.filter(p => p.startsWith("ip4:") || p.startsWith("ip6:"));
  if (ipMechs.length) parts2.push(`Authorized IPs: ${ipMechs.join(", ")}`);
  return parts2.join(" | ");
}

function parseDmarcPolicy(dmarc: string): string {
  const get = (k: string) => dmarc.match(new RegExp(`${k}=([^;\\s]+)`))?.[1] ?? null;
  const p    = get("p")    ?? "none";
  const sp   = get("sp");
  const adkim = get("adkim") === "s" ? "strict" : "relaxed";
  const aspf  = get("aspf")  === "s" ? "strict" : "relaxed";
  const pct   = get("pct")  ?? "100";
  const rua   = get("rua");
  const ruf   = get("ruf");
  const policyIcon = p === "reject" ? "✅" : p === "quarantine" ? "⚠️" : "❌";
  const parts: string[] = [`${policyIcon} Policy: ${p}`];
  if (sp) parts.push(`Subdomain: ${sp}`);
  parts.push(`DKIM align: ${adkim}`, `SPF align: ${aspf}`, `Coverage: ${pct}%`);
  if (rua) parts.push(`Aggregate reports: ${rua}`);
  if (ruf) parts.push(`Forensic reports: ${ruf}`);
  return parts.join(" | ");
}

// Common SRV service prefixes to probe
const SRV_PREFIXES = [
  "_http._tcp", "_https._tcp",
  "_sip._tcp", "_sip._udp", "_sips._tcp",
  "_ldap._tcp", "_kerberos._tcp", "_kerberos._udp",
  "_xmpp-client._tcp", "_xmpp-server._tcp",
  "_smtp._tcp", "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
  "_autodiscover._tcp", "_ftp._tcp",
  "_caldav._tcp", "_caldavs._tcp", "_carddav._tcp", "_carddavs._tcp",
  "_minecraft._tcp", "_teamspeak._tcp",
];

async function runDnsRecon(target: string): Promise<{ subdomains: SubdomainFinding[]; dnsRecords: DnsRecord[] }> {
  const domain = extractDomain(target);
  if (!domain || isIp(domain)) return { subdomains: [], dnsRecords: [] };

  const dnsRecords: DnsRecord[] = [];
  const subdomains: SubdomainFinding[] = [];

  // All standard + special lookups fire in parallel
  const [a, aaaa, mx, ns, txt, soa, cname, dmarcTxt, mtaSts, bimi, srvBatch] = await Promise.allSettled([
    dns.resolve4(domain, { ttl: true }),
    dns.resolve6(domain, { ttl: true }),
    dns.resolveMx(domain),
    dns.resolveNs(domain),
    dns.resolveTxt(domain),
    dns.resolveSoa(domain),
    dns.resolveCname(domain).catch(() => [] as string[]),
    // DMARC lives at _dmarc.domain — always query explicitly
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => [] as string[][]),
    // MTA-STS policy indicator
    dns.resolveTxt(`_mta-sts.${domain}`).catch(() => [] as string[][]),
    // BIMI (Brand Indicators for Message Identification)
    dns.resolveTxt(`default._bimi.${domain}`).catch(() => [] as string[][]),
    // All SRV prefixes in one batch
    Promise.allSettled(
      SRV_PREFIXES.map(async (svc) => {
        const records = await dns.resolveSrv(`${svc}.${domain}`);
        return { svc, records };
      })
    ),
  ]);

  // A records — collect IPs for PTR lookups
  const resolvedIps: string[] = [];
  if (a.status === "fulfilled") {
    for (const r of a.value) {
      dnsRecords.push({ type: "A", value: r.address, ttl: r.ttl });
      resolvedIps.push(r.address);
    }
  }

  if (aaaa.status === "fulfilled") {
    for (const r of aaaa.value) {
      dnsRecords.push({ type: "AAAA", value: r.address, ttl: r.ttl });
      resolvedIps.push(r.address);
    }
  }

  if (mx.status === "fulfilled")
    for (const r of mx.value) dnsRecords.push({ type: "MX", value: r.exchange, ttl: 300, priority: r.priority });

  if (ns.status === "fulfilled")
    for (const r of ns.value) dnsRecords.push({ type: "NS", value: r, ttl: 3600 });

  // TXT records — annotate SPF records with policy analysis
  if (txt.status === "fulfilled") {
    for (const r of txt.value) {
      const joined = r.join(" ");
      const notes = joined.startsWith("v=spf1") ? parseSpfPolicy(joined) : undefined;
      dnsRecords.push({ type: "TXT", value: joined, ttl: 300, notes });
    }
  }

  if (soa.status === "fulfilled")
    dnsRecords.push({ type: "SOA", value: `${soa.value.nsname} ${soa.value.hostmaster} (serial: ${soa.value.serial}, refresh: ${soa.value.refresh}s, expire: ${soa.value.expire}s)`, ttl: soa.value.minttl });

  if (cname.status === "fulfilled" && Array.isArray(cname.value))
    for (const r of cname.value) dnsRecords.push({ type: "CNAME", value: r, ttl: 300 });

  // DMARC — explicit type with parsed analysis
  if (dmarcTxt.status === "fulfilled") {
    for (const r of dmarcTxt.value) {
      const joined = r.join(" ");
      if (joined.startsWith("v=DMARC1")) {
        dnsRecords.push({ type: "DMARC", value: joined, ttl: 300, notes: parseDmarcPolicy(joined) });
      }
    }
  }
  // If no DMARC found, add an absent record as a warning
  const hasDmarc = dnsRecords.some(r => r.type === "DMARC");
  if (!hasDmarc) {
    dnsRecords.push({ type: "DMARC", value: "(not configured)", ttl: 0, notes: "❌ No DMARC record — domain is vulnerable to email spoofing" });
  }

  // Check if SPF exists in TXT
  const hasSpf = dnsRecords.some(r => r.type === "TXT" && r.value.startsWith("v=spf1"));
  if (!hasSpf) {
    dnsRecords.push({ type: "TXT", value: "(no SPF record)", ttl: 0, notes: "❌ No SPF record found — anyone can send email claiming to be from this domain" });
  }

  // MTA-STS
  if (mtaSts.status === "fulfilled") {
    for (const r of mtaSts.value) {
      const joined = r.join(" ");
      if (joined) dnsRecords.push({ type: "MTA-STS", value: joined, ttl: 300, notes: "MTA-STS policy indicator — enforces TLS for email delivery" });
    }
  }

  // BIMI
  if (bimi.status === "fulfilled") {
    for (const r of bimi.value) {
      const joined = r.join(" ");
      if (joined) dnsRecords.push({ type: "BIMI", value: joined, ttl: 300, notes: "Brand Indicators for Message Identification — displays logo in email clients" });
    }
  }

  // SRV records
  if (srvBatch.status === "fulfilled") {
    for (const result of srvBatch.value) {
      if (result.status === "fulfilled" && result.value.records.length > 0) {
        const { svc, records } = result.value;
        for (const r of records) {
          dnsRecords.push({
            type: "SRV",
            value: `${svc}.${domain}`,
            ttl: 300,
            priority: r.priority,
            weight: r.weight,
            port: r.port,
            target: r.name,
          });
        }
      }
    }
  }

  // PTR (Reverse DNS) — resolve each A/AAAA IP
  await Promise.allSettled(
    resolvedIps.slice(0, 10).map(async (ip) => {
      try {
        const hostnames = await dns.reverse(ip);
        if (hostnames.length > 0) {
          dnsRecords.push({ type: "PTR", value: ip, ttl: 300, target: hostnames[0], notes: `Reverse DNS: ${ip} → ${hostnames[0]}` });
        }
      } catch {}
    })
  );

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
  let ip = isIp(domain) ? domain : "";
  if (!ip) { try { const ips = await dns.resolve4(domain); ip = ips[0] ?? ""; } catch {} }
  if (!ip) return [];

  const intel: IntelItem[] = [];
  intel.push({ type: "GeoIP", key: "IP Address", value: ip });

  // Source 1: ip-api.com — full geo + ASN + hosting/proxy flags
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,org,as,hosting,proxy,isp,lon,lat`, { signal: ctrl.signal });
    if (res.ok) {
      const d: any = await res.json();
      if (d.status === "success") {
        if (d.country)    intel.push({ type: "GeoIP",   key: "Country",      value: `${d.country}${d.countryCode ? ` (${d.countryCode})` : ""}` });
        if (d.regionName) intel.push({ type: "GeoIP",   key: "Region",       value: d.regionName });
        if (d.city)       intel.push({ type: "GeoIP",   key: "City",         value: d.city });
        if (d.lat && d.lon) intel.push({ type: "GeoIP", key: "Coordinates",  value: `${d.lat}, ${d.lon}` });
        if (d.as)         intel.push({ type: "ASN",     key: "AS Number",    value: d.as });
        if (d.org)        intel.push({ type: "ASN",     key: "Organization", value: d.org });
        if (d.isp)        intel.push({ type: "ASN",     key: "ISP",          value: d.isp });
        intel.push({ type: "Hosting", key: "IP Type", value: d.hosting ? "Datacenter / Hosting IP" : "Residential / ISP IP" });
        if (d.proxy)      intel.push({ type: "Risk",    key: "Proxy / VPN",  value: d.proxy ? "YES — traffic behind proxy/VPN" : "No proxy detected" });
      }
    }
  } catch {}

  // Source 2: ipinfo.io — reverse hostname + additional org/ASN confirmation
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 6000);
    const res = await fetch(`https://ipinfo.io/${ip}/json`, {
      signal: ctrl.signal,
      headers: { "Accept": "application/json", "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    });
    if (res.ok) {
      const d: any = await res.json();
      if (d.hostname) intel.push({ type: "Network", key: "Reverse Hostname", value: d.hostname });
      if (d.org && !intel.some(i => i.key === "Organization")) intel.push({ type: "ASN", key: "Organization", value: d.org });
    }
  } catch {}

  // Source 3: ARIN RDAP (follows redirects to RIPE/APNIC/etc for non-ARIN IPs)
  // Returns network name, handle, and IP range (start–end + CIDR prefix)
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 8000);
    const rdapRes = await fetch(`https://rdap.arin.net/registry/ip/${ip}`, {
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "Accept": "application/rdap+json", "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    });
    if (rdapRes.ok) {
      const d: any = await rdapRes.json();
      if (d.name)   intel.push({ type: "Network", key: "Network Name",   value: d.name });
      if (d.handle) intel.push({ type: "Network", key: "Network Handle", value: d.handle });
      if (d.startAddress && d.endAddress)
        intel.push({ type: "Network", key: "IP Range", value: `${d.startAddress} – ${d.endAddress}` });
      const cidr = d.cidr0_cidrs?.[0];
      if (cidr?.v4prefix)
        intel.push({ type: "Network", key: "IP CIDR Prefix", value: `${cidr.v4prefix}/${cidr.length}` });
      // Extract ASN from linked entity if present
      for (const entity of d.entities ?? []) {
        if (entity.roles?.includes("registration") && entity.handle?.startsWith("AS")) {
          intel.push({ type: "ASN", key: "ARIN ASN Handle", value: entity.handle });
        }
      }
    }
  } catch {}

  return intel;
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

// ── WAF Detection (header + body fingerprinting, 30+ WAFs) ────────────────────

function detectWafFromHeaders(headers: Record<string, string>, server: string, body: string): WafDetection | null {
  const h = headers;
  const s = (server ?? "").toLowerCase();
  const b = (body ?? "").toLowerCase();

  // High-confidence header signatures
  if (h["cf-ray"] || /cloudflare/i.test(s))             return { name: "Cloudflare", method: "cf-ray / server header", confidence: "high" };
  if (h["x-iinfo"] || h["x-iinfo-ns"] || h["x-cdn"] === "Incapsula") return { name: "Imperva Incapsula", method: "x-iinfo header", confidence: "high" };
  if (h["x-amz-cf-id"] || h["x-amz-rid"])               return { name: "AWS WAF / CloudFront", method: "x-amz-cf-id header", confidence: "high" };
  if (h["x-sucuri-id"] || h["x-sucuri-cache"])           return { name: "Sucuri", method: "x-sucuri header", confidence: "high" };
  if (h["x-fw-hash"])                                     return { name: "Wordfence", method: "x-fw-hash header", confidence: "high" };
  if (s.includes("ddos-guard"))                           return { name: "DDoS-Guard", method: "server header", confidence: "high" };
  if (h["x-reblaze-protection"] || h["x-rb-waf"])       return { name: "Reblaze", method: "x-reblaze-protection header", confidence: "high" };
  if (h["x-datadome-request-id"] || h["x-dd-b"])        return { name: "DataDome", method: "x-datadome header", confidence: "high" };
  if (h["x-px-authorization"] || h["x-px-original-token"]) return { name: "PerimeterX", method: "x-px header", confidence: "high" };
  if (h["x-protected-by"]?.toLowerCase().includes("barracuda")) return { name: "Barracuda WAF", method: "x-protected-by header", confidence: "high" };
  if (s.includes("bigip") || s.includes("f5 asm") || h["x-wa-info"]) return { name: "F5 BIG-IP ASM", method: "server / x-wa-info header", confidence: "high" };
  if (h["x-waf-event-info"] || h["x-blocks"])           return { name: "IBM DataPower Gateway", method: "x-waf-event-info header", confidence: "high" };
  if (h["x-malicious-content-protection"])               return { name: "Fortinet FortiWeb", method: "x-malicious-content-protection header", confidence: "high" };
  if (s.includes("netscaler") || h["ns-server"])         return { name: "Citrix NetScaler AppFW", method: "server header", confidence: "high" };
  if (h["x-avi-waf-status"])                             return { name: "Avi Networks WAF", method: "x-avi-waf-status header", confidence: "high" };
  if (h["x-akamai-transformed"] || /akamai/i.test(s))   return { name: "Akamai Kona Site Defender", method: "x-akamai-transformed header", confidence: "high" };
  if (h["x-azure-ref"])                                  return { name: "Azure Front Door WAF", method: "x-azure-ref header", confidence: "high" };
  if (h["x-kong-proxy-latency"] || h["x-kong-upstream-latency"]) return { name: "Kong Gateway", method: "x-kong header", confidence: "high" };
  if (h["x-waf"] || h["x-waf-score"])                   return { name: "Generic WAF", method: "x-waf header", confidence: "medium" };
  if (h["x-wr-diag"])                                    return { name: "WebARX WAF", method: "x-wr-diag header", confidence: "high" };
  if (h["x-powered-by"]?.toLowerCase().includes("neustar")) return { name: "Neustar SiteProtect", method: "x-powered-by header", confidence: "high" };
  if (h["x-envoy-upstream-service-time"])                return { name: "Envoy Proxy", method: "x-envoy header", confidence: "medium" };
  if (h["x-mod-pagespeed"] && (s.includes("apache") || s.includes("nginx"))) return { name: "ModSecurity", method: "header pattern", confidence: "medium" };
  if (s.includes("litespeed") || h["x-litespeed-cache"]) return { name: "LiteSpeed WAF", method: "server / cache header", confidence: "medium" };
  if (h["x-shield"])                                     return { name: "Shield WAF", method: "x-shield header", confidence: "medium" };
  if (h["server"]?.includes("ARR") && h["x-powered-by"]?.includes("ASP.NET")) return { name: "Microsoft Azure WAF / ARR", method: "ARR server header", confidence: "medium" };
  if (h["via"]?.includes("1.1 varnish"))                 return { name: "Fastly WAF", method: "via header", confidence: "medium" };

  // Cookie-based fingerprints
  const cookies = (h["set-cookie"] ?? "");
  if (cookies.includes("__cf_bm") || cookies.includes("__cfduid")) return { name: "Cloudflare", method: "cf cookie fingerprint", confidence: "medium" };
  if (cookies.includes("_px3") || cookies.includes("_pxhd"))        return { name: "PerimeterX", method: "px cookie fingerprint", confidence: "medium" };
  if (cookies.includes("datadome"))                                   return { name: "DataDome", method: "cookie fingerprint", confidence: "medium" };

  // Block-page body signatures
  if (b.includes("__cf_chl") || b.includes("cf-challenge") || b.includes("just a moment") || b.includes("checking your browser"))
    return { name: "Cloudflare", method: "JS challenge page", confidence: "high" };
  if (b.includes("sucuri_cloudproxy") || b.includes("sucuri website firewall"))
    return { name: "Sucuri", method: "block page", confidence: "high" };
  if (b.includes("incapsula incident id") || b.includes("_incapsula_resource"))
    return { name: "Imperva Incapsula", method: "block page", confidence: "high" };
  if (b.includes("perimeterx") || b.includes("_pxid="))
    return { name: "PerimeterX", method: "block page", confidence: "high" };
  if (b.includes("datadome") && b.includes("blocked"))
    return { name: "DataDome", method: "block page", confidence: "high" };
  if (b.includes("barracuda networks"))
    return { name: "Barracuda WAF", method: "block page", confidence: "high" };
  if (b.includes("mod_security") && (b.includes("request rejected") || b.includes("not acceptable")))
    return { name: "ModSecurity", method: "block page", confidence: "high" };
  if (b.includes("fortiweb") || b.includes("fortigate") || b.includes("web application firewall violation"))
    return { name: "Fortinet FortiWeb", method: "block page", confidence: "high" };
  if (b.includes("webknight") || b.includes("aqtronix webknight"))
    return { name: "WebKnight WAF", method: "block page", confidence: "high" };

  return null;
}

// ── Active WAF Probe (Node-native, equivalent to wafw00f) ─────────────────────
// Sends payloads with common WAF triggers and analyzes the 40x/50x response.
async function runActiveWafProbe(target: string): Promise<WafDetection | null> {
  const baseUrl = target.startsWith("http") ? target : `https://${target}`;
  const triggerPath = `/?s=<script>alert(1)</script>&id=1+OR+1=1--&etc=/etc/passwd`;
  try {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 14000);
    const resp = await fetch(`${baseUrl}${triggerPath}`, {
      signal: ctrl.signal,
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
      redirect: "follow",
    });
    clearTimeout(tid);
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });
    const body = await resp.text().catch(() => "");
    const server = headers["server"] ?? "";

    // WAF typically returns 403 / 406 / 429 / 503 for malicious payloads
    const detected = detectWafFromHeaders(headers, server, body);
    if (detected) return { ...detected, method: `${detected.method} (active probe, ${resp.status})` };

    if ([403, 406, 429, 503].includes(resp.status)) {
      const b = body.toLowerCase();
      if (b.includes("blocked") || b.includes("firewall") || b.includes("security") || b.includes("denied") || b.includes("forbidden"))
        return { name: "Unknown WAF", method: `active probe — ${resp.status} block response`, confidence: "low" };
    }
  } catch {}
  return null;
}

// ── CDN / WAF org filter for origin IP discovery ───────────────────────────────
const CDN_ORG_KEYWORDS = ["cloudflare", "akamai", "fastly", "amazon", "cloudfront", "incapsula",
  "sucuri", "azure", "microsoft", "google cloud", "ddos-guard", "stackpath", "cdn", "imperva"];

function isCdnOrg(text: string): boolean {
  const t = text.toLowerCase();
  return CDN_ORG_KEYWORDS.some(k => t.includes(k));
}

async function shodanIpEnrich(ip: string): Promise<{ ports: number[]; org: string; reverseDns: string; tags: string[] } | null> {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return null;
    const d = await r.json() as any;
    return { ports: d.ports ?? [], org: (d.hostnames ?? []).join(", "), reverseDns: (d.hostnames ?? [])[0] ?? "", tags: d.tags ?? [] };
  } catch { return null; }
}

// Lightweight WAF header check for subdomain probing (HEAD request, 5s timeout)
async function quickWafCheck(host: string): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 5000);
    const resp = await fetch(`https://${host}`, { signal: ctrl.signal, method: "HEAD", redirect: "follow" });
    clearTimeout(tid);
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headers[k] = v; });
    return detectWafFromHeaders(headers, headers["server"] ?? "", "")?.name ?? null;
  } catch { return null; }
}

async function discoverOriginIps(domain: string, dnsRecords: DnsRecord[], subdomains: SubdomainFinding[]): Promise<OriginIpCandidate[]> {
  const candidates: OriginIpCandidate[] = [];
  const seen = new Set<string>();
  const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

  const addCandidate = async (ip: string, method: string) => {
    if (!ip || seen.has(ip) || !IP_RE.test(ip)) return;
    seen.add(ip);
    const info = await shodanIpEnrich(ip);
    // Filter out IPs that belong to CDN/WAF infrastructure
    const orgInfo = `${info?.org ?? ""} ${(info?.tags ?? []).join(" ")}`;
    if (isCdnOrg(orgInfo)) return;
    candidates.push({
      ip, method,
      confidence: "medium",
      reverseDns: info?.reverseDns,
      org: info?.org,
      openPorts: info?.ports,
    });
  };

  // Method 1: SPF record ip4: directives (servers sending mail = real origin IPs)
  for (const r of dnsRecords) {
    if (r.type === "TXT" && r.value.includes("v=spf1")) {
      for (const m of r.value.matchAll(/ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g))
        await addCandidate(m[1], "SPF record ip4 directive");
    }
  }

  // Method 2: Active non-CDN subdomain IPs from Phase 1 DNS recon
  for (const sub of subdomains.filter(s => s.status === "active" && s.ip))
    await addCandidate(sub.ip!, `DNS — ${sub.name}`);

  // Method 3: HackerTarget historical host search (free, no API key)
  try {
    const resp = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { signal: AbortSignal.timeout(10000) });
    const text = await resp.text();
    if (!text.startsWith("error") && !text.startsWith("API count") && !text.startsWith("<?")) {
      for (const line of text.trim().split("\n")) {
        const parts = line.split(",");
        if (parts.length >= 2) await addCandidate(parts[1].trim(), "DNS history — hackertarget.com");
      }
    }
  } catch {}

  // Method 4: Confirm origin by direct IP bypass (Host header spoofing)
  for (const c of candidates.slice(0, 5)) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), 5000);
      const resp = await fetch(`https://${c.ip}`, {
        signal: ctrl.signal,
        headers: { "Host": domain },
        redirect: "manual",
      });
      clearTimeout(tid);
      if (resp.status > 0 && resp.status < 500) {
        c.confidence = "high";
        c.method += " — bypass confirmed";
      }
    } catch {}
  }

  // Method 5: SecurityTrails (if API key configured — optional)
  const stKey = process.env["SECURITYTRAILS_API_KEY"];
  if (stKey) {
    try {
      const resp = await fetch(`https://api.securitytrails.com/v1/history/${domain}/dns/a`, {
        signal: AbortSignal.timeout(8000),
        headers: { apikey: stKey, Accept: "application/json" },
      });
      if (resp.ok) {
        const data = await resp.json() as any;
        for (const rec of (data.records ?? []))
          for (const v of (rec.values ?? []))
            if (v.ip) await addCandidate(v.ip, "SecurityTrails DNS history");
      }
    } catch {}
  }

  return candidates.slice(0, 12);
}

// ── Phase 3: Web Recon ─────────────────────────────────────────────────────────

function parseCookieFlags(setCookieList: string[]): CookieFlag[] {
  return setCookieList.filter(Boolean).map(raw => ({
    name: (raw.split(";")[0] ?? "").split("=")[0]?.trim() ?? "unknown",
    secure:   /;\s*secure\b/i.test(raw),
    httpOnly: /;\s*httponly\b/i.test(raw),
    sameSite: (/;\s*samesite\s*=\s*(\w+)/i.exec(raw)?.[1] ?? "").trim(),
    raw,
  }));
}

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
      // getSetCookie() handles multiple Set-Cookie headers correctly (Node 18+ undici)
      const setCookieList: string[] = typeof (response.headers as any).getSetCookie === "function"
        ? (response.headers as any).getSetCookie() as string[]
        : (headers["set-cookie"] ? [headers["set-cookie"]] : []);
      const cookieFlags = parseCookieFlags(setCookieList);
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

      const wafDet = detectWafFromHeaders(headers, server, body);
      const wafDetails: WafDetection | undefined = wafDet ?? undefined;
      const waf = wafDet?.name ?? "none";

      let cdn: string | null = null;
      if (headers["cf-ray"])                                     cdn = "Cloudflare";
      else if (headers["x-amz-cf-id"])                          cdn = "AWS CloudFront";
      else if (headers["x-cache"]?.includes("cloudfront"))      cdn = "AWS CloudFront";
      else if (headers["x-fastly-request-id"])                  cdn = "Fastly";
      else if (/akamai/i.test(headers["server"] ?? ""))          cdn = "Akamai";
      else if (headers["x-azure-ref"])                           cdn = "Azure CDN";

      return { url: response.url ?? url, status: response.status, title, server, contentLength: body.length, tech: [...new Set(tech)], waf, cdn, headers, cookieFlags: cookieFlags.length > 0 ? cookieFlags : undefined, wafDetails };
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
          const severityToCvss: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 3.0, info: 1.0 };
          findings.push({
            cve: `SEC-${pat.name.replace(/\s+/g, "-").toUpperCase().slice(0, 20)}`,
            cvss: severityToCvss[pat.severity] ?? 5.0,
            severity: pat.severity,
            title: `${pat.name} exposed in ${path}`,
            cwe: pat.cwe,
            remediation: pat.remediation,
            source: `Credential discovered at ${path}: ${raw}`,
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

  // ── Cookie security flag analysis ────────────────────────────────────────────
  const cookies = httpInfo.cookieFlags ?? [];
  if (cookies.length > 0) {
    const insecure  = cookies.filter(c => !c.secure);
    const noHO      = cookies.filter(c => !c.httpOnly);
    const noSS      = cookies.filter(c => !c.sameSite);
    if (insecure.length > 0)
      vulns.push({ cve: "COOKIE-SECURE", cvss: 5.3, severity: "medium",
        title: `${insecure.length} Cookie(s) Missing Secure Flag`,
        cwe: "CWE-614",
        remediation: `Add the Secure attribute to: ${insecure.map(c => `"${c.name}"`).join(", ")}. Prevents cookies from being sent over plain HTTP.` });
    if (noHO.length > 0)
      vulns.push({ cve: "COOKIE-HTTPONLY", cvss: 4.3, severity: "medium",
        title: `${noHO.length} Cookie(s) Missing HttpOnly Flag`,
        cwe: "CWE-1004",
        remediation: `Add the HttpOnly attribute to: ${noHO.map(c => `"${c.name}"`).join(", ")}. Prevents JavaScript from reading the cookie, reducing XSS session theft.` });
    if (noSS.length > 0)
      vulns.push({ cve: "COOKIE-SAMESITE", cvss: 3.7, severity: "low",
        title: `${noSS.length} Cookie(s) Missing SameSite Attribute`,
        cwe: "CWE-352",
        remediation: `Add SameSite=Lax or SameSite=Strict to: ${noSS.map(c => `"${c.name}"`).join(", ")}. Reduces CSRF attack surface.` });
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

// ── Real CVE lookup from Shodan InternetDB + NVD CPE API ─────────────────────
// Replaces the old static keyword-matching CVE_POOL.
//
// Strategy:
//  1. Shodan InternetDB returns CVE IDs per IP — enrich with NVD for full metadata
//  2. nmap CPE strings (e.g. cpe:/a:apache:http_server:2.4.49) → NVD CPE API
//  Both sources are deduped into a single VulnFinding[] list.

async function lookupRealCves(
  ports: PortFinding[],
  shodanCveIds: string[],
): Promise<VulnFinding[]> {
  const seen = new Set<string>();
  const results: VulnFinding[] = [];

  const nvdFromCve = (c: NvdCve): VulnFinding => ({
    cve: c.cve, cvss: c.cvss ?? 0, severity: c.severity,
    title: c.title, cwe: c.cwe ?? "CWE-Unknown", remediation: c.remediation,
  });

  // ── 1. Shodan CVE IDs enriched via NVD ──────────────────────────────────
  if (shodanCveIds.length > 0) {
    const enriched = await enrichShodanCves(shodanCveIds);
    for (const c of enriched) {
      if (!seen.has(c.cve)) { seen.add(c.cve); results.push(nvdFromCve(c)); }
    }
  }

  // ── 2. CPEs from nmap service fingerprinting → NVD CPE API ──────────────
  const allCpes = ports.flatMap((p: any) => p.cpes ?? []).filter(Boolean) as string[];
  if (allCpes.length > 0) {
    const fromCpe = await lookupCvesFromCpes(allCpes);
    for (const c of fromCpe) {
      if (!seen.has(c.cve)) { seen.add(c.cve); results.push(nvdFromCve(c)); }
    }
  }

  return results.sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0));
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

  // ── Load platform API keys for this run ──────────────────────────────────
  const [nvdKey, shodanKey, vtKey, hunterKey, githubToken, fofaEmail, fofaApiKey, censysApiId, censysApiSecret, intelxApiKey, criminalIpApiKey] = await Promise.all([
    getPlatformSetting("nvd_api_key"),
    getPlatformSetting("shodan_api_key"),
    getPlatformSetting("virustotal_api_key"),
    getPlatformSetting("hunter_api_key"),
    getPlatformSetting("github_token"),
    getPlatformSetting("fofa_email"),
    getPlatformSetting("fofa_api_key"),
    getPlatformSetting("censys_api_id"),
    getPlatformSetting("censys_api_secret"),
    getPlatformSetting("intelx_api_key"),
    getPlatformSetting("criminalip_api_key"),
  ]);
  if (nvdKey) setNvdApiKey(nvdKey);

  // ── Auto-ensure built-in tools exist for this tenant (fallback — startup seed is primary) ──
  for (const def of BUILTIN_TOOL_DEFS) {
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

  // ── Parallel asset processing with concurrency cap ────────────────────────
  // Assets within a scan run MAX_PARALLEL_ASSETS at a time instead of sequentially.
  // Each asset still runs its own phases sequentially internally.
  const assetErrors: { assetId: number; err: unknown }[] = [];
  const findingTotals: number[] = [];

  async function processAsset(config: AssetToolConfigItem): Promise<void> {
    const currentScan = await db.select({ status: scansTable.status }).from(scansTable)
      .where(eq(scansTable.id, scanId)).then(r => r[0]);
    if (currentScan?.status === "cancelled") return;

    const asset = assets.find(a => a.id === config.assetId);
    if (!asset) return;

    const toolsForAsset = config.toolIds.length > 0
      ? allTools.filter(t => config.toolIds.includes(t.id))
      : enabledTools;
    if (toolsForAsset.length === 0) return;

    const target = asset.value;
    const domain = extractDomain(target);
    const now = () => new Date().toISOString();
    const ms = (start: number) => Date.now() - start;

    // ── Auto-trigger brand threat scan for Domain/Subdomain assets immediately ─
    // This fires per-asset (not post-scan), so brand intel runs in parallel
    // with the main pipeline rather than waiting for all assets to complete.
    if ((asset.type === "domain" || asset.type === "subdomain") && domain && !isIp(domain) && isValidHostname(domain)) {
      setImmediate(async () => {
        try {
          await triggerBrandThreatScan(tenantId, domain, scanId);
        } catch (err) {
          logger.warn({ err, assetId: asset.id, domain }, "Per-asset brand threat trigger failed (non-fatal)");
        }
      });
    }

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

    // ── PHASE 1 parallel: all independent OSINT/recon/intel tools fire together ─
    // DNS recon, CT logs, geo/ASN, WHOIS, cloud surface, VirusTotal, Hunter.io,
    // DKIM/SPF/DMARC, GitHub exposure, and all commercial intel sources (Fofa,
    // Censys, IntelX, CriminalIP) all start simultaneously with Promise.allSettled.
    await Promise.allSettled([
      // ── Core recon ──────────────────────────────────────────────────────────
      needsDns   && (async () => { dnsResult   = await runDnsRecon(target); })(),
      needsCt    && !isIp(domain) && (async () => { ctSubdomains = await runCtLogLookup(domain); })(),
      needsGeo   && (async () => { geoIntel    = await runGeoIntel(target); })(),
      needsWhois && !isIp(domain) && (async () => { whoisIntel  = await runWhoisIntel(target); })(),
      needsCloud && (async () => { cloudIntel  = await runCloudSurfaceScan(target); })(),

      // ── VirusTotal domain reputation (parallel with recon) ──────────────────
      vtKey && domain && !isIp(domain) && (async () => {
        try {
          const vtResult = await getVirusTotalDomain(domain, vtKey!);
          if (vtResult) {
            geoIntel.push({ type: "VirusTotal", key: "Reputation score",  value: String(vtResult.reputation) });
            geoIntel.push({ type: "VirusTotal", key: "Detection summary", value: `${vtResult.malicious} malicious, ${vtResult.suspicious} suspicious, ${vtResult.harmless} clean` });
            if (vtResult.categories.length > 0)
              geoIntel.push({ type: "VirusTotal", key: "Categories", value: vtResult.categories.slice(0, 5).join(", ") });
            if (vtResult.registrar)
              geoIntel.push({ type: "VirusTotal", key: "Registrar", value: vtResult.registrar });
            if (vtResult.lastAnalysisDate)
              geoIntel.push({ type: "VirusTotal", key: "Last analysis", value: vtResult.lastAnalysisDate });
            logger.info({ domain, malicious: vtResult.malicious, suspicious: vtResult.suspicious }, "VirusTotal scan complete");
          }
        } catch (err) { logger.warn({ err, domain }, "VirusTotal lookup failed (non-fatal)"); }
      })(),

      // ── Hunter.io employee email OSINT (parallel with recon) ────────────────
      hunterKey && domain && !isIp(domain) && (async () => {
        try {
          const hunterResult = await hunterDomainSearch(domain, hunterKey!);
          if (hunterResult && hunterResult.emails.length > 0) {
            if (hunterResult.organization)
              geoIntel.push({ type: "Hunter.io", key: "Organization",  value: hunterResult.organization });
            if (hunterResult.pattern)
              geoIntel.push({ type: "Hunter.io", key: "Email pattern", value: hunterResult.pattern });
            geoIntel.push({ type: "Hunter.io", key: "Emails found", value: String(hunterResult.emails.length) });
            for (const e of hunterResult.emails.slice(0, 25)) {
              const label = [e.firstName, e.lastName, e.position, e.department].filter(Boolean).join(", ")
                || `Confidence: ${e.confidence}%`;
              geoIntel.push({ type: "Hunter.io", key: e.email, value: label });
            }
            logger.info({ domain, emailCount: hunterResult.emails.length }, "Hunter.io OSINT complete");
          }
        } catch (err) { logger.warn({ err, domain }, "Hunter.io OSINT failed (non-fatal)"); }
      })(),

      // ── DKIM / SPF / DMARC email security check ──────────────────────────────
      domain && !isIp(domain) && (async () => {
        try {
          const result = await runDkimCheck(domain);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            if (d.spf)   whoisIntel.push({ type: "Email Security", key: "SPF record",    value: d.spf });
            if (d.dmarc) whoisIntel.push({ type: "Email Security", key: "DMARC policy",  value: d.dmarc });
            if (d.hasDkim) whoisIntel.push({ type: "Email Security", key: "DKIM selectors found", value: String((d.dkimSelectors as any[]).length) });
            if (!d.hasSpf)   whoisIntel.push({ type: "Email Security", key: "SPF missing",   value: "No SPF record — spoofing risk" });
            if (!d.hasDmarc) whoisIntel.push({ type: "Email Security", key: "DMARC missing", value: "No DMARC record — spoofing risk" });
            logger.info({ domain, hasDkim: d.hasDkim, hasSpf: d.hasSpf, hasDmarc: d.hasDmarc }, "DKIM/SPF/DMARC check complete");
          }
        } catch (err) { logger.warn({ err, domain }, "DKIM check failed (non-fatal)"); }
      })(),

      // ── GitHub code & repo exposure ───────────────────────────────────────────
      domain && !isIp(domain) && (async () => {
        try {
          const result = await runGithubExposure(domain, githubToken ?? null);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            if (d.totalExposures > 0)
              geoIntel.push({ type: "GitHub", key: "Total exposures",      value: String(d.totalExposures) });
            if (d.codeReferences?.length)
              geoIntel.push({ type: "GitHub", key: "Code references",      value: String(d.codeReferences.length) });
            if (d.relatedRepos?.length)
              geoIntel.push({ type: "GitHub", key: "Related repositories", value: String(d.relatedRepos.length) });
            if (d.orgInfo)
              geoIntel.push({ type: "GitHub", key: "GitHub org",           value: `${d.orgInfo.login} (${d.orgInfo.publicRepos} public repos)` });
            logger.info({ domain, exposures: d.totalExposures }, "GitHub exposure scan complete");
          }
        } catch (err) { logger.warn({ err, domain }, "GitHub exposure scan failed (non-fatal)"); }
      })(),

      // ── Fofa internet scanner (commercial intel) ──────────────────────────────
      fofaEmail && fofaApiKey && domain && !isIp(domain) && (async () => {
        try {
          const result = await runFofaSearch(domain, fofaEmail!, fofaApiKey!);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            geoIntel.push({ type: "Fofa", key: "Hosts indexed", value: String(d.total ?? d.results?.length ?? 0) });
            if (d.results?.length) {
              const sample = (d.results as any[]).slice(0, 5).map((r: any) => `${r.host}:${r.port}`).join(", ");
              geoIntel.push({ type: "Fofa", key: "Sample hosts", value: sample });
            }
            logger.info({ domain, total: d.total }, "Fofa search complete");
          }
        } catch (err) { logger.warn({ err, domain }, "Fofa search failed (non-fatal)"); }
      })(),

      // ── Censys host search (commercial intel) ─────────────────────────────────
      censysApiId && censysApiSecret && domain && !isIp(domain) && (async () => {
        try {
          const result = await runCensysSearch(domain, censysApiId!, censysApiSecret!);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            geoIntel.push({ type: "Censys", key: "Hosts indexed", value: String(d.total ?? d.results?.length ?? 0) });
            if (d.results?.length) {
              const services = (d.results as any[]).flatMap((r: any) => r.services ?? [])
                .map((s: any) => `${s.port}/${s.name}`).slice(0, 8).join(", ");
              if (services) geoIntel.push({ type: "Censys", key: "Exposed services", value: services });
            }
            logger.info({ domain, total: d.total }, "Censys search complete");
          }
        } catch (err) { logger.warn({ err, domain }, "Censys search failed (non-fatal)"); }
      })(),

      // ── Intelligence X breach & dark-web search (commercial intel) ────────────
      intelxApiKey && domain && !isIp(domain) && (async () => {
        try {
          const result = await runIntelxSearch(domain, intelxApiKey!);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            if ((d.totalFound ?? 0) > 0)
              geoIntel.push({ type: "IntelX", key: "Records in breach/dark-web DBs", value: String(d.totalFound) });
            else
              geoIntel.push({ type: "IntelX", key: "Breach exposure", value: "No records found in IntelX" });
            logger.info({ domain, total: d.totalFound }, "IntelX search complete");
          }
        } catch (err) { logger.warn({ err, domain }, "IntelX search failed (non-fatal)"); }
      })(),

      // ── CriminalIP threat intelligence (commercial intel) ─────────────────────
      criminalIpApiKey && domain && !isIp(domain) && (async () => {
        try {
          const result = await runCriminalIpSearch(domain, criminalIpApiKey!);
          if (result.status === "ok" && result.data) {
            const d = result.data as any;
            if (d.report?.summary?.score !== undefined)
              geoIntel.push({ type: "CriminalIP", key: "Threat score",    value: String(d.report.summary.score) });
            if (d.report?.ip_count)
              geoIntel.push({ type: "CriminalIP", key: "Associated IPs",  value: String(d.report.ip_count) });
            logger.info({ domain }, "CriminalIP threat intel complete");
          }
        } catch (err) { logger.warn({ err, domain }, "CriminalIP search failed (non-fatal)"); }
      })(),
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

      portScanReport = await scanPorts(target, shodanKey ?? undefined);
      realPorts = portScanReport.ports as PortFinding[];

      const masscanSection = portScanReport.masscan.available
        ? [
            `=== MASSCAN — Ultra-fast SYN Port Discovery (${portScanReport.masscan.ports.length} ports, method: ${portScanReport.scanMethod}) ===`,
            portScanReport.masscan.raw.slice(0, 3000) || "(no output)",
          ]
        : [
            `=== MASSCAN — Not available (${portScanReport.masscan.failReason ?? "unavailable"}) ===`,
            portScanReport.masscan.raw || "(install masscan: apt-get install masscan, requires CAP_NET_RAW)",
          ];

      nmapRaw = [
        `=== NAABU — Full TCP Port Discovery (${portScanReport.naabuPorts.length} ports found, 1–65535) ===`,
        portScanReport.naabuRaw.slice(0, 3000) || "(no output)",
        "",
        ...masscanSection,
        "",
        `=== NMAP — Service Detection + NSE Scripts (method: ${portScanReport.scanMethod}) ===`,
        portScanReport.nmapRaw.slice(0, 8000) || "(no output)",
        "",
        portScanReport.shodan
          ? `=== SHODAN ${shodanKey ? "Full API" : "InternetDB"} — ${portScanReport.targetIp ?? "?"} ===\nPorts: ${portScanReport.shodan.ports.join(", ") || "none"}\nTags: ${portScanReport.shodan.tags.join(", ") || "none"}\nCPEs: ${portScanReport.shodan.cpes.slice(0, 5).join(", ") || "none"}\nCVEs: ${portScanReport.shodan.vulns.join(", ") || "none"}\nHostnames: ${portScanReport.shodan.hostnames.join(", ") || "none"}`
          : `=== SHODAN ${shodanKey ? "Full API" : "InternetDB"} — no data available ===`,
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
    let jsAnalysis: JsAnalysisResult | null = null;
    let paramDiscovery: ParamDiscoveryResult | null = null;
    let cloudRecon: CloudReconResult | null = null;
    let secretsHunt: SecretsHuntResult | null = null;
    let dirFuzz: DirFuzzResult | null = null;
    let vulnScan: VulnScanResult | null = null;
    const hasScreenshotTools = toolsForAsset.some(t => t.category === "screenshot");
    // Screenshots + tech detection always run for web asset types regardless of tool pipeline
    const isWebAsset = ["domain", "subdomain", "url", "ip"].includes(asset.type ?? "");
    const shouldScreenshot = isWebAsset; // always capture for web assets
    if (needsHttp || toolsForAsset.some(t => t.category === "web_recon") || hasScreenshotTools || isWebAsset) {
      const p3Start = Date.now();
      for (const t of p3) startTool(t.name, t.category === "screenshot"
        ? `Capturing screenshots of ${domain}…`
        : `Probing web application at ${domain}…`);

      let wafProbeResult: WafDetection | null = null;
      let originIpCandidates: OriginIpCandidate[] = [];

      await Promise.allSettled([
        (async () => { httpInfo  = await runHttpProbe(target); })(),
        (async () => {
          const discovered = await runEndpointDiscovery(target);
          endpoints = discovered.map(d => ({
            url:      d.url,
            method:   "GET",
            status:   d.status ?? 0,
            title:    d.title,
            category: d.category,
            source:   d.source,
          }));
        })(),
        (async () => { detectedTechs = await detectTechnologies(target); })(),
        // Active WAF probe (Node-native, runs in parallel with HTTP probe)
        (async () => { wafProbeResult = await runActiveWafProbe(target); })(),
        // Origin IP discovery: SPF + subdomain IPs + hackertarget + bypass check + SecurityTrails
        (async () => { originIpCandidates = await discoverOriginIps(domain, dnsResult.dnsRecords, dnsResult.subdomains); })(),
        shouldScreenshot
          ? (async () => { capturedPages = await captureScreenshots(target, 90000); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { jsAnalysis = await runJsAnalysis(target); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { paramDiscovery = await runParamDiscovery(target); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { cloudRecon = await runCloudRecon(target); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { secretsHunt = await runSecretsHunt(target, githubToken); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { dirFuzz = await runDirFuzz(target, dnsResult.subdomains.map(s => s.name)); })()
          : Promise.resolve(),
        isWebAsset
          ? (async () => { vulnScan = await runNucleiScan(target, dnsResult.subdomains.map(s => s.name)); })()
          : Promise.resolve(),
      ]);

      // Merge active WAF probe result if header detection didn't find a high-confidence WAF
      if (httpInfo) {
        if (!httpInfo.wafDetails || httpInfo.wafDetails.confidence !== "high") {
          if (wafProbeResult) {
            httpInfo.wafDetails = wafProbeResult;
            httpInfo.waf = wafProbeResult.name;
          }
        }
        if (originIpCandidates.length > 0) httpInfo.originIps = originIpCandidates;
      }

      // ── Multi-host tech fingerprinting on live subdomains ─────────────────
      // Run detectTechnologies on up to 15 live subdomains discovered in Phase 1,
      // then merge unique techs and attach per-host data to httpInfo.
      {
        const primaryDomain = extractDomain(target);
        const liveHosts = dnsResult.subdomains.filter(s => s.status === "active" && s.ip).slice(0, 15);
        if (liveHosts.length > 0) {
          // Tag primary domain on all existing detections
          for (const t of detectedTechs) t.hosts = [primaryDomain];

          const subResults = await Promise.allSettled(
            liveHosts.map(async s => ({
              host: s.name,
              techs: await detectTechnologies(s.name, 8000),
              waf: await quickWafCheck(s.name),
            }))
          );

          const hostFpMap = new Map<string, { techs: string[]; waf?: string }>();
          for (const r of subResults) {
            if (r.status !== "fulfilled" || !r.value.techs.length) continue;
            const { host, techs, waf } = r.value;
            hostFpMap.set(host, { techs: techs.map(t => t.name), waf: waf ?? undefined });
            for (const t of techs) {
              const existing = detectedTechs.find(d => d.slug === t.slug);
              if (existing) {
                (existing.hosts ??= []).push(host);
              } else {
                detectedTechs.push({ ...t, hosts: [host] });
              }
            }
          }

          // Attach per-host fingerprints + WAF to httpInfo for UI display
          if (httpInfo && hostFpMap.size > 0) {
            httpInfo.hostFingerprints = [...hostFpMap.entries()].map(([host, { techs, waf }]) => ({ host, techs, waf }));
          }
        } else {
          // Single-host scan — tag primary domain on all detections
          for (const t of detectedTechs) t.hosts = [primaryDomain];
        }
      }

      // ── Auto-store technology detections for this asset ──────────────────
      const validTechs = detectedTechs.filter(t => t.name && t.slug && t.category);
      if (validTechs.length > 0) {
        try {
          await db.delete(technologyDetectionsTable)
            .where(and(eq(technologyDetectionsTable.tenantId, tenantId), eq(technologyDetectionsTable.assetId, asset.id)));
          await db.insert(technologyDetectionsTable).values(
            validTechs.map(t => ({
              tenantId,
              assetId: asset.id,
              scanId,
              technology: t.name,
              slug: t.slug,
              category: t.category,
              version: t.version ?? null,
              confidence: t.confidence ?? 100,
              website: t.website ?? null,
              cpe: t.cpe ?? null,
              icon: t.icon ?? null,
            }))
          );
        } catch (techErr) {
          logger.warn({ err: techErr, assetId: asset.id }, "Technology detections insert failed (non-fatal)");
        }
      }

      // ── Auto-store screenshots for this asset ─────────────────────────
      const validPages = capturedPages.filter(p => p.screenshotData && p.screenshotData.length > 0 && p.url && p.pageType);
      if (validPages.length > 0) {
        try {
          await db.delete(screenshotsTable)
            .where(and(eq(screenshotsTable.tenantId, tenantId), eq(screenshotsTable.assetId, asset.id)));
          await db.insert(screenshotsTable).values(
            validPages.map(p => ({
              tenantId,
              assetId: asset.id,
              scanId,
              url:            p.url,
              pageType:       p.pageType,
              screenshotData: p.screenshotData,
              title:          p.title ?? null,
              statusCode:     p.statusCode ?? null,
              findings:       p.findings ?? null,
            }))
          );
        } catch (ssErr) {
          logger.warn({ err: ssErr, assetId: asset.id }, "Screenshots insert failed (non-fatal)");
        }
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

      const shodanCveIds: string[] = portScanReport?.shodan?.vulns ?? [];

      await Promise.allSettled([
        needsSecrets && (async () => { secretFindings = await runSecretsScanner(target, endpoints, httpInfo); })(),
        (async () => {
          cveFindings = await lookupRealCves(realPorts, shodanCveIds);
          headerVulnFindings = analyzeSecurityHeaders(httpInfo);
        })(),
      ].filter(Boolean));

      for (const t of p4) {
        const isSecrets = t.name === "trufflehog";
        const count = isSecrets ? secretFindings.length : cveFindings.length + headerVulnFindings.length;
        doneTool(t.name, count, isSecrets ? `${secretFindings.length} secrets/credentials found` : `${cveFindings.length} CVEs (Shodan+NVD), ${headerVulnFindings.length} header issues`, p4Start);
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

      // ── Auto-trigger brand threat scans for discovered subdomains ─────────
      // Fan-out brand monitoring to each unique subdomain found via enumeration
      // (full subdomain name, not just apex) so brand intelligence covers the
      // complete discovered attack surface.
      setImmediate(async () => {
        try {
          const triggeredDomains = new Set<string>();
          if (domain) triggeredDomains.add(domain); // already triggered for parent asset
          for (const s of subdomainScanReport.all) {
            const sub = s.name?.toLowerCase().trim();
            if (!sub || isIp(sub) || !isValidHostname(sub)) continue;
            if (triggeredDomains.has(sub)) continue;
            triggeredDomains.add(sub);
            await triggerBrandThreatScan(tenantId, sub, scanId);
          }
        } catch (err) {
          logger.warn({ err, assetId: asset.id }, "Subdomain brand threat fan-out failed (non-fatal)");
        }
      });
    }

    // ── Compile all data and store per-tool results ────────────────────────────
    const allIntel    = [...sslIntel, ...geoIntel, ...whoisIntel, ...cloudIntel];
    const allVulns    = [...cveFindings, ...sslVulns, ...headerVulnFindings, ...secretFindings];
    const allSubdomains = dnsResult.subdomains;
    const allDns      = dnsResult.dnsRecords;

    // ── Update asset primary IP from DNS A record if not already set ──────────
    const primaryIp = allDns.find(r => r.type === "A")?.value ?? null;
    if (primaryIp && !asset.ipAddress) {
      await db.update(assetsTable)
        .set({ ipAddress: primaryIp })
        .where(eq(assetsTable.id, asset.id))
        .catch(() => {});
    }

    const results: Array<typeof scanAssetResultsTable.$inferInsert> = [];
    const findingInserts: Array<typeof findingsTable.$inferInsert>   = [];

    // ── VirusTotal findings — domains flagged malicious or suspicious ─────────
    if (vtKey && domain && !isIp(domain)) {
      try {
        const vtResult = await getVirusTotalDomain(domain, vtKey);
        if (vtResult && vtResult.malicious > 0) {
          const vtSev = vtResult.malicious >= 10 ? "critical" : vtResult.malicious >= 5 ? "high" : "medium";
          findingInserts.push({
            tenantId, assetId: asset.id, scanId,
            title: `VirusTotal: ${domain} flagged by ${vtResult.malicious} security engine${vtResult.malicious > 1 ? "s" : ""}`,
            cve: `VT-MALICIOUS-${domain.replace(/[^a-z0-9]/gi, "-").toUpperCase().slice(0, 30)}`,
            severity: vtSev,
            cvss: vtResult.malicious >= 10 ? 9.0 : vtResult.malicious >= 5 ? 7.5 : 5.0,
            cwe: "CWE-829",
            status: "open",
            description: `VirusTotal flagged ${domain} as malicious by ${vtResult.malicious} vendor${vtResult.malicious > 1 ? "s" : ""} (${vtResult.suspicious} suspicious, ${vtResult.harmless} clean). Reputation score: ${vtResult.reputation}.${vtResult.categories.length > 0 ? ` Categories: ${vtResult.categories.slice(0, 3).join(", ")}.` : ""}`,
            remediation: "Investigate immediately. Check for drive-by downloads, phishing content, or malware. Consider blocking at the network perimeter and reviewing recent code changes.",
          });
        } else if (vtResult && vtResult.suspicious > 0) {
          findingInserts.push({
            tenantId, assetId: asset.id, scanId,
            title: `VirusTotal: ${domain} flagged suspicious by ${vtResult.suspicious} engine${vtResult.suspicious > 1 ? "s" : ""}`,
            cve: `VT-SUSPICIOUS-${domain.replace(/[^a-z0-9]/gi, "-").toUpperCase().slice(0, 30)}`,
            severity: "low",
            cvss: 3.0,
            cwe: "CWE-829",
            status: "open",
            description: `VirusTotal analysis flagged ${domain} as suspicious by ${vtResult.suspicious} vendor${vtResult.suspicious > 1 ? "s" : ""}. Reputation score: ${vtResult.reputation}.`,
            remediation: `Review the full VirusTotal report for ${domain} and monitor for further malicious activity.`,
          });
        }
      } catch { /* non-fatal — VT findings are bonus data */ }
    }

    // ── Exposed Dangerous Services — port scan findings ───────────────────────
    if (portScanReport && portScanReport.ports.length > 0) {
      type PortRisk = "critical" | "high" | "medium";
      const DANGER: Record<number, { service: string; risk: PortRisk; cwe: string; reason: string; cvss: number }> = {
        21:    { service: "FTP",               risk: "high",     cwe: "CWE-319", reason: "Unencrypted file transfer protocol",               cvss: 7.5 },
        23:    { service: "Telnet",            risk: "critical", cwe: "CWE-319", reason: "Plaintext remote access — no encryption",           cvss: 9.1 },
        135:   { service: "RPC",               risk: "high",     cwe: "CWE-284", reason: "Windows RPC endpoint exposed to internet",          cvss: 7.3 },
        139:   { service: "NetBIOS",           risk: "critical", cwe: "CWE-284", reason: "Windows NetBIOS file sharing exposed",              cvss: 9.0 },
        161:   { service: "SNMP",              risk: "high",     cwe: "CWE-200", reason: "Network management data accessible externally",      cvss: 7.5 },
        389:   { service: "LDAP",              risk: "high",     cwe: "CWE-284", reason: "Directory service exposed to internet",              cvss: 7.3 },
        445:   { service: "SMB",               risk: "critical", cwe: "CWE-284", reason: "EternalBlue/ransomware target — file sharing exposed", cvss: 9.8 },
        1433:  { service: "MSSQL",             risk: "critical", cwe: "CWE-284", reason: "Database server directly exposed to internet",       cvss: 9.8 },
        1521:  { service: "Oracle DB",         risk: "critical", cwe: "CWE-284", reason: "Database server directly exposed to internet",       cvss: 9.8 },
        2379:  { service: "etcd",              risk: "critical", cwe: "CWE-284", reason: "Kubernetes config store exposed to internet",        cvss: 9.8 },
        3306:  { service: "MySQL",             risk: "critical", cwe: "CWE-284", reason: "Database server directly exposed to internet",       cvss: 9.8 },
        3389:  { service: "RDP",               risk: "critical", cwe: "CWE-284", reason: "Remote Desktop — brute-force & ransomware target",  cvss: 9.8 },
        4243:  { service: "Docker API",        risk: "critical", cwe: "CWE-284", reason: "Docker remote API exposed — container escape risk",  cvss: 9.8 },
        5432:  { service: "PostgreSQL",        risk: "critical", cwe: "CWE-284", reason: "Database server directly exposed to internet",       cvss: 9.8 },
        5900:  { service: "VNC",               risk: "critical", cwe: "CWE-319", reason: "Remote desktop without encryption",                 cvss: 9.0 },
        5984:  { service: "CouchDB",           risk: "high",     cwe: "CWE-284", reason: "Database may be publicly accessible without auth",  cvss: 7.5 },
        6379:  { service: "Redis",             risk: "critical", cwe: "CWE-306", reason: "No auth by default — remote code execution risk",   cvss: 9.8 },
        6443:  { service: "Kubernetes API",    risk: "critical", cwe: "CWE-284", reason: "Kubernetes API server exposed to internet",         cvss: 9.8 },
        8080:  { service: "HTTP-Alt",          risk: "medium",   cwe: "CWE-200", reason: "Development HTTP server exposed externally",        cvss: 5.3 },
        9200:  { service: "Elasticsearch",     risk: "critical", cwe: "CWE-306", reason: "No auth by default — full data exposure risk",      cvss: 9.8 },
        9300:  { service: "Elasticsearch",     risk: "critical", cwe: "CWE-284", reason: "Elasticsearch cluster communication exposed",       cvss: 9.0 },
        11211: { service: "Memcached",         risk: "high",     cwe: "CWE-284", reason: "Cache exposed — DDoS amplification attack vector",  cvss: 7.5 },
        27017: { service: "MongoDB",           risk: "critical", cwe: "CWE-306", reason: "No auth by default — full database exposure risk",  cvss: 9.8 },
        27018: { service: "MongoDB",           risk: "critical", cwe: "CWE-284", reason: "MongoDB shard server exposed to internet",          cvss: 9.0 },
        50070: { service: "HDFS NameNode",     risk: "high",     cwe: "CWE-284", reason: "Hadoop NameNode UI exposed externally",             cvss: 7.3 },
      };
      for (const p of portScanReport.ports) {
        const info = DANGER[p.port];
        if (!info) continue;
        const slug  = (asset.value || "").replace(/[^A-Z0-9]/gi, "").toUpperCase().slice(0, 20);
        const cveId = `EXP-PORT-${p.port}-${slug}`;
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: `Exposed ${info.service} (Port ${p.port}/${(p.protocol ?? "tcp")})`,
          cve: cveId,
          severity: info.risk,
          cvssScore: String(info.cvss),
          cwe: info.cwe,
          status: "open" as const,
          description: `Port ${p.port}/${(p.protocol ?? "tcp")} (${p.service || info.service}) is directly accessible from the internet on ${asset.name} (${asset.value}). ${info.reason}. Detected service version: ${p.version || "unknown"}.`,
          remediation: `Restrict access to port ${p.port} using network firewall rules (iptables/Security Groups/NSGs). If this service must be accessible, place it behind a VPN or reverse proxy with strict authentication and rate limiting. Disable the service entirely if not required.`,
          evidence: JSON.stringify({ port: p.port, protocol: p.protocol, service: p.service, version: p.version }),
        });
      }
    }

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
        // ── JS analysis tools: full result stored via dedicated DB entry below ─
        else if (name === "linkfinder" || name === "secretfinder") {
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

    // ── Record tool runs in tool_runs table ─────────────────────────────────
    try {
      const toolRunInserts = toolsForAsset.map(tool => {
        const tp = toolProgress.find(t => t.toolName === tool.name);
        const r  = results.find(res => res.toolName === tool.name);
        const status = tp?.status === "failed" ? "failed" : "completed";
        return {
          tenantId,
          toolId:      tool.id,
          assetId:     asset.id,
          status,
          output:      r?.rawOutput ? r.rawOutput.slice(0, 50_000) : null,
          triggeredBy: null as null,
          startedAt:   tp?.startedAt   ? new Date(tp.startedAt)   : new Date(),
          completedAt: tp?.completedAt ? new Date(tp.completedAt) : new Date(),
        };
      });
      for (let i = 0; i < toolRunInserts.length; i += 50) {
        await db.insert(toolRunsTable).values(toolRunInserts.slice(i, i + 50));
      }
    } catch (err) {
      logger.warn({ err, scanId, assetId: asset.id }, "Failed to record pipeline tool runs (non-fatal)");
    }

    // ── JS Analysis: store result + create secret findings ─────────────────────
    if (isWebAsset && jsAnalysis && jsAnalysis.stats.analyzedFiles > 0) {
      const cvssMap: Record<string, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 3.0, info: 1.0 };
      const jsSecretVulns = jsAnalysis.secrets
        .filter(s => s.severity !== "info")
        .map(s => ({
          cve:  `JSSEC-${s.type.replace(/[^A-Z0-9]/gi, "-").toUpperCase().slice(0, 20)}`,
          cvss: cvssMap[s.severity] ?? 5.0,
          severity: s.severity,
          title: `${s.type} exposed in JavaScript`,
          cwe: s.cwe,
          remediation: s.remediation,
          source: `${s.file.split("/").pop()}, line ${s.line}`,
        }));

      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "linkfinder", toolCategory: "web_recon",
        rawOutput: [
          `[LinkFinder + SecretFinder] JS Analysis — ${target}`,
          `Files found: ${jsAnalysis.stats.totalFiles}  |  Analyzed: ${jsAnalysis.stats.analyzedFiles}`,
          `Endpoints extracted: ${jsAnalysis.stats.totalEndpoints}`,
          `Secrets detected: ${jsAnalysis.stats.totalSecrets} (${jsAnalysis.stats.criticalSecrets} critical, ${jsAnalysis.stats.highSecrets} high)`,
          "",
          "=== JS FILES ===",
          ...jsAnalysis.jsFiles.map(f =>
            `  [${f.analyzed ? "ANALYZED" : "SKIPPED "}] ${f.url}  (${(f.size / 1024).toFixed(0)}KB)  →  ${f.endpointCount} endpoints, ${f.secretCount} secrets`
          ),
          "",
          "=== EXTRACTED ENDPOINTS (sample) ===",
          ...jsAnalysis.endpoints.slice(0, 100).map(e =>
            `  ${e.method ? `[${e.method}] ` : ""}${e.path}  (${e.file.split("/").pop()})`
          ),
          jsAnalysis.endpoints.length > 100 ? `  ... and ${jsAnalysis.endpoints.length - 100} more endpoints` : "",
          "",
          "=== SECRETS DETECTED ===",
          ...jsAnalysis.secrets.map(s =>
            `  [${s.severity.toUpperCase()}] ${s.type}  |  ${s.file.split("/").pop()}:${s.line}  |  ${s.value}`
          ),
        ].join("\n"),
        jsAnalysis: jsAnalysis as any,
        vulnerabilities: jsSecretVulns.length ? jsSecretVulns as any : null,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
      });

      // Insert JS secrets as findings (exclude info-severity)
      for (const s of jsAnalysis.secrets.filter(sec => sec.severity !== "info")) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: `${s.type} exposed in JavaScript`,
          cve: `JSSEC-${s.type.replace(/[^A-Z0-9]/gi, "-").toUpperCase().slice(0, 20)}`,
          severity: s.severity as "critical" | "high" | "medium" | "low" | "info",
          cvssScore: String(cvssMap[s.severity] ?? 5.0),
          cwe: s.cwe, status: "open",
          description: `${s.type} found in ${s.file.split("/").pop()}, line ${s.line}. Context: ${s.rawContext.slice(0, 300)}`,
          remediation: s.remediation,
        });
      }
    }

    // ── Parameter Discovery: store result ──────────────────────────────────────
    if (isWebAsset && paramDiscovery && paramDiscovery.stats.total > 0) {
      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "paramspider", toolCategory: "web_recon",
        rawOutput: [
          `Parameter Discovery — ${target}`,
          `Total params found: ${paramDiscovery.stats.total}  |  Unique param names: ${paramDiscovery.stats.unique}`,
          `From archive: ${paramDiscovery.stats.fromArchive}  |  From crawl: ${paramDiscovery.stats.fromCrawl}  |  From forms: ${paramDiscovery.stats.fromForm}  |  From brute-force: ${paramDiscovery.stats.fromBrute}`,
          "",
          "=== BY CATEGORY ===",
          `  SSRF/Redirect:  ${paramDiscovery.stats.ssrf}`,
          `  IDOR:           ${paramDiscovery.stats.idor}`,
          `  XSS/SQLi:       ${paramDiscovery.stats.xss_sqli}`,
          `  Auth/Token:     ${paramDiscovery.stats.auth}`,
          `  File/Path:      ${paramDiscovery.stats.file_path}`,
          `  Other:          ${paramDiscovery.stats.other}`,
          "",
          "=== UNIQUE PARAMETER NAMES ===",
          paramDiscovery.uniqueNames.join(", "),
          "",
          "=== PARAMETER DETAILS (top 200) ===",
          ...paramDiscovery.params.slice(0, 200).map(p =>
            `  [${p.category.toUpperCase()}][${p.confidence}] ${p.name} (${p.method}) — ${p.url} [${p.source}]${p.example ? ` example: ${p.example}` : ""}`
          ),
          paramDiscovery.params.length > 200 ? `  ... and ${paramDiscovery.params.length - 200} more parameters` : "",
        ].join("\n"),
        paramDiscovery: paramDiscovery as any,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
        vulnerabilities: null as any,
      });
    }

    // ── Cloud Recon: store result + create findings for public buckets ──────────
    if (isWebAsset && cloudRecon && (cloudRecon.stats.existingBuckets > 0 || cloudRecon.stats.publicFirebase > 0)) {
      const cloudVulns = [
        ...cloudRecon.buckets
          .filter(b => b.isPublic)
          .map(b => ({
            cve: `CLOUD-${b.provider.toUpperCase()}-${b.name.replace(/[^A-Z0-9]/gi, "-").toUpperCase().slice(0, 20)}`,
            cvss: b.isListable ? 9.0 : 7.5,
            severity: b.isListable ? "critical" : "high",
            title: `${b.isListable ? "Publicly listable" : "Publicly accessible"} ${b.provider === "aws_s3" ? "S3" : b.provider === "gcs" ? "GCS" : "Azure"} bucket: ${b.name}`,
            cwe: "CWE-552",
            remediation: `Set bucket ACL to private. Remove public-read/public-read-write ACL. Enable Block Public Access settings.`,
            source: b.url,
          })),
        ...cloudRecon.firebase
          .filter(f => f.isPublic)
          .map(f => ({
            cve: `CLOUD-FIREBASE-${f.name.toUpperCase().slice(0, 20)}`,
            cvss: f.dataKeys && f.dataKeys.length > 0 ? 9.5 : 8.0,
            severity: f.dataKeys && f.dataKeys.length > 0 ? "critical" : "high",
            title: `Public Firebase Realtime Database: ${f.name}`,
            cwe: "CWE-284",
            remediation: "Set Firebase Realtime Database rules to require authentication. Change rules from .read: true to .read: auth != null",
            source: f.url,
          })),
      ];

      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "cloud-enum", toolCategory: "cloud_recon",
        rawOutput: [
          `[Cloud Asset Recon] S3 + GCS + Azure + Firebase — ${target}`,
          `Bucket names tested: ${cloudRecon.stats.totalTested}`,
          `Buckets found: ${cloudRecon.stats.existingBuckets} (${cloudRecon.stats.publicBuckets} public, ${cloudRecon.stats.privateBuckets} private)`,
          `  AWS S3: ${cloudRecon.stats.awsFound}  |  GCS: ${cloudRecon.stats.gcsFound}  |  Azure: ${cloudRecon.stats.azureFound}`,
          `Firebase: ${cloudRecon.stats.publicFirebase} public, ${cloudRecon.stats.restrictedFirebase} restricted`,
          "",
          "=== CLOUD BUCKETS FOUND ===",
          ...cloudRecon.buckets.map(b =>
            `  [${b.provider.toUpperCase()}][${b.status.toUpperCase()}] ${b.name}\n    URL: ${b.url}\n    HTTP: ${b.httpStatus}${b.fileCount != null ? `  Files: ${b.fileCount}` : ""}${b.sampleFiles?.length ? `\n    Sample files: ${b.sampleFiles.slice(0, 5).join(", ")}` : ""}`
          ),
          "",
          "=== FIREBASE DATABASES ===",
          cloudRecon.firebase.length === 0 ? "  None found" : "",
          ...cloudRecon.firebase.map(f =>
            `  [${f.status.toUpperCase()}] ${f.url}\n    HTTP: ${f.httpStatus}${f.dataKeys ? `  Keys: ${f.dataKeys.join(", ")}` : ""}${f.dataPreview ? `\n    Preview: ${f.dataPreview.slice(0, 150)}` : ""}`
          ),
          "",
          "=== SSRF METADATA ENDPOINTS (for manual testing) ===",
          ...cloudRecon.ssrfEndpoints.map(e =>
            `  [${e.risk.toUpperCase()}] ${e.provider}\n    Primary URL: ${e.url}\n    ${e.description.slice(0, 200)}`
          ),
        ].join("\n"),
        cloudRecon: cloudRecon as any,
        vulnerabilities: cloudVulns.length ? cloudVulns as any : null,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
      });

      // Insert public bucket/firebase findings
      for (const v of cloudVulns) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: v.title,
          cve: v.cve,
          severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
          cvssScore: String(v.cvss),
          cwe: v.cwe,
          status: "open",
          description: `${v.title}. Resource URL: ${v.source}`,
          remediation: v.remediation,
        });
      }
    }

    // ── Secrets Hunt: store result + create findings ─────────────────────────
    if (isWebAsset && secretsHunt && (secretsHunt.stats.secretsFound > 0 || secretsHunt.stats.gitDirsExposed > 0)) {
      const secretVulns = [
        // GitHub secret findings → vulnerabilities
        ...secretsHunt.githubSecrets
          .filter(s => s.severity === "critical" || s.severity === "high")
          .slice(0, 30)
          .map(s => ({
            cve: `GH-SECRET-${s.type.replace(/\s+/g, "-").toUpperCase().slice(0, 25)}-${s.repo.split("/")[1]?.slice(0, 10).toUpperCase() ?? "REPO"}`,
            cvss: s.severity === "critical" ? 9.5 : 7.5,
            severity: s.severity,
            title: `Exposed ${s.type} in GitHub repo ${s.repo} (${s.file})`,
            cwe: "CWE-312",
            remediation: `Immediately rotate the exposed credential. Use git-filter-repo or BFG Repo Cleaner to remove from history. Enable pre-commit hooks with detect-secrets or trufflehog to prevent future leaks.`,
            source: s.url,
          })),
        // Exposed .git directory → vulnerabilities
        ...secretsHunt.gitDirectories
          .filter(d => d.isExposed)
          .map(d => ({
            cve: `GIT-DIR-EXPOSURE-${d.host.replace(/[^A-Z0-9]/gi, "-").toUpperCase().slice(0, 25)}`,
            cvss: 8.8,
            severity: "high" as const,
            title: `Exposed .git directory on ${d.host}`,
            cwe: "CWE-538",
            remediation: `Block /.git/ path access via web server config (e.g., Nginx: location /.git { deny all; }). Remove .git directory from web root. Rotate any credentials found in repository history.`,
            source: d.url,
          })),
      ];

      const org = secretsHunt.githubOrg;
      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "trufflehog", toolCategory: "secrets",
        rawOutput: [
          `[Secrets Hunter] TruffleHog-equivalent + .git exposure — ${target}`,
          org ? `GitHub Org: ${org.login} (${org.publicRepoCount} public repos, ${secretsHunt.stats.reposScanned} scanned)` : "GitHub org: not found",
          `Repos scanned: ${secretsHunt.stats.reposScanned}  Files scanned: ${secretsHunt.stats.filesScanned}  Commits scanned: ${secretsHunt.stats.commitsScanned}`,
          `Secrets found: ${secretsHunt.stats.secretsFound} (${secretsHunt.stats.verifiedSecrets} verified)`,
          `  Critical: ${secretsHunt.stats.criticalCount}  High: ${secretsHunt.stats.highCount}  Medium: ${secretsHunt.stats.mediumCount}`,
          ``,
          "=== GITHUB SECRETS ===",
          secretsHunt.githubSecrets.length === 0 ? "  No secrets found" : "",
          ...secretsHunt.githubSecrets.map(s =>
            `  [${s.severity.toUpperCase()}][${s.verified ? "VERIFIED" : "PATTERN"}] ${s.type}\n    Repo: ${s.repo}  File: ${s.file}${s.commitSha ? `  Commit: ${s.commitSha}` : ""}\n    Value: ${s.value}\n    Context: ${s.lineContext}`
          ),
          ``,
          "=== .GIT DIRECTORY EXPOSURE ===",
          `Checked: ${secretsHunt.stats.gitDirsChecked} hosts  Exposed: ${secretsHunt.stats.gitDirsExposed}`,
          ...secretsHunt.gitDirectories.filter(d => d.isExposed).map(d =>
            `  [EXPOSED] ${d.host}\n    URL: ${d.url}\n    Branch: ${d.branch ?? "unknown"}\n    Remote: ${d.remoteUrl ?? "unknown"}\n    Last commit: ${d.commitMsg ?? "unknown"}`
          ),
          ...secretsHunt.gitDirectories.filter(d => !d.isExposed).map(d =>
            `  [SAFE] ${d.host}  HTTP ${d.httpStatus}`
          ),
        ].join("\n"),
        secretsHunt: secretsHunt as any,
        vulnerabilities: secretVulns.length ? secretVulns as any : null,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
      });

      for (const v of secretVulns) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: v.title, cve: v.cve,
          severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
          cvssScore: String(v.cvss), cwe: v.cwe, status: "open",
          description: `${v.title}. Source: ${v.source}`,
          remediation: v.remediation,
        });
      }
    }

    // ── Dir Fuzz: store result + create findings for critical exposures ─────────
    if (isWebAsset && dirFuzz && dirFuzz.stats.totalUnique > 0) {
      // Critical paths that being HTTP-200 accessible is a finding
      const CRITICAL_PATHS = new Set([".env",".env.local",".env.backup",".env.prod","config.json","secrets.json","credentials.json","database.sql","backup.sql","dump.sql","backup.zip",".aws/credentials",".htpasswd","id_rsa"]);
      const HIGH_PATHS = new Set(["phpmyadmin","adminer","adminer.php","wp-admin","phpinfo.php","info.php","debug",".git/HEAD"]);
      const MEDIUM_PATHS = new Set(["swagger-ui","swagger","graphql","graphiql","api-docs","openapi.json","actuator","actuator/env","actuator/heapdump","server-status"]);

      const dirVulns: Array<{ cve: string; cvss: number; severity: string; title: string; cwe: string; remediation: string; source: string }> = [];
      const seen = new Set<string>();
      for (const host of dirFuzz.hosts) {
        for (const ep of host.endpoints) {
          if (ep.source !== "fuzz" || ep.statusCode !== 200) continue;
          const pathClean = ep.path.replace(/^\//, "");
          const key = `${pathClean}:${ep.host}`;
          if (seen.has(key)) continue;
          seen.add(key);

          if (CRITICAL_PATHS.has(pathClean)) {
            dirVulns.push({ cve: `EXPOSED-FILE-${pathClean.replace(/[^A-Z0-9]/gi,"-").toUpperCase()}-${ep.host.replace(/[^A-Z0-9]/gi,"-").toUpperCase().slice(0,20)}`, cvss: 9.5, severity: "critical", title: `Sensitive file exposed: ${ep.url}`, cwe: "CWE-538", remediation: `Immediately remove or block public access to ${ep.path}. Add server-level deny rule (e.g. Nginx: location ~ /\\.env { deny all; }). Rotate any credentials contained in the file.`, source: ep.url });
          } else if (HIGH_PATHS.has(pathClean)) {
            dirVulns.push({ cve: `EXPOSED-ADMIN-${pathClean.replace(/[^A-Z0-9]/gi,"-").toUpperCase()}-${ep.host.replace(/[^A-Z0-9]/gi,"-").toUpperCase().slice(0,20)}`, cvss: 7.5, severity: "high", title: `Admin interface exposed: ${ep.url}`, cwe: "CWE-284", remediation: `Restrict access to ${ep.path} via IP allowlist or authentication gateway. Consider relocating admin interfaces off the public web root.`, source: ep.url });
          } else if (MEDIUM_PATHS.has(pathClean)) {
            dirVulns.push({ cve: `EXPOSED-API-DOCS-${pathClean.replace(/[^A-Z0-9]/gi,"-").toUpperCase()}-${ep.host.replace(/[^A-Z0-9]/gi,"-").toUpperCase().slice(0,20)}`, cvss: 5.3, severity: "medium", title: `API documentation/debug endpoint exposed: ${ep.url}`, cwe: "CWE-200", remediation: `Restrict ${ep.path} to authenticated or internal users only. Disable debug endpoints in production.`, source: ep.url });
          }
        }
      }

      const interestingUrls = dirFuzz.hosts.flatMap(h => h.endpoints.filter(e => e.isInteresting || (e.source === "fuzz" && e.statusCode === 200)));

      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "feroxbuster", toolCategory: "web_recon",
        rawOutput: [
          `Directory Fuzzing — ${target}`,
          `Hosts scanned: ${dirFuzz.stats.hostsScanned} (${dirFuzz.stats.hostsLive} live)`,
          `Total unique endpoints: ${dirFuzz.stats.totalUnique}`,
          `  Active scan hits: ${dirFuzz.stats.fuzzHits}`,
          `  Archive sources:  ${dirFuzz.stats.waybackFound}`,
          `  Crawler:          ${dirFuzz.stats.crawledFound}`,
          `  Interesting:      ${dirFuzz.stats.interestingEndpoints}`,
          `  Live (2xx/3xx):   ${dirFuzz.stats.liveEndpoints}`,
          ``,
          "=== ALL_ENDPOINTS_MASTER.TXT ===",
          ...dirFuzz.masterList.slice(0, 200),
          dirFuzz.masterList.length > 200 ? `... (${dirFuzz.masterList.length - 200} more — see report for full list)` : "",
          ``,
          "=== INTERESTING ENDPOINTS ===",
          ...interestingUrls.slice(0, 100).map(e =>
            `  [${e.statusCode}] [${e.source.toUpperCase()}] ${e.url}${e.redirectTo ? ` → ${e.redirectTo}` : ""}`
          ),
        ].join("\n"),
        dirFuzz: dirFuzz as any,
        vulnerabilities: dirVulns.length ? dirVulns as any : null,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
      });

      for (const v of dirVulns) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: v.title, cve: v.cve,
          severity: v.severity as "critical" | "high" | "medium" | "low" | "info",
          cvssScore: String(v.cvss), cwe: v.cwe, status: "open",
          description: `${v.title}. This was discovered by directory fuzzing. Immediate remediation is required.`,
          remediation: v.remediation,
        });
      }
    }

    // ── Nuclei Scan: store result + create findings ───────────────────────────
    if (isWebAsset && vulnScan) {
      const rawLines = [
        `Vulnerability Template Scanner — ${target}`,
        `Hosts scanned: ${vulnScan.stats.hostsScanned} | Findings: ${vulnScan.stats.totalFindings} (${vulnScan.stats.critical} critical, ${vulnScan.stats.high} high, ${vulnScan.stats.medium} medium, ${vulnScan.stats.low} low)`,
        `CORS vulnerable: ${vulnScan.stats.corsVulnerable} | Header issues: ${vulnScan.stats.headerIssues} | Avg header score: ${vulnScan.stats.avgHeaderScore}/100`,
        ``,
        "=== TEMPLATE FINDINGS ===",
        ...vulnScan.findings.map(f => `  [${f.severity.toUpperCase().padEnd(8)}] [${f.category}] ${f.name}`),
        `                          URL: ${vulnScan.findings.map(f => f.url).join("\n")}`,
        ``,
        "=== CORS MISCONFIGURATIONS ===",
        ...vulnScan.cors.map(c => `  [${c.severity.toUpperCase()}] ${c.variant}: ACAO=${c.allowOrigin}${c.allowCredentials ? " + credentials" : ""}`),
        vulnScan.cors.length === 0 ? "  No CORS issues found" : "",
        ``,
        "=== SECURITY HEADER ANALYSIS ===",
        ...vulnScan.headers.map(h => `  ${h.host}: Grade ${h.grade} (${h.score}/100) | Issues: ${h.checks.filter(c => c.issue).map(c => c.name).join(", ") || "none"}`),
      ];

      await db.insert(scanAssetResultsTable).values({
        tenantId, scanId, assetId: asset.id,
        toolName: "nuclei", toolCategory: "vuln_scan",
        rawOutput: rawLines.join("\n"),
        vulnScan: vulnScan as any,
        vulnerabilities: vulnScan.findings.length ? vulnScan.findings as any : null,
        ports: null as any, subdomains: null as any, endpoints: null as any,
        httpInfo: null as any, dnsRecords: null as any, intelligence: null as any,
      });

      // Findings: create DB findings for critical/high/medium template hits
      for (const f of vulnScan.findings) {
        if (f.severity === "info") continue;
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: f.name,
          cve: f.cve ?? f.templateId,
          severity: f.severity,
          cvssScore: f.cvss ? String(f.cvss) : f.severity === "critical" ? "9.0" : f.severity === "high" ? "7.5" : f.severity === "medium" ? "5.3" : "3.1",
          cwe: f.cwe,
          status: "open" as const,
          description: `${f.description} URL: ${f.url}. Evidence: ${f.evidence.slice(0, 300)}`,
          remediation: f.remediation,
        });
      }

      // CORS findings
      for (const c of vulnScan.cors) {
        findingInserts.push({
          tenantId, assetId: asset.id, scanId,
          title: `CORS Misconfiguration (${c.variant}) — ${c.host}`,
          cve: `CORS-${c.variant.toUpperCase().replace(/-/g, "_")}-${c.host.replace(/[^A-Z0-9]/gi, "_").toUpperCase().slice(0, 20)}`,
          severity: c.severity,
          cvssScore: c.severity === "high" ? "8.1" : "5.4",
          cwe: "CWE-942",
          status: "open" as const,
          description: c.description,
          remediation: c.remediation,
        });
      }

      // Header grade D/F → medium finding
      for (const h of vulnScan.headers) {
        if (h.score < 50) {
          findingInserts.push({
            tenantId, assetId: asset.id, scanId,
            title: `Weak Security Headers: ${h.host} (Grade ${h.grade}, ${h.score}/100)`,
            cve: `SEC-HEADERS-WEAK-${h.host.replace(/[^A-Z0-9]/gi, "_").toUpperCase().slice(0, 25)}`,
            severity: "medium" as const,
            cvssScore: "5.3",
            cwe: "CWE-16",
            status: "open" as const,
            description: `Security header analysis scored ${h.score}/100 (Grade ${h.grade}) for ${h.host}. Missing/misconfigured: ${h.checks.filter(c => c.issue).map(c => c.name).join(", ")}.`,
            remediation: "Implement all recommended security headers. Minimum: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy.",
          });
        }
      }
    }

    // Deduplicate by CVE+asset, enrich with EPSS/KEV, then insert
    const uniqueFindings = new Map<string, typeof findingInserts[0]>();
    for (const f of findingInserts) {
      const key = `${f.cve ?? ""}-${f.assetId}`;
      if (!uniqueFindings.has(key)) uniqueFindings.set(key, f);
    }
    const deduped = Array.from(uniqueFindings.values());
    let enriched = deduped;
    try {
      enriched = await enrichFindingsWithEpssKev(deduped) as typeof deduped;
    } catch (err) {
      logger.warn({ err }, "EPSS/KEV enrichment failed — inserting without enrichment (non-fatal)");
    }
    for (let i = 0; i < enriched.length; i += 50) {
      await db.insert(findingsTable).values(enriched.slice(i, i + 50));
    }
    findingTotals.push(enriched.length);

    // ── Passive discovery: save results to history (non-blocking) ─────────────
    // Runs free tools + any configured commercial API tools in the background
    // so the scan result isn't delayed. Results are stored in discovery_results.
    setImmediate(async () => {
      try {
        const discoveryOpts: PassiveDiscoveryOptions = {
          githubToken, shodanApiKey: shodanKey, fofaEmail, fofaApiKey,
          censysApiId, censysApiSecret, intelxApiKey, criminalIpApiKey,
        };
        const discoveryResults = await runPassiveDiscovery(target, discoveryOpts);
        for (const result of discoveryResults) {
          await db.insert(discoveryResultsTable).values({
            tenantId, assetId: asset.id, scanId,
            source: result.source, status: result.status,
            data: result.data as any, summary: result.summary,
          }).catch(() => {/* ignore single-row errors */});
        }
        logger.info({ target, scanId, modules: discoveryResults.map(r => `${r.source}:${r.status}`).join(",") }, "Passive discovery history saved");
      } catch (err) {
        logger.warn({ err, target, scanId }, "Passive discovery background save failed (non-fatal)");
      }
    });

    // Mark all tools done in case any got stuck
    for (const t of toolProgress) {
      if (t.status === "running" || t.status === "queued") {
        Object.assign(t, { status: "done", completedAt: new Date().toISOString(), detail: "Complete" });
      }
    }
  }

  // ── Run assets in parallel, capped at MAX_PARALLEL_ASSETS ─────────────────
  async function runWithConcurrency(items: AssetToolConfigItem[], concurrency: number) {
    const queue = [...items];
    const workers = Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      while (queue.length > 0) {
        const item = queue.shift();
        if (!item) break;
        try {
          await processAsset(item);
        } catch (err) {
          assetErrors.push({ assetId: item.assetId, err });
          logger.error({ err, scanId, assetId: item.assetId }, "Asset pipeline failed (non-fatal — continuing other assets)");
        }
      }
    });
    await Promise.all(workers);
  }

  await runWithConcurrency(assetConfigs, MAX_PARALLEL_ASSETS);

  if (assetErrors.length > 0) {
    logger.warn({ scanId, failedAssets: assetErrors.length }, "Some assets failed during parallel scan");
  }

  totalFindings = findingTotals.reduce((a, b) => a + b, 0);
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
  const scan = await db.select({ tenantId: scansTable.tenantId, status: scansTable.status }).from(scansTable)
    .where(eq(scansTable.id, scanId)).then(r => r[0]);
  const role = req.user!.role;
  const isPrivileged = role === "super_admin" || role === "admin" || role === "manager";
  if (!scan || (!isPrivileged && scan.tenantId !== req.user!.tenantId)) { res.status(404).json({ error: "Scan not found" }); return; }
  const progress = scanProgressMap.get(scanId) ?? [];
  const pos = queuePosition(scanId);
  // Attach queue metadata as a synthetic first entry when scan is waiting
  if (pos > 0) {
    (res as any).json({ queued: true, queuePosition: pos, activeScans, maxConcurrent: MAX_CONCURRENT_SCANS, progress });
    return;
  }
  res.json(progress);
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

  // Enforce ownership verification before scanning.
  // Fetch by ID only (no tenantId filter) — SA/admin can scan cross-tenant assets.
  const scanAssetIds = configs.map(c => c.assetId);
  const assetRows = await db
    .select({ id: assetsTable.id, name: assetsTable.name, verificationStatus: assetsTable.verificationStatus, tenantId: assetsTable.tenantId })
    .from(assetsTable)
    .where(inArray(assetsTable.id, scanAssetIds));
  const unverified = assetRows.filter(a => a.verificationStatus !== "verified");
  if (unverified.length > 0) {
    res.status(422).json({
      error: "Cannot scan unverified assets. Verify ownership before scanning.",
      unverifiedAssets: unverified.map(a => ({ id: a.id, name: a.name })),
    });
    return;
  }

  // Determine effective tenant: if all assets belong to the same client tenant, use that tenant
  // so that the scan record, findings, and tech detections are attributed to the correct tenant.
  const uniqueAssetTenantIds = [...new Set(assetRows.map(a => a.tenantId).filter((t): t is number => t != null))];
  const effectiveTenantId = uniqueAssetTenantIds.length === 1 ? uniqueAssetTenantIds[0] : tenantId;

  // Pipeline config is always loaded from the CALLER's tenant (SA/admin configured the tools)
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

  // Scan record is created under the effective (client) tenant so the client can see it
  const willQueue = activeScans >= MAX_CONCURRENT_SCANS;
  const [scan] = await db.insert(scansTable).values({
    tenantId: effectiveTenantId, name: name ?? `Pipeline Scan — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: willQueue ? "pending" : "running",
    assetIds: configs.map(c => c.assetId), startedAt: willQueue ? null : new Date(), findingsCount: 0,
  }).returning();

  res.status(201).json({
    scanId: scan.id, status: scan.status, assetCount: configs.length, findingsCount: 0,
    queued: willQueue, queuePosition: willQueue ? scanQueue.length + 1 : 0,
  });

  setImmediate(() => {
    enqueueAndRun({ scanId: scan.id, tenantId: effectiveTenantId, userId, configs, allTools, enabledTools }).catch(() => {});
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
  const callerTenantId = req.user!.tenantId;
  const role = req.user!.role;
  const isPrivileged = role === "super_admin" || role === "admin" || role === "manager";

  // Privileged users (admin/SA/manager) can view scans across tenants — important when they
  // run a pipeline scan against a client's asset (scan stored under the client's tenantId).
  const scan = isPrivileged
    ? await db.select().from(scansTable).where(eq(scansTable.id, scanId)).then(r => r[0])
    : await db.select().from(scansTable)
        .where(and(eq(scansTable.id, scanId), eq(scansTable.tenantId, callerTenantId))).then(r => r[0]);
  if (!scan) { res.status(404).json({ error: "Scan not found" }); return; }

  // Use the scan's actual tenantId for tool/result lookups
  const tenantId = isPrivileged ? scan.tenantId : callerTenantId;

  // Fetch all enabled tools for this tenant so we know which tools were configured
  const enabledToolRecords = await db
    .select({ name: securityToolsTable.name, category: securityToolsTable.category })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(toolPipelineStepsTable.toolId, securityToolsTable.id))
    .where(and(eq(toolPipelineStepsTable.tenantId, callerTenantId), eq(toolPipelineStepsTable.isEnabled, true)));
  const configuredTools = enabledToolRecords.map(t => ({
    name: t.name,
    phase: TOOL_PHASE[t.name] ?? 1,
    phaseName: PHASE_NAMES[TOOL_PHASE[t.name] ?? 1] ?? "Recon",
    category: t.category ?? "recon",
  })).sort((a, b) => a.phase - b.phase);

  const scanResults = await db.select().from(scanAssetResultsTable)
    .where(isPrivileged
      ? eq(scanAssetResultsTable.scanId, scanId)
      : and(eq(scanAssetResultsTable.scanId, scanId), eq(scanAssetResultsTable.tenantId, tenantId)));
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
    let jsAnalysis: unknown = null;
    let paramDiscovery: unknown = null;
    let cloudRecon: unknown = null;
    let secretsHunt: unknown = null;
    let dirFuzz: unknown = null;
    let vulnScan: unknown = null;

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
      if (r.jsAnalysis)      { tr.jsAnalysis       = r.jsAnalysis;      jsAnalysis = r.jsAnalysis; }
      if (r.paramDiscovery)  { tr.paramDiscovery   = r.paramDiscovery;  paramDiscovery = r.paramDiscovery; }
      if (r.cloudRecon)      { tr.cloudRecon       = r.cloudRecon;      cloudRecon = r.cloudRecon; }
      if (r.secretsHunt)     { tr.secretsHunt      = r.secretsHunt;     secretsHunt = r.secretsHunt; }
      if (r.dirFuzz)         { tr.dirFuzz          = r.dirFuzz;         dirFuzz = r.dirFuzz; }
      if (r.vulnScan)        { tr.vulnScan         = r.vulnScan;        vulnScan = r.vulnScan; }
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
    // Prefixes used by every secrets-producing scanner:
    //  SEC-      → runSecretsScanner (env files, config files, JS files)
    //  CRED-     → legacy credential findings
    //  JSSEC-    → jsAnalyzer (API keys / secrets embedded in JS bundles)
    //  GH-SECRET-→ secretsHunter (GitHub repo secret scan)
    const SECRET_PREFIXES = ["SEC-", "CRED-", "JSSEC-", "GH-SECRET-"];
    const isSecretFinding = (id: string) => SECRET_PREFIXES.some(p => id.startsWith(p));
    const secretVulns = vulns.filter((v: any) => isSecretFinding(v.cve ?? ""));
    // Remap VulnFinding fields → shape the Secrets card expects: type / value / file
    const secrets = secretVulns.map((v: any) => {
      const titleStr = String(v.title ?? "");
      // "AWS Access Key exposed in /.env" → type = "AWS Access Key"
      const typeMatch = titleStr.match(/^(.+?)\s+(?:exposed|found|detected|discovered)\s+(?:in|at)/i);
      const type = ((typeMatch?.[1] ?? titleStr) || v.cve) ?? "Secret";
      // "Credential discovered at /.env: AKIA****1234" → file = "/.env", value = "AKIA****1234"
      const sourceStr = String(v.source ?? "");
      const sourceMatch = sourceStr.match(/at\s+(\S+)[:\s]+(.+)/);
      const file = sourceMatch?.[1] ?? "";
      const value = sourceMatch?.[2]?.trim() ?? "";
      return { type, value, file, port: (v as any).port ?? null, severity: v.severity, cve: v.cve, remediation: v.remediation };
    });
    const cves = vulns.filter((v: any) => !isSecretFinding(v.cve ?? "") && !v.cve?.startsWith("HDR-") && !v.cve?.startsWith("CWE-"));
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
      jsAnalysis,
      paramDiscovery,
      cloudRecon,
      secretsHunt,
      dirFuzz,
      vulnScan,
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
  const willQueue = activeScans >= MAX_CONCURRENT_SCANS;
  const [scan] = await db.insert(scansTable).values({
    tenantId, name: `${schedule.name} — ${new Date().toLocaleDateString()}`,
    type: "pipeline", status: willQueue ? "pending" : "running",
    assetIds: configs.map(c => c.assetId), startedAt: willQueue ? null : new Date(), findingsCount: 0,
  }).returning();
  res.status(201).json({
    scanId: scan.id, status: scan.status, assetCount: configs.length, findingsCount: 0,
    queued: willQueue, queuePosition: willQueue ? scanQueue.length + 1 : 0,
  });
  setImmediate(() => {
    enqueueAndRun({ scanId: scan.id, tenantId, userId, configs, allTools, enabledTools, scheduleId }).catch(() => {});
  });
});

export default router;
