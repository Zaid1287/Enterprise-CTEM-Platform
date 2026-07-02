import { Router } from "express";
import { exec } from "child_process";
import { promisify } from "util";
import { eq, and, desc, sql } from "drizzle-orm";
import { db, securityToolsTable, toolPipelineStepsTable, toolRunsTable, assetsTable, alertsTable } from "@workspace/db";
import {
  CreateSecurityToolBody, GetSecurityToolParams,
  UpdateSecurityToolParams, UpdateSecurityToolBody,
  DeleteSecurityToolParams,
  RunSecurityToolParams, RunSecurityToolBody,
  SetToolPipelineBody,
  ListToolRunsQueryParams, GetToolRunParams,
  RunPipelineForAssetParams,
} from "@workspace/api-zod";
import { requireAuth, requireRole, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { logAudit } from "../lib/audit";

const router = Router();
router.use(denyExternalMembers);
const execAsync = promisify(exec);

// ── Real tool execution (replaces all simulated output) ───────────────────────
// Attempts to run the tool's configured runCommand against the target.
// Returns real stdout/stderr, or a clear install message if the binary is absent.
async function runToolCommand(
  tool: typeof securityToolsTable.$inferSelect,
  target: string,
): Promise<string> {
  const runCmd = tool.runCommand ?? "";
  const timestamp = new Date().toISOString();

  if (!runCmd) {
    return [
      `[INFO] Tool: ${tool.name}`,
      `[INFO] Target: ${target}`,
      `[INFO] Started: ${timestamp}`,
      `[WARN] No run command configured for this tool.`,
      `[HINT] Open Tool Library → Edit → set a run command (e.g. nmap -sV {target}).`,
    ].join("\n");
  }

  // Sanitize target and substitute {target}, {domain}, {company}, {output}
  const safeTarget = target.replace(/[;&|`$(){}<>!]/g, "").slice(0, 512);
  const domain     = safeTarget.replace(/^https?:\/\//, "").split("/")[0] ?? safeTarget;
  const company    = domain.split(".")[0] ?? domain;
  const outFile    = `/tmp/${tool.name.replace(/[^a-z0-9]/gi, "-")}-${Date.now()}.txt`;

  const cmd = runCmd
    .replace(/\{target\}/g,  safeTarget)
    .replace(/\{domain\}/g,  domain)
    .replace(/\{company\}/g, company)
    .replace(/\{output\}/g,  outFile);

  const header = [
    `[INFO] Tool: ${tool.name}`,
    `[INFO] Target: ${safeTarget}`,
    `[INFO] Command: ${cmd}`,
    `[INFO] Started: ${timestamp}`,
    "",
  ].join("\n");

  try {
    const { stdout, stderr } = await execAsync(cmd, { timeout: 60_000 });
    const body = [stdout, stderr].filter(Boolean).join("\n").trim();
    return `${header}${body || "(no output)"}\n\n[DONE] ${tool.name} completed at ${new Date().toISOString()}`;
  } catch (err: any) {
    const msg  = String(err.message ?? "");
    const sErr = String(err.stderr ?? "");
    const notInstalled =
      err.code === "ENOENT" ||
      msg.includes("not found") ||
      msg.includes("command not found") ||
      sErr.includes("command not found");

    if (notInstalled) {
      return [
        header.trimEnd(),
        `\n[NOT INSTALLED] "${tool.name}" binary was not found on this server.`,
        `[INSTALL]  ${tool.installCommand ?? "See the tool's GitHub page for install instructions."}`,
        `[UPDATE]   ${tool.updateCommand  ?? "N/A"}`,
        `[GITHUB]   ${tool.githubUrl      ?? "N/A"}`,
        `\n[NOTE] Once installed, this tool integrates with the automated scan pipeline.`,
        `[NOTE] Run manually on your workstation: ${cmd}`,
      ].join("\n");
    }

    const errOut = [err.stdout, err.stderr].filter(Boolean).join("\n").trim();
    return [
      header.trimEnd(),
      `\n[ERROR] Exit code ${err.code ?? "unknown"}: ${msg}`,
      errOut ? `\n[OUTPUT]\n${errOut}` : "",
      `\n[DONE] ${tool.name} failed at ${new Date().toISOString()}`,
    ].join("\n");
  }
}

async function enrichRuns(runs: (typeof toolRunsTable.$inferSelect)[]) {
  const allToolIds = [...new Set(runs.map(r => r.toolId))];
  const allAssetIds = [...new Set(runs.filter(r => r.assetId != null).map(r => r.assetId!))];

  const [tools, assets] = await Promise.all([
    allToolIds.length
      ? db.select({ id: securityToolsTable.id, name: securityToolsTable.name }).from(securityToolsTable)
      : Promise.resolve([]),
    allAssetIds.length
      ? db.select({ id: assetsTable.id, name: assetsTable.name }).from(assetsTable)
      : Promise.resolve([]),
  ]);

  const toolMap = new Map(tools.map(t => [t.id, t.name]));
  const assetMap = new Map(assets.map(a => [a.id, a.name]));

  return runs.map(r => ({
    id: r.id,
    tenantId: r.tenantId,
    toolId: r.toolId,
    toolName: toolMap.get(r.toolId) ?? "Unknown Tool",
    assetId: r.assetId ?? null,
    assetName: r.assetId != null ? (assetMap.get(r.assetId) ?? null) : null,
    status: r.status,
    output: r.output,
    triggeredBy: r.triggeredBy,
    startedAt: r.startedAt?.toISOString() ?? null,
    completedAt: r.completedAt?.toISOString() ?? null,
    createdAt: r.createdAt.toISOString(),
  }));
}

async function buildPipelineResponse(tenantId: number) {
  const steps = await db.select().from(toolPipelineStepsTable)
    .where(eq(toolPipelineStepsTable.tenantId, tenantId))
    .orderBy(toolPipelineStepsTable.stepOrder);

  const toolIds = [...new Set(steps.map(s => s.toolId))];
  const tools = toolIds.length
    ? await db.select({ id: securityToolsTable.id, name: securityToolsTable.name, githubUrl: securityToolsTable.githubUrl, category: securityToolsTable.category }).from(securityToolsTable)
    : [];
  const toolMap = new Map(tools.map(t => [t.id, t]));

  return steps.map(s => ({
    id: s.id,
    toolId: s.toolId,
    toolName: toolMap.get(s.toolId)?.name ?? "Unknown",
    toolGithubUrl: toolMap.get(s.toolId)?.githubUrl ?? "",
    toolCategory: toolMap.get(s.toolId)?.category ?? "",
    stepOrder: s.stepOrder,
    isEnabled: s.isEnabled,
  }));
}

// ── IMPORTANT: /tools/pipeline must be registered BEFORE /tools/:toolId ──

router.get("/tools/pipeline", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  res.json(await buildPipelineResponse(req.user!.tenantId));
});

router.put("/tools/pipeline", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = SetToolPipelineBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }

  await db.delete(toolPipelineStepsTable).where(eq(toolPipelineStepsTable.tenantId, req.user!.tenantId));

  if (parsed.data.steps.length > 0) {
    await db.insert(toolPipelineStepsTable).values(
      parsed.data.steps.map(s => ({
        tenantId: req.user!.tenantId,
        toolId: s.toolId,
        stepOrder: s.stepOrder,
        isEnabled: s.isEnabled,
      }))
    );
  }

  res.json(await buildPipelineResponse(req.user!.tenantId));
});

const DEFAULT_TOOLS = [
  { name: "dnsrecon", description: "Full DNS enumeration — A/AAAA/MX/NS/SOA/TXT/SRV/PTR records, SPF/DMARC analysis, zone transfer attempts, reverse DNS, and brute-force; auto-runs on every domain scan via the built-in DNS engine", githubUrl: "https://github.com/darkoperator/dnsrecon", category: "recon", installCommand: "pip3 install dnsrecon", updateCommand: "pip3 install --upgrade dnsrecon", runCommand: "dnsrecon -d {target} -t std,brt,srv,axfr --xml /tmp/dnsrecon-{target}.xml", outputFormat: "xml" },
  { name: "subfinder",  description: "Fast passive subdomain discovery with 40+ data sources (VirusTotal, Chaos, DNSdb, Shodan, Censys, BeVigil, etc.) — integrated into the subdomain engine and auto-runs on every domain scan", githubUrl: "https://github.com/projectdiscovery/subfinder", category: "recon", installCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", updateCommand: "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", runCommand: "subfinder -d {target} -all -json", outputFormat: "json" },
  { name: "findomain",  description: "CT-log-based subdomain enumeration using Certificate Transparency + AlienVault OTX, Wayback CDX, URLScan, RapidDNS, and CommonCrawl passive APIs — integrated into the subdomain engine and auto-runs on every domain scan", githubUrl: "https://github.com/Findomain/Findomain", category: "recon", installCommand: "curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-x86_64.zip && unzip findomain-linux-x86_64.zip && chmod +x findomain", updateCommand: "curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-x86_64.zip && unzip -o findomain-linux-x86_64.zip && chmod +x findomain", runCommand: "findomain -t {target} -q", outputFormat: "text" },
  { name: "alterx",     description: "Smart subdomain permutation wordlist generator — creates up to 10k variations from existing subdomains using dev/staging/prod/cdn patterns; integrated into the subdomain engine", githubUrl: "https://github.com/projectdiscovery/alterx", category: "recon", installCommand: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest", updateCommand: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest", runCommand: "alterx -d {target} -silent", outputFormat: "text" },
  { name: "httpx", description: "Fast and multi-purpose HTTP toolkit for probing web servers", githubUrl: "https://github.com/projectdiscovery/httpx", category: "web_recon", installCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", updateCommand: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", runCommand: "httpx -u {target} -title -status-code -tech-detect -json", outputFormat: "json" },
  { name: "naabu", description: "Fast port scanner with reliability and ease of use in mind", githubUrl: "https://github.com/projectdiscovery/naabu", category: "port_scan", installCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", updateCommand: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest", runCommand: "naabu -host {target} -top-ports 1000 -json", outputFormat: "json" },
  { name: "dnsx", description: "Fast and multi-purpose DNS toolkit for resolution and enumeration", githubUrl: "https://github.com/projectdiscovery/dnsx", category: "recon", installCommand: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", updateCommand: "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest", runCommand: "dnsx -d {target} -resp -a -cname -mx -json", outputFormat: "json" },
  { name: "katana", description: "Next-generation crawling and spidering framework", githubUrl: "https://github.com/projectdiscovery/katana", category: "web_recon", installCommand: "go install github.com/projectdiscovery/katana/cmd/katana@latest", updateCommand: "go install github.com/projectdiscovery/katana/cmd/katana@latest", runCommand: "katana -u {target} -d 3 -json", outputFormat: "json" },
  { name: "mapcidr", description: "CIDR manipulation and aggregation tool for IP range operations", githubUrl: "https://github.com/projectdiscovery/mapcidr", category: "recon", installCommand: "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", updateCommand: "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest", runCommand: "mapcidr -cl {target} -aggregate", outputFormat: "text" },
  { name: "shuffledns", description: "DNS brute force and resolution using massdns as the backend", githubUrl: "https://github.com/projectdiscovery/shuffledns", category: "recon", installCommand: "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", updateCommand: "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest", runCommand: "shuffledns -d {target} -w wordlist.txt -r resolvers.txt", outputFormat: "text" },
  { name: "asnmap", description: "Map ASN numbers to IP CIDR ranges for network reconnaissance", githubUrl: "https://github.com/projectdiscovery/asnmap", category: "recon", installCommand: "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest", updateCommand: "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest", runCommand: "asnmap -a {target} -json", outputFormat: "json" },
  { name: "cdncheck", description: "Detect CDN, WAF, and cloud provider for given IP addresses", githubUrl: "https://github.com/projectdiscovery/cdncheck", category: "recon", installCommand: "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", updateCommand: "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest", runCommand: "cdncheck -i {target} -json", outputFormat: "json" },
  { name: "uncover", description: "Quickly discover exposed hosts using Shodan, Fofa, Censys, and more", githubUrl: "https://github.com/projectdiscovery/uncover", category: "recon", installCommand: "go install github.com/projectdiscovery/uncover/cmd/uncover@latest", updateCommand: "go install github.com/projectdiscovery/uncover/cmd/uncover@latest", runCommand: "uncover -q \"{target}\" -e shodan,censys,fofa -json", outputFormat: "json" },
  { name: "tldfinder", description: "Find all top-level domains associated with an organization", githubUrl: "https://github.com/projectdiscovery/tldfinder", category: "recon", installCommand: "go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest", updateCommand: "go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest", runCommand: "tldfinder -d {target}", outputFormat: "text" },
  { name: "useragent", description: "Browser user agent parsing and random generation for reconnaissance", githubUrl: "https://github.com/projectdiscovery/useragent", category: "web_recon", installCommand: "go install github.com/projectdiscovery/useragent/cmd/useragent@latest", updateCommand: "go install github.com/projectdiscovery/useragent/cmd/useragent@latest", runCommand: "useragent --count 10", outputFormat: "json" },
  { name: "aix", description: "AI-powered LLM integration for automated security reconnaissance workflows", githubUrl: "https://github.com/projectdiscovery/aix", category: "osint", installCommand: "go install github.com/projectdiscovery/aix/cmd/aix@latest", updateCommand: "go install github.com/projectdiscovery/aix/cmd/aix@latest", runCommand: "aix -p \"Enumerate attack surface of {target}\"", outputFormat: "text" },
  { name: "vulnx", description: "Intelligent bot auto shell injector and CMS vulnerability scanner", githubUrl: "https://github.com/anouarbensaad/vulnx", category: "vuln_scan", installCommand: "git clone https://github.com/anouarbensaad/vulnx && pip3 install -r vulnx/requirements.txt", updateCommand: "git -C vulnx pull origin master", runCommand: "python3 vulnx.py -u {target} --dork cms", outputFormat: "text" },
  { name: "goleak", description: "Goroutine leak detector for Go programs — catches resource leaks in tests", githubUrl: "https://github.com/uber-go/goleak", category: "vuln_scan", installCommand: "go get go.uber.org/goleak", updateCommand: "go get go.uber.org/goleak@latest", runCommand: "go test -run TestMain ./... -count=1", outputFormat: "text" },

  // ── ASM: Vulnerability Scanning ──
  { name: "nuclei", description: "Fast template-based vulnerability scanner with 9000+ community templates for CVEs, misconfigs, and exposures", githubUrl: "https://github.com/projectdiscovery/nuclei", category: "vuln_scan", installCommand: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", updateCommand: "nuclei -update-templates && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", runCommand: "nuclei -u {target} -severity critical,high,medium -json", outputFormat: "json" },
  { name: "nikto", description: "Web server scanner that checks for dangerous files, outdated software, and server misconfigurations", githubUrl: "https://github.com/sullo/nikto", category: "vuln_scan", installCommand: "git clone https://github.com/sullo/nikto && apt-get install -y libnet-ssleay-perl", updateCommand: "git -C nikto pull", runCommand: "perl nikto/program/nikto.pl -h {target} -Format json", outputFormat: "json" },
  { name: "wpscan", description: "WordPress security scanner for plugin/theme vulnerabilities, user enumeration, and weak credentials", githubUrl: "https://github.com/wpscanteam/wpscan", category: "vuln_scan", installCommand: "gem install wpscan", updateCommand: "gem update wpscan", runCommand: "wpscan --url {target} --format json --enumerate vp,vt,u", outputFormat: "json" },
  { name: "trufflehog", description: "Scan git repos, S3 buckets, and web surfaces for leaked credentials, API keys, and secrets", githubUrl: "https://github.com/trufflesecurity/trufflehog", category: "vuln_scan", installCommand: "go install github.com/trufflesecurity/trufflehog/v3@latest", updateCommand: "go install github.com/trufflesecurity/trufflehog/v3@latest", runCommand: "trufflehog git https://{target} --json --only-verified", outputFormat: "json" },
  { name: "wapiti", description: "Web application vulnerability auditor — tests for SQLi, XSS, SSRF, XXE, and 30+ attack categories", githubUrl: "https://github.com/wapiti-scanner/wapiti", category: "vuln_scan", installCommand: "pip3 install wapiti3", updateCommand: "pip3 install --upgrade wapiti3", runCommand: "wapiti -u https://{target} --format json -o /tmp/wapiti-{target}.json", outputFormat: "json" },

  // ── ASM: Port & Network Scanning ──
  { name: "masscan", description: "Fastest Internet port scanner — scan entire IPv4 ranges at 10M+ packets/sec", githubUrl: "https://github.com/robertdavidgraham/masscan", category: "port_scan", installCommand: "apt-get install -y masscan", updateCommand: "git clone https://github.com/robertdavidgraham/masscan && make -C masscan", runCommand: "masscan {target} -p0-65535 --rate=1000 --output-format json", outputFormat: "json" },
  { name: "rustscan", description: "Blazing fast port scanner (Rust) that auto-pipes to nmap for service detection", githubUrl: "https://github.com/RustScan/RustScan", category: "port_scan", installCommand: "cargo install rustscan", updateCommand: "cargo install rustscan", runCommand: "rustscan -a {target} --ulimit 5000 -- -sV -sC", outputFormat: "text" },

  // ── ASM: Web Reconnaissance ──
  { name: "feroxbuster", description: "Fast, recursive content discovery tool for finding hidden directories, files, and API endpoints", githubUrl: "https://github.com/epi052/feroxbuster", category: "web_recon", installCommand: "cargo install feroxbuster", updateCommand: "cargo install feroxbuster", runCommand: "feroxbuster -u https://{target} -w /usr/share/wordlists/dirb/common.txt --json", outputFormat: "json" },
  { name: "gobuster", description: "Directory/file, DNS, and vhost brute-force scanner for web attack surface discovery", githubUrl: "https://github.com/OJ/gobuster", category: "web_recon", installCommand: "go install github.com/OJ/gobuster/v3@latest", updateCommand: "go install github.com/OJ/gobuster/v3@latest", runCommand: "gobuster dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -o json", outputFormat: "json" },
  { name: "ffuf", description: "Fast web fuzzer for directory discovery, parameter fuzzing, and virtual host enumeration", githubUrl: "https://github.com/ffuf/ffuf", category: "web_recon", installCommand: "go install github.com/ffuf/ffuf/v2@latest", updateCommand: "go install github.com/ffuf/ffuf/v2@latest", runCommand: "ffuf -u https://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -of json", outputFormat: "json" },
  { name: "whatweb", description: "Web technology fingerprinter — detects CMS, frameworks, analytics, JavaScript libraries, and server details", githubUrl: "https://github.com/urbanadventurer/WhatWeb", category: "web_recon", installCommand: "gem install whatweb", updateCommand: "gem update whatweb", runCommand: "whatweb --log-json=/dev/stdout {target}", outputFormat: "json" },
  { name: "wafw00f", description: "Identify and fingerprint WAF (Web Application Firewall) products protecting a target", githubUrl: "https://github.com/EnableSecurity/wafw00f", category: "web_recon", installCommand: "pip3 install wafw00f", updateCommand: "pip3 install --upgrade wafw00f", runCommand: "wafw00f {target} -f json", outputFormat: "json" },
  { name: "wappalyzer", description: "Technology fingerprinting engine — identifies CMS, JS frameworks, CDN, analytics, security products, and 60+ tech categories via HTTP headers, HTML patterns, cookies, and script signatures", githubUrl: "https://github.com/enthec/webappanalyzer", category: "web_recon", installCommand: "built-in (no install required)", updateCommand: "built-in", runCommand: "wappalyzer {target}", outputFormat: "json" },
  { name: "webcheck", description: "Comprehensive web security checker — audits HTTP security headers (HSTS, CSP, X-Frame-Options, CORP, COEP), cookie flags, TLS configuration, and security policy compliance", githubUrl: "https://github.com/lissy93/web-check", category: "web_recon", installCommand: "built-in (no install required)", updateCommand: "built-in", runCommand: "webcheck {target}", outputFormat: "json" },

  // ── Module 5: Screenshot Engine ──
  { name: "gowitness",  description: "Web screenshot utility using system Chromium — captures index, login, signup, admin, and API pages with full-page renders and HTTP metadata", githubUrl: "https://github.com/sensepost/gowitness", category: "screenshot", installCommand: "built-in (system chromium)", updateCommand: "built-in", runCommand: "gowitness single --url https://{target}", outputFormat: "json" },
  { name: "eyewitness", description: "EyeWitness — visual recon tool that captures web screenshots, server headers, and identifies default credentials on web-exposed services", githubUrl: "https://github.com/RedSiege/EyeWitness", category: "screenshot", installCommand: "built-in (system chromium)", updateCommand: "built-in", runCommand: "eyewitness --web --single https://{target}", outputFormat: "json" },
  { name: "snapback",   description: "Snapback — screenshot and sensitive info disclosure scanner for web pages, detecting hardcoded API keys, tokens, credentials, and internal endpoints in page source", githubUrl: "https://github.com/dekz/snapback", category: "screenshot", installCommand: "built-in (system chromium)", updateCommand: "built-in", runCommand: "snapback scan {target}", outputFormat: "json" },

  // ── ASM: SSL/TLS Inspection ──
  { name: "testssl", description: "Comprehensive SSL/TLS configuration checker — cipher suites, cert validity, heartbleed, POODLE, BEAST, etc.", githubUrl: "https://github.com/drwetter/testssl.sh", category: "ssl_check", installCommand: "git clone https://github.com/drwetter/testssl.sh", updateCommand: "git -C testssl.sh pull", runCommand: "bash testssl.sh/testssl.sh --jsonfile /tmp/testssl-{target}.json {target}", outputFormat: "json" },
  { name: "sslscan", description: "SSL/TLS scanner that checks supported ciphers, protocols, certificate details, and Heartbleed", githubUrl: "https://github.com/rbsec/sslscan", category: "ssl_check", installCommand: "apt-get install -y sslscan", updateCommand: "apt-get install -y sslscan", runCommand: "sslscan --xml=/dev/stdout {target}", outputFormat: "xml" },

  // ── ASM: Recon & OSINT ──
  { name: "amass", description: "Enterprise-grade attack surface mapping — DNS enumeration, certificate transparency, OSINT, and graph analysis", githubUrl: "https://github.com/owasp-amass/amass", category: "recon", installCommand: "go install github.com/owasp-amass/amass/v4/...@master", updateCommand: "go install github.com/owasp-amass/amass/v4/...@master", runCommand: "amass enum -d {target} -json /tmp/amass-{target}.json", outputFormat: "json" },
  { name: "gau", description: "Fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl for attack surface discovery", githubUrl: "https://github.com/lc/gau", category: "recon", installCommand: "go install github.com/lc/gau/v2/cmd/gau@latest", updateCommand: "go install github.com/lc/gau/v2/cmd/gau@latest", runCommand: "gau {target} --json", outputFormat: "json" },
  { name: "cloud_enum", description: "Multi-cloud OSINT tool to enumerate AWS S3, Azure blobs, and GCP buckets for an organization", githubUrl: "https://github.com/initstring/cloud_enum", category: "recon", installCommand: "git clone https://github.com/initstring/cloud_enum && pip3 install -r cloud_enum/requirements.txt", updateCommand: "git -C cloud_enum pull", runCommand: "python3 cloud_enum/cloud_enum.py -k {target} --threads 5", outputFormat: "text" },
  { name: "s3scanner", description: "Scan for misconfigured AWS S3 buckets — checks public access, ACLs, and object listings", githubUrl: "https://github.com/sa7mon/S3Scanner", category: "recon", installCommand: "go install github.com/sa7mon/S3Scanner@latest", updateCommand: "go install github.com/sa7mon/S3Scanner@latest", runCommand: "S3Scanner scan --bucket {target} --json", outputFormat: "json" },
  { name: "theHarvester", description: "OSINT tool for gathering emails, subdomains, hosts, employee names, and IPs from public sources", githubUrl: "https://github.com/laramies/theHarvester", category: "osint", installCommand: "git clone https://github.com/laramies/theHarvester && pip3 install -r theHarvester/requirements/base.txt", updateCommand: "git -C theHarvester pull", runCommand: "python3 theHarvester/theHarvester.py -d {target} -b all -f /tmp/theharvester-{target}", outputFormat: "json" },
  { name: "maltego", description: "Visual link analysis and OSINT platform for mapping relationships between domains, IPs, and people", githubUrl: "https://github.com/MaltegoTech/maltego-trx", category: "osint", installCommand: "pip3 install maltego-trx", updateCommand: "pip3 install --upgrade maltego-trx", runCommand: "python3 -m maltego_trx.transform {target}", outputFormat: "json" },
];

async function seedDefaultTools(tenantId: number, userId: number): Promise<void> {
  const existing = await db.select({ name: securityToolsTable.name }).from(securityToolsTable)
    .where(eq(securityToolsTable.tenantId, tenantId));
  const existingNames = new Set(existing.map(t => t.name.toLowerCase()));
  const toInsert = DEFAULT_TOOLS.filter(t => !existingNames.has(t.name.toLowerCase()));
  if (toInsert.length === 0) return;
  await db.insert(securityToolsTable).values(
    toInsert.map(t => ({ ...t, tenantId, isActive: true, createdBy: userId }))
  );
}

function mapTool(t: typeof securityToolsTable.$inferSelect) {
  return {
    id: t.id, tenantId: t.tenantId, name: t.name, description: t.description,
    githubUrl: t.githubUrl, category: t.category, runCommand: t.runCommand,
    installCommand: t.installCommand, updateCommand: t.updateCommand, outputFormat: t.outputFormat,
    isActive: t.isActive, createdBy: t.createdBy,
    currentVersion: t.currentVersion ?? null,
    latestVersion: t.latestVersion ?? null,
    toolUpdateCheckedAt: t.toolUpdateCheckedAt ? t.toolUpdateCheckedAt.toISOString() : null,
    createdAt: t.createdAt.toISOString(),
  };
}

router.post("/tools/seed-defaults", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  const existing = await db.select({ name: securityToolsTable.name }).from(securityToolsTable)
    .where(eq(securityToolsTable.tenantId, tenantId));
  const existingNames = new Set(existing.map(t => t.name.toLowerCase()));
  const toInsert = DEFAULT_TOOLS.filter(t => !existingNames.has(t.name.toLowerCase()));
  if (toInsert.length === 0) { res.json({ added: 0, message: "All default tools already present" }); return; }
  await db.insert(securityToolsTable).values(
    toInsert.map(t => ({ ...t, tenantId, isActive: true, createdBy: req.user!.id }))
  );
  res.json({ added: toInsert.length, message: `Added ${toInsert.length} default tool(s)` });
});

router.get("/tools", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const tenantId = req.user!.tenantId;
  await seedDefaultTools(tenantId, req.user!.id);

  const tools = await db.select().from(securityToolsTable)
    .where(eq(securityToolsTable.tenantId, tenantId))
    .orderBy(securityToolsTable.createdAt);

  res.json(tools.map(mapTool));
});

router.post("/tools", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const parsed = CreateSecurityToolBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }
  const [tool] = await db.insert(securityToolsTable).values({
    ...parsed.data,
    tenantId: req.user!.tenantId,
    createdBy: req.user!.id,
  }).returning();
  await logAudit(req.user!, "create_tool", "security_tool", tool.id);
  res.status(201).json({
    ...tool,
    installCommand: tool.installCommand, updateCommand: tool.updateCommand, outputFormat: tool.outputFormat,
    createdAt: tool.createdAt.toISOString(),
  });
});

router.get("/tools/:toolId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = GetSecurityToolParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }
  const [tool] = await db.select().from(securityToolsTable)
    .where(and(eq(securityToolsTable.id, p.data.toolId), eq(securityToolsTable.tenantId, req.user!.tenantId)));
  if (!tool) { res.status(404).json({ error: "Tool not found" }); return; }
  res.json({ ...tool, createdAt: tool.createdAt.toISOString() });
});

router.patch("/tools/:toolId", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = UpdateSecurityToolParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }
  const parsed = UpdateSecurityToolBody.safeParse(req.body);
  if (!parsed.success) { res.status(400).json(parsed.error.issues); return; }
  const [tool] = await db.update(securityToolsTable).set(parsed.data as any)
    .where(and(eq(securityToolsTable.id, p.data.toolId), eq(securityToolsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!tool) { res.status(404).json({ error: "Tool not found" }); return; }
  res.json({ ...tool, createdAt: tool.createdAt.toISOString() });
});

router.delete("/tools/:toolId", requireAuth, requireRole("admin", "super_admin"), async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = DeleteSecurityToolParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }
  const [tool] = await db.delete(securityToolsTable)
    .where(and(eq(securityToolsTable.id, p.data.toolId), eq(securityToolsTable.tenantId, req.user!.tenantId)))
    .returning();
  if (!tool) { res.status(404).json({ error: "Tool not found" }); return; }
  await logAudit(req.user!, "delete_tool", "security_tool", tool.id);
  res.sendStatus(204);
});

router.post("/tools/:toolId/run", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = RunSecurityToolParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }
  const body = RunSecurityToolBody.safeParse(req.body);
  if (!body.success) { res.status(400).json(body.error.issues); return; }

  const [tool] = await db.select().from(securityToolsTable)
    .where(and(eq(securityToolsTable.id, p.data.toolId), eq(securityToolsTable.tenantId, req.user!.tenantId)));
  if (!tool) { res.status(404).json({ error: "Tool not found" }); return; }

  const targetIds = (body.data as any).assetIds ?? ((body.data as any).assetId ? [(body.data as any).assetId] : []);

  const runs: (typeof toolRunsTable.$inferSelect)[] = [];

  if (targetIds.length === 0) {
    const startedAt = new Date();
    const output = await runToolCommand(tool, "");
    const [run] = await db.insert(toolRunsTable).values({
      tenantId: req.user!.tenantId,
      toolId: tool.id,
      status: "completed",
      output,
      triggeredBy: req.user!.id,
      startedAt,
      completedAt: new Date(),
    }).returning();
    runs.push(run);
  } else {
    for (const assetId of targetIds) {
      const [asset] = await db.select().from(assetsTable)
        .where(and(eq(assetsTable.id, assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
      const startedAt = new Date();
      const output = asset
        ? await runToolCommand(tool, asset.value)
        : `[ERROR] Asset not found: ${assetId}`;
      const [run] = await db.insert(toolRunsTable).values({
        tenantId: req.user!.tenantId,
        toolId: tool.id,
        assetId,
        status: "completed",
        output,
        triggeredBy: req.user!.id,
        startedAt,
        completedAt: new Date(),
      }).returning();
      runs.push(run);
    }
  }

  await logAudit(req.user!, "run_tool", "security_tool", tool.id);

  // Create an alert for each completed/failed tool run
  for (const run of runs) {
    const failed = run.output?.startsWith("[ERROR]") ?? false;
    const targetName = run.assetId
      ? (await db.select({ name: assetsTable.name }).from(assetsTable).where(eq(assetsTable.id, run.assetId)).then(r => r[0]?.name ?? `Asset #${run.assetId}`))
      : "no target";
    await db.insert(alertsTable).values({
      tenantId: req.user!.tenantId,
      title: `${tool.name} run ${failed ? "failed" : "completed"}`,
      message: `Tool "${tool.name}" ${failed ? "failed" : "completed successfully"} against ${targetName}.`,
      severity: failed ? "high" : "low",
      type: "scan_complete",
      isRead: false,
    });
  }

  res.json(await enrichRuns(runs));
});

router.post("/assets/:assetId/run-pipeline", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = RunPipelineForAssetParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }

  const [asset] = await db.select().from(assetsTable)
    .where(and(eq(assetsTable.id, p.data.assetId), eq(assetsTable.tenantId, req.user!.tenantId)));
  if (!asset) { res.status(404).json({ error: "Asset not found" }); return; }

  const steps = await db.select().from(toolPipelineStepsTable)
    .where(and(eq(toolPipelineStepsTable.tenantId, req.user!.tenantId), eq(toolPipelineStepsTable.isEnabled, true)))
    .orderBy(toolPipelineStepsTable.stepOrder);

  if (steps.length === 0) { res.json([]); return; }

  const tools = await db.select().from(securityToolsTable)
    .where(eq(securityToolsTable.tenantId, req.user!.tenantId));
  const toolMap = new Map(tools.map(t => [t.id, t]));

  const runs: (typeof toolRunsTable.$inferSelect)[] = [];
  for (const step of steps) {
    const tool = toolMap.get(step.toolId);
    if (!tool || !tool.isActive) continue;
    const startedAt = new Date();
    const output = await runToolCommand(tool, asset.value);
    const [run] = await db.insert(toolRunsTable).values({
      tenantId: req.user!.tenantId,
      toolId: tool.id,
      assetId: asset.id,
      status: "completed",
      output,
      triggeredBy: req.user!.id,
      startedAt,
      completedAt: new Date(),
    }).returning();
    runs.push(run);
  }

  await logAudit(req.user!, "run_pipeline", "asset", asset.id);
  res.json(await enrichRuns(runs));
});

router.get("/tool-runs", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const q = ListToolRunsQueryParams.safeParse(req.query);
  const filters = [eq(toolRunsTable.tenantId, req.user!.tenantId)];
  if (q.success) {
    if ((q.data as any).toolId)  filters.push(eq(toolRunsTable.toolId, Number((q.data as any).toolId)));
    if ((q.data as any).assetId) filters.push(eq(toolRunsTable.assetId, Number((q.data as any).assetId)));
    if ((q.data as any).status)  filters.push(eq(toolRunsTable.status, (q.data as any).status));
  }
  const page     = Math.max(1, Number((q.success && (q.data as any).page)     || 1));
  const pageSize = Math.min(100, Math.max(1, Number((q.success && (q.data as any).pageSize) || 20)));
  const offset   = (page - 1) * pageSize;

  const [countRow, runsRaw] = await Promise.all([
    db.select({ total: sql<number>`count(*)::int` }).from(toolRunsTable).where(and(...filters)),
    db.select().from(toolRunsTable).where(and(...filters)).orderBy(desc(toolRunsTable.createdAt)).limit(pageSize).offset(offset),
  ]);
  const total = countRow[0]?.total ?? 0;
  const runs  = await enrichRuns(runsRaw);
  res.json({ runs, total, page, pageSize });
});

// ── Scanner health — which binaries are available ─────────────────────────────
router.get("/tools/health", requireAuth, async (_req, res): Promise<void> => {
  const TOOLS = [
    { name: "nuclei",      binary: "nuclei",      category: "vuln_scan",  description: "Nuclei — template-based vulnerability scanner" },
    { name: "subfinder",   binary: "subfinder",   category: "recon",      description: "Subfinder — passive subdomain enumeration" },
    { name: "nmap",        binary: "nmap",        category: "port_scan",  description: "Nmap — network port scanner" },
    { name: "naabu",       binary: "naabu",       category: "port_scan",  description: "Naabu — fast port scanner" },
    { name: "masscan",     binary: "masscan",     category: "port_scan",  description: "Masscan — high-speed port scanner" },
    { name: "ffuf",        binary: "ffuf",        category: "fuzzing",    description: "ffuf — web fuzzer / directory bruteforce" },
    { name: "nikto",       binary: "nikto",       category: "web_vuln",   description: "Nikto — web server vulnerability scanner" },
    { name: "amass",       binary: "amass",       category: "recon",      description: "Amass — attack surface enumeration" },
    { name: "katana",      binary: "katana",      category: "crawling",   description: "Katana — web crawler / endpoint discovery" },
    { name: "dnsx",        binary: "dnsx",        category: "dns",        description: "dnsx — DNS toolkit" },
    { name: "gobuster",    binary: "gobuster",    category: "fuzzing",    description: "Gobuster — directory/DNS bruteforce" },
    { name: "feroxbuster", binary: "feroxbuster", category: "fuzzing",    description: "Feroxbuster — recursive content discovery" },
    { name: "dalfox",      binary: "dalfox",      category: "web_vuln",   description: "Dalfox — XSS scanner" },
    { name: "httpx",       binary: "httpx",       category: "probing",    description: "httpx — HTTP toolkit / web prober" },
    { name: "chromium",    binary: "chromium",    category: "screenshot", description: "Chromium — headless browser for screenshots" },
    { name: "shuffledns",  binary: "shuffledns",  category: "dns",        description: "shuffleDNS — DNS bruteforce resolver" },
    { name: "wpscan",      binary: "wpscan",      category: "web_vuln",   description: "WPScan — WordPress vulnerability scanner" },
    { name: "dnsx-alt",    binary: "dnsx",        category: "dns",        description: "dnsx (alt) — additional DNS alias check" },
  ];

  const { execFileSync } = await import("child_process");
  const { execFile } = await import("child_process");
  const { promisify } = await import("util");
  const execFileAsync = promisify(execFile);

  async function checkTool(tool: (typeof TOOLS)[number]) {
    let path: string | undefined;
    try {
      path = execFileSync("which", [tool.binary], { encoding: "utf8", timeout: 2000 }).trim();
    } catch {
      return { ...tool, available: false, path: undefined, version: undefined };
    }
    let version: string | undefined;
    for (const flag of ["--version", "-version", "-V"]) {
      try {
        const { stdout, stderr } = await execFileAsync(tool.binary, [flag], { timeout: 3000 });
        const raw = (stdout || stderr).split("\n")[0].trim().slice(0, 80);
        if (raw) { version = raw; break; }
      } catch (e: any) {
        const raw = (e?.stderr ?? e?.stdout ?? "").split("\n")[0].trim().slice(0, 80);
        if (raw) { version = raw; break; }
      }
    }
    return { ...tool, available: true, path, version };
  }

  // Deduplicate by binary name before checking
  const seen = new Set<string>();
  const unique = TOOLS.filter(t => { if (seen.has(t.binary)) return false; seen.add(t.binary); return true; });

  const results = await Promise.all(unique.map(checkTool));
  const available = results.filter(r => r.available).length;

  res.json({
    tools: results,
    summary: { total: results.length, available, missing: results.length - available },
    checkedAt: new Date().toISOString(),
  });
});

router.get("/tool-runs/:runId", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const p = GetToolRunParams.safeParse(req.params);
  if (!p.success) { res.status(400).json({ error: p.error.message }); return; }
  const [run] = await db.select().from(toolRunsTable)
    .where(and(eq(toolRunsTable.id, p.data.runId), eq(toolRunsTable.tenantId, req.user!.tenantId)));
  if (!run) { res.status(404).json({ error: "Run not found" }); return; }
  const [enriched] = await enrichRuns([run]);
  res.json(enriched);
});

export default router;
