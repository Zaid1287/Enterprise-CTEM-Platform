import { eq, and } from "drizzle-orm";
import { db, tenantsTable, usersTable, securityToolsTable, cdnWhitelistTable, toolPipelineStepsTable, complianceControlsTable, complianceFrameworksTable, alertRulesTable } from "@workspace/db";
import { hashPassword } from "./auth";
import { logger } from "./logger";

// ── Global platform tenant ID cache ───────────────────────────────────────────
// The tool catalog and pipeline are global — always owned by the platform tenant.
let _cachedPlatformTenantId: number | null = null;
export async function getPlatformTenantId(): Promise<number> {
  if (_cachedPlatformTenantId !== null) return _cachedPlatformTenantId;
  const [pt] = await db.select({ id: tenantsTable.id })
    .from(tenantsTable).where(eq(tenantsTable.isPlatform, true)).limit(1);
  if (!pt) throw new Error("Platform tenant not found — cannot resolve global pipeline");
  _cachedPlatformTenantId = pt.id;
  return _cachedPlatformTenantId;
}

// ── Built-in tool definitions ──────────────────────────────────────────────────
// These are auto-seeded for every tenant on startup so they always appear in
// the tool catalog and pipeline, even before the first scan is initiated.

export const BUILTIN_TOOL_DEFS = [
  // Web reconnaissance
  { name: "wappalyzer",   description: "Technology fingerprinting engine — identifies CMS, JS frameworks, CDN, analytics, security products, and 60+ tech categories via HTTP headers, HTML patterns, cookies, and script signatures",                                            category: "web_recon",  githubUrl: "https://github.com/enthec/webappanalyzer",                   runCommand: "wappalyzer {target}" },
  { name: "webcheck",     description: "Comprehensive web security checker — audits HTTP security headers (HSTS, CSP, X-Frame-Options, CORP, COEP), cookie flags, TLS configuration, and security policy compliance",                                                              category: "web_recon",  githubUrl: "https://github.com/lissy93/web-check",                       runCommand: "webcheck {target}" },
  // Screenshots
  { name: "gowitness",    description: "Web screenshot utility using system Chromium — captures index, login, signup, admin, and API pages with full-page renders and HTTP metadata",                                                                                               category: "screenshot", githubUrl: "https://github.com/sensepost/gowitness",                      runCommand: "gowitness single --url https://{target}" },
  { name: "eyewitness",   description: "Visual recon tool that captures web screenshots, server headers, and identifies default credentials on web-exposed services",                                                                                                               category: "screenshot", githubUrl: "https://github.com/RedSiege/EyeWitness",                     runCommand: "eyewitness --web --single https://{target}" },
  { name: "snapback",     description: "Screenshot and sensitive info disclosure scanner for web pages, detecting hardcoded API keys, tokens, credentials, and internal endpoints",                                                                                                 category: "screenshot", githubUrl: "https://github.com/dekz/snapback",                           runCommand: "snapback scan {target}" },
  // Subdomain enumeration
  { name: "subfinder",    description: "Fast passive subdomain discovery with 40+ data sources (VirusTotal, Chaos, DNSdb, Shodan, etc.) — auto-runs on every domain asset scan",                                                                                                  category: "recon",      githubUrl: "https://github.com/projectdiscovery/subfinder",              runCommand: "subfinder -d {target} -all -silent" },
  { name: "findomain",    description: "CT-log-based subdomain finder using Certificate Transparency + multiple passive sources — auto-runs on every domain asset scan",                                                                                                            category: "recon",      githubUrl: "https://github.com/Findomain/Findomain",                     runCommand: "findomain -t {target} -q" },
  { name: "httpx",        description: "Fast multi-purpose HTTP probing — status codes, tech detection, web server, page titles, redirect chains — probes all discovered subdomains",                                                                                              category: "web_recon",  githubUrl: "https://github.com/projectdiscovery/httpx",                  runCommand: "httpx -u {target} -json -status-code -title -tech-detect" },
  { name: "dnsx",         description: "Fast bulk DNS resolver and brute-forcer — resolves all subdomain candidates and active DNS brute-force with built-in wordlist",                                                                                                            category: "recon",      githubUrl: "https://github.com/projectdiscovery/dnsx",                   runCommand: "dnsx -d {target} -silent -a" },
  { name: "alterx",       description: "Smart subdomain permutation wordlist generator — creates variations from existing subdomains using customisable patterns for active discovery",                                                                                             category: "recon",      githubUrl: "https://github.com/projectdiscovery/alterx",                 runCommand: "alterx -d {target} -silent" },
  // Endpoint discovery / URL harvesting
  { name: "gau",          description: "GetAllURLs — aggregates historical URLs from Wayback Machine, Common Crawl, URLScan.io, and OTX AlienVault; auto-runs passive URL harvesting on every domain scan",                                                                        category: "web_recon",  githubUrl: "https://github.com/lc/gau",                                  runCommand: "gau {target}" },
  { name: "waybackurls",  description: "Wayback Machine CDX API client — queries Internet Archive for all historically crawled URLs for a domain, revealing endpoints no longer publicly linked",                                                                                   category: "web_recon",  githubUrl: "https://github.com/tomnomnom/waybackurls",                   runCommand: "waybackurls {target}" },
  { name: "katana",       description: "JS-aware web crawler (ProjectDiscovery) — renders pages with Puppeteer, intercepts XHR/fetch network requests, parses JS bundles for embedded API routes and endpoints",                                                                   category: "web_recon",  githubUrl: "https://github.com/projectdiscovery/katana",                 runCommand: "katana -u https://{target} -js-crawl -silent" },
  { name: "hakrawler",    description: "Fast web crawler — extracts URLs from HTML anchor/form tags, JS src references, sitemaps, and robots.txt; crawls up to 80 pages per scan",                                                                                                 category: "web_recon",  githubUrl: "https://github.com/hakluke/hakrawler",                        runCommand: "hakrawler -url https://{target} -depth 3 -scope subs" },
  { name: "uro",          description: "URL deduplication & normalization — collapses parameterized URLs with identical structure, removes duplicate paths, and merges all harvested URLs from GAU, Wayback, Katana, Hakrawler, and wordlist probe",                               category: "web_recon",  githubUrl: "https://github.com/s0md3v/uro",                              runCommand: "uro" },
  { name: "feroxbuster",  description: "Fast directory & file brute-forcer — actively probes 400+ paths from a built-in SecLists-derived wordlist to discover hidden admin panels, API endpoints, config files, backups, and sensitive paths not found through passive harvesting", category: "web_recon",  githubUrl: "https://github.com/epi052/feroxbuster",                      runCommand: "feroxbuster -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/common.txt --silent" },
  // JavaScript Analysis
  { name: "linkfinder",   description: "JavaScript endpoint extractor — fetches all JS files from target pages and applies LinkFinder regex patterns (paths, fetch/axios/XHR calls, route definitions) to surface API endpoints, hidden routes, and internal URLs embedded in client-side code", category: "web_recon",  githubUrl: "https://github.com/GerbenJavado/LinkFinder",                 runCommand: "python linkfinder.py -i https://{target} -d -o cli" },
  { name: "secretfinder", description: "JavaScript secret scanner — runs SecretFinder regex patterns across all discovered JS files to detect exposed AWS keys, API tokens, OAuth credentials, private keys, JWTs, hardcoded passwords, internal network URLs, GraphQL queries, and email addresses", category: "web_recon",  githubUrl: "https://github.com/m4ll0k/SecretFinder",                    runCommand: "python SecretFinder.py -i https://{target} -e -o cli" },
  // Cloud Asset Recon
  { name: "cloud-enum",    description: "Cloud storage enumeration — derives bucket/container naming patterns from the target domain and tests S3, GCS, and Azure Blob Storage for public access, listable buckets, and exposed files; auto-runs on every domain scan", category: "cloud_recon", githubUrl: "https://github.com/initstring/cloud_enum",    runCommand: "cloud_enum.py -k {company} --quickscan" },
  { name: "GrayhatWarfare",description: "Cloud bucket search engine — cross-references target domain and company name against public bucket indexes to surface exposed S3, GCS, and Azure Blob Storage containers with real file listings", category: "cloud_recon", githubUrl: "https://grayhatwarfare.com",                   runCommand: "curl 'https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={company}'" },
  { name: "firebase-recon",description: "Firebase database exposure checker — probes Firebase Realtime Database and Cloud Firestore URLs derived from target name for unauthenticated read access; public databases can leak all stored user data", category: "cloud_recon", githubUrl: "https://github.com/Turr0n/firebase",           runCommand: "python firebase.py --domain {target} --firebase" },
  // Vulnerability Scanning
  { name: "nuclei",   description: "Template-based vulnerability scanner — runs 40+ purpose-built detection templates across every live host to find exposed admin panels (phpMyAdmin, Adminer, Kibana, Jenkins, Grafana), sensitive file leaks (.env, .git, AWS credentials, SSH keys), misconfigurations (Spring Actuator, Symfony profiler, Laravel debug), known CVEs (CVE-2017-9841 PHPUnit RCE), and technology-specific weaknesses; CORS misconfiguration testing (reflected-origin, null-origin, subdomain-confusion); full security header analysis with scoring", category: "vuln_scan", githubUrl: "https://github.com/projectdiscovery/nuclei", runCommand: "nuclei -u https://{target} -as -tags cve,exposed-panels,misconfig,default-logins -o nuclei_output.json -json" },
  { name: "nikto",    description: "Web server vulnerability scanner — probes for 6700+ dangerous files, outdated server software, and version-specific issues; complements Nuclei by detecting server misconfigurations, CGI vulnerabilities, and missing security headers", category: "vuln_scan", githubUrl: "https://github.com/sullo/nikto", runCommand: "nikto -h {target} -o nikto_output.xml -Format xml -timeout 10" },
  { name: "dalfox",   description: "Parameter analysis and XSS scanner — discovers and validates reflected and DOM-based cross-site scripting vulnerabilities across discovered endpoints using smart payloads", category: "vuln_scan", githubUrl: "https://github.com/hahwul/dalfox", runCommand: "dalfox url https://{target} --deep-domxss --output dalfox_output.txt" },
  // Directory Fuzzing
  { name: "feroxbuster", description: "Recursive directory + file brute-forcer — uses an embedded 240-path wordlist to discover hidden admin panels, API endpoints, backup files, and config leaks across the primary target and all discovered live subdomains via concurrent HEAD probes; results merged with passive URL sources", category: "web_recon", githubUrl: "https://github.com/epi052/feroxbuster",                                  runCommand: "feroxbuster -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 --smart-info -o ferox_output.txt" },
  { name: "gau",         description: "GetAllUrls — fetches all known URLs for the target from Wayback Machine CDX API and AlienVault OTX passive sources; surfaces historical endpoints, forgotten API paths, and archived sensitive files without sending a single request to the target", category: "web_recon", githubUrl: "https://github.com/lc/gau",                                            runCommand: "gau --threads 5 --subs {target} | tee gau_output.txt" },
  { name: "katana",      description: "Next-generation web crawler — crawls the target homepage and follows all internal links (href, src, action, data-url attributes and JS string paths) to map the live application surface; runs after GAU to complement passive discovery with active crawling", category: "web_recon", githubUrl: "https://github.com/projectdiscovery/katana",                          runCommand: "katana -u https://{target} -d 3 -jc -o katana_output.txt" },
  { name: "hakrawler",   description: "Simple, fast HTTP crawler — extracts links and endpoints from HTML responses, form actions, and JS files; contributes to the master endpoint list alongside feroxbuster, GAU, and Wayback results", category: "web_recon", githubUrl: "https://github.com/hakluke/hakrawler",                                      runCommand: "echo 'https://{target}' | hakrawler -depth 3 -scope yolo -u | tee hakrawler_output.txt" },
  // Secrets Hunting
  { name: "trufflehog",   description: "Git secrets scanner — scans GitHub org repos and recent commit history for verified credentials using TruffleHog-equivalent pattern detection; finds AWS keys, GitHub tokens, private keys, Stripe keys, OpenAI credentials, Slack tokens, database URLs hardcoded in source code", category: "secrets",    githubUrl: "https://github.com/trufflesecurity/trufflehog",              runCommand: "trufflehog github --org={company} --only-verified --json" },
  { name: "gitdumper",    description: "Exposed .git directory detector — checks every discovered web host for accessible /.git/HEAD which allows full source code recovery; extracts remote URL, current branch, and latest commit message from exposed repositories", category: "secrets",    githubUrl: "https://github.com/internetwache/GitTools",                  runCommand: "gitdumper.sh https://{target}/.git/ /tmp/gitdump" },
  // Parameter Discovery
  { name: "paramspider",  description: "Parameter harvesting tool — mines historical URLs from Wayback Machine and CommonCrawl to extract real query parameters used by the target, crawls live pages for form inputs and href params, auto-runs on every domain scan", category: "web_recon",  githubUrl: "https://github.com/devanshbatham/paramspider",              runCommand: "paramspider -d {target} --level high --quiet" },
  { name: "arjun",        description: "Hidden HTTP parameter discovery — brute-forces ~300 common parameter names against target endpoints using differential response analysis (length change + value reflection detection), identifies parameters not exposed in page HTML", category: "web_recon",  githubUrl: "https://github.com/s0md3v/Arjun",                           runCommand: "arjun -u https://{target} -oJ arjun_output.json" },
  { name: "dnstwist",     description: "Domain permutation engine for detecting typosquatting and brand impersonation — generates lookalike domain permutations (homoglyphs, transposition, omission, substitution, addition, TLD-swap) and checks live DNS/MX/WHOIS records to identify phishing infrastructure and brand-squatting domains targeting your organization", category: "recon", githubUrl: "https://github.com/elceef/dnstwist", runCommand: "dnstwist {target} -f json --mxcheck --whois" },
  // OSINT / Threat Intelligence
  { name: "theHarvester", description: "Email, subdomain, host, and employee name harvesting — queries 20+ OSINT sources including Shodan, Bing, Google, LinkedIn, HunterIO, and VirusTotal to build a comprehensive intelligence picture of the target organization", category: "osint", githubUrl: "https://github.com/laramies/theHarvester", runCommand: "theHarvester -d {target} -b all -f /tmp/harvester-{target}.xml" },
  { name: "shodan",       description: "Internet-wide scanner — cross-references target IP addresses and domain against Shodan's continuous scan database for open ports, banners, CVEs, and service fingerprints without active probing", category: "osint", githubUrl: "https://www.shodan.io", runCommand: "shodan host {target}" },
  { name: "censys",       description: "Certificate and host search — uses Censys data to find all IPs, open services, and certificates associated with the target domain, including historical records and cloud IP mappings", category: "osint", githubUrl: "https://censys.io", runCommand: "censys search {target} --index-type hosts" },
  // Port Scanning
  { name: "naabu",    description: "Fast SYN/CONNECT port scanner (ProjectDiscovery) — scans top-1000 ports on all resolved IPs using reliable fallback modes; forms the foundation of Phase 2 port mapping when Masscan and Nmap are unavailable", category: "port_scan", githubUrl: "https://github.com/projectdiscovery/naabu", runCommand: "naabu -host {target} -top-ports 1000 -json" },
  { name: "masscan",  description: "Stateless TCP port scanner — asynchronous mass scanning at up to 25 Mpps; runs first in Phase 2 for large CIDR/IP asset types; falls back to naabu if CAP_NET_RAW is denied", category: "port_scan", githubUrl: "https://github.com/robertdavidgraham/masscan", runCommand: "masscan {target} -p1-65535 --rate 10000 -oJ masscan_output.json" },
  { name: "nmap",     description: "Network exploration and security auditing — service version detection (-sV), OS detection (-O), and script scanning (--script default) on discovered open ports; runs after naabu/masscan to enrich port data with service details", category: "port_scan", githubUrl: "https://nmap.org", runCommand: "nmap -sV -sC -p {ports} {target} -oX nmap_output.xml" },
  // SSL/TLS
  { name: "sslscan",  description: "SSL/TLS configuration scanner — enumerates cipher suites, protocol versions (SSLv2/3, TLS 1.0/1.1), certificate chain, expiry, and weak key detection; runs on all hosts with open port 443 or discovered TLS services", category: "ssl_check", githubUrl: "https://github.com/rbsec/sslscan", runCommand: "sslscan --no-colour {target}" },
  { name: "testssl",  description: "Comprehensive TLS/SSL tester — checks for BEAST, BREACH, POODLE, HEARTBLEED, ROBOT, TLS_FALLBACK_SCSV, and 80+ other SSL/TLS issues; generates severity-rated findings for each discovered weakness", category: "ssl_check", githubUrl: "https://github.com/drwetter/testssl.sh", runCommand: "testssl.sh --jsonfile /tmp/testssl-{target}.json {target}" },
] as const;

// ── Seed tools for all tenants on startup ─────────────────────────────────────

async function seedBuiltinToolsForAllTenants(): Promise<void> {
  const tenants = await db.select({ id: tenantsTable.id }).from(tenantsTable);
  let inserted = 0;
  for (const { id: tenantId } of tenants) {
    for (const def of BUILTIN_TOOL_DEFS) {
      const exists = await db.select({ id: securityToolsTable.id })
        .from(securityToolsTable)
        .where(and(eq(securityToolsTable.tenantId, tenantId), eq(securityToolsTable.name, def.name)))
        .then(r => r.length > 0);
      if (!exists) {
        await db.insert(securityToolsTable).values({
          tenantId,
          name:           def.name,
          description:    def.description,
          category:       def.category,
          githubUrl:      def.githubUrl,
          installCommand: "built-in (no install required)",
          updateCommand:  "built-in",
          runCommand:     def.runCommand,
          outputFormat:   "json",
          isActive:       true,
        });
        inserted++;
      }
    }
  }
  if (inserted > 0) logger.info({ inserted }, "Built-in tools seeded for all tenants");
}

// ── Pipeline sync helpers ──────────────────────────────────────────────────────
// Copy platform's enabled pipeline steps to a single tenant, mapping tool IDs.
// Only inserts steps for tools that already exist in the target tenant's catalog.

export async function syncPipelineToTenant(targetTenantId: number): Promise<void> {
  const [platformTenant] = await db.select({ id: tenantsTable.id })
    .from(tenantsTable).where(eq(tenantsTable.isPlatform, true)).limit(1);
  if (!platformTenant || platformTenant.id === targetTenantId) return;

  // Get platform steps with their tool names (name is the stable key across tenants)
  const platformSteps = await db
    .select({
      toolName: securityToolsTable.name,
      stepOrder: toolPipelineStepsTable.stepOrder,
      isEnabled: toolPipelineStepsTable.isEnabled,
    })
    .from(toolPipelineStepsTable)
    .innerJoin(securityToolsTable, eq(securityToolsTable.id, toolPipelineStepsTable.toolId))
    .where(eq(toolPipelineStepsTable.tenantId, platformTenant.id))
    .orderBy(toolPipelineStepsTable.stepOrder);

  if (platformSteps.length === 0) return;

  // Build a name→id map for the target tenant's tool catalog
  const clientTools = await db
    .select({ id: securityToolsTable.id, name: securityToolsTable.name })
    .from(securityToolsTable)
    .where(eq(securityToolsTable.tenantId, targetTenantId));
  const clientToolMap = new Map(clientTools.map(t => [t.name, t.id]));

  // Delete the target tenant's existing pipeline steps
  await db.delete(toolPipelineStepsTable)
    .where(eq(toolPipelineStepsTable.tenantId, targetTenantId));

  // Insert new steps using the target tenant's tool IDs
  const stepsToInsert = platformSteps
    .map(step => {
      const toolId = clientToolMap.get(step.toolName);
      if (!toolId) return null;
      return {
        tenantId: targetTenantId,
        toolId,
        stepOrder: step.stepOrder,
        isEnabled: step.isEnabled,
      };
    })
    .filter((s): s is NonNullable<typeof s> => s !== null);

  if (stepsToInsert.length > 0) {
    await db.insert(toolPipelineStepsTable).values(stepsToInsert);
  }

  logger.info(
    { targetTenantId, synced: stepsToInsert.length, platform: platformTenant.id },
    "Pipeline synced to tenant"
  );
}

// Copy platform pipeline steps to ALL non-platform tenants at once.
// Called whenever the SA saves the pipeline config via PUT /tools/pipeline.

export async function syncPipelineToAllClientTenants(): Promise<void> {
  const clientTenants = await db
    .select({ id: tenantsTable.id })
    .from(tenantsTable)
    .where(eq(tenantsTable.isPlatform, false));

  for (const { id } of clientTenants) {
    await syncPipelineToTenant(id);
  }
  logger.info({ count: clientTenants.length }, "Pipeline synced to all client tenants");
}

// ── Compliance controls seeding ────────────────────────────────────────────────
// Seeds a representative set of the most critical controls for each framework.
// Status defaults to non_compliant — tenants work through them over time.

const SEED_CONTROLS: Array<{ frameworkShortName: string; controlId: string; title: string; description: string }> = [
  // ISO 27001:2022 — core information security controls
  { frameworkShortName: "ISO27001", controlId: "A.5.1",  title: "Policies for information security",        description: "Define, approve, publish, and review policies for information security." },
  { frameworkShortName: "ISO27001", controlId: "A.5.9",  title: "Inventory of information and other assets",description: "Maintain an inventory of information assets and identify their owners." },
  { frameworkShortName: "ISO27001", controlId: "A.5.15", title: "Access control",                            description: "Implement rules to control physical and logical access based on business requirements." },
  { frameworkShortName: "ISO27001", controlId: "A.5.23", title: "Information security for cloud services",   description: "Establish processes for acquisition, use, management, and exit from cloud services." },
  { frameworkShortName: "ISO27001", controlId: "A.7.2",  title: "Physical entry",                            description: "Secure areas must be protected by entry controls to ensure only authorised personnel are allowed access." },
  { frameworkShortName: "ISO27001", controlId: "A.8.5",  title: "Secure authentication",                    description: "Implement secure authentication technologies and procedures based on information access restrictions." },
  { frameworkShortName: "ISO27001", controlId: "A.8.8",  title: "Management of technical vulnerabilities",  description: "Obtain timely information about technical vulnerabilities and remediate them appropriately." },
  { frameworkShortName: "ISO27001", controlId: "A.8.16", title: "Monitoring activities",                    description: "Monitor networks, systems, and applications for anomalous behaviour and take action." },
  { frameworkShortName: "ISO27001", controlId: "A.8.24", title: "Use of cryptography",                      description: "Define and implement rules for the effective use of cryptography to protect information." },
  { frameworkShortName: "ISO27001", controlId: "A.8.28", title: "Secure coding",                            description: "Apply secure coding principles to software development to reduce security vulnerabilities." },
  // SOC 2 Type II — trust service criteria
  { frameworkShortName: "SOC2", controlId: "CC1.1", title: "COSO Principle 1 — Integrity and ethical values",         description: "The entity demonstrates a commitment to integrity and ethical values." },
  { frameworkShortName: "SOC2", controlId: "CC2.1", title: "COSO Principle 13 — Information",                          description: "The entity obtains or generates relevant, quality information to support the functioning of internal control." },
  { frameworkShortName: "SOC2", controlId: "CC6.1", title: "Logical and physical access controls",                     description: "Implement logical access security measures to protect against threats from sources outside the system." },
  { frameworkShortName: "SOC2", controlId: "CC6.2", title: "Authentication and access provisioning",                   description: "Manage prior to issuance, identify and authenticate users for logical and physical access." },
  { frameworkShortName: "SOC2", controlId: "CC6.6", title: "Logical access security — external threats",               description: "Implement controls to prevent unauthorized access from external threats." },
  { frameworkShortName: "SOC2", controlId: "CC7.1", title: "System monitoring",                                        description: "Detect and monitor for configuration changes that could indicate potential vulnerabilities or misconfigurations." },
  { frameworkShortName: "SOC2", controlId: "CC7.2", title: "Monitoring for anomalies and security events",             description: "Monitor system components and the operation of controls for anomalies and security events." },
  { frameworkShortName: "SOC2", controlId: "CC7.4", title: "Incident response",                                        description: "Respond to identified security incidents in accordance with defined procedures." },
  { frameworkShortName: "SOC2", controlId: "CC9.1", title: "Risk mitigation",                                          description: "Identify and select risk mitigation activities for risks arising from business disruptions." },
  { frameworkShortName: "SOC2", controlId: "A1.2",  title: "Availability — recovery objectives",                       description: "Environmental protections, software, data backup processes, and recovery infrastructure meet defined recovery time and point objectives." },
  // PCI DSS 4.0 — payment card data security
  { frameworkShortName: "PCI-DSS", controlId: "1.1", title: "Install and maintain network security controls",         description: "Network security controls are established, configured, and maintained." },
  { frameworkShortName: "PCI-DSS", controlId: "2.2", title: "System components are properly configured",              description: "System components are configured and managed securely." },
  { frameworkShortName: "PCI-DSS", controlId: "3.4", title: "Access to PAN is restricted",                            description: "Access to full PAN is restricted to those with a legitimate business need." },
  { frameworkShortName: "PCI-DSS", controlId: "6.2", title: "Bespoke and custom software security",                   description: "Bespoke and custom software are developed securely." },
  { frameworkShortName: "PCI-DSS", controlId: "6.3", title: "Security vulnerabilities are identified and addressed",  description: "Security vulnerabilities in system components are identified and protected against." },
  { frameworkShortName: "PCI-DSS", controlId: "8.2", title: "User identification and authentication",                 description: "User identification and authentication is managed via an authentication policy." },
  { frameworkShortName: "PCI-DSS", controlId: "10.2","title": "Audit logs are implemented",                           description: "Audit logs capture all individual user access to cardholder data." },
  { frameworkShortName: "PCI-DSS", controlId: "11.3","title": "External and internal vulnerabilities are managed",    description: "External and internal vulnerabilities are regularly identified, prioritized, and addressed." },
  { frameworkShortName: "PCI-DSS", controlId: "12.3","title": "Risks are identified and managed",                     description: "Risks to the cardholder data environment are formally identified, evaluated, and managed." },
  // HIPAA — health information privacy and security
  { frameworkShortName: "HIPAA", controlId: "164.308(a)(1)", title: "Security management process",     description: "Implement policies and procedures to prevent, detect, contain, and correct security violations." },
  { frameworkShortName: "HIPAA", controlId: "164.308(a)(3)", title: "Workforce security",              description: "Implement policies and procedures to authorise appropriate access to ePHI by workforce members." },
  { frameworkShortName: "HIPAA", controlId: "164.308(a)(5)", title: "Security awareness and training", description: "Implement a security awareness and training program for all workforce members." },
  { frameworkShortName: "HIPAA", controlId: "164.308(a)(6)", title: "Security incident procedures",   description: "Implement policies and procedures to address security incidents." },
  { frameworkShortName: "HIPAA", controlId: "164.312(a)(1)", title: "Access control",                 description: "Implement technical policies and procedures for electronic information systems that maintain ePHI." },
  { frameworkShortName: "HIPAA", controlId: "164.312(b)",    title: "Audit controls",                 description: "Implement hardware, software, and procedural mechanisms to record and examine ePHI access." },
  { frameworkShortName: "HIPAA", controlId: "164.312(c)(1)", title: "Integrity controls",             description: "Implement policies and procedures to protect ePHI from improper alteration or destruction." },
  { frameworkShortName: "HIPAA", controlId: "164.312(d)",    title: "Person or entity authentication","description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed." },
  { frameworkShortName: "HIPAA", controlId: "164.312(e)(1)", title: "Transmission security",          description: "Implement technical security measures to guard against unauthorized access to ePHI in transit." },
  // CIS Controls v8 — implementation groups
  { frameworkShortName: "CIS", controlId: "CIS-1",  title: "Inventory and control of enterprise assets",     description: "Actively manage all enterprise assets connected to the infrastructure to accurately know what needs to be protected." },
  { frameworkShortName: "CIS", controlId: "CIS-2",  title: "Inventory and control of software assets",       description: "Actively manage all software on the network so only authorized software is installed and can execute." },
  { frameworkShortName: "CIS", controlId: "CIS-3",  title: "Data protection",                                description: "Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data." },
  { frameworkShortName: "CIS", controlId: "CIS-4",  title: "Secure configuration of enterprise assets",      description: "Establish and maintain the secure configuration of enterprise assets and software." },
  { frameworkShortName: "CIS", controlId: "CIS-5",  title: "Account management",                             description: "Use processes and tools to assign and manage authorization to credentials for user accounts." },
  { frameworkShortName: "CIS", controlId: "CIS-6",  title: "Access control management",                      description: "Use processes and tools to create, assign, manage, and revoke access credentials and privileges." },
  { frameworkShortName: "CIS", controlId: "CIS-7",  title: "Continuous vulnerability management",            description: "Develop a plan to continuously assess and track vulnerabilities on all enterprise assets." },
  { frameworkShortName: "CIS", controlId: "CIS-8",  title: "Audit log management",                           description: "Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack." },
  { frameworkShortName: "CIS", controlId: "CIS-12", title: "Network infrastructure management",              description: "Establish and maintain the secure network infrastructure of enterprise assets." },
  { frameworkShortName: "CIS", controlId: "CIS-16", title: "Application software security",                  description: "Manage the security life cycle of in-house developed, hosted, or acquired software to prevent, detect, and remediate security weaknesses." },
];

export async function seedComplianceControlsForTenant(tenantId: number): Promise<void> {
  // Load frameworks (global, not per-tenant)
  const frameworks = await db.select().from(complianceFrameworksTable);
  if (frameworks.length === 0) return;

  const frameworkMap = new Map(frameworks.map(f => [f.shortName, f.id]));
  let inserted = 0;

  for (const ctrl of SEED_CONTROLS) {
    const frameworkId = frameworkMap.get(ctrl.frameworkShortName);
    if (!frameworkId) continue;

    // Idempotent — skip if this control already exists for this tenant+framework+controlId
    const exists = await db
      .select({ id: complianceControlsTable.id })
      .from(complianceControlsTable)
      .where(
        and(
          eq(complianceControlsTable.tenantId, tenantId),
          eq(complianceControlsTable.frameworkId, frameworkId),
          eq(complianceControlsTable.controlId, ctrl.controlId),
        )
      )
      .then(r => r.length > 0);

    if (!exists) {
      await db.insert(complianceControlsTable).values({
        tenantId,
        frameworkId,
        controlId: ctrl.controlId,
        title: ctrl.title,
        description: ctrl.description,
        status: "non_compliant",
      });
      inserted++;
    }
  }

  if (inserted > 0) {
    logger.info({ tenantId, inserted }, "Compliance controls seeded for tenant");
  }
}

// ── Default alert rules seeding ────────────────────────────────────────────────
// Seeds 3 baseline alert rules so tenants get notified about critical events
// right away. Destination is left blank so they can fill in channel details.

const DEFAULT_ALERT_RULES = [
  { name: "Critical Finding Detected",  triggerType: "critical_finding", channel: "email" },
  { name: "High Severity Finding",      triggerType: "high_finding",     channel: "email" },
  { name: "Scan Completed",             triggerType: "scan_complete",    channel: "email" },
] as const;

export async function seedDefaultAlertRulesForTenant(tenantId: number): Promise<void> {
  let inserted = 0;
  for (const rule of DEFAULT_ALERT_RULES) {
    const exists = await db
      .select({ id: alertRulesTable.id })
      .from(alertRulesTable)
      .where(
        and(
          eq(alertRulesTable.tenantId, tenantId),
          eq(alertRulesTable.triggerType, rule.triggerType),
        )
      )
      .then(r => r.length > 0);

    if (!exists) {
      await db.insert(alertRulesTable).values({
        tenantId,
        name: rule.name,
        triggerType: rule.triggerType,
        channel: rule.channel,
        destination: null,
        isActive: true,
      });
      inserted++;
    }
  }
  if (inserted > 0) {
    logger.info({ tenantId, inserted }, "Default alert rules seeded for tenant");
  }
}

// ── CDN whitelist seed ────────────────────────────────────────────────────────

const BUILTIN_CDN_SEED = [
  { label: "Cloudflare",   cidr: "104.16.0.0/12",   ipStart: "104.16.0.0",   ipEnd: "104.31.255.255",   description: "Cloudflare CDN range 1" },
  { label: "Cloudflare",   cidr: "172.64.0.0/13",   ipStart: "172.64.0.0",   ipEnd: "172.71.255.255",   description: "Cloudflare CDN range 2" },
  { label: "Cloudflare",   cidr: "162.158.0.0/15",  ipStart: "162.158.0.0",  ipEnd: "162.159.255.255",  description: "Cloudflare CDN range 3" },
  { label: "Cloudflare",   cidr: "190.93.240.0/20", ipStart: "190.93.240.0", ipEnd: "190.93.255.255",   description: "Cloudflare CDN range 4" },
  { label: "Akamai",       cidr: "23.32.0.0/11",    ipStart: "23.32.0.0",    ipEnd: "23.63.255.255",    description: "Akamai Technologies CDN range 1" },
  { label: "Akamai",       cidr: "23.192.0.0/11",   ipStart: "23.192.0.0",   ipEnd: "23.223.255.255",   description: "Akamai Technologies CDN range 2" },
  { label: "Akamai",       cidr: "72.246.0.0/15",   ipStart: "72.246.0.0",   ipEnd: "72.247.255.255",   description: "Akamai Technologies CDN range 3" },
  { label: "Akamai",       cidr: "96.6.0.0/15",     ipStart: "96.6.0.0",     ipEnd: "96.7.255.255",     description: "Akamai Technologies CDN range 4" },
  { label: "CloudFront",   cidr: "13.32.0.0/14",    ipStart: "13.32.0.0",    ipEnd: "13.35.255.255",    description: "AWS CloudFront CDN range 1" },
  { label: "CloudFront",   cidr: "13.224.0.0/14",   ipStart: "13.224.0.0",   ipEnd: "13.227.255.255",   description: "AWS CloudFront CDN range 2" },
  { label: "CloudFront",   cidr: "52.84.0.0/14",    ipStart: "52.84.0.0",    ipEnd: "52.87.255.255",    description: "AWS CloudFront CDN range 3" },
  { label: "CloudFront",   cidr: "54.182.0.0/14",   ipStart: "54.182.0.0",   ipEnd: "54.185.255.255",   description: "AWS CloudFront CDN range 4" },
  { label: "CloudFront",   cidr: "99.84.0.0/14",    ipStart: "99.84.0.0",    ipEnd: "99.87.255.255",    description: "AWS CloudFront CDN range 5" },
  { label: "CloudFront",   cidr: "130.176.0.0/16",  ipStart: "130.176.0.0",  ipEnd: "130.176.255.255",  description: "AWS CloudFront CDN range 6" },
  { label: "CloudFront",   cidr: "143.204.0.0/16",  ipStart: "143.204.0.0",  ipEnd: "143.204.255.255",  description: "AWS CloudFront CDN range 7" },
  { label: "CloudFront",   cidr: "205.251.192.0/18",ipStart: "205.251.192.0",ipEnd: "205.251.255.255",  description: "AWS CloudFront CDN range 8" },
  { label: "GoDaddy",      cidr: "184.168.0.0/16",  ipStart: "184.168.0.0",  ipEnd: "184.168.255.255",  description: "GoDaddy domain parking" },
  { label: "Namecheap",    cidr: "198.54.117.0/24", ipStart: "198.54.117.0", ipEnd: "198.54.117.255",   description: "Namecheap/Enom parking range 1" },
  { label: "Namecheap",    cidr: "199.102.0.0/17",  ipStart: "199.102.0.0",  ipEnd: "199.102.127.255",  description: "Namecheap/Enom parking range 2" },
  { label: "Sedo",         cidr: "185.53.178.0/24", ipStart: "185.53.178.0", ipEnd: "185.53.178.255",   description: "Sedo domain parking" },
  { label: "Bodis",        cidr: "50.63.202.0/24",  ipStart: "50.63.202.0",  ipEnd: "50.63.202.255",    description: "Bodis domain parking" },
  { label: "Dan.com",      cidr: "80.244.75.0/24",  ipStart: "80.244.75.0",  ipEnd: "80.244.75.255",    description: "Dan.com domain parking / aftermarket" },
] as const;

async function seedCdnWhitelist(): Promise<void> {
  const existing = await db.select({ id: cdnWhitelistTable.id }).from(cdnWhitelistTable).limit(1);
  if (existing.length > 0) return;
  await db.insert(cdnWhitelistTable).values(
    BUILTIN_CDN_SEED.map(e => ({ ...e, isActive: true, isBuiltIn: true }))
  );
  logger.info({ count: BUILTIN_CDN_SEED.length }, "CDN whitelist seeded with built-in ranges");
}

// ── Main startup seed ─────────────────────────────────────────────────────────

export async function seedPlatformOnStartup(): Promise<void> {
  try {
    const [platformTenant] = await db.select().from(tenantsTable)
      .where(eq(tenantsTable.isPlatform, true));

    if (!platformTenant) {
      const [tenant] = await db.insert(tenantsTable).values({
        name: "Platform",
        slug: "platform",
        plan: "enterprise",
        isPlatform: true,
        isActive: true,
      }).returning();

      const passwordHash = await hashPassword("123456789");
      await db.insert(usersTable).values({
        tenantId: tenant.id,
        email: "jes@gmail.com",
        passwordHash,
        firstName: "Super",
        lastName: "Admin",
        role: "super_admin",
        isActive: true,
      });

      logger.info("Platform tenant seeded. Login: jes@gmail.com / 123456789");
    }

    // Always ensure built-in tools exist for every tenant (idempotent)
    await seedBuiltinToolsForAllTenants();
    // Seed CDN whitelist once if table is empty
    await seedCdnWhitelist();

    // Sync pipeline from platform to all client tenants (idempotent — only runs if client has 0 steps)
    const [pt] = await db.select({ id: tenantsTable.id })
      .from(tenantsTable).where(eq(tenantsTable.isPlatform, true)).limit(1);
    if (pt) {
      const clientTenants = await db.select({ id: tenantsTable.id })
        .from(tenantsTable).where(eq(tenantsTable.isPlatform, false));
      for (const { id: clientId } of clientTenants) {
        // Only sync if client has no pipeline steps configured
        const hasSteps = await db
          .select({ id: toolPipelineStepsTable.id })
          .from(toolPipelineStepsTable)
          .where(eq(toolPipelineStepsTable.tenantId, clientId))
          .limit(1)
          .then(r => r.length > 0);
        if (!hasSteps) {
          await syncPipelineToTenant(clientId);
        }
      }
    }

    // Seed compliance controls for all tenants (idempotent)
    const allTenants = await db.select({ id: tenantsTable.id }).from(tenantsTable);
    for (const { id } of allTenants) {
      await seedComplianceControlsForTenant(id);
    }

    // Seed default alert rules for all tenants (idempotent)
    for (const { id } of allTenants) {
      await seedDefaultAlertRulesForTenant(id);
    }
  } catch (err) {
    logger.error({ err }, "Platform seed failed");
  }
}
