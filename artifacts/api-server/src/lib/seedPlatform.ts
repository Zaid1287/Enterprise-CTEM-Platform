import { eq, and } from "drizzle-orm";
import { db, tenantsTable, usersTable, securityToolsTable, cdnWhitelistTable } from "@workspace/db";
import { hashPassword } from "./auth";
import { logger } from "./logger";

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
  // ── Endpoint discovery / URL harvesting ────────────────────────────────────
  { name: "gau",          description: "GetAllURLs — aggregates historical URLs from Wayback Machine, Common Crawl, URLScan.io, and OTX AlienVault; auto-runs passive URL harvesting on every domain scan",                                                                        category: "web_recon",  githubUrl: "https://github.com/lc/gau",                                  runCommand: "gau {target}" },
  { name: "waybackurls",  description: "Wayback Machine CDX API client — queries Internet Archive for all historically crawled URLs for a domain, revealing endpoints no longer publicly linked",                                                                                   category: "web_recon",  githubUrl: "https://github.com/tomnomnom/waybackurls",                   runCommand: "waybackurls {target}" },
  { name: "katana",       description: "JS-aware web crawler (ProjectDiscovery) — renders pages with Puppeteer, intercepts XHR/fetch network requests, parses JS bundles for embedded API routes and endpoints",                                                                   category: "web_recon",  githubUrl: "https://github.com/projectdiscovery/katana",                 runCommand: "katana -u https://{target} -js-crawl -silent" },
  { name: "hakrawler",    description: "Fast web crawler — extracts URLs from HTML anchor/form tags, JS src references, sitemaps, and robots.txt; crawls up to 80 pages per scan",                                                                                                 category: "web_recon",  githubUrl: "https://github.com/hakluke/hakrawler",                        runCommand: "hakrawler -url https://{target} -depth 3 -scope subs" },
  { name: "uro",          description: "URL deduplication & normalization — collapses parameterized URLs with identical structure, removes duplicate paths, and merges all harvested URLs from GAU, Wayback, Katana, Hakrawler, and wordlist probe",                               category: "web_recon",  githubUrl: "https://github.com/s0md3v/uro",                              runCommand: "uro" },
  { name: "feroxbuster",  description: "Fast directory & file brute-forcer — actively probes 400+ paths from a built-in SecLists-derived wordlist to discover hidden admin panels, API endpoints, config files, backups, and sensitive paths not found through passive harvesting", category: "web_recon",  githubUrl: "https://github.com/epi052/feroxbuster",                      runCommand: "feroxbuster -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/common.txt --silent" },
  // ── JavaScript Analysis ─────────────────────────────────────────────────────
  { name: "linkfinder",   description: "JavaScript endpoint extractor — fetches all JS files from target pages and applies LinkFinder regex patterns (paths, fetch/axios/XHR calls, route definitions) to surface API endpoints, hidden routes, and internal URLs embedded in client-side code", category: "web_recon",  githubUrl: "https://github.com/GerbenJavado/LinkFinder",                 runCommand: "python linkfinder.py -i https://{target} -d -o cli" },
  { name: "secretfinder", description: "JavaScript secret scanner — runs SecretFinder regex patterns across all discovered JS files to detect exposed AWS keys, API tokens, OAuth credentials, private keys, JWTs, hardcoded passwords, internal network URLs, GraphQL queries, and email addresses", category: "web_recon",  githubUrl: "https://github.com/m4ll0k/SecretFinder",                    runCommand: "python SecretFinder.py -i https://{target} -e -o cli" },
  // ── Cloud Asset Recon ───────────────────────────────────────────────────────
  { name: "cloud-enum",    description: "Cloud storage enumeration — derives bucket/container naming patterns from the target domain and tests S3, GCS, and Azure Blob Storage for public access, listable buckets, and exposed files; auto-runs on every domain scan", category: "cloud_recon", githubUrl: "https://github.com/initstring/cloud_enum",    runCommand: "cloud_enum.py -k {company} --quickscan" },
  { name: "GrayhatWarfare",description: "Cloud bucket search engine — cross-references target domain and company name against public bucket indexes to surface exposed S3, GCS, and Azure Blob Storage containers with real file listings", category: "cloud_recon", githubUrl: "https://grayhatwarfare.com",                   runCommand: "curl 'https://buckets.grayhatwarfare.com/api/v2/buckets?keywords={company}'" },
  { name: "firebase-recon",description: "Firebase database exposure checker — probes Firebase Realtime Database and Cloud Firestore URLs derived from target name for unauthenticated read access; public databases can leak all stored user data", category: "cloud_recon", githubUrl: "https://github.com/Turr0n/firebase",           runCommand: "python firebase.py --domain {target} --firebase" },
  // ── Secrets Hunting ──────────────────────────────────────────────────────────
  // ── Vulnerability Scanning ───────────────────────────────────────────────────
  { name: "nuclei",   description: "Template-based vulnerability scanner — runs 40+ purpose-built detection templates across every live host to find exposed admin panels (phpMyAdmin, Adminer, Kibana, Jenkins, Grafana), sensitive file leaks (.env, .git, AWS credentials, SSH keys), misconfigurations (Spring Actuator, Symfony profiler, Laravel debug), known CVEs (CVE-2017-9841 PHPUnit RCE), and technology-specific weaknesses; CORS misconfiguration testing (reflected-origin, null-origin, subdomain-confusion); full security header analysis with scoring", category: "vuln_scan", githubUrl: "https://github.com/projectdiscovery/nuclei", runCommand: "nuclei -u https://{target} -as -tags cve,exposed-panels,misconfig,default-logins -o nuclei_output.json -json" },
  { name: "nikto",    description: "Web server vulnerability scanner — probes for 6700+ dangerous files, outdated server software, and version-specific issues; complements Nuclei by detecting server misconfigurations, CGI vulnerabilities, and missing security headers", category: "vuln_scan", githubUrl: "https://github.com/sullo/nikto", runCommand: "nikto -h {target} -o nikto_output.xml -Format xml -timeout 10" },
  { name: "dalfox",   description: "Parameter analysis and XSS scanner — discovers and validates reflected and DOM-based cross-site scripting vulnerabilities across discovered endpoints using smart payloads", category: "vuln_scan", githubUrl: "https://github.com/hahwul/dalfox", runCommand: "dalfox url https://{target} --deep-domxss --output dalfox_output.txt" },
  // ── Directory Fuzzing ────────────────────────────────────────────────────────
  { name: "feroxbuster", description: "Recursive directory + file brute-forcer — uses an embedded 240-path wordlist to discover hidden admin panels, API endpoints, backup files, and config leaks across the primary target and all discovered live subdomains via concurrent HEAD probes; results merged with passive URL sources", category: "web_recon", githubUrl: "https://github.com/epi052/feroxbuster",                                  runCommand: "feroxbuster -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 --smart-info -o ferox_output.txt" },
  { name: "gau",         description: "GetAllUrls — fetches all known URLs for the target from Wayback Machine CDX API and AlienVault OTX passive sources; surfaces historical endpoints, forgotten API paths, and archived sensitive files without sending a single request to the target", category: "web_recon", githubUrl: "https://github.com/lc/gau",                                            runCommand: "gau --threads 5 --subs {target} | tee gau_output.txt" },
  { name: "katana",      description: "Next-generation web crawler — crawls the target homepage and follows all internal links (href, src, action, data-url attributes and JS string paths) to map the live application surface; runs after GAU to complement passive discovery with active crawling", category: "web_recon", githubUrl: "https://github.com/projectdiscovery/katana",                          runCommand: "katana -u https://{target} -d 3 -jc -o katana_output.txt" },
  { name: "hakrawler",   description: "Simple, fast HTTP crawler — extracts links and endpoints from HTML responses, form actions, and JS files; contributes to the master endpoint list alongside feroxbuster, GAU, and Wayback results", category: "web_recon", githubUrl: "https://github.com/hakluke/hakrawler",                                      runCommand: "echo 'https://{target}' | hakrawler -depth 3 -scope yolo -u | tee hakrawler_output.txt" },
  // ── Secrets Hunting ──────────────────────────────────────────────────────────
  { name: "trufflehog",   description: "Git secrets scanner — scans GitHub org repos and recent commit history for verified credentials using TruffleHog-equivalent pattern detection; finds AWS keys, GitHub tokens, private keys, Stripe keys, OpenAI credentials, Slack tokens, database URLs hardcoded in source code", category: "secrets",    githubUrl: "https://github.com/trufflesecurity/trufflehog",              runCommand: "trufflehog github --org={company} --only-verified --json" },
  { name: "gitdumper",    description: "Exposed .git directory detector — checks every discovered web host for accessible /.git/HEAD which allows full source code recovery; extracts remote URL, current branch, and latest commit message from exposed repositories", category: "secrets",    githubUrl: "https://github.com/internetwache/GitTools",                  runCommand: "gitdumper.sh https://{target}/.git/ /tmp/gitdump" },
  // ── Parameter Discovery ─────────────────────────────────────────────────────
  { name: "paramspider",  description: "Parameter harvesting tool — mines historical URLs from Wayback Machine and CommonCrawl to extract real query parameters used by the target, crawls live pages for form inputs and href params, auto-runs on every domain scan", category: "web_recon",  githubUrl: "https://github.com/devanshbatham/paramspider",              runCommand: "paramspider -d {target} --level high --quiet" },
  { name: "arjun",        description: "Hidden HTTP parameter discovery — brute-forces ~300 common parameter names against target endpoints using differential response analysis (length change + value reflection detection), identifies parameters not exposed in page HTML", category: "web_recon",  githubUrl: "https://github.com/s0md3v/Arjun",                           runCommand: "arjun -u https://{target} -oJ arjun_output.json" },
  { name: "dnstwist",     description: "Domain permutation engine for detecting typosquatting and brand impersonation — generates lookalike domain permutations (homoglyphs, transposition, omission, substitution, addition, TLD-swap) and checks live DNS/MX/WHOIS records to identify phishing infrastructure and brand-squatting domains targeting your organization", category: "recon", githubUrl: "https://github.com/elceef/dnstwist", runCommand: "dnstwist {target} -f json --mxcheck --whois" },
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

// ── CDN whitelist seed ────────────────────────────────────────────────────────
// Runs once on startup when the table is empty, seeding the 22 known CDN and
// domain-parking IP ranges.  Super-admins can add/edit/delete from the UI.

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
  if (existing.length > 0) return; // already seeded
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
  } catch (err) {
    logger.error({ err }, "Platform seed failed");
  }
}
