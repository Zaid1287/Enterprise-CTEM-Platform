import { eq, and } from "drizzle-orm";
import { db, tenantsTable, usersTable, securityToolsTable } from "@workspace/db";
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
  } catch (err) {
    logger.error({ err }, "Platform seed failed");
  }
}
