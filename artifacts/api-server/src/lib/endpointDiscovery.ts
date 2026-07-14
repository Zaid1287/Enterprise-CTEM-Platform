import { exec } from "child_process";
import { promisify } from "util";
import { logger } from "./logger.js";
import puppeteer from "puppeteer";
import { orchestratedFetch } from "./scanOrchestrator.js";

const execAsync = promisify(exec);

export type UrlCategory = "api" | "admin" | "sensitive" | "graphql" | "parameterized" | "auth" | "page" | "asset" | "other";
export type UrlSource   = "wayback" | "commoncrawl" | "urlscan" | "otx" | "crawl" | "js-crawl" | "probe";

export interface DiscoveredUrl {
  url:      string;
  source:   UrlSource;
  status?:  number;
  title?:   string;
  category: UrlCategory;
}

// ── Categorization patterns ────────────────────────────────────────────────────

const CAT_PATTERNS: { category: UrlCategory; patterns: RegExp[] }[] = [
  { category: "graphql",      patterns: [/graphql/i, /\/gql\b/, /\?query=/i, /__schema/i] },
  { category: "api",          patterns: [/\/api\//i, /\/v\d+\//i, /\/rest\//i, /\/rpc\//i, /\.json($|\?)/i, /\/swagger/i, /\/openapi/i, /\/service\//i, /\/webhook/i, /\/endpoint/i] },
  { category: "admin",        patterns: [/\/admin/i, /\/administrator/i, /\/wp-admin/i, /\/dashboard/i, /\/panel/i, /\/manager/i, /\/manage/i, /\/backend/i, /\/console/i, /\/cpanel/i, /\/plesk/i, /\/phpmyadmin/i, /\/server-status/i, /\/server-info/i] },
  { category: "auth",         patterns: [/\/login/i, /\/signin/i, /\/sign-in/i, /\/signup/i, /\/sign-up/i, /\/register/i, /\/oauth/i, /\/auth\b/i, /\/sso\b/i, /\/saml/i, /\/token/i, /\/logout/i, /\/password/i, /\/forgot/i, /\/reset-password/i] },
  { category: "sensitive",    patterns: [/\.env\b/i, /\/\.git\//i, /\.bak$/i, /\.sql$/i, /backup/i, /dump\./i, /credentials/i, /secret/i, /\.pem$/i, /\.key$/i, /\.htaccess/i, /\.htpasswd/i, /wp-config/i, /database\.yml/i, /\.npmrc/i, /\.dockerignore/i, /[Dd]ockerfile/i, /docker-compose/i, /\.aws\//i, /actuator/i, /\/metrics($|\?)/i, /\/debug\b/i, /phpinfo/i, /info\.php/i, /web\.config/i, /\.kube\//i] },
  { category: "parameterized", patterns: [/\?[^=]+=.+/] },
  { category: "asset",        patterns: [/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|mp4|mp3|zip|gz|tar|pdf)(\?|$)/i] },
];

function categorizeUrl(url: string): UrlCategory {
  for (const { category, patterns } of CAT_PATTERNS) {
    if (patterns.some(p => p.test(url))) return category;
  }
  return "page";
}

// ── Utility ────────────────────────────────────────────────────────────────────

const SKIP_EXTENSIONS = /\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|webp|bmp|mp4|mp3|avi|mov|zip|gz|tar|rar|pdf|doc|docx|xls|xlsx|ppt|pptx)(\?|$)/i;

function isUsefulUrl(url: string): boolean {
  if (!url.startsWith("http")) return false;
  if (SKIP_EXTENSIONS.test(url)) return false;
  return true;
}

function timedFetch(url: string, opts: RequestInit = {}, _ms = 12000): Promise<Response> {
  return orchestratedFetch(url, opts, { intensity: "endpoint-discovery" });
}

const UA = "Mozilla/5.0 (compatible; SecurityScanner/1.0)";

// ── URO-style deduplication ────────────────────────────────────────────────────
// Collapses URLs with same path + same param names (different values) to one entry.
// Normalises trailing slashes and sorts query param keys.

function uroDedup(urls: string[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const raw of urls) {
    try {
      const u = new URL(raw);
      const params = [...u.searchParams.keys()].sort().join(",");
      const key = `${u.hostname}${u.pathname.toLowerCase().replace(/\/$/, "")}${params ? "?" + params : ""}`;
      if (!seen.has(key)) { seen.add(key); result.push(raw); }
    } catch { /* skip malformed */ }
  }
  return result;
}

// ── Source 1: Wayback Machine CDX API (one of the four GAU sources) ────────────

async function fetchWaybackUrls(domain: string): Promise<string[]> {
  try {
    const res = await timedFetch(
      `https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=text&fl=original&collapse=urlkey&limit=15000&matchType=domain&filter=statuscode:200`,
      { headers: { "User-Agent": UA } },
      20000
    );
    if (!res.ok) return [];
    const text = await res.text();
    return text.split("\n").map(l => l.trim()).filter(l => l.startsWith("http"));
  } catch (e) {
    logger.debug({ err: e, domain }, "Wayback Machine fetch failed");
    return [];
  }
}

// ── Source 2: Common Crawl Index API (GAU source) ─────────────────────────────

async function fetchCommonCrawlUrls(domain: string): Promise<string[]> {
  try {
    // Fetch latest index ID
    const idxRes = await timedFetch("https://index.commoncrawl.org/collinfo.json", {}, 8000);
    const indexes = idxRes.ok ? await idxRes.json() as { id: string }[] : [];
    const latestId = indexes[0]?.id ?? "CC-MAIN-2025-08";

    const res = await timedFetch(
      `https://index.commoncrawl.org/${latestId}-index?url=*.${domain}&output=text&fl=url&limit=8000`,
      { headers: { "User-Agent": UA } },
      20000
    );
    if (!res.ok) return [];
    const text = await res.text();
    return text.split("\n").map(l => l.trim()).filter(l => l.startsWith("http"));
  } catch (e) {
    logger.debug({ err: e, domain }, "Common Crawl fetch failed");
    return [];
  }
}

// ── Source 3: URLScan.io (GAU source) ─────────────────────────────────────────

async function fetchUrlScanUrls(domain: string): Promise<string[]> {
  try {
    const res = await timedFetch(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=200`,
      { headers: { "User-Agent": UA } },
      12000
    );
    if (!res.ok) return [];
    const data = await res.json() as { results?: { page?: { url?: string } }[] };
    return (data.results ?? []).map(r => r.page?.url ?? "").filter(u => u.startsWith("http"));
  } catch (e) {
    logger.debug({ err: e, domain }, "URLScan.io fetch failed");
    return [];
  }
}

// ── Source 4: OTX AlienVault (GAU source) ─────────────────────────────────────

async function fetchOtxUrls(domain: string): Promise<string[]> {
  try {
    const res = await timedFetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=500`,
      { headers: { "User-Agent": UA } },
      12000
    );
    if (!res.ok) return [];
    const data = await res.json() as { url_list?: { url: string }[] };
    return (data.url_list ?? []).map(e => e.url).filter(u => u.startsWith("http"));
  } catch (e) {
    logger.debug({ err: e, domain }, "OTX fetch failed");
    return [];
  }
}

// ── Hakrawler equivalent: HTTP crawl + link extraction ─────────────────────────

function extractLinks(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const base = new URL(baseUrl);
  const patterns = [
    /href=["']([^"'#\s]+)["']/gi,
    /action=["']([^"'#\s]+)["']/gi,
    /data-href=["']([^"'#\s]+)["']/gi,
    /content=["']([^"']+)["']/gi,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      try {
        const resolved = new URL(m[1]!.trim(), base).href;
        if (resolved.startsWith("http")) urls.push(resolved);
      } catch { /* skip */ }
    }
  }
  return urls;
}

async function crawlLinks(target: string, maxPages = 80): Promise<string[]> {
  const base = new URL(target.startsWith("http") ? target : `https://${target}`);
  const visited = new Set<string>();
  const queue: string[] = [base.href];
  const discovered: string[] = [];

  while (queue.length > 0 && visited.size < maxPages) {
    const url = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);
    try {
      const res = await timedFetch(url, {
        redirect: "follow",
        headers: { "User-Agent": UA },
      }, 8000);
      const ct = res.headers.get("content-type") ?? "";
      if (!ct.includes("html") && !ct.includes("text")) continue;
      const html = await res.text();
      for (const link of extractLinks(html, url)) {
        try {
          const lu = new URL(link);
          if (lu.hostname === base.hostname || lu.hostname.endsWith(`.${base.hostname}`)) {
            discovered.push(link);
            if (!visited.has(link)) queue.push(link);
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }
  return discovered;
}

// ── Katana equivalent: Puppeteer JS-aware crawling ────────────────────────────

function extractUrlsFromJs(jsContent: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const base = new URL(baseUrl);
  const patterns = [
    // Quoted paths starting with /
    /["'`](\/[\w\-./]+(?:\?[\w=&%+.\-_~]*)?)/g,
    // fetch/axios/XHR/request calls
    /(?:fetch|axios\.(?:get|post|put|delete|patch|request)|request\.(?:get|post))\(\s*["'`]([^"'`]+)["'`]/g,
    // Full http URLs in strings
    /["'`](https?:\/\/[^"'`\s<>{}|\\^[\]`]{5,300})["'`]/g,
    // Template literals with api/v\d paths
    /`([^`]*\/(?:api|v\d+|rest|graphql|gql)[^`]*)`/g,
  ];
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(jsContent)) !== null) {
      const raw = m[1]!.trim();
      if (!raw || raw.length < 2 || raw.length > 500) continue;
      try {
        const resolved = raw.startsWith("http") ? raw : new URL(raw, base).href;
        const ru = new URL(resolved);
        if (ru.hostname === base.hostname || ru.hostname.endsWith(`.${base.hostname}`) || raw.startsWith("/")) {
          urls.push(resolved);
        }
      } catch { /* skip */ }
    }
  }
  return urls;
}

async function crawlJsAware(target: string): Promise<string[]> {
  const base = new URL(target.startsWith("http") ? target : `https://${target}`);
  const discovered: string[] = [];
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;

  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--no-zygote"],
      timeout: 30000,
    });

    const page = await browser.newPage();
    await page.setUserAgent(UA);
    await page.setRequestInterception(true);

    const capturedUrls: string[] = [];

    // Capture all network requests (Katana-style passive URL collection)
    page.on("request", req => {
      const url = req.url();
      if (url.startsWith("http")) capturedUrls.push(url);
      req.continue();
    });

    // Crawl up to 15 pages
    const toVisit = [base.href];
    const visitedPages = new Set<string>();

    while (toVisit.length > 0 && visitedPages.size < 15) {
      const url = toVisit.shift()!;
      if (visitedPages.has(url)) continue;
      visitedPages.add(url);
      try {
        await page.goto(url, { waitUntil: "networkidle2", timeout: 20000 });

        // Extract all links from rendered DOM
        const links: string[] = await (page as any).evaluate(() => {
          // @ts-ignore — runs in browser context
          const els = document.querySelectorAll("a[href], form[action], [data-href]");
          return Array.from(els as ArrayLike<any>).map((el: any) => {
            const href = el.getAttribute("href") ?? el.getAttribute("action") ?? el.getAttribute("data-href") ?? "";
            // @ts-ignore — runs in browser context
            try { return new URL(href, window.location.href).href; } catch { return ""; }
          }).filter(Boolean);
        });

        // Extract inline JS content for URL mining
        const inlineScripts: string[] = await (page as any).evaluate(() =>
          // @ts-ignore — runs in browser context
          Array.from(document.querySelectorAll("script:not([src])")).map((s: any) => s.textContent ?? "")
        );
        for (const s of inlineScripts) discovered.push(...extractUrlsFromJs(s, url));

        for (const link of links) {
          try {
            const lu = new URL(link);
            if (lu.hostname === base.hostname || lu.hostname.endsWith(`.${base.hostname}`)) {
              discovered.push(link);
              if (!visitedPages.has(link)) toVisit.push(link);
            }
          } catch { /* skip */ }
        }
      } catch { /* skip failed pages */ }
    }

    discovered.push(...capturedUrls);

    // Also fetch and parse all external JS files loaded during navigation
    const jsFiles = [...new Set(capturedUrls.filter(u => /\.js(\?|$)/i.test(u)).slice(0, 30))];
    const jsFetches = await Promise.allSettled(
      jsFiles.map(async jsUrl => {
        const r = await timedFetch(jsUrl, { headers: { "User-Agent": UA } }, 8000);
        const txt = await r.text();
        return extractUrlsFromJs(txt, base.href);
      })
    );
    for (const r of jsFetches) {
      if (r.status === "fulfilled") discovered.push(...r.value);
    }

  } catch (e) {
    logger.debug({ err: e, target }, "Puppeteer crawl failed — falling back to static crawl");
    // Fallback: static HTML + JS extraction
    try {
      const res = await timedFetch(base.href, { headers: { "User-Agent": UA } }, 10000);
      const html = await res.text();

      // Extract JS srcs
      const jsSrcRe = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
      const jsSrcs: string[] = [];
      let m: RegExpExecArray | null;
      while ((m = jsSrcRe.exec(html)) !== null) {
        try { jsSrcs.push(new URL(m[1]!, base).href); } catch { /* skip */ }
      }
      // Extract inline scripts
      const inlineRe = /<script[^>]*>([\s\S]*?)<\/script>/gi;
      while ((m = inlineRe.exec(html)) !== null) {
        discovered.push(...extractUrlsFromJs(m[1]!, base.href));
      }
      // Fetch up to 20 JS files
      const fetches = await Promise.allSettled(
        jsSrcs.slice(0, 20).map(async jsUrl => {
          const r = await timedFetch(jsUrl, { headers: { "User-Agent": UA } }, 8000);
          return extractUrlsFromJs(await r.text(), base.href);
        })
      );
      for (const r of fetches) {
        if (r.status === "fulfilled") discovered.push(...r.value);
      }
    } catch { /* give up */ }
  } finally {
    if (browser) await browser.close().catch(() => { /* ignore */ });
  }

  return discovered;
}

// ── Source 7: Wordlist brute-force (SecLists-derived, built-in) ───────────────
// Probes ~400 common paths from SecLists Discovery/Web-Content/common.txt
// and raft-medium + admin/API-specific lists — equivalent to feroxbuster "common" mode.

const WORDLIST_PATHS = [
  // ── Core / discovery
  "/", "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/.well-known/security.txt",
  "/.well-known/apple-app-site-association", "/.well-known/assetlinks.json",
  "/humans.txt", "/crossdomain.xml", "/browserconfig.xml",
  // ── API / versioned endpoints
  "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v4",
  "/api/v1/users", "/api/v1/user", "/api/v1/me", "/api/v1/profile",
  "/api/v1/auth", "/api/v1/login", "/api/v1/token", "/api/v1/refresh",
  "/api/v2/users", "/api/v2/auth", "/api/v2/login",
  "/api/health", "/api/healthz", "/api/status", "/api/ping",
  "/api/docs", "/api/swagger", "/api/openapi.json", "/api/graphql",
  "/api/admin", "/api/config", "/api/settings", "/api/debug",
  "/rest", "/rest/v1", "/rest/v2", "/rpc",
  "/graphql", "/gql", "/graphiql", "/playground",
  "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger/index.html",
  "/swagger/v1/swagger.json", "/openapi.json", "/openapi.yaml",
  "/api-docs", "/api-docs/swagger.json", "/apidocs", "/apidocs/swagger.json",
  "/docs", "/documentation",
  // ── Health / monitoring
  "/health", "/healthz", "/health/live", "/health/ready",
  "/status", "/ping", "/alive", "/ready",
  "/metrics", "/prometheus", "/stats",
  "/actuator", "/actuator/health", "/actuator/env", "/actuator/info",
  "/actuator/beans", "/actuator/mappings", "/actuator/loggers",
  "/manage", "/management", "/management/health",
  // ── Admin panels
  "/admin", "/admin/", "/admin/login", "/admin/index",
  "/administrator", "/administrator/index.php",
  "/adminer", "/adminer.php",
  "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-json", "/wp-json/wp/v2",
  "/wp-content", "/wp-includes",
  "/phpmyadmin", "/phpmyadmin/", "/pma", "/pma/",
  "/panel", "/panel/login", "/cpanel", "/webmail",
  "/manager", "/manager/html", "/management",
  "/dashboard", "/dashboard/",
  "/console", "/debug", "/debug/",
  "/backend", "/backend/",
  "/plesk", "/directadmin",
  "/server-status", "/server-info",
  "/phpinfo.php", "/info.php", "/php_info.php",
  // ── Authentication / SSO
  "/login", "/signin", "/sign-in", "/signup", "/sign-up",
  "/register", "/logout", "/signout",
  "/auth", "/auth/login", "/auth/logout", "/auth/callback",
  "/oauth", "/oauth/authorize", "/oauth/token", "/oauth/callback",
  "/oauth2", "/oauth2/authorize", "/oauth2/token",
  "/sso", "/saml", "/saml/login", "/saml/acs",
  "/oidc", "/openid", "/connect/authorize",
  "/forgot-password", "/reset-password", "/verify-email",
  "/2fa", "/mfa", "/otp",
  // ── Sensitive files
  "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.test",
  "/.env.example", "/.env.backup",
  "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.gitignore",
  "/.svn/entries", "/.svn/wc.db",
  "/.htaccess", "/.htpasswd", "/.htpasswd_test",
  "/.npmrc", "/.yarnrc", "/.pnpmfile.cjs",
  "/.aws/credentials", "/.aws/config",
  "/.ssh/id_rsa", "/.ssh/known_hosts",
  "/.kube/config",
  "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
  "/docker-compose.prod.yml", "/docker-compose.override.yml",
  "/.dockerignore",
  // ── Config / credentials files
  "/config.json", "/config.js", "/config.yml", "/config.yaml",
  "/config.php", "/configuration.php",
  "/app-config.json", "/app.config.json", "/app-config.js",
  "/settings.json", "/settings.py", "/settings.php",
  "/secrets.json", "/credentials.json", "/credentials.yml",
  "/database.yml", "/database.json", "/db.json",
  "/application.yml", "/application.yaml", "/application.properties",
  "/bootstrap.yml", "/bootstrap.yaml",
  "/web.config", "/appsettings.json", "/appsettings.Development.json",
  "/wp-config.php", "/wp-config.php.bak", "/configuration.php",
  "/local.settings.json",
  // ── Backup / archive files
  "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
  "/db.sql", "/dump.sql", "/database.sql",
  "/backup.php", "/backup.bak",
  "/.backup", "/old", "/old/",
  "/archive", "/temp", "/tmp",
  // ── Common web pages
  "/about", "/contact", "/home", "/index",
  "/index.html", "/index.php", "/default.asp",
  "/404", "/403", "/500", "/error",
  "/privacy", "/terms", "/legal",
  "/blog", "/news", "/feed", "/rss.xml", "/atom.xml",
  "/faq", "/help", "/support",
  // ── User / account routes
  "/user", "/users", "/users/me", "/profile", "/account",
  "/settings", "/preferences", "/billing",
  "/password", "/password/reset", "/password/change",
  // ── File upload / storage
  "/upload", "/uploads", "/files", "/file",
  "/media", "/assets", "/static", "/public",
  "/images", "/img", "/css", "/js",
  "/storage", "/download", "/downloads",
  // ── CMS / framework specific
  "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
  "/xmlrpc.php", "/feed.php",
  "/.well-known/change-password",
  "/rails/info/properties", "/rails/mailers",
  "/django-admin", "/admin/doc",
  "/__debug__", "/__debug__/sql", "/_debug_toolbar",
  "/_ah/health", "/_ah/start",
  "/app", "/app/",
  // ── Internal / dev tools
  "/internal", "/private", "/secret",
  "/test", "/testing", "/dev", "/development",
  "/staging", "/qa", "/preview",
  "/v1", "/v2", "/v3",
  // ── Security / compliance
  "/security", "/security.txt", "/.well-known/security.txt",
  "/vulnerability-disclosure",
  "/csp-report", "/report-to",
  // ── Cloud / infrastructure
  "/metadata", "/metadata/v1",
  "/latest/meta-data", "/latest/user-data",
  "/computeMetadata/v1",
] as const;

async function probeCommonPaths(target: string): Promise<string[]> {
  const base = new URL(target.startsWith("http") ? target : `https://${target}`);
  const found: string[] = [];

  // Probe in batches of 30 concurrent requests
  const BATCH = 30;
  const paths = [...WORDLIST_PATHS];
  for (let i = 0; i < paths.length; i += BATCH) {
    const batch = paths.slice(i, i + BATCH);
    const results = await Promise.allSettled(
      batch.map(async path => {
        const url = `${base.origin}${path}`;
        try {
          const ctrl = new AbortController();
          setTimeout(() => ctrl.abort(), 6000);
          const r = await orchestratedFetch(url, {
            method: "HEAD",
            redirect: "follow",
            signal: ctrl.signal,
            headers: { "User-Agent": UA },
          }, { intensity: "endpoint-discovery" });
          // Include anything that exists (not 404/410/501)
          if (r.status !== 404 && r.status !== 410 && r.status !== 501 && r.status > 0) {
            return url;
          }
          return null;
        } catch { return null; }
      })
    );
    for (const r of results) {
      if (r.status === "fulfilled" && r.value) found.push(r.value);
    }
  }
  return found;
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

const CATEGORY_ORDER: UrlCategory[] = ["sensitive", "admin", "graphql", "api", "auth", "parameterized", "page", "asset", "other"];

// ── Katana web crawler ─────────────────────────────────────────────────────────

async function runKatana(target: string): Promise<string[]> {
  try {
    const safeTarget = target.replace(/"/g, "").replace(/`/g, "").slice(0, 500);
    const { stdout } = await execAsync(
      `katana -u "${safeTarget}" -d 2 -jc -silent -no-color -timeout 20 -rate-limit 50 2>/dev/null`,
      { timeout: 90000 }
    );
    return stdout.trim().split("\n")
      .map(l => l.trim())
      .filter(l => l.startsWith("http") && !l.includes(" "));
  } catch {
    return [];
  }
}

export async function runEndpointDiscovery(target: string): Promise<DiscoveredUrl[]> {
  const base = new URL(target.startsWith("http") ? target : `https://${target}`);
  const domain = base.hostname.replace(/^www\./, "");

  logger.info({ domain, target }, "Starting endpoint discovery");

  // Run all 8 sources in parallel (added katana)
  const [wayback, commoncrawl, urlscan, otx, crawled, jsCrawled, probed, katana] = await Promise.allSettled([
    fetchWaybackUrls(domain),
    fetchCommonCrawlUrls(domain),
    fetchUrlScanUrls(domain),
    fetchOtxUrls(domain),
    crawlLinks(base.href),
    crawlJsAware(base.href),
    probeCommonPaths(base.href),   // wordlist brute-force (feroxbuster equivalent)
    runKatana(base.href),          // katana JS-aware crawler
  ]);

  // Merge, preserving first-seen source per URL
  const urlSourceMap = new Map<string, UrlSource>();
  const addAll = (res: PromiseSettledResult<string[]>, source: UrlSource) => {
    if (res.status !== "fulfilled") return;
    for (const u of res.value) {
      if (isUsefulUrl(u) && !urlSourceMap.has(u)) urlSourceMap.set(u, source);
    }
  };

  addAll(wayback,      "wayback");
  addAll(commoncrawl,  "commoncrawl");
  addAll(urlscan,      "urlscan");
  addAll(otx,          "otx");
  addAll(crawled,      "crawl");
  addAll(jsCrawled,    "js-crawl");
  addAll(probed,       "probe");
  addAll(katana,       "crawl");   // katana JS-aware crawl (same source tag)

  // URO-style deduplication
  const rawUrls = [...urlSourceMap.keys()];
  const dedupedUrls = uroDedup(rawUrls);

  // Build final list with category
  const results: DiscoveredUrl[] = dedupedUrls.map(url => ({
    url,
    source: urlSourceMap.get(url) ?? "crawl",
    category: categorizeUrl(url),
  }));

  // Sort by priority category
  results.sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category));

  logger.info({
    domain,
    total:       results.length,
    wayback:     wayback.status     === "fulfilled" ? wayback.value.length     : 0,
    commoncrawl: commoncrawl.status === "fulfilled" ? commoncrawl.value.length : 0,
    urlscan:     urlscan.status     === "fulfilled" ? urlscan.value.length     : 0,
    otx:         otx.status         === "fulfilled" ? otx.value.length         : 0,
    crawled:     crawled.status     === "fulfilled" ? crawled.value.length     : 0,
    jsCrawled:   jsCrawled.status   === "fulfilled" ? jsCrawled.value.length   : 0,
    probed:      probed.status      === "fulfilled" ? probed.value.length      : 0,
    katana:      katana.status      === "fulfilled" ? katana.value.length      : 0,
  }, "Endpoint discovery complete");

  return results.slice(0, 5000); // cap at 5000 to keep JSON payload reasonable
}
