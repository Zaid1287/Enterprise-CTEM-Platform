import { logger } from "./logger";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface FuzzedEndpoint {
  url: string;
  path: string;
  host: string;
  statusCode: number;
  contentLength?: number;
  contentType?: string;
  redirectTo?: string;
  source: "fuzz" | "wayback" | "crawl" | "otx";
  isInteresting: boolean;
}

export interface HostFuzzResult {
  host: string;
  baseUrl: string;
  isLive: boolean;
  liveStatusCode: number;
  endpoints: FuzzedEndpoint[];
  stats: {
    fuzzHits: number;
    waybackFound: number;
    crawled: number;
    live200: number;
    live301: number;
    live401403: number;
    interesting: number;
  };
}

export interface DirFuzzResult {
  hosts: HostFuzzResult[];
  masterList: string[];
  stats: {
    hostsScanned: number;
    hostsLive: number;
    totalUnique: number;
    liveEndpoints: number;
    fuzzHits: number;
    waybackFound: number;
    crawledFound: number;
    interestingEndpoints: number;
  };
}

// ── Wordlist ───────────────────────────────────────────────────────────────────

// Full wordlist for primary target (~240 paths)
const WORDLIST: string[] = [
  // Admin panels
  "admin","administrator","admin.php","admin/login","admin/index.php",
  "wp-admin","wp-login.php","phpmyadmin","adminer","adminer.php",
  "panel","controlpanel","cpanel","webmin","portainer","manage","management","manager",
  // API + docs
  "api","api/v1","api/v2","api/v3","graphql","graphiql","playground",
  "swagger","swagger-ui","swagger-ui.html","swagger.json","swagger.yaml",
  "api-docs","openapi.json","openapi.yaml","docs","redoc",
  "v1","v2","v3","rest","rest/v1","rest/v2","ws","websocket",
  // Auth
  "login","signin","register","signup","auth","oauth","oauth2","sso","saml",
  "logout","forgot-password","reset-password","change-password","token","authorize",
  "accounts","account/login","user/login","users/login","api/login","api/auth",
  // Config / backup (high-value)
  ".env",".env.local",".env.backup",".env.prod",".env.staging",
  "config.json","config.yaml","config.yml","config.xml",
  "settings.json","settings.yaml","secrets.json","credentials.json",
  "wp-config.php","web.config","app.config","application.properties",
  "backup.sql","backup.zip","database.sql","db.sql","dump.sql","data.sql",
  ".aws/credentials",".htpasswd","id_rsa","id_rsa.pub",
  // Version control
  ".git",".git/HEAD",".git/config",".svn","CVS",".hg",".gitignore",".dockerignore",
  // Dev / debug
  "debug","phpinfo.php","info.php","php-info.php",
  "server-status","server-info","__debug__",
  "test","test.php","test.html","temp","tmp","cache","bak","old",
  // Well-known
  "robots.txt","sitemap.xml","sitemap_index.xml","sitemap.txt",
  ".well-known/security.txt",".well-known/openid-configuration",
  ".well-known/assetlinks.json",".well-known/apple-app-site-association",
  "security.txt","humans.txt","ads.txt","app-ads.txt",
  // Dashboard / monitoring
  "dashboard","home","portal","app","console","monitor","monitoring",
  "health","healthz","ready","readyz","status","ping","alive","live",
  "metrics","stats","statistics",
  // Spring Actuator
  "actuator","actuator/health","actuator/env","actuator/info",
  "actuator/mappings","actuator/beans","actuator/loggers",
  "actuator/metrics","actuator/threaddump","actuator/heapdump",
  "actuator/httptrace","actuator/conditions","actuator/configprops",
  // Node / Kubernetes
  "node_modules/.package-lock.json",".npmrc","package.json","yarn.lock","package-lock.json",
  ".kube/config","kubernetes/config",
  // Docker
  "docker-compose.yml","docker-compose.yaml","Dockerfile",
  // CI / build
  ".travis.yml","Jenkinsfile",".github/workflows",".gitlab-ci.yml",
  "Makefile","build.gradle","pom.xml","requirements.txt","Gemfile","composer.json",
  // Static
  "assets","static","media","uploads","files","images","img","js","css","fonts",
  "download","downloads","export","export.json","export.csv","data.json","data.csv",
  // Logs
  "logs","log","error.log","access.log","debug.log","error_log","php_error.log",
  // CMS
  "xmlrpc.php","wp-json","wp-json/wp/v2/users","wp-content/uploads",
  "typo3","joomla","drupal","administrator/index.php",
  // Users
  "users","user","profile","api/users","api/v1/users","api/v2/users",
  // Internal
  "internal","private","secure","secret","staff","employee","hr","it","intranet",
  // Misc
  "search","feed","rss","atom",
  "verify","confirm","activate","invite",
  "support","help","helpdesk","ticket",
  "payment","billing","checkout","cart","invoice","subscription",
  "mail","email","smtp",
  "manifest.json","manifest.webmanifest","service-worker.js","sw.js",
  "crossdomain.xml","browserconfig.xml","favicon.ico",
  // S3 / cloud
  "bucket","storage","cdn","s3","blob",
];

// Mini wordlist for subdomain fuzzing (~85 paths — highest value only)
const WORDLIST_MINI: string[] = [
  "admin","administrator","wp-admin","phpmyadmin","panel","cpanel","webmin",
  "api","api/v1","api/v2","graphql","swagger","swagger-ui","api-docs","openapi.json",
  "login","signin","auth","oauth","sso","dashboard","portal","console","manage",
  ".env",".env.local",".env.backup","config.json","secrets.json","wp-config.php",
  "backup.sql","database.sql","dump.sql","backup.zip",".git","CVS",".svn",
  "debug","phpinfo.php","info.php","server-status","test",
  "robots.txt","sitemap.xml",".well-known/security.txt",
  "health","healthz","status","metrics","actuator","actuator/health","actuator/env",
  "uploads","files","download","logs","error.log",
  "users","api/users","internal","private","staff",
  "docker-compose.yml","Dockerfile",".travis.yml",".github/workflows",
  "xmlrpc.php","wp-json/wp/v2/users",
];

const INTERESTING_KEYWORDS = [
  "admin","login","password","secret","key","token","auth","config","backup",
  "database","debug","swagger","graphql","actuator","env","git","private","internal",
];

const UA = "Mozilla/5.0 (compatible; CTEM-DirFuzzer/1.0; +https://sentinelware.io)";

// ── Concurrency semaphore ─────────────────────────────────────────────────────

class Semaphore {
  private queue: Array<() => void> = [];
  constructor(private count: number) {}
  acquire(): Promise<void> {
    if (this.count > 0) { this.count--; return Promise.resolve(); }
    return new Promise(r => this.queue.push(r));
  }
  release(): void {
    const next = this.queue.shift();
    if (next) next(); else this.count++;
  }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

async function headProbe(
  url: string, timeoutMs = 5000
): Promise<{ status: number; length?: number; type?: string; redirect?: string } | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, {
      method: "HEAD", signal: ctrl.signal, redirect: "manual",
      headers: { "User-Agent": UA, "Connection": "close" },
    });
    clearTimeout(t);
    return {
      status: res.status,
      length: res.headers.get("content-length") != null
        ? parseInt(res.headers.get("content-length")!, 10) : undefined,
      type: res.headers.get("content-type") ?? undefined,
      redirect: [301, 302, 303, 307, 308].includes(res.status)
        ? (res.headers.get("location") ?? undefined) : undefined,
    };
  } catch { return null; }
}

async function getHtml(url: string, timeoutMs = 10000): Promise<string> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return "";
    return (await res.text()).slice(0, 200_000);
  } catch { return ""; }
}

// ── Passive URL sources ───────────────────────────────────────────────────────

async function fetchWayback(host: string): Promise<string[]> {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host + "/*")}&output=json&fl=original&collapse=urlkey&limit=500&filter=statuscode:200&matchType=domain`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return [];
    const data: string[][] = await res.json().catch(() => []);
    return data.slice(1).map(row => row[0]).filter(Boolean);
  } catch { return []; }
}

async function fetchOtx(host: string): Promise<string[]> {
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/hostname/${host}/url_list?limit=200`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return [];
    const data = await res.json().catch(() => null);
    if (!data?.url_list) return [];
    return (data.url_list as Array<{ url: string }>).map(u => u.url).filter(Boolean);
  } catch { return []; }
}

// ── Crawler (Katana/Hakrawler equivalent) ─────────────────────────────────────

async function crawlHost(baseUrl: string): Promise<string[]> {
  const html = await getHtml(baseUrl);
  if (!html) return [];

  const base = new URL(baseUrl);
  const urls = new Set<string>();

  // Extract href, src, action, data-url
  const attrRe = /(?:href|src|action|data-url|data-href|data-endpoint)\s*=\s*["']([^"'#\s]+)/gi;
  // Extract JS string paths like "/api/v1/users"
  const jsPathRe = /["'`](\/[a-zA-Z0-9_\-./]{3,100})["'`]/g;

  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname && u.pathname !== "/" && u.pathname !== "") {
        urls.add(u.href);
      }
    } catch {}
  }
  while ((m = jsPathRe.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname) urls.add(u.href);
    } catch {}
  }

  return [...urls].slice(0, 300);
}

// ── Interesting path heuristic ────────────────────────────────────────────────

function isInterestingPath(path: string, status: number): boolean {
  const p = path.toLowerCase();
  if (status >= 200 && status < 300) return true;
  if (status === 401 || status === 403) {
    return INTERESTING_KEYWORDS.some(kw => p.includes(kw));
  }
  return false;
}

// ── Per-host fuzzer ───────────────────────────────────────────────────────────

async function fuzzHost(baseUrl: string, isFull: boolean): Promise<HostFuzzResult> {
  let host: string;
  try { host = new URL(baseUrl).hostname; } catch { return emptyHost(baseUrl, "unknown", false, 0); }

  // Quick liveness check first
  const liveness = await headProbe(baseUrl, 8000);
  if (!liveness || liveness.status === 0) {
    // Try HTTP fallback if HTTPS failed
    const httpBase = baseUrl.startsWith("https://")
      ? baseUrl.replace("https://", "http://") : null;
    if (httpBase) {
      const fallback = await headProbe(httpBase, 6000);
      if (!fallback || fallback.status === 0) return emptyHost(baseUrl, host, false, 0);
      return fuzzLiveHost(httpBase, host, fallback.status, isFull);
    }
    return emptyHost(baseUrl, host, false, 0);
  }

  return fuzzLiveHost(baseUrl, host, liveness.status, isFull);
}

function emptyHost(baseUrl: string, host: string, isLive: boolean, code: number): HostFuzzResult {
  return { host, baseUrl, isLive, liveStatusCode: code, endpoints: [], stats: { fuzzHits: 0, waybackFound: 0, crawled: 0, live200: 0, live301: 0, live401403: 0, interesting: 0 } };
}

async function fuzzLiveHost(baseUrl: string, host: string, liveStatus: number, isFull: boolean): Promise<HostFuzzResult> {
  const sem = new Semaphore(25); // 25 concurrent requests
  const all: FuzzedEndpoint[] = [];

  // 1. Passive sources (Wayback + OTX) — run in parallel
  const [wbUrls, otxUrls] = await Promise.allSettled([
    fetchWayback(host),
    isFull ? fetchOtx(host) : Promise.resolve<string[]>([]),
  ]);
  const passiveRaw = [
    ...(wbUrls.status === "fulfilled" ? wbUrls.value : []),
    ...(otxUrls.status === "fulfilled" ? otxUrls.value : []),
  ];
  const passiveSeen = new Set<string>();
  for (const raw of passiveRaw) {
    try {
      const u = new URL(raw);
      if (!passiveSeen.has(u.href)) {
        passiveSeen.add(u.href);
        all.push({ url: u.href, path: u.pathname, host, statusCode: 200, source: "wayback", isInteresting: false });
      }
    } catch {}
  }

  // 2. Crawl (Katana/Hakrawler equivalent) — full scan only
  if (isFull) {
    const crawled = await crawlHost(baseUrl);
    for (const u of crawled) {
      if (!passiveSeen.has(u)) {
        try {
          const pu = new URL(u);
          all.push({ url: u, path: pu.pathname, host, statusCode: 200, source: "crawl", isInteresting: false });
        } catch {}
      }
    }
  }

  // 3. Directory fuzzing (Feroxbuster equivalent) — active probing
  const wordlist = isFull ? WORDLIST : WORDLIST_MINI;
  const fuzzResults = await Promise.allSettled(
    wordlist.map(async (word) => {
      await sem.acquire();
      try {
        const url = `${baseUrl}/${word}`;
        const r = await headProbe(url, 5000);
        if (!r) return null;
        // Record 200-399, 401, 403 — skip 404 and errors
        if (r.status === 404 || r.status === 0 || r.status >= 500) return null;
        return {
          url, path: `/${word}`, host,
          statusCode: r.status, contentLength: r.length, contentType: r.type, redirectTo: r.redirect,
          source: "fuzz" as const,
          isInteresting: isInterestingPath(word, r.status),
        } satisfies FuzzedEndpoint;
      } finally { sem.release(); }
    })
  );
  for (const r of fuzzResults) {
    if (r.status === "fulfilled" && r.value) all.push(r.value);
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const deduped = all.filter(e => {
    if (seen.has(e.url)) return false;
    seen.add(e.url);
    return true;
  });

  const stats = {
    fuzzHits:    deduped.filter(e => e.source === "fuzz").length,
    waybackFound: deduped.filter(e => e.source === "wayback" || e.source === "otx").length,
    crawled:     deduped.filter(e => e.source === "crawl").length,
    live200:     deduped.filter(e => e.statusCode >= 200 && e.statusCode < 300).length,
    live301:     deduped.filter(e => e.statusCode >= 300 && e.statusCode < 400).length,
    live401403:  deduped.filter(e => e.statusCode === 401 || e.statusCode === 403).length,
    interesting: deduped.filter(e => e.isInteresting).length,
  };

  return { host, baseUrl, isLive: true, liveStatusCode: liveStatus, endpoints: deduped.slice(0, 2000), stats };
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runDirFuzz(target: string, subdomainNames: string[] = []): Promise<DirFuzzResult> {
  const empty: DirFuzzResult = {
    hosts: [], masterList: [],
    stats: { hostsScanned: 0, hostsLive: 0, totalUnique: 0, liveEndpoints: 0, fuzzHits: 0, waybackFound: 0, crawledFound: 0, interestingEndpoints: 0 },
  };

  let primaryBase: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    primaryBase = `${u.protocol}//${u.hostname}`;
  } catch { return empty; }

  const domain = new URL(primaryBase).hostname.replace(/^www\./, "");

  // Build host list: primary + up to 12 unique subdomains
  const extraBases = [...new Set(
    subdomainNames
      .filter(n => n && !n.includes("*") && n !== domain && n !== `www.${domain}`)
      .slice(0, 12)
      .map(n => `https://${n}`)
  )];

  logger.info({ target, extraHosts: extraBases.length }, "Dir fuzz starting");

  // Run primary (full) + subdomains (mini) in parallel — cap to 4 minutes total
  const results: HostFuzzResult[] = await Promise.race([
    Promise.allSettled([
      fuzzHost(primaryBase, true),
      ...extraBases.map(b => fuzzHost(b, false)),
    ]).then(settled => settled.filter(r => r.status === "fulfilled").map(r => (r as PromiseFulfilledResult<HostFuzzResult>).value)),
    new Promise<HostFuzzResult[]>(r => setTimeout(() => r([]), 4 * 60 * 1000)),
  ]);

  // Build master list: all unique URLs across all hosts, deduplicated
  const masterSeen = new Set<string>();
  const masterList: string[] = [];
  for (const hr of results) {
    for (const ep of hr.endpoints) {
      if (!masterSeen.has(ep.url)) { masterSeen.add(ep.url); masterList.push(ep.url); }
    }
  }

  const liveHosts = results.filter(r => r.isLive);
  const totalEndpoints = results.reduce((s, r) => s + r.endpoints.length, 0);
  const liveEndpoints = results.reduce((s, r) => s + r.stats.live200 + r.stats.live301, 0);

  const stats = {
    hostsScanned:        results.length,
    hostsLive:           liveHosts.length,
    totalUnique:         masterList.length,
    liveEndpoints,
    fuzzHits:            results.reduce((s, r) => s + r.stats.fuzzHits, 0),
    waybackFound:        results.reduce((s, r) => s + r.stats.waybackFound, 0),
    crawledFound:        results.reduce((s, r) => s + r.stats.crawled, 0),
    interestingEndpoints: results.reduce((s, r) => s + r.stats.interesting, 0),
  };

  logger.info({ target, ...stats }, "Dir fuzz complete");

  return {
    hosts: results,
    masterList: masterList.slice(0, 5000), // cap for DB storage
    stats,
  };
}
