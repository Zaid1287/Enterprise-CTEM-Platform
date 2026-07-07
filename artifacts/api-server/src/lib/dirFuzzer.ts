import { execSync } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";
import { orchestratedExec } from "./orchestratedExec";

const FFUF_WORDLIST = "/home/runner/workspace/wordlists/common.txt";
const FFUF_BIN     = (() => { try { return execSync("which ffuf 2>/dev/null", { timeout: 3000 }).toString().trim(); } catch { return ""; } })();

// ── Types ──────────────────────────────────────────────────────────────────────

export interface FuzzedEndpoint {
  url: string;
  path: string;
  host: string;
  statusCode: number;
  contentLength?: number;
  contentType?: string;
  redirectTo?: string;
  source: "fuzz" | "recursive" | "wayback" | "crawl" | "otx";
  isInteresting: boolean;
  depth: number;
  parentPath: string;
}

export interface HostFuzzResult {
  host: string;
  baseUrl: string;
  isLive: boolean;
  liveStatusCode: number;
  endpoints: FuzzedEndpoint[];
  stats: {
    fuzzHits: number;
    recursiveHits: number;
    waybackFound: number;
    crawled: number;
    live200: number;
    live301: number;
    live401403: number;
    interesting: number;
    maxDepthReached: number;
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
    recursiveHits: number;
    waybackFound: number;
    crawledFound: number;
    interestingEndpoints: number;
    maxDepthReached: number;
  };
}

// ── Wordlist: root-level (~240 paths) ─────────────────────────────────────────

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
  // Docker / CI
  "docker-compose.yml","docker-compose.yaml","Dockerfile",
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

// Mini wordlist for subdomain fuzzing (~85 paths)
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

// Recursive wordlist — directory exploration within discovered directories
const WORDLIST_RECURSIVE: string[] = [
  // Sub-directories of known panels/APIs
  "login","logout","register","signup","users","user","profile","settings","config",
  "admin","manage","dashboard","console","panel",
  "api","v1","v2","v3","graphql","rest",
  "list","index","search","export","import","data","report","reports",
  "create","new","add","edit","update","delete","remove",
  "backup","backups","dump","export.sql","export.csv","data.json",
  // Files
  "index.php","index.html","index.js","index.asp","index.aspx","default.asp","default.aspx",
  "config.php","config.json","config.yml","settings.php","settings.json",
  ".env","env.php","credentials.json","secrets.json","secrets.php",
  "README.md","readme.txt","CHANGELOG.md","INSTALL.md","TODO.md",
  // Debug / info
  "phpinfo.php","info.php","debug","test.php","test","tmp","temp",
  "server-status","health","healthz","status","ping",
  // Uploads / media
  "uploads","files","images","img","media","static","assets","content",
  "download","downloads","attachment","attachments",
  // Auth sub-paths
  "token","refresh","logout","callback","authorize","verify","confirm",
  "forgot","reset","change","mfa","2fa","otp",
  // Common sub-resources
  "log","logs","error.log","access.log","debug.log",
  "metrics","stats","statistics","monitor","monitoring",
];

const INTERESTING_KEYWORDS = [
  "admin","login","password","secret","key","token","auth","config","backup",
  "database","debug","swagger","graphql","actuator","env","git","private","internal",
];

const UA = "Mozilla/5.0 (compatible; CTEM-DirFuzzer/1.0; +https://sentinelware.io)";

// ── Extensions that indicate a file (not a directory for recursion) ───────────
const FILE_EXTENSIONS = new Set([
  ".php",".asp",".aspx",".html",".htm",".js",".css",".json",".yaml",".yml",
  ".xml",".txt",".sql",".zip",".tar",".gz",".log",".csv",".pdf",".png",".jpg",
  ".jpeg",".gif",".ico",".svg",".woff",".woff2",".ttf",".eot",".map",
  ".config",".properties",".env",".md",".sh",".py",".rb",".go",".rs",
]);

const KNOWN_FILE_PATHS = new Set([
  ".env",".env.local",".env.backup",".env.prod",".env.staging",
  "config.json","config.yaml","config.yml","config.xml",
  "settings.json","settings.yaml","secrets.json","credentials.json",
  "wp-config.php","web.config","app.config","application.properties",
  "backup.sql","backup.zip","database.sql","db.sql","dump.sql","data.sql",
  ".aws/credentials",".htpasswd","id_rsa","id_rsa.pub",
  "robots.txt","sitemap.xml","sitemap_index.xml","sitemap.txt",
  "humans.txt","ads.txt","app-ads.txt","security.txt",
  ".git/HEAD",".git/config",".gitignore",".dockerignore",
  "phpinfo.php","info.php","php-info.php",
  "node_modules/.package-lock.json",".npmrc","package.json","yarn.lock","package-lock.json",
  ".kube/config","kubernetes/config",
  "docker-compose.yml","docker-compose.yaml","Dockerfile",
  ".travis.yml","Jenkinsfile",".github/workflows",".gitlab-ci.yml",
  "Makefile","build.gradle","pom.xml","requirements.txt","Gemfile","composer.json",
  "export.json","export.csv","data.json","data.csv",
  "error.log","access.log","debug.log","error_log","php_error.log",
  "xmlrpc.php","wp-json/wp/v2/users",
  "manifest.json","manifest.webmanifest","service-worker.js","sw.js",
  "crossdomain.xml","browserconfig.xml","favicon.ico",
]);

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
  url: string, _timeoutMs = 5000
): Promise<{ status: number; length?: number; type?: string; redirect?: string } | null> {
  try {
    const res = await orchestratedFetch(url, {
      method: "HEAD", redirect: "manual",
      headers: { "User-Agent": UA, "Connection": "close" },
    }, { intensity: "endpoint-discovery" });
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

async function getHtml(url: string, _timeoutMs = 10000): Promise<string> {
  try {
    const res = await orchestratedFetch(url, { headers: { "User-Agent": UA } }, { intensity: "endpoint-discovery" });
    if (!res.ok) return "";
    return (await res.text()).slice(0, 200_000);
  } catch { return ""; }
}

// ── Passive URL sources ───────────────────────────────────────────────────────

async function fetchWayback(host: string): Promise<string[]> {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(host + "/*")}&output=json&fl=original&collapse=urlkey&limit=500&filter=statuscode:200&matchType=domain`;
    const res = await orchestratedFetch(url, { headers: { "User-Agent": UA } }, { intensity: "passive" });
    if (!res.ok) return [];
    const data = await res.json().catch(() => []) as string[][];
    return data.slice(1).map(row => row[0]).filter(Boolean);
  } catch { return []; }
}

async function fetchOtx(host: string): Promise<string[]> {
  try {
    const url = `https://otx.alienvault.com/api/v1/indicators/hostname/${host}/url_list?limit=200`;
    const res = await orchestratedFetch(url, { headers: { "User-Agent": UA } }, { intensity: "passive" });
    if (!res.ok) return [];
    const data = await res.json().catch(() => null) as any;
    if (!data?.url_list) return [];
    return (data.url_list as Array<{ url: string }>).map(u => u.url).filter(Boolean);
  } catch { return []; }
}

// ── Crawler ───────────────────────────────────────────────────────────────────

async function crawlHost(baseUrl: string): Promise<string[]> {
  const html = await getHtml(baseUrl);
  if (!html) return [];
  const base = new URL(baseUrl);
  const urls = new Set<string>();
  const attrRe  = /(?:href|src|action|data-url|data-href|data-endpoint)\s*=\s*["']([^"'#\s]+)/gi;
  const jsPathRe = /["'`](\/[a-zA-Z0-9_\-./]{3,100})["'`]/g;
  let m: RegExpExecArray | null;
  while ((m = attrRe.exec(html)) !== null) {
    try {
      const u = new URL(m[1], baseUrl);
      if (u.hostname === base.hostname && u.pathname !== "/" && u.pathname !== "") urls.add(u.href);
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

// ── Path heuristics ───────────────────────────────────────────────────────────

function isInterestingPath(path: string, status: number): boolean {
  const p = path.toLowerCase();
  if (status >= 200 && status < 300) return true;
  if (status === 401 || status === 403) return INTERESTING_KEYWORDS.some(kw => p.includes(kw));
  return false;
}

/** Returns true if a path looks like a browseable directory (not a file) */
function isDirectoryLike(word: string, status: number): boolean {
  if (![200, 201, 301, 302, 307, 308, 403].includes(status)) return false;
  // Known file paths are not directories
  if (KNOWN_FILE_PATHS.has(word)) return false;
  // Check last segment for a file extension
  const lastSegment = word.split("/").pop() ?? word;
  const dotIdx = lastSegment.lastIndexOf(".");
  if (dotIdx > 0) {
    const ext = lastSegment.slice(dotIdx).toLowerCase();
    if (FILE_EXTENSIONS.has(ext)) return false;
  }
  return true;
}

// ── Core fuzzer: probes a wordlist under a base URL ──────────────────────────

async function probeWordlist(
  baseUrl: string,
  host: string,
  wordlist: string[],
  visited: Set<string>,
  sem: Semaphore,
  depth: number,
  parentPath: string,
  source: "fuzz" | "recursive",
  maxEndpoints: number,
  accumulator: FuzzedEndpoint[],
): Promise<string[]> {
  const directoriesFound: string[] = [];

  const tasks = wordlist.map(async (word) => {
    if (accumulator.length >= maxEndpoints) return;
    const url = `${baseUrl}/${word}`;
    if (visited.has(url)) return;
    visited.add(url);

    await sem.acquire();
    try {
      const r = await headProbe(url, 5000);
      if (!r) return;
      // Skip 404 and server errors
      if (r.status === 404 || r.status === 0 || r.status >= 500) return;

      const endpoint: FuzzedEndpoint = {
        url,
        path: `/${word}`,
        host,
        statusCode:    r.status,
        contentLength: r.length,
        contentType:   r.type,
        redirectTo:    r.redirect,
        source,
        isInteresting: isInterestingPath(word, r.status),
        depth,
        parentPath,
      };
      accumulator.push(endpoint);

      // Flag directory-like paths for recursion
      if (isDirectoryLike(word, r.status)) {
        directoriesFound.push(word);
      }
    } finally { sem.release(); }
  });

  await Promise.allSettled(tasks);
  return directoriesFound;
}

// ── Per-host fuzzer with recursive BFS ───────────────────────────────────────

const MAX_DEPTH    = 3;
const MAX_ENDPOINTS = 2000;
const SEM_SIZE     = 25;

// ── ffuf binary integration ───────────────────────────────────────────────────

interface FfufResult { url: string; status: number; length: number; redirectlocation?: string }

async function runFfuf(baseUrl: string, host: string): Promise<FuzzedEndpoint[]> {
  if (!FFUF_BIN || !fs.existsSync(FFUF_WORDLIST)) return [];
  const outFile = path.join(os.tmpdir(), `ffuf-${host.replace(/\W/g, "_")}-${Date.now()}.json`);
  try {
    const cmd = [
      FFUF_BIN,
      "-u", `${baseUrl}/FUZZ`,
      "-w", FFUF_WORDLIST,
      "-mc", "200,201,204,301,302,307,401,403",
      "-t", "40",
      "-timeout", "10",
      "-of", "json",
      "-o", outFile,
      "-s",   // silent — no progress output
    ].join(" ");
    await orchestratedExec(
      (proxyUrl) => proxyUrl ? `${cmd} -replay-proxy "${proxyUrl}"` : cmd,
      { timeout: 90000, targetHost: host },
    ).catch(() => null);
    if (!fs.existsSync(outFile)) return [];
    const raw = fs.readFileSync(outFile, "utf8");
    fs.unlinkSync(outFile);
    const data = JSON.parse(raw) as { results?: FfufResult[] };
    const results = data.results ?? [];
    logger.info({ host, count: results.length }, "ffuf scan complete");
    return results.map(r => ({
      url:           r.url,
      path:          (() => { try { return new URL(r.url).pathname; } catch { return r.url; } })(),
      host,
      statusCode:    r.status,
      contentLength: r.length,
      redirectTo:    r.redirectlocation ?? undefined,
      source:        "fuzz" as const,
      isInteresting: INTERESTING_KEYWORDS.some(kw => r.url.includes(kw)),
      depth:         0,
      parentPath:    "",
    }));
  } catch (err) {
    logger.warn({ err, host }, "ffuf scan failed");
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
    return [];
  }
}

// ── Gobuster integration ──────────────────────────────────────────────────────

async function runGobuster(baseUrl: string, host: string): Promise<FuzzedEndpoint[]> {
  const wlFile = path.join(os.tmpdir(), `gob-wl-${Date.now()}.txt`);
  const outFile = path.join(os.tmpdir(), `gobuster-${host.replace(/\W/g, "_")}-${Date.now()}.txt`);
  try {
    fs.writeFileSync(wlFile, [...WORDLIST, ...WORDLIST_MINI].filter((v, i, a) => a.indexOf(v) === i).join("\n"));
    await orchestratedExec(
      (proxyUrl) => `gobuster dir -u "${baseUrl}" -w "${wlFile}" -o "${outFile}" -q -t 25 --timeout 10s --no-error${proxyUrl ? ` --proxy "${proxyUrl}"` : ""} 2>/dev/null`,
      { timeout: 90_000, targetHost: host },
    ).catch(() => null);
    if (!fs.existsSync(outFile)) return [];
    return fs.readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean).flatMap(line => {
      const m = line.match(/^(\S+)\s+\(Status:\s*(\d+)\)/);
      if (!m) return [];
      const [, urlPath, statusStr] = m;
      const status = parseInt(statusStr, 10);
      const redirect = line.match(/-->\s*(\S+)/)?.[1];
      const fullPath = urlPath.startsWith("/") ? urlPath : `/${urlPath}`;
      return [{ url: `${baseUrl}${fullPath}`, path: fullPath, host, statusCode: status, redirectTo: redirect, source: "fuzz" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => fullPath.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
    });
  } catch { return []; }
  finally {
    try { if (fs.existsSync(wlFile)) fs.unlinkSync(wlFile); } catch {}
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── Feroxbuster integration ───────────────────────────────────────────────────

async function runFeroxbuster(baseUrl: string, host: string): Promise<FuzzedEndpoint[]> {
  const wlFile = path.join(os.tmpdir(), `ferox-wl-${Date.now()}.txt`);
  const outFile = path.join(os.tmpdir(), `ferox-${host.replace(/\W/g, "_")}-${Date.now()}.txt`);
  try {
    fs.writeFileSync(wlFile, WORDLIST.join("\n"));
    await orchestratedExec(
      (proxyUrl) => `feroxbuster -u "${baseUrl}" -w "${wlFile}" -o "${outFile}" --no-state --silent -t 25 --timeout 10 -k${proxyUrl ? ` --proxy "${proxyUrl}"` : ""} 2>/dev/null`,
      { timeout: 90_000, targetHost: host },
    ).catch(() => null);
    if (!fs.existsSync(outFile)) return [];
    return fs.readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean).flatMap(line => {
      const m = line.match(/^(\d{3})\s+\w+\s+\S+\s+\S+\s+\S+\s+(\S+)/);
      if (!m) return [];
      const [, statusStr, rawUrl] = m;
      try {
        const u = new URL(rawUrl);
        return [{ url: u.href, path: u.pathname, host, statusCode: parseInt(statusStr, 10), source: "fuzz" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => u.pathname.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
      } catch { return []; }
    });
  } catch { return []; }
  finally {
    try { if (fs.existsSync(wlFile)) fs.unlinkSync(wlFile); } catch {}
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── Katana web crawler integration ────────────────────────────────────────────

async function runKatana(baseUrl: string, host: string): Promise<FuzzedEndpoint[]> {
  const outFile = path.join(os.tmpdir(), `katana-${host.replace(/\W/g, "_")}-${Date.now()}.txt`);
  try {
    await orchestratedExec(
      (proxyUrl) => `katana -u "${baseUrl}" -o "${outFile}" -silent -depth 3 -jc -kf all -timeout 10 -rl 50 -no-color${proxyUrl ? ` -proxy "${proxyUrl}"` : ""} 2>/dev/null`,
      { timeout: 90_000, targetHost: host },
    ).catch(() => null);
    if (!fs.existsSync(outFile)) return [];
    return fs.readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean).flatMap(line => {
      try {
        const u = new URL(line.trim());
        if (u.hostname !== host) return [];
        return [{ url: u.href, path: u.pathname, host, statusCode: 200, source: "crawl" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => u.pathname.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
      } catch { return []; }
    });
  } catch { return []; }
  finally {
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── GAU integration ───────────────────────────────────────────────────────────

const GAU_BIN = "/tmp/security-tools/gau";

async function runGau(host: string): Promise<FuzzedEndpoint[]> {
  if (!fs.existsSync(GAU_BIN)) return [];
  try {
    const { stdout } = await orchestratedExec(
      `"${GAU_BIN}" --threads 5 --timeout 10 --retries 1 --blacklist png,jpg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3 "${host}" 2>/dev/null`,
      { timeout: 60_000, targetHost: host },
    );
    return stdout.trim().split("\n").filter(Boolean).flatMap(rawUrl => {
      try {
        const u = new URL(rawUrl.trim());
        if (u.hostname !== host && !u.hostname.endsWith(`.${host}`)) return [];
        return [{ url: u.href, path: u.pathname, host, statusCode: 200, source: "wayback" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => u.pathname.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
      } catch { return []; }
    });
  } catch { return []; }
}

// ── Waybackurls integration ───────────────────────────────────────────────────

const WAYBACKURLS_BIN = "/tmp/security-tools/waybackurls";

async function runWaybackurlsBin(host: string): Promise<FuzzedEndpoint[]> {
  if (!fs.existsSync(WAYBACKURLS_BIN)) return [];
  try {
    const { stdout } = await orchestratedExec(
      `echo "${host}" | "${WAYBACKURLS_BIN}" 2>/dev/null`,
      { timeout: 60_000, targetHost: host },
    );
    return stdout.trim().split("\n").filter(Boolean).flatMap(rawUrl => {
      try {
        const u = new URL(rawUrl.trim());
        if (u.hostname !== host && !u.hostname.endsWith(`.${host}`)) return [];
        return [{ url: u.href, path: u.pathname, host, statusCode: 200, source: "wayback" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => u.pathname.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
      } catch { return []; }
    });
  } catch { return []; }
}

// ── Hakrawler integration ─────────────────────────────────────────────────────

const HAKRAWLER_BIN = path.join(process.env.HOME ?? "/home/runner", "go/bin/hakrawler");

async function runHakrawler(baseUrl: string, host: string): Promise<FuzzedEndpoint[]> {
  if (!fs.existsSync(HAKRAWLER_BIN)) return [];
  try {
    const { stdout } = await orchestratedExec(
      `echo "${baseUrl}" | "${HAKRAWLER_BIN}" -depth 3 -insecure -subs 2>/dev/null`,
      { timeout: 60_000, targetHost: host },
    );
    return stdout.trim().split("\n").filter(Boolean).flatMap(rawUrl => {
      try {
        const u = new URL(rawUrl.trim());
        if (u.hostname !== host && !u.hostname.endsWith(`.${host}`)) return [];
        return [{ url: u.href, path: u.pathname, host, statusCode: 200, source: "crawl" as const, isInteresting: INTERESTING_KEYWORDS.some(kw => u.pathname.toLowerCase().includes(kw)), depth: 0, parentPath: "" }];
      } catch { return []; }
    });
  } catch { return []; }
}

async function fuzzHost(baseUrl: string, isFull: boolean): Promise<HostFuzzResult> {
  let host: string;
  try { host = new URL(baseUrl).hostname; } catch { return emptyHost(baseUrl, "unknown", false, 0); }

  const liveness = await headProbe(baseUrl, 8000);
  if (!liveness || liveness.status === 0) {
    const httpBase = baseUrl.startsWith("https://") ? baseUrl.replace("https://", "http://") : null;
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
  return {
    host, baseUrl, isLive, liveStatusCode: code, endpoints: [],
    stats: { fuzzHits: 0, recursiveHits: 0, waybackFound: 0, crawled: 0, live200: 0, live301: 0, live401403: 0, interesting: 0, maxDepthReached: 0 },
  };
}

async function fuzzLiveHost(baseUrl: string, host: string, liveStatus: number, isFull: boolean): Promise<HostFuzzResult> {
  const sem     = new Semaphore(SEM_SIZE);
  const visited = new Set<string>();
  const all: FuzzedEndpoint[] = [];

  // 1. Passive sources (Wayback + OTX)
  const [wbUrls, otxUrls] = await Promise.allSettled([
    fetchWayback(host),
    isFull ? fetchOtx(host) : Promise.resolve<string[]>([]),
  ]);
  const passiveRaw = [
    ...(wbUrls.status  === "fulfilled" ? wbUrls.value  : []),
    ...(otxUrls.status === "fulfilled" ? otxUrls.value : []),
  ];
  const passiveSeen = new Set<string>();
  for (const raw of passiveRaw) {
    try {
      const u = new URL(raw);
      if (!passiveSeen.has(u.href)) {
        passiveSeen.add(u.href);
        all.push({ url: u.href, path: u.pathname, host, statusCode: 200, source: "wayback", isInteresting: false, depth: 0, parentPath: "" });
      }
    } catch {}
  }

  // 2. Crawl
  if (isFull) {
    const crawled = await crawlHost(baseUrl);
    for (const u of crawled) {
      if (!passiveSeen.has(u)) {
        try {
          const pu = new URL(u);
          all.push({ url: u, path: pu.pathname, host, statusCode: 200, source: "crawl", isInteresting: false, depth: 0, parentPath: "" });
        } catch {}
      }
    }
  }

  // 3. Root-level active fuzz (depth 0) — all binary tools in parallel
  const rootWordlist = isFull ? WORDLIST : WORDLIST_MINI;
  const [depth0Dirs, ffufHits, gobusterHits, feroxHits, katanaHits, gauHits, waybackBinHits, hakrawlerHits] = await Promise.all([
    probeWordlist(baseUrl, host, rootWordlist, visited, sem, 0, "", "fuzz", MAX_ENDPOINTS, all),
    runFfuf(baseUrl, host),
    isFull ? runGobuster(baseUrl, host) : Promise.resolve<FuzzedEndpoint[]>([]),
    isFull ? runFeroxbuster(baseUrl, host) : Promise.resolve<FuzzedEndpoint[]>([]),
    runKatana(baseUrl, host),
    runGau(host),
    runWaybackurlsBin(host),
    runHakrawler(baseUrl, host),
  ]);
  // Merge all binary tool results — deduplicate by URL
  const seenUrls = new Set(all.map(e => e.url));
  for (const r of [...ffufHits, ...gobusterHits, ...feroxHits, ...katanaHits, ...gauHits, ...waybackBinHits, ...hakrawlerHits]) {
    if (!seenUrls.has(r.url) && all.length < MAX_ENDPOINTS) {
      seenUrls.add(r.url);
      visited.add(r.url);
      all.push(r);
    }
  }

  // 4. Recursive BFS — fuzz inside discovered directories
  let maxDepthReached = 0;

  interface BFSEntry { base: string; depth: number; parentPath: string; dirs: string[] }
  const bfsQueue: BFSEntry[] = depth0Dirs.map(d => ({
    base: `${baseUrl}/${d}`,
    depth: 1,
    parentPath: `/${d}`,
    dirs: [],
  }));

  while (bfsQueue.length > 0 && all.length < MAX_ENDPOINTS) {
    const batch = bfsQueue.splice(0, 5); // process up to 5 dirs per wave
    const waveResults = await Promise.allSettled(
      batch.map(async ({ base, depth, parentPath }) => {
        if (depth > MAX_DEPTH || all.length >= MAX_ENDPOINTS) return [];
        const discovered = await probeWordlist(
          base, host, WORDLIST_RECURSIVE, visited, sem,
          depth, parentPath, "recursive", MAX_ENDPOINTS, all
        );
        return discovered.map(d => ({
          base: `${base}/${d}`,
          depth: depth + 1,
          parentPath: `${parentPath}/${d}`,
          dirs: [],
        }));
      })
    );

    for (const result of waveResults) {
      if (result.status === "fulfilled") {
        for (const entry of result.value) {
          if (entry.depth <= MAX_DEPTH) {
            bfsQueue.push(entry);
            if (entry.depth > maxDepthReached) maxDepthReached = entry.depth;
          }
        }
      }
    }
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const deduped = all.filter(e => {
    if (seen.has(e.url)) return false;
    seen.add(e.url);
    return true;
  });

  const stats = {
    fuzzHits:      deduped.filter(e => e.source === "fuzz").length,
    recursiveHits: deduped.filter(e => e.source === "recursive").length,
    waybackFound:  deduped.filter(e => e.source === "wayback" || e.source === "otx").length,
    crawled:       deduped.filter(e => e.source === "crawl").length,
    live200:       deduped.filter(e => e.statusCode >= 200 && e.statusCode < 300).length,
    live301:       deduped.filter(e => e.statusCode >= 300 && e.statusCode < 400).length,
    live401403:    deduped.filter(e => e.statusCode === 401 || e.statusCode === 403).length,
    interesting:   deduped.filter(e => e.isInteresting).length,
    maxDepthReached,
  };

  return { host, baseUrl, isLive: true, liveStatusCode: liveStatus, endpoints: deduped.slice(0, MAX_ENDPOINTS), stats };
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runDirFuzz(target: string, subdomainNames: string[] = []): Promise<DirFuzzResult> {
  const empty: DirFuzzResult = {
    hosts: [], masterList: [],
    stats: { hostsScanned: 0, hostsLive: 0, totalUnique: 0, liveEndpoints: 0, fuzzHits: 0, recursiveHits: 0, waybackFound: 0, crawledFound: 0, interestingEndpoints: 0, maxDepthReached: 0 },
  };

  let primaryBase: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    primaryBase = `${u.protocol}//${u.hostname}`;
  } catch { return empty; }

  const domain = new URL(primaryBase).hostname.replace(/^www\./, "");

  const extraBases = [...new Set(
    subdomainNames
      .filter(n => n && !n.includes("*") && n !== domain && n !== `www.${domain}`)
      .slice(0, 12)
      .map(n => `https://${n}`)
  )];

  logger.info({ target, extraHosts: extraBases.length }, "Dir fuzz starting (recursive enabled)");

  const results: HostFuzzResult[] = await Promise.race([
    Promise.allSettled([
      fuzzHost(primaryBase, true),
      ...extraBases.map(b => fuzzHost(b, false)),
    ]).then(settled =>
      settled.filter(r => r.status === "fulfilled").map(r => (r as PromiseFulfilledResult<HostFuzzResult>).value)
    ),
    new Promise<HostFuzzResult[]>(r => setTimeout(() => r([]), 5 * 60 * 1000)),
  ]);

  const masterSeen = new Set<string>();
  const masterList: string[] = [];
  for (const hr of results) {
    for (const ep of hr.endpoints) {
      if (!masterSeen.has(ep.url)) { masterSeen.add(ep.url); masterList.push(ep.url); }
    }
  }

  const liveHosts      = results.filter(r => r.isLive);
  const totalEndpoints = results.reduce((s, r) => s + r.endpoints.length, 0);
  const liveEndpoints  = results.reduce((s, r) => s + r.stats.live200 + r.stats.live301, 0);
  const overallMaxDepth = results.reduce((m, r) => Math.max(m, r.stats.maxDepthReached), 0);

  const stats = {
    hostsScanned:        results.length,
    hostsLive:           liveHosts.length,
    totalUnique:         masterList.length,
    liveEndpoints,
    fuzzHits:            results.reduce((s, r) => s + r.stats.fuzzHits, 0),
    recursiveHits:       results.reduce((s, r) => s + r.stats.recursiveHits, 0),
    waybackFound:        results.reduce((s, r) => s + r.stats.waybackFound, 0),
    crawledFound:        results.reduce((s, r) => s + r.stats.crawled, 0),
    interestingEndpoints: results.reduce((s, r) => s + r.stats.interesting, 0),
    maxDepthReached:     overallMaxDepth,
  };

  logger.info({ target, ...stats }, "Dir fuzz complete");

  return { hosts: results, masterList: masterList.slice(0, 5000), stats };
}
