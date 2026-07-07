import { exec } from "child_process";
import { promisify } from "util";
import fs from "fs";
import path from "path";
import dns from "dns/promises";
import { orchestratedFetch } from "./scanOrchestrator";

const execAsync = promisify(exec);

// ── Paths ──────────────────────────────────────────────────────────────────────
const BIN_DIR = "/tmp/subdomain-tools";
const WORDLIST_PATH = path.join(BIN_DIR, "wordlist.txt");

function binPath(name: string): string {
  return path.join(BIN_DIR, name);
}

// ── Binary download URLs (GitHub releases, curl follows 302 to actual release) ─

const TOOL_URLS: Record<string, { url: string; binaryName?: string }> = {
  subfinder: { url: "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip" },
  findomain: { url: "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip", binaryName: "findomain-linux" },
  alterx:    { url: "https://github.com/projectdiscovery/alterx/releases/latest/download/alterx_linux_amd64.zip" },
  dnsx:      { url: "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_linux_amd64.zip" },
  httpx:     { url: "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip" },
};

// ── Types ──────────────────────────────────────────────────────────────────────

export interface EnrichedSubdomain {
  name: string;
  ip: string;
  cname: string | null;
  status: string;
  cdnProvider: string | null;
  sources: string[];
  httpStatus: number | null;
  httpTitle: string | null;
  redirectTo: string | null;
  webServer: string | null;
}

export interface SubdomainScanReport {
  domain: string;
  all: EnrichedSubdomain[];
  live200: EnrichedSubdomain[];
  live401_403: EnrichedSubdomain[];
  liveRedirects: EnrichedSubdomain[];
  dead: EnrichedSubdomain[];
  sourceCounts: Record<string, number>;
  totalPassive: number;
  totalAfterBrute: number;
  totalResolved: number;
  permutationsGenerated: number;
  durationMs: number;
  rawOutput: string;
}

// ── Binary auto-install ────────────────────────────────────────────────────────

async function ensureBinary(name: string): Promise<string | null> {
  // 0. System-installed binary via Nix PATH — fastest, most reliable
  try {
    const r = await execAsync(`which ${name} 2>/dev/null`, { timeout: 3000 });
    const sys = r.stdout.trim();
    if (sys) return sys;
  } catch {}

  const bin = binPath(name);
  if (fs.existsSync(bin)) {
    try { fs.chmodSync(bin, 0o755); } catch {}
    return bin;
  }

  const info = TOOL_URLS[name];
  if (!info) return null;

  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });

  const zipFile = path.join(BIN_DIR, `${name}.zip`);
  try {
    await execAsync(`curl -sL --max-time 120 -o "${zipFile}" "${info.url}"`);

    // Try extracting: tool name or alternate name in zip
    const binaryInZip = info.binaryName ?? name;
    const tryNames = [binaryInZip, name, `${name}_linux_amd64`];
    for (const tryName of tryNames) {
      try {
        await execAsync(`unzip -o -j "${zipFile}" "${tryName}" -d "${BIN_DIR}" 2>/dev/null`);
        const extracted = path.join(BIN_DIR, tryName);
        if (fs.existsSync(extracted) && fs.statSync(extracted).size > 0) {
          if (extracted !== bin) fs.renameSync(extracted, bin);
          fs.chmodSync(bin, 0o755);
          try { fs.unlinkSync(zipFile); } catch {}
          return bin;
        }
      } catch {}
    }

    // Fallback: unzip everything and look for the binary
    await execAsync(`unzip -o -j "${zipFile}" -d "${BIN_DIR}" 2>/dev/null`);
    if (fs.existsSync(bin) && fs.statSync(bin).size > 0) {
      fs.chmodSync(bin, 0o755);
      try { fs.unlinkSync(zipFile); } catch {}
      return bin;
    }
  } catch {}

  return null;
}

// ── Brute-force wordlist ───────────────────────────────────────────────────────

const BRUTE_WORDS = [
  "www","mail","ftp","api","dev","staging","test","beta","app","admin","vpn","remote",
  "portal","cdn","static","img","images","media","assets","auth","sso","login","accounts",
  "secure","account","user","users","member","blog","docs","help","support","forum",
  "community","wiki","status","demo","dashboard","panel","cpanel","manage","management",
  "monitor","monitoring","shop","store","checkout","cart","orders","billing","payment",
  "payments","git","gitlab","github","code","repo","svn","ci","cd","jenkins","travis",
  "jira","confluence","slack","chat","email","smtp","imap","pop","webmail","ops","devops",
  "infra","cloud","db","database","mysql","postgres","redis","mongo","elastic","kibana",
  "grafana","prometheus","influx","metrics","logs","logging","v1","v2","v3","api1","api2",
  "internal","intranet","extranet","rdp","ssh","bastion","gateway","proxy","ns1","ns2",
  "ns3","dns","mx1","mx2","smtp1","smtp2","web","web1","web2","www1","www2","mobile","m",
  "pwa","uat","qa","stg","prod","production","live","sandbox","preview","old","new",
  "legacy","backup","archive","download","downloads","upload","search","analytics",
  "tracking","pixel","events","push","notify","office","corp","corporate","hr","finance",
  "legal","sales","marketing","partner","vendors","client","customers","id","identity",
  "iam","oauth","files","data","feeds","rss","sitemap","health","ping","heartbeat",
  "uptime","incident","mx","relay","bounce","spam","filter","k8s","docker","registry",
  "noc","soc","dev1","dev2","dev3","test1","test2","qa1","qa2","node1","node2","server1",
  "server2","lb1","lb2","edge","origin","cache","connect","webhook","hooks","callback",
  "mgmt","admin2","autodiscover","autoconfig","cname","direct","owa","exchange","cas",
  "mta","mta-sts","dmarc","spf","vpn2","remote2","secure2","login2","auth2","sso2",
  "api3","v4","v5","wap","cp","whm","plesk","ftp2","sftp","nfs","smb","ldap","ad",
  "radius","tacacs","nagios","zabbix","netdata","consul","vault","etcd","minio","s3",
  "blob","storage","backup2","dr","disaster","recovery","failover","cluster","haproxy",
  "nginx","apache","iis","tomcat","jboss","wildfly","websphere","weblogic","oss",
  "assets2","img2","video","videos","audio","stream","live2","rtmp","media2","upload2",
  "cms","wordpress","drupal","joomla","magento","shopify","prestashop","opencart",
  "forms","surveys","crm","erp","hrms","timesheet","expense","procurement","inventory",
  "warehouse","logistics","fleet","tracking2","iot","sensors","telemetry","firmware",
  "update","updates","patch","release","deploy","build","artifact","registry2","hub",
  "api-gateway","apigw","gw","fw","firewall","ids","ips","siem","waf","reverse","nat",
  "dmz","vpn3","ssl","tls","cert","pki","ca","crl","ocsp","ldaps","ad2","adfs","saml",
  "okta","ping","onelogin","duo","mfa","totp","2fa","token","oauth2","oidc","jwt",
  "graphql","rest","soap","grpc","microservice","service","svc","internal2","private",
  "public","shared","common","global","regional","local","us","eu","ap","us-east",
  "us-west","eu-west","eu-central","ap-south","ap-northeast","cn","br","uk","de","fr",
  "jp","in","au","sg","hk","ru","tr","za","ng","mx","ar","cl","co","pe",
  "p","c","i","a","b","d","e","f","g","h","j","k","l","n","o","q","r","s","t","u","v",
  "smtp3","mx3","mail2","mail3","inbound","outbound","bulk","transactional","newsletter",
  "subscription","unsubscribe","bounce2","postmaster","abuse","hostmaster","noreply",
  "donotreply","info","contact","hello","hi","hey","team","legal2","privacy","terms",
  "careers","jobs","press","news","ir","investor","relations","affiliate","reseller",
  "partner2","agent","broker","distributor","franchise","channel","ecosystem","platform",
  "studio","lab","labs","research","innovation","ai","ml","data2","science","bi",
  "intelligence","insight","insights","report","reports","dashboard2","visualize",
  "chart","chart2","metrics2","kpi","scorecard","benchmark","compare","forecast",
];

// ── Utility functions ──────────────────────────────────────────────────────────

function isValidSubdomain(name: string, rootDomain: string): boolean {
  if (!name || name === rootDomain) return false;
  if (!name.endsWith(`.${rootDomain}`)) return false;
  if (/[^a-z0-9.\-]/.test(name)) return false;
  if (name.startsWith("*.")) return false;
  return true;
}

function extractSubdomainsFromUrls(urls: string[], domain: string): string[] {
  const result = new Set<string>();
  for (const url of urls) {
    try {
      const parsed = new URL(url.startsWith("http") ? url : `https://${url}`);
      const host = parsed.hostname.toLowerCase();
      if (isValidSubdomain(host, domain)) result.add(host);
    } catch {}
  }
  return [...result];
}

function detectCdn(ipOrHost: string): string | null {
  if (!ipOrHost) return null;
  if (/cloudfront\.net/i.test(ipOrHost))      return "CloudFront";
  if (/akamaized\.net|akamai/i.test(ipOrHost)) return "Akamai";
  if (/fastly\.net/i.test(ipOrHost))           return "Fastly";
  if (/azureedge\.net/i.test(ipOrHost))        return "Azure CDN";
  if (/cloudflare|cdn\.cloudflare/i.test(ipOrHost)) return "Cloudflare";
  if (/stackpathcdn/i.test(ipOrHost))          return "StackPath";
  if (/llnwd|limelight/i.test(ipOrHost))       return "Limelight";
  if (/edgecastcdn|verizondigitalmedia/i.test(ipOrHost)) return "Edgecast";
  if (/incapsula|imperva/i.test(ipOrHost))     return "Imperva";
  if (/sucuri/i.test(ipOrHost))                return "Sucuri";
  return null;
}

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallback), ms)),
  ]);
}

// ── Passive source: crt.sh ────────────────────────────────────────────────────

async function queryCrtSh(domain: string): Promise<string[]> {
  try {
    const res = await orchestratedFetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    }, { intensity: "passive" });
    if (!res.ok) return [];
    const data: any[] = await res.json().catch(() => []);
    const seen = new Set<string>();
    for (const entry of data) {
      for (const name of (entry.name_value ?? "").split("\n")) {
        const clean = name.toLowerCase().replace(/^\*\./, "").trim();
        if (isValidSubdomain(clean, domain)) seen.add(clean);
      }
    }
    return [...seen];
  } catch { return []; }
}

// ── Passive source: AlienVault OTX ────────────────────────────────────────────

async function queryAlienVault(domain: string): Promise<string[]> {
  try {
    const res = await orchestratedFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    }, { intensity: "passive" });
    if (!res.ok) return [];
    const data = await res.json().catch(() => ({}));
    const subs = new Set<string>();
    for (const entry of data?.passive_dns ?? []) {
      const h = (entry.hostname ?? "").toLowerCase();
      if (isValidSubdomain(h, domain)) subs.add(h);
    }
    // Also check OTX subdomains endpoint
    const res2 = await orchestratedFetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/url_list?limit=100`, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    }, { intensity: "passive" }).catch(() => null);
    if (res2?.ok) {
      const data2 = await res2.json().catch(() => ({}));
      for (const entry of data2?.url_list ?? []) {
        const url = entry?.url ?? "";
        try {
          const h = new URL(url).hostname.toLowerCase();
          if (isValidSubdomain(h, domain)) subs.add(h);
        } catch {}
      }
    }
    return [...subs];
  } catch { return []; }
}

// ── Passive source: Wayback Machine CDX ───────────────────────────────────────

async function queryWayback(domain: string): Promise<string[]> {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}&output=json&fl=original&collapse=urlkey&limit=5000`;
    const res = await orchestratedFetch(url, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    }, { intensity: "passive" });
    if (!res.ok) return [];
    const rows: any[] = await res.json().catch(() => []);
    // rows[0] is header ["original"], skip it
    const urls = rows.slice(1).map(r => r[0] ?? "").filter(Boolean);
    return extractSubdomainsFromUrls(urls, domain);
  } catch { return []; }
}

// ── Passive source: URLScan.io ────────────────────────────────────────────────

async function queryUrlScan(domain: string): Promise<string[]> {
  try {
    const res = await orchestratedFetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=200`, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0" },
    }, { intensity: "passive" });
    if (!res.ok) return [];
    const data = await res.json().catch(() => ({}));
    const subs = new Set<string>();
    for (const result of data?.results ?? []) {
      const h = (result?.page?.domain ?? "").toLowerCase();
      if (isValidSubdomain(h, domain)) subs.add(h);
      // Also extract from page.url
      try {
        const h2 = new URL(result?.page?.url ?? "").hostname.toLowerCase();
        if (isValidSubdomain(h2, domain)) subs.add(h2);
      } catch {}
    }
    return [...subs];
  } catch { return []; }
}

// ── Passive source: RapidDNS ──────────────────────────────────────────────────

async function queryRapidDns(domain: string): Promise<string[]> {
  try {
    const res = await orchestratedFetch(`https://rapiddns.io/subdomain/${domain}?full=1&down=1`, {
      headers: { "User-Agent": "Mozilla/5.0 CTEM-Scanner/1.0", "Accept": "text/plain" },
    }, { intensity: "passive" });
    if (!res.ok) return [];
    const text = await res.text();
    const subs = new Set<string>();
    for (const line of text.split("\n")) {
      const clean = line.trim().toLowerCase();
      if (isValidSubdomain(clean, domain)) subs.add(clean);
    }
    return [...subs];
  } catch { return []; }
}

// ── Passive source: CommonCrawl ───────────────────────────────────────────────

async function queryCommonCrawl(domain: string): Promise<string[]> {
  try {
    // Get the latest CC index
    const infoRes = await orchestratedFetch("https://index.commoncrawl.org/collinfo.json", {}, { intensity: "passive" });
    if (!infoRes.ok) return [];
    const indices: any[] = await infoRes.json().catch(() => []);
    const latest = indices[0]?.id ?? "CC-MAIN-2024-51";

    const ccUrl = `https://index.commoncrawl.org/${latest}/cdx/search?url=*.${domain}&output=json&fl=url&limit=2000`;
    const res = await orchestratedFetch(ccUrl, {}, { intensity: "passive" });
    if (!res.ok) return [];
    const text = await res.text();
    const subs = new Set<string>();
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        const obj = JSON.parse(line);
        const h = new URL(obj.url ?? "").hostname.toLowerCase();
        if (isValidSubdomain(h, domain)) subs.add(h);
      } catch {}
    }
    return [...subs];
  } catch { return []; }
}

// ── Binary tool: subfinder ────────────────────────────────────────────────────

async function runSubfinder(domain: string, bin: string): Promise<string[]> {
  try {
    const { stdout } = await execAsync(
      `"${bin}" -d "${domain}" -silent -all -timeout 30`,
      { timeout: 90_000 },
    );
    const subs = new Set<string>();
    for (const line of stdout.split("\n")) {
      const clean = line.trim().toLowerCase();
      if (isValidSubdomain(clean, domain)) subs.add(clean);
    }
    return [...subs];
  } catch { return []; }
}

// ── Binary tool: findomain ────────────────────────────────────────────────────

async function runFindomain(domain: string, bin: string): Promise<string[]> {
  try {
    const { stdout } = await execAsync(
      `"${bin}" -t "${domain}" -q`,
      { timeout: 90_000 },
    );
    const subs = new Set<string>();
    for (const line of stdout.split("\n")) {
      const clean = line.trim().toLowerCase();
      if (isValidSubdomain(clean, domain)) subs.add(clean);
    }
    return [...subs];
  } catch { return []; }
}

// ── Binary tool: alterx (permutation generation) ──────────────────────────────

async function runAlterX(subdomains: string[], bin: string): Promise<string[]> {
  if (subdomains.length === 0) return [];
  try {
    const inputFile = path.join(BIN_DIR, `alterx-input-${Date.now()}.txt`);
    fs.writeFileSync(inputFile, subdomains.slice(0, 500).join("\n"));
    const { stdout } = await execAsync(
      `"${bin}" -l "${inputFile}" -silent -limit 10000`,
      { timeout: 60_000, maxBuffer: 50 * 1024 * 1024 },
    );
    try { fs.unlinkSync(inputFile); } catch {}
    const perms = new Set<string>();
    for (const line of stdout.split("\n")) {
      const clean = line.trim().toLowerCase();
      const rootDomain = subdomains[0]?.split(".").slice(-2).join(".");
      if (rootDomain && isValidSubdomain(clean, rootDomain)) perms.add(clean);
    }
    return [...perms].slice(0, 10_000);
  } catch { return []; }
}

// ── Binary tool: dnsx (bulk DNS resolution) ───────────────────────────────────

async function runDnsx(candidates: string[], bin: string): Promise<Map<string, string>> {
  if (candidates.length === 0) return new Map();
  const result = new Map<string, string>();
  try {
    const inputFile = path.join(BIN_DIR, `dnsx-input-${Date.now()}.txt`);
    fs.writeFileSync(inputFile, candidates.join("\n"));
    const { stdout } = await execAsync(
      `"${bin}" -l "${inputFile}" -silent -a -resp-only -retry 1 -t 150`,
      { timeout: 90_000, maxBuffer: 50 * 1024 * 1024 },
    );
    try { fs.unlinkSync(inputFile); } catch {}

    // dnsx with -a -resp-only outputs: subdomain\tIP or just subdomains resolved
    // Parse both formats
    const lines = stdout.split("\n").filter(Boolean);
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 2) {
        result.set(parts[0].toLowerCase(), parts[1]);
      } else if (parts.length === 1) {
        result.set(parts[0].toLowerCase(), "");
      }
    }
  } catch {}
  return result;
}

// ── Fallback: Node.js DNS resolution (no binary needed) ───────────────────────

async function resolveWithNodeDns(candidates: string[]): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  const CONCURRENCY = 100;
  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    const batch = candidates.slice(i, i + CONCURRENCY);
    await Promise.allSettled(
      batch.map(async (sub) => {
        try {
          const ips = await dns.resolve4(sub);
          if (ips.length > 0) result.set(sub, ips[0]);
        } catch {}
      }),
    );
  }
  return result;
}

// ── DNS brute-force with built-in wordlist ────────────────────────────────────

async function bruteForceDns(
  domain: string,
  dnsxBin: string | null,
): Promise<Map<string, string>> {
  const candidates = BRUTE_WORDS.map(w => `${w}.${domain}`);

  if (dnsxBin) {
    const res = await runDnsx(candidates, dnsxBin);
    if (res.size > 0) return res;
  }

  // Fallback to Node.js DNS
  return resolveWithNodeDns(candidates);
}

// ── Binary tool: httpx (HTTP probing) ─────────────────────────────────────────

interface HttpxResult {
  status: number;
  title: string;
  webServer: string;
  redirectTo: string;
  technologies: string[];
}

async function runHttpx(
  hosts: string[],
  bin: string,
): Promise<Map<string, HttpxResult>> {
  const result = new Map<string, HttpxResult>();
  if (hosts.length === 0) return result;

  try {
    const inputFile = path.join(BIN_DIR, `httpx-input-${Date.now()}.txt`);
    fs.writeFileSync(inputFile, hosts.join("\n"));
    const { stdout } = await execAsync(
      `"${bin}" -l "${inputFile}" -silent -status-code -title -web-server -location -tech-detect -threads 50 -timeout 8 -no-color -json`,
      { timeout: 90_000, maxBuffer: 100 * 1024 * 1024 },
    );
    try { fs.unlinkSync(inputFile); } catch {}

    for (const line of stdout.split("\n")) {
      if (!line.trim()) continue;
      try {
        const obj = JSON.parse(line);
        const host = (obj.input ?? obj.url ?? "").replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase();
        if (!host) continue;
        result.set(host, {
          status: obj.status_code ?? 0,
          title: obj.title ?? "",
          webServer: obj.webserver ?? obj["web-server"] ?? "",
          redirectTo: obj.location ?? "",
          technologies: obj.tech ?? obj.technologies ?? [],
        });
      } catch {}
    }
  } catch {}
  return result;
}

// ── Fallback: Node.js HTTP probing ────────────────────────────────────────────

async function probeHttpFallback(
  hosts: string[],
): Promise<Map<string, HttpxResult>> {
  const result = new Map<string, HttpxResult>();
  const CONCURRENCY = 30;

  for (let i = 0; i < hosts.length; i += CONCURRENCY) {
    const batch = hosts.slice(i, i + CONCURRENCY);
    await Promise.allSettled(
      batch.map(async (host) => {
        for (const scheme of ["https", "http"]) {
          try {
            const res = await orchestratedFetch(`${scheme}://${host}`, {
              redirect: "manual",
            }, { intensity: "passive" });
            const body = await res.text().catch(() => "");
            const titleMatch = body.match(/<title[^>]*>([^<]*)<\/title>/i);
            const redirectTo = res.headers.get("location") ?? "";
            result.set(host, {
              status: res.status,
              title: titleMatch?.[1]?.trim() ?? "",
              webServer: res.headers.get("server") ?? "",
              redirectTo,
              technologies: [],
            });
            return;
          } catch {}
        }
      }),
    );
  }
  return result;
}

// ── Ensure wordlist file on disk (for dnsx) ───────────────────────────────────

function ensureWordlist(): void {
  if (!fs.existsSync(BIN_DIR)) fs.mkdirSync(BIN_DIR, { recursive: true });
  if (!fs.existsSync(WORDLIST_PATH)) {
    fs.writeFileSync(WORDLIST_PATH, BRUTE_WORDS.join("\n"));
  }
}

// ── Amass integration (Nix PATH) ─────────────────────────────────────────────

async function runAmass(domain: string): Promise<string[]> {
  const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, "").slice(0, 253);
  try {
    const { stdout } = await execAsync(
      `amass enum -passive -d "${safeDomain}" -timeout 5 -nocolor -silent 2>/dev/null`,
      { timeout: 90_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return stdout.trim().split("\n").filter(Boolean).map(l => l.trim().toLowerCase());
  } catch (err) {
    return [];
  }
}

// ── ShuffleDNS integration ────────────────────────────────────────────────────

const SHUFFLEDNS_BIN      = "/tmp/security-tools/shuffledns";
const SHUFFLEDNS_RESOLVERS = "/tmp/shuffledns-resolvers.txt";
const SHUFFLEDNS_WORDLIST  = "/tmp/shuffledns-wordlist.txt";

const SHUFFLE_RESOLVERS = [
  "1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112",
  "208.67.222.222","208.67.220.220","64.6.64.6","64.6.65.6",
  "185.228.168.9","185.228.169.9","77.88.8.8","77.88.8.1",
];

const SHUFFLE_WORDS = [
  "www","mail","ftp","dev","staging","api","admin","test","qa","prod",
  "beta","app","login","auth","portal","dashboard","cdn","media","img",
  "static","assets","data","blog","shop","store","remote","vpn","smtp",
  "pop","imap","mx","ns1","ns2","ns3","dns","web","www2","m","mobile",
  "intranet","internal","secure","support","help","docs","developer",
  "sandbox","demo","ops","monitor","status","smtp2","relay","gateway",
  "backup","bk","old","new","beta2","alpha","feature","v2","v3",
  "mysql","db","database","redis","cache","queue","worker","jobs",
  "service","services","git","gitlab","github","jira","confluence",
  "grafana","kibana","prometheus","vault","consul","k8s","jenkins",
];

function ensureShuffleDnsFiles(): boolean {
  try {
    if (!fs.existsSync(SHUFFLEDNS_RESOLVERS)) {
      fs.writeFileSync(SHUFFLEDNS_RESOLVERS, SHUFFLE_RESOLVERS.join("\n"), "utf8");
    }
    if (!fs.existsSync(SHUFFLEDNS_WORDLIST)) {
      fs.writeFileSync(SHUFFLEDNS_WORDLIST, SHUFFLE_WORDS.join("\n"), "utf8");
    }
    return fs.existsSync(SHUFFLEDNS_BIN);
  } catch { return false; }
}

async function runShuffleDns(domain: string): Promise<string[]> {
  const safeDomain = domain.replace(/[^a-zA-Z0-9.\-]/g, "").slice(0, 253);
  if (!ensureShuffleDnsFiles()) return [];
  const outFile = `/tmp/shuffledns-${safeDomain.replace(/\W/g, "_")}-${Date.now()}.txt`;
  try {
    await execAsync(
      `"${SHUFFLEDNS_BIN}" -d "${safeDomain}" -w "${SHUFFLEDNS_WORDLIST}" -r "${SHUFFLEDNS_RESOLVERS}" -o "${outFile}" -silent 2>/dev/null`,
      { timeout: 120_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    if (!fs.existsSync(outFile)) return [];
    return fs.readFileSync(outFile, "utf8").trim().split("\n")
      .filter(Boolean).map(l => l.trim().toLowerCase());
  } catch { return []; }
  finally {
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function scanSubdomains(domain: string): Promise<SubdomainScanReport> {
  const start = Date.now();
  const rawLines: string[] = [`=== SUBDOMAIN ENUMERATION: ${domain} ===\n`];

  ensureWordlist();

  // ── Phase A: Parallel binary install + passive sources ────────────────────
  rawLines.push("--- Phase A: Passive enumeration (all sources in parallel) ---");

  const [
    subfinderBin, findomainBin, alterxBin, dnsxBin, httpxBin,
    crtShSubs, alienVaultSubs, waybackSubs, urlscanSubs, rapidDnsSubs, commonCrawlSubs,
  ] = await Promise.all([
    // Binary downloads: 30s each (parallel, so wall-clock is max of all 5 = 30s)
    withTimeout(ensureBinary("subfinder"), 30_000, null),
    withTimeout(ensureBinary("findomain"), 30_000, null),
    withTimeout(ensureBinary("alterx"), 30_000, null),
    withTimeout(ensureBinary("dnsx"), 30_000, null),
    withTimeout(ensureBinary("httpx"), 30_000, null),
    withTimeout(queryCrtSh(domain), 16_000, [] as string[]),
    withTimeout(queryAlienVault(domain), 16_000, [] as string[]),
    withTimeout(queryWayback(domain), 16_000, [] as string[]),
    withTimeout(queryUrlScan(domain), 16_000, [] as string[]),
    withTimeout(queryRapidDns(domain), 16_000, [] as string[]),
    withTimeout(queryCommonCrawl(domain), 20_000, [] as string[]),
  ]);

  rawLines.push(`  subfinder binary: ${subfinderBin ? "ready" : "unavailable"}`);
  rawLines.push(`  findomain binary: ${findomainBin ? "ready" : "unavailable"}`);
  rawLines.push(`  alterx binary:    ${alterxBin ? "ready" : "unavailable"}`);
  rawLines.push(`  dnsx binary:      ${dnsxBin ? "ready" : "unavailable"}`);
  rawLines.push(`  httpx binary:     ${httpxBin ? "ready" : "unavailable"}`);

  const sourceCounts: Record<string, number> = {
    "crt.sh": crtShSubs.length,
    "AlienVault OTX": alienVaultSubs.length,
    "Wayback Machine": waybackSubs.length,
    "URLScan.io": urlscanSubs.length,
    "RapidDNS": rapidDnsSubs.length,
    "CommonCrawl": commonCrawlSubs.length,
  };

  rawLines.push(`\nPassive source results:`);
  for (const [src, count] of Object.entries(sourceCounts)) {
    rawLines.push(`  ${src.padEnd(18)}: ${count} subdomains`);
  }

  // ── Phase B: Run binary tools in parallel (subfinder + findomain + amass + shuffledns) ────
  rawLines.push("\n--- Phase B: Binary tool enumeration ---");

  const [subfinderSubs, findomainSubs, amassSubs, shufflednsSubdomains] = await Promise.all([
    subfinderBin ? withTimeout(runSubfinder(domain, subfinderBin), 45_000, [] as string[]) : Promise.resolve([] as string[]),
    findomainBin ? withTimeout(runFindomain(domain, findomainBin), 45_000, [] as string[]) : Promise.resolve([] as string[]),
    withTimeout(runAmass(domain), 90_000, [] as string[]),
    withTimeout(runShuffleDns(domain), 120_000, [] as string[]),
  ]);

  sourceCounts["Subfinder"]  = subfinderSubs.length;
  sourceCounts["Findomain"]  = findomainSubs.length;
  sourceCounts["Amass"]      = amassSubs.length;
  sourceCounts["ShuffleDNS"] = shufflednsSubdomains.length;
  rawLines.push(`  Subfinder:  ${subfinderSubs.length} subdomains`);
  rawLines.push(`  Findomain:  ${findomainSubs.length} subdomains`);
  rawLines.push(`  Amass:      ${amassSubs.length} subdomains`);
  rawLines.push(`  ShuffleDNS: ${shufflednsSubdomains.length} subdomains`);

  // ── Phase C: Merge all passive results ────────────────────────────────────
  rawLines.push("\n--- Phase C: Merge & deduplicate ---");

  const sourceMap = new Map<string, Set<string>>();
  const addSubs = (subs: string[], source: string) => {
    if (!sourceMap.has(source)) sourceMap.set(source, new Set());
    for (const s of subs) {
      if (isValidSubdomain(s, domain)) sourceMap.get(source)!.add(s);
    }
  };

  addSubs(crtShSubs,      "crt.sh");
  addSubs(alienVaultSubs, "AlienVault OTX");
  addSubs(waybackSubs,    "Wayback Machine");
  addSubs(urlscanSubs,    "URLScan.io");
  addSubs(rapidDnsSubs,   "RapidDNS");
  addSubs(commonCrawlSubs,"CommonCrawl");
  addSubs(subfinderSubs,       "Subfinder");
  addSubs(findomainSubs,       "Findomain");
  addSubs(amassSubs,           "Amass");
  addSubs(shufflednsSubdomains,"ShuffleDNS");

  // Build merged set with source tracking
  const mergedMap = new Map<string, Set<string>>(); // subdomain -> set of sources
  for (const [source, subs] of sourceMap.entries()) {
    for (const sub of subs) {
      if (!mergedMap.has(sub)) mergedMap.set(sub, new Set());
      mergedMap.get(sub)!.add(source);
    }
  }

  const totalPassive = mergedMap.size;
  rawLines.push(`  Total unique subdomains (passive): ${totalPassive}`);

  // ── Phase D: AlterX permutations ─────────────────────────────────────────
  rawLines.push("\n--- Phase D: AlterX permutations ---");

  let permutationsGenerated = 0;
  if (alterxBin && mergedMap.size > 0) {
    const permSubs = await withTimeout(
      runAlterX([...mergedMap.keys()], alterxBin),
      60_000, [] as string[],
    );
    permutationsGenerated = permSubs.length;
    rawLines.push(`  Generated ${permutationsGenerated} permutations`);
    for (const p of permSubs) {
      if (!mergedMap.has(p)) {
        mergedMap.set(p, new Set(["AlterX"]));
        if (!sourceCounts["AlterX"]) sourceCounts["AlterX"] = 0;
        sourceCounts["AlterX"]++;
      }
    }
  } else {
    rawLines.push(`  AlterX: ${alterxBin ? "0 permutations" : "binary unavailable"}`);
  }

  // ── Phase E: DNS brute-force ─────────────────────────────────────────────
  rawLines.push("\n--- Phase E: DNS brute-force ---");

  const bruteResults = await withTimeout(
    bruteForceDns(domain, dnsxBin),
    120_000, new Map<string, string>(),
  );

  let bruteNew = 0;
  for (const [sub, ip] of bruteResults.entries()) {
    if (!mergedMap.has(sub)) {
      mergedMap.set(sub, new Set(["DNS Brute-force"]));
      if (!sourceCounts["DNS Brute-force"]) sourceCounts["DNS Brute-force"] = 0;
      sourceCounts["DNS Brute-force"]++;
      bruteNew++;
    } else {
      mergedMap.get(sub)!.add("DNS Brute-force");
    }
  }

  const totalAfterBrute = mergedMap.size;
  rawLines.push(`  Brute-force: ${bruteResults.size} resolved, ${bruteNew} new subdomains`);
  rawLines.push(`  Total candidates after brute-force: ${totalAfterBrute}`);

  // ── Phase F: DNS resolution of all candidates ────────────────────────────
  rawLines.push("\n--- Phase F: Full DNS resolution ---");

  const allCandidates = [...mergedMap.keys()];
  let resolvedMap: Map<string, string>;

  if (dnsxBin) {
    resolvedMap = await withTimeout(
      runDnsx(allCandidates, dnsxBin),
      300_000, new Map<string, string>(),
    );
    if (resolvedMap.size === 0) {
      resolvedMap = await withTimeout(
        resolveWithNodeDns(allCandidates),
        120_000, new Map<string, string>(),
      );
    }
  } else {
    resolvedMap = await withTimeout(
      resolveWithNodeDns(allCandidates),
      120_000, new Map<string, string>(),
    );
  }

  // Also incorporate brute-force resolutions
  for (const [sub, ip] of bruteResults.entries()) {
    if (ip && !resolvedMap.has(sub)) resolvedMap.set(sub, ip);
  }

  const totalResolved = resolvedMap.size;
  rawLines.push(`  Resolved: ${totalResolved} / ${allCandidates.length} subdomains`);

  // ── Phase G: HTTP probing via httpx ──────────────────────────────────────
  rawLines.push("\n--- Phase G: HTTP probing ---");

  const resolvedHosts = [...resolvedMap.keys()];
  let httpxResults: Map<string, HttpxResult>;

  if (httpxBin) {
    httpxResults = await withTimeout(
      runHttpx(resolvedHosts, httpxBin),
      300_000, new Map<string, HttpxResult>(),
    );
    if (httpxResults.size === 0) {
      httpxResults = await withTimeout(
        probeHttpFallback(resolvedHosts),
        120_000, new Map<string, HttpxResult>(),
      );
    }
  } else {
    httpxResults = await withTimeout(
      probeHttpFallback(resolvedHosts),
      120_000, new Map<string, HttpxResult>(),
    );
  }

  rawLines.push(`  HTTP probed: ${httpxResults.size} hosts`);

  // ── Phase H: Build final results ─────────────────────────────────────────
  rawLines.push("\n--- Phase H: Compiling results ---");

  const all: EnrichedSubdomain[] = [];

  for (const [sub, sources] of mergedMap.entries()) {
    const ip = resolvedMap.get(sub) ?? "";
    const httpx = httpxResults.get(sub);
    let cname: string | null = null;
    try { const cns = await dns.resolveCname(sub).catch(() => []); cname = cns[0] ?? null; } catch {}

    const cdn = detectCdn(cname ?? ip);
    const status = ip ? (httpx ? "active" : "resolved") : "unresolved";

    all.push({
      name: sub,
      ip,
      cname,
      status,
      cdnProvider: cdn,
      sources: [...sources],
      httpStatus: httpx?.status ?? null,
      httpTitle: httpx?.title ?? null,
      redirectTo: httpx?.redirectTo ?? null,
      webServer: httpx?.webServer ?? null,
    });
  }

  // Sort: resolved with HTTP first, then resolved without, then unresolved
  all.sort((a, b) => {
    if (a.ip && !b.ip) return -1;
    if (!a.ip && b.ip) return 1;
    if (a.httpStatus && !b.httpStatus) return -1;
    if (!a.httpStatus && b.httpStatus) return 1;
    return a.name.localeCompare(b.name);
  });

  const live200      = all.filter(s => s.httpStatus === 200);
  const live401_403  = all.filter(s => s.httpStatus === 401 || s.httpStatus === 403);
  const liveRedirects= all.filter(s => s.httpStatus && [301, 302, 307, 308].includes(s.httpStatus));
  const dead         = all.filter(s => !s.ip);

  rawLines.push(`  200 OK:        ${live200.length}`);
  rawLines.push(`  401/403:       ${live401_403.length}`);
  rawLines.push(`  Redirects:     ${liveRedirects.length}`);
  rawLines.push(`  Dead/Unresolved: ${dead.length}`);
  rawLines.push(`  Total:         ${all.length}`);
  rawLines.push(`\n  Sample (first 20):`);
  for (const s of all.slice(0, 20)) {
    rawLines.push(`    ${s.name.padEnd(50)} ${(s.ip || "—").padEnd(18)} ${s.httpStatus ?? "—"}`);
  }

  const durationMs = Date.now() - start;
  rawLines.push(`\nTotal duration: ${(durationMs / 1000).toFixed(1)}s`);

  return {
    domain,
    all,
    live200,
    live401_403,
    liveRedirects,
    dead,
    sourceCounts,
    totalPassive,
    totalAfterBrute,
    totalResolved,
    permutationsGenerated,
    durationMs,
    rawOutput: rawLines.join("\n"),
  };
}
