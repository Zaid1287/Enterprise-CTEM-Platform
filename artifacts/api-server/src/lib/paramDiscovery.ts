import { logger } from "./logger";

// ── Types ──────────────────────────────────────────────────────────────────────

export type ParamSource   = "archive" | "crawl" | "form" | "brute";
export type ParamCategory = "ssrf_redirect" | "idor" | "xss_sqli" | "auth" | "file_path" | "other";

export interface DiscoveredParam {
  name: string;
  example?: string;
  url: string;
  source: ParamSource;
  method: "GET" | "POST";
  category: ParamCategory;
  confidence: "high" | "medium" | "low";
}

export interface ParamDiscoveryResult {
  params: DiscoveredParam[];
  uniqueNames: string[];
  stats: {
    total: number;
    unique: number;
    fromArchive: number;
    fromCrawl: number;
    fromForm: number;
    fromBrute: number;
    ssrf: number;
    idor: number;
    xss_sqli: number;
    auth: number;
    file_path: number;
    other: number;
  };
}

// ── Category classification ────────────────────────────────────────────────────

const SSRF_REDIRECT = new Set([
  "url", "redirect", "next", "return", "callback", "ref", "referer", "from", "to",
  "dest", "target", "source", "src", "site", "page", "link", "goto", "host", "origin",
  "endpoint", "proxy", "base_url", "forward", "continue", "out", "window", "uri",
  "location", "path_url", "redirect_uri", "redirect_url", "return_url", "target_url",
  "next_url", "success_url", "failure_url", "cancel_url", "ref_url", "back", "backurl",
  "navigation", "redir", "jump", "url_to", "go_to", "open", "view_url", "resource",
]);

const IDOR = new Set([
  "id", "user_id", "account_id", "order_id", "customer_id", "invoice_id", "product_id",
  "item_id", "object_id", "record_id", "doc_id", "file_id", "msg_id", "message_id",
  "post_id", "comment_id", "article_id", "report_id", "ticket_id", "uid", "guid",
  "uuid", "bid", "pid", "oid", "cid", "sid", "tid", "rid", "aid", "vid", "mid",
  "owner", "owner_id", "author_id", "creator_id", "member_id", "subscriber_id",
  "profile_id", "entity_id", "node_id", "parent_id", "child_id", "group_id",
  "team_id", "org_id", "workspace_id", "project_id", "task_id", "issue_id", "bug_id",
  "ref_id", "transaction_id", "payment_id", "booking_id", "reservation_id", "session_id",
]);

const XSS_SQLI = new Set([
  "search", "q", "query", "keyword", "term", "name", "title", "content", "text",
  "message", "comment", "input", "value", "data", "param", "variable", "field",
  "description", "notes", "subject", "body", "username", "email", "phone", "address",
  "first_name", "last_name", "full_name", "tag", "label", "filter", "category",
  "type", "mode", "format", "lang", "locale", "currency", "code", "error", "msg",
  "info", "detail", "reason", "status", "action", "method", "sort", "order",
  "group_by", "having", "where", "column", "table", "field_name", "attr", "key_name",
  "search_term", "search_query", "find", "lookup", "match", "pattern", "expr",
  "str", "string", "text_content", "raw", "html", "markup", "output",
]);

const AUTH_PARAMS = new Set([
  "token", "auth", "api_key", "access_token", "key", "secret", "password", "pass",
  "pwd", "session", "jwt", "bearer", "apikey", "auth_token", "authorization",
  "x_api_key", "client_id", "client_secret", "refresh_token", "id_token",
  "oauth_token", "app_id", "app_key", "app_secret", "consumer_key", "consumer_secret",
  "private_key", "public_key", "signature", "sig", "hmac", "nonce", "otp", "pin",
  "passphrase", "passkey", "security_token", "csrf_token", "xsrf_token",
]);

const FILE_PATH = new Set([
  "file", "path", "dir", "folder", "directory", "template", "include", "module",
  "controller", "view", "layout", "theme", "skin", "style", "plugin", "extension",
  "addon", "component", "action", "cmd", "command", "exec", "execute", "run",
  "upload", "download", "import", "export", "backup", "restore", "archive",
  "filename", "filepath", "file_path", "file_name", "document", "doc", "resource",
  "asset", "media", "image", "img", "photo", "video", "audio", "attachment",
  "static", "public", "private", "local", "remote", "external", "internal",
  "config", "conf", "cfg", "settings", "option", "lang_file", "log", "logfile",
]);

function categorizeParam(name: string): ParamCategory {
  const n = name.toLowerCase().replace(/[-\s]/g, "_");
  if (SSRF_REDIRECT.has(n)) return "ssrf_redirect";
  if (IDOR.has(n))          return "idor";
  if (AUTH_PARAMS.has(n))   return "auth";
  if (FILE_PATH.has(n))     return "file_path";
  if (XSS_SQLI.has(n))     return "xss_sqli";
  return "other";
}

// ── Arjun-style parameter brute-force wordlist (~300 high-impact params) ──────

const ARJUN_WORDLIST = [
  // Identity / IDOR
  "id","user_id","account_id","order_id","customer_id","invoice_id","product_id","item_id",
  "uid","guid","uuid","pid","oid","cid","sid","tid","rid","aid","vid","mid",
  "profile_id","member_id","author_id","post_id","comment_id","report_id","ticket_id",
  "project_id","task_id","group_id","org_id","team_id","transaction_id","payment_id",
  // SSRF / Open Redirect
  "url","redirect","next","return","callback","ref","referer","from","to","dest",
  "target","src","site","link","goto","host","origin","endpoint","proxy","forward",
  "continue","out","uri","location","redirect_uri","redirect_url","return_url","next_url",
  "back","backurl","redir","jump","go_to","open","resource","path_url","success_url",
  // Auth / Secrets
  "token","auth","api_key","access_token","key","secret","password","pass","pwd",
  "apikey","auth_token","client_id","client_secret","refresh_token","id_token",
  "oauth_token","app_id","app_key","signature","sig","nonce","otp","pin","csrf_token",
  "private_key","consumer_key","bearer","session","jwt","x_api_key","app_secret",
  // XSS / SQLi
  "search","q","query","keyword","term","name","title","content","text","message",
  "comment","input","value","data","field","description","notes","subject","body",
  "username","email","filter","category","type","mode","format","lang","locale",
  "code","error","msg","info","detail","reason","status","action","sort","order",
  "group_by","where","column","table","attr","key_name","search_query","find",
  "match","pattern","str","html","output","raw","markup","expr","lookup",
  // File / Path
  "file","path","dir","folder","directory","template","include","module","controller",
  "view","layout","theme","skin","style","plugin","cmd","command","exec","execute",
  "upload","download","import","export","backup","filename","filepath","document",
  "doc","resource","asset","image","img","attachment","config","conf","log","logfile",
  // Pagination / Misc
  "page","limit","offset","start","end","count","per_page","page_size","skip","take",
  "top","max","min","from_date","to_date","date","time","timestamp","version","v",
  "debug","test","admin","role","permission","level","group","privilege","scope",
  "method","tag","label","index","position","hash","ts","year","month","day",
  "width","height","size","color","bg","price","qty","quantity","amount","total",
  "currency","country","region","city","zip","phone","address","lat","lng","radius",
  "language","charset","encoding","callback","jsonp","padding","cors","origin",
  "expand","include_deleted","show_all","verbose","full","compact","minimal",
  "fields","columns","select","projection","embed","populate","depth","flatten",
];

// ── Helpers ────────────────────────────────────────────────────────────────────

const UA = "Mozilla/5.0 (compatible; CTEM-ParamScanner/1.0; +https://sentinelware.io)";

async function fetchText(url: string, timeoutMs = 10000): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

function parseQueryParams(url: string): string[] {
  try {
    const u = new URL(url);
    return [...u.searchParams.keys()];
  } catch {
    const m = url.match(/\?([^#]+)/);
    if (!m) return [];
    return m[1].split("&").map(p => p.split("=")[0]).filter(Boolean);
  }
}

function resolveUrl(href: string, base: string): string | null {
  try { return new URL(href, base).href; } catch { return null; }
}

// ── Source 1: Archived URL parameters (Wayback CDX) ──────────────────────────
// Real data from Wayback Machine — historically crawled URLs with query params

async function fetchArchivedParams(domain: string, baseUrl: string): Promise<DiscoveredParam[]> {
  const results: DiscoveredParam[] = [];
  try {
    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=text&fl=original&collapse=urlkey&limit=3000&filter=statuscode:200&matchType=domain`;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 20000);
    const res = await fetch(cdxUrl, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return results;

    const text = await res.text();
    const urls = text.trim().split("\n").filter(u => u.includes("?"));

    const seenKey = new Set<string>();

    for (const url of urls.slice(0, 2000)) {
      const params = parseQueryParams(url);
      for (const name of params) {
        if (!name || name.length < 2 || name.length > 50) continue;
        const key = `${name}::${url.split("?")[0]}`;
        if (seenKey.has(key)) continue;
        seenKey.add(key);
        // Extract example value
        let example: string | undefined;
        try {
          const u = new URL(url);
          example = u.searchParams.get(name) ?? undefined;
        } catch {}
        results.push({
          name,
          example: example?.slice(0, 60),
          url: url.split("?")[0],
          source: "archive",
          method: "GET",
          category: categorizeParam(name),
          confidence: "high", // historically confirmed real param
        });
      }
    }
  } catch {
    // Wayback CDX unreachable — skip gracefully
  }
  return results;
}

// ── Source 2: Live crawl (ParamSpider equivalent) ────────────────────────────
// Fetches the live page and up to 20 linked pages, extracts form inputs + href params

async function crawlForParams(baseUrl: string): Promise<DiscoveredParam[]> {
  const results: DiscoveredParam[] = [];
  const visited = new Set<string>();
  const queue: string[] = [baseUrl];
  const origin = new URL(baseUrl).origin;
  const seen = new Set<string>();

  const addParam = (name: string, url: string, source: "crawl" | "form", method: "GET" | "POST" = "GET", example?: string) => {
    if (!name || name.length < 2 || name.length > 60) return;
    const key = `${name}::${source}::${url}`;
    if (seen.has(key)) return;
    seen.add(key);
    results.push({ name, example, url, source, method, category: categorizeParam(name), confidence: "medium" });
  };

  while (queue.length > 0 && visited.size < 20) {
    const url = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);

    // Extract params already in the URL being crawled
    for (const name of parseQueryParams(url)) {
      let ex: string | undefined;
      try { ex = new URL(url).searchParams.get(name) ?? undefined; } catch {}
      addParam(name, url.split("?")[0], "crawl", "GET", ex);
    }

    const html = await fetchText(url, 10000);
    if (!html) continue;

    // Form inputs (ParamSpider-style)
    for (const formMatch of html.matchAll(/<form[^>]*action=['"]?([^'">\s]*)['"']?[^>]*method=['"]?([^'">\s]*)['"']?[^>]*>/gi)) {
      const action  = resolveUrl(formMatch[1] || url, origin) ?? url;
      const method  = (formMatch[2] || "GET").toUpperCase() as "GET" | "POST";
      // Extract all inputs within this form block  
      const formBlock = html.slice(formMatch.index!, Math.min(html.length, formMatch.index! + 5000));
      for (const inputMatch of formBlock.matchAll(/<(?:input|select|textarea)[^>]*name=['"]([^'"]+)['"]/gi)) {
        const name = inputMatch[1];
        let ex: string | undefined;
        const valMatch = inputMatch[0].match(/value=['"]([^'"]{0,60})['"]/i);
        if (valMatch) ex = valMatch[1];
        addParam(name, action, "form", method, ex);
      }
    }

    // href params from anchor tags
    for (const m of html.matchAll(/href=['"]([^'"]{1,300})['"]/gi)) {
      const href = m[1];
      const resolved = resolveUrl(href, origin);
      if (!resolved || !resolved.startsWith(origin)) continue;
      for (const name of parseQueryParams(resolved)) {
        let ex: string | undefined;
        try { ex = new URL(resolved).searchParams.get(name) ?? undefined; } catch {}
        addParam(name, resolved.split("?")[0], "crawl", "GET", ex);
      }
      // Queue new pages on the same domain (strip query)
      const clean = resolved.split("?")[0].split("#")[0];
      if (!visited.has(clean) && !queue.includes(clean)) queue.push(clean);
    }
  }

  return results;
}

// ── Source 3: Arjun-style brute-force ─────────────────────────────────────────
// Probes the target with batches of params and detects which ones cause response changes.
// Completely real — sends real HTTP requests and analyses real responses.

const PROBE_BATCH  = 25;   // params per batch request
const PROBE_VALUE  = "CTEMPARAM1337x";   // distinctive test value for reflection/error detection

async function bruteForceParams(baseUrl: string): Promise<DiscoveredParam[]> {
  const results: DiscoveredParam[] = [];

  // Baseline — fetch target twice to get stable response length
  const base1 = await fetchText(baseUrl, 12000);
  if (!base1) return results;
  const base2 = await fetchText(baseUrl, 12000);
  const baseLen = Math.round(((base1.length + (base2?.length ?? base1.length)) / 2));

  // Filter to params not already in the URL
  const existingParams = new Set(parseQueryParams(baseUrl));
  const wordlist = ARJUN_WORDLIST.filter(p => !existingParams.has(p));

  const seen = new Set<string>();

  // Process in batches
  const batches: string[][] = [];
  for (let i = 0; i < wordlist.length; i += PROBE_BATCH) {
    batches.push(wordlist.slice(i, i + PROBE_BATCH));
  }

  // Run batches with limited parallelism (4 at a time to be polite)
  const PARALLEL = 4;
  for (let i = 0; i < batches.length; i += PARALLEL) {
    const batchGroup = batches.slice(i, i + PARALLEL);

    await Promise.allSettled(batchGroup.map(async (batch) => {
      try {
        // Build URL with all params in this batch
        const params = new URLSearchParams();
        for (const p of batch) params.set(p, PROBE_VALUE);
        const batchUrl = baseUrl.includes("?")
          ? `${baseUrl}&${params.toString()}`
          : `${baseUrl}?${params.toString()}`;

        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 10000);
        const res = await fetch(batchUrl, { signal: ctrl.signal, headers: { "User-Agent": UA } });
        clearTimeout(t);
        if (!res.ok && res.status >= 500) return; // server error — skip

        const body = await res.text();
        const bodyLen = body.length;

        // If response length changed significantly OR our probe value is reflected, investigate
        const lenDiff = Math.abs(bodyLen - baseLen) / Math.max(baseLen, 1);
        const reflected = body.includes(PROBE_VALUE);
        if (lenDiff < 0.05 && !reflected) return; // no significant change

        // Binary search: probe each param individually to find which one(s) triggered the change
        await Promise.allSettled(batch.map(async (paramName) => {
          try {
            const singleParams = new URLSearchParams([[paramName, PROBE_VALUE]]);
            const singleUrl = baseUrl.includes("?")
              ? `${baseUrl}&${singleParams.toString()}`
              : `${baseUrl}?${singleParams.toString()}`;

            const ctrl2 = new AbortController();
            const t2 = setTimeout(() => ctrl2.abort(), 8000);
            const res2 = await fetch(singleUrl, { signal: ctrl2.signal, headers: { "User-Agent": UA } });
            clearTimeout(t2);
            if (!res2.ok && res2.status >= 500) return;

            const body2 = await res2.text();
            const singleDiff = Math.abs(body2.length - baseLen) / Math.max(baseLen, 1);
            const singleReflect = body2.includes(PROBE_VALUE);

            if (singleDiff > 0.03 || singleReflect) {
              if (seen.has(paramName)) return;
              seen.add(paramName);
              results.push({
                name: paramName,
                url: baseUrl.split("?")[0],
                source: "brute",
                method: "GET",
                category: categorizeParam(paramName),
                confidence: singleReflect ? "high" : "medium",
                example: singleReflect ? PROBE_VALUE : undefined,
              });
            }
          } catch {}
        }));
      } catch {}
    }));
  }

  return results;
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runParamDiscovery(target: string): Promise<ParamDiscoveryResult> {
  const empty: ParamDiscoveryResult = {
    params: [], uniqueNames: [],
    stats: { total: 0, unique: 0, fromArchive: 0, fromCrawl: 0, fromForm: 0, fromBrute: 0, ssrf: 0, idor: 0, xss_sqli: 0, auth: 0, file_path: 0, other: 0 },
  };

  let base: URL;
  try {
    base = new URL(target.startsWith("http") ? target : `https://${target}`);
  } catch { return empty; }

  const domain = base.hostname.replace(/^www\./, "");
  logger.info({ target, domain }, "Parameter discovery starting");

  // Run all 3 sources in parallel
  const [archivedRes, crawledRes, brutedRes] = await Promise.allSettled([
    fetchArchivedParams(domain, base.href),
    crawlForParams(base.href),
    bruteForceParams(base.href),
  ]);

  const archived = archivedRes.status === "fulfilled" ? archivedRes.value : [];
  const crawled  = crawledRes.status  === "fulfilled" ? crawledRes.value  : [];
  const bruted   = brutedRes.status   === "fulfilled" ? brutedRes.value   : [];

  // Merge all params — deduplicate by name+url+source
  const allParams = [...archived, ...crawled, ...bruted];

  // Deduplicate by (name, url, source) — prefer high confidence
  const seen = new Map<string, DiscoveredParam>();
  for (const p of allParams) {
    const key = `${p.name.toLowerCase()}::${p.url}::${p.source}`;
    const existing = seen.get(key);
    if (!existing || (p.confidence === "high" && existing.confidence !== "high")) {
      seen.set(key, p);
    }
  }
  const params = [...seen.values()];

  // Sort: high confidence first, then by category priority
  const CAT_ORDER: ParamCategory[] = ["ssrf_redirect", "auth", "idor", "file_path", "xss_sqli", "other"];
  params.sort((a, b) => {
    const confOrder = { high: 0, medium: 1, low: 2 };
    const co = confOrder[a.confidence] - confOrder[b.confidence];
    if (co !== 0) return co;
    return CAT_ORDER.indexOf(a.category) - CAT_ORDER.indexOf(b.category);
  });

  // Unique param names (across all sources/URLs)
  const uniqueNames = [...new Set(params.map(p => p.name))];

  const stats = {
    total:       params.length,
    unique:      uniqueNames.length,
    fromArchive: archived.length,
    fromCrawl:   crawled.filter(p => p.source === "crawl").length,
    fromForm:    crawled.filter(p => p.source === "form").length,
    fromBrute:   bruted.length,
    ssrf:        params.filter(p => p.category === "ssrf_redirect").length,
    idor:        params.filter(p => p.category === "idor").length,
    xss_sqli:    params.filter(p => p.category === "xss_sqli").length,
    auth:        params.filter(p => p.category === "auth").length,
    file_path:   params.filter(p => p.category === "file_path").length,
    other:       params.filter(p => p.category === "other").length,
  };

  logger.info({ target, ...stats }, "Parameter discovery complete");

  return { params: params.slice(0, 3000), uniqueNames, stats };
}
