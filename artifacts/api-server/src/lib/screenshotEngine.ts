import puppeteer, { type Browser } from "puppeteer-core";
import https from "https";
import http from "http";
import { execFileSync } from "child_process";

export interface PageScreenshot {
  url:            string;
  pageType:       "index" | "login" | "signup" | "admin" | "api" | "sensitive" | "error";
  screenshotData: string; // base64-encoded PNG
  title:          string;
  statusCode:     number;
  findings:       SensitiveFinding[];
}

export interface SensitiveFinding {
  type:     string;
  value:    string;
  severity: "critical" | "high" | "medium" | "low";
  context?: string;
}

// ── Secret patterns to scan for in page source ────────────────────────────────
const SENSITIVE_PATTERNS: Array<{ name: string; re: RegExp; severity: SensitiveFinding["severity"]; mask: boolean }> = [
  // Cloud & infrastructure
  { name: "AWS Access Key",         re: /AKIA[0-9A-Z]{16}/g,                                                   severity: "critical", mask: true  },
  { name: "AWS Secret Key",         re: /(?:aws.{0,10}secret|secret.{0,10}key)\s*[:=]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi, severity: "critical", mask: true },
  { name: "AWS Session Token",      re: /FwoGZXIvYXdz[A-Za-z0-9/+=]{100,}/g,                                   severity: "critical", mask: true  },
  // Version control & CI
  { name: "GitHub Token",           re: /gh[pos]_[A-Za-z0-9]{36}/g,                                            severity: "critical", mask: true  },
  { name: "GitHub App Token",       re: /ghu_[A-Za-z0-9]{36}/g,                                                severity: "critical", mask: true  },
  // Payment
  { name: "Stripe Secret Key",      re: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,                                  severity: "critical", mask: true  },
  { name: "Stripe Publishable Key", re: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,                                  severity: "medium",   mask: false },
  // Communication
  { name: "Slack Token",            re: /xox[baprs]-[A-Za-z0-9-]+/g,                                           severity: "high",     mask: true  },
  { name: "Slack Webhook URL",      re: /https:\/\/hooks\.slack\.com\/services\/[^\s'"<>]+/g,                   severity: "medium",   mask: false },
  { name: "Twilio Account SID",     re: /AC[0-9a-f]{32}/g,                                                     severity: "high",     mask: true  },
  { name: "SendGrid API Key",       re: /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{43,}/g,                      severity: "critical", mask: true  },
  // AI / LLM
  { name: "OpenAI API Key",         re: /sk-(?:proj-)?[A-Za-z0-9_\-]{48,}/g,                                   severity: "critical", mask: true  },
  { name: "Anthropic API Key",      re: /sk-ant-[A-Za-z0-9_\-]{40,}/g,                                         severity: "critical", mask: true  },
  // Google
  { name: "Google API Key",         re: /AIza[0-9A-Za-z\-_]{35}/g,                                             severity: "critical", mask: true  },
  { name: "Firebase Config",        re: /firebaseConfig\s*=\s*\{[^}]+apiKey\s*:\s*['"][^'"]+['"]/g,            severity: "high",     mask: false },
  // Generic patterns
  { name: "Generic API Key",        re: /(?:api_key|apikey|api[-_]?key)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]?/gi, severity: "high", mask: true },
  { name: "Bearer Token",           re: /authorization\s*[:=]\s*['"]?bearer\s+([A-Za-z0-9._\-]{20,})['"]?/gi, severity: "high",     mask: true  },
  { name: "Private Key Block",      re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,                  severity: "critical", mask: false },
  { name: "Basic Auth in URL",      re: /https?:\/\/[^:]+:[^@]{4,}@[a-zA-Z0-9.]+/g,                           severity: "high",     mask: true  },
  { name: "Database URL",           re: /(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^\s'"<>]+/gi,        severity: "critical", mask: true  },
  { name: "npm Token",              re: /npm_[A-Za-z0-9]{36}/g,                                                 severity: "high",     mask: true  },
  { name: "Mailchimp Key",          re: /[0-9a-f]{32}-us\d{1,2}/g,                                             severity: "high",     mask: true  },
  { name: "JWT Token",              re: /eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, severity: "high",     mask: true  },
  { name: "Hardcoded Password",     re: /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"<>\s]{8,}['"]/gi,            severity: "high",     mask: true  },
  { name: "Connection String",      re: /(?:Server|Data Source)\s*=[^;]+;[^;]*(?:Password|Pwd)\s*=[^;'"<>\s]+/gi, severity: "critical", mask: true },
  { name: "Exposed .env Variable",  re: /^(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY)\s*=\s*['"]?[^\s'"<>]{8,}['"]?/gim, severity: "high", mask: true },
  // Info disclosure
  { name: "Internal IP",            re: /(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d+\.\d+/g,           severity: "medium",   mask: false },
  { name: "Email Address",          re: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,                  severity: "low",      mask: false },
  { name: "Google Analytics ID",    re: /(?:UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10})/g,                            severity: "low",      mask: false },
];

// ── Page type detection ───────────────────────────────────────────────────────
const LOGIN_PATHS    = ["/login", "/signin", "/sign-in", "/auth", "/auth/login", "/user/login", "/account/login", "/wp-login.php", "/admin/login"];
const SIGNUP_PATHS   = ["/signup", "/register", "/sign-up", "/create-account", "/join", "/auth/register"];
const ADMIN_PATHS    = ["/admin", "/dashboard", "/control", "/manage", "/panel", "/backend", "/wp-admin", "/administrator"];
const API_PATHS      = ["/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/openapi.json", "/.well-known"];

function detectPageType(url: string, html: string): "index" | "login" | "signup" | "admin" | "api" {
  const u = url.toLowerCase();
  if (LOGIN_PATHS.some(p => u.includes(p))) return "login";
  if (SIGNUP_PATHS.some(p => u.includes(p))) return "signup";
  if (ADMIN_PATHS.some(p => u.includes(p))) return "admin";
  if (API_PATHS.some(p => u.includes(p))) return "api";
  // Heuristics from HTML
  const lower = html.toLowerCase();
  if (lower.includes("type=\"password\"") && (lower.includes("sign in") || lower.includes("log in") || lower.includes("login"))) return "login";
  if (lower.includes("type=\"password\"") && (lower.includes("register") || lower.includes("sign up") || lower.includes("create account"))) return "signup";
  return "index";
}

// ── Scan source for sensitive patterns ───────────────────────────────────────
function scanForSensitiveInfo(source: string): SensitiveFinding[] {
  const findings: SensitiveFinding[] = [];
  const seen = new Set<string>();

  for (const p of SENSITIVE_PATTERNS) {
    const matches = [...source.matchAll(p.re)];
    for (const m of matches.slice(0, 3)) { // cap at 3 per pattern
      const raw = m[0];
      const key = `${p.name}:${raw.slice(0, 20)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // Mask sensitive values
      const display = p.mask ? raw.slice(0, 8) + "****" + raw.slice(-4) : raw;
      findings.push({ type: p.name, value: display, severity: p.severity, context: m[1] ? m[1].slice(0, 30) : undefined });
    }
  }

  return findings;
}

// ── Launch browser (puppeteer-core pointing to system Chromium) ───────────────
let _browser: Browser | null = null;

function findChromium(): string {
  // 1. Explicit env override
  if (process.env.PUPPETEER_EXECUTABLE_PATH) return process.env.PUPPETEER_EXECUTABLE_PATH;
  // 2. Try `which chromium` / `which google-chrome`
  for (const bin of ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"]) {
    try { return execFileSync("which", [bin], { encoding: "utf8", timeout: 3000 }).trim(); } catch {}
  }
  // 3. Well-known static paths
  const candidates = [
    "/run/current-system/sw/bin/chromium",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
  ];
  for (const p of candidates) {
    try { require("fs").accessSync(p, require("fs").constants.X_OK); return p; } catch {}
  }
  throw new Error("No Chromium executable found. Install the chromium system package.");
}

async function getBrowser(): Promise<Browser> {
  if (_browser && _browser.connected) return _browser;
  const executablePath = findChromium();

  _browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--no-first-run",
      "--no-zygote",
      "--disable-extensions",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-default-apps",
      "--single-process",
    ],
  });
  return _browser;
}

// ── Fetch page source via plain HTTP (fast fallback for source scanning) ───────
async function fetchSource(url: string): Promise<{ html: string; statusCode: number }> {
  return new Promise(resolve => {
    const mod = url.startsWith("https") ? https : http;
    const req = mod.get(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; CTEM-Scanner/1.0)" }, timeout: 8000 } as any, res => {
      let data = "";
      res.on("data", chunk => { if (data.length < 500_000) data += chunk; });
      res.on("end", () => resolve({ html: data, statusCode: res.statusCode ?? 200 }));
    });
    req.on("error", () => resolve({ html: "", statusCode: 0 }));
    req.on("timeout", () => { req.destroy(); resolve({ html: "", statusCode: 0 }); });
  });
}

// ── Take a screenshot of one URL using Puppeteer ──────────────────────────────
async function screenshotPage(browser: Browser, url: string): Promise<{ data: string; title: string; statusCode: number; html: string }> {
  const page = await browser.newPage();
  let statusCode = 200;
  try {
    await page.setViewport({ width: 1280, height: 800 });
    await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36");
    const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    statusCode = response?.status() ?? 200;
    // Brief wait for dynamic content to settle
    await new Promise(r => setTimeout(r, 1500));
    const title = await page.title().catch(() => "");
    const html  = await page.content().catch(() => "");
    const screenshot = await page.screenshot({ type: "png", fullPage: false }) as Buffer;
    return { data: screenshot.toString("base64"), title, statusCode, html };
  } finally {
    await page.close().catch(() => {});
  }
}

// ── Build candidate URL list for a target domain ──────────────────────────────
function buildCandidateUrls(target: string): Array<{ url: string; pageType: PageScreenshot["pageType"]; dedup: boolean }> {
  const base = target.startsWith("http") ? target.replace(/\/$/, "") : `https://${target}`;
  return [
    // Index / home
    { url: base,                          pageType: "index",     dedup: true  },
    // Login paths
    { url: `${base}/login`,               pageType: "login",     dedup: true  },
    { url: `${base}/signin`,              pageType: "login",     dedup: true  },
    { url: `${base}/sign-in`,             pageType: "login",     dedup: true  },
    { url: `${base}/auth/login`,          pageType: "login",     dedup: true  },
    { url: `${base}/user/login`,          pageType: "login",     dedup: true  },
    { url: `${base}/wp-login.php`,        pageType: "login",     dedup: true  },
    { url: `${base}/admin/login`,         pageType: "login",     dedup: true  },
    { url: `${base}/forgot-password`,     pageType: "login",     dedup: true  },
    // Signup paths
    { url: `${base}/register`,            pageType: "signup",    dedup: true  },
    { url: `${base}/signup`,              pageType: "signup",    dedup: true  },
    { url: `${base}/sign-up`,             pageType: "signup",    dedup: true  },
    { url: `${base}/create-account`,      pageType: "signup",    dedup: true  },
    // Admin paths
    { url: `${base}/admin`,               pageType: "admin",     dedup: true  },
    { url: `${base}/dashboard`,           pageType: "admin",     dedup: true  },
    { url: `${base}/wp-admin`,            pageType: "admin",     dedup: true  },
    { url: `${base}/administrator`,       pageType: "admin",     dedup: true  },
    // API / docs
    { url: `${base}/api`,                 pageType: "api",       dedup: true  },
    { url: `${base}/swagger`,             pageType: "api",       dedup: true  },
    { url: `${base}/graphql`,             pageType: "api",       dedup: true  },
    { url: `${base}/openapi.json`,        pageType: "api",       dedup: true  },
    // Sensitive file disclosures (no dedup — each is distinct)
    { url: `${base}/.env`,               pageType: "sensitive",  dedup: false },
    { url: `${base}/.env.local`,         pageType: "sensitive",  dedup: false },
    { url: `${base}/.env.production`,    pageType: "sensitive",  dedup: false },
    { url: `${base}/config.js`,          pageType: "sensitive",  dedup: false },
    { url: `${base}/app.js`,             pageType: "sensitive",  dedup: false },
    { url: `${base}/robots.txt`,         pageType: "sensitive",  dedup: false },
    { url: `${base}/phpinfo.php`,        pageType: "sensitive",  dedup: false },
    { url: `${base}/.git/config`,        pageType: "sensitive",  dedup: false },
    { url: `${base}/wp-config.php.bak`,  pageType: "sensitive",  dedup: false },
    { url: `${base}/.well-known/security.txt`, pageType: "sensitive", dedup: false },
  ];
}

// ── Main entry: capture screenshots of a target ───────────────────────────────
export async function captureScreenshots(target: string, timeoutMs = 60000): Promise<PageScreenshot[]> {
  const results: PageScreenshot[] = [];
  const deadline = Date.now() + timeoutMs;

  let browser: Browser | null = null;
  try {
    browser = await getBrowser();
  } catch (err) {
    // Browser not available — fall back to source-only scan (no visual screenshots)
    return captureSourceOnly(target, timeoutMs);
  }

  const candidates = buildCandidateUrls(target);
  const seen = new Set<string>();

  for (const { url, pageType, dedup } of candidates) {
    if (Date.now() > deadline) break;
    // For dedup-enabled types, skip if we already captured this page type
    if (dedup && seen.has(pageType)) continue;

    try {
      const { data, title, statusCode, html } = await screenshotPage(browser, url);
      // Skip missing pages — but keep 200-range and interesting status codes
      if (statusCode === 0) continue;
      if (statusCode === 404 && pageType !== "sensitive") continue;

      const actualType = dedup ? detectPageType(url, html) : pageType;
      if (dedup && seen.has(actualType)) continue;
      if (dedup) seen.add(actualType);

      const findings = scanForSensitiveInfo(html);

      // For sensitive files: skip if no content AND no findings (blank 200 still counts)
      if (pageType === "sensitive" && html.length < 20 && findings.length === 0) continue;

      results.push({
        url, statusCode, title, findings,
        pageType: actualType,
        screenshotData: data,
      });
    } catch {
      // Page unreachable — skip silently
    }
  }

  return results;
}

// ── Fallback: source-only mode when Chromium is unavailable ──────────────────
async function captureSourceOnly(target: string, timeoutMs: number): Promise<PageScreenshot[]> {
  const base = target.startsWith("http") ? target.replace(/\/$/, "") : `https://${target}`;
  const deadline = Date.now() + timeoutMs;
  const results: PageScreenshot[] = [];
  const seen = new Set<string>();

  for (const { url, pageType, dedup } of buildCandidateUrls(target)) {
    if (Date.now() > deadline) break;
    if (dedup && seen.has(pageType)) continue;

    const { html, statusCode } = await fetchSource(url);
    if (statusCode === 0) continue;
    if (statusCode === 404 && pageType !== "sensitive") continue;
    if (!html) continue;

    const actualType = dedup ? detectPageType(url, html) : pageType;
    if (dedup && seen.has(actualType)) continue;
    if (dedup) seen.add(actualType);

    const findings = scanForSensitiveInfo(html);
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch?.[1]?.trim() ?? "";

    // Generate a simple SVG placeholder representing page info (no real screenshot)
    const svg = generateSvgPreview({ url, title, statusCode, findings, pageType: actualType });
    results.push({
      url, statusCode: statusCode || 200, title, findings,
      pageType: actualType,
      screenshotData: Buffer.from(svg).toString("base64"),
    });
  }

  return results;
}

// ── SVG preview card (shown when real Chromium screenshots aren't available) ───
function generateSvgPreview(opts: { url: string; title: string; statusCode: number; findings: SensitiveFinding[]; pageType: string }): string {
  const { url, title, statusCode, findings, pageType } = opts;
  const domain = url.replace(/^https?:\/\//, "").split("/")[0];
  const fgColor = statusCode >= 400 ? "#ef4444" : "#22c55e";
  const badgeColor = pageType === "login" ? "#f59e0b" : pageType === "admin" ? "#ef4444" : pageType === "signup" ? "#8b5cf6" : "#3b82f6";
  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount     = findings.filter(f => f.severity === "high").length;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="800" viewBox="0 0 1280 800">
  <rect width="1280" height="800" fill="#0f1117"/>
  <rect x="0" y="0" width="1280" height="48" fill="#1a1d2e"/>
  <circle cx="24" cy="24" r="8" fill="#ef4444"/>
  <circle cx="48" cy="24" r="8" fill="#f59e0b"/>
  <circle cx="72" cy="24" r="8" fill="#22c55e"/>
  <rect x="96" y="12" width="800" height="24" rx="4" fill="#0d0f1a"/>
  <text x="280" y="28" font-family="monospace" font-size="13" fill="#6b7280">${escXml(url.slice(0, 80))}</text>
  <rect x="940" y="12" width="60" height="24" rx="4" fill="${fgColor}22"/>
  <text x="970" y="28" font-family="monospace" font-size="13" fill="${fgColor}" text-anchor="middle">${statusCode}</text>
  <rect x="30" y="80" width="120" height="28" rx="6" fill="${badgeColor}"/>
  <text x="90" y="99" font-family="sans-serif" font-size="14" font-weight="bold" fill="white" text-anchor="middle">${pageType.toUpperCase()}</text>
  <text x="170" y="99" font-family="sans-serif" font-size="18" font-weight="bold" fill="#f1f5f9">${escXml(title.slice(0, 60) || domain)}</text>
  <text x="30" y="150" font-family="monospace" font-size="13" fill="#6b7280">${escXml(domain)}</text>
  ${findings.length === 0
    ? `<rect x="30" y="190" width="400" height="60" rx="8" fill="#14532d22"/>
       <text x="50" y="228" font-family="sans-serif" font-size="15" fill="#22c55e">✓ No sensitive information detected</text>`
    : `<rect x="30" y="190" width="600" height="28" rx="6" fill="#7f1d1d44"/>
       <text x="50" y="208" font-family="sans-serif" font-size="14" font-weight="bold" fill="#ef4444">⚠ ${findings.length} sensitive item${findings.length > 1 ? "s" : ""} detected — ${criticalCount} critical, ${highCount} high</text>
       ${findings.slice(0, 8).map((f, i) => `
         <rect x="30" y="${230 + i * 50}" width="1220" height="42" rx="6" fill="${f.severity === "critical" ? "#7f1d1d" : f.severity === "high" ? "#78350f" : "#1e3a5f"}22"/>
         <text x="50" y="${254 + i * 50}" font-family="monospace" font-size="13" fill="${f.severity === "critical" ? "#ef4444" : f.severity === "high" ? "#f59e0b" : "#60a5fa"}">[${f.severity.toUpperCase()}] ${escXml(f.type)}: ${escXml(f.value)}</text>
       `).join("")}`}
  <text x="30" y="780" font-family="monospace" font-size="11" fill="#374151">CTEM Scanner — Gowitness/EyeWitness Engine — ${new Date().toISOString()}</text>
</svg>`;
}

function escXml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function closeBrowser(): void {
  _browser?.close().catch(() => {});
  _browser = null;
}

/**
 * Pre-warm the browser instance so the first scan doesn't pay
 * the cold-start cost. Called at server startup.
 */
export async function warmBrowser(): Promise<void> {
  try {
    const b = await getBrowser();
    // Open and immediately close a blank page to fully initialize the renderer
    const p = await b.newPage();
    await p.close();
  } catch {
    // Non-fatal — browser will be lazy-started on first scan
  }
}
