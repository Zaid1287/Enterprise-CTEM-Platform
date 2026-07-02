import { exec } from "child_process";
import { promisify } from "util";
import { logger } from "./logger";

const execAsync = promisify(exec);
const UA = "Mozilla/5.0 (compatible; CTEM-WPScan/1.0)";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface WpFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  remediation: string;
  cve?: string;
  url?: string;
}

export interface WpScanResult {
  isWordpress: boolean;
  wpVersion?: string;
  phpVersion?: string;
  findings: WpFinding[];
  pluginsFound: string[];
  themesFound: string[];
  usersFound: string[];
  stats: {
    findingsCount: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// ── HTTP helper ────────────────────────────────────────────────────────────────

async function fetchUrl(
  url: string, timeoutMs = 8000
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": UA },
      redirect: "follow",
    });
    clearTimeout(t);
    const body = (await res.text()).slice(0, 200_000);
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { status: res.status, body, headers };
  } catch { return null; }
}

// ── WordPress detection ────────────────────────────────────────────────────────

function detectWordPress(body: string, headers: Record<string, string>): { isWp: boolean; version?: string; phpVersion?: string } {
  const isWp =
    body.includes("/wp-content/") ||
    body.includes("/wp-includes/") ||
    body.includes("wp-json") ||
    (headers["x-powered-by"] ?? "").toLowerCase().includes("wordpress") ||
    body.includes("wordpress.org") ||
    body.includes("generatedby\":\"WordPress");

  let version: string | undefined;
  const vMatches = [
    body.match(/WordPress\s+([\d.]+)/i),
    body.match(/<meta[^>]+generator[^>]+WordPress\s+([\d.]+)/i),
    body.match(/ver=([\d.]+)/),
  ];
  for (const m of vMatches) {
    if (m) { version = m[1]; break; }
  }

  const phpMatch = (headers["x-powered-by"] ?? "").match(/PHP\/([\d.]+)/i);
  return { isWp, version, phpVersion: phpMatch?.[1] };
}

// ── HTTP-based security checks ─────────────────────────────────────────────────

interface WpCheck {
  path: string;
  title: string;
  severity: WpFinding["severity"];
  check: (r: NonNullable<Awaited<ReturnType<typeof fetchUrl>>>) => boolean;
  description: string;
  remediation: string;
}

const WP_CHECKS: WpCheck[] = [
  {
    path: "/xmlrpc.php",
    title: "WordPress XML-RPC Enabled",
    severity: "high",
    check: r => r.status === 405 || (r.status === 200 && (r.body.includes("XML-RPC") || r.body.includes("xmlrpc"))),
    description: "WordPress XML-RPC is enabled. Allows brute-force amplification (multicall) and was used in historically significant attacks.",
    remediation: "Disable XML-RPC in wp-config.php: `add_filter('xmlrpc_enabled', '__return_false')`. Or block it at the web server level.",
  },
  {
    path: "/wp-json/wp/v2/users",
    title: "WordPress User Enumeration via REST API",
    severity: "medium",
    check: r => r.status === 200 && r.body.includes('"id"') && r.body.includes('"name"'),
    description: "WordPress REST API exposes user accounts including usernames, enabling targeted credential attacks.",
    remediation: "Restrict user enumeration: add `add_filter('rest_endpoints', ...)` to block /wp/v2/users for non-admins.",
  },
  {
    path: "/?author=1",
    title: "WordPress Author Username Enumeration",
    severity: "low",
    check: r => r.body.toLowerCase().includes("/author/") && r.status < 400,
    description: "WordPress exposes usernames via the /?author=N parameter redirect.",
    remediation: "Add a redirect rule to prevent author enumeration, or use a plugin like `Stop User Enumeration`.",
  },
  {
    path: "/wp-content/debug.log",
    title: "WordPress Debug Log Exposed",
    severity: "high",
    check: r => r.status === 200 && r.body.length > 10 && (r.body.includes("PHP") || r.body.includes("Error") || r.body.includes("Warning")),
    description: "WordPress debug.log is publicly accessible. May contain database credentials, internal paths, and stack traces.",
    remediation: "Set WP_DEBUG to false in production wp-config.php. Add `deny from all` for debug.log in .htaccess.",
  },
  {
    path: "/wp-config.php.bak",
    title: "WordPress Config Backup Exposed",
    severity: "critical",
    check: r => r.status === 200 && r.body.length > 100,
    description: "WordPress configuration backup file exposed. May contain database credentials and secret keys.",
    remediation: "Delete all backup config files immediately. Never store them in the web root.",
  },
  {
    path: "/wp-config.php~",
    title: "WordPress Config Backup (Tilde) Exposed",
    severity: "critical",
    check: r => r.status === 200 && r.body.length > 100,
    description: "WordPress config backup (editor temporary file) exposed with potential credentials.",
    remediation: "Delete all backup config files. Use .gitignore to prevent config files from being committed.",
  },
  {
    path: "/readme.html",
    title: "WordPress Version Disclosure via readme.html",
    severity: "info",
    check: r => r.status === 200 && r.body.toLowerCase().includes("wordpress"),
    description: "WordPress readme.html is accessible and discloses the WordPress version number.",
    remediation: "Delete readme.html and license.txt from the WordPress root directory.",
  },
  {
    path: "/license.txt",
    title: "WordPress License File Exposed",
    severity: "info",
    check: r => r.status === 200 && r.body.toLowerCase().includes("wordpress"),
    description: "WordPress license.txt is accessible, potentially disclosing version information.",
    remediation: "Delete license.txt from the WordPress root directory.",
  },
  {
    path: "/wp-includes/",
    title: "WordPress wp-includes Directory Listing",
    severity: "medium",
    check: r => r.status === 200 && r.body.includes("Index of"),
    description: "WordPress wp-includes directory has listing enabled, exposing internal file structure.",
    remediation: "Disable directory listing: add `Options -Indexes` to .htaccess.",
  },
  {
    path: "/wp-content/uploads/",
    title: "WordPress Uploads Directory Listing",
    severity: "low",
    check: r => r.status === 200 && r.body.includes("Index of"),
    description: "WordPress uploads directory listing is enabled, potentially exposing sensitive uploaded files.",
    remediation: "Add an empty index.php to wp-content/uploads/ and disable directory listing.",
  },
  {
    path: "/.htaccess",
    title: ".htaccess File Exposed",
    severity: "medium",
    check: r => r.status === 200 && (r.body.includes("RewriteRule") || r.body.includes("Options")),
    description: "Apache .htaccess file is publicly readable, exposing web server configuration rules.",
    remediation: "Configure web server to deny access to .htaccess: `<Files .htaccess> deny from all </Files>`",
  },
  {
    path: "/wp-login.php",
    title: "WordPress Login Page — Brute-Force Risk",
    severity: "low",
    check: r => r.status === 200 && r.body.includes("wp-login"),
    description: "WordPress login page is publicly accessible without rate limiting. Susceptible to brute-force attacks.",
    remediation: "Add CAPTCHA, rate limiting, or IP allowlisting to /wp-login.php. Consider using a Web Application Firewall.",
  },
];

async function runWpHttpChecks(baseUrl: string): Promise<WpFinding[]> {
  const findings: WpFinding[] = [];
  const results = await Promise.allSettled(
    WP_CHECKS.map(async ({ path, title, severity, check, description, remediation }) => {
      const r = await fetchUrl(`${baseUrl}${path}`, 8000);
      if (r && check(r)) {
        findings.push({ title, severity, description, remediation, url: `${baseUrl}${path}` });
      }
    })
  );
  void results;
  return findings;
}

// ── Plugin enumeration via directory listing ───────────────────────────────────

async function enumeratePlugins(baseUrl: string): Promise<string[]> {
  const plugins: string[] = [];
  const r = await fetchUrl(`${baseUrl}/wp-content/plugins/`, 6000);
  if (r && r.status === 200) {
    const matches = [...r.body.matchAll(/href="([a-zA-Z0-9][a-zA-Z0-9\-_.]+)\/"/g)];
    plugins.push(...matches.map(m => m[1]).filter(p => p !== ".." && !p.startsWith(".")));
  }
  return [...new Set(plugins)].slice(0, 30);
}

async function enumerateThemes(baseUrl: string): Promise<string[]> {
  const themes: string[] = [];
  const r = await fetchUrl(`${baseUrl}/wp-content/themes/`, 6000);
  if (r && r.status === 200) {
    const matches = [...r.body.matchAll(/href="([a-zA-Z0-9][a-zA-Z0-9\-_.]+)\/"/g)];
    themes.push(...matches.map(m => m[1]).filter(t => t !== ".." && !t.startsWith(".")));
  }
  // Also detect active theme from homepage source
  const home = await fetchUrl(baseUrl, 6000);
  if (home) {
    const themeMatch = home.body.match(/\/wp-content\/themes\/([a-zA-Z0-9\-_.]+)\//);
    if (themeMatch && !themes.includes(themeMatch[1])) themes.unshift(themeMatch[1]);
  }
  return [...new Set(themes)].slice(0, 20);
}

// ── User enumeration via REST ──────────────────────────────────────────────────

async function enumerateUsers(baseUrl: string): Promise<string[]> {
  const r = await fetchUrl(`${baseUrl}/wp-json/wp/v2/users?per_page=20`, 8000);
  if (!r || r.status !== 200) return [];
  try {
    const data = JSON.parse(r.body) as Array<{ name?: string; slug?: string }>;
    return data.map(u => u.slug ?? u.name ?? "").filter(Boolean).slice(0, 20);
  } catch { return []; }
}

// ── Nuclei WordPress templates ─────────────────────────────────────────────────

async function runNucleiWpTemplates(baseUrl: string): Promise<WpFinding[]> {
  try {
    const { stdout } = await execAsync(
      `nuclei -u "${baseUrl}" -tags wordpress -json -timeout 15 -rate-limit 50 -no-interactsh -silent -no-update-check 2>/dev/null`,
      { timeout: 90_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return stdout.trim().split("\n")
      .filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })
      .map((r: any) => ({
        title: r.info?.name ?? r["template-id"] ?? "WordPress Issue",
        severity: (r.info?.severity ?? "medium") as WpFinding["severity"],
        description: r.info?.description ?? `WordPress vulnerability detected via template ${r["template-id"]}`,
        remediation: r.info?.remediation ?? "Update WordPress core, plugins, and themes to latest versions.",
        cve: r.info?.classification?.["cve-id"]?.[0],
        url: r["matched-at"] ?? baseUrl,
      }));
  } catch { return []; }
}

// ── Main export ────────────────────────────────────────────────────────────────

export async function runWpScan(target: string): Promise<WpScanResult> {
  const empty: WpScanResult = {
    isWordpress: false, findings: [], pluginsFound: [], themesFound: [], usersFound: [],
    stats: { findingsCount: 0, critical: 0, high: 0, medium: 0, low: 0 },
  };

  let baseUrl: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    baseUrl = `${u.protocol}//${u.hostname}`;
  } catch { return empty; }

  // Detect WordPress first
  const home = await fetchUrl(baseUrl, 10000);
  if (!home) return empty;

  const { isWp, version, phpVersion } = detectWordPress(home.body, home.headers);
  if (!isWp) return { ...empty, isWordpress: false };

  logger.info({ target, version }, "WordPress detected — running WP security checks");

  // Run all checks in parallel
  const [httpFindings, nucleiFindings, plugins, themes, users] = await Promise.allSettled([
    runWpHttpChecks(baseUrl),
    runNucleiWpTemplates(baseUrl),
    enumeratePlugins(baseUrl),
    enumerateThemes(baseUrl),
    enumerateUsers(baseUrl),
  ]);

  const allFindings: WpFinding[] = [
    ...(httpFindings.status === "fulfilled" ? httpFindings.value : []),
    ...(nucleiFindings.status === "fulfilled" ? nucleiFindings.value : []),
  ];

  // Deduplicate findings by title
  const seen = new Set<string>();
  const dedupedFindings = allFindings.filter(f => {
    if (seen.has(f.title)) return false;
    seen.add(f.title);
    return true;
  });

  return {
    isWordpress: true,
    wpVersion: version,
    phpVersion,
    findings: dedupedFindings,
    pluginsFound: plugins.status === "fulfilled" ? plugins.value : [],
    themesFound: themes.status === "fulfilled" ? themes.value : [],
    usersFound: users.status === "fulfilled" ? users.value : [],
    stats: {
      findingsCount: dedupedFindings.length,
      critical: dedupedFindings.filter(f => f.severity === "critical").length,
      high: dedupedFindings.filter(f => f.severity === "high").length,
      medium: dedupedFindings.filter(f => f.severity === "medium").length,
      low: dedupedFindings.filter(f => f.severity === "low").length,
    },
  };
}
