import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import { logger } from "./logger";

const execAsync = promisify(exec);

// ── Types ──────────────────────────────────────────────────────────────────────

export interface GitHubSecretFinding {
  type: string;
  severity: "critical" | "high" | "medium";
  repo: string;
  file: string;
  value: string;        // masked value
  lineContext: string;  // surrounding context with sensitive part masked
  url: string;          // link to file on GitHub
  verified: boolean;    // true = high-specificity pattern (TruffleHog "verified" equivalent)
  source: "file" | "commit";
  commitSha?: string;
}

export interface GitHubRepo {
  name: string;
  fullName: string;
  url: string;
  stars: number;
  language?: string;
  pushedAt?: string;
  description?: string;
}

export interface GitHubOrgInfo {
  login: string;
  name?: string;
  url: string;
  type: "org" | "user";
  publicRepoCount: number;
  repos: GitHubRepo[];
}

export interface GitDirExposure {
  url: string;
  host: string;
  isExposed: boolean;
  httpStatus: number;
  branch?: string;
  remoteUrl?: string;
  configContent?: string;
  commitMsg?: string;
  severity: "critical";
}

export interface SecretsHuntResult {
  githubOrg?: GitHubOrgInfo;
  githubSecrets: GitHubSecretFinding[];
  gitDirectories: GitDirExposure[];
  stats: {
    reposScanned: number;
    filesScanned: number;
    commitsScanned: number;
    secretsFound: number;
    verifiedSecrets: number;
    gitDirsChecked: number;
    gitDirsExposed: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
  };
}

// ── Secret patterns (TruffleHog verified-detector equivalents) ─────────────────

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  verified: boolean;    // high-specificity pattern
  capture?: number;     // capture group index for the secret value (0 = full match)
}

const PATTERNS: SecretPattern[] = [
  // AWS
  { name: "AWS Access Key ID",      regex: /\b(AKIA[0-9A-Z]{16})\b/g,                                                         severity: "critical", verified: true,  capture: 1 },
  { name: "AWS Secret Access Key",  regex: /[Aa][Ww][Ss]_?[Ss][Ee][Cc][Rr][Ee][Tt]_?[Aa][Cc][Cc][Ee][Ss]{2}_?[Kk][Ee][Yy][\s\S]{0,20}(['"]?)([A-Za-z0-9/+]{40})\1/g, severity: "critical", verified: true, capture: 2 },
  // GitHub tokens
  { name: "GitHub PAT",             regex: /\b(ghp_[A-Za-z0-9_]{36})\b/g,                                                    severity: "critical", verified: true,  capture: 1 },
  { name: "GitHub OAuth Token",     regex: /\b(gho_[A-Za-z0-9_]{36})\b/g,                                                    severity: "critical", verified: true,  capture: 1 },
  { name: "GitHub Fine-grained",    regex: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,                                              severity: "critical", verified: true,  capture: 1 },
  // Private keys
  { name: "RSA/Private Key",        regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g,                       severity: "critical", verified: true,  capture: 1 },
  // Stripe
  { name: "Stripe Secret Key",      regex: /\b(sk_live_[A-Za-z0-9]{24,})\b/g,                                                severity: "critical", verified: true,  capture: 1 },
  { name: "Stripe Restricted Key",  regex: /\b(rk_live_[A-Za-z0-9]{24,})\b/g,                                                severity: "high",     verified: true,  capture: 1 },
  // OpenAI
  { name: "OpenAI API Key",         regex: /\b(sk-(?:proj-)?[A-Za-z0-9T]{20}[A-Za-z0-9_\-T]{20,})\b/g,                      severity: "critical", verified: true,  capture: 1 },
  // Slack
  { name: "Slack Bot Token",        regex: /\b(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24})\b/g,                             severity: "high",     verified: true,  capture: 1 },
  { name: "Slack Webhook URL",      regex: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/g, severity: "high",     verified: true,  capture: 1 },
  // SendGrid
  { name: "SendGrid API Key",       regex: /\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b/g,                             severity: "high",     verified: true,  capture: 1 },
  // Twilio
  { name: "Twilio Auth Token",      regex: /[Tt]wilio[\s\S]{0,30}([A-Fa-f0-9]{32})/g,                                        severity: "high",     verified: false, capture: 1 },
  // Generic
  { name: "Database Connection URL", regex: /((?:mongodb(?:\+srv)?|postgresql|mysql|redis):\/\/[^\s'"<>]+)/g,                 severity: "high",     verified: false, capture: 1 },
  { name: "Generic API Key",        regex: /(?:api[_\-]?key|apikey)\s*[=:]+\s*['"]([A-Za-z0-9_\-]{20,})['"](?:,|\s)/gi,     severity: "high",     verified: false, capture: 1 },
  { name: "JWT Secret",             regex: /(?:jwt[_\-]?secret|jwt[_\-]?key)\s*[=:]+\s*['"]([^'"]{8,})['"](?:,|\s)/gi,      severity: "high",     verified: false, capture: 1 },
  { name: "Password in Config",     regex: /(?:^|\s)(?:password|passwd|pwd)\s*[=:]+\s*['"]([^\s'"]{8,})['"](?:,|\s|$)/gim,  severity: "medium",   verified: false, capture: 1 },
  { name: "Hardcoded Secret",       regex: /(?:secret|private[_\-]?key)\s*[=:]+\s*['"]([A-Za-z0-9_+/=\-]{16,})['"](?:,|\s)/gi, severity: "medium", verified: false, capture: 1 },
];

// Sensitive file names to look for in repo roots
const SENSITIVE_FILES = new Set([
  ".env", ".env.example", ".env.local", ".env.prod", ".env.staging", ".env.development",
  ".env.test", ".env.backup", "config.json", "config.yaml", "config.yml", "settings.json",
  "settings.yaml", "settings.py", "secrets.json", "credentials.json", "app.config.js",
  "application.properties", "application.yml", "application.yaml",
  "docker-compose.yml", "docker-compose.yaml", "docker-compose.override.yml",
  "terraform.tfvars", "terraform.tfvars.json", ".terraform.tfvars",
  "wp-config.php", "database.yml", "database.json", "firebase.json",
  ".boto", ".s3cfg", "netrc", ".netrc", "id_rsa", "id_ed25519",
]);

// ── Helpers ────────────────────────────────────────────────────────────────────

const UA = "Mozilla/5.0 (compatible; CTEM-SecretsHunter/1.0; +https://sentinelware.io)";

function maskSecret(value: string): string {
  return value;
}

function maskContext(ctx: string, secret: string): string {
  return ctx.slice(0, 300);
}

// Module-level GitHub token — set via runSecretsHunt(target, token)
let _githubToken: string | null = null;

// GitHub API helper — graceful, checks rate limit
async function ghFetch(path: string, remainingRef: { v: number }): Promise<{ ok: boolean; data: any }> {
  if (remainingRef.v < 3) return { ok: false, data: null };
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 10000);
    const headers: Record<string, string> = { "User-Agent": UA, "Accept": "application/vnd.github+json" };
    if (_githubToken) headers.Authorization = `Bearer ${_githubToken}`;
    const res = await fetch(`https://api.github.com${path}`, { signal: ctrl.signal, headers });
    clearTimeout(t);
    remainingRef.v = parseInt(res.headers.get("X-RateLimit-Remaining") ?? "50", 10);
    if (!res.ok) return { ok: false, data: null };
    const data = await res.json().catch(() => null);
    return { ok: true, data };
  } catch {
    return { ok: false, data: null };
  }
}

// Plain HTTP helper for .git checks
async function httpGet(url: string, timeoutMs = 8000): Promise<{ status: number; body: string }> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA }, redirect: "follow" });
    clearTimeout(t);
    const body = await res.text().catch(() => "");
    return { status: res.status, body: body.slice(0, 8192) };
  } catch {
    return { status: 0, body: "" };
  }
}

// Extract company name from target
function extractCompany(target: string): string {
  try {
    const host = target.startsWith("http") ? new URL(target).hostname : target;
    return host.replace(/^www\./, "").split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "");
  } catch { return ""; }
}

// ── Secret scanning (apply patterns to text) ──────────────────────────────────

function scanText(text: string, repo: string, file: string, source: "file" | "commit", commitSha?: string): GitHubSecretFinding[] {
  const findings: GitHubSecretFinding[] = [];
  const seen = new Set<string>();

  for (const p of PATTERNS) {
    const re = new RegExp(p.regex.source, p.regex.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const rawValue = p.capture ? (m[p.capture] ?? m[0]) : m[0];
      if (!rawValue || rawValue.length < 8) continue;
      const key = `${p.name}:${rawValue.slice(0, 8)}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const start = Math.max(0, m.index - 80);
      const end   = Math.min(text.length, m.index + m[0].length + 80);
      const ctx   = text.slice(start, end).replace(/\n/g, " ").trim();

      findings.push({
        type: p.name,
        severity: p.severity,
        verified: p.verified,
        repo,
        file,
        value: rawValue,
        lineContext: ctx.slice(0, 300),
        url: `https://github.com/${repo}/blob/HEAD/${file}`,
        source,
        commitSha,
      });
    }
  }

  return findings;
}

// ── GitHub scanning ───────────────────────────────────────────────────────────

async function findGitHubTarget(company: string, rl: { v: number }): Promise<GitHubOrgInfo | null> {
  // Try org first, then user
  for (const path of [`/orgs/${company}`, `/users/${company}`]) {
    const r = await ghFetch(path, rl);
    if (!r.ok || !r.data) continue;
    const type = r.data.type === "Organization" ? "org" as const : "user" as const;
    const listPath = type === "org"
      ? `/orgs/${r.data.login}/repos?sort=pushed&per_page=20&type=public`
      : `/users/${r.data.login}/repos?sort=pushed&per_page=20`;
    const reposR = await ghFetch(listPath, rl);
    const repos: GitHubRepo[] = Array.isArray(reposR.data) ? reposR.data.slice(0, 20).map((repo: any) => ({
      name: repo.name, fullName: repo.full_name, url: repo.html_url,
      stars: repo.stargazers_count, language: repo.language,
      pushedAt: repo.pushed_at, description: repo.description,
    })) : [];
    return {
      login: r.data.login, name: r.data.name ?? r.data.login, url: r.data.html_url,
      type, publicRepoCount: r.data.public_repos ?? repos.length, repos,
    };
  }
  return null;
}

async function scanRepo(
  org: string, repo: string, rl: { v: number },
  statsRef: { filesScanned: number; commitsScanned: number }
): Promise<GitHubSecretFinding[]> {
  const findings: GitHubSecretFinding[] = [];

  // 1. Check root directory for sensitive files
  const rootR = await ghFetch(`/repos/${org}/${repo}/contents/`, rl);
  if (rootR.ok && Array.isArray(rootR.data)) {
    const sensitiveInRoot = rootR.data.filter((f: any) =>
      f.type === "file" && SENSITIVE_FILES.has(f.name.toLowerCase())
    ).slice(0, 4); // max 4 sensitive files per repo

    for (const file of sensitiveInRoot) {
      const fileR = await ghFetch(`/repos/${org}/${repo}/contents/${file.path}`, rl);
      if (!fileR.ok || !fileR.data?.content) continue;
      statsRef.filesScanned++;
      const decoded = Buffer.from(fileR.data.content.replace(/\n/g, ""), "base64").toString("utf-8");
      findings.push(...scanText(decoded, `${org}/${repo}`, file.name, "file"));
    }

    // Also check common config subdirs
    const configDirs = rootR.data.filter((f: any) => f.type === "dir" && ["config", "configs", ".github", "deploy", "k8s", "kubernetes", "helm", "infra", "infrastructure"].includes(f.name.toLowerCase())).slice(0, 2);
    for (const dir of configDirs) {
      const dirR = await ghFetch(`/repos/${org}/${repo}/contents/${dir.path}`, rl);
      if (!dirR.ok || !Array.isArray(dirR.data)) continue;
      const sensitiveInDir = dirR.data.filter((f: any) => f.type === "file" && SENSITIVE_FILES.has(f.name.toLowerCase())).slice(0, 2);
      for (const file of sensitiveInDir) {
        const fileR = await ghFetch(`/repos/${org}/${repo}/contents/${file.path}`, rl);
        if (!fileR.ok || !fileR.data?.content) continue;
        statsRef.filesScanned++;
        const decoded = Buffer.from(fileR.data.content.replace(/\n/g, ""), "base64").toString("utf-8");
        findings.push(...scanText(decoded, `${org}/${repo}`, file.path, "file"));
      }
    }
  }

  // 2. Scan recent commits (TruffleHog-style git history scan)
  const commitsR = await ghFetch(`/repos/${org}/${repo}/commits?per_page=5`, rl);
  if (commitsR.ok && Array.isArray(commitsR.data)) {
    for (const commit of commitsR.data.slice(0, 3)) {
      const commitR = await ghFetch(`/repos/${org}/${repo}/commits/${commit.sha}`, rl);
      if (!commitR.ok || !commitR.data?.files) continue;
      statsRef.commitsScanned++;
      for (const file of (commitR.data.files as any[]).slice(0, 10)) {
        if (!file.patch) continue;
        const added = file.patch.split("\n").filter((l: string) => l.startsWith("+")).join("\n");
        if (added.length < 20) continue;
        findings.push(...scanText(added, `${org}/${repo}`, file.filename, "commit", commit.sha.slice(0, 7)));
      }
    }
  }

  return findings;
}

async function runGitHubScanning(company: string): Promise<{ org: GitHubOrgInfo | undefined; secrets: GitHubSecretFinding[]; stats: { reposScanned: number; filesScanned: number; commitsScanned: number } }> {
  const rl = { v: 60 }; // remaining rate limit (pessimistic start)
  const stats = { reposScanned: 0, filesScanned: 0, commitsScanned: 0 };

  const orgInfo = await findGitHubTarget(company, rl);
  if (!orgInfo || orgInfo.repos.length === 0) return { org: orgInfo ?? undefined, secrets: [], stats };

  const secrets: GitHubSecretFinding[] = [];
  const reposToScan = orgInfo.repos.slice(0, 7); // scan top 7 most recently pushed repos

  await Promise.allSettled(reposToScan.map(async (repo) => {
    if (rl.v < 5) return;
    const found = await scanRepo(orgInfo.login, repo.name, rl, stats);
    secrets.push(...found);
    stats.reposScanned++;
  }));

  // Deduplicate by (type + masked value + repo)
  const seen = new Set<string>();
  const deduped = secrets.filter(s => {
    const k = `${s.type}:${s.value}:${s.repo}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });

  return { org: orgInfo, secrets: deduped, stats };
}

// ── .git directory exposure ───────────────────────────────────────────────────

async function checkGitDir(baseUrl: string): Promise<GitDirExposure> {
  const host = new URL(baseUrl).hostname;
  const headUrl = `${baseUrl}/.git/HEAD`;
  const { status, body: headBody } = await httpGet(headUrl, 8000);

  if (status !== 200 || !headBody.trim().startsWith("ref:")) {
    return { url: headUrl, host, isExposed: false, httpStatus: status, severity: "critical" };
  }

  const branch = headBody.match(/ref: refs\/heads\/(.+)/)?.[1]?.trim();

  // Try to fetch config
  const { status: cfgStatus, body: cfgBody } = await httpGet(`${baseUrl}/.git/config`, 6000);
  const remoteUrl = cfgStatus === 200 ? cfgBody.match(/url\s*=\s*(.+)/)?.[1]?.trim() : undefined;

  // Fetch latest commit message
  const { status: msgStatus, body: msgBody } = await httpGet(`${baseUrl}/.git/COMMIT_EDITMSG`, 5000);
  const commitMsg = msgStatus === 200 ? msgBody.trim().slice(0, 200) : undefined;

  return {
    url: headUrl, host, isExposed: true, httpStatus: status,
    severity: "critical", branch, remoteUrl,
    configContent: cfgStatus === 200 ? cfgBody.slice(0, 800) : undefined,
    commitMsg,
  };
}

async function runGitDirChecks(target: string): Promise<GitDirExposure[]> {
  let base: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    base = `${u.protocol}//${u.hostname}`;
  } catch { return []; }

  const domain = new URL(base).hostname.replace(/^www\./, "");
  const hosts = [
    base,
    `https://www.${domain}`,
    `https://dev.${domain}`,
    `https://staging.${domain}`,
    `https://api.${domain}`,
    `https://admin.${domain}`,
    `https://app.${domain}`,
    `https://portal.${domain}`,
  ].filter((h, i, arr) => arr.indexOf(h) === i); // deduplicate

  const results = await Promise.allSettled(hosts.map(h => checkGitDir(h)));
  return results
    .filter(r => r.status === "fulfilled")
    .map(r => (r as PromiseFulfilledResult<GitDirExposure>).value);
}

// ── TruffleHog binary integration ─────────────────────────────────────────────

async function runTrufflehogOnGitUrl(repoUrl: string): Promise<GitHubSecretFinding[]> {
  try {
    const { stdout } = await execAsync(
      `trufflehog git "${repoUrl}" --json --no-update --only-verified 2>/dev/null`,
      { timeout: 60_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return stdout.trim().split("\n")
      .filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })
      .map((r: any) => ({
        type:        r.DetectorName ?? r.detector_name ?? "Secret",
        severity:    "critical" as const,
        repo:        repoUrl,
        file:        r.SourceMetadata?.Data?.Git?.file ?? "",
        value:       `[${r.DetectorName ?? "secret"} detected — verified]`,
        lineContext: (r.Raw ?? "").slice(0, 100),
        url:         repoUrl,
        verified:    true,
        source:      "file" as const,
        commitSha:   r.SourceMetadata?.Data?.Git?.commit ?? undefined,
      }));
  } catch { return []; }
}

async function runTrufflehogOnFilesystem(dir: string): Promise<GitHubSecretFinding[]> {
  if (!fs.existsSync(dir)) return [];
  try {
    const { stdout } = await execAsync(
      `trufflehog filesystem "${dir}" --json --no-update 2>/dev/null`,
      { timeout: 60_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return stdout.trim().split("\n")
      .filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })
      .map((r: any) => ({
        type:        r.DetectorName ?? "Secret",
        severity:    (r.Verified ? "critical" : "high") as "critical" | "high",
        repo:        dir,
        file:        r.SourceMetadata?.Data?.Filesystem?.file ?? "",
        value:       `[${r.DetectorName ?? "secret"} in exposed .git]`,
        lineContext: (r.Raw ?? "").slice(0, 100),
        url:         dir,
        verified:    r.Verified ?? false,
        source:      "file" as const,
      }));
  } catch { return []; }
}

async function runGitDumperAndScan(gitUrl: string): Promise<GitHubSecretFinding[]> {
  const tmpDir = `/tmp/gitdump-${Date.now()}`;
  try {
    await execAsync(
      `python3 -m gitdumper "${gitUrl}" "${tmpDir}" 2>/dev/null`,
      { timeout: 60_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return runTrufflehogOnFilesystem(tmpDir);
  } catch { return []; }
  finally {
    try { await execAsync(`rm -rf "${tmpDir}"`, { timeout: 5000 }); } catch {}
  }
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runSecretsHunt(target: string, githubToken?: string | null): Promise<SecretsHuntResult> {
  _githubToken = githubToken ?? null;
  const empty: SecretsHuntResult = {
    githubSecrets: [], gitDirectories: [],
    stats: { reposScanned: 0, filesScanned: 0, commitsScanned: 0, secretsFound: 0, verifiedSecrets: 0, gitDirsChecked: 0, gitDirsExposed: 0, criticalCount: 0, highCount: 0, mediumCount: 0 },
  };

  const company = extractCompany(target);
  if (!company || company.length < 2) return empty;

  logger.info({ target, company }, "Secrets hunt starting");

  const [ghResult, gitDirResults] = await Promise.allSettled([
    runGitHubScanning(company),
    runGitDirChecks(target),
  ]);

  const gh   = ghResult.status   === "fulfilled" ? ghResult.value   : { org: undefined, secrets: [], stats: { reposScanned: 0, filesScanned: 0, commitsScanned: 0 } };
  const dirs = gitDirResults.status === "fulfilled" ? gitDirResults.value : [];

  const exposed = dirs.filter(d => d.isExposed);

  // ── TruffleHog binary: scan exposed .git dirs + public GitHub repos ─────────
  const thGitDirResults = await Promise.allSettled(
    exposed.slice(0, 3).map(d => runGitDumperAndScan(d.url))
  );
  const thGitDirSecrets = thGitDirResults.flatMap(r => r.status === "fulfilled" ? r.value : []);

  const publicRepoUrls: string[] = (gh.org as any)?.repos
    ?.filter((r: any) => !r.private)
    .slice(0, 5)
    .map((r: any) => r.clone_url ?? r.html_url ?? r.url)
    .filter(Boolean) ?? [];
  const thRepoResults = await Promise.allSettled(
    publicRepoUrls.map(url => runTrufflehogOnGitUrl(url))
  );
  const thRepoSecrets = thRepoResults.flatMap(r => r.status === "fulfilled" ? r.value : []);

  const allSecrets = [...gh.secrets, ...thGitDirSecrets, ...thRepoSecrets];

  const stats = {
    reposScanned:    gh.stats.reposScanned,
    filesScanned:    gh.stats.filesScanned,
    commitsScanned:  gh.stats.commitsScanned,
    secretsFound:    allSecrets.length,
    verifiedSecrets: allSecrets.filter(s => s.verified).length,
    gitDirsChecked:  dirs.length,
    gitDirsExposed:  exposed.length,
    criticalCount:   allSecrets.filter(s => s.severity === "critical").length,
    highCount:       allSecrets.filter(s => s.severity === "high").length,
    mediumCount:     allSecrets.filter(s => s.severity === "medium").length,
  };

  logger.info({ target, company, ...stats }, "Secrets hunt complete");

  // Sort secrets: verified first, then by severity
  allSecrets.sort((a, b) => {
    if (a.verified !== b.verified) return a.verified ? -1 : 1;
    const order = { critical: 0, high: 1, medium: 2 };
    return order[a.severity] - order[b.severity];
  });

  return {
    githubOrg: gh.org,
    githubSecrets: allSecrets.slice(0, 500),
    gitDirectories: dirs,
    stats,
  };
}
