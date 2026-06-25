import { logger } from "./logger";

// ── Types ──────────────────────────────────────────────────────────────────────

export type JsSecretSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface JsSecret {
  type: string;
  value: string;
  rawContext: string;
  file: string;
  line: number;
  severity: JsSecretSeverity;
  cwe: string;
  remediation: string;
}

export interface JsEndpoint {
  path: string;
  file: string;
  method?: string;
}

export interface JsFile {
  url: string;
  size: number;
  analyzed: boolean;
  endpointCount: number;
  secretCount: number;
}

export interface JsAnalysisResult {
  jsFiles: JsFile[];
  endpoints: JsEndpoint[];
  secrets: JsSecret[];
  stats: {
    totalFiles: number;
    analyzedFiles: number;
    totalEndpoints: number;
    totalSecrets: number;
    criticalSecrets: number;
    highSecrets: number;
  };
}

// ── Secret patterns (SecretFinder + custom) ───────────────────────────────────

interface SecretPattern {
  name: string;
  severity: JsSecretSeverity;
  cwe: string;
  pattern: RegExp;
  remediation: string;
}

const JS_SECRET_PATTERNS: SecretPattern[] = [
  // Cloud credentials
  { name: "AWS Access Key ID",       severity: "critical", cwe: "CWE-798", pattern: /AKIA[0-9A-Z]{16}/g,                                                                                       remediation: "Revoke in AWS IAM immediately. Rotate all associated permissions." },
  { name: "AWS Secret Access Key",   severity: "critical", cwe: "CWE-798", pattern: /(?:aws.{0,20}secret|secret.{0,10}key)\s*[=:'"]+\s*['"]?([A-Za-z0-9\/+]{38,42})['"]?/gi,                 remediation: "Revoke AWS credentials. Never commit secrets to code." },
  { name: "Google API Key",          severity: "high",     cwe: "CWE-798", pattern: /AIza[0-9A-Za-z_-]{35}/g,                                                                                  remediation: "Restrict key in Google Cloud Console and add HTTP referrer restrictions." },
  { name: "Google OAuth Client ID",  severity: "medium",   cwe: "CWE-798", pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,                                                  remediation: "Restrict OAuth client ID to specific origins in Google Cloud Console." },
  { name: "Firebase API Key",        severity: "high",     cwe: "CWE-798", pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g,                                                               remediation: "Restrict Firebase API key to specific apps/domains in Firebase Console." },
  // Auth tokens
  { name: "GitHub Personal Token",   severity: "high",     cwe: "CWE-798", pattern: /ghp_[a-zA-Z0-9]{36}/g,                                                                                    remediation: "Revoke in GitHub Settings → Developer Settings → Personal access tokens." },
  { name: "GitHub OAuth Token",      severity: "high",     cwe: "CWE-798", pattern: /gho_[a-zA-Z0-9]{36}/g,                                                                                    remediation: "Revoke the OAuth token and audit associated OAuth applications." },
  { name: "GitHub Actions Token",    severity: "high",     cwe: "CWE-798", pattern: /ghs_[a-zA-Z0-9]{36}/g,                                                                                    remediation: "Actions tokens are short-lived; check workflow for secret exposure." },
  { name: "Slack Bot Token",         severity: "high",     cwe: "CWE-798", pattern: /xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}/g,                                                       remediation: "Revoke in Slack API dashboard under OAuth & Permissions." },
  { name: "Slack Webhook URL",       severity: "medium",   cwe: "CWE-200", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,                          remediation: "Revoke webhook and generate a new one." },
  { name: "Stripe Live Secret Key",  severity: "critical", cwe: "CWE-798", pattern: /sk_live_[0-9a-zA-Z]{24,}/g,                                                                               remediation: "Revoke in Stripe dashboard → API Keys immediately." },
  { name: "Stripe Pub Key (Live)",   severity: "info",     cwe: "CWE-200", pattern: /pk_live_[0-9a-zA-Z]{24,}/g,                                                                               remediation: "Publishable key is low-risk, but ensure secret key is not also exposed." },
  { name: "Stripe Test Secret Key",  severity: "medium",   cwe: "CWE-798", pattern: /sk_test_[0-9a-zA-Z]{24,}/g,                                                                               remediation: "Rotate test key. Test keys should not appear in frontend code." },
  { name: "OpenAI API Key",          severity: "high",     cwe: "CWE-798", pattern: /sk-[a-zA-Z0-9]{48}/g,                                                                                     remediation: "Revoke at platform.openai.com/api-keys and regenerate." },
  { name: "Anthropic API Key",       severity: "high",     cwe: "CWE-798", pattern: /sk-ant-[a-zA-Z0-9_-]{90,}/g,                                                                              remediation: "Revoke at console.anthropic.com. Move to server-side env variables." },
  { name: "SendGrid API Key",        severity: "high",     cwe: "CWE-798", pattern: /SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{40,}/g,                                                            remediation: "Revoke in SendGrid Settings → API Keys." },
  { name: "Twilio Account SID",      severity: "high",     cwe: "CWE-798", pattern: /AC[a-zA-Z0-9]{32}/g,                                                                                      remediation: "Rotate Twilio credentials in console.twilio.com." },
  { name: "Mailgun API Key",         severity: "high",     cwe: "CWE-798", pattern: /key-[0-9a-zA-Z]{32}/g,                                                                                    remediation: "Revoke key in Mailgun API Keys section." },
  { name: "PayPal Braintree Token",  severity: "critical", cwe: "CWE-798", pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,                                                   remediation: "Revoke in Braintree dashboard immediately." },
  { name: "Square Access Token",     severity: "critical", cwe: "CWE-798", pattern: /EAAA[a-zA-Z0-9]{60,}/g,                                                                                   remediation: "Revoke token in Square Developer Dashboard." },
  { name: "Mapbox Token",            severity: "medium",   cwe: "CWE-798", pattern: /pk\.eyJ1[a-zA-Z0-9._+\/=\-]{80,150}/g,                                                                    remediation: "Restrict token to specific URLs in Mapbox Account → Tokens." },
  { name: "npm Auth Token",          severity: "high",     cwe: "CWE-798", pattern: /\/\/registry\.npmjs\.org\/:_authToken=[a-zA-Z0-9_-]{36}/g,                                                remediation: "Revoke token at npmjs.com/settings. Never commit .npmrc with tokens." },
  // Cryptographic material
  { name: "RSA/EC Private Key",      severity: "critical", cwe: "CWE-321", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,                                                 remediation: "Immediately revoke cert/key pair, reissue from CA, rotate all usages." },
  { name: "JWT Token",               severity: "medium",   cwe: "CWE-522", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,                                     remediation: "Investigate JWT exposure. Ensure signing secrets are not exposed." },
  // Database
  { name: "SQL Connection String",   severity: "critical", cwe: "CWE-312", pattern: /(?:mysql|mssql|postgres(?:ql)?|jdbc):\/\/[^:\s<>"']{2,}:[^@\s<>"']{4,}@\S{4,}/gi,                       remediation: "Remove DB credentials from code. Use environment variables." },
  { name: "MongoDB URI with Creds",  severity: "critical", cwe: "CWE-312", pattern: /mongodb(?:\+srv)?:\/\/[^:\s<>"']+:[^@\s<>"']+@[^\s<>"']{4,}/g,                                            remediation: "Rotate MongoDB credentials. Use environment variables." },
  // Hardcoded credentials
  { name: "Hardcoded Password",      severity: "high",     cwe: "CWE-259", pattern: /(?:password|passwd|pwd)\s*[:=]\s*['"]([a-zA-Z0-9!@#$%^&*()_+\-]{8,})['"]/gi,                            remediation: "Remove hardcoded passwords. Use environment variables or vaults." },
  { name: "Hardcoded Username",      severity: "low",      cwe: "CWE-798", pattern: /(?:username|user_name|login)\s*[:=]\s*['"]([a-zA-Z0-9._\-]{3,30})['"]/gi,                                remediation: "Avoid hardcoded usernames. Use environment variables." },
  { name: "Generic API Secret",      severity: "medium",   cwe: "CWE-798", pattern: /(?:api.?secret|client.?secret|auth.?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]/gi,                   remediation: "Move secrets to environment variables or a secrets manager." },
  { name: "Generic API Key",         severity: "medium",   cwe: "CWE-798", pattern: /(?:api.?key|apikey|api_key)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]/gi,                                  remediation: "Move API keys to server-side environment variables." },
  { name: "Basic Auth in URL",       severity: "high",     cwe: "CWE-312", pattern: /https?:\/\/[^:\s<>"']+:[^@\s<>"']{4,}@[a-zA-Z0-9][^\s<>"']{4,}/g,                                      remediation: "Never embed credentials in URLs. Use proper auth headers." },
  // Reconnaissance data
  { name: "Internal Network URL",    severity: "high",     cwe: "CWE-200", pattern: /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|localhost|127\.0\.0\.1)(?::\d+)?[^\s'"<>]*/gi, remediation: "Remove internal URLs from client-side code. They reveal internal architecture." },
  { name: "GraphQL Operation",       severity: "info",     cwe: "CWE-200", pattern: /(?:query|mutation|subscription)\s+\w+\s*(?:\([^)]{0,100}\))?\s*\{[^}]{10,300}\}/g,                        remediation: "Review exposed GraphQL operations for sensitive field access." },
  { name: "Email Address",           severity: "info",     cwe: "CWE-200", pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,                                                     remediation: "Verify exposed emails are intentional. Internal emails may enable phishing." },
];

// ── LinkFinder equivalent patterns ────────────────────────────────────────────

const HTTP_CALL_PATTERNS: { pattern: RegExp; methodGroup: number; urlGroup: number }[] = [
  { pattern: /fetch\(\s*['"`](\/[^'"`]{1,200})['"`]\s*(?:,\s*\{\s*method\s*:\s*['"]([A-Z]+)['"]\s*\})?/gi, urlGroup: 1, methodGroup: 2 },
  { pattern: /axios\.([a-zA-Z]+)\(\s*['"`]([^'"`]{1,200})['"`]/gi,                                          methodGroup: 1, urlGroup: 2 },
  { pattern: /\$\.ajax\(\s*\{\s*url\s*:\s*['"`]([^'"`]{1,200})['"`]\s*,\s*type\s*:\s*['"]([A-Z]+)['"]/gi,  urlGroup: 1, methodGroup: 2 },
  { pattern: /XMLHttpRequest[\s\S]{0,200}?\.open\(\s*['"]([A-Z]+)['"]\s*,\s*['"`]([^'"`]{1,200})['"`]/gi,  methodGroup: 1, urlGroup: 2 },
  { pattern: /(?:request|http|got)\s*\.\s*([a-zA-Z]+)\s*\(\s*['"`]([^'"`]{1,200})['"`]/gi,                 methodGroup: 1, urlGroup: 2 },
];

// Primary LinkFinder-style path extraction regex
const PATH_PATTERN = /(?:"|'|`)(((?:https?:\/\/|\/\/)[^"'`\s]{1,300})|((?:\/|\.\.\/|\.\/)[^"'`><,;| *()(%%$^\/\\\[\]][^"'`><,;|]{1,300})|([a-zA-Z0-9_\-/]{2,}\/[a-zA-Z0-9_\-/.]{2,}\.(?:[a-zA-Z]{1,4}|action)(?:[?#][^"'`]{0,100})?))(?:"|'|`)/gi;

// ── Helpers ────────────────────────────────────────────────────────────────────

function maskValue(s: string): string {
  return s.trim().replace(/^['"`]|['"`]$/g, "");
}

function getLineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function extractContext(content: string, index: number, matchLen: number): string {
  const start = Math.max(0, index - 80);
  const end = Math.min(content.length, index + matchLen + 80);
  const snippet = content.slice(start, end);
  const secretStart = index - start;
  const secretEnd = secretStart + matchLen;
  return snippet
    .replace(/[\r\n]+/g, " ")
    .trim()
    .slice(0, 220);
}

// ── LinkFinder: extract endpoints from JS content ─────────────────────────────

function runLinkFinder(content: string, fileUrl: string): JsEndpoint[] {
  const found = new Set<string>();
  const endpoints: JsEndpoint[] = [];

  const addEndpoint = (path: string, method?: string) => {
    if (!path || path.length < 2 || path.length > 400) return;
    if (/^(?:javascript:|data:|mailto:|tel:|blob:)/i.test(path)) return;
    if (/(?:google-analytics|googletagmanager|facebook\.net|twitter\.com|cdn\.jsdelivr|cloudflare\.com|jquery\.com|bootstrap\.|fontawesome)/i.test(path)) return;
    if (found.has(path)) {
      if (method) {
        const existing = endpoints.find(e => e.path === path);
        if (existing && !existing.method) existing.method = method.toUpperCase();
      }
      return;
    }
    found.add(path);
    endpoints.push({ path, file: fileUrl, method: method ? method.toUpperCase() : undefined });
  };

  // Primary path regex (LinkFinder-style)
  const patt = new RegExp(PATH_PATTERN.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = patt.exec(content)) !== null) {
    addEndpoint(m[1]?.trim() ?? "");
  }

  // HTTP call patterns — enrich with method
  for (const { pattern, methodGroup, urlGroup } of HTTP_CALL_PATTERNS) {
    const p = new RegExp(pattern.source, "gi");
    while ((m = p.exec(content)) !== null) {
      addEndpoint(m[urlGroup]?.trim() ?? "", m[methodGroup]);
    }
  }

  // Route definitions (Express/React Router style)
  const routePattern = /(?:app|router|Route)\s*\.\s*([a-zA-Z]+)\s*\(\s*['"`]([^'"`]{2,100})['"`]/gi;
  while ((m = routePattern.exec(content)) !== null) {
    addEndpoint(m[2]?.trim() ?? "", m[1]);
  }

  return endpoints;
}

// ── SecretFinder: detect secrets in JS content ────────────────────────────────

function runSecretFinder(content: string, fileUrl: string): JsSecret[] {
  const secrets: JsSecret[] = [];
  const seenKeys = new Set<string>();

  for (const sp of JS_SECRET_PATTERNS) {
    const pattern = new RegExp(sp.pattern.source, "gi");
    let m: RegExpExecArray | null;
    let count = 0;
    while ((m = pattern.exec(content)) !== null && count < 5) {
      const raw = m[0];
      const dedupeKey = `${sp.name}:${raw.slice(0, 24)}`;
      if (seenKeys.has(dedupeKey)) continue;
      seenKeys.add(dedupeKey);
      count++;
      secrets.push({
        type:        sp.name,
        value:       maskValue(raw),
        rawContext:  extractContext(content, m.index, raw.length),
        file:        fileUrl,
        line:        getLineNumber(content, m.index),
        severity:    sp.severity,
        cwe:         sp.cwe,
        remediation: sp.remediation,
      });
    }
  }

  return secrets;
}

// ── Extract JS file URLs from page HTML ───────────────────────────────────────

async function extractJsUrls(target: string, baseOrigin: string): Promise<string[]> {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 12000);
  try {
    const res = await fetch(target, {
      signal: ctrl.signal,
      headers: { "User-Agent": "Mozilla/5.0 (compatible; CTEM-Scanner/1.0; +https://sentinelware.io)" },
    });
    if (!res.ok) return [];
    const html = await res.text();
    const urls = new Set<string>();

    // <script src="...">
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+\.js(?:\?[^"']*)?)['"]/gi)) {
      try { urls.add(new URL(m[1], baseOrigin).href); } catch {}
    }
    // ES module imports in inline scripts / manifest
    for (const m of html.matchAll(/(?:import|from)\s+["']([^"']+\.js(?:\?[^"']*)?)["']/gi)) {
      try { urls.add(new URL(m[1], baseOrigin).href); } catch {}
    }
    // Asset manifest / next.js _app / chunk references
    for (const m of html.matchAll(/["'](\/(?:_next|static|assets|js|dist|chunks|build|public)\/[^"']+\.js(?:\?[^"']*)?)["']/gi)) {
      try { urls.add(new URL(m[1], baseOrigin).href); } catch {}
    }

    return [...urls];
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

// ── Fetch + analyse a single JS file ─────────────────────────────────────────

const MAX_JS_SIZE = 5 * 1024 * 1024;

async function analyzeJsFile(url: string): Promise<{ file: JsFile; endpoints: JsEndpoint[]; secrets: JsSecret[] }> {
  const file: JsFile = { url, size: 0, analyzed: false, endpointCount: 0, secretCount: 0 };
  try {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "User-Agent": "Mozilla/5.0 (compatible; CTEM-Scanner/1.0)" },
    });
    clearTimeout(timeout);
    if (!res.ok) return { file, endpoints: [], secrets: [] };

    const ct = res.headers.get("content-type") ?? "";
    if (/image\/|video\/|audio\//i.test(ct)) return { file, endpoints: [], secrets: [] };

    const buf = await res.arrayBuffer();
    file.size = buf.byteLength;
    if (file.size > MAX_JS_SIZE) return { file, endpoints: [], secrets: [] };

    const content = new TextDecoder().decode(buf);
    file.analyzed = true;

    const endpoints = runLinkFinder(content, url);
    const secrets   = runSecretFinder(content, url);
    file.endpointCount = endpoints.length;
    file.secretCount   = secrets.length;

    return { file, endpoints, secrets };
  } catch {
    return { file, endpoints: [], secrets: [] };
  }
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runJsAnalysis(target: string): Promise<JsAnalysisResult> {
  const empty: JsAnalysisResult = {
    jsFiles: [], endpoints: [], secrets: [],
    stats: { totalFiles: 0, analyzedFiles: 0, totalEndpoints: 0, totalSecrets: 0, criticalSecrets: 0, highSecrets: 0 },
  };

  let base: URL;
  try {
    base = new URL(target.startsWith("http") ? target : `https://${target}`);
  } catch { return empty; }

  logger.info({ target }, "JS analysis starting");

  // 1. Discover JS file URLs from the page
  const jsUrls = await extractJsUrls(base.href, base.origin);
  const uniqueUrls = [...new Set(jsUrls)].slice(0, 60);

  if (uniqueUrls.length === 0) {
    logger.info({ target }, "JS analysis: no JS files found");
    return empty;
  }

  // 2. Analyse each JS file in parallel batches
  const allEndpoints: JsEndpoint[] = [];
  const allSecrets:   JsSecret[]   = [];
  const allFiles:     JsFile[]     = [];

  const BATCH = 10;
  for (let i = 0; i < uniqueUrls.length; i += BATCH) {
    const results = await Promise.allSettled(
      uniqueUrls.slice(i, i + BATCH).map(u => analyzeJsFile(u))
    );
    for (const r of results) {
      if (r.status !== "fulfilled") continue;
      allFiles.push(r.value.file);
      allEndpoints.push(...r.value.endpoints);
      allSecrets.push(...r.value.secrets);
    }
  }

  // 3. Deduplicate endpoints by path
  const seenPaths = new Set<string>();
  const dedupedEndpoints = allEndpoints.filter(e => {
    if (seenPaths.has(e.path)) return false;
    seenPaths.add(e.path);
    return true;
  });

  const criticalSecrets = allSecrets.filter(s => s.severity === "critical").length;
  const highSecrets     = allSecrets.filter(s => s.severity === "high").length;
  const analyzedFiles   = allFiles.filter(f => f.analyzed).length;

  logger.info({
    target,
    totalFiles: uniqueUrls.length,
    analyzedFiles,
    endpoints: dedupedEndpoints.length,
    secrets: allSecrets.length,
    criticalSecrets,
    highSecrets,
  }, "JS analysis complete");

  return {
    jsFiles:   allFiles,
    endpoints: dedupedEndpoints.slice(0, 2000),
    secrets:   allSecrets.slice(0, 500),
    stats: {
      totalFiles:     uniqueUrls.length,
      analyzedFiles,
      totalEndpoints: dedupedEndpoints.length,
      totalSecrets:   allSecrets.length,
      criticalSecrets,
      highSecrets,
    },
  };
}
