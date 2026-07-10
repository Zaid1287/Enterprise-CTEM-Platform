import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { logger } from "./logger";
import { orchestratedFetch } from "./scanOrchestrator";

const execAsync = promisify(exec);

// ── Nuclei template bootstrap ─────────────────────────────────────────────────
// Downloads the official nuclei-templates repo once at startup. Subsequent
// calls are no-ops (nuclei skips download if templates already exist).
export async function bootstrapNucleiTemplates(): Promise<void> {
  try {
    const { stdout } = await execAsync(
      "nuclei -update-templates -silent 2>&1 || true",
      { timeout: 120_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    logger.info({ output: stdout.slice(0, 200) }, "Nuclei templates bootstrap complete");
  } catch (err) {
    logger.warn({ err }, "Nuclei template bootstrap failed (non-fatal — using built-in checks)");
  }
}

// ── Types ──────────────────────────────────────────────────────────────────────

export type VulnSeverity = "critical" | "high" | "medium" | "low" | "info";
export type VulnCategory = "exposed-panel" | "sensitive-file" | "misconfiguration" | "cve" | "cors" | "header";

export interface NucleiVuln {
  templateId: string;
  name: string;
  severity: VulnSeverity;
  category: VulnCategory;
  host: string;
  url: string;
  evidence: string;
  description: string;
  remediation: string;
  cvss?: number;
  cve?: string;
  cwe?: string;
  tags: string[];
}

export interface HeaderCheck {
  name: string;
  present: boolean;
  value?: string;
  severity: VulnSeverity;
  issue: string;
  recommendation: string;
}

export interface HeaderAnalysis {
  host: string;
  url: string;
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  serverBanner?: string;
  poweredBy?: string;
  checks: HeaderCheck[];
}

export interface CorsResult {
  host: string;
  url: string;
  isVulnerable: boolean;
  severity: "high" | "medium" | "low";
  variant: "reflected-origin" | "null-origin" | "wildcard-credentials" | "subdomain-confusion";
  allowOrigin: string;
  allowCredentials: boolean;
  description: string;
  remediation: string;
}

export interface VulnScanResult {
  findings: NucleiVuln[];
  headers: HeaderAnalysis[];
  cors: CorsResult[];
  stats: {
    hostsScanned: number;
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    corsVulnerable: number;
    headerIssues: number;
    avgHeaderScore: number;
  };
}

// ── Nuclei-style templates (40+ checks) ───────────────────────────────────────

interface Template {
  id: string;
  name: string;
  severity: VulnSeverity;
  category: VulnCategory;
  paths: string[];
  matchers: Array<{ type: "status" | "word" | "header"; values: (string | number)[] }>;
  description: string;
  remediation: string;
  cvss?: number;
  cve?: string;
  cwe?: string;
  tags: string[];
}

const TEMPLATES: Template[] = [
  // ── Sensitive files ────────────────────────────────────────────────────────
  { id: "git-head-exposure",       name: "Git Repository Exposed (.git/HEAD)",    severity: "high",   category: "sensitive-file",   paths: [".git/HEAD", ".git/config"],                          matchers: [{ type: "status", values: [200] }, { type: "word", values: ["ref:", "[core]", "bare"] }], description: "The .git directory is publicly accessible, exposing the entire source code history including credentials, secrets, and business logic.", remediation: "Block access to .git via web server config (e.g., Nginx: `location ~ /\\.git { deny all; }`).", cvss: 7.5, cwe: "CWE-538", tags: ["git","exposure","source-code"] },
  { id: "env-file-exposure",       name: "Environment File Exposed (.env)",        severity: "critical", category: "sensitive-file", paths: [".env", ".env.local", ".env.backup", ".env.prod", ".env.staging"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["DB_", "DATABASE_URL", "SECRET", "API_KEY", "TOKEN=", "KEY=", "PASSWORD=", "PASS="] }], description: "The .env file containing application secrets, database credentials, and API keys is publicly accessible.", remediation: "Deny access to all .env files via server config. Immediately rotate all exposed credentials.", cvss: 9.8, cwe: "CWE-312", tags: ["env","credentials","exposure"] },
  { id: "aws-credentials",         name: "AWS Credentials File Exposed",           severity: "critical", category: "sensitive-file", paths: [".aws/credentials", ".aws/config"],                   matchers: [{ type: "status", values: [200] }, { type: "word", values: ["aws_access_key_id", "[default]", "aws_secret"] }], description: "AWS credentials file is publicly accessible, exposing cloud access keys.", remediation: "Remove or block access to .aws/ via server configuration. Rotate all exposed AWS keys immediately.", cvss: 9.8, cwe: "CWE-312", tags: ["aws","cloud","credentials"] },
  { id: "ssh-private-key",         name: "SSH Private Key Exposed",                severity: "critical", category: "sensitive-file", paths: ["id_rsa", ".ssh/id_rsa", "id_ecdsa", "id_ed25519"],   matchers: [{ type: "status", values: [200] }, { type: "word", values: ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "BEGIN EC PRIVATE KEY"] }], description: "An SSH private key is publicly accessible. This allows unauthorized server access.", remediation: "Immediately remove the key file, revoke the key from all servers, generate a new key pair.", cvss: 9.8, cwe: "CWE-321", tags: ["ssh","key","critical"] },
  { id: "phpinfo-disclosure",      name: "PHP Info Disclosure",                    severity: "medium", category: "misconfiguration", paths: ["phpinfo.php", "info.php", "php-info.php", "phpi.php"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["PHP Version", "phpinfo()", "System", "Build Date"] }], description: "phpinfo() exposes PHP version, server config, installed extensions, and environment variables including potentially sensitive data.", remediation: "Remove phpinfo() files from production. Restrict PHP version disclosure via `expose_php = Off`.", cvss: 5.3, cwe: "CWE-200", tags: ["php","disclosure","info"] },
  { id: "wp-config-exposure",      name: "WordPress Config File Exposed",          severity: "critical", category: "sensitive-file", paths: ["wp-config.php", "wp-config.php.bak", "wp-config.php~"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["DB_NAME", "DB_HOST", "DB_USER", "AUTH_KEY", "SECURE_AUTH_KEY"] }], description: "WordPress configuration file exposing database credentials and secret keys.", remediation: "Immediately block access to wp-config.php via .htaccess or Nginx config.", cvss: 9.8, cwe: "CWE-312", tags: ["wordpress","credentials"] },
  { id: "config-json-exposure",    name: "Config/Secrets File Exposed",            severity: "high",   category: "sensitive-file",   paths: ["config.json", "secrets.json", "credentials.json", "settings.json", "application.json"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["password", "secret", "token", "api_key", "apiKey", "auth", "credential"] }], description: "A JSON configuration file containing credentials or sensitive configuration is publicly accessible.", remediation: "Remove sensitive config files from web root. Store secrets in environment variables or a secrets manager.", cvss: 8.5, cwe: "CWE-312", tags: ["config","secrets"] },
  { id: "database-backup",         name: "Database Backup Exposed",                severity: "critical", category: "sensitive-file", paths: ["backup.sql", "database.sql", "db.sql", "dump.sql", "data.sql", "backup.sql.gz"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "USE ", "--"] }], description: "A SQL database backup file is publicly accessible, potentially exposing all application data.", remediation: "Move backup files out of the web root. Use server-side access controls for backups.", cvss: 9.8, cwe: "CWE-312", tags: ["database","backup","exposure"] },
  { id: "htpasswd-exposure",       name: ".htpasswd File Exposed",                 severity: "high",   category: "sensitive-file",   paths: [".htpasswd"],                                         matchers: [{ type: "status", values: [200] }, { type: "word", values: ["$apr1$", "$2y$", ":{SHA}", ":$1$", "$6$"] }], description: "The .htpasswd file containing password hashes is publicly accessible.", remediation: "Deny access to all .ht* files: `location ~ /\\.ht { deny all; }`", cvss: 7.5, cwe: "CWE-312", tags: ["auth","passwords"] },
  { id: "docker-compose-exposure", name: "Docker Compose File Exposed",            severity: "medium", category: "sensitive-file",   paths: ["docker-compose.yml", "docker-compose.yaml"],         matchers: [{ type: "status", values: [200] }, { type: "word", values: ["services:", "image:", "environment:", "volumes:"] }], description: "Docker Compose configuration exposed, revealing container structure, environment variables, and potentially credentials.", remediation: "Block access to docker-compose.yml and restrict configuration files via server rules.", cvss: 5.3, cwe: "CWE-200", tags: ["docker","disclosure"] },

  // ── Exposed admin panels ───────────────────────────────────────────────────
  { id: "phpmyadmin-panel",        name: "phpMyAdmin Admin Panel Exposed",         severity: "high",   category: "exposed-panel",    paths: ["phpmyadmin", "phpmyadmin/index.php", "pma", "mysql", "mysqladmin"], matchers: [{ type: "status", values: [200, 301, 302] }, { type: "word", values: ["phpMyAdmin", "PMA_", "phpMyAdmin"] }], description: "phpMyAdmin database management interface is publicly accessible. Brute-force or credential stuffing could lead to full database compromise.", remediation: "Restrict phpMyAdmin to specific IPs using server ACLs. Require strong authentication and enable 2FA.", cvss: 7.5, cwe: "CWE-284", tags: ["phpmyadmin","admin","database"] },
  { id: "adminer-panel",           name: "Adminer Database Panel Exposed",         severity: "high",   category: "exposed-panel",    paths: ["adminer", "adminer.php", "adminer-4.7.8.php"],       matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Adminer", "adminer", "Login — Adminer"] }], description: "Adminer database management tool is publicly accessible without IP restriction.", remediation: "Remove or restrict access to Adminer. Use IP allowlist or VPN for database admin tools.", cvss: 7.5, cwe: "CWE-284", tags: ["adminer","admin","database"] },
  { id: "grafana-panel",           name: "Grafana Dashboard Exposed",              severity: "medium", category: "exposed-panel",    paths: ["grafana", "grafana/login"],                          matchers: [{ type: "status", values: [200, 302] }, { type: "word", values: ["Grafana", "grafana", "GF_SECURITY"] }], description: "Grafana monitoring dashboard is publicly accessible. Default credentials (admin/admin) are commonly exploited.", remediation: "Change default credentials, enforce MFA, and restrict Grafana behind a VPN or IP allowlist.", cvss: 5.3, cwe: "CWE-284", tags: ["grafana","monitoring","panel"] },
  { id: "kibana-panel",            name: "Kibana Dashboard Exposed",               severity: "high",   category: "exposed-panel",    paths: ["app/kibana", "kibana", "_plugin/kibana"],             matchers: [{ type: "status", values: [200, 302] }, { type: "word", values: ["Kibana", "kibana", "Elastic"] }], description: "Kibana Elasticsearch dashboard is publicly accessible, potentially exposing indexed log data and infrastructure info.", remediation: "Enable Kibana security, configure authentication, and restrict network access to trusted IPs.", cvss: 7.5, cwe: "CWE-284", tags: ["kibana","elasticsearch","panel"] },
  { id: "jenkins-panel",           name: "Jenkins CI/CD Panel Exposed",            severity: "high",   category: "exposed-panel",    paths: ["jenkins", "jenkins/login", "j/api/json"],            matchers: [{ type: "status", values: [200, 302, 403] }, { type: "word", values: ["Jenkins", "Dashboard [Jenkins]", "Sign in - Jenkins"] }], description: "Jenkins CI/CD server is publicly accessible. Unauthenticated access can lead to RCE via build scripts.", remediation: "Enable Jenkins authentication, disable signup, restrict network access.", cvss: 8.5, cwe: "CWE-284", tags: ["jenkins","ci-cd","rce"] },

  // ── API documentation ──────────────────────────────────────────────────────
  { id: "swagger-ui",              name: "Swagger/OpenAPI UI Exposed",             severity: "medium", category: "exposed-panel",    paths: ["swagger-ui", "swagger-ui.html", "swagger", "api-docs", "openapi.json", "swagger.json"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Swagger UI", "swagger-ui", "openapi", "SwaggerUI", "swagger: \"2.0\"", "openapi: \"3"] }], description: "API documentation is publicly accessible, revealing all API endpoints, parameters, authentication mechanisms, and data models.", remediation: "Restrict API docs to authenticated users or internal network. Disable in production if not needed.", cvss: 5.3, cwe: "CWE-200", tags: ["swagger","api-docs","exposure"] },
  { id: "graphql-playground",      name: "GraphQL Playground/IDE Exposed",         severity: "medium", category: "exposed-panel",    paths: ["graphql", "graphiql", "playground", "api/graphql"],  matchers: [{ type: "status", values: [200] }, { type: "word", values: ["GraphiQL", "__schema", "graphiql", "GraphQL IDE", "playground"] }], description: "GraphQL introspection and interactive playground is enabled in production, revealing the full schema and allowing unrestricted query execution.", remediation: "Disable GraphQL introspection in production. Restrict playground to development environments.", cvss: 5.3, cwe: "CWE-200", tags: ["graphql","introspection","api"] },

  // ── Spring Actuator (high risk) ────────────────────────────────────────────
  { id: "actuator-env",            name: "Spring Actuator /env Exposed",           severity: "critical", category: "misconfiguration", paths: ["actuator/env", "actuator/environment"],           matchers: [{ type: "status", values: [200] }, { type: "word", values: ["activeProfiles", "propertySources", "systemEnvironment"] }], description: "Spring Boot Actuator /env endpoint exposed. This discloses all environment variables, configuration properties, and application secrets.", remediation: "Restrict Actuator endpoints: `management.endpoints.web.exposure.include=health,info`. Enable security on all Actuator endpoints.", cvss: 9.8, cwe: "CWE-200", tags: ["spring","actuator","secrets"] },
  { id: "actuator-heapdump",       name: "Spring Actuator /heapdump Exposed",      severity: "critical", category: "misconfiguration", paths: ["actuator/heapdump"],                              matchers: [{ type: "status", values: [200] }, { type: "header", values: ["octet-stream", "application/octet"] }], description: "Spring Boot heap dump is accessible. Memory dumps contain all in-memory data including credentials, session tokens, and PII.", remediation: "Disable the heapdump endpoint immediately: `management.endpoint.heapdump.enabled=false`.", cvss: 9.8, cwe: "CWE-312", tags: ["spring","actuator","heap-dump"] },
  { id: "actuator-loggers",        name: "Spring Actuator /loggers Exposed",       severity: "high",   category: "misconfiguration", paths: ["actuator/loggers", "actuator/trace", "actuator/httptrace"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["levels", "loggers", "ROOT", "TRACE", "DEBUG"] }], description: "Spring Boot Actuator loggers/trace endpoints are exposed, potentially allowing log level manipulation and HTTP trace data disclosure.", remediation: "Restrict all Actuator endpoints behind authentication. Expose only health and info for public use.", cvss: 7.5, cwe: "CWE-200", tags: ["spring","actuator"] },
  { id: "actuator-beans",          name: "Spring Actuator /beans Exposed",         severity: "high",   category: "misconfiguration", paths: ["actuator/beans", "actuator/mappings", "actuator/conditions"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["beans", "aliases", "type", "dependencies", "requestMappingConditions"] }], description: "Spring Boot Actuator /beans and /mappings endpoints expose application architecture, bean definitions, and URL routing.", remediation: "Apply Spring Security to all actuator endpoints.", cvss: 6.5, cwe: "CWE-200", tags: ["spring","actuator","disclosure"] },

  // ── Server status / debug ──────────────────────────────────────────────────
  { id: "apache-server-status",    name: "Apache Server Status Exposed",           severity: "medium", category: "misconfiguration", paths: ["server-status", "server-info"],                     matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Apache Server Status", "requests/sec", "Apache Server Information"] }], description: "Apache mod_status is enabled and publicly accessible, revealing active connections, request paths, worker stats, and client IP addresses.", remediation: "Restrict server-status to localhost: `Allow from 127.0.0.1` in the Apache config.", cvss: 5.3, cwe: "CWE-200", tags: ["apache","server-status"] },
  { id: "symfony-profiler",        name: "Symfony Debug Profiler Exposed",         severity: "high",   category: "misconfiguration", paths: ["_profiler", "_wdt", "_profiler/phpinfo"],            matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Symfony", "Profiler", "Debug", "symfony"] }], description: "Symfony debug toolbar/profiler is accessible in production, revealing SQL queries, configuration, request/response data, and environment variables.", remediation: "Set `APP_ENV=prod` in production. The profiler is disabled in production mode.", cvss: 8.0, cwe: "CWE-200", tags: ["symfony","php","debug"] },
  { id: "laravel-ignition",        name: "Laravel Ignition Debug Page Exposed",    severity: "high",   category: "misconfiguration", paths: ["_ignition/health-check", "telescope", "horizon"],   matchers: [{ type: "status", values: [200] }, { type: "word", values: ["ignition", "Telescope", "Horizon", "Laravel"] }], description: "Laravel debug tooling (Ignition/Telescope/Horizon) is accessible in production. Can expose stack traces, queries, jobs, and application internals.", remediation: "Set `APP_DEBUG=false` and `APP_ENV=production`. Restrict Telescope/Horizon via authentication middleware.", cvss: 7.5, cwe: "CWE-200", tags: ["laravel","php","debug"] },

  // ── CMS / Framework specific ───────────────────────────────────────────────
  { id: "wordpress-xmlrpc",        name: "WordPress XMLRPC Enabled",               severity: "medium", category: "misconfiguration", paths: ["xmlrpc.php"],                                       matchers: [{ type: "status", values: [200, 405] }, { type: "word", values: ["XML-RPC server accepts POST requests only", "xmlrpc"] }], description: "WordPress XML-RPC is enabled, allowing brute-force amplification attacks (thousands of login attempts per request) and pingback DDoS.", remediation: "Disable XMLRPC via .htaccess: `deny from all` on xmlrpc.php. Or use a security plugin.", cvss: 6.5, cwe: "CWE-307", tags: ["wordpress","xmlrpc","brute-force"] },
  { id: "wordpress-user-enum",     name: "WordPress User Enumeration",             severity: "medium", category: "misconfiguration", paths: ["wp-json/wp/v2/users"],                              matchers: [{ type: "status", values: [200] }, { type: "word", values: ["\"slug\":", "\"capabilities\":", "\"roles\":", "rest_url"] }], description: "WordPress REST API exposes user list without authentication, enabling username enumeration for targeted attacks.", remediation: "Disable user endpoint or require authentication: add `add_filter('rest_endpoints', ...)` in functions.php.", cvss: 5.3, cwe: "CWE-200", tags: ["wordpress","user-enum"] },
  { id: "drupal-changelog",        name: "Drupal Version Disclosure (CHANGELOG)",  severity: "low",    category: "misconfiguration", paths: ["CHANGELOG.txt", "INSTALL.txt", "README.txt"],       matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Drupal", "drupal"] }], description: "Drupal version information is disclosed via CHANGELOG.txt, enabling targeted exploitation.", remediation: "Remove or deny access to CHANGELOG.txt, INSTALL.txt, and README.txt.", cvss: 3.7, cwe: "CWE-200", tags: ["drupal","cms","version-disclosure"] },
  { id: "phpunit-rce",             name: "PHPUnit Remote Code Execution (CVE-2017-9841)", severity: "critical", category: "cve", paths: ["vendor/phpunit/phpunit/phpunit", "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"], matchers: [{ type: "status", values: [200] }, { type: "word", values: ["phpunit", "eval-stdin", "PHP"] }], description: "PHPUnit eval-stdin.php is exposed. This allows unauthenticated remote code execution. Actively exploited in the wild.", remediation: "Remove vendor directory from web root immediately. Configure server to block access to vendor/. Update PHPUnit if needed.", cvss: 9.8, cve: "CVE-2017-9841", cwe: "CWE-94", tags: ["phpunit","rce","cve","critical"] },
  { id: "rails-info",              name: "Rails Debug Info Page Exposed",           severity: "high",   category: "misconfiguration", paths: ["rails/info/properties", "rails/info/routes"],       matchers: [{ type: "status", values: [200] }, { type: "word", values: ["Rails.root", "Rails.version", "ruby_version"] }], description: "Rails debug info page is accessible in production, exposing framework versions, route definitions, and server configuration.", remediation: "Set `config.consider_all_requests_local = false` in production environment.", cvss: 6.5, cwe: "CWE-200", tags: ["rails","ruby","debug"] },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

const UA = "Mozilla/5.0 (compatible; Nuclei/3.1; +https://sentinelware.io)";

async function fetchUrl(
  url: string, _timeoutMs = 8000, headers?: Record<string, string>
): Promise<{ status: number; body: string; headers: Record<string, string> } | null> {
  try {
    const res = await orchestratedFetch(url, {
      method: "GET", redirect: "manual",
      headers: { "User-Agent": UA, "Accept": "*/*", ...headers },
    }, { intensity: "vuln-scan" });
    const body = (await res.text().catch(() => "")).slice(0, 8000);
    const h: Record<string, string> = {};
    res.headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
    return { status: res.status, body, headers: h };
  } catch { return null; }
}

function bodyMatches(body: string, words: (string | number)[]): boolean {
  const b = body.toLowerCase();
  return words.some(w => b.includes(String(w).toLowerCase()));
}

// ── Template runner ───────────────────────────────────────────────────────────

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

async function runTemplates(baseUrl: string, host: string, sem: Semaphore): Promise<NucleiVuln[]> {
  const found: NucleiVuln[] = [];
  const base = baseUrl.replace(/\/$/, "");

  await Promise.allSettled(
    TEMPLATES.flatMap(tpl =>
      tpl.paths.map(async (path) => {
        await sem.acquire();
        try {
          const url = `${base}/${path}`;
          const r = await fetchUrl(url);
          if (!r) return;

          for (const m of tpl.matchers) {
            if (m.type === "status" && !m.values.includes(r.status)) return;
            if (m.type === "word" && !bodyMatches(r.body, m.values)) return;
            if (m.type === "header") {
              const ct = r.headers["content-type"] ?? "";
              if (!m.values.some(v => ct.includes(String(v)))) return;
            }
          }

          const snippet = r.body.slice(0, 200).replace(/\s+/g, " ").trim();
          found.push({
            templateId: tpl.id,
            name: tpl.name,
            severity: tpl.severity,
            category: tpl.category,
            host,
            url,
            evidence: snippet || `HTTP ${r.status}`,
            description: tpl.description,
            remediation: tpl.remediation,
            cvss: tpl.cvss,
            cve: tpl.cve,
            cwe: tpl.cwe,
            tags: tpl.tags,
          });
        } finally { sem.release(); }
      })
    )
  );

  // Deduplicate by templateId + host
  const seen = new Set<string>();
  return found.filter(f => {
    const k = `${f.templateId}:${f.host}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ── CORS testing ──────────────────────────────────────────────────────────────

async function testCors(baseUrl: string, host: string): Promise<CorsResult[]> {
  const results: CorsResult[] = [];
  const domain = host.replace(/^www\./, "");

  const vectors: Array<{ origin: string; variant: CorsResult["variant"] }> = [
    { origin: "https://evil.example.com",       variant: "reflected-origin" },
    { origin: "null",                            variant: "null-origin" },
    { origin: `https://attacker.${domain}`,     variant: "subdomain-confusion" },
    { origin: `https://${domain}.evil.com`,     variant: "reflected-origin" },
  ];

  await Promise.allSettled(
    vectors.map(async ({ origin, variant }) => {
      const r = await fetchUrl(baseUrl, 6000, {
        Origin: origin, "Cache-Control": "no-cache",
      });
      if (!r) return;

      const acao = r.headers["access-control-allow-origin"] ?? "";
      const acac = r.headers["access-control-allow-credentials"]?.toLowerCase() === "true";

      if (!acao) return;

      const isVulnerable = acao === origin || acao === "*" || acao === "null";
      if (!isVulnerable) return;

      let severity: "high" | "medium" | "low" = "medium";
      let description = "";
      let remediation = "";

      if (variant === "null-origin" && acao === "null") {
        severity = "high";
        description = `CORS allows the 'null' origin — can be exploited via sandboxed iframes or file:// URIs to bypass same-origin policy.`;
        remediation = "Never allow 'null' as a CORS origin. Use an explicit allowlist of trusted origins.";
      } else if (variant === "wildcard-credentials" && acao === "*") {
        severity = acac ? "high" : "low";
        description = `CORS is configured with wildcard origin (*). ${acac ? "Combined with Access-Control-Allow-Credentials: true, this is a critical misconfiguration." : "Wildcard disallows credentials but may expose APIs publicly."}`;
        remediation = "Replace wildcard with an explicit origin allowlist. Never combine ACAO: * with ACAC: true.";
      } else if (acao === origin) {
        severity = acac ? "high" : "medium";
        description = `CORS reflects the supplied Origin (${origin}). ${acac ? "With credentials enabled, attackers on any domain can make authenticated cross-origin requests." : "Origin is reflected without strict validation."}`;
        remediation = "Validate CORS origins against a strict allowlist. Do not reflect arbitrary Origins. If credentials are needed, use an explicit allowlist only.";
      } else return;

      results.push({
        host, url: baseUrl, isVulnerable: true,
        severity, variant,
        allowOrigin: acao, allowCredentials: acac,
        description, remediation,
      });
    })
  );

  // Deduplicate by variant
  const seen = new Set<string>();
  return results.filter(r => {
    const k = `${r.variant}:${r.host}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ── Security header analysis ──────────────────────────────────────────────────

interface HeaderRule {
  name: string;
  check: (headers: Record<string, string>, isHttps: boolean) => { present: boolean; value?: string; severity: VulnSeverity; issue: string; recommendation: string };
}

const HEADER_RULES: HeaderRule[] = [
  {
    name: "Content-Security-Policy",
    check: (h) => {
      const csp = h["content-security-policy"];
      if (!csp) return { present: false, severity: "high", issue: "Missing CSP header. Cross-site scripting attacks are not mitigated.", recommendation: "Set a strict Content-Security-Policy. Minimum: `default-src 'self'`. Avoid 'unsafe-inline' and 'unsafe-eval'." };
      const weak = ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"].some(w => csp.includes(w));
      return { present: true, value: csp.slice(0, 120), severity: weak ? "medium" : "info", issue: weak ? `CSP contains weak directives (unsafe-inline/unsafe-eval/data:): ${csp.slice(0, 80)}` : "", recommendation: "Avoid 'unsafe-inline' and 'unsafe-eval'. Use nonces/hashes instead." };
    },
  },
  {
    name: "X-Frame-Options",
    check: (h) => {
      const xfo = h["x-frame-options"];
      if (!xfo) return { present: false, severity: "medium", issue: "Missing X-Frame-Options. The page may be embedded in an iframe enabling clickjacking attacks.", recommendation: "Add: `X-Frame-Options: DENY` or `SAMEORIGIN`. Prefer CSP `frame-ancestors` directive." };
      return { present: true, value: xfo, severity: "info", issue: "", recommendation: "" };
    },
  },
  {
    name: "Strict-Transport-Security",
    check: (h, isHttps) => {
      if (!isHttps) return { present: false, severity: "info", issue: "HSTS not applicable to HTTP connections.", recommendation: "Serve all content over HTTPS and enable HSTS." };
      const hsts = h["strict-transport-security"];
      if (!hsts) return { present: false, severity: "high", issue: "Missing HSTS header. Users may connect over insecure HTTP.", recommendation: "Add: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`" };
      const match = hsts.match(/max-age=(\d+)/);
      const age = match ? parseInt(match[1]) : 0;
      if (age < 2592000) return { present: true, value: hsts, severity: "medium", issue: `HSTS max-age too short (${age}s < 30 days). Easy to bypass.`, recommendation: "Set max-age to at least 31536000 (1 year)." };
      return { present: true, value: hsts, severity: "info", issue: "", recommendation: "" };
    },
  },
  {
    name: "X-Content-Type-Options",
    check: (h) => {
      const xcto = h["x-content-type-options"];
      if (!xcto) return { present: false, severity: "medium", issue: "Missing X-Content-Type-Options. MIME-type sniffing attacks possible.", recommendation: "Add: `X-Content-Type-Options: nosniff`" };
      return { present: true, value: xcto, severity: "info", issue: "", recommendation: "" };
    },
  },
  {
    name: "Referrer-Policy",
    check: (h) => {
      const rp = h["referrer-policy"];
      if (!rp) return { present: false, severity: "low", issue: "Missing Referrer-Policy. Browser may send full URL in Referer header to third parties.", recommendation: "Add: `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`." };
      return { present: true, value: rp, severity: "info", issue: "", recommendation: "" };
    },
  },
  {
    name: "Permissions-Policy",
    check: (h) => {
      const pp = h["permissions-policy"] ?? h["feature-policy"];
      if (!pp) return { present: false, severity: "low", issue: "Missing Permissions-Policy. Browser features (camera, mic, geolocation) unrestricted.", recommendation: "Add: `Permissions-Policy: geolocation=(), microphone=(), camera=()` to disable unused browser features." };
      return { present: true, value: pp, severity: "info", issue: "", recommendation: "" };
    },
  },
  {
    name: "Server Version Disclosure",
    check: (h) => {
      const sv = h["server"] ?? "";
      const version = /([a-z]+\/[\d.]+)/i.exec(sv);
      if (version) return { present: true, value: sv, severity: "low", issue: `Server header discloses software version: ${sv}. Aids targeted exploitation.`, recommendation: "Configure server to omit version: `ServerTokens Prod` (Apache), `server_tokens off` (Nginx)." };
      if (sv) return { present: true, value: sv, severity: "info", issue: "", recommendation: "" };
      return { present: false, severity: "info", issue: "", recommendation: "Good — no Server header exposed." };
    },
  },
  {
    name: "X-Powered-By Disclosure",
    check: (h) => {
      const xpb = h["x-powered-by"] ?? "";
      if (xpb) return { present: true, value: xpb, severity: "low", issue: `X-Powered-By discloses technology stack: ${xpb}. Aids fingerprinting.`, recommendation: "Remove X-Powered-By header: `Header unset X-Powered-By` (Apache), `proxy_hide_header X-Powered-By` (Nginx), `expose_php = Off` (PHP)." };
      return { present: false, severity: "info", issue: "", recommendation: "" };
    },
  },
];

function gradeScore(score: number): HeaderAnalysis["grade"] {
  if (score >= 95) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 50) return "C";
  if (score >= 35) return "D";
  return "F";
}

async function analyzeHeaders(baseUrl: string, host: string): Promise<HeaderAnalysis> {
  const isHttps = baseUrl.startsWith("https://");
  const r = await fetchUrl(baseUrl, 8000);
  if (!r) {
    return { host, url: baseUrl, score: 0, grade: "F", checks: [], serverBanner: undefined, poweredBy: undefined };
  }

  const checks: HeaderCheck[] = HEADER_RULES.map(rule => {
    const result = rule.check(r.headers, isHttps);
    return { name: rule.name, ...result };
  });

  // Score: start at 100, deduct per severity
  const deductions: Record<VulnSeverity, number> = { critical: 30, high: 20, medium: 10, low: 5, info: 0 };
  let score = 100;
  for (const c of checks) {
    if (!c.present || c.issue) score -= deductions[c.severity];
  }
  score = Math.max(0, score);

  return {
    host, url: baseUrl, score, grade: gradeScore(score),
    serverBanner: r.headers["server"],
    poweredBy: r.headers["x-powered-by"],
    checks,
  };
}

// ── Nuclei binary integration ──────────────────────────────────────────────────

function mapNucleiTag(tags: string[]): VulnCategory {
  const t = tags.join(",").toLowerCase();
  if (t.includes("cve"))     return "cve";
  if (t.includes("panel") || t.includes("login") || t.includes("dashboard")) return "exposed-panel";
  if (t.includes("cors"))    return "cors";
  if (t.includes("secret") || t.includes("exposure") || t.includes("file")) return "sensitive-file";
  return "misconfiguration";
}

async function runNucleiBinary(target: string): Promise<NucleiVuln[]> {
  try {
    const safeTarget = target.replace(/"/g, "").replace(/`/g, "").slice(0, 500);
    // No outer process timeout — nuclei binary runs until it naturally completes.
    // The 120 s limit was killing the binary mid-output on large targets, causing
    // partial JSON output that gets silently dropped.
    const { stdout } = await execAsync(
      `nuclei -u "${safeTarget}" -severity critical,high,medium -json -timeout 15 -rate-limit 100 -no-interactsh -silent 2>/dev/null`,
      { env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    return stdout.trim().split("\n")
      .filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })
      .map((r: any) => ({
        templateId: r["template-id"] ?? r.templateID ?? "",
        name:       r.info?.name ?? r["template-id"] ?? "Unknown",
        severity:   (r.info?.severity ?? "info") as VulnSeverity,
        category:   mapNucleiTag(r.info?.tags ?? []),
        host:       r.host ?? safeTarget,
        url:        r["matched-at"] ?? r.matched ?? r.host ?? safeTarget,
        evidence:   (r["extracted-results"] ?? [r["matched-at"] ?? ""]).join(", ").slice(0, 500),
        description: r.info?.description ?? "",
        remediation: r.info?.remediation ?? "Review and remediate the detected vulnerability.",
        cvss:       r.info?.classification?.["cvss-score"] ?? undefined,
        cve:        r.info?.classification?.["cve-id"]?.[0] ?? undefined,
        cwe:        r.info?.classification?.["cwe-id"]?.[0] ?? undefined,
        tags:       r.info?.tags ?? [],
      }));
  } catch (err) {
    logger.warn({ target, err }, "Nuclei binary unavailable or timed out — using built-in templates");
    return [];
  }
}

// ── Main orchestrator ─────────────────────────────────────────────────────────

export async function runNucleiScan(target: string, subdomainNames: string[] = []): Promise<VulnScanResult> {
  const empty: VulnScanResult = {
    findings: [], headers: [], cors: [],
    stats: { hostsScanned: 0, totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, corsVulnerable: 0, headerIssues: 0, avgHeaderScore: 0 },
  };

  let primaryBase: string;
  try {
    const u = new URL(target.startsWith("http") ? target : `https://${target}`);
    primaryBase = `${u.protocol}//${u.hostname}`;
  } catch { return empty; }

  // ── Real nuclei binary (runs first, parallel with built-in templates) ──────
  const binaryFindingsPromise = runNucleiBinary(primaryBase);
  logger.info({ target }, "Nuclei binary scan started (parallel with built-in templates)");

  const domain = new URL(primaryBase).hostname.replace(/^www\./, "");

  // Build host list: primary + up to 8 live subdomains
  const extraBases = [...new Set(
    subdomainNames
      .filter(n => n && !n.includes("*") && n !== domain && n !== `www.${domain}`)
      .slice(0, 8)
      .map(n => `https://${n}`)
  )];

  const allBases = [primaryBase, ...extraBases];
  logger.info({ target, hosts: allBases.length }, "Nuclei scan starting");

  const sem = new Semaphore(20); // max 20 concurrent requests across all hosts
  // No hard timeout — let all templates run to completion regardless of how long it takes.
  // A timeout here was the primary cause of zero-finding scans: if the wall-clock fired
  // first, ALL nuclei findings were silently discarded, making every timed-out scan
  // look identical to a scan that found nothing.
  const [findings, headers, cors] = await Promise.all([
    // Template scans across all hosts
    Promise.allSettled(allBases.map(b => runTemplates(b, new URL(b).hostname, sem)))
      .then(r => r.flatMap(x => x.status === "fulfilled" ? x.value : [])),
    // Header analysis (primary host + up to 5 subdomains)
    Promise.allSettled(allBases.slice(0, 6).map(b => analyzeHeaders(b, new URL(b).hostname)))
      .then(r => r.filter(x => x.status === "fulfilled").map(x => (x as PromiseFulfilledResult<HeaderAnalysis>).value)),
    // CORS testing (primary host only — most impactful)
    testCors(primaryBase, domain),
  ]);

  // ── Merge binary findings (deduplicate by templateId+host) ───────────────
  const binaryFindings = await binaryFindingsPromise;
  const seen = new Set(findings.map(f => `${f.templateId}::${f.host}`));
  const newBinaryFindings = binaryFindings.filter(f => !seen.has(`${f.templateId}::${f.host}`));
  const allFindings = [...findings, ...newBinaryFindings];
  logger.info({ target, builtIn: findings.length, binary: binaryFindings.length, merged: allFindings.length }, "Nuclei merged results");

  const corsVulns = cors.filter(c => c.isVulnerable);
  const headerIssues = headers.reduce((sum, h) => sum + h.checks.filter(c => c.issue).length, 0);
  const avgHeaderScore = headers.length > 0 ? Math.round(headers.reduce((s, h) => s + h.score, 0) / headers.length) : 0;

  const stats = {
    hostsScanned:    allBases.length,
    totalFindings:   allFindings.length,
    critical:        allFindings.filter(f => f.severity === "critical").length,
    high:            allFindings.filter(f => f.severity === "high").length,
    medium:          allFindings.filter(f => f.severity === "medium").length,
    low:             allFindings.filter(f => f.severity === "low").length,
    info:            allFindings.filter(f => f.severity === "info").length,
    corsVulnerable:  corsVulns.length,
    headerIssues,
    avgHeaderScore,
  };

  logger.info({ target, ...stats }, "Nuclei scan complete");
  return { findings: allFindings, headers, cors: corsVulns, stats };
}

// ── Custom Nuclei Templates from DB ───────────────────────────────────────────

export interface CustomNucleiTemplate {
  id: number;
  name: string;
  content: string;
}

export async function runCustomNucleiTemplatesBinary(
  target: string,
  templates: CustomNucleiTemplate[],
): Promise<NucleiVuln[]> {
  if (!templates.length) return [];

  const tmpDir = path.join(os.tmpdir(), `nuclei-custom-${Date.now()}`);
  try {
    await fs.promises.mkdir(tmpDir, { recursive: true });

    await Promise.all(templates.map(async (t) => {
      const safeName = t.name.replace(/[^a-zA-Z0-9\-_]/g, "_");
      await fs.promises.writeFile(
        path.join(tmpDir, `${safeName}-${t.id}.yaml`),
        t.content,
        "utf8"
      );
    }));

    const safeTarget = target.replace(/"/g, "").replace(/`/g, "").slice(0, 500);
    const { stdout } = await execAsync(
      `nuclei -u "${safeTarget}" -t "${tmpDir}" -json -timeout 15 -rate-limit 50 -no-interactsh -silent -no-update-check 2>/dev/null`,
      { timeout: 120_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );

    logger.info({ target, templates: templates.length }, "Custom nuclei templates binary scan complete");

    return stdout.trim().split("\n")
      .filter(Boolean)
      .flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } })
      .map((r: any) => ({
        templateId: r["template-id"] ?? r.templateID ?? "",
        name: r.info?.name ?? r["template-id"] ?? "Custom Template Finding",
        severity: (r.info?.severity ?? "medium") as VulnSeverity,
        category: mapNucleiTag(r.info?.tags ?? []),
        host: r.host ?? safeTarget,
        url: r["matched-at"] ?? r.matched ?? r.host ?? safeTarget,
        evidence: (r["extracted-results"] ?? [r["matched-at"] ?? ""]).join(", ").slice(0, 500),
        description: r.info?.description ?? "Custom nuclei template match",
        remediation: r.info?.remediation ?? "Review the custom template finding and remediate accordingly.",
        cvss: r.info?.classification?.["cvss-score"] ?? undefined,
        cve: r.info?.classification?.["cve-id"]?.[0] ?? undefined,
        cwe: r.info?.classification?.["cwe-id"]?.[0] ?? undefined,
        tags: r.info?.tags ?? [],
      }));
  } catch (err) {
    logger.warn({ target, err }, "Custom nuclei templates scan failed");
    return [];
  } finally {
    try { await fs.promises.rm(tmpDir, { recursive: true, force: true }); } catch {}
  }
}
