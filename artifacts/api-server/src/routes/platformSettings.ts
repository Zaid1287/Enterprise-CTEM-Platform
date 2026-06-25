import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, platformSettingsTable } from "@workspace/db";
import { requireAuth, type AuthenticatedRequest } from "../lib/auth";

const router = Router();

const PLATFORM_KEYS = [
  { key: "resend_api_key",       label: "Resend API Key",        description: "Used for sending alert emails, invitations, and notifications via Resend.com",   category: "email" },
  { key: "slack_webhook_url",    label: "Slack Webhook URL",     description: "Incoming webhook URL for posting alerts to a Slack channel",                     category: "notifications" },
  { key: "discord_webhook_url",  label: "Discord Webhook URL",   description: "Discord webhook URL for posting alerts to a Discord server",                      category: "notifications" },
  { key: "shodan_api_key",       label: "Shodan API Key",        description: "Enables full Shodan API lookups (vulnerability data, ports, CPEs, CVEs, hostnames). Without this key, the free Shodan InternetDB is used instead.", category: "scanning" },
  { key: "nvd_api_key",          label: "NVD API Key",           description: "NVD (National Vulnerability Database) API key — increases rate limit from 5 req/30s to 50 req/30s", category: "scanning" },
  { key: "virustotal_api_key",   label: "VirusTotal API Key",    description: "Used for domain/IP reputation lookups during reconnaissance",                     category: "scanning" },
  { key: "hunter_api_key",       label: "Hunter.io API Key",     description: "Used to find employee emails associated with a target domain (OSINT)",            category: "osint" },
  { key: "github_token",         label: "GitHub Token",          description: "GitHub personal access token (classic) — enables GitHub code search and secrets scanning with higher rate limits (30 req/min vs 10 unauthenticated)", category: "osint" },
  { key: "fofa_email",           label: "Fofa Email",            description: "Fofa.info account email — required alongside the Fofa API key for passive discovery queries", category: "intelligence" },
  { key: "fofa_api_key",         label: "Fofa API Key",          description: "Fofa.info API key — queries the Fofa internet scanner for hosts matching target domains", category: "intelligence" },
  { key: "censys_api_id",        label: "Censys API ID",         description: "Censys Search API ID — scans Censys host database for IPs/services linked to a domain", category: "intelligence" },
  { key: "censys_api_secret",    label: "Censys API Secret",     description: "Censys Search API Secret — used with the API ID for Basic authentication",        category: "intelligence" },
  { key: "intelx_api_key",       label: "IntelX API Key",        description: "Intelligence X (intelx.io) API key — searches breached data, pastes, dark web mentions for target domains", category: "intelligence" },
  { key: "criminalip_api_key",   label: "CriminalIP API Key",    description: "CriminalIP (criminalip.io) API key — provides threat intelligence reports and IP risk scoring for target domains", category: "intelligence" },
  { key: "hibp_api_key",         label: "HIBP API Key",          description: "Have I Been Pwned API key — checks if your domain's email accounts appear in known data breaches", category: "brand_threat" },
  { key: "google_safe_browsing_key", label: "Google Safe Browsing Key", description: "Google Safe Browsing API key — verifies brand threat domains against Google's phishing/malware database", category: "brand_threat" },
  { key: "whoisxml_api_key",     label: "WhoisXML API Key",      description: "WhoisXML API key — enhanced WHOIS lookups with registrant contact data and domain age analysis", category: "brand_threat" },
  { key: "smtp_host",            label: "SMTP Host",             description: "Custom SMTP server host (used if Resend is not configured)",                      category: "email" },
  { key: "smtp_port",            label: "SMTP Port",             description: "Custom SMTP server port (e.g. 587 for TLS)",                                       category: "email" },
  { key: "smtp_user",            label: "SMTP Username",         description: "SMTP authentication username",                                                    category: "email" },
  { key: "smtp_pass",            label: "SMTP Password",         description: "SMTP authentication password",                                                    category: "email" },
  { key: "smtp_from",            label: "SMTP From Address",     description: "The from email address used for outgoing emails",                                  category: "email" },
  { key: "telegram_bot_token",   label: "Telegram Bot Token",    description: "Token for your Telegram bot (from @BotFather). Used to send alert notifications via Telegram.", category: "notifications" },
  { key: "telegram_chat_id",     label: "Telegram Chat ID",      description: "Telegram chat/group/channel ID to receive platform-level alert notifications.",                category: "notifications" },
];

function isSuperAdmin(req: AuthenticatedRequest): boolean {
  return req.user?.role === "super_admin";
}

function maskValue(key: string, value: string): string {
  if (!value) return "";
  const sensitiveKeys = ["api_key", "webhook_url", "smtp_pass", "smtp_user"];
  const isSensitive = sensitiveKeys.some(k => key.includes(k));
  if (!isSensitive) return value;
  if (value.length <= 8) return "••••••••";
  return "••••" + value.slice(-6);
}

router.get("/platform/settings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isSuperAdmin(req)) { res.status(403).json({ error: "Super admin only" }); return; }

  const stored = await db.select().from(platformSettingsTable);
  const storedMap = new Map(stored.map(s => [s.key, s.value]));

  const settings = PLATFORM_KEYS.map(def => ({
    key: def.key,
    label: def.label,
    description: def.description,
    category: def.category,
    hasValue: !!storedMap.get(def.key),
    maskedValue: maskValue(def.key, storedMap.get(def.key) ?? ""),
  }));

  res.json(settings);
});

router.put("/platform/settings", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isSuperAdmin(req)) { res.status(403).json({ error: "Super admin only" }); return; }

  const updates = req.body as Record<string, string>;

  for (const [key, value] of Object.entries(updates)) {
    const def = PLATFORM_KEYS.find(k => k.key === key);
    if (!def) continue;

    const existing = await db.select().from(platformSettingsTable).where(eq(platformSettingsTable.key, key));
    if (existing.length > 0) {
      if (value === "" || value === null || value === undefined) {
        await db.delete(platformSettingsTable).where(eq(platformSettingsTable.key, key));
      } else {
        await db.update(platformSettingsTable).set({ value, label: def.label, description: def.description, category: def.category }).where(eq(platformSettingsTable.key, key));
      }
    } else if (value) {
      await db.insert(platformSettingsTable).values({ key, value, label: def.label, description: def.description, category: def.category });
    }
  }

  res.json({ ok: true });
});

router.get("/platform/settings/raw/:key", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isSuperAdmin(req)) { res.status(403).json({ error: "Super admin only" }); return; }
  const [row] = await db.select().from(platformSettingsTable).where(eq(platformSettingsTable.key, req.params.key));
  res.json({ value: row?.value ?? "" });
});

export async function getPlatformSetting(key: string): Promise<string | null> {
  const [row] = await db.select({ value: platformSettingsTable.value }).from(platformSettingsTable).where(eq(platformSettingsTable.key, key));
  return row?.value ?? null;
}

export default router;
