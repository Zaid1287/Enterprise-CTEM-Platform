import { Router } from "express";
import { eq } from "drizzle-orm";
import { db, platformSettingsTable } from "@workspace/db";
import { requireAuth, denyExternalMembers, type AuthenticatedRequest } from "../lib/auth";
import { reinitRedis, setRuntimeRedisUrl } from "../lib/redis";
import { restartScanWorker } from "../workers/scanWorker";
import { restartAlertWorker } from "../workers/alertWorker";

const router = Router();
router.use(denyExternalMembers);

interface PlatformKeyDef {
  key: string;
  label: string;
  description: string;
  category: string;
  comingSoon?: boolean;
}

const PLATFORM_KEYS: PlatformKeyDef[] = [
  { key: "redis_url",            label: "Redis URL",              description: "Redis connection URL (redis:// or rediss:// for TLS). Upstash: use rediss:// scheme. Enables BullMQ durable scan queuing, retry on failure, and crash recovery. Without Redis, scans run in-process and are lost on server restart.", category: "infrastructure" },
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
  { key: "phishtank_api_key",    label: "PhishTank API Key",     description: "PhishTank API key — removes anonymous throttle when downloading the PhishTank verified phishing URL feed", category: "brand_threat" },
  { key: "smtp_host",            label: "SMTP Host",             description: "Custom SMTP server host (used if Resend is not configured)",                      category: "email" },
  { key: "smtp_port",            label: "SMTP Port",             description: "Custom SMTP server port (e.g. 587 for TLS)",                                       category: "email" },
  { key: "smtp_user",            label: "SMTP Username",         description: "SMTP authentication username",                                                    category: "email" },
  { key: "smtp_pass",            label: "SMTP Password",         description: "SMTP authentication password",                                                    category: "email" },
  { key: "smtp_from",            label: "SMTP From Address",     description: "The from email address used for outgoing emails",                                  category: "email" },
  { key: "telegram_bot_token",      label: "Telegram Bot Token",         description: "Token for your Telegram bot (from @BotFather). Used to send alert notifications via Telegram.", category: "notifications" },
  { key: "telegram_chat_id",        label: "Telegram Chat ID",           description: "Telegram chat/group/channel ID to receive platform-level alert notifications.",                category: "notifications" },
  { key: "stripe_secret_key",       label: "Stripe Secret Key",          description: "Stripe Secret Key (sk_live_... or sk_test_...) — enables subscription billing, checkout sessions, and customer portal. Never expose this client-side.", category: "billing" },
  { key: "stripe_webhook_secret",   label: "Stripe Webhook Secret",      description: "Stripe Webhook Signing Secret (whsec_...) — used to verify that webhook events originate from Stripe. Create it in your Stripe Dashboard → Developers → Webhooks.", category: "billing" },
  { key: "stripe_publishable_key",  label: "Stripe Publishable Key",     description: "Stripe Publishable Key (pk_live_... or pk_test_...) — used client-side to initialize Stripe.js for checkout. Safe to expose publicly.", category: "billing" },
  { key: "meta_ads_access_token",        label: "Meta Ads Access Token",         description: "Meta (Facebook/Instagram) Marketing API access token — queries the Ads Library for brand-impersonating ads and unauthorized advertiser pages.", category: "brand_intelligence" },
  { key: "youtube_api_key",              label: "YouTube Data API Key",          description: "YouTube Data API v3 key — searches for brand-impersonating channels, fake product videos, and scam promotions targeting your brand.", category: "brand_intelligence" },
  { key: "twitter_x_bearer_token",       label: "Twitter/X Bearer Token",        description: "Twitter/X API v2 Bearer Token — monitors tweets, accounts, and trending topics for brand impersonation (scanning enabled when approved).", category: "brand_intelligence", comingSoon: true },
  { key: "instagram_graph_api_token",    label: "Instagram Graph API Token",     description: "Instagram Graph API access token — tracks fake Instagram accounts and posts impersonating your brand (scanning enabled when approved).", category: "brand_intelligence", comingSoon: true },
  { key: "tiktok_research_api_token",    label: "TikTok Research API Token",     description: "TikTok Research API access token — scans TikTok for scam videos and impersonating accounts targeting your brand (scanning enabled when approved).", category: "brand_intelligence", comingSoon: true },
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
    comingSoon: def.comingSoon ?? false,
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

router.post("/platform/settings/test-key", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  const { key } = req.body as { key: string };
  const TESTABLE: Record<string, (val: string, extra: string) => Promise<string>> = {
    shodan_api_key: async (val) => {
      const r = await fetch(`https://api.shodan.io/api-info?key=${encodeURIComponent(val)}`);
      const j = await r.json() as any;
      if (j.error) throw new Error(j.error);
      return `Connected. Query credits: ${j.query_credits ?? "?"}, Scan credits: ${j.scan_credits ?? "?"}`;
    },
    virustotal_api_key: async (val) => {
      const r = await fetch("https://www.virustotal.com/api/v3/users/self", { headers: { "x-apikey": val } });
      if (!r.ok) throw new Error("Invalid API key");
      const j = await r.json() as any;
      return `Connected as ${j.data?.attributes?.email ?? "user"}`;
    },
    nvd_api_key: async (val) => {
      const r = await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", { headers: { apiKey: val } });
      if (!r.ok) throw new Error(`NVD returned ${r.status}`);
      return "NVD API key valid — enhanced rate limit active";
    },
    redis_url: async (val) => {
      const { default: Redis } = await import("ioredis");
      const isTls = val.startsWith("rediss://");
      const client = new Redis(val, {
        maxRetriesPerRequest: 1, enableReadyCheck: false, lazyConnect: true,
        connectTimeout: 5000, ...(isTls ? { tls: {} } : {}),
      });
      try {
        await client.connect();
        await client.ping();
        const info = await client.info("server").catch(() => "");
        const version = info.match(/redis_version:([^\r\n]+)/)?.[1]?.trim() ?? "?";
        return `Connected — Redis ${version}`;
      } finally {
        client.disconnect();
      }
    },
    censys_api_id: async (val, secret) => {
      const creds = Buffer.from(`${val}:${secret}`).toString("base64");
      const r = await fetch("https://search.censys.io/api/v1/account", { headers: { Authorization: `Basic ${creds}` } });
      if (!r.ok) throw new Error("Invalid credentials");
      const j = await r.json() as any;
      return `Connected as ${j.login ?? "user"}`;
    },
  };
  if (!TESTABLE[key]) { res.status(400).json({ error: "Key not testable" }); return; }
  const [row] = await db.select({ value: platformSettingsTable.value }).from(platformSettingsTable).where(eq(platformSettingsTable.key, key));
  if (!row?.value) { res.status(400).json({ error: "Key not set. Save the key first." }); return; }
  let extra = "";
  if (key === "censys_api_id") {
    const [secRow] = await db.select({ value: platformSettingsTable.value }).from(platformSettingsTable).where(eq(platformSettingsTable.key, "censys_api_secret"));
    extra = secRow?.value ?? "";
  }
  try {
    const message = await TESTABLE[key](row.value, extra);
    res.json({ ok: true, message });
  } catch (e: any) {
    res.json({ ok: false, message: e.message ?? "Test failed" });
  }
});

// ── POST /platform/workers/restart ── Apply new Redis URL and restart BullMQ workers
router.post("/platform/workers/restart", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isSuperAdmin(req)) { res.status(403).json({ error: "Super admin only" }); return; }
  try {
    const [row] = await db.select({ value: platformSettingsTable.value })
      .from(platformSettingsTable).where(eq(platformSettingsTable.key, "redis_url"));
    const redisUrl = row?.value ?? process.env.REDIS_URL ?? "";
    if (!redisUrl) {
      res.status(400).json({ ok: false, message: "No Redis URL configured. Save a Redis URL first." });
      return;
    }
    setRuntimeRedisUrl(redisUrl);
    await reinitRedis(redisUrl);
    await Promise.all([restartScanWorker(), restartAlertWorker()]);
    res.json({ ok: true, message: "Workers restarted with new Redis URL" });
  } catch (err: any) {
    res.status(500).json({ ok: false, message: err?.message ?? "Restart failed" });
  }
});

// ── GET /platform/workers/status ── Worker / Redis status for super admin
router.get("/platform/workers/status", requireAuth, async (req: AuthenticatedRequest, res): Promise<void> => {
  if (!isSuperAdmin(req)) { res.status(403).json({ error: "Super admin only" }); return; }
  const { isRedisAvailable, getActiveRedisUrl } = await import("../lib/redis");
  const redisConnected = isRedisAvailable();
  const hasUrl = !!getActiveRedisUrl();
  res.json({ redisConfigured: hasUrl, redisConnected, bullmqActive: redisConnected });
});

export async function getPlatformSetting(key: string): Promise<string | null> {
  const [row] = await db.select({ value: platformSettingsTable.value }).from(platformSettingsTable).where(eq(platformSettingsTable.key, key));
  return row?.value ?? null;
}

export default router;
