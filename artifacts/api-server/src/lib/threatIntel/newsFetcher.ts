/**
 * Threat Intelligence News Fetcher
 * Pulls from real cybersecurity RSS feeds, classifies severity,
 * extracts tags/CVEs/actors, and upserts into ti_news_feeds.
 *
 * Sources (all free, no API key required):
 *  - The Hacker News      (feeds.feedburner.com/TheHackersNews)
 *  - BleepingComputer     (bleepingcomputer.com/feed/)
 *  - Krebs on Security    (krebsonsecurity.com/feed/)
 *  - Dark Reading         (darkreading.com/rss.xml)
 *  - SecurityWeek         (feeds.feedburner.com/securityweek)
 *  - Cybersecurity News   (cybersecuritynews.com/feed/)
 *  - Graham Cluley        (grahamcluley.com/feed/)
 *  - SANS ISC             (isc.sans.edu/rssfeed.xml)
 */

import { db, tiFeedRunsTable, tiNewsFeedsTable } from "@workspace/db";
import { eq, sql } from "drizzle-orm";
import { logger } from "../logger.js";

const FETCH_TIMEOUT_MS = 20_000;
const UA = "Sentinelware-CTEM-TI/1.0 (+https://sentinelware.io)";

// ── News sources ──────────────────────────────────────────────────────────────

export interface NewsSource {
  id: string;         // internal key — stored as `source` in DB
  displayName: string;
  url: string;
  type: "rss" | "atom";
  defaultSeverity: "low" | "medium" | "high";
  tags: string[];
}

export const NEWS_SOURCES: NewsSource[] = [
  {
    id: "hackernews",
    displayName: "The Hacker News",
    url: "https://feeds.feedburner.com/TheHackersNews",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity", "hacking"],
  },
  {
    id: "therecord",
    displayName: "The Record",
    url: "https://therecord.media/feed/",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity", "threat-intel"],
  },
  {
    id: "krebsonsecurity",
    displayName: "Krebs on Security",
    url: "https://krebsonsecurity.com/feed/",
    type: "rss",
    defaultSeverity: "high",
    tags: ["cybersecurity", "investigation"],
  },
  {
    id: "darkreading",
    displayName: "Dark Reading",
    url: "https://www.darkreading.com/rss.xml",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity", "enterprise"],
  },
  {
    id: "securityweek",
    displayName: "SecurityWeek",
    url: "https://feeds.feedburner.com/securityweek",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity", "vulnerabilities"],
  },
  {
    id: "cybersecuritynews",
    displayName: "Cybersecurity News",
    url: "https://cybersecuritynews.com/feed/",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity"],
  },
  {
    id: "grahamcluley",
    displayName: "Graham Cluley",
    url: "https://grahamcluley.com/feed/",
    type: "rss",
    defaultSeverity: "low",
    tags: ["cybersecurity", "analysis"],
  },
  {
    id: "sans_isc",
    displayName: "SANS ISC",
    url: "https://isc.sans.edu/rssfeed.xml",
    type: "rss",
    defaultSeverity: "medium",
    tags: ["cybersecurity", "threat-intel", "SANS"],
  },
];

// ── Severity classifier ───────────────────────────────────────────────────────

const CRITICAL_PATTERNS = [
  /zero.?day/i, /0.?day/i, /actively exploit/i, /emergency patch/i,
  /nation.state/i, /critical infrastructure/i, /in the wild/i, /worm/i,
];
const HIGH_PATTERNS = [
  /ransomware/i, /data breach/i, /\bapt\b/i, /critical (vuln|flaw|bug)/i,
  /remote code exec/i, /\brce\b/i, /backdoor/i, /rootkit/i, /supply.chain/i,
  /espionage/i, /spyware/i, /cyberattack/i, /breach/i, /stolen/i,
];
const MEDIUM_PATTERNS = [
  /vulnerabilit/i, /\bcve-\d/i, /patch/i, /advisory/i, /flaw/i,
  /phishing/i, /malware/i, /trojan/i, /botnet/i, /exploit/i,
  /privilege escal/i, /authentication bypass/i,
];

function classifySeverity(text: string, defaultSev: string): "critical" | "high" | "medium" | "low" | "info" {
  if (CRITICAL_PATTERNS.some(p => p.test(text))) return "critical";
  if (HIGH_PATTERNS.some(p => p.test(text))) return "high";
  if (MEDIUM_PATTERNS.some(p => p.test(text))) return "medium";
  return defaultSev as any;
}

// ── Tag extractor ─────────────────────────────────────────────────────────────

const KNOWN_TAGS = [
  "ransomware", "phishing", "malware", "APT", "zero-day", "vulnerability",
  "data breach", "exploit", "CVE", "patch", "RCE", "supply chain",
  "nation-state", "backdoor", "botnet", "spyware", "rootkit", "DDoS",
  "credential theft", "social engineering", "SQL injection", "XSS",
  "cloud security", "IoT", "OT/ICS", "healthcare", "finance", "government",
  "critical infrastructure", "AI security", "deepfake",
];

function extractTags(text: string, sourceTags: string[]): string[] {
  const found = new Set<string>(sourceTags);
  for (const tag of KNOWN_TAGS) {
    if (new RegExp(`\\b${tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(text)) {
      found.add(tag);
    }
  }
  return Array.from(found).slice(0, 10);
}

function extractCves(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) ?? [];
  return [...new Set(matches.map(c => c.toUpperCase()))].slice(0, 10);
}

function extractActors(text: string): string[] {
  const KNOWN_ACTORS = [
    "APT28", "APT29", "APT41", "Lazarus Group", "Sandworm", "Cozy Bear",
    "Fancy Bear", "Charming Kitten", "Volt Typhoon", "Salt Typhoon",
    "BlackCat", "LockBit", "REvil", "Conti", "Cl0p", "Scattered Spider",
    "ALPHV", "Kimsuky", "Turla", "TA505",
  ];
  return KNOWN_ACTORS.filter(a => new RegExp(`\\b${a.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i").test(text));
}

// ── Simple RSS/Atom XML parser ────────────────────────────────────────────────

interface ParsedItem {
  title: string;
  url: string;
  summary: string;
  publishedAt: Date | null;
}

function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim();
}

function extractTag(xml: string, tag: string): string {
  // Handle both <tag>content</tag> and CDATA
  const re = new RegExp(`<${tag}[^>]*>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`, "i");
  const m = xml.match(re);
  if (!m) return "";
  return decodeHtmlEntities(stripHtml((m[1] ?? m[2] ?? "").trim()));
}

function extractAttr(xml: string, tag: string, attr: string): string {
  const re = new RegExp(`<${tag}[^>]+${attr}="([^"]*)"`, "i");
  const m = xml.match(re);
  return m ? m[1] : "";
}

function parseRss(xml: string): ParsedItem[] {
  const items: ParsedItem[] = [];
  // Split on <item> or <entry> boundaries
  const isAtom = /<feed[\s>]/i.test(xml);
  const itemTag = isAtom ? "entry" : "item";
  const parts = xml.split(new RegExp(`<${itemTag}[\\s>]`, "i")).slice(1);

  for (const part of parts) {
    const chunk = part.replace(new RegExp(`<\\/${itemTag}>.*`, "si"), "");

    const title = extractTag(chunk, "title") || "Untitled";

    // URL: <link href="..."/> (Atom) or <link>...</link> (RSS)
    let url = extractAttr(chunk, "link", "href");
    if (!url) url = extractTag(chunk, "link");
    if (!url) url = extractTag(chunk, "guid");

    // Summary: content:encoded > description > summary > content
    let summary = extractTag(chunk, "content:encoded") ||
                  extractTag(chunk, "description") ||
                  extractTag(chunk, "summary") ||
                  extractTag(chunk, "content");
    summary = summary.slice(0, 500);

    // Date: pubDate > published > updated > dc:date
    const rawDate = extractTag(chunk, "pubDate") ||
                    extractTag(chunk, "published") ||
                    extractTag(chunk, "updated") ||
                    extractTag(chunk, "dc:date");
    let publishedAt: Date | null = null;
    if (rawDate) {
      try { publishedAt = new Date(rawDate); if (isNaN(publishedAt.getTime())) publishedAt = null; }
      catch { publishedAt = null; }
    }

    if (title && url) {
      items.push({ title, url, summary, publishedAt });
    }
  }
  return items;
}

// ── Fetch one source ──────────────────────────────────────────────────────────

async function fetchSource(source: NewsSource): Promise<{ added: number; updated: number; error?: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);

  let xml: string;
  try {
    const resp = await fetch(source.url, {
      signal: ctrl.signal,
      headers: { "User-Agent": UA, "Accept": "application/rss+xml, application/xml, text/xml, */*" },
    });
    clearTimeout(timer);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    xml = await resp.text();
  } catch (err: any) {
    clearTimeout(timer);
    throw new Error(`Fetch failed: ${err.message}`);
  }

  const items = parseRss(xml);
  if (items.length === 0) throw new Error("No items parsed from feed");

  let added = 0, updated = 0;

  for (const item of items) {
    if (!item.url) continue;

    const combined = `${item.title} ${item.summary}`;
    const severity = classifySeverity(combined, source.defaultSeverity);
    const tags = extractTags(combined, source.tags);
    const cves = extractCves(combined);
    const actors = extractActors(combined);

    try {
      const existing = await db.select({ id: tiNewsFeedsTable.id })
        .from(tiNewsFeedsTable)
        .where(eq(tiNewsFeedsTable.url, item.url))
        .limit(1);

      if (existing.length > 0) {
        // Update if needed (title might have changed, summary enriched)
        await db.update(tiNewsFeedsTable)
          .set({ title: item.title, summary: item.summary || null, severity, tags, cves, actors })
          .where(eq(tiNewsFeedsTable.url, item.url));
        updated++;
      } else {
        await db.insert(tiNewsFeedsTable).values({
          title: item.title,
          url: item.url,
          source: source.id,
          sourceName: source.displayName,
          summary: item.summary || null,
          severity,
          tags,
          sectors: [],
          cves,
          actors,
          publishedAt: item.publishedAt,
        });
        added++;
      }
    } catch (dbErr: any) {
      // Unique constraint on url — race condition, skip
      if (dbErr.code !== "23505") logger.warn({ err: dbErr.message }, `[news] DB error for ${item.url}`);
    }
  }

  return { added, updated };
}

// ── Public entry points ───────────────────────────────────────────────────────

/** Refresh a single source by id, or all sources if sourceId is undefined */
export async function runNewsFeedRefresh(sourceId?: string): Promise<void> {
  const sources = sourceId
    ? NEWS_SOURCES.filter(s => s.id === sourceId)
    : NEWS_SOURCES;

  if (sources.length === 0) {
    logger.warn(`[news] Unknown source: ${sourceId}`);
    return;
  }

  for (const source of sources) {
    const [feedRun] = await db.insert(tiFeedRunsTable).values({
      source: `news_${source.id}`,
      status: "running",
      recordsAdded: 0,
      recordsUpdated: 0,
    }).returning();

    try {
      const { added, updated } = await fetchSource(source);
      await db.update(tiFeedRunsTable).set({
        status: "completed",
        recordsAdded: added,
        recordsUpdated: updated,
        completedAt: new Date(),
      }).where(eq(tiFeedRunsTable.id, feedRun.id));
      logger.info(`[news] ${source.displayName}: +${added} new, ~${updated} updated`);
    } catch (err: any) {
      await db.update(tiFeedRunsTable).set({
        status: "failed",
        error: err.message,
        completedAt: new Date(),
      }).where(eq(tiFeedRunsTable.id, feedRun.id));
      logger.warn(`[news] ${source.displayName} failed: ${err.message}`);
    }
  }
}

/** Get last-run status for all news sources */
export async function getNewsSourcesStatus(): Promise<Array<{
  id: string;
  displayName: string;
  lastRun: any;
  status: string;
  recordsAdded: number;
  error: string | null;
  completedAt: Date | null;
}>> {
  const runs = await db.select().from(tiFeedRunsTable)
    .where(sql`source LIKE 'news_%'`)
    .orderBy(sql`started_at DESC`)
    .limit(200);

  const latest: Record<string, any> = {};
  for (const r of runs) {
    if (!latest[r.source]) latest[r.source] = r;
  }

  return NEWS_SOURCES.map(s => {
    const run = latest[`news_${s.id}`] ?? null;
    return {
      id: s.id,
      displayName: s.displayName,
      lastRun: run,
      status: run?.status ?? "never",
      recordsAdded: run?.recordsAdded ?? 0,
      error: run?.error ?? null,
      completedAt: run?.completedAt ?? null,
    };
  });
}
