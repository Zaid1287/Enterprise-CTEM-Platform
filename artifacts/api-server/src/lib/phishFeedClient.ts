import { logger } from "./logger";

interface PhishFeedState {
  phishtank: Set<string>;
  openphish: Set<string>;
  lastFetched: number;
  lastPhishTankKey: string | null;
}

const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const state: PhishFeedState = {
  phishtank: new Set(),
  openphish: new Set(),
  lastFetched: 0,
  lastPhishTankKey: null,
};

let _phishTankKey: string | null = null;

export function setPhishTankKey(key: string | null): void {
  // If key changed, invalidate the PhishTank cache so next call re-fetches
  if (key !== _phishTankKey) {
    _phishTankKey = key;
    state.lastFetched = 0;
  }
}

async function refreshFeeds(): Promise<void> {
  if (Date.now() - state.lastFetched < CACHE_TTL_MS) return;

  const [ptResult, opResult] = await Promise.allSettled([
    fetchPhishTank(_phishTankKey),
    fetchOpenPhish(),
  ]);

  if (ptResult.status === "fulfilled") state.phishtank = ptResult.value;
  if (opResult.status === "fulfilled") state.openphish = opResult.value;
  state.lastFetched = Date.now();
  state.lastPhishTankKey = _phishTankKey;
}

async function fetchPhishTank(apiKey: string | null): Promise<Set<string>> {
  const urls = new Set<string>();
  const endpoint = apiKey
    ? `https://data.phishtank.com/data/${encodeURIComponent(apiKey)}/online-valid.json`
    : "https://data.phishtank.com/data/online-valid.json";
  try {
    const res = await fetch(endpoint, { signal: AbortSignal.timeout(20_000) });
    if (res.status === 429 || res.status === 403 || res.status === 401) {
      // Key invalid or rate-limited — if we used a key, fall back to anonymous
      if (apiKey) {
        logger.warn({ status: res.status }, "PhishTank keyed fetch failed, trying anonymous");
        return fetchPhishTank(null);
      }
      logger.warn({ status: res.status }, "PhishTank anonymous fetch rate-limited");
      return urls;
    }
    if (!res.ok) return urls;
    const data = await res.json() as any[];
    for (const entry of data) {
      if (entry.url) urls.add(normalizeUrl(entry.url as string));
    }
    logger.info(`PhishTank feed loaded: ${urls.size} entries${apiKey ? " (keyed)" : " (anonymous)"}`);
  } catch (e: any) {
    logger.warn(`PhishTank feed fetch failed: ${e.message}`);
  }
  return urls;
}

async function fetchOpenPhish(): Promise<Set<string>> {
  const urls = new Set<string>();
  try {
    const res = await fetch(
      "https://openphish.com/feed.txt",
      { signal: AbortSignal.timeout(10_000) },
    );
    if (!res.ok) return urls;
    const text = await res.text();
    for (const line of text.split("\n")) {
      const u = line.trim();
      if (u) urls.add(normalizeUrl(u));
    }
    logger.info(`OpenPhish feed loaded: ${urls.size} entries`);
  } catch (e: any) {
    logger.warn(`OpenPhish feed fetch failed: ${e.message}`);
  }
  return urls;
}

function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return url.toLowerCase().replace(/^www\./, "").split("/")[0];
  }
}

export interface PhishCheckResult {
  isPhishing: boolean;
  source: string | null;
}

export async function checkPhishingFeed(domain: string): Promise<PhishCheckResult> {
  try {
    await refreshFeeds();
  } catch {
    return { isPhishing: false, source: null };
  }

  const norm = domain.toLowerCase().replace(/^www\./, "");

  if (state.phishtank.has(norm)) return { isPhishing: true, source: "PhishTank" };
  if (state.openphish.has(norm)) return { isPhishing: true, source: "OpenPhish" };

  return { isPhishing: false, source: null };
}

export function getPhishFeedStats() {
  return {
    phishtankCount: state.phishtank.size,
    openphishCount: state.openphish.size,
    lastFetched: state.lastFetched ? new Date(state.lastFetched).toISOString() : null,
    cacheAgeMins: state.lastFetched ? Math.floor((Date.now() - state.lastFetched) / 60_000) : null,
    hasApiKey: !!_phishTankKey,
  };
}
