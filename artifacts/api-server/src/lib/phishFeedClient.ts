import { logger } from "./logger";

interface PhishFeedState {
  phishtank: Set<string>;
  openphish: Set<string>;
  lastFetched: number;
}

const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const state: PhishFeedState = {
  phishtank: new Set(),
  openphish: new Set(),
  lastFetched: 0,
};

async function refreshFeeds(): Promise<void> {
  if (Date.now() - state.lastFetched < CACHE_TTL_MS) return;

  const [ptResult, opResult] = await Promise.allSettled([
    fetchPhishTank(),
    fetchOpenPhish(),
  ]);

  if (ptResult.status === "fulfilled") state.phishtank = ptResult.value;
  if (opResult.status === "fulfilled") state.openphish = opResult.value;
  state.lastFetched = Date.now();
}

async function fetchPhishTank(): Promise<Set<string>> {
  const urls = new Set<string>();
  try {
    const res = await fetch(
      "https://data.phishtank.com/data/online-valid.json",
      { signal: AbortSignal.timeout(15_000) },
    );
    if (!res.ok) return urls;
    const data = await res.json() as any[];
    for (const entry of data) {
      if (entry.url) urls.add(normalizeUrl(entry.url as string));
    }
    logger.info(`PhishTank feed loaded: ${urls.size} entries`);
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
  };
}
