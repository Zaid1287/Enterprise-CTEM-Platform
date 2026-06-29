import { logger } from "./logger";

export interface IntelXResult {
  bucket: string;
  type: number;
  name: string;
  date: string;
  preview?: string;
  storageid?: string;
  systemid?: string;
}

interface IntelXSearchResponse {
  id: string;
  status: number;
}

interface IntelXResultsResponse {
  records?: Array<{
    bucket: string;
    type: number;
    name: string;
    date: string;
    storageid?: string;
    systemid?: string;
  }>;
  status: number;
}

const BASE_URL = "https://2.intelx.io";
const DEFAULT_MAX_RESULTS = 20;
const POLL_DELAY_MS = 2000;
const MAX_POLLS = 5;

export async function intelxSearch(
  query: string,
  apiKey: string,
  maxResults = DEFAULT_MAX_RESULTS,
): Promise<IntelXResult[]> {
  if (!apiKey || !query.trim()) return [];

  try {
    const searchRes = await fetch(`${BASE_URL}/intelligent/search`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-key": apiKey,
      },
      body: JSON.stringify({
        term: query,
        maxresults: maxResults,
        media: 0,
        sort: 4,
        terminate: [],
      }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!searchRes.ok) {
      logger.warn({ status: searchRes.status, query }, "IntelX search init failed");
      return [];
    }

    const searchData = (await searchRes.json()) as IntelXSearchResponse;
    const searchId = searchData.id;
    if (!searchId) return [];

    for (let poll = 0; poll < MAX_POLLS; poll++) {
      await new Promise(r => setTimeout(r, POLL_DELAY_MS));

      const resultRes = await fetch(
        `${BASE_URL}/intelligent/search/result?id=${encodeURIComponent(searchId)}&limit=${maxResults}&offset=0`,
        {
          headers: { "x-key": apiKey },
          signal: AbortSignal.timeout(10_000),
        },
      );
      if (!resultRes.ok) continue;

      const resultData = (await resultRes.json()) as IntelXResultsResponse;

      if (resultData.status === 1) {
        // status 1 = search complete — return all available records
        const records = resultData.records ?? [];
        return records.map(r => ({
          bucket: r.bucket,
          type: r.type,
          name: r.name,
          date: r.date,
          storageid: r.storageid,
          systemid: r.systemid,
        }));
      }
      // status 0 = still running — keep polling
    }

    return [];
  } catch (err) {
    logger.warn({ err, query }, "IntelX search error");
    return [];
  }
}

export function intelxTypeToBucket(type: number): string {
  const map: Record<number, string> = {
    0: "pastes",
    1: "darkweb",
    2: "documents",
    3: "leaks",
    4: "linkedin",
    5: "twitter",
    6: "reddit",
    7: "forum",
    8: "email",
    9: "credential",
  };
  return map[type] ?? "unknown";
}
