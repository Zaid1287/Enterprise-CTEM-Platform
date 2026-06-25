export interface SafeBrowsingResult {
  isFlagged: boolean;
  threatType: string | null;
  platformType: string | null;
}

export async function checkGoogleSafeBrowsing(
  urls: string[],
  apiKey: string,
): Promise<Map<string, SafeBrowsingResult>> {
  const results = new Map<string, SafeBrowsingResult>();
  if (!urls.length || !apiKey) return results;

  const chunks: string[][] = [];
  for (let i = 0; i < urls.length; i += 500) chunks.push(urls.slice(i, i + 500));

  for (const chunk of chunks) {
    try {
      const body = {
        client: { clientId: "sentinelware-ctem", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: chunk.map(url => ({ url })),
        },
      };

      const res = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(10_000),
        },
      );

      if (!res.ok) continue;
      const data = await res.json() as any;

      for (const match of (data.matches ?? []) as any[]) {
        const url = match.threat?.url as string | undefined;
        if (!url) continue;
        results.set(url, {
          isFlagged: true,
          threatType: match.threatType ?? null,
          platformType: match.platformType ?? null,
        });
      }
    } catch {
      // silently skip
    }
  }

  return results;
}
