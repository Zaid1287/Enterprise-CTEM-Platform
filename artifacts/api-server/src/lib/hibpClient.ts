import { logger } from "./logger";

export interface HibpBreach {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  modifiedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isSensitive: boolean;
  isFabricated: boolean;
  isSpamList: boolean;
  logoPath: string;
}

export interface HibpDomainResult {
  breaches: HibpBreach[];
  totalPwnedAccounts: number;
}

const HIBP_BASE = "https://haveibeenpwned.com";
const HIBP_DELAY_MS = 1500;

export async function hibpDomainLookup(domain: string, apiKey?: string): Promise<HibpDomainResult | null> {
  try {
    // When API key is present: use the domain-specific endpoint
    if (apiKey) {
      await new Promise(r => setTimeout(r, HIBP_DELAY_MS));
      const res = await fetch(
        `${HIBP_BASE}/api/v3/breacheddomain/${encodeURIComponent(domain)}`,
        {
          headers: {
            "hibp-api-key": apiKey,
            "user-agent": "Sentinelware-CTEM/1.0",
          },
          signal: AbortSignal.timeout(12_000),
        },
      );
      if (res.status === 404) {
        // 404 means no breaches found for this domain
        return { breaches: [], totalPwnedAccounts: 0 };
      }
      if (!res.ok) {
        logger.warn(`HIBP breacheddomain API error: ${res.status} for ${domain}`);
        return null;
      }
      // Response is { email: string[] } mapping emails to breach names
      const emailBreachMap = await res.json() as Record<string, string[]>;
      const emailCount = Object.keys(emailBreachMap).length;
      const allBreachNames = [...new Set(Object.values(emailBreachMap).flat())];
      // Fetch details for each unique breach name (rate-limited)
      const breaches: HibpBreach[] = [];
      for (const breachName of allBreachNames.slice(0, 20)) {
        await new Promise(r => setTimeout(r, HIBP_DELAY_MS));
        try {
          const bRes = await fetch(
            `${HIBP_BASE}/api/v3/breach/${encodeURIComponent(breachName)}`,
            {
              headers: {
                "hibp-api-key": apiKey,
                "user-agent": "Sentinelware-CTEM/1.0",
              },
              signal: AbortSignal.timeout(10_000),
            },
          );
          if (bRes.ok) {
            const b = await bRes.json() as HibpBreach;
            breaches.push(b);
          }
        } catch {
          // individual breach fetch failure is non-fatal
        }
      }
      return { breaches, totalPwnedAccounts: emailCount };
    }

    // Without API key: fetch public breach list and filter by domain match
    const res = await fetch(
      `${HIBP_BASE}/api/v3/breaches`,
      {
        headers: { "user-agent": "Sentinelware-CTEM/1.0" },
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!res.ok) {
      logger.warn(`HIBP public breaches API error: ${res.status}`);
      return null;
    }
    const all = await res.json() as HibpBreach[];
    const domainBreaches = all.filter((b: HibpBreach) =>
      b.domain && (b.domain === domain || b.domain.endsWith(`.${domain}`))
    );
    const totalPwned = domainBreaches.reduce((s, b) => s + (b.pwnCount ?? 0), 0);
    return { breaches: domainBreaches, totalPwnedAccounts: totalPwned };
  } catch (e: any) {
    logger.warn(`HIBP lookup failed for ${domain}: ${e.message}`);
    return null;
  }
}

export async function hibpEmailLookup(email: string, apiKey: string): Promise<HibpBreach[] | null> {
  if (!apiKey) return null;
  try {
    await new Promise(r => setTimeout(r, HIBP_DELAY_MS));
    const res = await fetch(
      `${HIBP_BASE}/api/v3/breachedaccount/${encodeURIComponent(email)}`,
      {
        headers: {
          "hibp-api-key": apiKey,
          "user-agent": "Sentinelware-CTEM/1.0",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (res.status === 404) return [];
    if (!res.ok) return null;
    return await res.json() as HibpBreach[];
  } catch (e: any) {
    logger.warn(`HIBP email lookup failed for ${email}: ${e.message}`);
    return null;
  }
}

export function severityFromBreach(breach: HibpBreach): string {
  if (breach.pwnCount > 1_000_000 || breach.isSensitive) return "critical";
  if (breach.pwnCount > 100_000) return "high";
  if (breach.pwnCount > 10_000) return "medium";
  return "low";
}
