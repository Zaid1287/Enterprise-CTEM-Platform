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

export async function hibpDomainLookup(domain: string, apiKey: string): Promise<HibpDomainResult | null> {
  if (!apiKey) return null;
  try {
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breaches`,
      {
        headers: {
          "hibp-api-key": apiKey,
          "user-agent": "Sentinelware-CTEM/1.0",
        },
        signal: AbortSignal.timeout(10_000),
      },
    );
    if (!res.ok) {
      logger.warn(`HIBP API error: ${res.status}`);
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
    const res = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`,
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
