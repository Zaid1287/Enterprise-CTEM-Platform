export interface HunterEmail {
  email: string;
  firstName?: string;
  lastName?: string;
  position?: string;
  department?: string;
  confidence: number;
  type: "personal" | "generic";
}

export interface HunterDomainResult {
  domain: string;
  organization?: string;
  pattern?: string;
  totalCount: number;
  emails: HunterEmail[];
}

export async function hunterDomainSearch(
  domain: string,
  apiKey: string,
  limit = 100,
): Promise<HunterDomainResult | null> {
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 12000);
    const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${apiKey}&limit=${limit}`;
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { "Accept": "application/json" },
    });
    if (res.status === 401) throw new Error("Hunter.io: invalid API key");
    if (res.status === 429) throw new Error("Hunter.io: rate limit exceeded");
    if (!res.ok) return null;
    const data = await res.json() as any;
    const d = data?.data;
    if (!d) return null;
    return {
      domain: d.domain ?? domain,
      organization: d.organization ?? undefined,
      pattern: d.pattern ?? undefined,
      totalCount: d.emails?.length ?? 0,
      emails: (d.emails ?? []).map((e: any): HunterEmail => ({
        email:      e.value,
        firstName:  e.first_name  ?? undefined,
        lastName:   e.last_name   ?? undefined,
        position:   e.position    ?? undefined,
        department: e.department  ?? undefined,
        confidence: e.confidence  ?? 0,
        type:       e.type === "personal" ? "personal" : "generic",
      })),
    };
  } catch {
    return null;
  }
}
