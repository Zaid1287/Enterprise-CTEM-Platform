export interface RdapResult {
  registrar: string | null;
  registrantCountry: string | null;
  registrantOrg: string | null;
  createdDate: string | null;
  expiresDate: string | null;
  updatedDate: string | null;
  abuseContact: string | null;
  ageDays: number | null;
  nameservers: string[];
  status: string[];
}

const RDAP_BOOTSTRAP = "https://rdap.org/domain/";

function extractDate(events: any[], eventAction: string): string | null {
  if (!Array.isArray(events)) return null;
  const ev = events.find((e: any) => e.eventAction === eventAction);
  return ev?.eventDate ?? null;
}

function ageDays(dateStr: string | null): number | null {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / 86_400_000);
}

export async function rdapLookup(domain: string): Promise<RdapResult | null> {
  try {
    const res = await fetch(`${RDAP_BOOTSTRAP}${domain}`, {
      signal: AbortSignal.timeout(8000),
      headers: { "Accept": "application/json" },
    });
    if (!res.ok) return null;
    const data = await res.json() as any;

    const nameservers: string[] = (data.nameservers ?? [])
      .map((ns: any) => (ns.ldhName ?? "").toLowerCase())
      .filter(Boolean);

    const status: string[] = Array.isArray(data.status) ? data.status : [];

    let registrar: string | null = null;
    let registrantCountry: string | null = null;
    let registrantOrg: string | null = null;
    let abuseContact: string | null = null;

    for (const entity of (data.entities ?? []) as any[]) {
      const roles: string[] = entity.roles ?? [];
      if (roles.includes("registrar")) {
        registrar = entity.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3]
          ?? entity.handle ?? null;
        const contacts: any[] = (entity.entities ?? []) as any[];
        for (const c of contacts) {
          if ((c.roles ?? []).includes("abuse")) {
            abuseContact = c.vcardArray?.[1]?.find((v: any) => v[0] === "email")?.[3] ?? null;
          }
        }
      }
      if (roles.includes("registrant")) {
        registrantOrg = entity.vcardArray?.[1]?.find((v: any) => v[0] === "fn")?.[3] ?? null;
        const adr = entity.vcardArray?.[1]?.find((v: any) => v[0] === "adr");
        if (adr) {
          const params = adr[1] ?? {};
          registrantCountry = params["country-name"] ?? null;
          if (!registrantCountry && Array.isArray(adr[3])) {
            registrantCountry = adr[3][6] ?? null;
          }
        }
      }
    }

    const createdDate = extractDate(data.events, "registration");
    const expiresDate = extractDate(data.events, "expiration");
    const updatedDate = extractDate(data.events, "last changed");

    return {
      registrar,
      registrantCountry,
      registrantOrg,
      createdDate,
      expiresDate,
      updatedDate,
      abuseContact,
      ageDays: ageDays(createdDate),
      nameservers,
      status,
    };
  } catch {
    return null;
  }
}
