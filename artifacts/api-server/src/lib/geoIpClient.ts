export interface GeoIpResult {
  country: string | null;
  countryCode: string | null;
  city: string | null;
  asn: string | null;
  org: string | null;
  isp: string | null;
}

const ipApiBase = "http://ip-api.com/batch";

export async function geoIpBatch(ips: string[]): Promise<Map<string, GeoIpResult>> {
  const results = new Map<string, GeoIpResult>();
  if (!ips.length) return results;

  const chunks: string[][] = [];
  for (let i = 0; i < ips.length; i += 100) chunks.push(ips.slice(i, i + 100));

  for (const chunk of chunks) {
    try {
      const res = await fetch(`${ipApiBase}?fields=status,message,country,countryCode,city,as,org,isp,query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(chunk),
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) continue;
      const data = await res.json() as any[];
      for (const item of data) {
        if (item.status !== "success") continue;
        results.set(item.query as string, {
          country: item.country ?? null,
          countryCode: item.countryCode ?? null,
          city: item.city ?? null,
          asn: item.as ?? null,
          org: item.org ?? null,
          isp: item.isp ?? null,
        });
      }
    } catch {
      // silently skip
    }
    if (chunks.length > 1) await new Promise(r => setTimeout(r, 200));
  }
  return results;
}

export async function geoIpSingle(ip: string): Promise<GeoIpResult | null> {
  const map = await geoIpBatch([ip]);
  return map.get(ip) ?? null;
}
