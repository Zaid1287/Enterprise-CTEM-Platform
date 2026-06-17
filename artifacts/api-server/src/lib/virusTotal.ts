export interface VirusTotalResult {
  target: string;
  targetType: "domain" | "ip";
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  reputation: number;
  categories: string[];
  registrar?: string;
  lastAnalysisDate?: string;
}

async function vtFetch(url: string, apiKey: string): Promise<any> {
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), 12000);
  const res = await fetch(url, {
    headers: { "x-apikey": apiKey, "Accept": "application/json" },
    signal: ctrl.signal,
  });
  if (res.status === 404) return null;
  if (res.status === 401) throw new Error("VirusTotal: invalid API key");
  if (res.status === 429) throw new Error("VirusTotal: rate limit exceeded");
  if (!res.ok) throw new Error(`VirusTotal API error: HTTP ${res.status}`);
  return res.json();
}

export async function getVirusTotalDomain(domain: string, apiKey: string): Promise<VirusTotalResult | null> {
  try {
    const data = await vtFetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
      apiKey,
    );
    if (!data?.data?.attributes) return null;
    const a = data.data.attributes;
    const stats = a.last_analysis_stats ?? {};
    return {
      target: domain,
      targetType: "domain",
      malicious:  stats.malicious  ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless:   stats.harmless   ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: a.reputation ?? 0,
      categories: Object.values(a.categories ?? {}) as string[],
      registrar:  a.registrar ?? undefined,
      lastAnalysisDate: a.last_analysis_date
        ? new Date(a.last_analysis_date * 1000).toISOString()
        : undefined,
    };
  } catch {
    return null;
  }
}

export async function getVirusTotalIp(ip: string, apiKey: string): Promise<VirusTotalResult | null> {
  try {
    const data = await vtFetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${ip}`,
      apiKey,
    );
    if (!data?.data?.attributes) return null;
    const a = data.data.attributes;
    const stats = a.last_analysis_stats ?? {};
    return {
      target: ip,
      targetType: "ip",
      malicious:  stats.malicious  ?? 0,
      suspicious: stats.suspicious ?? 0,
      harmless:   stats.harmless   ?? 0,
      undetected: stats.undetected ?? 0,
      reputation: a.reputation ?? 0,
      categories: [],
      lastAnalysisDate: a.last_analysis_date
        ? new Date(a.last_analysis_date * 1000).toISOString()
        : undefined,
    };
  } catch {
    return null;
  }
}
