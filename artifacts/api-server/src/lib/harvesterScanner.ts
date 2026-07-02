import { logger } from "./logger";

const UA = "Mozilla/5.0 (compatible; CTEM-OSINT/1.0)";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface HarvesterEmail {
  email: string;
  source: string;
}

export interface HarvesterHost {
  hostname: string;
  ip?: string;
  source: string;
}

export interface HarvesterResult {
  emails: HarvesterEmail[];
  hosts: HarvesterHost[];
  ips: string[];
  urls: string[];
  stats: {
    emailsFound: number;
    hostsFound: number;
    ipsFound: number;
  };
}

// ── Sources ────────────────────────────────────────────────────────────────────

async function safeFetch(url: string, timeoutMs = 15000): Promise<string | null> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    const res = await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": UA } });
    clearTimeout(t);
    if (!res.ok) return null;
    return res.text();
  } catch { return null; }
}

async function queryHackerTargetHostSearch(domain: string): Promise<HarvesterHost[]> {
  const text = await safeFetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
  if (!text) return [];
  return text.trim().split("\n")
    .filter(l => l.includes(",") && l.includes(domain))
    .map(l => {
      const [hostname, ip] = l.split(",");
      return { hostname: hostname.trim(), ip: ip?.trim(), source: "hackertarget" };
    });
}

async function queryDnsDumpster(domain: string): Promise<HarvesterHost[]> {
  const text = await safeFetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`);
  if (!text) return [];
  return text.trim().split("\n")
    .filter(l => l && !l.includes("error") && !l.includes("API count"))
    .map(l => {
      const parts = l.split(/\s+/);
      const hostname = parts[parts.length - 1];
      return { hostname, source: "dnslookup" };
    })
    .filter(h => h.hostname && h.hostname.includes(domain));
}

async function queryThreatCrowdEmails(domain: string): Promise<HarvesterEmail[]> {
  const text = await safeFetch(`https://api.hackertarget.com/reversedns/?q=${encodeURIComponent(domain)}`);
  if (!text) return [];
  const emailRe = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;
  return [...new Set(text.match(emailRe) ?? [])].map(e => ({ email: e, source: "hackertarget-reverse" }));
}

async function queryEmailsFromCertificates(domain: string): Promise<HarvesterEmail[]> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      signal: ctrl.signal, headers: { "User-Agent": UA },
    });
    clearTimeout(t);
    if (!res.ok) return [];
    const data = await res.json() as Array<{ email?: string; name_value: string }>;
    const emails = new Set<string>();
    for (const e of data) {
      if (e.email?.includes("@")) emails.add(e.email);
    }
    return [...emails].slice(0, 30).map(e => ({ email: e, source: "crt.sh" }));
  } catch { return []; }
}

async function queryHunterIo(domain: string, apiKey: string): Promise<HarvesterEmail[]> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(
      `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${encodeURIComponent(apiKey)}&limit=50`,
      { signal: ctrl.signal, headers: { "User-Agent": UA } }
    );
    clearTimeout(t);
    if (!res.ok) return [];
    const data = await res.json() as any;
    return (data?.data?.emails ?? []).map((e: any) => ({
      email: e.value,
      source: "hunter.io",
    }));
  } catch { return []; }
}

async function queryRapidDns(domain: string): Promise<HarvesterHost[]> {
  const text = await safeFetch(`https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`);
  if (!text) return [];
  const matches = [...text.matchAll(/>\s*([a-z0-9][a-z0-9\-.]*\.[a-z]{2,})\s*</gi)];
  return matches
    .map(m => m[1].toLowerCase().trim())
    .filter(h => h.endsWith(`.${domain}`) || h === domain)
    .map(h => ({ hostname: h, source: "rapiddns" }));
}

async function queryAlienVault(domain: string): Promise<{ hosts: HarvesterHost[]; ips: string[] }> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 15000);
    const res = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`,
      { signal: ctrl.signal, headers: { "User-Agent": UA } }
    );
    clearTimeout(t);
    if (!res.ok) return { hosts: [], ips: [] };
    const data = await res.json() as any;
    const hosts: HarvesterHost[] = [];
    const ips: string[] = [];
    for (const entry of data?.passive_dns ?? []) {
      if (entry.hostname) hosts.push({ hostname: entry.hostname, ip: entry.address, source: "alienvault" });
      if (entry.address && /^\d{1,3}(\.\d{1,3}){3}$/.test(entry.address)) ips.push(entry.address);
    }
    return { hosts, ips };
  } catch { return { hosts: [], ips: [] }; }
}

// ── Main export ────────────────────────────────────────────────────────────────

export async function runHarvesterScan(target: string, hunterApiKey?: string | null): Promise<HarvesterResult> {
  const domain = target.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "").trim();
  logger.info({ domain }, "OSINT harvester scan starting");

  const [htHosts, dnsHosts, certEmails, avResult, rapidHosts, hunterEmails] = await Promise.allSettled([
    queryHackerTargetHostSearch(domain),
    queryDnsDumpster(domain),
    queryEmailsFromCertificates(domain),
    queryAlienVault(domain),
    queryRapidDns(domain),
    hunterApiKey ? queryHunterIo(domain, hunterApiKey) : Promise.resolve<HarvesterEmail[]>([]),
  ]);

  const allHostEntries: HarvesterHost[] = [
    ...(htHosts.status === "fulfilled" ? htHosts.value : []),
    ...(dnsHosts.status === "fulfilled" ? dnsHosts.value : []),
    ...(avResult.status === "fulfilled" ? avResult.value.hosts : []),
    ...(rapidHosts.status === "fulfilled" ? rapidHosts.value : []),
  ];

  const ips = [
    ...(avResult.status === "fulfilled" ? avResult.value.ips : []),
    ...allHostEntries.map(h => h.ip).filter((ip): ip is string => Boolean(ip)),
  ];

  const allEmails: HarvesterEmail[] = [
    ...(certEmails.status === "fulfilled" ? certEmails.value : []),
    ...(hunterEmails.status === "fulfilled" ? hunterEmails.value : []),
  ];

  const deduped = new Map<string, HarvesterHost>();
  for (const h of allHostEntries) {
    const key = h.hostname.toLowerCase();
    if (!deduped.has(key)) deduped.set(key, h);
  }

  const emailDeduped = new Map<string, HarvesterEmail>();
  for (const e of allEmails) {
    const key = e.email.toLowerCase();
    if (!emailDeduped.has(key)) emailDeduped.set(key, e);
  }

  const result: HarvesterResult = {
    emails: [...emailDeduped.values()],
    hosts: [...deduped.values()].filter(h => h.hostname.includes(".")),
    ips: [...new Set(ips)].filter(ip => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)),
    urls: [],
    stats: {
      emailsFound: emailDeduped.size,
      hostsFound: deduped.size,
      ipsFound: new Set(ips).size,
    },
  };

  logger.info({ domain, ...result.stats }, "OSINT harvester scan complete");
  return result;
}
