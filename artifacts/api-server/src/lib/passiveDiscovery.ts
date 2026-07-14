import dns from "node:dns/promises";
import { logger } from "./logger";
import { orchestratedFetch, orchestratedDnsResolve } from "./scanOrchestrator";

const UA = "Sentinelware-CTEM/1.0";
const timeout = (ms: number) => AbortSignal.timeout(ms);

export type DiscoveryStatus = "ok" | "skipped" | "error";

export interface DiscoveryModuleResult {
  source: string;
  status: DiscoveryStatus;
  data: Record<string, unknown> | null;
  summary: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function extractDomain(target: string): string {
  try {
    const url = target.startsWith("http") ? new URL(target) : new URL(`https://${target}`);
    return url.hostname.replace(/^www\./, "");
  } catch { return target.replace(/^www\./, "").split("/")[0]; }
}

function extractCompany(domain: string): string {
  return domain.split(".")[0].toLowerCase().replace(/[^a-z0-9-]/g, "");
}

async function safeFetch(url: string, opts: RequestInit & { timeoutMs?: number } = {}): Promise<Response | null> {
  const { timeoutMs: _timeoutMs, ...rest } = opts;
  try {
    const res = await orchestratedFetch(url, { ...rest, headers: { "User-Agent": UA, ...(rest.headers ?? {}) } }, { intensity: "passive" });
    return res;
  } catch {
    return null;
  }
}

// ── 1. CT Logs (crt.sh) ───────────────────────────────────────────────────────
// No API key required. Free public API.

export async function runCtLogs(target: string): Promise<DiscoveryModuleResult> {
  const domain = extractDomain(target);
  const source = "ct_logs";
  try {
    const res = await safeFetch(`https://crt.sh/?q=%.${domain}&output=json`, { timeoutMs: 15000 });
    if (!res || !res.ok) return { source, status: "error", data: null, summary: "crt.sh unreachable" };
    const raw: Array<{ name_value: string; issuer_name: string; not_before: string; not_after: string; id: number }> = await res.json().catch(() => []) as any;

    const seen = new Set<string>();
    const certs: Array<{ name: string; issuer: string; notBefore: string; notAfter: string }> = [];
    for (const row of raw) {
      const names = row.name_value.split("\n").map(n => n.trim().toLowerCase()).filter(n => n.endsWith(`.${domain}`) || n === domain);
      for (const name of names) {
        if (!seen.has(name)) {
          seen.add(name);
          certs.push({ name, issuer: row.issuer_name?.split("O=")[1]?.split(",")[0] ?? "Unknown", notBefore: row.not_before, notAfter: row.not_after });
        }
      }
    }

    const uniqueNames = [...seen];
    return {
      source,
      status: "ok",
      data: { domain, totalCertRecords: raw.length, uniqueNames, certs: certs.slice(0, 200) },
      summary: `${uniqueNames.length} unique subdomains from ${raw.length} CT log entries`,
    };
  } catch (err) {
    logger.error({ err }, "CT Logs error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 2. Reverse WHOIS (HackerTarget) ──────────────────────────────────────────
// Free tier: 20 req/day unauthenticated. No API key needed for basic use.

export async function runReverseWhois(target: string): Promise<DiscoveryModuleResult> {
  const domain = extractDomain(target);
  const company = extractCompany(domain);
  const source = "reverse_whois";
  try {
    const [byDomain, byCompany] = await Promise.all([
      safeFetch(`https://api.hackertarget.com/reversewhois/?q=${encodeURIComponent(domain)}`, { timeoutMs: 12000 }),
      company.length >= 3
        ? safeFetch(`https://api.hackertarget.com/reversewhois/?q=${encodeURIComponent(company)}`, { timeoutMs: 12000 })
        : Promise.resolve(null),
    ]);

    const domainText = byDomain?.ok ? (await byDomain.text().catch(() => "")) : "";
    const companyText = byCompany?.ok ? (await (byCompany as Response).text().catch(() => "")) : "";

    const parseLines = (t: string) => t.split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("error") && !l.startsWith("No") && l.includes(".")).slice(0, 100);
    const byDomainDomains = parseLines(domainText);
    const byCompanyDomains = parseLines(companyText);
    const allDomains = [...new Set([...byDomainDomains, ...byCompanyDomains])];

    if (allDomains.length === 0 && (domainText.includes("error") || domainText.includes("No results"))) {
      return { source, status: "ok", data: { domain, company, domains: [] }, summary: "No reverse WHOIS matches found" };
    }

    return {
      source,
      status: "ok",
      data: { domain, company, byDomain: byDomainDomains, byCompany: byCompanyDomains, allDomains },
      summary: `${allDomains.length} related domains found via reverse WHOIS`,
    };
  } catch (err) {
    logger.error({ err }, "Reverse WHOIS error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 3. ASN Lookup (BGPView + HackerTarget) ────────────────────────────────────
// Free APIs, no API key required.

export interface AsnRecord {
  asn: number;
  name: string;
  description: string;
  countryCode: string;
  prefixes: string[];
}

export async function runAsnLookup(target: string): Promise<DiscoveryModuleResult> {
  const domain = extractDomain(target);
  const source = "asn_lookup";
  try {
    // Step 1: Resolve the domain to IPs
    const ips: string[] = [];
    try {
      const [a4, a6] = await Promise.allSettled([orchestratedDnsResolve(domain), dns.resolve6(domain)]);
      if (a4.status === "fulfilled") ips.push(...a4.value.slice(0, 3));
      if (a6.status === "fulfilled") ips.push(...a6.value.slice(0, 2));
    } catch { /* ignore */ }

    // Step 2: BGPView search for ASN by domain/org
    const bgpRes = await safeFetch(`https://api.bgpview.io/search?query_term=${encodeURIComponent(domain)}`, { timeoutMs: 10000 });
    const bgpData: any = bgpRes?.ok ? await bgpRes.json().catch(() => null) : null;

    const asnRecords: AsnRecord[] = [];
    if (bgpData?.data?.asns) {
      for (const asn of bgpData.data.asns.slice(0, 10)) {
        asnRecords.push({
          asn: asn.asn, name: asn.name ?? "", description: asn.description ?? "",
          countryCode: asn.country_code ?? "", prefixes: [],
        });
      }
    }

    // Step 3: For each resolved IP, get ASN via ip-api.com (free)
    const ipAsnMap: Record<string, { asn: string; org: string; isp: string; country: string; city: string }> = {};
    await Promise.allSettled(ips.map(async ip => {
      const r = await safeFetch(`http://ip-api.com/json/${ip}?fields=status,countryCode,city,org,isp,as`, { timeoutMs: 6000 });
      if (r?.ok) {
        const d: any = await r.json().catch(() => null);
        if (d?.status === "success") ipAsnMap[ip] = { asn: d.as ?? "", org: d.org ?? "", isp: d.isp ?? "", country: d.countryCode ?? "", city: d.city ?? "" };
      }
    }));

    // Step 4: HackerTarget AS lookup for IP
    const htAsns: string[] = [];
    for (const ip of ips.slice(0, 2)) {
      const r = await safeFetch(`https://api.hackertarget.com/aslookup/?q=${ip}`, { timeoutMs: 8000 });
      if (r?.ok) { const t = await r.text().catch(() => ""); if (t && !t.startsWith("error")) htAsns.push(t.trim()); }
    }

    return {
      source,
      status: "ok",
      data: { domain, resolvedIps: ips, ipAsnInfo: ipAsnMap, bgpViewAsns: asnRecords, hackerTargetAsns: htAsns },
      summary: `${ips.length} IPs resolved; ${Object.keys(ipAsnMap).length} ASN records found`,
    };
  } catch (err) {
    logger.error({ err }, "ASN Lookup error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 4. DKIM Check (DNS TXT) ───────────────────────────────────────────────────
// Checks common DKIM selectors for the domain. No API key required.

const COMMON_DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
  "smtp", "mail", "dkim", "dkim1", "m1", "mxe", "mailchimp", "sendgrid",
  "key1", "key2", "zoho", "mandrill", "sparkpost", "protonmail", "pm", "mx",
];

export interface DkimRecord {
  selector: string;
  record: string;
  keyType?: string;
  version?: string;
}

export async function runDkimCheck(target: string): Promise<DiscoveryModuleResult> {
  const domain = extractDomain(target);
  const source = "dkim_check";

  if (!domain || domain.includes("/")) {
    return { source, status: "skipped", data: null, summary: "DKIM check requires a domain target" };
  }

  try {
    const results = await Promise.allSettled(
      COMMON_DKIM_SELECTORS.map(async sel => {
        const records = await dns.resolveTxt(`${sel}._domainkey.${domain}`).catch(() => null);
        if (!records) return null;
        const joined = records.map(r => r.join("")).join("");
        if (!joined.includes("v=DKIM")) return null;
        return {
          selector: sel,
          record: joined.slice(0, 500),
          keyType: joined.match(/k=([a-z0-9]+)/i)?.[1],
          version: joined.match(/v=([^;]+)/i)?.[1],
        };
      })
    );

    const found: DkimRecord[] = results
      .filter(r => r.status === "fulfilled" && r.value !== null)
      .map(r => (r as PromiseFulfilledResult<DkimRecord>).value);

    // Also get SPF + DMARC for completeness
    const [spfRaw, dmarcRaw] = await Promise.allSettled([
      dns.resolveTxt(domain).then(rs => rs.flat().find(r => r.startsWith("v=spf1")) ?? null),
      dns.resolveTxt(`_dmarc.${domain}`).then(rs => rs.flat().join("")).catch(() => null),
    ]);

    const spf = spfRaw.status === "fulfilled" ? spfRaw.value : null;
    const dmarc = dmarcRaw.status === "fulfilled" ? dmarcRaw.value : null;

    return {
      source,
      status: "ok",
      data: {
        domain,
        dkimSelectors: found,
        selectorsChecked: COMMON_DKIM_SELECTORS,
        spf: spf ?? null,
        dmarc: dmarc ?? null,
        hasDkim: found.length > 0,
        hasSpf: !!spf,
        hasDmarc: !!dmarc,
      },
      summary: `${found.length} DKIM selectors found; SPF: ${!!spf}; DMARC: ${!!dmarc}`,
    };
  } catch (err) {
    logger.error({ err }, "DKIM check error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 5. GitHub Exposure ────────────────────────────────────────────────────────
// Uses GitHub Search API. Rate limit: 10/min unauth, 30/min with token.

export async function runGithubExposure(target: string, githubToken?: string | null): Promise<DiscoveryModuleResult> {
  const domain = extractDomain(target);
  const company = extractCompany(domain);
  const source = "github_exposure";

  const headers: Record<string, string> = {
    "User-Agent": UA,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (githubToken) headers.Authorization = `Bearer ${githubToken}`;

  const ghFetch = async (path: string) => {
    const res = await safeFetch(`https://api.github.com${path}`, { headers, timeoutMs: 12000 });
    if (!res?.ok) return null;
    return res.json().catch(() => null);
  };

  try {
    // Search for the domain in public GitHub code
    const [codeSearch, repoSearch] = await Promise.allSettled([
      ghFetch(`/search/code?q=${encodeURIComponent(domain)}&per_page=10`),
      ghFetch(`/search/repositories?q=${encodeURIComponent(domain)}+in:name,description&per_page=10&sort=stars`),
    ]);

    const codeItems: Array<{ name: string; path: string; url: string; repo: string }> = [];
    if (codeSearch.status === "fulfilled" && (codeSearch.value as any)?.items) {
      for (const item of (codeSearch.value as any).items.slice(0, 10)) {
        codeItems.push({ name: item.name, path: item.path, url: item.html_url, repo: item.repository?.full_name ?? "" });
      }
    }

    const repos: Array<{ name: string; stars: number; url: string; description: string; language: string }> = [];
    if (repoSearch.status === "fulfilled" && (repoSearch.value as any)?.items) {
      for (const item of (repoSearch.value as any).items.slice(0, 10)) {
        repos.push({ name: item.full_name, stars: item.stargazers_count, url: item.html_url, description: item.description ?? "", language: item.language ?? "" });
      }
    }

    // Try to find org/user with company name
    const orgData: any = await ghFetch(`/orgs/${company}`).catch(() => null) ?? await ghFetch(`/users/${company}`).catch(() => null);
    const orgInfo = orgData ? { login: orgData.login, name: orgData.name, url: orgData.html_url, publicRepos: orgData.public_repos, type: orgData.type } : null;

    const totalExposures = codeItems.length + repos.length;
    return {
      source,
      status: "ok",
      data: {
        domain, company,
        codeReferences: codeItems,
        relatedRepos: repos,
        orgInfo,
        authenticated: !!githubToken,
        totalExposures,
      },
      summary: `${codeItems.length} code references, ${repos.length} repos, org: ${orgInfo ? orgInfo.login : "not found"}`,
    };
  } catch (err) {
    logger.error({ err }, "GitHub exposure error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 6. Shodan (Full API — key required) ───────────────────────────────────────

export async function runShodanSearch(target: string, apiKey: string | null): Promise<DiscoveryModuleResult> {
  const source = "shodan";
  if (!apiKey) return { source, status: "skipped", data: null, summary: "Shodan API key not configured" };

  const domain = extractDomain(target);
  try {
    // Resolve IPs first
    const ips: string[] = [];
    try { ips.push(...(await orchestratedDnsResolve(domain)).slice(0, 3)); } catch { /* ignore */ }

    const hostResults: unknown[] = [];
    for (const ip of ips.slice(0, 3)) {
      const res = await safeFetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, { timeoutMs: 10000 });
      if (res?.ok) {
        const d: any = await res.json().catch(() => null);
        if (d) hostResults.push({ ip, ports: d.ports ?? [], vulns: Object.keys(d.vulns ?? {}), os: d.os, org: d.org, tags: d.tags ?? [], hostnames: d.hostnames ?? [], country: d.country_name });
      }
    }

    // Domain search
    const domainRes = await safeFetch(`https://api.shodan.io/dns/domain/${domain}?key=${apiKey}`, { timeoutMs: 10000 });
    const domainData: any = domainRes?.ok ? await domainRes.json().catch(() => null) : null;

    return {
      source,
      status: "ok",
      data: { domain, hostData: hostResults, domainInfo: domainData },
      summary: `${hostResults.length} IPs scanned via Shodan Full API`,
    };
  } catch (err) {
    logger.error({ err }, "Shodan search error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 7. Fofa Search (API key + email required) ─────────────────────────────────

export async function runFofaSearch(target: string, email: string | null, apiKey: string | null): Promise<DiscoveryModuleResult> {
  const source = "fofa";
  if (!email || !apiKey) return { source, status: "skipped", data: null, summary: "Fofa email + API key not configured" };

  const domain = extractDomain(target);
  const query = `domain="${domain}"`;
  const qbase64 = Buffer.from(query).toString("base64");
  const url = `https://fofa.info/api/v1/search/all?email=${encodeURIComponent(email)}&key=${apiKey}&qbase64=${qbase64}&fields=host,ip,port,title,country,server,protocol&size=100`;

  try {
    const res = await safeFetch(url, { timeoutMs: 15000 });
    if (!res?.ok) return { source, status: "error", data: null, summary: `Fofa API returned ${res?.status ?? "no response"}` };
    const data: any = await res.json().catch(() => null);
    if (data?.error) return { source, status: "error", data: null, summary: `Fofa: ${data.errmsg ?? data.error}` };

    const results: Array<Record<string, string>> = [];
    if (Array.isArray(data?.results)) {
      const fields = ["host", "ip", "port", "title", "country", "server", "protocol"];
      for (const row of data.results.slice(0, 100)) {
        const obj: Record<string, string> = {};
        fields.forEach((f, i) => { obj[f] = row[i] ?? ""; });
        results.push(obj);
      }
    }

    return {
      source,
      status: "ok",
      data: { domain, query, total: data?.size ?? results.length, results },
      summary: `${results.length} Fofa results for domain "${domain}"`,
    };
  } catch (err) {
    logger.error({ err }, "Fofa search error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 8. Censys Search (API ID + Secret required) ───────────────────────────────

export async function runCensysSearch(target: string, apiId: string | null, apiSecret: string | null): Promise<DiscoveryModuleResult> {
  const source = "censys";
  if (!apiId || !apiSecret) return { source, status: "skipped", data: null, summary: "Censys API ID + secret not configured" };

  const domain = extractDomain(target);
  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString("base64");
  const query = `services.tls.certificates.leaf_data.names: ${domain} or dns.reverse_dns.reverse_dns_name: ${domain}`;

  try {
    const res = await safeFetch(`https://search.censys.io/api/v2/hosts/search?q=${encodeURIComponent(query)}&per_page=50`, {
      timeoutMs: 15000,
      headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" },
    });
    if (!res?.ok) {
      const errText = (await res?.text().catch(() => "")) ?? "";
      return { source, status: "error", data: null, summary: `Censys API ${res?.status}: ${errText.slice(0, 200)}` };
    }
    const data: any = await res.json().catch(() => null);

    const hits: Array<{ ip: string; services: unknown[]; location?: unknown; autonomous_system?: unknown }> = data?.result?.hits ?? [];
    const results = hits.slice(0, 50).map(h => ({
      ip: h.ip,
      services: Array.isArray(h.services) ? h.services.map((s: any) => ({ port: s.port, name: s.service_name, transport: s.transport_protocol })) : [],
      country: (h.location as any)?.country ?? "",
      asn: (h.autonomous_system as any)?.asn ?? "",
      org: (h.autonomous_system as any)?.name ?? "",
    }));

    return {
      source,
      status: "ok",
      data: { domain, query, total: data?.result?.total?.value ?? results.length, results },
      summary: `${results.length} hosts found via Censys`,
    };
  } catch (err) {
    logger.error({ err }, "Censys search error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 9. IntelX Search (API key required) ──────────────────────────────────────

export async function runIntelxSearch(target: string, apiKey: string | null): Promise<DiscoveryModuleResult> {
  const source = "intelx";
  if (!apiKey) return { source, status: "skipped", data: null, summary: "IntelX API key not configured" };

  const domain = extractDomain(target);
  try {
    // Step 1: Submit search
    const searchRes = await safeFetch("https://2.intelx.io/intelligent/search", {
      method: "POST",
      timeoutMs: 12000,
      headers: { "x-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ term: domain, buckets: [], lookuplevel: 0, maxresults: 50, timeout: 0, datefrom: "", dateto: "", sort: 4, media: 0, terminate: [] }),
    });
    if (!searchRes?.ok) return { source, status: "error", data: null, summary: `IntelX search failed: ${searchRes?.status}` };
    const searchData: any = await searchRes.json().catch(() => null);
    const searchId = searchData?.id;
    if (!searchId) return { source, status: "error", data: null, summary: "IntelX: no search ID returned" };

    // Step 2: Wait and fetch results (IntelX is async)
    await new Promise(r => setTimeout(r, 2000));
    const resultsRes = await safeFetch(`https://2.intelx.io/intelligent/search/result?id=${searchId}&limit=50&offset=0`, {
      timeoutMs: 12000,
      headers: { "x-key": apiKey },
    });
    if (!resultsRes?.ok) return { source, status: "error", data: null, summary: `IntelX results failed: ${resultsRes?.status}` };
    const resultsData: any = await resultsRes.json().catch(() => null);

    const records = (resultsData?.records ?? []).slice(0, 50).map((r: any) => ({
      name: r.name ?? "",
      date: r.date ?? "",
      type: r.type ?? 0,
      media: r.media ?? 0,
      storageid: r.storageid ?? "",
      bucket: r.bucket ?? "",
    }));

    return {
      source,
      status: "ok",
      data: { domain, searchId, totalFound: resultsData?.records?.length ?? 0, records },
      summary: `${records.length} IntelX records found for "${domain}"`,
    };
  } catch (err) {
    logger.error({ err }, "IntelX search error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── 10. CriminalIP Search (API key required) ──────────────────────────────────

export async function runCriminalIpSearch(target: string, apiKey: string | null): Promise<DiscoveryModuleResult> {
  const source = "criminalip";
  if (!apiKey) return { source, status: "skipped", data: null, summary: "CriminalIP API key not configured" };

  const domain = extractDomain(target);
  try {
    const [domainRes, scanRes] = await Promise.allSettled([
      safeFetch(`https://api.criminalip.io/v1/domain/report?query=${encodeURIComponent(domain)}`, {
        timeoutMs: 15000,
        headers: { "x-api-key": apiKey },
      }),
      safeFetch(`https://api.criminalip.io/v1/domain/scan`, {
        method: "POST",
        timeoutMs: 15000,
        headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
        body: JSON.stringify({ query: domain }),
      }),
    ]);

    const domainData: any = domainRes.status === "fulfilled" && domainRes.value?.ok
      ? await domainRes.value.json().catch(() => null)
      : null;

    const scanData: any = scanRes.status === "fulfilled" && scanRes.value?.ok
      ? await scanRes.value.json().catch(() => null)
      : null;

    if (!domainData && !scanData) {
      return { source, status: "error", data: null, summary: "CriminalIP API returned no data" };
    }

    const summary_parts: string[] = [];
    if (domainData?.data?.summary) summary_parts.push(`Score: ${domainData.data.summary.score ?? "?"}`);
    if (domainData?.data?.ip_count) summary_parts.push(`${domainData.data.ip_count} IPs`);

    return {
      source,
      status: "ok",
      data: { domain, report: domainData?.data ?? null, scan: scanData?.data ?? null },
      summary: summary_parts.length ? summary_parts.join("; ") : `CriminalIP data collected for ${domain}`,
    };
  } catch (err) {
    logger.error({ err }, "CriminalIP search error");
    return { source, status: "error", data: null, summary: String(err) };
  }
}

// ── Run all passive discovery modules ─────────────────────────────────────────

export interface PassiveDiscoveryOptions {
  githubToken?: string | null;
  shodanApiKey?: string | null;
  fofaEmail?: string | null;
  fofaApiKey?: string | null;
  censysApiId?: string | null;
  censysApiSecret?: string | null;
  intelxApiKey?: string | null;
  criminalIpApiKey?: string | null;
  securityTrailsApiKey?: string | null;
  modules?: string[];  // if set, only run these modules
}

export async function runPassiveDiscovery(
  target: string,
  opts: PassiveDiscoveryOptions = {},
): Promise<DiscoveryModuleResult[]> {
  const requested = opts.modules ?? ["ct_logs", "reverse_whois", "asn_lookup", "dkim_check", "github_exposure", "shodan", "fofa", "censys", "intelx", "criminalip"];
  const want = (name: string) => requested.includes(name);

  const tasks: Promise<DiscoveryModuleResult>[] = [];

  if (want("ct_logs"))        tasks.push(runCtLogs(target));
  if (want("reverse_whois"))  tasks.push(runReverseWhois(target));
  if (want("asn_lookup"))     tasks.push(runAsnLookup(target));
  if (want("dkim_check"))     tasks.push(runDkimCheck(target));
  if (want("github_exposure")) tasks.push(runGithubExposure(target, opts.githubToken));
  if (want("shodan"))         tasks.push(runShodanSearch(target, opts.shodanApiKey ?? null));
  if (want("fofa"))           tasks.push(runFofaSearch(target, opts.fofaEmail ?? null, opts.fofaApiKey ?? null));
  if (want("censys"))         tasks.push(runCensysSearch(target, opts.censysApiId ?? null, opts.censysApiSecret ?? null));
  if (want("intelx"))         tasks.push(runIntelxSearch(target, opts.intelxApiKey ?? null));
  if (want("criminalip"))     tasks.push(runCriminalIpSearch(target, opts.criminalIpApiKey ?? null));

  const results = await Promise.allSettled(tasks);
  return results.map(r =>
    r.status === "fulfilled"
      ? r.value
      : { source: "unknown", status: "error" as const, data: null, summary: String((r as PromiseRejectedResult).reason) }
  );
}
