interface CookieEntry {
  value: string;
  expires?: Date;
}

const jar = new Map<string, Map<string, CookieEntry>>();

function extractDomain(urlOrDomain: string): string {
  try {
    return new URL(urlOrDomain.startsWith("http") ? urlOrDomain : `https://${urlOrDomain}`).hostname;
  } catch {
    return urlOrDomain;
  }
}

export function storeCookies(urlOrDomain: string, setCookieHeaders: string[]): void {
  const domain = extractDomain(urlOrDomain);
  if (!jar.has(domain)) jar.set(domain, new Map());
  const domainJar = jar.get(domain)!;

  for (const header of setCookieHeaders) {
    const parts = header.split(";").map(p => p.trim());
    const kv = parts[0];
    if (!kv) continue;
    const eqIdx = kv.indexOf("=");
    if (eqIdx === -1) continue;
    const name  = kv.slice(0, eqIdx).trim();
    const value = kv.slice(eqIdx + 1).trim();

    let expires: Date | undefined;
    for (const attr of parts.slice(1)) {
      const lower = attr.toLowerCase();
      if (lower.startsWith("max-age=")) {
        const secs = parseInt(lower.slice(8), 10);
        if (!isNaN(secs)) expires = new Date(Date.now() + secs * 1000);
      } else if (lower.startsWith("expires=")) {
        const d = new Date(attr.slice(8));
        if (!isNaN(d.getTime())) expires = d;
      }
    }

    domainJar.set(name, { value, expires });
  }
}

export function getCookieHeader(urlOrDomain: string): string {
  const domain = extractDomain(urlOrDomain);
  const domainJar = jar.get(domain);
  if (!domainJar) return "";

  const now = Date.now();
  const parts: string[] = [];
  for (const [name, entry] of domainJar) {
    if (entry.expires && entry.expires.getTime() < now) {
      domainJar.delete(name);
      continue;
    }
    parts.push(`${name}=${entry.value}`);
  }
  return parts.join("; ");
}

export function clearCookies(urlOrDomain: string): void {
  const domain = extractDomain(urlOrDomain);
  jar.delete(domain);
}

export function clearAllCookies(): void {
  jar.clear();
}
