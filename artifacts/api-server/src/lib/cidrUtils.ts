/** Convert dotted-decimal IPv4 to 32-bit unsigned integer. */
export function ip2int(ip: string): number {
  const p = ip.split(".").map(Number);
  return ((p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!) >>> 0;
}

/** Convert 32-bit unsigned integer back to dotted-decimal IPv4. */
export function int2ip(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/**
 * Parse a CIDR string (e.g. "23.32.0.0/11") into its first and last host IP.
 * Returns null when the input is not a valid IPv4 CIDR.
 */
export function cidrToRange(cidr: string): { start: string; end: string } | null {
  const m = cidr.trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const bits = parseInt(m[2]!, 10);
  if (bits < 0 || bits > 32) return null;
  const parts = m[1]!.split(".").map(Number);
  if (parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  const baseInt = ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
  const mask    = bits === 0 ? 0 : ((0xFFFFFFFF << (32 - bits)) >>> 0);
  const start   = (baseInt & mask) >>> 0;
  const end     = (start | (~mask >>> 0)) >>> 0;
  return { start: int2ip(start), end: int2ip(end) };
}
