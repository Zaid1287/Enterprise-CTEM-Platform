import { exec } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";
import fs from "fs";
import path from "path";
import zlib from "zlib";

const execAsync = promisify(exec);
const NAABU_BIN = "/tmp/naabu";
const NAABU_ZIP = path.resolve(__dirname, "../binaries/naabu.zip");

// ── Auto-extract naabu from bundled zip if not present ───────────────────────

function ensureNaabu(): boolean {
  if (fs.existsSync(NAABU_BIN)) {
    try { fs.accessSync(NAABU_BIN, fs.constants.X_OK); return true; } catch { /* fall through */ }
  }
  if (!fs.existsSync(NAABU_ZIP)) return false;
  try {
    const zip = fs.readFileSync(NAABU_ZIP);
    // Locate "naabu" entry via central directory
    let eocd = zip.length - 22;
    while (eocd >= 0 && zip.readUInt32LE(eocd) !== 0x06054b50) eocd--;
    if (eocd < 0) return false;
    const cdOffset = zip.readUInt32LE(eocd + 16);
    const numEntries = zip.readUInt16LE(eocd + 10);
    let cdPos = cdOffset;
    for (let i = 0; i < numEntries; i++) {
      const method = zip.readUInt16LE(cdPos + 10);
      const compSize = zip.readUInt32LE(cdPos + 20);
      const fnLen = zip.readUInt16LE(cdPos + 28);
      const extLen = zip.readUInt16LE(cdPos + 30);
      const commLen = zip.readUInt16LE(cdPos + 32);
      const lhOffset = zip.readUInt32LE(cdPos + 42);
      const fname = zip.slice(cdPos + 46, cdPos + 46 + fnLen).toString();
      if (fname === "naabu") {
        const lhFnLen = zip.readUInt16LE(lhOffset + 26);
        const lhExtLen = zip.readUInt16LE(lhOffset + 28);
        const dataStart = lhOffset + 30 + lhFnLen + lhExtLen;
        const compressed = zip.slice(dataStart, dataStart + compSize);
        const binary = method === 8
          ? zlib.inflateRawSync(compressed, { chunkSize: 40 * 1024 * 1024 })
          : compressed;
        fs.writeFileSync(NAABU_BIN, binary, { mode: 0o755 });
        return true;
      }
      cdPos += 46 + fnLen + extLen + commLen;
    }
  } catch {
    return false;
  }
  return false;
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface PortDetail {
  port: number;
  protocol: string;
  service: string;
  version: string;
  state: string;
  banner?: string;
  scripts?: Record<string, string>;
  cpes?: string[];
}

export interface ShodanHostData {
  ip: string;
  ports: number[];
  tags: string[];
  cpes: string[];
  vulns: string[];
  hostnames: string[];
}

export interface PortScanReport {
  ports: PortDetail[];
  naabuPorts: number[];
  nmapRaw: string;
  naabuRaw: string;
  shodan?: ShodanHostData;
  scanMethod: "naabu+nmap" | "nmap-only";
  scannedAt: string;
  targetIp?: string;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function isIp(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
}

export function extractTarget(target: string): string {
  return target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0].toLowerCase().trim();
}

async function resolveToIp(target: string): Promise<string | null> {
  const host = extractTarget(target);
  if (isIp(host)) return host;
  try {
    const ips = await dns.resolve4(host);
    return ips[0] ?? null;
  } catch {
    return null;
  }
}

// ── Nmap output parser ────────────────────────────────────────────────────────

function parseNmapOutput(output: string): PortDetail[] {
  const ports: PortDetail[] = [];
  const lines = output.split("\n");
  let current: PortDetail | null = null;
  let lastScriptKey: string | null = null;

  for (const line of lines) {
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)/);
    if (portMatch) {
      if (current) ports.push(current);

      const service = portMatch[3].replace(/\?$/, "");
      const rest = portMatch[4].trim();

      const cpes: string[] = [];
      for (const m of rest.matchAll(/cpe:\/[^\s)]+/g)) cpes.push(m[0]);
      const version = rest.replace(/\s*cpe:\/[^\s)]+/g, "").replace(/\s+$/, "").trim();

      current = { port: parseInt(portMatch[1]), protocol: portMatch[2], service, version, state: "open", scripts: {} };
      if (cpes.length > 0) current.cpes = cpes;
      lastScriptKey = null;
      continue;
    }

    if (current && (line.startsWith("| ") || line.startsWith("|_"))) {
      const raw = line.replace(/^\|_?\s?/, "");
      const hdr = raw.match(/^([a-z][a-z0-9-]+):\s*(.*)/);
      if (hdr && !raw.startsWith(" ") && !raw.startsWith("\t")) {
        lastScriptKey = hdr[1];
        if (!current.scripts) current.scripts = {};
        current.scripts[lastScriptKey] = hdr[2];
        if (lastScriptKey === "banner") current.banner = hdr[2].trim();
      } else if (lastScriptKey && current.scripts) {
        current.scripts[lastScriptKey] += "\n" + raw;
      }
    }
  }
  if (current) ports.push(current);
  return ports;
}

// ── Naabu: fast full-port discovery ─────────────────────────────────────────

async function runNaabu(target: string): Promise<{ ports: number[]; raw: string }> {
  const naabuAvailable = ensureNaabu();
  if (!naabuAvailable) return { ports: [], raw: "(naabu not available; using nmap fallback)" };

  const host = extractTarget(target);
  const cmd = `${NAABU_BIN} -host ${host} -p 1-65535 -rate 3000 -timeout 5 -silent 2>/dev/null`;
  let stdout = "";
  try {
    const r = await execAsync(cmd, { timeout: 90000 });
    stdout = r.stdout.trim();
  } catch (err: any) {
    stdout = err?.stdout?.trim() ?? "";
  }

  const ports: number[] = [];
  for (const line of stdout.split("\n")) {
    const m = line.trim().match(/:(\d+)$/);
    if (m) {
      const n = parseInt(m[1]);
      if (!isNaN(n) && n > 0 && n <= 65535) ports.push(n);
    }
  }
  return { ports: [...new Set(ports)].sort((a, b) => a - b), raw: stdout };
}

// ── Nmap: service detection + banner grabbing + NSE scripts ──────────────────

async function runNmapDetailed(target: string, openPorts: number[]): Promise<{ portDetails: PortDetail[]; raw: string }> {
  const host = extractTarget(target);
  const portSpec = openPorts.length > 0
    ? `-p ${openPorts.slice(0, 300).join(",")}`
    : "--top-ports 1000";

  const scripts = [
    "banner",
    "http-title",
    "http-server-header",
    "ssl-cert",
    "ssh-hostkey",
    "smtp-commands",
    "ftp-anon",
    "rdp-enum-encryption",
    "mysql-info",
    "ms-sql-info",
    "mongodb-info",
  ].join(",");

  const cmd = [
    "nmap",
    "-sV --version-intensity 6",
    "-sC",
    `--script=${scripts}`,
    portSpec,
    "-T4 --open",
    "--max-rtt-timeout 3s --host-timeout 120s",
    host,
  ].join(" ");

  let stdout = "";
  try {
    const r = await execAsync(cmd, { timeout: 150000 });
    stdout = r.stdout;
  } catch (err: any) {
    stdout = err?.stdout ?? String(err?.message ?? err);
  }
  return { portDetails: parseNmapOutput(stdout), raw: stdout };
}

// ── Shodan InternetDB (free, no API key) ──────────────────────────────────────

export async function queryShodanInternetDB(ip: string): Promise<ShodanHostData | null> {
  if (!ip || !isIp(ip)) return null;
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10000);
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: ctrl.signal });
    if (!res.ok) return null;
    const d: any = await res.json();
    if (d.detail === "No information available") return null;
    return {
      ip,
      ports: (d.ports ?? []).map(Number),
      tags: d.tags ?? [],
      cpes: d.cpes ?? [],
      vulns: d.vulns ?? [],
      hostnames: d.hostnames ?? [],
    };
  } catch {
    return null;
  }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function scanPorts(target: string): Promise<PortScanReport> {
  const scannedAt = new Date().toISOString();
  const targetIp = await resolveToIp(target);

  const [naabuResult, shodanData] = await Promise.all([
    runNaabu(target),
    targetIp ? queryShodanInternetDB(targetIp) : Promise.resolve(null),
  ]);

  const naabuPorts = naabuResult.ports;
  const shodanPorts = shodanData?.ports ?? [];
  const allDiscoveredPorts = [...new Set([...naabuPorts, ...shodanPorts])].sort((a, b) => a - b);

  const nmapResult = await runNmapDetailed(target, allDiscoveredPorts);

  const nmapPortSet = new Set(nmapResult.portDetails.map(p => p.port));
  const extraPorts: PortDetail[] = allDiscoveredPorts
    .filter(p => !nmapPortSet.has(p))
    .map(p => ({ port: p, protocol: "tcp", service: "unknown", version: "", state: "open" }));

  const mergedPorts = [
    ...nmapResult.portDetails.map(p => {
      const sh = shodanData?.cpes?.filter(c =>
        c.toLowerCase().includes(p.service.toLowerCase()) ||
        c.toLowerCase().includes(String(p.port))
      ) ?? [];
      return { ...p, cpes: [...new Set([...(p.cpes ?? []), ...sh])].filter(Boolean) };
    }),
    ...extraPorts,
  ].sort((a, b) => a.port - b.port);

  return {
    ports: mergedPorts,
    naabuPorts,
    nmapRaw: nmapResult.raw,
    naabuRaw: naabuResult.raw,
    shodan: shodanData ?? undefined,
    scanMethod: naabuPorts.length > 0 ? "naabu+nmap" : "nmap-only",
    scannedAt,
    targetIp: targetIp ?? undefined,
  };
}
