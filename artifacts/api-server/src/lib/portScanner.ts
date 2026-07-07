import { exec, execSync } from "child_process";
import { promisify } from "util";
import dns from "dns/promises";
import fs from "fs";
import path from "path";
import { orchestratedFetch } from "./scanOrchestrator";
import zlib from "zlib";

const execAsync = promisify(exec);
let NAABU_BIN     = "/tmp/naabu";   // may be overridden to system binary
const MASSCAN_BIN = "/tmp/masscan-tool";
const NAABU_ZIP   = path.resolve(__dirname, "../binaries/naabu.zip");

// ── Auto-extract naabu from bundled zip (prefers system binary via Nix) ───────

function ensureNaabu(): boolean {
  // 1. System-installed naabu (Nix PATH — preferred, no extraction needed)
  try {
    const sys = execSync("which naabu 2>/dev/null", { timeout: 3000 }).toString().trim();
    if (sys) { NAABU_BIN = sys; return true; }
  } catch {}

  // 2. Already cached at /tmp/naabu
  if (fs.existsSync(NAABU_BIN)) {
    try { fs.accessSync(NAABU_BIN, fs.constants.X_OK); return true; } catch { /* fall through */ }
  }
  if (!fs.existsSync(NAABU_ZIP)) return false;
  try {
    const zip = fs.readFileSync(NAABU_ZIP);
    let eocd = zip.length - 22;
    while (eocd >= 0 && zip.readUInt32LE(eocd) !== 0x06054b50) eocd--;
    if (eocd < 0) return false;
    const cdOffset  = zip.readUInt32LE(eocd + 16);
    const numEntries = zip.readUInt16LE(eocd + 10);
    let cdPos = cdOffset;
    for (let i = 0; i < numEntries; i++) {
      const method   = zip.readUInt16LE(cdPos + 10);
      const compSize = zip.readUInt32LE(cdPos + 20);
      const fnLen    = zip.readUInt16LE(cdPos + 28);
      const extLen   = zip.readUInt16LE(cdPos + 30);
      const commLen  = zip.readUInt16LE(cdPos + 32);
      const lhOffset = zip.readUInt32LE(cdPos + 42);
      const fname    = zip.slice(cdPos + 46, cdPos + 46 + fnLen).toString();
      if (fname === "naabu") {
        const lhFnLen  = zip.readUInt16LE(lhOffset + 26);
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
  } catch { return false; }
  return false;
}

// ── Masscan: install from system or download binary ───────────────────────────

function ensureMasscan(): { bin: string | null; method: string } {
  // 1. Already cached
  if (fs.existsSync(MASSCAN_BIN)) {
    try { fs.accessSync(MASSCAN_BIN, fs.constants.X_OK); return { bin: MASSCAN_BIN, method: "cached" }; } catch {}
  }

  // 2. System-installed masscan
  try {
    const sys = execSync("which masscan 2>/dev/null", { timeout: 3000 }).toString().trim();
    if (sys) {
      try { fs.copyFileSync(sys, MASSCAN_BIN); fs.chmodSync(MASSCAN_BIN, 0o755); } catch {}
      return { bin: sys, method: "system" };
    }
  } catch {}

  // 3. Try apt-get (synchronous, background-safe since we're in a worker context)
  try {
    execSync("apt-get install -y masscan 2>/dev/null", { timeout: 60000 });
    const sys2 = execSync("which masscan 2>/dev/null", { timeout: 3000 }).toString().trim();
    if (sys2) {
      try { fs.copyFileSync(sys2, MASSCAN_BIN); fs.chmodSync(MASSCAN_BIN, 0o755); } catch {}
      return { bin: sys2, method: "apt" };
    }
  } catch {}

  return { bin: null, method: "unavailable" };
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface PortDetail {
  port: number;
  protocol: string;
  service: string;
  version: string;
  state: string;
  banner?: string;
  scripts?: Record<string, string>;
  cpes?: string[];
  source?: "naabu" | "masscan" | "nmap" | "shodan";
}

export interface ShodanHostData {
  ip: string;
  ports: number[];
  tags: string[];
  cpes: string[];
  vulns: string[];
  hostnames: string[];
}

export interface MasscanPortEntry {
  port: number;
  proto: string;
  status: string;
  ttl?: number;
}

export interface MasscanResult {
  ports: number[];
  entries: MasscanPortEntry[];
  raw: string;
  available: boolean;
  failReason?: string;
}

export interface PortScanReport {
  ports: PortDetail[];
  naabuPorts: number[];
  masscan: MasscanResult;
  nmapRaw: string;
  naabuRaw: string;
  shodan?: ShodanHostData;
  scanMethod: "naabu+masscan+nmap" | "naabu+nmap" | "masscan+nmap" | "nmap-only";
  scannedAt: string;
  targetIp?: string;
  shodanSource?: "full-api" | "internetdb";
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
  } catch { return null; }
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
      const rest    = portMatch[4].trim();
      const cpes: string[] = [];
      for (const m of rest.matchAll(/cpe:\/[^\s)]+/g)) cpes.push(m[0]);
      const version = rest.replace(/\s*cpe:\/[^\s)]+/g, "").replace(/\s+$/, "").trim();
      current = { port: parseInt(portMatch[1]), protocol: portMatch[2], service, version, state: "open", scripts: {}, source: "nmap" };
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

// ── Masscan JSON output parser ────────────────────────────────────────────────

function parseMasscanJson(output: string): MasscanPortEntry[] {
  const entries: MasscanPortEntry[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim().replace(/,$/, "");
    if (!trimmed.startsWith("{")) continue;
    try {
      const obj = JSON.parse(trimmed);
      for (const p of obj.ports ?? []) {
        entries.push({
          port:   p.port ?? 0,
          proto:  p.proto ?? "tcp",
          status: p.status ?? "open",
          ttl:    p.ttl,
        });
      }
    } catch {}
  }
  return entries;
}

// ── Naabu: fast full-port discovery ──────────────────────────────────────────

async function runNaabu(target: string): Promise<{ ports: number[]; raw: string }> {
  const naabuAvailable = ensureNaabu();
  if (!naabuAvailable) return { ports: [], raw: "(naabu binary not available)" };

  const host = extractTarget(target);
  const cmd  = `${NAABU_BIN} -host ${host} -p 1-65535 -rate 3000 -timeout 5 -silent 2>/dev/null`;
  let stdout = "";
  try {
    const r = await execAsync(cmd, { timeout: 90000 });
    stdout = r.stdout.trim();
  } catch (err: any) { stdout = err?.stdout?.trim() ?? ""; }

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

// ── Masscan: ultra-fast SYN + UDP scan ───────────────────────────────────────

async function runMasscan(target: string, targetIp: string | null): Promise<MasscanResult> {
  const { bin, method } = ensureMasscan();

  if (!bin) {
    return {
      ports: [], entries: [], raw: "(masscan not installed — install with: apt-get install masscan)",
      available: false, failReason: "not-installed",
    };
  }

  const scanTarget = targetIp ?? extractTarget(target);
  if (!scanTarget) {
    return { ports: [], entries: [], raw: "(could not resolve target IP)", available: false, failReason: "no-ip" };
  }

  // Run TCP full-port and top UDP ports
  const tcpCmd = `${bin} -p1-65535 ${scanTarget} --rate=10000 --open -oJ - 2>/dev/null`;
  const udpCmd = `${bin} -pU:53,67,68,69,123,161,162,500,514,520,623,1194,1900,4500,5353 ${scanTarget} --rate=1000 --open -oJ - 2>/dev/null`;

  let tcpOut = "";
  let udpOut = "";
  let failReason: string | undefined;

  try {
    const [tcpResult, udpResult] = await Promise.allSettled([
      execAsync(tcpCmd, { timeout: 120000 }),
      execAsync(udpCmd, { timeout: 60000 }),
    ]);
    if (tcpResult.status === "fulfilled") tcpOut = tcpResult.value.stdout;
    else {
      const errMsg = String((tcpResult as any).reason?.message ?? "");
      if (errMsg.includes("FAILED") || errMsg.includes("permission") || errMsg.includes("pcap") || errMsg.includes("LIBPCAP")) {
        failReason = "raw-socket-denied";
      } else {
        failReason = "error";
      }
    }
    if (udpResult.status === "fulfilled") udpOut = udpResult.value.stdout;
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    if (msg.includes("permission") || msg.includes("pcap") || msg.includes("FAILED")) {
      failReason = "raw-socket-denied";
    }
  }

  const raw = [tcpOut, udpOut].filter(Boolean).join("\n").trim() ||
    (failReason === "raw-socket-denied"
      ? "(masscan requires raw socket access — run as root or grant CAP_NET_RAW capability)"
      : "(no output)");

  const tcpEntries = parseMasscanJson(tcpOut);
  const udpEntries = parseMasscanJson(udpOut);
  const allEntries = [...tcpEntries, ...udpEntries];
  const ports = [...new Set(allEntries.map(e => e.port))].sort((a, b) => a - b);

  return {
    ports,
    entries: allEntries,
    raw: `=== Masscan TCP (${method}) ===\n${tcpOut.slice(0, 4000) || "(no tcp output)"}\n\n=== Masscan UDP ===\n${udpOut.slice(0, 1000) || "(no udp output)"}`,
    available: true,
    failReason,
  };
}

// ── Nmap: service detection + banner grabbing + NSE scripts ──────────────────

async function runNmapDetailed(target: string, ports: number[]): Promise<{ portDetails: PortDetail[]; raw: string }> {
  const host     = extractTarget(target);
  const portSpec = ports.length > 0 ? `-p ${ports.slice(0, 500).join(",")}` : "-p 1-1024";

  const scripts = [
    "banner",
    "http-title", "http-server-header", "http-methods",
    "ssl-cert", "ssl-enum-ciphers",
    "ssh-hostkey", "ssh-auth-methods",
    "ftp-anon", "ftp-bounce",
    "smtp-commands", "smtp-open-relay",
    "dns-recursion", "dns-service-discovery",
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
  } catch (err: any) { stdout = err?.stdout ?? String(err?.message ?? err); }
  return { portDetails: parseNmapOutput(stdout), raw: stdout };
}

// ── Rustscan: ultra-fast async port scanner ───────────────────────────────────

async function runRustscan(target: string): Promise<{ ports: number[]; raw: string }> {
  try {
    const sys = execSync("which rustscan 2>/dev/null", { timeout: 3000 }).toString().trim();
    if (!sys) return { ports: [], raw: "(rustscan not found in PATH)" };

    const host = extractTarget(target);
    const cmd  = `rustscan -a ${host} --range 1-65535 --ulimit 5000 --no-nmap --timeout 3000 2>/dev/null`;
    let stdout = "";
    try {
      const r = await execAsync(cmd, { timeout: 120000 });
      stdout = r.stdout;
    } catch (err: any) { stdout = err?.stdout?.trim() ?? ""; }

    const ports: number[] = [];
    for (const line of stdout.split("\n")) {
      const m = line.match(/Open\s+[^:]+:(\d+)/i) ?? line.match(/:(\d+)$/);
      if (m) {
        const n = parseInt(m[1]);
        if (!isNaN(n) && n > 0 && n <= 65535) ports.push(n);
      }
    }
    return { ports: [...new Set(ports)].sort((a, b) => a - b), raw: stdout };
  } catch { return { ports: [], raw: "(rustscan error)" }; }
}

// ── Shodan InternetDB (free, no API key) ──────────────────────────────────────

export async function queryShodanInternetDB(ip: string): Promise<ShodanHostData | null> {
  if (!ip || !isIp(ip)) return null;
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 10000);
    const res = await orchestratedFetch(`https://internetdb.shodan.io/${ip}`, { signal: ctrl.signal }, { intensity: "passive" });
    if (!res.ok) return null;
    const d: any = await res.json();
    if (d.detail === "No information available") return null;
    return { ip, ports: (d.ports ?? []).map(Number), tags: d.tags ?? [], cpes: d.cpes ?? [], vulns: d.vulns ?? [], hostnames: d.hostnames ?? [] };
  } catch { return null; }
}

// ── Shodan Full API ───────────────────────────────────────────────────────────

export async function queryShodanFullApi(ip: string, apiKey: string): Promise<ShodanHostData | null> {
  if (!ip || !isIp(ip)) return null;
  try {
    const ctrl = new AbortController();
    setTimeout(() => ctrl.abort(), 12000);
    const res = await orchestratedFetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`, { signal: ctrl.signal }, { intensity: "passive" });
    if (!res.ok) return null;
    const d: any = await res.json();
    if (d.error) return null;
    const vulns: string[] = Object.keys(d.vulns ?? {});
    const cpes: string[]  = [...new Set(
      (d.data ?? []).flatMap((item: any) => [
        ...(Array.isArray(item.cpe)   ? item.cpe   : []),
        ...(Array.isArray(item.cpe23) ? item.cpe23 : []),
      ]) as string[]
    )];
    return { ip, ports: (d.ports ?? []).map(Number), tags: d.tags ?? [], cpes, vulns, hostnames: d.hostnames ?? [] };
  } catch { return null; }
}

// ── Main export ───────────────────────────────────────────────────────────────

export async function scanPorts(target: string, shodanApiKey?: string | null): Promise<PortScanReport> {
  const scannedAt = new Date().toISOString();
  const targetIp  = await resolveToIp(target);

  // Run naabu, masscan, rustscan, and shodan in parallel
  const [naabuResult, masscanResult, rustscanResult, shodanData] = await Promise.all([
    runNaabu(target),
    runMasscan(target, targetIp),
    runRustscan(target),
    targetIp
      ? (shodanApiKey
          ? queryShodanFullApi(targetIp, shodanApiKey)
          : queryShodanInternetDB(targetIp))
      : Promise.resolve(null),
  ]);

  const naabuPorts     = naabuResult.ports;
  const masscanPorts   = masscanResult.ports;
  const rustscanPorts  = rustscanResult.ports;
  const shodanPorts    = shodanData?.ports ?? [];

  // Union of all discovered ports
  const allDiscoveredPorts = [...new Set([...naabuPorts, ...masscanPorts, ...rustscanPorts, ...shodanPorts])].sort((a, b) => a - b);

  // Deep service scan on union
  const nmapResult = await runNmapDetailed(target, allDiscoveredPorts);

  // Annotate source on nmap results; fill in extras as naabu/masscan ports
  const nmapPortSet = new Set(nmapResult.portDetails.map(p => p.port));
  const masscanPortSet = new Set(masscanPorts);
  const naabuPortSet   = new Set(naabuPorts);

  const extraPorts: PortDetail[] = allDiscoveredPorts
    .filter(p => !nmapPortSet.has(p))
    .map(p => ({
      port: p, protocol: "tcp", service: "unknown", version: "", state: "open",
      source: masscanPortSet.has(p) ? "masscan" as const : naabuPortSet.has(p) ? "naabu" as const : "shodan" as const,
    }));

  const mergedPorts = [
    ...nmapResult.portDetails.map(p => {
      const sh  = shodanData?.cpes?.filter(c =>
        c.toLowerCase().includes(p.service.toLowerCase()) || c.toLowerCase().includes(String(p.port))
      ) ?? [];
      return { ...p, cpes: [...new Set([...(p.cpes ?? []), ...sh])].filter(Boolean) };
    }),
    ...extraPorts,
  ].sort((a, b) => a.port - b.port);

  // Determine scan method
  const hasNaabu    = naabuPorts.length > 0;
  const hasMasscan  = masscanPorts.length > 0;
  const hasRustscan = rustscanPorts.length > 0;
  let scanMethod: PortScanReport["scanMethod"];
  if (hasNaabu && hasMasscan)       scanMethod = "naabu+masscan+nmap";
  else if (hasNaabu || hasRustscan) scanMethod = "naabu+nmap";
  else if (hasMasscan)              scanMethod = "masscan+nmap";
  else                              scanMethod = "nmap-only";

  return {
    ports: mergedPorts,
    naabuPorts,
    masscan: masscanResult,
    nmapRaw:    nmapResult.raw,
    naabuRaw:   naabuResult.raw,
    shodan:     shodanData ?? undefined,
    scanMethod,
    scannedAt,
    targetIp:   targetIp ?? undefined,
    shodanSource: shodanData ? (shodanApiKey ? "full-api" : "internetdb") : undefined,
  };
}
