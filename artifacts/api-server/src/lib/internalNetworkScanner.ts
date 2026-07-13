/**
 * Internal Network Scanner
 *
 * Discovers devices on an internal subnet using four real techniques:
 *
 *   1. ARP / Ping sweep via nmap  — discovers all active hosts, gets MAC addresses
 *   2. mDNS / Bonjour probing     — discovers services via DNS-SD multicast (port 5353)
 *   3. SNMP sweep                 — queries sysDescr/sysName/sysLocation on live hosts
 *   4. NetBIOS Name Service       — resolves device names on Windows LAN (UDP 137)
 *
 * NOTE: This scanner must run on a machine physically connected to the target
 * subnet. In a cloud/container deployment it will only see the container's
 * own network. For customer LAN scanning, deploy as an on-prem agent.
 */

import { execFile } from "child_process";
import { promisify } from "util";
import * as dgram from "dgram";
import * as os from "os";
import { logger } from "./logger";

const execFileAsync = promisify(execFile);

export interface NetworkDevice {
  ipAddress: string;
  macAddress: string | null;
  macVendor: string | null;
  hostname: string | null;
  netbiosName: string | null;
  mdnsName: string | null;
  mdnsServices: string[];
  deviceType: string;
  snmpSysDescr: string | null;
  snmpSysName: string | null;
  snmpSysLocation: string | null;
  openPorts: number[];
  discoveryMethods: string[];
  osGuess: string | null;
}

// ── Utility: auto-detect local subnets ───────────────────────────────────────

export function detectLocalSubnets(): string[] {
  const subnets: string[] = [];
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name] ?? []) {
      if (iface.family !== "IPv4" || iface.internal || iface.address.startsWith("127.")) continue;
      // Convert IP + netmask to CIDR
      const parts = iface.address.split(".").map(Number);
      const mask = iface.netmask.split(".").map(Number);
      const network = parts.map((p, i) => p & mask[i]).join(".");
      const cidr = mask.reduce((acc, m) => acc + m.toString(2).split("").filter(b => b === "1").length, 0);
      if (cidr >= 16 && cidr <= 30) subnets.push(`${network}/${cidr}`);
    }
  }
  return subnets.length > 0 ? subnets : ["192.168.1.0/24"];
}

// ── 1. Nmap Ping Sweep (ARP on LAN) ──────────────────────────────────────────

interface NmapHost {
  ip: string;
  mac: string | null;
  macVendor: string | null;
  hostname: string | null;
  status: "up" | "down";
}

export async function nmapPingSweep(subnet: string): Promise<NmapHost[]> {
  try {
    // -sn: ping scan (no port scan), -T4: fast timing, --host-timeout: bail on slow hosts
    const { stdout } = await execFileAsync("nmap", [
      "-sn", "-T4", "--host-timeout", "5s",
      "--max-rtt-timeout", "1s", "--min-hostgroup", "64",
      "-oX", "-",     // XML output to stdout
      subnet,
    ], { timeout: 120_000 });

    return parseNmapXml(stdout);
  } catch (err: any) {
    logger.warn({ err: err.message, subnet }, "nmap sweep failed");
    return [];
  }
}

function parseNmapXml(xml: string): NmapHost[] {
  const hosts: NmapHost[] = [];
  // Simple regex-based XML parse (no external lib needed for nmap output)
  const hostBlocks = xml.match(/<host\b[^>]*>[\s\S]*?<\/host>/g) ?? [];
  for (const block of hostBlocks) {
    const statusMatch = block.match(/<status state="([^"]+)"/);
    if (!statusMatch || statusMatch[1] !== "up") continue;

    const ipMatch = block.match(/<address addr="([\d.]+)" addrtype="ipv4"/);
    const macMatch = block.match(/<address addr="([0-9A-F:]{17})" addrtype="mac"[^>]*>/i);
    const vendorMatch = block.match(/addrtype="mac"[^>]*vendor="([^"]+)"/i);
    const hostnameMatch = block.match(/<hostname name="([^"]+)"/);

    if (!ipMatch) continue;
    hosts.push({
      ip: ipMatch[1],
      mac: macMatch ? macMatch[1].toUpperCase() : null,
      macVendor: vendorMatch ? vendorMatch[1] : null,
      hostname: hostnameMatch ? hostnameMatch[1] : null,
      status: "up",
    });
  }
  return hosts;
}

// ── 2. mDNS / Bonjour Discovery ───────────────────────────────────────────────

interface MDNSDevice {
  ip: string;
  name: string;
  services: string[];
}

export async function probeMDNS(timeoutMs = 4000): Promise<MDNSDevice[]> {
  return new Promise(resolve => {
    const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });
    const discoveredServices = new Map<string, string[]>();
    const deviceNames = new Map<string, string>();

    socket.on("error", () => socket.close());

    socket.on("message", (msg) => {
      try {
        const result = parseDnsPacket(msg);
        for (const answer of result.answers) {
          if (answer.type === "PTR" && answer.data) {
            const service = answer.name;
            const existing = discoveredServices.get(service) ?? [];
            if (!existing.includes(answer.data)) existing.push(answer.data);
            discoveredServices.set(service, existing);
          }
          if ((answer.type === "A" || answer.type === "AAAA") && answer.name) {
            deviceNames.set(answer.data ?? "", answer.name.replace(/\.local\.?$/, ""));
          }
        }
      } catch { /* ignore malformed packets */ }
    });

    socket.bind(0, () => {
      // Send DNS-SD query: PTR query for _services._dns-sd._udp.local
      const query = buildMDNSQuery("_services._dns-sd._udp.local", 12 /* PTR */);
      socket.setBroadcast(true);
      socket.send(query, 5353, "224.0.0.1", () => {
        // Also probe common service types
        const commonServices = [
          "_http._tcp.local", "_https._tcp.local", "_smb._tcp.local",
          "_afpovertcp._tcp.local", "_ftp._tcp.local", "_ssh._tcp.local",
          "_printer._tcp.local", "_ipp._tcp.local", "_airplay._tcp.local",
          "_companion-link._tcp.local", "_googlecast._tcp.local",
        ];
        for (const svc of commonServices) {
          const q = buildMDNSQuery(svc, 12);
          socket.send(q, 5353, "224.0.0.1");
        }
      });

      setTimeout(() => {
        socket.close();
        const devices: MDNSDevice[] = [];
        for (const [name, services] of discoveredServices) {
          devices.push({ ip: "", name: name.replace(/\.local\.?$/, ""), services });
        }
        // Add devices by name where we have IP
        for (const [ip, name] of deviceNames) {
          const existing = devices.find(d => d.name === name);
          if (existing) existing.ip = ip;
          else devices.push({ ip, name, services: [] });
        }
        resolve(devices.filter(d => d.name));
      }, timeoutMs);
    });
  });
}

function buildMDNSQuery(name: string, qtype: number): Buffer {
  // DNS query packet
  const labels = name.split(".");
  const parts: Buffer[] = [
    Buffer.from([0x00, 0x00, // ID
      0x00, 0x00,           // FLAGS: standard query
      0x00, 0x01,           // QDCOUNT: 1 question
      0x00, 0x00,           // ANCOUNT
      0x00, 0x00,           // NSCOUNT
      0x00, 0x00,           // ARCOUNT
    ]),
  ];
  for (const label of labels) {
    if (label.length === 0) continue;
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, "ascii"));
  }
  parts.push(Buffer.from([
    0x00,           // null terminator
    0x00, qtype,    // QTYPE (PTR=12, A=1)
    0x80, 0x01,     // QCLASS IN with unicast-response bit
  ]));
  return Buffer.concat(parts);
}

interface DnsPacket {
  answers: Array<{ name: string; type: string; data: string }>;
}

function parseDnsPacket(buf: Buffer): DnsPacket {
  const answers: Array<{ name: string; type: string; data: string }> = [];
  if (buf.length < 12) return { answers };

  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  let offset = 12;

  // Skip questions
  for (let i = 0; i < qdcount && offset < buf.length; i++) {
    while (offset < buf.length && buf[offset] !== 0) {
      if ((buf[offset] & 0xc0) === 0xc0) { offset += 2; break; }
      offset += buf[offset] + 1;
    }
    if (offset < buf.length && buf[offset] === 0) offset++;
    offset += 4; // type + class
  }

  // Parse answers
  for (let i = 0; i < ancount && offset < buf.length; i++) {
    const { name, nextOffset } = readDnsName(buf, offset);
    offset = nextOffset;
    if (offset + 10 > buf.length) break;
    const rtype = buf.readUInt16BE(offset);
    offset += 8; // type + class + ttl
    const rdlen = buf.readUInt16BE(offset); offset += 2;
    const rdataEnd = offset + rdlen;

    if (rtype === 12) { // PTR
      const { name: ptrName } = readDnsName(buf, offset);
      answers.push({ name, type: "PTR", data: ptrName });
    } else if (rtype === 1 && rdlen === 4) { // A
      const ip = `${buf[offset]}.${buf[offset+1]}.${buf[offset+2]}.${buf[offset+3]}`;
      answers.push({ name, type: "A", data: ip });
    }

    offset = rdataEnd;
  }

  return { answers };
}

function readDnsName(buf: Buffer, offset: number): { name: string; nextOffset: number } {
  const labels: string[] = [];
  let jumped = false;
  let nextOffset = offset;
  let safety = 0;

  while (offset < buf.length && safety++ < 64) {
    const len = buf[offset];
    if (len === 0) { if (!jumped) nextOffset = offset + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer
      const ptr = ((len & 0x3f) << 8) | buf[offset + 1];
      if (!jumped) nextOffset = offset + 2;
      offset = ptr;
      jumped = true;
      continue;
    }
    offset++;
    labels.push(buf.slice(offset, offset + len).toString("ascii"));
    offset += len;
  }

  return { name: labels.join("."), nextOffset };
}

// ── 3. SNMP v1/v2c Sweep ─────────────────────────────────────────────────────

interface SnmpResult {
  ip: string;
  sysDescr: string | null;
  sysName: string | null;
  sysLocation: string | null;
}

const SNMP_COMMUNITY = "public";

// OIDs as byte arrays (1.3.6.1.2.1.1.x.0)
const OID_SYSDESCR    = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
const OID_SYSNAME     = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
const OID_SYSLOCATION = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00];

function buildSnmpGetRequest(requestId: number): Buffer {
  function encodeOid(oid: number[]): Buffer {
    return Buffer.concat([
      Buffer.from([0x06, oid.length]), // OID tag + length
      Buffer.from(oid),
    ]);
  }
  function encodeVarbind(oid: number[]): Buffer {
    const oidBuf = encodeOid(oid);
    const nullBuf = Buffer.from([0x05, 0x00]); // NULL value
    const seqContent = Buffer.concat([oidBuf, nullBuf]);
    return Buffer.concat([Buffer.from([0x30, seqContent.length]), seqContent]);
  }
  function encodeTlv(tag: number, content: Buffer): Buffer {
    return Buffer.concat([Buffer.from([tag, content.length]), content]);
  }
  function encodeInt(val: number): Buffer {
    return encodeTlv(0x02, Buffer.from([val >> 24, (val >> 16) & 0xff, (val >> 8) & 0xff, val & 0xff]));
  }
  function encodeString(str: string): Buffer {
    const content = Buffer.from(str, "ascii");
    return encodeTlv(0x04, content);
  }

  const varbindList = Buffer.concat([
    encodeVarbind(OID_SYSDESCR),
    encodeVarbind(OID_SYSNAME),
    encodeVarbind(OID_SYSLOCATION),
  ]);
  const pdu = Buffer.concat([
    encodeInt(requestId),    // request-id
    encodeInt(0),            // error-status
    encodeInt(0),            // error-index
    encodeTlv(0x30, varbindList), // VarBindList
  ]);
  const pduWrapped = encodeTlv(0xa0, pdu); // GetRequest PDU

  const message = Buffer.concat([
    encodeInt(1),              // version: 1 = SNMPv1 (encoded as integer 0 for v1, 1 for v2c)
    encodeString(SNMP_COMMUNITY),
    pduWrapped,
  ]);
  return encodeTlv(0x30, message);
}

function parseSnmpResponse(buf: Buffer): { sysDescr: string | null; sysName: string | null; sysLocation: string | null } {
  try {
    // Very basic BER parser — just extract OctetString values in order
    const strings: string[] = [];
    let i = 0;
    while (i < buf.length - 2) {
      if (buf[i] === 0x04) { // OctetString
        const len = buf[i+1];
        if (len > 0 && i + 2 + len <= buf.length) {
          strings.push(buf.slice(i+2, i+2+len).toString("utf-8").replace(/\0/g, "").trim());
        }
        i += 2 + len;
      } else {
        i++;
      }
    }
    // strings[0] = community (skip), [1] = sysDescr, [2] = sysName, [3] = sysLocation
    return {
      sysDescr:    strings[1] ?? null,
      sysName:     strings[2] ?? null,
      sysLocation: strings[3] ?? null,
    };
  } catch {
    return { sysDescr: null, sysName: null, sysLocation: null };
  }
}

export async function snmpQuery(ip: string, timeoutMs = 2000): Promise<SnmpResult> {
  return new Promise(resolve => {
    const socket = dgram.createSocket("udp4");
    let resolved = false;

    const done = (result: Omit<SnmpResult, "ip">) => {
      if (!resolved) {
        resolved = true;
        socket.close();
        resolve({ ip, ...result });
      }
    };

    socket.on("error", () => done({ sysDescr: null, sysName: null, sysLocation: null }));
    socket.on("message", (msg) => {
      done(parseSnmpResponse(msg));
    });

    setTimeout(() => done({ sysDescr: null, sysName: null, sysLocation: null }), timeoutMs);

    const pkt = buildSnmpGetRequest(Math.floor(Math.random() * 0xffff));
    socket.send(pkt, 161, ip);
  });
}

// ── 4. NetBIOS Name Service ───────────────────────────────────────────────────

interface NetBIOSResult {
  ip: string;
  name: string | null;
  workgroup: string | null;
  mac: string | null;
}

function buildNBNSStatusRequest(): Buffer {
  // NBNS Node Status Request for wildcard name "*"
  const transactionId = Math.floor(Math.random() * 0xffff);
  return Buffer.from([
    (transactionId >> 8) & 0xff, transactionId & 0xff,  // Transaction ID
    0x00, 0x00,  // Flags: query
    0x00, 0x01,  // QDCOUNT: 1
    0x00, 0x00,  // ANCOUNT
    0x00, 0x00,  // NSCOUNT
    0x00, 0x00,  // ARCOUNT
    // Question: NBSTAT for wildcard *<00>
    0x20,        // Length of encoded name (32)
    // Encoded: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (wildcard * = 0x43 0x41)
    0x43, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x00,        // End of name
    0x00, 0x21,  // Type: NBSTAT
    0x00, 0x01,  // Class: IN
  ]);
}

function parseNBNSResponse(buf: Buffer, ip: string): NetBIOSResult {
  try {
    if (buf.length < 57) return { ip, name: null, workgroup: null, mac: null };
    const numNames = buf[56];
    if (numNames === 0 || buf.length < 57 + numNames * 18) return { ip, name: null, workgroup: null, mac: null };

    let workstationName: string | null = null;
    let workgroupName: string | null = null;

    for (let i = 0; i < numNames; i++) {
      const offset = 57 + i * 18;
      const rawName = buf.slice(offset, offset + 15).toString("ascii").replace(/\x00/g, "").trim();
      const nameType = buf[offset + 15];
      const flags = buf.readUInt16BE(offset + 16);

      if (nameType === 0x00 && !(flags & 0x8000)) workstationName = rawName;      // Workstation name
      if (nameType === 0x00 && (flags & 0x8000)) workgroupName = rawName;         // Workgroup
      if (nameType === 0x1e) workgroupName = rawName;                             // Browser election
    }

    // MAC address is at the end (last 6 bytes before the end)
    const macOffset = 57 + numNames * 18;
    let mac: string | null = null;
    if (macOffset + 6 <= buf.length) {
      const macBytes = buf.slice(macOffset, macOffset + 6);
      mac = Array.from(macBytes).map(b => b.toString(16).padStart(2, "0")).join(":").toUpperCase();
      if (mac === "00:00:00:00:00:00") mac = null;
    }

    return { ip, name: workstationName, workgroup: workgroupName, mac };
  } catch {
    return { ip, name: null, workgroup: null, mac: null };
  }
}

export async function netbiosQuery(ip: string, timeoutMs = 2000): Promise<NetBIOSResult> {
  return new Promise(resolve => {
    const socket = dgram.createSocket("udp4");
    let resolved = false;

    const done = (result: NetBIOSResult) => {
      if (!resolved) {
        resolved = true;
        try { socket.close(); } catch { /* ignore */ }
        resolve(result);
      }
    };

    socket.on("error", () => done({ ip, name: null, workgroup: null, mac: null }));
    socket.on("message", (msg) => done(parseNBNSResponse(msg, ip)));
    setTimeout(() => done({ ip, name: null, workgroup: null, mac: null }), timeoutMs);

    const pkt = buildNBNSStatusRequest();
    socket.send(pkt, 137, ip);
  });
}

// ── Device Type Inference ─────────────────────────────────────────────────────

function inferDeviceType(device: Partial<NetworkDevice>): string {
  const allText = [
    device.snmpSysDescr ?? "",
    device.hostname ?? "",
    device.netbiosName ?? "",
    device.mdnsName ?? "",
    device.mdnsServices?.join(" ") ?? "",
  ].join(" ").toLowerCase();

  if (/printer|mfp|laserjet|officejet|xerox|canon|epson|brother|ricoh|kyocera|hp.*print/i.test(allText)) return "printer";
  if (/router|gateway|mikrotik|cisco|juniper|firewall|pfsense|opnsense|fortigate|ubiquiti|unifi/i.test(allText)) return "router";
  if (/switch|catalyst|netgear|dlink|tplink|tp-link|procurve/i.test(allText)) return "switch";
  if (/nas|synology|qnap|freenas|truenas|storage/i.test(allText)) return "nas";
  if (/raspberry|arduino|esp8266|esp32|iot|camera|webcam|hue|nest|ring|alexa|homepod/i.test(allText)) return "iot";
  if (/windows|win10|win11|desktop|laptop|workstation|pc\b/i.test(allText)) return "workstation";
  if (/linux|ubuntu|debian|centos|rhel|server|esxi|vmware|proxmox|hypervisor/i.test(allText)) return "server";
  if (device.mdnsServices?.some(s => s.includes("_airplay") || s.includes("_companion"))) return "iot";
  if (device.mdnsServices?.some(s => s.includes("_smb") || s.includes("_afp"))) return "nas";
  return "unknown";
}

// ── Main Scan Orchestrator ────────────────────────────────────────────────────

export async function runInternalNetworkScan(subnet?: string): Promise<{
  devices: NetworkDevice[];
  subnet: string;
  discoveryMethods: string[];
}> {
  const targetSubnet = subnet ?? detectLocalSubnets()[0] ?? "192.168.1.0/24";
  logger.info({ subnet: targetSubnet }, "Internal network scan started");

  const discoveryMethods: string[] = [];

  // Step 1: nmap ping sweep to find live hosts
  const nmapHosts = await nmapPingSweep(targetSubnet);
  if (nmapHosts.length > 0) discoveryMethods.push("nmap_arp");
  logger.info({ found: nmapHosts.length }, "nmap sweep complete");

  const deviceMap = new Map<string, NetworkDevice>();
  for (const h of nmapHosts) {
    deviceMap.set(h.ip, {
      ipAddress: h.ip,
      macAddress: h.mac,
      macVendor: h.macVendor,
      hostname: h.hostname,
      netbiosName: null,
      mdnsName: null,
      mdnsServices: [],
      deviceType: "unknown",
      snmpSysDescr: null,
      snmpSysName: null,
      snmpSysLocation: null,
      openPorts: [],
      discoveryMethods: ["nmap"],
      osGuess: null,
    });
  }

  // Step 2: mDNS probing (runs in parallel with subsequent steps)
  const mdnsPromise = probeMDNS(3000).then(mdnsDevices => {
    discoveryMethods.push("mdns");
    for (const md of mdnsDevices) {
      if (md.ip && deviceMap.has(md.ip)) {
        const dev = deviceMap.get(md.ip)!;
        dev.mdnsName = md.name;
        dev.mdnsServices = md.services;
        if (!dev.discoveryMethods.includes("mdns")) dev.discoveryMethods.push("mdns");
      } else if (md.ip) {
        // New device discovered via mDNS
        deviceMap.set(md.ip, {
          ipAddress: md.ip,
          macAddress: null, macVendor: null, hostname: null,
          netbiosName: null, mdnsName: md.name, mdnsServices: md.services,
          deviceType: "unknown", snmpSysDescr: null, snmpSysName: null, snmpSysLocation: null,
          openPorts: [], discoveryMethods: ["mdns"], osGuess: null,
        });
      }
    }
    logger.info({ found: mdnsDevices.length }, "mDNS probing complete");
  }).catch(err => logger.warn({ err }, "mDNS probing failed (non-fatal)"));

  // Step 3: SNMP sweep on all known hosts (batch of 20 concurrent)
  const snmpPromise = (async () => {
    const ips = Array.from(deviceMap.keys());
    for (let i = 0; i < ips.length; i += 20) {
      const batch = ips.slice(i, i + 20);
      const results = await Promise.all(batch.map(ip => snmpQuery(ip)));
      for (const r of results) {
        if (r.sysDescr || r.sysName) {
          const dev = deviceMap.get(r.ip);
          if (dev) {
            dev.snmpSysDescr = r.sysDescr;
            dev.snmpSysName = r.sysName;
            dev.snmpSysLocation = r.sysLocation;
            if (!dev.discoveryMethods.includes("snmp")) dev.discoveryMethods.push("snmp");
          }
        }
      }
    }
    if (ips.some(ip => {
      const d = deviceMap.get(ip);
      return d?.snmpSysDescr != null;
    })) discoveryMethods.push("snmp");
    logger.info({ hosts: ips.length }, "SNMP sweep complete");
  })().catch(err => logger.warn({ err }, "SNMP sweep failed (non-fatal)"));

  // Step 4: NetBIOS sweep
  const netbiosPromise = (async () => {
    const ips = Array.from(deviceMap.keys());
    for (let i = 0; i < ips.length; i += 20) {
      const batch = ips.slice(i, i + 20);
      const results = await Promise.all(batch.map(ip => netbiosQuery(ip)));
      for (const r of results) {
        if (r.name) {
          const dev = deviceMap.get(r.ip);
          if (dev) {
            dev.netbiosName = r.name;
            if (r.mac && !dev.macAddress) dev.macAddress = r.mac;
            if (!dev.discoveryMethods.includes("netbios")) dev.discoveryMethods.push("netbios");
          }
        }
      }
    }
    if (Array.from(deviceMap.values()).some(d => d.netbiosName)) discoveryMethods.push("netbios");
    logger.info({ hosts: ips.length }, "NetBIOS sweep complete");
  })().catch(err => logger.warn({ err }, "NetBIOS sweep failed (non-fatal)"));

  // Wait for all enrichment steps
  await Promise.all([mdnsPromise, snmpPromise, netbiosPromise]);

  // Step 5: Infer device types from all collected data
  const devices = Array.from(deviceMap.values()).map(dev => ({
    ...dev,
    deviceType: inferDeviceType(dev),
  }));

  logger.info({
    subnet: targetSubnet,
    total: devices.length,
    methods: discoveryMethods,
  }, "Internal network scan complete");

  return { devices, subnet: targetSubnet, discoveryMethods };
}
