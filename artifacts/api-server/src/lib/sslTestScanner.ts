import { exec } from "child_process";
import { promisify } from "util";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import tls from "tls";
import { logger } from "./logger";

const execAsync = promisify(exec);
const TESTSSL_BIN = "/tmp/security-tools/testssl.sh";

// ── Types ──────────────────────────────────────────────────────────────────────

export interface SslVulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  finding: string;
  description: string;
  remediation: string;
}

export interface SslProtocol {
  name: string;
  enabled: boolean;
}

export interface SslTestResult {
  host: string;
  port: number;
  grade: string;
  protocol: string;
  certValid: boolean;
  certExpiry?: string;
  certSubject?: string;
  certIssuer?: string;
  selfSigned: boolean;
  vulnerabilities: SslVulnerability[];
  cipherSuites: string[];
  protocols: SslProtocol[];
  rawOutput?: string;
  source: "testssl" | "node-tls";
}

// ── Node.js TLS fallback ───────────────────────────────────────────────────────

function nodeJsTlsCheck(host: string, port: number): Promise<Partial<SslTestResult>> {
  return new Promise(resolve => {
    const timeout = setTimeout(() => resolve({}), 10000);
    try {
      const socket = tls.connect({ host, port, rejectUnauthorized: false, timeout: 8000 }, () => {
        clearTimeout(timeout);
        const cert = socket.getPeerCertificate(true);
        const proto = socket.getProtocol() ?? "";
        const cipher = socket.getCipher();
        const selfSigned = cert?.issuer?.CN === cert?.subject?.CN;

        const vulns: SslVulnerability[] = [];
        // Flag weak TLS versions
        if (proto.includes("TLSv1.0") || proto.includes("TLSv1.1")) {
          vulns.push({
            id: "weak_tls_version",
            name: "Weak TLS Version",
            severity: "high",
            finding: proto,
            description: `${proto} is deprecated and vulnerable to POODLE and other downgrade attacks.`,
            remediation: "Disable TLS 1.0 and TLS 1.1. Use TLS 1.2 or 1.3 only.",
          });
        }
        if (selfSigned) {
          vulns.push({
            id: "self_signed_cert",
            name: "Self-Signed Certificate",
            severity: "medium",
            finding: "Certificate is self-signed",
            description: "The TLS certificate is self-signed and not trusted by default clients.",
            remediation: "Use a certificate from a trusted Certificate Authority (e.g. Let's Encrypt).",
          });
        }
        if (cipher?.name && (cipher.name.includes("RC4") || cipher.name.includes("DES") || cipher.name.includes("NULL") || cipher.name.includes("EXPORT"))) {
          vulns.push({
            id: "weak_cipher",
            name: "Weak Cipher Suite",
            severity: "high",
            finding: cipher.name,
            description: `Weak cipher suite in use: ${cipher.name}. May be vulnerable to decryption attacks.`,
            remediation: "Disable weak cipher suites. Use strong AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
          });
        }

        socket.destroy();
        resolve({
          protocol: proto,
          certValid: socket.authorized,
          certExpiry: cert.valid_to,
          certSubject: (Array.isArray(cert.subject?.CN) ? (cert.subject.CN as string[])[0] : cert.subject?.CN as string | undefined) ?? undefined,
          certIssuer: (Array.isArray(cert.issuer?.O) ? (cert.issuer.O as string[])[0] : cert.issuer?.O as string | undefined) ?? (Array.isArray(cert.issuer?.CN) ? (cert.issuer.CN as string[])[0] : cert.issuer?.CN as string | undefined) ?? undefined,
          selfSigned,
          vulnerabilities: vulns,
          cipherSuites: cipher?.name ? [cipher.name] : [],
          protocols: [{ name: proto, enabled: true }],
          source: "node-tls",
        });
      });
      socket.on("error", (err) => {
        clearTimeout(timeout);
        logger.warn({ host, port, err: err.message }, "Node TLS check error");
        resolve({});
      });
    } catch (err) {
      clearTimeout(timeout);
      resolve({});
    }
  });
}

// ── testssl.sh integration ─────────────────────────────────────────────────────

const SEVERITY_MAP: Record<string, SslVulnerability["severity"]> = {
  "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
  "INFO": "info", "OK": "info", "NOT_TESTED": "info",
};

const VULN_IDS = new Set([
  "heartbleed", "ccs", "ticketbleed", "robot", "secure_renegotiation",
  "crime", "breach", "poodle_ssl", "sweet32", "lucky13", "freak",
  "drown", "logjam", "beast", "rc4", "fallback_scsv",
  "tls1_1", "sslv2", "sslv3",
]);

async function runTestssl(host: string, port: number): Promise<Partial<SslTestResult>> {
  if (!fs.existsSync(TESTSSL_BIN)) {
    logger.info({ host, port }, "testssl.sh not found, using Node.js TLS fallback");
    return {};
  }
  const outFile = path.join(os.tmpdir(), `testssl-${host.replace(/\W/g, "_")}-${Date.now()}.json`);
  try {
    await execAsync(
      `bash "${TESTSSL_BIN}" --jsonfile "${outFile}" --quiet --fast --color 0 --no-dns --nodns none ${host}:${port} 2>/dev/null`,
      { timeout: 120_000, env: { ...process.env, HOME: process.env.HOME ?? "/home/runner" } }
    );
    if (!fs.existsSync(outFile)) return {};
    const raw = fs.readFileSync(outFile, "utf8").trim();
    if (!raw.startsWith("[")) return {};
    const data = JSON.parse(raw) as any[];

    const vulns: SslVulnerability[] = [];
    const ciphers: string[] = [];
    const protocols: SslProtocol[] = [];
    let grade = "?";
    let certExpiry: string | undefined;
    let certSubject: string | undefined;
    let certIssuer: string | undefined;
    let certValid = true;
    let selfSigned = false;
    let protocol = "";

    for (const entry of data) {
      const id: string = entry.id ?? "";
      const finding: string = entry.finding ?? "";
      const severity: string = entry.severity ?? "INFO";
      const findingLow = finding.toLowerCase();

      if (id === "overall_grade") { grade = finding; continue; }
      if (id === "cert_validTo" || id === "cert_expirationStatus") { certExpiry = finding; continue; }
      if (id === "cert_subjectCN" || id === "cert_subjectDN") { certSubject = finding; continue; }
      if (id === "cert_caIssuers" || id === "cert_issuerDN") { certIssuer = finding; continue; }
      if (id === "cert_trust") { certValid = !findingLow.includes("not trusted") && !findingLow.includes("failed"); continue; }
      if (id === "cert_chain_of_trust" && findingLow.includes("self")) { selfSigned = true; continue; }
      if (id === "protocol_negotiated" || id === "negotiated_protocol") { protocol = finding; continue; }

      if (id.startsWith("SSLv") || id.startsWith("TLSv") || id.startsWith("TLS1")) {
        const enabled = !findingLow.includes("not offered") && !findingLow.includes("no ") && !findingLow.startsWith("no");
        protocols.push({ name: id.replace(/_/g, "."), enabled });
        if (enabled && (id === "SSLv2" || id === "SSLv3" || id === "TLS1" || id === "TLS1_1")) {
          vulns.push({
            id,
            name: `Deprecated Protocol: ${id.replace(/_/g, ".")}`,
            severity: id.startsWith("SSL") ? "critical" : "high",
            finding,
            description: `${id.replace(/_/g, ".")} is deprecated and vulnerable. Servers should only offer TLS 1.2 and TLS 1.3.`,
            remediation: `Disable ${id.replace(/_/g, ".")} in your TLS configuration. Configure your web server to offer TLS 1.2+ only.`,
          });
        }
        continue;
      }

      if (id.includes("cipher") && finding && !findingLow.includes("none")) {
        const cipherName = finding.split(/\s+/)[0];
        if (cipherName && cipherName.length > 3) ciphers.push(cipherName);
        continue;
      }

      // Vulnerabilities
      const sev = SEVERITY_MAP[severity] ?? "info";
      if (
        (VULN_IDS.has(id.toLowerCase()) || severity === "CRITICAL" || severity === "HIGH" || severity === "MEDIUM") &&
        !findingLow.includes("not vulnerable") &&
        !findingLow.includes("not affected") &&
        !findingLow.startsWith("no ") &&
        finding.trim()
      ) {
        vulns.push({
          id,
          name: id.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase()),
          severity: sev,
          finding,
          description: `TLS vulnerability: ${id} — ${finding}`,
          remediation: "Update TLS configuration. Disable deprecated protocols and weak cipher suites. Enable only TLS 1.2/1.3 with AEAD ciphers.",
        });
      }
    }

    logger.info({ host, port, grade, vulns: vulns.length, ciphers: ciphers.length }, "testssl.sh scan complete");
    return {
      grade, protocol, certValid, certExpiry, certSubject, certIssuer, selfSigned,
      vulnerabilities: vulns,
      cipherSuites: [...new Set(ciphers)].slice(0, 30),
      protocols,
      source: "testssl",
    };
  } catch (err) {
    logger.warn({ host, port, err }, "testssl.sh execution failed");
    return {};
  } finally {
    try { if (fs.existsSync(outFile)) fs.unlinkSync(outFile); } catch {}
  }
}

// ── Main export ────────────────────────────────────────────────────────────────

export async function runSslTest(host: string, port = 443): Promise<SslTestResult> {
  const base: SslTestResult = {
    host, port, grade: "?", protocol: "", certValid: false, selfSigned: false,
    vulnerabilities: [], cipherSuites: [], protocols: [],
    source: "node-tls",
  };

  // Run testssl.sh and Node TLS check in parallel — testssl takes priority when available
  const [testsslResult, nodeResult] = await Promise.allSettled([
    runTestssl(host, port),
    nodeJsTlsCheck(host, port),
  ]);

  const ts = testsslResult.status === "fulfilled" ? testsslResult.value : {};
  const nd = nodeResult.status === "fulfilled" ? nodeResult.value : {};

  // Merge: testssl overrides Node.js; Node.js fills gaps
  return { ...base, ...nd, ...ts, host, port };
}
