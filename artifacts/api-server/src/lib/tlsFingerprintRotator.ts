/**
 * tlsFingerprintRotator.ts
 *
 * TLS + TCP-layer fingerprint rotation for the scan orchestrator.
 *
 * ── WHY THIS MATTERS ──────────────────────────────────────────────────────────
 * Even when HTTP headers (User-Agent, Accept, Sec-CH-UA) are rotated perfectly,
 * a WAF can still fingerprint the client via:
 *
 *   JA3 hash  — derived from the TLS ClientHello: TLS version, cipher suite
 *               order, extensions list, elliptic curves, and EC point formats.
 *               Every browser has a distinctive JA3; a scanner that never
 *               changes its cipher ordering is trivially identified.
 *
 *   TCP profile — socket-level settings that vary by OS:
 *                 Windows   TTL=128  keepAlive=7200s  MSS=1460  window=65535
 *                 Linux     TTL=64   keepAlive=7200s  MSS=1460  window=29200
 *                 macOS     TTL=64   keepAlive=7200s  MSS=1460  window=65535
 *               Node.js exposes keepAlive delay and TCP_NODELAY; TTL/MSS/window
 *               are kernel-level and cannot be varied from userspace (no public
 *               Node.js API) — we vary what we can.
 *
 * ── WHAT WE IMPLEMENT ────────────────────────────────────────────────────────
 * 4 TLS profiles based on real browser ClientHello cipher orderings:
 *   chrome_120  — Chrome 120 on Windows
 *   firefox_121 — Firefox 121 on Windows
 *   safari_17   — Safari 17 on macOS Sonoma
 *   edge_120    — Edge 120 on Windows
 *
 * Each profile also sets keepAlive delay and noDelay to match the OS the browser
 * would run on, giving a consistent TCP + TLS fingerprint combination.
 *
 * undici's Agent accepts a `connect` function that receives the raw socket;
 * we use buildConnector({ ciphers, ... }) to set the cipher suite ordering at
 * the TLS layer and then configure the socket before the callback fires.
 */

import { buildConnector, Agent } from "undici";
import { resolveWithRotation } from "./dnsResolverPool.js";

export interface TlsProfile {
  id: string;
  label: string;
  /** OpenSSL colon-separated cipher string */
  ciphers: string;
  minVersion: "TLSv1.2" | "TLSv1.3";
  /** Emulates the OS TCP keepalive initial delay (ms) */
  keepAliveInitialDelay: number;
  /** TCP_NODELAY — false = Nagle enabled (Windows default); true = no buffering */
  noDelay: boolean;
}

export const TLS_PROFILES: TlsProfile[] = [
  {
    id: "chrome_120",
    label: "Chrome 120 / Windows",
    // Real Chrome 120 cipher preference order (OpenSSL names)
    ciphers: [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      "ECDHE-RSA-CHACHA20-POLY1305",
      "ECDHE-RSA-AES128-SHA",
      "ECDHE-RSA-AES256-SHA",
      "AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "AES128-SHA",
      "AES256-SHA",
    ].join(":"),
    minVersion: "TLSv1.2",
    keepAliveInitialDelay: 0,
    noDelay: false,
  },
  {
    id: "firefox_121",
    label: "Firefox 121 / Windows",
    // Firefox 121 prefers CHACHA20 before AES-256; ECDSA before RSA for some suites
    ciphers: [
      "TLS_AES_128_GCM_SHA256",
      "TLS_CHACHA20_POLY1305_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      "ECDHE-RSA-CHACHA20-POLY1305",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES256-CBC-SHA",
      "ECDHE-ECDSA-AES128-CBC-SHA",
      "ECDHE-RSA-AES128-CBC-SHA",
      "ECDHE-RSA-AES256-CBC-SHA",
      "AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "AES128-SHA",
      "AES256-SHA",
    ].join(":"),
    minVersion: "TLSv1.2",
    keepAliveInitialDelay: 0,
    noDelay: true,
  },
  {
    id: "safari_17",
    label: "Safari 17 / macOS Sonoma",
    // Safari 17 prefers AES-256 before AES-128 (opposite of Chrome)
    ciphers: [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES256-CBC-SHA384",
      "ECDHE-ECDSA-AES128-CBC-SHA256",
      "ECDHE-RSA-AES256-CBC-SHA384",
      "ECDHE-RSA-AES128-CBC-SHA256",
      "ECDHE-ECDSA-AES256-CBC-SHA",
      "ECDHE-ECDSA-AES128-CBC-SHA",
      "ECDHE-RSA-AES256-CBC-SHA",
      "ECDHE-RSA-AES128-CBC-SHA",
      "AES256-GCM-SHA384",
      "AES128-GCM-SHA256",
      "AES256-CBC-SHA256",
      "AES128-CBC-SHA256",
      "AES256-CBC-SHA",
      "AES128-CBC-SHA",
    ].join(":"),
    minVersion: "TLSv1.2",
    keepAliveInitialDelay: 15_000,  // macOS TCP keepalive fires faster
    noDelay: true,
  },
  {
    id: "edge_120",
    label: "Edge 120 / Windows",
    // Edge 120 — Chromium engine, but RSA-before-ECDSA for some suites
    ciphers: [
      "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-CHACHA20-POLY1305",
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      "ECDHE-RSA-AES128-SHA",
      "ECDHE-RSA-AES256-SHA",
      "AES128-GCM-SHA256",
      "AES256-GCM-SHA384",
      "AES128-SHA",
      "AES256-SHA",
    ].join(":"),
    minVersion: "TLSv1.2",
    keepAliveInitialDelay: 0,
    noDelay: false,
  },
];

// ── Per-tenant TLS profile index ──────────────────────────────────────────────
// Round-robins through profiles per tenant so consecutive requests from the
// same scan don't reuse the same TLS fingerprint.
const _tlsProfileIndex = new Map<number, number>();

export function getNextTlsProfile(tenantId: number): TlsProfile {
  const idx = (_tlsProfileIndex.get(tenantId) ?? 0) % TLS_PROFILES.length;
  _tlsProfileIndex.set(tenantId, idx + 1);
  return TLS_PROFILES[idx]!;
}

export function getRandomTlsProfile(excludeId?: string): TlsProfile {
  const pool = excludeId ? TLS_PROFILES.filter(p => p.id !== excludeId) : TLS_PROFILES;
  const candidates = pool.length > 0 ? pool : TLS_PROFILES;
  return candidates[Math.floor(Math.random() * candidates.length)]!;
}

/**
 * Build an undici Agent that routes DNS through the rotating pool AND applies
 * the given TLS cipher profile to every TLS handshake.
 *
 * This replaces `_dnsRotationAgent` as the default dispatcher so that every
 * request gets both DNS rotation AND a unique TLS fingerprint.
 */
export function buildTlsDispatcher(profile: TlsProfile): Agent {
  const connector = buildConnector({
    ciphers:    profile.ciphers,
    minVersion: profile.minVersion,
    rejectUnauthorized: false,  // scanner context — self-signed certs are valid targets
  });

  return new Agent({
    connect: (opts: any, callback: any) => {
      const originalHostname: string = opts.hostname ?? "";

      // Apply TCP socket settings before callback fires
      const wrappedCallback = (err: Error | null, socket: any) => {
        if (!err && socket && typeof socket.setKeepAlive === "function") {
          socket.setKeepAlive(true, profile.keepAliveInitialDelay);
          socket.setNoDelay(profile.noDelay);
        }
        callback(err, socket);
      };

      // DNS rotation — resolve hostname through the pool, preserve SNI
      if (!originalHostname || /^\d{1,3}(\.\d{1,3}){3}$/.test(originalHostname) || originalHostname.includes(":")) {
        connector(opts, wrappedCallback);
        return;
      }

      resolveWithRotation(originalHostname)
        .then(ips => {
          if (ips.length > 0) {
            opts.servername = opts.servername || originalHostname;
            opts.hostname   = ips[Math.floor(Math.random() * ips.length)];
          }
          connector(opts, wrappedCallback);
        })
        .catch(() => connector(opts, wrappedCallback));
    },
  });
}

/**
 * Build an undici Agent that routes through a SOCKS4/SOCKS5 proxy and also
 * applies the TLS cipher profile.  Requires the `socks` package.
 */
export async function buildSocksDispatcher(
  socksHost: string,
  socksPort: number,
  socksType: 4 | 5,
  username?: string | null,
  password?: string | null,
  tlsProfile?: TlsProfile,
): Promise<Agent> {
  const { SocksClient } = await import("socks");
  const tls = await import("tls");

  const ciphers = tlsProfile?.ciphers;
  const keepAliveDelay = tlsProfile?.keepAliveInitialDelay ?? 0;
  const noDelay = tlsProfile?.noDelay ?? false;

  return new Agent({
    connect: async (opts: any, callback: any) => {
      try {
        const port = parseInt(String(opts.port ?? (opts.protocol === "https:" ? 443 : 80)));

        const { socket: rawSocket } = await SocksClient.createConnection({
          proxy: {
            host:     socksHost,
            port:     socksPort,
            type:     socksType,
            ...(username ? { userId: username, password: password ?? "" } : {}),
          },
          command:     "connect",
          destination: { host: opts.hostname as string, port },
        });

        rawSocket.setKeepAlive(true, keepAliveDelay);
        rawSocket.setNoDelay(noDelay);

        if (opts.protocol === "https:") {
          const tlsSocket = tls.connect({
            socket:             rawSocket,
            servername:         opts.servername || opts.hostname,
            rejectUnauthorized: false,
            ...(ciphers ? { ciphers } : {}),
          });
          tlsSocket.once("secureConnect", () => callback(null, tlsSocket));
          tlsSocket.once("error", (e: Error) => callback(e, null));
        } else {
          callback(null, rawSocket);
        }
      } catch (err) {
        callback(err as Error, null);
      }
    },
  });
}
