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
 *                 macOS     TTL=64   keepAlive=15s    MSS=1460  window=65535
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
 * CIPHER STRING NOTE:
 *   The `ciphers` option in Node.js TLS (OpenSSL SSL_CTX_set_cipher_list) only
 *   accepts TLS 1.2 and earlier cipher suite names.  TLS 1.3 cipher names
 *   (TLS_AES_*, TLS_CHACHA20_*) belong to `cipherSuites` (OpenSSL
 *   SSL_CTX_set_ciphersuites).  Mixing them in `ciphers` causes OpenSSL to
 *   silently ignore the TLS 1.3 names — verified in Node.js 24.  JA3
 *   differentiation is achieved entirely via TLS 1.2 cipher suite ordering,
 *   which IS respected.  TLS 1.3 sessions use Node.js defaults for all profiles
 *   (acceptable: OpenSSL cannot reorder TLS 1.3 ciphers anyway).
 *
 * TCP keepAlive values match real OS defaults:
 *   Windows (Chrome/Edge/Firefox): TCP_KEEPIDLE = 7200 s  TCP_NODELAY varies
 *   macOS (Safari):                TCP_KEEPIDLE = 15 s    TCP_NODELAY = true
 */

import { buildConnector, Agent } from "undici";
import { resolveWithRotation } from "./dnsResolverPool.js";

export interface TlsProfile {
  id: string;
  label: string;
  /** OpenSSL colon-separated cipher string — TLS 1.2 suites ONLY */
  ciphers: string;
  minVersion: "TLSv1.2" | "TLSv1.3";
  /**
   * OS TCP keepalive initial delay in ms.
   * Windows default = 7 200 000 ms (2 h); macOS default = 15 000 ms (15 s).
   */
  keepAliveInitialDelay: number;
  /**
   * TCP_NODELAY — disables Nagle's algorithm.
   * false = Nagle ON  (Windows default for most apps)
   * true  = Nagle OFF (macOS / Firefox on Windows)
   */
  noDelay: boolean;
}

export const TLS_PROFILES: TlsProfile[] = [
  {
    id: "chrome_120",
    label: "Chrome 120 / Windows",
    // Chrome 120 TLS 1.2 cipher preference order (OpenSSL names only).
    // ECDSA ciphers before RSA; AES-128 before AES-256.
    ciphers: [
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
    keepAliveInitialDelay: 7_200_000,  // Windows TCP_KEEPIDLE default = 7200 s
    noDelay: false,                    // Nagle ON — Windows Chrome default
  },
  {
    id: "firefox_121",
    label: "Firefox 121 / Windows",
    // Firefox 121 TLS 1.2 order: CHACHA20 before AES-256; ECDSA/RSA interleaved
    // differently from Chrome; also includes CBC suites Chrome dropped.
    ciphers: [
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
    keepAliveInitialDelay: 7_200_000,  // Windows TCP_KEEPIDLE default
    noDelay: true,                     // Firefox sets TCP_NODELAY on Windows
  },
  {
    id: "safari_17",
    label: "Safari 17 / macOS Sonoma",
    // Safari 17 TLS 1.2 order: AES-256 BEFORE AES-128 (opposite of Chrome);
    // includes CBC-SHA256 suites that Chrome removed.
    ciphers: [
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
    keepAliveInitialDelay: 15_000,     // macOS TCP_KEEPIDLE default = 15 s
    noDelay: true,                     // macOS sets TCP_NODELAY by default
  },
  {
    id: "edge_120",
    label: "Edge 120 / Windows",
    // Edge 120 (Chromium) TLS 1.2: RSA-before-ECDSA for GCM suites,
    // distinguishing it from Chrome (ECDSA first).
    ciphers: [
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
    keepAliveInitialDelay: 7_200_000,  // Windows TCP_KEEPIDLE default
    noDelay: false,                    // Edge (Chromium) same as Chrome
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
 * Each profile contains only TLS 1.2 cipher names so OpenSSL correctly sets
 * the TLS 1.2 cipher list.  TLS 1.3 sessions use the Node.js platform default
 * (all three standard AES/CHACHA20 suites), which cannot be reordered anyway.
 *
 * TCP keepAlive and noDelay are applied to the raw socket after each connect
 * to match the OS profile the selected browser would run on.
 */
export function buildTlsDispatcher(profile: TlsProfile): Agent {
  const connector = buildConnector({
    ciphers:            profile.ciphers,
    minVersion:         profile.minVersion,
    rejectUnauthorized: false,  // scanner context — self-signed certs are valid targets
  });

  return new Agent({
    connect: (opts: any, callback: any) => {
      const originalHostname: string = opts.hostname ?? "";

      // Wrap the callback to apply TCP socket options after the socket is ready
      const wrappedCallback = (err: Error | null, socket: any) => {
        if (!err && socket) {
          if (typeof socket.setKeepAlive === "function") {
            socket.setKeepAlive(true, profile.keepAliveInitialDelay);
          }
          if (typeof socket.setNoDelay === "function") {
            socket.setNoDelay(profile.noDelay);
          }
        }
        callback(err, socket);
      };

      // If already an IP address, skip DNS rotation (no hostname to resolve)
      if (
        !originalHostname ||
        /^\d{1,3}(\.\d{1,3}){3}$/.test(originalHostname) ||
        originalHostname.includes(":")
      ) {
        connector(opts, wrappedCallback);
        return;
      }

      // DNS rotation — resolve through the pool, preserve SNI
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
 * Build an undici Agent that routes ALL traffic through a SOCKS4 or SOCKS5
 * proxy and also applies the given TLS cipher profile to HTTPS connections.
 *
 * The SOCKS tunnel is established first via the `socks` package, then TLS is
 * layered on top for HTTPS targets using `tls.connect({ socket })`.
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

  const ciphers         = tlsProfile?.ciphers;
  const keepAliveDelay  = tlsProfile?.keepAliveInitialDelay ?? 7_200_000;
  const noDelay         = tlsProfile?.noDelay ?? false;

  return new Agent({
    connect: (opts: any, callback: any) => {
      const port = parseInt(String(opts.port ?? ""), 10) || (opts.protocol === "https:" ? 443 : 80);

      SocksClient.createConnection({
        proxy: {
          host:    socksHost,
          port:    socksPort,
          type:    socksType,
          ...(username ? { userId: username, password: password ?? "" } : {}),
        },
        command:     "connect",
        destination: { host: opts.hostname as string, port },
      })
        .then(({ socket: rawSocket }) => {
          rawSocket.setKeepAlive(true, keepAliveDelay);
          rawSocket.setNoDelay(noDelay);

          if (opts.protocol === "https:") {
            const tlsSocket = tls.connect({
              socket:             rawSocket,
              servername:         (opts.servername || opts.hostname) as string,
              rejectUnauthorized: false,
              ...(ciphers ? { ciphers } : {}),
            });
            tlsSocket.once("secureConnect", () => callback(null, tlsSocket));
            tlsSocket.once("error",         (e: Error) => callback(e, null));
          } else {
            callback(null, rawSocket);
          }
        })
        .catch((err: Error) => callback(err, null));
    },
  });
}
