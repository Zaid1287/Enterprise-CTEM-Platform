import * as net from "net";
import * as http from "http";
import { SocksClient } from "socks";
import { logger } from "./logger.js";

export interface ProxyHealthResult {
  reachable: boolean;
  latencyMs: number;
  error?: string;
}

export interface ProxyAuthTestResult {
  reachable: boolean;
  authOk: boolean;
  httpStatus?: number;
  latencyMs: number;
  error?: string;
}

export function pingProxyTcp(ip: string, port: number, timeoutMs = 3000): Promise<ProxyHealthResult> {
  return new Promise(resolve => {
    const start = Date.now();
    const sock = new net.Socket();

    const done = (reachable: boolean, error?: string) => {
      const latencyMs = Date.now() - start;
      sock.destroy();
      resolve({ reachable, latencyMs, error });
    };

    sock.setTimeout(timeoutMs);
    sock.on("connect", () => done(true));
    sock.on("timeout", () => done(false, "timeout"));
    sock.on("error", err => done(false, err.message));
    sock.connect(port, ip);
  });
}

export async function healthCheckProxy(ip: string, port: number): Promise<ProxyHealthResult> {
  try {
    const result = await pingProxyTcp(ip, port, 3000);
    logger.debug({ ip, port, ...result }, "Proxy health check");
    return result;
  } catch (err: any) {
    return { reachable: false, latencyMs: 0, error: err?.message ?? "unknown" };
  }
}

/**
 * Test an HTTP/HTTPS proxy by sending a CONNECT tunnel request.
 * A 200 response means the proxy accepted the credentials and opened the tunnel.
 * A 407 response means authentication failed.
 */
function testHttpProxyAuth(
  ip: string,
  port: number,
  username: string | null,
  password: string | null,
  targetHost: string,
  targetPort: number,
  timeoutMs: number,
  start: number,
): Promise<ProxyAuthTestResult> {
  return new Promise(resolve => {
    const authHeader =
      username && password
        ? `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`
        : undefined;

    const req = http.request({
      host: ip,
      port,
      method: "CONNECT",
      path: `${targetHost}:${targetPort}`,
      headers: authHeader ? { "Proxy-Authorization": authHeader } : {},
      timeout: timeoutMs,
    });

    req.on("connect", (res, socket) => {
      const latencyMs = Date.now() - start;
      socket.destroy();

      const status = res.statusCode ?? 0;
      if (status === 407) {
        resolve({
          reachable: true,
          authOk: false,
          httpStatus: 407,
          latencyMs,
          error: "Proxy authentication failed (407)",
        });
      } else if (status === 200) {
        resolve({ reachable: true, authOk: true, httpStatus: 200, latencyMs });
      } else {
        resolve({
          reachable: true,
          authOk: false,
          httpStatus: status,
          latencyMs,
          error: `Unexpected CONNECT response: ${status}`,
        });
      }
    });

    req.on("error", err => {
      resolve({
        reachable: false,
        authOk: false,
        latencyMs: Date.now() - start,
        error: err.message,
      });
    });

    req.on("timeout", () => {
      req.destroy();
      resolve({ reachable: false, authOk: false, latencyMs: timeoutMs, error: "timeout" });
    });

    req.end();
  });
}

/**
 * Test a SOCKS4/SOCKS5 proxy by establishing a full tunnel to the target host.
 * Successful connection means the proxy accepted the credentials.
 */
async function testSocksProxyAuth(
  ip: string,
  port: number,
  proxyType: string,
  username: string | null,
  password: string | null,
  targetHost: string,
  targetPort: number,
  timeoutMs: number,
  start: number,
): Promise<ProxyAuthTestResult> {
  const socksType = proxyType === "socks4" ? 4 : 5;
  try {
    const proxy: any = { host: ip, port, type: socksType };
    if (username) proxy.userId = username;
    if (password) proxy.password = password;

    const { socket } = await SocksClient.createConnection({
      proxy,
      command: "connect",
      destination: { host: targetHost, port: targetPort },
      timeout: timeoutMs,
    });
    socket.destroy();
    return { reachable: true, authOk: true, latencyMs: Date.now() - start };
  } catch (err: any) {
    const latencyMs = Date.now() - start;
    const msg: string = err?.message ?? "SOCKS connection failed";
    const isAuthErr =
      /auth|username|password|credential|403|rejected/i.test(msg);
    return {
      reachable: !isAuthErr,
      authOk: false,
      latencyMs,
      error: msg,
    };
  }
}

/**
 * Make a real connection through the proxy (with credentials if provided) and
 * report whether authentication succeeded.
 *
 * For HTTP/HTTPS proxies the CONNECT method is used — the proxy's response
 * code (200 vs 407) tells us auth status without needing to reach the target.
 * For SOCKS4/SOCKS5 proxies the socks package establishes the tunnel.
 */
export async function testProxyWithAuth(
  ip: string,
  port: number,
  proxyType: string,
  username: string | null,
  password: string | null,
  testUrl: string,
  timeoutMs = 8000,
): Promise<ProxyAuthTestResult> {
  const start = Date.now();
  try {
    let targetHost: string;
    let targetPort: number;
    try {
      const u = new URL(testUrl);
      targetHost = u.hostname;
      targetPort = u.port
        ? parseInt(u.port, 10)
        : u.protocol === "https:" ? 443 : 80;
    } catch {
      targetHost = "example.com";
      targetPort = 80;
    }

    const type = (proxyType ?? "http").toLowerCase();
    if (type === "socks5" || type === "socks4" || type === "socks") {
      return await testSocksProxyAuth(
        ip, port, type, username, password, targetHost, targetPort, timeoutMs, start,
      );
    }
    return await testHttpProxyAuth(
      ip, port, username, password, targetHost, targetPort, timeoutMs, start,
    );
  } catch (err: any) {
    return {
      reachable: false,
      authOk: false,
      latencyMs: Date.now() - start,
      error: err?.message ?? "unknown",
    };
  }
}
