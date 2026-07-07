import * as net from "net";
import { logger } from "./logger.js";

export interface ProxyHealthResult {
  reachable: boolean;
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
