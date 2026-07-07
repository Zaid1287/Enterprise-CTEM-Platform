import * as dns from "dns";
import { logger } from "./logger.js";

interface ResolverStats {
  ip: string;
  totalRequests: number;
  failures: number;
  totalLatencyMs: number;
}

const RESOLVERS: ResolverStats[] = [
  { ip: "8.8.8.8",         totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "1.1.1.1",         totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "9.9.9.9",         totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "208.67.222.222",  totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "8.26.56.26",      totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "94.140.14.14",    totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "185.228.168.9",   totalRequests: 0, failures: 0, totalLatencyMs: 0 },
  { ip: "64.6.64.6",       totalRequests: 0, failures: 0, totalLatencyMs: 0 },
];

const MAX_FAILURE_RATE = 0.20;
const MAX_AVG_LATENCY_MS = 2_000;
const TIMEOUT_MS = 5_000;

let roundRobinIndex = 0;

function getHealthyResolvers(): ResolverStats[] {
  return RESOLVERS.filter(r => {
    if (r.totalRequests < 5) return true;
    const failureRate = r.failures / r.totalRequests;
    const avgLatency  = r.totalLatencyMs / r.totalRequests;
    return failureRate <= MAX_FAILURE_RATE && avgLatency <= MAX_AVG_LATENCY_MS;
  });
}

function pickNextResolver(): ResolverStats {
  const healthy = getHealthyResolvers();
  if (healthy.length === 0) return RESOLVERS[0];
  const resolver = healthy[roundRobinIndex % healthy.length];
  roundRobinIndex = (roundRobinIndex + 1) % healthy.length;
  return resolver;
}

function resolveWithResolver(hostname: string, resolverIp: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();
    resolver.setServers([resolverIp]);
    const timer = setTimeout(() => reject(new Error("timeout")), TIMEOUT_MS);
    resolver.resolve4(hostname, (err, addresses) => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(addresses);
    });
  });
}

export async function resolveWithRotation(hostname: string): Promise<string[]> {
  const resolver = pickNextResolver();
  const start = Date.now();
  resolver.totalRequests++;

  try {
    const addresses = await resolveWithResolver(hostname, resolver.ip);
    resolver.totalLatencyMs += Date.now() - start;
    return addresses;
  } catch (err) {
    resolver.failures++;
    resolver.totalLatencyMs += Date.now() - start;
    logger.debug({ hostname, resolver: resolver.ip, err }, "DNS resolver failed — trying fallback");

    const fallbacks = RESOLVERS.filter(r => r.ip !== resolver.ip);
    for (const fb of fallbacks) {
      const fbStart = Date.now();
      try {
        fb.totalRequests++;
        const addresses = await resolveWithResolver(hostname, fb.ip);
        fb.totalLatencyMs += Date.now() - fbStart;
        return addresses;
      } catch {
        fb.failures++;
        fb.totalLatencyMs += Date.now() - fbStart;
      }
    }

    throw new Error(`All DNS resolvers failed for ${hostname}`);
  }
}

function resolveCnameWithResolver(hostname: string, resolverIp: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const resolver = new dns.Resolver();
    resolver.setServers([resolverIp]);
    const timer = setTimeout(() => reject(new Error("timeout")), TIMEOUT_MS);
    resolver.resolveCname(hostname, (err, addresses) => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(addresses);
    });
  });
}

/** Resolve CNAME records using the rotating DNS pool. Returns [] on failure (CNAME is optional). */
export async function resolveCnameWithRotation(hostname: string): Promise<string[]> {
  const resolver = pickNextResolver();
  const start = Date.now();
  resolver.totalRequests++;
  try {
    const addresses = await resolveCnameWithResolver(hostname, resolver.ip);
    resolver.totalLatencyMs += Date.now() - start;
    return addresses;
  } catch {
    resolver.failures++;
    resolver.totalLatencyMs += Date.now() - start;
    const fallbacks = RESOLVERS.filter(r => r.ip !== resolver.ip);
    for (const fb of fallbacks) {
      const fbStart = Date.now();
      try {
        fb.totalRequests++;
        const addresses = await resolveCnameWithResolver(hostname, fb.ip);
        fb.totalLatencyMs += Date.now() - fbStart;
        return addresses;
      } catch {
        fb.failures++;
        fb.totalLatencyMs += Date.now() - fbStart;
      }
    }
    return [];
  }
}

export function getDnsResolverStats(): Array<{ ip: string; totalRequests: number; failures: number; failureRate: number; avgLatencyMs: number; healthy: boolean }> {
  return RESOLVERS.map(r => {
    const failureRate = r.totalRequests > 0 ? r.failures / r.totalRequests : 0;
    const avgLatencyMs = r.totalRequests > 0 ? r.totalLatencyMs / r.totalRequests : 0;
    return {
      ip: r.ip,
      totalRequests: r.totalRequests,
      failures: r.failures,
      failureRate: Math.round(failureRate * 1000) / 1000,
      avgLatencyMs: Math.round(avgLatencyMs),
      healthy: failureRate <= MAX_FAILURE_RATE && avgLatencyMs <= MAX_AVG_LATENCY_MS,
    };
  });
}
