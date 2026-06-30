import Redis from "ioredis";
import { logger } from "./logger";

let _cacheRedis: Redis | null = null;
let _initialized = false;

let _runtimeRedisUrl: string | null = null;

export function setRuntimeRedisUrl(url: string): void {
  _runtimeRedisUrl = url;
  if (!process.env.REDIS_URL) {
    process.env.REDIS_URL = url;
  }
}

export function getActiveRedisUrl(): string | null {
  return process.env.REDIS_URL ?? _runtimeRedisUrl ?? null;
}

function buildConnection(url: string, maxRetriesPerRequest: number | null = 3): Redis {
  const isTls = url.startsWith("rediss://");
  const conn = new Redis(url, {
    maxRetriesPerRequest,
    enableReadyCheck: false,
    lazyConnect: true,
    retryStrategy: (times: number) => Math.min(times * 500, 5000),
    ...(isTls ? { tls: {} } : {}),
  });

  conn.on("connect", () => logger.info("Redis connected"));
  conn.on("ready", () => logger.info("Redis ready"));
  conn.on("error", (err: Error) => logger.warn({ err: err.message }, "Redis error"));
  conn.on("close", () => logger.info("Redis connection closed"));

  return conn;
}

export function getRedis(): Redis | null {
  if (!_initialized) {
    _initialized = true;
    const url = getActiveRedisUrl();
    if (url) {
      _cacheRedis = buildConnection(url, 3);
      _cacheRedis.connect().catch(() => {});
    } else {
      logger.info("No Redis URL — Redis cache disabled, using in-memory fallback");
    }
  }
  return _cacheRedis;
}

export async function reinitRedis(url: string): Promise<void> {
  if (_cacheRedis) {
    await _cacheRedis.quit().catch(() => {});
    _cacheRedis = null;
  }
  _initialized = false;
  setRuntimeRedisUrl(url);
  getRedis();
}

export function makeBullConnection(): Redis | null {
  const url = getActiveRedisUrl();
  if (!url) return null;
  const conn = buildConnection(url, null);
  conn.connect().catch(() => {});
  return conn;
}

export function isRedisAvailable(): boolean {
  const r = getRedis();
  return r !== null && (r.status === "ready" || r.status === "connect");
}
