import Redis from "ioredis";
import { logger } from "./logger";

let _cacheRedis: Redis | null = null;
let _initialized = false;

function buildConnection(maxRetriesPerRequest: number | null = 3): Redis | null {
  const url = process.env.REDIS_URL;
  if (!url) return null;

  const conn = new Redis(url, {
    maxRetriesPerRequest,
    enableReadyCheck: false,
    lazyConnect: true,
    retryStrategy: (times: number) => Math.min(times * 500, 5000),
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
    _cacheRedis = buildConnection(3);
    if (_cacheRedis) {
      _cacheRedis.connect().catch(() => {});
    } else {
      logger.info("REDIS_URL not set — Redis cache disabled, using in-memory fallback");
    }
  }
  return _cacheRedis;
}

export function makeBullConnection(): Redis | null {
  const conn = buildConnection(null);
  if (conn) {
    conn.connect().catch(() => {});
  }
  return conn;
}

export function isRedisAvailable(): boolean {
  const r = getRedis();
  return r !== null && (r.status === "ready" || r.status === "connect");
}
