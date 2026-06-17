import { getRedis } from "./redis";
import { logger } from "./logger";

const memCache = new Map<string, { value: string; expiresAt: number }>();

const DEFAULT_TTL = 300;

function memGet(key: string): string | null {
  const entry = memCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memCache.delete(key);
    return null;
  }
  return entry.value;
}

function memSet(key: string, value: string, ttl: number): void {
  memCache.set(key, { value, expiresAt: Date.now() + ttl * 1000 });
  if (memCache.size > 500) {
    const now = Date.now();
    for (const [k, v] of memCache) {
      if (now > v.expiresAt) memCache.delete(k);
      if (memCache.size <= 400) break;
    }
  }
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  const redis = getRedis();
  try {
    const raw = redis ? await redis.get(key) : memGet(key);
    if (!raw) return null;
    return JSON.parse(raw) as T;
  } catch (err) {
    logger.warn({ err, key }, "Cache get error");
    return null;
  }
}

export async function cacheSet(key: string, value: unknown, ttl = DEFAULT_TTL): Promise<void> {
  const redis = getRedis();
  const serialized = JSON.stringify(value);
  try {
    if (redis) {
      await redis.setex(key, ttl, serialized);
    } else {
      memSet(key, serialized, ttl);
    }
  } catch (err) {
    logger.warn({ err, key }, "Cache set error");
  }
}

export async function cacheDelete(...patterns: string[]): Promise<void> {
  const redis = getRedis();
  for (const pattern of patterns) {
    try {
      if (redis) {
        const keys = await redis.keys(pattern);
        if (keys.length > 0) await redis.del(...keys);
      } else {
        const glob = pattern.replace(/\*/g, "");
        for (const k of memCache.keys()) {
          if (k.startsWith(glob) || k === pattern) memCache.delete(k);
        }
      }
    } catch (err) {
      logger.warn({ err, pattern }, "Cache delete error");
    }
  }
}

export function ck(...parts: (string | number)[]): string {
  return parts.join(":");
}
