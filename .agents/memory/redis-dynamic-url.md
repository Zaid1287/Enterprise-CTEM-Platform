---
name: Redis dynamic URL + BullMQ worker lifecycle
description: How Redis URL is loaded from platform_settings on startup and how workers restart dynamically when admin saves a new URL
---

## Rule
Redis URL comes from two sources (priority order):
1. `process.env.REDIS_URL` (env var / Replit secret)
2. `platform_settings.redis_url` (read via `loadRedisUrlFromPlatformSettings()` on startup)

`setRuntimeRedisUrl(url)` sets both the runtime var AND `process.env.REDIS_URL`. `getActiveRedisUrl()` checks `process.env.REDIS_URL ?? _runtimeRedisUrl`.

## Startup sequence (index.ts)
1. `seedPlatformOnStartup()` seeds DB defaults
2. `loadRedisUrlFromPlatformSettings()` reads `redis_url` from DB and calls `setRuntimeRedisUrl(url)` if found
3. `getRedis()` initializes ioredis connection
4. `startWorkersIfRedisAvailable()` starts BullMQ scan + alert workers only if Redis URL is set
5. Without Redis URL → graceful in-process fallback; no crash

## TLS
`rediss://` prefix → ioredis gets `tls: {}` option automatically in `buildConnection()`. Upstash requires `rediss://` (double-s) scheme.

## Hot restart (POST /api/platform/workers/restart)
1. Reads `redis_url` from platform_settings
2. Calls `reinitRedis(url)` which quits old connection, calls `setRuntimeRedisUrl(url)`, inits new ioredis
3. Calls `restartScanWorker()` + `restartAlertWorker()` (stop old worker, start new with stored `_port`)

**Why:** Redis URL often set via Platform Settings UI after deployment (not known at container start). Workers need to pick up the new URL without a container restart.

## BullMQ connection pattern
Each worker and queue gets its own dedicated ioredis connection via `makeBullConnection()` with `maxRetriesPerRequest: null` (required by BullMQ spec). The cache Redis (`getRedis()`) uses `maxRetriesPerRequest: 3`.

## scanWorker._port
`startScanWorker(port)` always stores `_port = port` BEFORE checking Redis URL. This means `restartScanWorker()` → `startScanWorker(_port)` always has the correct port even if the initial call returned early due to no Redis URL.
