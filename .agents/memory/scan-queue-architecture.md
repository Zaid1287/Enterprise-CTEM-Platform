---
name: Scan Queue Architecture
description: How concurrent scan execution is managed — queue, concurrency caps, parallel assets, recovery.
---

# Scan Queue Architecture

## Constants (top of pipelineScans.ts)
- `MAX_CONCURRENT_SCANS = 5` — max scans running simultaneously across all tenants
- `MAX_PARALLEL_ASSETS = 3` — max assets processed in parallel within a single scan

## How it works
- `enqueueAndRun()` — single entry point for all scan execution (pipeline-run + run-now routes)
- `scanQueue: QueueEntry[]` — in-memory FIFO queue
- `activeScans: number` — atomic counter, incremented on dequeue, decremented in finally block
- `drainQueue()` — called after every enqueue and every scan completion; starts as many scans as slots allow
- `processAsset()` — nested async function inside `executePipeline`, handles one asset end-to-end
- `runWithConcurrency()` — runs processAsset calls with MAX_PARALLEL_ASSETS worker pool pattern

## DB status flow
- `pending` — scan inserted while queue is full (willQueue = true)
- `running` — set by drainQueue when a slot opens (startedAt also set then)
- `completed` / `failed` / `cancelled` — terminal states

## Startup recovery
- On server start, any scan stuck as `running` (from a prior crash) is immediately set to `failed`
- This prevents phantom running scans after a restart

## Why this approach
- Each asset scan spawns many child processes (nmap, nuclei, subfinder…); uncapped concurrency = OOM
- Queue is in-memory — if server restarts, queued scans (status=pending) are NOT auto-recovered (they stay pending in DB forever). A future improvement would be to re-enqueue them on startup.
- Worker threads were considered but rejected: executePipeline uses closures, in-memory maps, and shared DB connections that don't serialize into worker_thread message passing.

## Known limitation
- Queue is process-local — won't work with multiple server instances (horizontal scaling). For that, a DB-backed job queue (e.g. pg-boss, BullMQ with Redis) would be needed.
