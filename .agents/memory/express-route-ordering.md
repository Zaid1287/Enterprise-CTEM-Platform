---
name: Express route ordering in CTEM API server
description: Static sub-paths must be registered before param routes to avoid Express shadowing them.
---

Static route segments must be registered before wildcard/param segments in Express.

Example: `POST /scans/pipeline-run` must be registered (via its own router) before `GET /scans/:scanId`.

**Why:** Express matches routes in registration order. If `/scans/:scanId` is registered first, a request to `/scans/pipeline-run` will match it with `scanId = "pipeline-run"` instead of the intended handler.

**How to apply:** In `artifacts/api-server/src/routes/index.ts`, always add new static-sub-path routers before `scansRouter`. The pipelineScansRouter is already placed before scansRouter for this reason.
