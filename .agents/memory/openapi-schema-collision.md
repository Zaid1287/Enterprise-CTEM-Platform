---
name: OpenAPI schema name collision with Orval auto-generated param types
description: Schemas named GetXxxParams collide with Orval-generated path param types, causing ambiguous export errors.
---

Orval auto-generates a `GetXxxParams` type for every operation that has path/query parameters (e.g. `getScanAssetReport` → `GetScanAssetReportParams`). If you also define a schema named `GetScanAssetReportParams` in the OpenAPI spec, the api-zod barrel export will fail with "module has already exported a member" ambiguity.

**Why:** Both `generated/api.ts` and `generated/types.ts` export the same name.

**How to apply:** Never define OpenAPI component schemas whose names match the Orval-generated param type naming pattern (`Get{OperationId}Params`, `Get{OperationId}QueryParams`). Path parameters are already defined inline in the endpoint definition — no separate schema is needed.
