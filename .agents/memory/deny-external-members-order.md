---
name: denyExternalMembers router ordering
description: router.use(denyExternalMembers) without a path prefix intercepts all requests, so vendor-accessible routers must be registered first in index.ts.
---

## Rule
`router.use(denyExternalMembers)` in any sub-router runs for **every request** passing through that sub-router — not just paths the sub-router owns. When sub-routers are mounted without path prefixes in `index.ts`, any router registered before assetsRouter/findingsRouter that uses this pattern will intercept vendor requests first, returning 403 before the intended router handles them.

## Why
Express calls each `router.use(subRouter)` in registration order. A `router.use(fn)` inside the sub-router without a path prefix matches all paths. `denyExternalMembers` returns 403 immediately for vendor/employee/third_party roles without calling `next()`, ending the request before Express tries later routers.

## How to apply
- `assetsRouter` and `findingsRouter` must appear in `routes/index.ts` **before** any router containing `router.use(denyExternalMembers)` (currently before `usersRouter`).
- When adding a new vendor-accessible router, register it before `usersRouter` in `index.ts`.
- Long-term fix: scope `denyExternalMembers` to path prefixes — e.g. `router.use("/users", denyExternalMembers)` — so it can't intercept foreign paths regardless of registration order.
