# CTEM Platform

Enterprise-grade multi-tenant Continuous Threat Exposure Management platform with 15 security modules.

## Run & Operate

- API server runs automatically via workflow `artifacts/api-server: API Server` (port 8080, proxied at `/api`)
- Frontend runs via workflow `artifacts/ctem-platform: web` (port 23203, proxied at `/`)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL`, `SESSION_SECRET`

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- Frontend: React 19, Vite, Tailwind CSS v4, wouter (routing), Zustand (auth state), TanStack Query, Recharts
- API: Express 5, JWT auth (access + refresh tokens)
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod, drizzle-zod
- API codegen: Orval (OpenAPI → React Query hooks + Zod schemas)
- Build: esbuild (ESM bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — source of truth for all API contracts (all 15 modules)
- `lib/api-client-react/src/generated/api.ts` — generated React Query hooks
- `lib/api-zod/src/generated/api.ts` — generated Zod validation schemas
- `lib/db/src/schema/` — Drizzle ORM table definitions
- `artifacts/api-server/src/routes/` — Express route handlers per module
- `artifacts/ctem-platform/src/pages/` — React page components
- `artifacts/ctem-platform/src/components/layout/` — Sidebar, Navbar, AppLayout

## Architecture decisions

- Contract-first: OpenAPI spec → codegen → hooks. Never write API fetch code by hand.
- JWT bearer tokens stored in sessionStorage, injected via `setAuthTokenGetter` in custom-fetch.
- All mutations use `{ data: ... }` wrapper pattern (Orval codegen convention) — e.g. `mutateAsync({ data: { email, password } })`.
- Multi-tenant: every DB query is scoped by `tenantId` from the JWT. No cross-tenant data leakage.
- Demo seed data is auto-created on registration: 5 assets, 6 findings, risk scores, alerts, compliance controls.

## Product

15 modules: Asset Inventory, Asset Groups, Discovery/Scans, Vulnerability Findings, Risk Scoring, Compliance Management, Alerting, Reports, AI Copilot, Audit Logs, User Management, Tenant Settings, plus Dashboard with charts.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- After editing API server routes, the workflow must restart to rebuild the esbuild bundle.
- Orval mutations wrap body in `{ data: ... }` — do NOT pass raw objects to `mutateAsync`.
- Run `pnpm --filter @workspace/api-spec run codegen` after any OpenAPI spec change.
- The API server listens on port 8080 but is accessed via the proxy at `localhost:80/api`.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
