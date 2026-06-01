---
name: CTEM auth flow
description: How JWT auth works in this app — tokens, storage, injection
---

Auth is JWT-based (not cookies). Access token (15min) + refresh token (7d).

**Storage:** `sessionStorage` keys:
- `ctem_token` — access token
- `ctem_refresh_token` — refresh token
- `ctem_user` — serialized AuthUser JSON

**Injection:** `setAuthTokenGetter(() => token)` from `@workspace/api-client-react` wires the token into every `customFetch` call automatically. Called from `lib/auth.ts:setToken()`.

**State:** Zustand store at `artifacts/ctem-platform/src/hooks/useAuth.ts`. Initializes from sessionStorage on load.

**Protected routes:** `<ProtectedRoute>` in `App.tsx` checks `isAuthenticated`, redirects to `/login` if false.

**Why:** Browser sessionStorage keeps credentials scoped to the tab (cleared on close) without the CSRF attack surface of cookies. The `customFetch` injection pattern means all generated hooks get auth automatically.
