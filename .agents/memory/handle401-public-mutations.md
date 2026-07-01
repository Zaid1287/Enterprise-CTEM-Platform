---
name: handle401 and public mutations
description: MutationCache.onError fires for all mutations; guard handle401 so login failures don't wipe component error state
---

## Rule
In `handle401` (App.tsx MutationCache.onError), always check `if (!useAuth.getState().isAuthenticated) return` before calling `attemptTokenRefresh()` or `logout()`.

## Why
`MutationCache.onError` fires for ALL mutations, including public ones like login. When login returns 401:
1. The local catch block in `handleSubmit` calls `setError(...)` — correct
2. But `handle401` also fires, calls `logout()`, which updates Zustand state
3. `PublicRoute` subscribes to `isAuthenticated` — Zustand's `set()` triggers a re-render
4. The re-render can unmount/remount `LoginPage`, wiping its local `useState` values including `error`

The guard short-circuits handle401 for unauthenticated contexts so only already-logged-in sessions attempt the refresh flow.

## How to apply
Any time a global mutation error handler (MutationCache.onError) calls auth-state-modifying functions, gate on current authentication status first.
