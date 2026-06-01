---
name: Orval mutation wrapper pattern
description: Orval-generated mutations require a { data: ... } wrapper, not raw objects
---

When Orval generates mutation hooks from OpenAPI request bodies, the `mutateAsync` / `mutate` call must use a `{ data: BodyType<T> }` wrapper:

```ts
// CORRECT
await loginMutation.mutateAsync({ data: { email, password } });

// WRONG — TS2353 error
await loginMutation.mutateAsync({ email, password });
```

Mutations with no body (e.g. logout) take `void` — call with no arguments:
```ts
await logoutMutation.mutateAsync();   // CORRECT
await logoutMutation.mutateAsync({}); // WRONG — TS2345
```

**Why:** Orval wraps body params to allow per-request customization (request interceptors, etc.). This is a fixed convention in the generated code — do not fight it.

**How to apply:** Any time you write a new page that calls a generated mutation, always check the generated signature in `lib/api-client-react/src/generated/api.ts` for the exact variables type before writing the call.
