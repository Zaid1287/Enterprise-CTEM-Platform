---
name: TanStack Query queryKey required in hook options
description: Some generated hooks require queryKey in the query options object or TypeScript errors block Vite HMR.
---

Hooks like `useGetToolRun` have a required `queryKey` field in their `query` options object (not optional). Passing only `{ enabled: bool }` causes a TS2741 error that Vite treats as a module syntax failure, breaking HMR for the entire file.

**Why:** The generated `UseQueryOptions` type requires `queryKey` to be set. Older usage patterns that omit it silently break when @tanstack/query-core is updated.

**How to apply:** Always use the matching `getXxxQueryKey()` helper alongside `enabled`:
```typescript
const { data } = useGetToolRun(id ?? 0, {
  query: { enabled: !!id, queryKey: getGetToolRunQueryKey(id ?? 0) },
});
```
