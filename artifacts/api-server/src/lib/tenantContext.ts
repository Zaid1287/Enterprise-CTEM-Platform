import { AsyncLocalStorage } from "async_hooks";

const storage = new AsyncLocalStorage<number>();

/**
 * Run fn within an async context tagged with tenantId.
 * All nested async operations (awaits, Promises) inherit the context automatically.
 * The return value is whatever fn() returns (including Promises).
 */
export function runWithTenant<T>(tenantId: number, fn: () => T): T {
  return storage.run(tenantId, fn);
}

/**
 * Read the current tenantId from the async context.
 * Returns undefined when called outside a runWithTenant() scope.
 */
export function getCurrentTenantId(): number | undefined {
  return storage.getStore();
}
