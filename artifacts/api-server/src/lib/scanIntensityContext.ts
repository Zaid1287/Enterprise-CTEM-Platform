import { AsyncLocalStorage } from "async_hooks";
import type { ScanIntensity } from "./delayEngine.js";

const storage = new AsyncLocalStorage<ScanIntensity>();

export function runWithScanIntensity<T>(intensity: ScanIntensity, fn: () => T): T {
  return storage.run(intensity, fn);
}

/**
 * Returns the per-scan intensity set by runWithScanIntensity(),
 * or undefined when called outside a scan execution scope.
 */
export function getCurrentScanIntensity(): ScanIntensity | undefined {
  return storage.getStore();
}
