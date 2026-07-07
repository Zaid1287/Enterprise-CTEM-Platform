export type ScanIntensity =
  | "passive"
  | "endpoint-discovery"
  | "dir-fuzzing"
  | "heavy-enumeration"
  | "vuln-scan";

const DELAY_RANGES: Record<ScanIntensity, [number, number]> = {
  "passive":             [300,  900],
  "endpoint-discovery":  [700,  1800],
  "dir-fuzzing":         [1000, 3000],
  "heavy-enumeration":   [1500, 4000],
  "vuln-scan":           [800,  2000],
};

// ── Per-tenant delay multipliers ────────────────────────────────────────────────
// Key = tenantId (> 0).  tenantId=0 is the "global/fallback" slot used when
// no tenant context is available (e.g. startup code).
// Clamped to [0.1, 10.0] so operators cannot accidentally set 0 or a runaway
// value.  Updated by scanOrchestrator after reading `scan_delay_multiplier`
// from orchestrator_config on every config load cycle (TTL = 60 s).
//
// BUG FIXED: previously a single _delayMultiplier global was shared across all
// tenants — whichever tenant's config loaded last silently overwrote every other
// tenant's setting.  Now each tenant has its own slot in the Map.
const _delayMultipliers = new Map<number, number>();
const DEFAULT_MULTIPLIER = 1.0;

/**
 * Set the delay multiplier for a specific tenant.
 * Pass tenantId=0 (or omit it) to update the global fallback.
 */
export function setDelayMultiplier(multiplier: number, tenantId?: number): void {
  const clamped = Math.max(0.1, Math.min(10.0, multiplier));
  _delayMultipliers.set(tenantId ?? 0, clamped);
}

/**
 * Get a random delay for the given scan intensity, scaled by the tenant's
 * delay multiplier (falls back to global/1.0 when tenantId is not set).
 */
export function getDelay(
  intensity: ScanIntensity = "endpoint-discovery",
  tenantId?: number,
): number {
  const mult = _delayMultipliers.get(tenantId ?? 0)
    ?? _delayMultipliers.get(0)
    ?? DEFAULT_MULTIPLIER;
  const [min, max] = DELAY_RANGES[intensity] ?? DELAY_RANGES["endpoint-discovery"];
  const scaledMin = Math.round(min * mult);
  const scaledMax = Math.round(max * mult);
  return Math.floor(scaledMin + Math.random() * (scaledMax - scaledMin));
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
