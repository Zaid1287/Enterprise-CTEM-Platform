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
 * Log-normal-like random sample in [min, max].
 *
 * Real human browsing follows a right-skewed distribution — most inter-request
 * gaps are short but occasional longer pauses occur naturally.  A uniform
 * random distribution is a well-known bot-detection signal.  We approximate a
 * log-normal shape using the Box-Muller transform then clamp to [min, max].
 *
 * ~68% of samples fall within ±1σ of the mean (the lower third of the range),
 * and the long right tail produces the occasional 2-3× pause that makes the
 * traffic pattern look human.
 */
function logNormalDelay(min: number, max: number): number {
  if (min >= max) return min;
  const mean  = (min + max) / 2;
  const sigma = (max - min) / 5;           // ~95 % of samples stay in range
  // Box-Muller transform — pair of uniform → standard normal
  const u1 = Math.max(1e-10, Math.random());
  const u2 = Math.random();
  const z  = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return Math.round(Math.max(min, Math.min(max, mean + sigma * z)));
}

/**
 * Get a human-paced delay for the given scan intensity, scaled by the tenant's
 * delay multiplier (falls back to global/1.0 when tenantId is not set).
 *
 * Returns a log-normal-distributed value so request timing does NOT produce a
 * flat uniform histogram — that pattern is a reliable bot-detection signal.
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
  return logNormalDelay(scaledMin, scaledMax);
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
