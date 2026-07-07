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

// Multiplier applied to all delay ranges.  1.0 = default (no change).
// >1.0 = slower (more stealth); <1.0 = faster (less stealth, not recommended).
// Clamped to [0.1, 10.0] so operators can't accidentally set 0 or a runaway value.
// Updated by scanOrchestrator after reading `scan_delay_multiplier` from
// orchestrator_config on every config load cycle (TTL = 60 s).
let _delayMultiplier = 1.0;

export function setDelayMultiplier(multiplier: number): void {
  _delayMultiplier = Math.max(0.1, Math.min(10.0, multiplier));
}

export function getDelay(intensity: ScanIntensity = "endpoint-discovery"): number {
  const [min, max] = DELAY_RANGES[intensity] ?? DELAY_RANGES["endpoint-discovery"];
  const scaledMin = Math.round(min * _delayMultiplier);
  const scaledMax = Math.round(max * _delayMultiplier);
  return Math.floor(scaledMin + Math.random() * (scaledMax - scaledMin));
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
