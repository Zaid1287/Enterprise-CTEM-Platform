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

export function getDelay(intensity: ScanIntensity = "endpoint-discovery"): number {
  const [min, max] = DELAY_RANGES[intensity] ?? DELAY_RANGES["endpoint-discovery"];
  return Math.floor(min + Math.random() * (max - min));
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
