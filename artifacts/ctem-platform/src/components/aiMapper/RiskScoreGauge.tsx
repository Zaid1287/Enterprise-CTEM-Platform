import { cn } from "@/lib/utils";

interface Props {
  score: number;
  size?: "sm" | "md" | "lg";
  factors?: Array<{ label: string; value: string; highlight?: "bad" | "good" | "warn" | "neutral" }>;
}

const SIZE_CONFIG = {
  sm: { px: 80,  r: 30, sw: 5, fs: 13, textY: -2 },
  md: { px: 120, r: 46, sw: 7, fs: 18, textY: -4 },
  lg: { px: 160, r: 62, sw: 9, fs: 24, textY: -6 },
};

export function RiskScoreGauge({ score, size = "md", factors }: Props) {
  const { px, r, sw, fs, textY } = SIZE_CONFIG[size];
  const cx = px / 2;
  const cy = px / 2;
  const circ = 2 * Math.PI * r;
  const arc = circ * 0.5;
  const pct  = Math.min(1, Math.max(0, score / 10));
  const dash = arc * pct;
  const gap  = circ - dash;
  const vbH  = cy + sw + 6;

  const color =
    score >= 9 ? "#ef4444" :
    score >= 7 ? "#f97316" :
    score >= 4 ? "#eab308" :
                 "#22c55e";

  const label =
    score >= 9 ? "CRITICAL" :
    score >= 7 ? "HIGH"     :
    score >= 4 ? "MEDIUM"   :
                 "LOW";

  const HIGHLIGHT_COLOR: Record<string, string> = {
    bad:     "text-red-400",
    warn:    "text-orange-400",
    good:    "text-green-400",
    neutral: "text-muted-foreground",
  };

  return (
    <div className="flex flex-col items-center gap-1 w-full">
      <svg width={px} height={vbH} viewBox={`0 0 ${px} ${vbH}`}>
        <circle
          cx={cx} cy={cy} r={r}
          fill="none" stroke="#334155" strokeWidth={sw}
          strokeDasharray={`${arc} ${circ - arc}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
        />
        <circle
          cx={cx} cy={cy} r={r}
          fill="none" stroke={color} strokeWidth={sw}
          strokeDasharray={`${dash} ${gap}`}
          strokeDashoffset={0}
          strokeLinecap="round"
          transform={`rotate(180 ${cx} ${cy})`}
          style={{ transition: "stroke-dasharray 0.4s ease" }}
        />
        <text
          x={cx} y={cy + textY}
          textAnchor="middle" dominantBaseline="middle"
          fontSize={fs} fontWeight="700" fill={color}
        >
          {score.toFixed(1)}
        </text>
      </svg>
      <span className={cn("text-xs font-semibold tracking-wide", {
        "text-red-400":    score >= 9,
        "text-orange-400": score >= 7 && score < 9,
        "text-yellow-400": score >= 4 && score < 7,
        "text-green-400":  score < 4,
      })}>
        {label}
      </span>
      {factors && factors.length > 0 && (
        <div className="w-full mt-2 space-y-1">
          {factors.map(f => (
            <div key={f.label} className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{f.label}</span>
              <span className={cn("font-medium", HIGHLIGHT_COLOR[f.highlight ?? "neutral"])}>
                {f.value}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
