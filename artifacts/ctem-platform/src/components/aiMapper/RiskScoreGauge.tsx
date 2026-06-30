import { cn } from "@/lib/utils";

interface Props {
  score: number;
  size?: "sm" | "md" | "lg";
}

const SIZE = { sm: 64, md: 96, lg: 128 };

export function RiskScoreGauge({ score, size = "md" }: Props) {
  const px   = SIZE[size];
  const r    = (px / 2) - 8;
  const circ = 2 * Math.PI * r;
  const arc  = circ * 0.75;
  const pct  = Math.min(1, Math.max(0, score / 10));
  const dash = arc * pct;
  const gap  = arc - dash;

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

  const offset = circ * 0.125;

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width={px} height={px} viewBox={`0 0 ${px} ${px}`}>
        {/* background track */}
        <circle
          cx={px / 2} cy={px / 2} r={r}
          fill="none" stroke="#334155" strokeWidth={size === "sm" ? 5 : 7}
          strokeDasharray={`${arc} ${circ - arc}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(135 ${px/2} ${px/2})`}
        />
        {/* value arc */}
        <circle
          cx={px / 2} cy={px / 2} r={r}
          fill="none" stroke={color} strokeWidth={size === "sm" ? 5 : 7}
          strokeDasharray={`${dash} ${gap + circ - arc}`}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform={`rotate(135 ${px/2} ${px/2})`}
          style={{ transition: "stroke-dasharray 0.4s ease" }}
        />
        {/* score text */}
        <text
          x={px / 2} y={px / 2 + 1}
          textAnchor="middle" dominantBaseline="middle"
          fontSize={size === "sm" ? 14 : size === "md" ? 20 : 28}
          fontWeight="700" fill={color}
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
    </div>
  );
}
