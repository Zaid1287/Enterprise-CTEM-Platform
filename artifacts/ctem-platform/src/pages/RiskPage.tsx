import {
  useListRiskScores, getListRiskScoresQueryKey,
  useGetTopRiskyAssets, getGetTopRiskyAssetsQueryKey,
} from "@workspace/api-client-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  RadialBarChart, RadialBar, Cell,
} from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, riskLevelBg, capitalize } from "@/lib/utils";

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

export default function RiskPage() {
  const { data: scores, isLoading } = useListRiskScores({
    query: { queryKey: getListRiskScoresQueryKey() },
  });
  const { data: topRisky } = useGetTopRiskyAssets({ limit: 10 }, {
    query: { queryKey: getGetTopRiskyAssetsQueryKey({ limit: 10 }) },
  });

  const list = scores as any[] ?? [];
  const levels = ["critical", "high", "medium", "low"];
  const breakdown = levels.map(level => ({
    level, count: list.filter((s: any) => s.level === level).length,
    color: RISK_COLORS[level],
  }));
  const avgScore = list.length > 0 ? list.reduce((s: number, a: any) => s + a.score, 0) / list.length : 0;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Risk Scoring</h1>
        <p className="text-sm text-muted-foreground">Quantified risk across all assets</p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {breakdown.map(({ level, count, color }) => (
          <div key={level} className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">{capitalize(level)} Risk</p>
            <p className="text-2xl font-bold tabular-nums" style={{ color }}>{count}</p>
            <p className="text-xs text-muted-foreground mt-1">assets</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Bar Chart */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Risk Distribution by Asset</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={list.sort((a: any, b: any) => b.score - a.score).slice(0, 10)}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" vertical={false} />
              <XAxis dataKey="assetName" tick={{ fill: "#64748b", fontSize: 9 }} tickFormatter={(v) => v.slice(0, 12)} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
              />
              <Bar dataKey="score" radius={[3, 3, 0, 0]}>
                {list.sort((a: any, b: any) => b.score - a.score).slice(0, 10).map((entry: any) => (
                  <Cell key={entry.assetId} fill={RISK_COLORS[entry.level] ?? "#64748b"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Risk Breakdown Donut */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-2">Overall Risk Level</h3>
          <div className="flex items-center gap-6">
            <div className="relative flex items-center justify-center w-32 h-32">
              <svg viewBox="0 0 36 36" className="w-32 h-32 -rotate-90">
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(217 33% 17%)" strokeWidth="3" />
                <circle
                  cx="18" cy="18" r="15.9" fill="none"
                  stroke={avgScore >= 70 ? "#ef4444" : avgScore >= 40 ? "#f97316" : "#22c55e"}
                  strokeWidth="3"
                  strokeDasharray={`${avgScore} ${100 - avgScore}`}
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute text-center">
                <p className="text-2xl font-bold tabular-nums">{Math.round(avgScore)}</p>
                <p className="text-[10px] text-muted-foreground">avg risk</p>
              </div>
            </div>
            <div className="space-y-2 flex-1">
              {breakdown.map(({ level, count, color }) => (
                <div key={level} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-sm" style={{ background: color }} />
                    <span className="capitalize text-muted-foreground">{level}</span>
                  </div>
                  <span className="font-medium tabular-nums">{count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Score Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-sm font-medium">Asset Risk Scores</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk Score</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Level</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">CVSS</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">EPSS</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">KEV Bonus</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Updated</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(7)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && list.sort((a: any, b: any) => b.score - a.score).map((s: any) => (
              <tr key={s.id} className="border-b border-border/50 hover:bg-accent/30">
                <td className="px-4 py-2.5 text-sm font-medium">{s.assetName}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2">
                    <div className="w-16 h-1.5 bg-accent rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${s.score}%`, background: RISK_COLORS[s.level] ?? "#64748b" }} />
                    </div>
                    <span className="text-xs font-bold tabular-nums">{Math.round(s.score)}</span>
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(s.level))}>{s.level}</span>
                </td>
                <td className="px-4 py-2.5 text-xs tabular-nums text-muted-foreground">{s.cvssComponent.toFixed(1)}</td>
                <td className="px-4 py-2.5 text-xs tabular-nums text-muted-foreground">{s.epssComponent.toFixed(1)}</td>
                <td className="px-4 py-2.5 text-xs tabular-nums text-muted-foreground">{s.kevBonus.toFixed(0)}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{new Date(s.updatedAt).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
