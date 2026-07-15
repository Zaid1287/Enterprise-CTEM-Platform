import { useState, useMemo } from "react";
import {
  useListRiskScores, getListRiskScoresQueryKey,
  useGetTopRiskyAssets, getGetTopRiskyAssetsQueryKey,
  useListAssets, getListAssetsQueryKey,
} from "@workspace/api-client-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend,
} from "recharts";
import { useQuery } from "@tanstack/react-query";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn, riskLevelBg, capitalize } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function RiskPage() {
  const { user } = useAuth();
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const [assetFilter, setAssetFilter] = useState<string>("all");
  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";

  const { data: scores, isLoading } = useListRiskScores({
    query: {
      queryKey: [...getListRiskScoresQueryKey(), tenantFilter],
      queryFn: () => apiFetch(`${BASE}/api/risk/scores${isPrivileged && tenantFilter ? `?tenantId=${tenantFilter}` : ""}`),
      staleTime: 0,
      refetchOnWindowFocus: true,
      refetchInterval: 30_000,
    },
  });

  const { data: topRisky } = useGetTopRiskyAssets({ limit: 10 }, {
    query: {
      queryKey: getGetTopRiskyAssetsQueryKey({ limit: 10 }),
      staleTime: 0,
      refetchOnWindowFocus: true,
      refetchInterval: 30_000,
    },
  });

  const { data: assetsRaw } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const assetsList = (assetsRaw as any[]) ?? [];

  // Issue 5: Real historical trend data from /risk/history
  const { data: historyData } = useQuery({
    queryKey: ["risk-history", tenantFilter],
    queryFn: () => apiFetch(`${BASE}/api/risk/history${isPrivileged && tenantFilter ? `?tenantId=${tenantFilter}` : ""}`),
    staleTime: 60_000,
    refetchInterval: 60_000,
  });

  const allScores = (scores as any[]) ?? [];
  // Apply per-asset filter
  const list = useMemo(() => {
    if (assetFilter === "all") return allScores;
    const id = Number(assetFilter);
    return allScores.filter((s: any) => s.assetId === id);
  }, [allScores, assetFilter]);
  const history = historyData as any[] ?? [];
  const levels = ["critical", "high", "medium", "low"];
  const breakdown = levels.map(level => ({
    level, count: list.filter((s: any) => s.level === level).length,
    color: RISK_COLORS[level],
  }));
  const avgScore = list.length > 0 ? list.reduce((s: number, a: any) => s + a.score, 0) / list.length : 0;

  // Format history for chart
  const trendData = history.map((h: any) => ({
    day: new Date(h.day).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
    avgScore: h.avgScore,
    critical: h.critical,
    high: h.high,
    medium: h.medium,
    low: h.low,
  }));

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold">Risk Scoring</h1>
          <p className="text-sm text-muted-foreground">Quantified risk across all assets</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Per-asset filter */}
          {allScores.length > 0 && (
            <Select value={assetFilter} onValueChange={setAssetFilter}>
              <SelectTrigger className="h-8 w-40 text-xs">
                <SelectValue placeholder="All Assets" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Assets</SelectItem>
                {allScores.map((s: any) => (
                  <SelectItem key={s.assetId} value={String(s.assetId)}>{s.assetName}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          {isPrivileged && <TenantFilter value={tenantFilter} onChange={v => { setTenantFilter(v); setAssetFilter("all"); }} />}
        </div>
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
        {/* Bar Chart — top 10 by score */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Top 10 Riskiest Assets</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[...list].sort((a: any, b: any) => b.score - a.score).slice(0, 10)}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" vertical={false} />
              <XAxis dataKey="assetName" tick={{ fill: "#64748b", fontSize: 9 }} tickFormatter={(v) => v.slice(0, 12)} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
              />
              <Bar dataKey="score" radius={[3, 3, 0, 0]} fill="#3b82f6"
                label={false}>
                {[...list].sort((a: any, b: any) => b.score - a.score).slice(0, 10).map((entry: any) => (
                  <rect key={entry.assetId} fill={RISK_COLORS[entry.level] ?? "#64748b"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Overall Risk Gauge */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-2">Overall Risk Level</h3>
          <div className="flex items-center gap-6">
            <div className="relative flex items-center justify-center w-32 h-32">
              <svg viewBox="0 0 36 36" className="w-32 h-32 -rotate-90">
                <circle cx="18" cy="18" r="15.9" fill="none" stroke="hsl(217 33% 17%)" strokeWidth="3" />
                <circle
                  cx="18" cy="18" r="15.9" fill="none"
                  stroke={avgScore >= 80 ? "#ef4444" : avgScore >= 55 ? "#f97316" : avgScore >= 30 ? "#eab308" : "#22c55e"}
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

      {/* Issue 5: Real Risk Trend Chart (powered by risk_score_history) */}
      <div className="bg-card border border-border rounded-xl p-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-medium">Risk Trend (Last 30 Days)</h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              {trendData.length === 0
                ? "Historical data is recorded with each scan and finding status change — data will appear after activity."
                : `${trendData.length} days of real scoring history`}
            </p>
          </div>
        </div>
        {trendData.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-xs text-muted-foreground border border-dashed border-border rounded-lg">
            No history yet — run a scan or change a finding status to start recording
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" vertical={false} />
              <XAxis dataKey="day" tick={{ fill: "#64748b", fontSize: 9 }} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip
                contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
              />
              <Legend wrapperStyle={{ fontSize: "10px" }} />
              <Line type="monotone" dataKey="avgScore" stroke="#3b82f6" strokeWidth={2} dot={false} name="Avg Score" />
              <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={1.5} dot={false} name="Critical" />
              <Line type="monotone" dataKey="high" stroke="#f97316" strokeWidth={1.5} dot={false} name="High" />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Score Table — all components (Issues 2, 3) */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-sm font-medium">Asset Risk Scores — Full Component Breakdown</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Score</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Level</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="Average CVSS × 25 pts">CVSS</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="Max EPSS × 15 pts">EPSS</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="KEV count × 8 pts">KEV</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="Business Impact (1–10) × 20 pts">Biz Impact</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="Highest severity bonus (5–20 pts)">Criticality</th>
                <th className="text-right px-3 py-2.5 text-xs font-medium text-muted-foreground" title="Exposed ports bonus (0–5 pts)">Exposure</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Updated</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(5)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(10)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
                </tr>
              ))}
              {!isLoading && [...list].filter((s: any) => s.score !== null).sort((a: any, b: any) => b.score - a.score).map((s: any) => (
                <tr key={s.assetId} className="border-b border-border/50 hover:bg-accent/30">
                  <td className="px-4 py-2.5 text-sm font-medium max-w-[140px] truncate">{s.assetName}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-14 h-1.5 bg-accent rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${s.score ?? 0}%`, background: RISK_COLORS[s.level] ?? "#64748b" }} />
                      </div>
                      <span className="text-xs font-bold tabular-nums">{s.score != null ? Math.round(s.score) : "—"}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(s.level))}>{s.level ?? "—"}</span>
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.cvssComponent ?? 0).toFixed(1)}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.epssComponent ?? 0).toFixed(1)}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.kevBonus ?? 0).toFixed(0)}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.businessImpactComponent ?? 0).toFixed(1)}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.criticalityBonus ?? 0).toFixed(0)}</td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-right text-muted-foreground">{(s.exposureBonus ?? 0).toFixed(1)}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground whitespace-nowrap">{s.updatedAt ? new Date(s.updatedAt).toLocaleDateString() : "—"}</td>
                </tr>
              ))}
              {!isLoading && list.length === 0 && (
                <tr>
                  <td colSpan={10} className="px-4 py-8 text-center text-xs text-muted-foreground">
                    No risk scores yet — run a scan to populate risk data
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
