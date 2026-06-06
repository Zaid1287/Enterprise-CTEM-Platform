import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { cn } from "@/lib/utils";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
} from "recharts";
import {
  TrendingUp, TrendingDown, Server, Bug, AlertTriangle, Bell,
  CheckCircle2, ShieldOff, Globe, Flag, XCircle, Clock,
  Loader2, ChevronRight, ShieldAlert, Shield, Activity,
  BarChart2, Layers,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

const TYPE_COLORS = [
  "#6366f1", "#8b5cf6", "#0ea5e9", "#14b8a6", "#f97316",
  "#ec4899", "#22c55e", "#eab308", "#64748b",
];

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  submitted:   { label: "Submitted",   color: "bg-blue-500/15 text-blue-400 border-blue-500/30",   icon: Clock },
  in_progress: { label: "In Progress", color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Loader2 },
  closed:      { label: "Closed",      color: "bg-green-500/15 text-green-400 border-green-500/30", icon: CheckCircle2 },
  rejected:    { label: "Rejected",    color: "bg-red-500/15 text-red-400 border-red-500/30",       icon: XCircle },
};

const TOOLTIP_STYLE = {
  background: "hsl(222 47% 11%)",
  border: "1px solid hsl(217 33% 17%)",
  borderRadius: "8px",
  fontSize: "12px",
};

function categoryColor(score: number) {
  if (score >= 80) return "#22c55e";
  if (score >= 60) return "#eab308";
  if (score >= 40) return "#f97316";
  return "#ef4444";
}

function RiskScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#ef4444" : score >= 60 ? "#f97316" : score >= 40 ? "#eab308" : "#22c55e";
  const label = score >= 80 ? "Critical" : score >= 60 ? "High" : score >= 40 ? "Medium" : "Low";
  const circumference = 2 * Math.PI * 40;
  const dash = (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center py-3">
      <div className="relative w-28 h-28">
        <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
          <circle cx="50" cy="50" r="40" fill="none" stroke="hsl(217 33% 17%)" strokeWidth="10" />
          <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="10"
            strokeDasharray={`${dash} ${circumference - dash}`}
            strokeLinecap="round" style={{ transition: "stroke-dasharray 1s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums" style={{ color }}>{score}</span>
          <span className="text-[10px] text-muted-foreground">/ 100</span>
        </div>
      </div>
      <span className="text-xs font-semibold mt-1" style={{ color }}>{label} Risk</span>
      <span className="text-[10px] text-muted-foreground mt-0.5">Based on your assets</span>
    </div>
  );
}

interface ClickableCardProps {
  label: string;
  value: number | string;
  sub?: string;
  icon: React.ElementType;
  color?: string;
  href: string;
  badge?: { text: string; color: string };
}

function ClickableCard({ label, value, sub, icon: Icon, color = "text-foreground", href, badge }: ClickableCardProps) {
  const [, navigate] = useLocation();
  return (
    <div
      onClick={() => navigate(href)}
      className="bg-card border border-border rounded-xl p-4 cursor-pointer hover:border-primary/40 hover:bg-accent/20 transition-all group"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className={cn("text-2xl font-bold tabular-nums", color)}>{value ?? "—"}</p>
          {sub && <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>}
        </div>
        <div className="w-8 h-8 rounded-lg bg-accent/50 flex items-center justify-center group-hover:bg-primary/10 transition-colors">
          <Icon className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
        </div>
      </div>
      {badge && (
        <div className="mt-2">
          <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold border", badge.color)}>
            {badge.text}
          </span>
        </div>
      )}
      <div className="flex items-center gap-1 mt-2 text-[10px] text-muted-foreground/60 group-hover:text-primary/60 transition-colors">
        <span>View details</span>
        <ChevronRight className="w-3 h-3" />
      </div>
    </div>
  );
}

function SectionCard({ title, href, children, action }: {
  title: string; href?: string; children: React.ReactNode; action?: React.ReactNode;
}) {
  const [, navigate] = useLocation();
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className={cn("px-4 py-3 border-b border-border flex items-center justify-between",
        href && "cursor-pointer hover:bg-accent/20 transition-colors")}
        onClick={href ? () => navigate(href) : undefined}>
        <h3 className="text-sm font-medium">{title}</h3>
        {action ?? (href && (
          <span className="text-xs text-muted-foreground hover:text-primary flex items-center gap-0.5 transition-colors">
            View all <ChevronRight className="w-3 h-3" />
          </span>
        ))}
      </div>
      {children}
    </div>
  );
}

export default function ClientDashboardPage() {
  const [, navigate] = useLocation();

  const { data: d, isLoading } = useQuery<any>({
    queryKey: ["client-overview"],
    queryFn: () => apiFetch(`${BASE}/api/dashboard/client-overview`),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div>
          <Skeleton className="h-6 w-48 mb-1" />
          <Skeleton className="h-4 w-72" />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Skeleton className="h-56 rounded-xl" />
          <Skeleton className="h-56 rounded-xl" />
          <Skeleton className="h-56 rounded-xl" />
        </div>
        <Skeleton className="h-64 rounded-xl" />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-72 rounded-xl" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-72 rounded-xl" />
          <Skeleton className="h-72 rounded-xl" />
        </div>
      </div>
    );
  }

  const openSeverityData = (d?.severityBreakdown ?? []).filter((s: any) => s.count > 0);
  const riskLevels = d?.riskLevels ?? {};
  const riskLevelData = Object.entries(riskLevels)
    .filter(([, v]) => (v as number) > 0)
    .map(([level, count]) => ({ level, count }));

  const fp = d?.falsePositives ?? { submitted: 0, confirmed: 0, rejected: 0 };
  const td = d?.takedowns ?? { total: 0, submitted: 0, inProgress: 0, closed: 0 };

  const scoreTimeline: { date: string; score: number }[] = d?.scoreTimeline ?? [];
  const categoryScores: { id: string; name: string; score: number; findingsCount: number }[] = d?.categoryScores ?? [];
  const topAssetTypes: { type: string; count: number }[] = d?.topAssetTypes ?? [];
  const topVulnerableAssets: any[] = d?.topVulnerableAssets ?? [];
  const topSecurityRisks: any[] = d?.topSecurityRisks ?? [];

  const timelineMin = Math.max(0, Math.min(...scoreTimeline.map(t => t.score)) - 5);
  const timelineMax = Math.min(100, Math.max(...scoreTimeline.map(t => t.score)) + 5);

  const formatTimelineDate = (dateStr: string) => {
    const d = new Date(dateStr);
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold">My Security Status</h1>
        <p className="text-sm text-muted-foreground">Your organization's current threat exposure overview</p>
      </div>

      {/* Row 1: Risk score gauge + key metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
        <div
          className="bg-card border border-border rounded-xl cursor-pointer hover:border-primary/40 hover:bg-accent/20 transition-all"
          onClick={() => navigate("/risk")}
        >
          <RiskScoreGauge score={d?.riskScore ?? 0} />
        </div>

        <ClickableCard
          label="My Assets"
          value={d?.totalAssets ?? 0}
          icon={Server}
          href="/assets"
          sub="Total monitored assets"
        />

        <ClickableCard
          label="Open Findings"
          value={d?.openFindings ?? 0}
          icon={Bug}
          color={d?.openFindings > 0 ? "text-amber-400" : undefined}
          href="/findings"
          sub="Across all assets"
        />

        <ClickableCard
          label="Critical Vulns"
          value={d?.criticalVulns ?? 0}
          icon={AlertTriangle}
          color={d?.criticalVulns > 0 ? "text-red-400" : undefined}
          href="/findings"
          sub="Requires immediate action"
          badge={d?.newVulnsFromLatestScan > 0
            ? { text: `+${d.newVulnsFromLatestScan} new from latest scan`, color: "bg-red-500/15 text-red-400 border-red-500/30" }
            : undefined}
        />

        <ClickableCard
          label="Open Alerts"
          value={d?.openAlerts ?? 0}
          icon={Bell}
          color={d?.openAlerts > 0 ? "text-yellow-400" : undefined}
          href="/alerts"
          sub="Unread notifications"
        />
      </div>

      {/* Row 2: Resolved + Takedowns summary + Open Vulnerabilities */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <ClickableCard
          label="Open Vulnerabilities"
          value={d?.openVulnerabilities ?? 0}
          icon={ShieldAlert}
          color={d?.openVulnerabilities > 0 ? "text-orange-400" : undefined}
          href="/findings"
          sub="Across all assets"
        />
        <ClickableCard
          label="Resolved Vulns"
          value={d?.resolvedVulns ?? 0}
          icon={CheckCircle2}
          color="text-green-400"
          href="/findings"
          sub="Successfully remediated"
        />
        <ClickableCard
          label="Takedown Requests"
          value={td.total}
          icon={ShieldOff}
          href="/takedowns"
          sub={`${td.inProgress} in progress · ${td.closed} closed`}
        />
      </div>

      {/* Score Timeline */}
      <SectionCard title="Score Timeline" action={
        <span className="text-xs text-muted-foreground">30-day risk score trend</span>
      }>
        <div className="p-4">
          {scoreTimeline.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
              <Activity className="w-8 h-8 mb-2" />
              <p className="text-sm">No timeline data yet</p>
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={scoreTimeline} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                <XAxis
                  dataKey="date"
                  tickFormatter={formatTimelineDate}
                  tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }}
                  tickLine={false}
                  axisLine={false}
                  interval={5}
                />
                <YAxis
                  domain={[timelineMin, timelineMax]}
                  tick={{ fontSize: 10, fill: "hsl(215 20% 55%)" }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={TOOLTIP_STYLE}
                  labelFormatter={formatTimelineDate}
                  formatter={(v: any) => [`${v}`, "Risk Score"]}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#6366f1"
                  strokeWidth={2}
                  fill="url(#scoreGrad)"
                  dot={false}
                  activeDot={{ r: 4, fill: "#6366f1" }}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </SectionCard>

      {/* Row 3: Severity pie + Assets at risk + Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Severity Breakdown pie */}
        <SectionCard title="Severity Breakdown" href="/findings"
          action={<span className="text-xs text-muted-foreground">Open vulnerabilities</span>}>
          <div className="p-4">
            {openSeverityData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
                <CheckCircle2 className="w-8 h-8 mb-2" />
                <p className="text-sm">No open vulnerabilities</p>
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={openSeverityData} dataKey="count" nameKey="severity"
                      cx="50%" cy="50%" innerRadius={45} outerRadius={70}>
                      {openSeverityData.map((entry: any) => (
                        <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#64748b"} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={TOOLTIP_STYLE}
                      formatter={(v: any, name: any) => [v, name.charAt(0).toUpperCase() + name.slice(1)]} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="space-y-1.5 mt-1">
                  {openSeverityData.map((s: any) => (
                    <div key={s.severity} className="flex items-center justify-between text-xs cursor-pointer"
                      onClick={() => navigate("/findings")}>
                      <div className="flex items-center gap-2">
                        <div className="w-2.5 h-2.5 rounded-sm" style={{ background: SEVERITY_COLORS[s.severity] }} />
                        <span className="capitalize text-muted-foreground">{s.severity}</span>
                      </div>
                      <span className="font-semibold tabular-nums">{s.count}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </SectionCard>

        {/* Assets at Risk */}
        <SectionCard title="My Assets at Risk" href="/assets">
          <div className="p-4">
            {riskLevelData.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
                <CheckCircle2 className="w-8 h-8 mb-2" />
                <p className="text-sm">All assets healthy</p>
              </div>
            ) : (
              <div className="space-y-3">
                {(["critical", "high", "medium", "low"] as const).map(level => {
                  const count = (riskLevels[level] as number) ?? 0;
                  const total = (Object.values(riskLevels) as number[]).reduce((a, b) => a + b, 0);
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  return (
                    <div key={level} className="cursor-pointer" onClick={() => navigate("/assets")}>
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <div className="w-2.5 h-2.5 rounded-full" style={{ background: RISK_COLORS[level] }} />
                          <span className="text-xs capitalize text-muted-foreground">{level}</span>
                        </div>
                        <span className="text-xs font-semibold tabular-nums">{count} assets</span>
                      </div>
                      <div className="h-1.5 bg-accent rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{ width: `${pct}%`, background: RISK_COLORS[level] }} />
                      </div>
                    </div>
                  );
                })}
                <p className="text-[10px] text-muted-foreground/50 pt-1">
                  {(Object.values(riskLevels) as number[]).reduce((a, b) => a + b, 0)} total assets scored
                </p>
              </div>
            )}
          </div>
        </SectionCard>

        {/* Recent Alerts */}
        <SectionCard title="Recent Alerts" href="/alerts">
          <div className="divide-y divide-border">
            {(d?.recentAlerts ?? []).length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
                <Bell className="w-8 h-8 mb-2" />
                <p className="text-sm">No recent alerts</p>
              </div>
            ) : (d?.recentAlerts ?? []).map((a: any) => (
              <div key={a.id}
                className="flex items-start gap-3 px-4 py-3 hover:bg-accent/20 cursor-pointer transition-colors"
                onClick={() => navigate("/alerts")}>
                <div className={cn("mt-1.5 w-1.5 h-1.5 rounded-full shrink-0",
                  a.severity === "critical" ? "bg-red-400" :
                  a.severity === "high" ? "bg-orange-400" :
                  a.severity === "medium" ? "bg-yellow-400" : "bg-blue-400")} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-medium truncate">{a.title}</p>
                    {!a.isRead && (
                      <div className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                    )}
                  </div>
                  {a.message && (
                    <p className="text-[10px] text-muted-foreground truncate mt-0.5">{a.message}</p>
                  )}
                  <p className="text-[10px] text-muted-foreground/50 mt-0.5">
                    {new Date(a.createdAt).toLocaleDateString()}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>

      {/* Category-Based Risk Scoring */}
      <SectionCard title="Category-Based Risk Scoring" action={
        <span className="text-xs text-muted-foreground">Score out of 100 — higher is safer</span>
      }>
        <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-3">
          {categoryScores.map(cat => {
            const color = categoryColor(cat.score);
            return (
              <div key={cat.id}>
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">{cat.name}</span>
                    {cat.findingsCount > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-accent text-muted-foreground tabular-nums">
                        {cat.findingsCount} finding{cat.findingsCount !== 1 ? "s" : ""}
                      </span>
                    )}
                  </div>
                  <span className="text-xs font-bold tabular-nums" style={{ color }}>{cat.score}</span>
                </div>
                <div className="h-2 bg-accent rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${cat.score}%`, background: color }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </SectionCard>

      {/* Top Asset Types + Top Vulnerable Assets */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Top Asset Types Discovered */}
        <SectionCard title="Top Asset Types Discovered" href="/assets">
          <div className="p-4">
            {topAssetTypes.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
                <Layers className="w-8 h-8 mb-2" />
                <p className="text-sm">No assets tracked yet</p>
              </div>
            ) : (
              <div className="flex gap-4 items-center">
                <div className="shrink-0">
                  <ResponsiveContainer width={140} height={140}>
                    <PieChart>
                      <Pie
                        data={topAssetTypes}
                        dataKey="count"
                        nameKey="type"
                        cx="50%" cy="50%"
                        innerRadius={38}
                        outerRadius={62}
                      >
                        {topAssetTypes.map((_: any, i: number) => (
                          <Cell key={i} fill={TYPE_COLORS[i % TYPE_COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={TOOLTIP_STYLE}
                        formatter={(v: any, name: any) => [v, name]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="flex-1 space-y-2 min-w-0">
                  {topAssetTypes.map((t: any, i: number) => {
                    const total = topAssetTypes.reduce((s: number, x: any) => s + x.count, 0);
                    const pct = total > 0 ? Math.round((t.count / total) * 100) : 0;
                    return (
                      <div key={t.type} className="cursor-pointer" onClick={() => navigate("/assets")}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            <div className="w-2 h-2 rounded-full shrink-0"
                              style={{ background: TYPE_COLORS[i % TYPE_COLORS.length] }} />
                            <span className="text-xs capitalize text-muted-foreground truncate">{t.type}</span>
                          </div>
                          <span className="text-xs font-semibold tabular-nums shrink-0 ml-2">{t.count}</span>
                        </div>
                        <div className="h-1 bg-accent rounded-full overflow-hidden">
                          <div className="h-full rounded-full transition-all duration-700"
                            style={{ width: `${pct}%`, background: TYPE_COLORS[i % TYPE_COLORS.length] }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </SectionCard>

        {/* Top Vulnerable Assets */}
        <SectionCard title="Top Vulnerable Assets" href="/assets">
          <div className="divide-y divide-border">
            {topVulnerableAssets.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-muted-foreground/40">
                <CheckCircle2 className="w-8 h-8 mb-2" />
                <p className="text-sm">No vulnerabilities found</p>
              </div>
            ) : topVulnerableAssets.map((a: any) => {
              const score = a.riskScore;
              const scoreColor = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
              return (
                <div key={a.id}
                  className="flex items-center gap-3 px-4 py-3 hover:bg-accent/20 cursor-pointer transition-colors"
                  onClick={() => navigate(`/assets/${a.id}`)}>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate">{a.name}</p>
                    <p className="text-[10px] text-muted-foreground font-mono truncate mt-0.5">{a.value}</p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {a.findings.critical > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold tabular-nums">
                        {a.findings.critical}C
                      </span>
                    )}
                    {a.findings.high > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 font-semibold tabular-nums">
                        {a.findings.high}H
                      </span>
                    )}
                    <span className="text-[10px] text-muted-foreground tabular-nums">
                      {a.findings.total} findings
                    </span>
                    {score != null && (
                      <span className={cn("text-sm font-bold tabular-nums w-8 text-right", scoreColor)}>
                        {score}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>
      </div>

      {/* Top Security Risks */}
      <SectionCard title="Top Security Risks" href="/findings" action={
        <span className="text-xs text-muted-foreground">Highest-priority open findings</span>
      }>
        <div className="divide-y divide-border">
          {topSecurityRisks.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-32 text-muted-foreground/40">
              <Shield className="w-8 h-8 mb-2" />
              <p className="text-sm">No open security risks</p>
            </div>
          ) : topSecurityRisks.map((f: any) => (
            <div key={f.id}
              className="flex items-start gap-3 px-4 py-3 hover:bg-accent/20 cursor-pointer transition-colors"
              onClick={() => navigate("/findings")}>
              <div className={cn(
                "mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase shrink-0",
                f.severity === "critical" ? "bg-red-500/20 text-red-400" :
                f.severity === "high"     ? "bg-orange-500/20 text-orange-400" :
                f.severity === "medium"   ? "bg-yellow-500/20 text-yellow-400" :
                                            "bg-green-500/20 text-green-400"
              )}>
                {f.severity?.charAt(0).toUpperCase()}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium truncate">{f.title}</p>
                <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                  <span className="text-[10px] text-muted-foreground truncate">{f.assetName}</span>
                  {f.cve && (
                    <span className="text-[10px] px-1.5 py-0 rounded bg-accent text-muted-foreground font-mono">{f.cve}</span>
                  )}
                  {f.isKev && (
                    <span className="text-[10px] px-1.5 py-0 rounded bg-red-500/15 text-red-400 font-semibold">KEV</span>
                  )}
                </div>
              </div>
              <div className="flex flex-col items-end gap-1 shrink-0">
                {f.cvss != null && (
                  <span className="text-[10px] text-muted-foreground tabular-nums">CVSS {f.cvss.toFixed(1)}</span>
                )}
                {f.epss != null && (
                  <span className="text-[10px] text-muted-foreground/60 tabular-nums">{(f.epss * 100).toFixed(1)}% EPSS</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Row: Takedown requests breakdown + False Positive Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Takedown Requests Breakdown */}
        <SectionCard title="Takedown Requests" href="/takedowns">
          <div className="p-4 space-y-3">
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Total Submissions", value: td.total, color: "text-foreground", icon: Globe },
                { label: "Open (Submitted)", value: td.submitted, color: "text-blue-400", icon: Clock },
                { label: "In Progress", value: td.inProgress, color: "text-amber-400", icon: Loader2 },
                { label: "Closed", value: td.closed, color: "text-green-400", icon: CheckCircle2 },
              ].map(({ label, value, color, icon: Icon }) => (
                <div key={label}
                  className="flex items-center gap-3 p-3 bg-accent/20 rounded-lg cursor-pointer hover:bg-accent/40 transition-colors"
                  onClick={() => navigate("/takedowns")}>
                  <Icon className={cn("w-4 h-4 shrink-0", color)} />
                  <div>
                    <p className={cn("text-base font-bold tabular-nums", color)}>{value}</p>
                    <p className="text-[10px] text-muted-foreground">{label}</p>
                  </div>
                </div>
              ))}
            </div>
            {(d?.recentTakedowns ?? []).length > 0 && (
              <div className="space-y-1.5 pt-1">
                <p className="text-xs text-muted-foreground font-medium">Recent</p>
                {(d.recentTakedowns).map((t: any) => {
                  const cfg = STATUS_CONFIG[t.status] ?? STATUS_CONFIG.submitted;
                  const StatusIcon = cfg.icon;
                  return (
                    <div key={t.id}
                      className="flex items-center gap-2 text-xs py-1.5 cursor-pointer hover:text-primary transition-colors"
                      onClick={() => navigate("/takedowns")}>
                      <StatusIcon className={cn("w-3.5 h-3.5 shrink-0", cfg.color.split(" ")[1])} />
                      <span className="flex-1 truncate">{t.title}</span>
                      <span className="text-muted-foreground/60 shrink-0">{new Date(t.createdAt).toLocaleDateString()}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </SectionCard>

        {/* False Positive Status */}
        <SectionCard title="False Positive Status" href="/findings">
          <div className="p-4 space-y-4">
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Submitted", value: fp.submitted, color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", icon: Flag },
                { label: "Confirmed", value: fp.confirmed, color: "text-green-400", bg: "bg-green-500/10 border-green-500/20", icon: CheckCircle2 },
                { label: "Rejected", value: fp.rejected, color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", icon: XCircle },
              ].map(({ label, value, color, bg, icon: Icon }) => (
                <div key={label}
                  className={cn("flex flex-col items-center justify-center p-3 rounded-xl border cursor-pointer hover:opacity-80 transition-opacity", bg)}
                  onClick={() => navigate("/findings")}>
                  <Icon className={cn("w-5 h-5 mb-1", color)} />
                  <p className={cn("text-xl font-bold tabular-nums", color)}>{value}</p>
                  <p className="text-[10px] text-muted-foreground text-center">{label}</p>
                </div>
              ))}
            </div>
            <div className="bg-accent/20 rounded-lg p-3 text-xs text-muted-foreground space-y-1.5">
              <p className="font-medium text-foreground text-[11px]">About False Positives</p>
              <p>Mark a finding as a false positive to flag it for review. Once confirmed, it will be excluded from your open vulnerability count and risk score calculations.</p>
              <button
                className="text-primary hover:underline text-[11px] font-medium mt-1"
                onClick={() => navigate("/findings")}>
                Review findings →
              </button>
            </div>
            <p className="text-[10px] text-muted-foreground/50">
              Total marked: {fp.submitted + fp.confirmed + fp.rejected} findings flagged across your tenant
            </p>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
