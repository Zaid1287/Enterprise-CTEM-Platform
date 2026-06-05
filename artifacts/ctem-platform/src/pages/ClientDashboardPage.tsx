import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { cn } from "@/lib/utils";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  TrendingUp, TrendingDown, Server, Bug, AlertTriangle, Bell,
  CheckCircle2, ShieldOff, Globe, Flag, XCircle, Clock,
  Loader2, ChevronRight, ShieldAlert,
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
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Skeleton className="h-56 rounded-xl" />
          <Skeleton className="h-56 rounded-xl" />
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

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold">My Security Status</h1>
        <p className="text-sm text-muted-foreground">Your organization's current threat exposure overview</p>
      </div>

      {/* Row 1: Risk score gauge + key metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
        {/* Risk Score Gauge */}
        <div
          className="bg-card border border-border rounded-xl cursor-pointer hover:border-primary/40 hover:bg-accent/20 transition-all"
          onClick={() => navigate("/risk")}
        >
          <RiskScoreGauge score={d?.riskScore ?? 0} />
        </div>

        {/* My Assets */}
        <ClickableCard
          label="My Assets"
          value={d?.totalAssets ?? 0}
          icon={Server}
          href="/assets"
          sub="Total monitored assets"
        />

        {/* Open Findings */}
        <ClickableCard
          label="Open Findings"
          value={d?.openFindings ?? 0}
          icon={Bug}
          color={d?.openFindings > 0 ? "text-amber-400" : undefined}
          href="/findings"
          sub="Across all assets"
        />

        {/* Critical Vulns */}
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

        {/* Open Alerts */}
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

      {/* Row 4: Takedown requests breakdown + False Positive Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Takedown Requests Breakdown */}
        <SectionCard title="Takedown Requests" href="/takedowns">
          <div className="p-4 space-y-3">
            {/* Status bar */}
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

            {/* Recent takedowns */}
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
