import { useAuth } from "@/hooks/useAuth";
import {
  useGetDashboardOverview,
  useGetRiskTrend,
  useGetFindingsBySeverity,
  useGetAssetBreakdown,
  useGetTopRiskyAssets,
  useGetRecentActivity,
  getGetDashboardOverviewQueryKey,
  getGetRiskTrendQueryKey,
  getGetFindingsBySeverityQueryKey,
  getGetAssetBreakdownQueryKey,
  getGetTopRiskyAssetsQueryKey,
  getGetRecentActivityQueryKey,
} from "@workspace/api-client-react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart, Area, PieChart, Pie, Cell, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  Server, Bug, ShieldCheck, Radar, Bell, TrendingUp, TrendingDown,
  AlertTriangle, Building2, Users, Shield, Target, ArrowRight,
  ShieldAlert, Activity, Globe, Clock, CheckCircle2, XCircle, Loader2,
} from "lucide-react";
import { Link } from "wouter";
import { cn, riskLevelBg, capitalize } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import ClientDashboardPage from "@/pages/ClientDashboardPage";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6",
};

function StatCard({ label, value, icon: Icon, trend, color = "text-foreground", sub }: any) {
  return (
    <div className="bg-card border border-border rounded-xl p-4">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className={cn("text-2xl font-bold tabular-nums", color)}>{value ?? "—"}</p>
          {sub && <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>}
        </div>
        <div className="w-8 h-8 rounded-lg bg-accent/50 flex items-center justify-center">
          <Icon className="w-4 h-4 text-muted-foreground" />
        </div>
      </div>
      {trend !== undefined && (
        <div className={cn("flex items-center gap-1 mt-2 text-xs", trend >= 0 ? "text-green-400" : "text-red-400")}>
          {trend >= 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          <span>{Math.abs(trend)}% vs last month</span>
        </div>
      )}
    </div>
  );
}

function DashboardSkeleton({ cards = 8 }: { cards?: number }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[...Array(Math.min(cards, 8))].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Skeleton className="h-60 rounded-xl" />
        <Skeleton className="h-60 rounded-xl" />
      </div>
    </div>
  );
}

/* ─── Super Admin Dashboard ─────────────────────────── */
function SuperAdminDashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ["platform-overview"],
    queryFn: () => apiFetch<any>(`${BASE}/api/dashboard/platform-overview`),
    staleTime: 30_000,
  });

  if (isLoading) return <DashboardSkeleton cards={6} />;
  const tenants: any[] = data?.tenants ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Platform Overview</h1>
        <p className="text-sm text-muted-foreground">All client organizations across the platform</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Client Tenants" value={data?.tenantCount} icon={Building2}
          sub={`${data?.activeTenantCount ?? 0} active`} color="text-purple-400" />
        <StatCard label="Total Users" value={data?.userCount} icon={Users} />
        <StatCard label="Total Assets" value={data?.assetCount} icon={Server} />
        <StatCard label="Open Findings" value={data?.openFindingCount} icon={Bug}
          color={data?.openFindingCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Critical Findings" value={data?.criticalCount} icon={AlertTriangle}
          color={data?.criticalCount > 0 ? "text-red-400" : undefined} />
        <StatCard label="Active Scans" value={data?.activeScans} icon={Radar} color="text-blue-400" />
        <StatCard label="Total Findings" value={data?.findingCount} icon={Bug} />
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium">Client Tenants</h3>
          <span className="text-xs text-muted-foreground">{tenants.length} organizations</span>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tenant</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Users</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Open</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Scans</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
            </tr>
          </thead>
          <tbody>
            {tenants.length === 0 && (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-sm text-muted-foreground">
                No client tenants yet. Register a new organization to get started.
              </td></tr>
            )}
            {tenants.map((t: any) => (
              <tr key={t.id} className="border-b border-border/50 hover:bg-accent/30">
                <td className="px-4 py-2.5">
                  <p className="font-medium">{t.name}</p>
                  <p className="text-[10px] text-muted-foreground">{t.slug}</p>
                </td>
                <td className="px-4 py-2.5"><Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge></td>
                <td className="px-4 py-2.5 text-right tabular-nums">{t.userCount}</td>
                <td className="px-4 py-2.5 text-right tabular-nums">{t.assetCount}</td>
                <td className="px-4 py-2.5 text-right tabular-nums">{t.openFindingCount}</td>
                <td className="px-4 py-2.5 text-right tabular-nums">
                  {t.criticalCount > 0 ? <span className="text-red-400 font-semibold">{t.criticalCount}</span>
                    : <span className="text-muted-foreground">0</span>}
                </td>
                <td className="px-4 py-2.5 text-right tabular-nums">
                  {t.activeScans > 0 ? <span className="text-blue-400">{t.activeScans}</span>
                    : <span className="text-muted-foreground">0</span>}
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                    t.isActive ? "bg-green-500/15 text-green-400 border-green-500/30"
                      : "bg-muted text-muted-foreground border-border")}>
                    {t.isActive ? "Active" : "Inactive"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ─── Account Manager Dashboard ─────────────────────── */
function RiskBar({ score, level }: { score: number; level: string }) {
  const color =
    level === "critical" ? "bg-red-500" :
    level === "high"     ? "bg-orange-500" :
    level === "medium"   ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-accent/60 rounded-full h-1.5 min-w-[48px]">
        <div className={cn("h-1.5 rounded-full transition-all", color)} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className={cn("text-xs font-mono font-semibold tabular-nums w-7 text-right",
        level === "critical" ? "text-red-400" : level === "high" ? "text-orange-400" :
        level === "medium"   ? "text-yellow-400" : "text-green-400",
      )}>{score}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
    severity === "high"     ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
    severity === "medium"   ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
    severity === "low"      ? "bg-green-500/15 text-green-400 border-green-500/30" :
    "bg-muted text-muted-foreground border-border";
  return (
    <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold border capitalize shrink-0", cls)}>
      {severity}
    </span>
  );
}

function TakedownStatusBadge({ status }: { status: string }) {
  const cls =
    status === "pending"   ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
    status === "submitted" ? "bg-blue-500/15 text-blue-400 border-blue-500/30" :
    status === "approved"  ? "bg-green-500/15 text-green-400 border-green-500/30" :
    status === "rejected"  ? "bg-red-500/15 text-red-400 border-red-500/30" :
    "bg-muted text-muted-foreground border-border";
  const Icon =
    status === "approved" ? CheckCircle2 :
    status === "rejected" ? XCircle :
    status === "submitted"? Loader2 : Clock;
  return (
    <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium border capitalize inline-flex items-center gap-1", cls)}>
      <Icon className="w-2.5 h-2.5" />{status}
    </span>
  );
}

function AccountManagerDashboard() {
  const { user } = useAuth();
  const { data, isLoading } = useQuery({
    queryKey: ["am-overview"],
    queryFn: () => apiFetch<any>(`${BASE}/api/dashboard/am-overview`),
    staleTime: 30_000,
  });

  if (isLoading) return <DashboardSkeleton cards={6} />;

  const clients: any[]          = data?.clients          ?? [];
  const riskTrend: any[]        = data?.riskTrend         ?? [];
  const topRiskAssets: any[]    = data?.topRiskAssets     ?? [];
  const severityBreakdown: any[]= data?.severityBreakdown ?? [];
  const recentAlerts: any[]     = data?.recentAlerts      ?? [];
  const takedownRequests: any[] = data?.takedownRequests  ?? [];

  const riskScore  = data?.portfolioRiskScore ?? 0;
  const riskLevel  = riskScore >= 70 ? "critical" : riskScore >= 40 ? "high" : riskScore >= 20 ? "medium" : "low";
  const riskColor  = riskScore >= 70 ? "text-red-400" : riskScore >= 40 ? "text-amber-400" : "text-green-400";

  const TOOLTIP_STYLE = {
    background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)",
    borderRadius: "8px", fontSize: "12px",
  };

  return (
    <div className="space-y-5">

      {/* ── Hero banner ──────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-xl border border-blue-500/20 bg-gradient-to-br from-blue-600/15 via-blue-500/5 to-purple-600/10 px-6 py-5">
        <div className="relative z-10 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Shield className="w-4 h-4 text-blue-400" />
              <span className="text-[11px] font-semibold tracking-widest uppercase text-blue-400">Account Manager</span>
            </div>
            <h1 className="text-xl font-bold">
              Welcome back, {user?.firstName ?? "Manager"}
            </h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Managing{" "}
              <span className="font-semibold text-foreground">{data?.clientCount ?? 0}</span>{" "}
              client{data?.clientCount !== 1 ? "s" : ""} ·{" "}
              <span className="font-semibold text-foreground">{data?.assetCount ?? 0}</span>{" "}
              assets under protection
            </p>
          </div>
          <div className="text-right shrink-0 hidden sm:block">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground mb-0.5">Portfolio Risk</p>
            <p className={cn("text-3xl font-bold tabular-nums", riskColor)}>{riskScore}</p>
            <p className="text-[10px] text-muted-foreground">avg score / 100</p>
          </div>
        </div>
        <Shield className="absolute -right-4 -bottom-4 w-32 h-32 text-blue-400/5 pointer-events-none" />
      </div>

      {/* ── Stat cards ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        <StatCard label="My Total Clients"      value={data?.clientCount}      icon={Building2}    color="text-blue-400" />
        <StatCard label="Assets Managed"        value={data?.assetCount}       icon={Server}       color="text-purple-400" />
        <StatCard label="Critical Issues"       value={data?.criticalCount}    icon={AlertTriangle}
          color={(data?.criticalCount ?? 0) > 0 ? "text-red-400" : undefined} />
        <StatCard label="Open Vulnerabilities" value={data?.openFindingCount} icon={Bug}
          color={(data?.openFindingCount ?? 0) > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Portfolio Risk Score"  value={riskScore}              icon={Activity}     color={riskColor} sub="avg / 100" />
        <StatCard label="Active Scans"          value={data?.activeScans}      icon={Radar}        color="text-cyan-400" />
      </div>

      {/* ── Charts row ───────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Risk Score Trend — 2/3 width */}
        <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-medium">Portfolio Risk Score Trend</h3>
              <p className="text-[11px] text-muted-foreground mt-0.5">All assigned client assets · 14 days</p>
            </div>
            <div className={cn("text-xs font-semibold px-2.5 py-1 rounded-md border", riskLevelBg(riskLevel))}>
              Score: {riskScore}
            </div>
          </div>
          {riskTrend.length === 0 ? (
            <div className="h-[180px] flex items-center justify-center text-sm text-muted-foreground">
              No scan data available yet
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={riskTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="amRiskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
                <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }}
                  tickFormatter={(v: string) => v?.slice(5)} />
                <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
                <Tooltip contentStyle={TOOLTIP_STYLE}
                  formatter={(v: number) => [`${v}`, "Risk Score"]} />
                <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2}
                  fill="url(#amRiskGrad)" dot={false} activeDot={{ r: 4, fill: "#3b82f6" }} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Severity Breakdown Pie — 1/3 width */}
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="mb-3">
            <h3 className="text-sm font-medium">Severity Breakdown</h3>
            <p className="text-[11px] text-muted-foreground mt-0.5">All assigned findings</p>
          </div>
          {severityBreakdown.length === 0 ? (
            <div className="h-[200px] flex flex-col items-center justify-center gap-2 text-sm text-muted-foreground">
              <ShieldCheck className="w-8 h-8 text-green-400/50" />
              No findings across portfolio
            </div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={130}>
                <PieChart>
                  <Pie data={severityBreakdown} dataKey="count" nameKey="severity"
                    cx="50%" cy="50%" innerRadius={38} outerRadius={58} paddingAngle={2}>
                    {severityBreakdown.map((entry: any) => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#64748b"} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(v: number, n: string) => [v, capitalize(n)]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 mt-1">
                {severityBreakdown.map((s: any) => (
                  <div key={s.severity} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-2.5 h-2.5 rounded-full shrink-0"
                        style={{ background: SEVERITY_COLORS[s.severity] ?? "#64748b" }} />
                      <span className="text-xs text-muted-foreground capitalize">{s.severity}</span>
                    </div>
                    <span className="text-xs font-mono font-semibold">{s.count}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* ── Top-Risk Assets + Recent Alerts ──────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Top-Risk Assets */}
        <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between shrink-0">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Target className="w-4 h-4 text-red-400" /> Top-Risk Assets
            </h3>
            <Link href="/assets">
              <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
                All assets <ArrowRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
          <div className="divide-y divide-border/50 flex-1">
            {topRiskAssets.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-muted-foreground">
                <Target className="w-7 h-7 mx-auto mb-2 opacity-30" />
                No risk scores computed yet
              </div>
            ) : topRiskAssets.map((a: any, idx: number) => (
              <Link key={a.assetId} href={`/assets/${a.assetId}`}>
                <div className="px-4 py-3 hover:bg-accent/30 cursor-pointer transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-muted-foreground/60 w-4 shrink-0">#{idx + 1}</span>
                        <p className="text-sm font-medium truncate">{a.assetName}</p>
                      </div>
                      <p className="text-[11px] text-muted-foreground ml-6 mt-0.5">
                        {a.clientName} · <span className="capitalize">{a.assetType}</span> · {a.findingsCount} finding{a.findingsCount !== 1 ? "s" : ""}
                      </p>
                    </div>
                    <span className={cn("ml-3 shrink-0 text-xs px-2 py-0.5 rounded font-semibold border capitalize", riskLevelBg(a.riskLevel))}>
                      {a.riskLevel}
                    </span>
                  </div>
                  <div className="ml-6">
                    <RiskBar score={a.riskScore} level={a.riskLevel} />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Recent Alerts */}
        <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between shrink-0">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Bell className="w-4 h-4 text-amber-400" /> Recent Alerts
            </h3>
            <Link href="/alerts">
              <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
          <div className="divide-y divide-border/50 flex-1">
            {recentAlerts.length === 0 ? (
              <div className="px-4 py-10 text-center text-sm text-muted-foreground">
                <Bell className="w-7 h-7 mx-auto mb-2 opacity-30" />
                No alerts for assigned assets
              </div>
            ) : recentAlerts.map((a: any) => (
              <div key={a.id} className={cn("px-4 py-3 transition-colors", !a.isRead && "bg-primary/[0.03]")}>
                <div className="flex items-start gap-2.5">
                  {!a.isRead && (
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                  )}
                  <div className="flex-1 min-w-0" style={{ marginLeft: a.isRead ? "10px" : undefined }}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-xs font-medium truncate flex-1">{a.title}</p>
                      <SeverityBadge severity={a.severity} />
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-1">
                      <Building2 className="w-2.5 h-2.5 shrink-0" />
                      {a.clientName} · {new Date(a.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Takedown Requests ─────────────────────────────────────────────── */}
      {takedownRequests.length > 0 && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" /> Takedown Requests
              <span className="text-[10px] bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded-full font-medium">
                {takedownRequests.length}
              </span>
            </h3>
            <Link href="/takedowns">
              <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
                Manage <ArrowRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-accent/20">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Domain</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Reason</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Date</th>
                </tr>
              </thead>
              <tbody>
                {takedownRequests.map((t: any) => (
                  <tr key={t.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-xs flex items-center gap-1.5">
                        <Globe className="w-3 h-3 text-muted-foreground shrink-0" />{t.domain}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{t.clientName}</td>
                    <td className="px-4 py-2.5"><TakedownStatusBadge status={t.status} /></td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[180px] truncate">
                      {t.reason ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 text-[11px] text-muted-foreground whitespace-nowrap">
                      {new Date(t.createdAt).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Client Portfolio Table ────────────────────────────────────────── */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Building2 className="w-4 h-4 text-blue-400" /> Client Portfolio
          </h3>
          <span className="text-xs text-muted-foreground">
            {clients.length} client{clients.length !== 1 ? "s" : ""} assigned
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-accent/20">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Company Name</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client Name</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground min-w-[140px]">Risk Score</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Open</th>
                <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-2.5 w-20" />
              </tr>
            </thead>
            <tbody>
              {clients.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center">
                    <Building2 className="w-8 h-8 mx-auto mb-2 text-muted-foreground/30" />
                    <p className="text-sm text-muted-foreground">No clients assigned yet.</p>
                    <p className="text-xs text-muted-foreground/60 mt-0.5">Contact your Super Admin to be assigned clients.</p>
                  </td>
                </tr>
              )}
              {clients.map((c: any) => {
                const cLevel = c.riskScore >= 70 ? "critical" : c.riskScore >= 40 ? "high" : c.riskScore >= 20 ? "medium" : "low";
                return (
                  <tr key={c.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-sm">{c.name}</p>
                      <p className="text-[10px] text-muted-foreground capitalize">{c.plan} plan</p>
                    </td>
                    <td className="px-4 py-3">
                      <p className="text-sm">{c.clientUserName}</p>
                      {c.clientUserEmail && (
                        <p className="text-[10px] text-muted-foreground truncate max-w-[160px]">{c.clientUserEmail}</p>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums font-mono text-sm">{c.assetCount}</td>
                    <td className="px-4 py-3">
                      {c.riskScore > 0
                        ? <RiskBar score={c.riskScore} level={cLevel} />
                        : <span className="text-xs text-muted-foreground">—</span>
                      }
                    </td>
                    <td className="px-4 py-3 text-right">
                      {c.criticalCount > 0
                        ? <span className="text-red-400 font-semibold tabular-nums">{c.criticalCount}</span>
                        : <span className="text-muted-foreground/50 tabular-nums">0</span>}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {c.openFindingCount > 0
                        ? <span className="text-amber-400 tabular-nums">{c.openFindingCount}</span>
                        : <span className="text-muted-foreground/50 tabular-nums">0</span>}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-medium border",
                        c.isActive
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : "bg-muted text-muted-foreground border-border")}>
                        {c.isActive ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <Link href="/my-clients">
                        <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1 justify-center">
                          View <ArrowRight className="w-3 h-3" />
                        </span>
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
}

/* ─── Client Dashboard ───────────────────────────────── */
function ClientDashboard() {
  const { data: overview, isLoading } = useGetDashboardOverview({
    query: { queryKey: getGetDashboardOverviewQueryKey() },
  });
  const { data: riskTrend } = useGetRiskTrend({ days: 14 }, {
    query: { queryKey: getGetRiskTrendQueryKey({ days: 14 }) },
  });
  if (isLoading) return <DashboardSkeleton cards={4} />;
  const o = overview as any;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">My Security Status</h1>
        <p className="text-sm text-muted-foreground">Your organization's current security posture</p>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="My Assets" value={o?.totalAssets} icon={Server} />
        <StatCard label="Open Findings" value={o?.openFindings} icon={Bug}
          color={o?.openFindings > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Critical" value={o?.criticalFindings} icon={AlertTriangle}
          color={o?.criticalFindings > 0 ? "text-red-400" : undefined} />
        <StatCard label="Risk Score" value={o?.riskScore} icon={TrendingUp}
          color={o?.riskScore > 70 ? "text-red-400" : o?.riskScore > 40 ? "text-amber-400" : "text-green-400"} />
      </div>
      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-sm font-medium mb-4">Risk Trend (14 days)</h3>
        <ResponsiveContainer width="100%" height={150}>
          <AreaChart data={riskTrend as any[]}>
            <defs>
              <linearGradient id="rg2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
            <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => v?.slice(5)} />
            <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
            <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }} />
            <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} fill="url(#rg2)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* ─── Admin Dashboard (full) ─────────────────────────── */
function AdminDashboard() {
  const { data: overview, isLoading: loadingOverview } = useGetDashboardOverview({
    query: { queryKey: getGetDashboardOverviewQueryKey() },
  });
  const { data: riskTrend } = useGetRiskTrend({ days: 30 }, {
    query: { queryKey: getGetRiskTrendQueryKey({ days: 30 }) },
  });
  const { data: findingsBySeverity } = useGetFindingsBySeverity({
    query: { queryKey: getGetFindingsBySeverityQueryKey() },
  });
  const { data: assetBreakdown } = useGetAssetBreakdown({
    query: { queryKey: getGetAssetBreakdownQueryKey() },
  });
  const { data: topRiskyAssets } = useGetTopRiskyAssets({ limit: 5 }, {
    query: { queryKey: getGetTopRiskyAssetsQueryKey({ limit: 5 }) },
  });
  const { data: recentActivity } = useGetRecentActivity({
    query: { queryKey: getGetRecentActivityQueryKey() },
  });

  if (loadingOverview) return <DashboardSkeleton />;
  const o = overview as any;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Security Overview</h1>
        <p className="text-sm text-muted-foreground">Real-time threat exposure metrics</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Assets" value={o?.totalAssets} icon={Server} trend={o?.assetsTrend} />
        <StatCard label="Open Findings" value={o?.openFindings} icon={Bug}
          color={o?.openFindings > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Critical" value={o?.criticalFindings} icon={AlertTriangle}
          color={o?.criticalFindings > 0 ? "text-red-400" : undefined} />
        <StatCard label="Active Scans" value={o?.activeScans} icon={Radar} />
        <StatCard label="Risk Score" value={o?.riskScore} icon={TrendingUp}
          color={o?.riskScore > 70 ? "text-red-400" : o?.riskScore > 40 ? "text-orange-400" : "text-green-400"} />
        <StatCard label="High Findings" value={o?.highFindings} icon={Bug}
          color={o?.highFindings > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Compliance" value={o?.complianceScore != null ? `${o.complianceScore}%` : "—"} icon={ShieldCheck}
          color={o?.complianceScore >= 70 ? "text-green-400" : "text-orange-400"} />
        <StatCard label="Unread Alerts" value={o?.unreadAlerts} icon={Bell}
          color={o?.unreadAlerts > 0 ? "text-yellow-400" : undefined} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Risk Score Trend (30 days)</h3>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={riskTrend as any[]}>
              <defs>
                <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => v?.slice(5)} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                labelStyle={{ color: "#94a3b8" }} />
              <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} fill="url(#riskGrad)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Findings by Severity</h3>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={findingsBySeverity as any[]} dataKey="count" nameKey="severity" cx="50%" cy="50%" innerRadius={50} outerRadius={75}>
                {(findingsBySeverity as any[] ?? []).map((entry: any) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#64748b"} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                formatter={(v: any, name: any) => [v, capitalize(name)]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-2 space-y-1">
            {(findingsBySeverity as any[] ?? []).filter((s: any) => s.count > 0).map((s: any) => (
              <div key={s.severity} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-sm" style={{ background: SEVERITY_COLORS[s.severity] }} />
                  <span className="capitalize text-muted-foreground">{s.severity}</span>
                </div>
                <span className="font-medium tabular-nums">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-3">Top Risky Assets</h3>
          <div className="space-y-2">
            {(topRiskyAssets as any[] ?? []).map((a: any) => (
              <div key={a.assetId} className="flex items-center gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between mb-0.5">
                    <p className="text-xs font-medium truncate">{a.assetName}</p>
                    <span className={cn("text-xs px-1.5 py-0.5 rounded text-[10px] font-medium ml-2", riskLevelBg(a.riskLevel))}>{a.riskLevel}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-accent rounded-full overflow-hidden">
                      <div className="h-full rounded-full"
                        style={{ width: `${a.riskScore}%`, background: a.riskScore >= 80 ? "#ef4444" : a.riskScore >= 60 ? "#f97316" : "#eab308" }} />
                    </div>
                    <span className="text-xs tabular-nums text-muted-foreground w-6 text-right">{a.riskScore}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-3">Recent Activity</h3>
          <div className="space-y-2">
            {(recentActivity as any[] ?? []).slice(0, 6).map((item: any) => (
              <div key={item.id} className="flex items-start gap-2.5 py-1 border-b border-border last:border-0">
                <div className={cn("mt-0.5 w-1.5 h-1.5 rounded-full shrink-0",
                  item.severity === "critical" ? "bg-red-400" : item.severity === "high" ? "bg-orange-400" :
                  item.severity === "medium" ? "bg-yellow-400" : "bg-blue-400")} />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium truncate">{item.title}</p>
                  <p className="text-[11px] text-muted-foreground truncate">{item.description}</p>
                </div>
                <span className="text-[10px] text-muted-foreground shrink-0">{new Date(item.createdAt).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-sm font-medium mb-4">Asset Type Breakdown</h3>
        <ResponsiveContainer width="100%" height={120}>
          <BarChart data={assetBreakdown as any[]}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" vertical={false} />
            <XAxis dataKey="type" tick={{ fill: "#64748b", fontSize: 11 }} />
            <YAxis tick={{ fill: "#64748b", fontSize: 11 }} allowDecimals={false} />
            <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }} />
            <Bar dataKey="count" fill="#3b82f6" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

/* ─── Role Router ────────────────────────────────────── */
export default function DashboardPage() {
  const { user } = useAuth();
  if (user?.role === "super_admin") return <SuperAdminDashboard />;
  if (user?.role === "account_manager") return <AccountManagerDashboard />;
  if (user?.role === "client") return <ClientDashboardPage />;
  return <AdminDashboard />;
}
