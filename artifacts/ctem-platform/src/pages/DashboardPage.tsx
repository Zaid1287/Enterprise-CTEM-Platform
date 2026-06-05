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
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from "recharts";
import {
  Server, Bug, ShieldCheck, Radar, Bell, TrendingUp, TrendingDown,
  AlertTriangle, Building2, Users,
} from "lucide-react";
import { cn, riskLevelBg, capitalize } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";

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
function AccountManagerDashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ["am-overview"],
    queryFn: () => apiFetch<any>(`${BASE}/api/dashboard/am-overview`),
    staleTime: 30_000,
  });

  if (isLoading) return <DashboardSkeleton cards={6} />;
  const clients: any[] = data?.clients ?? [];

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Client Portfolio</h1>
        <p className="text-sm text-muted-foreground">Your assigned client organizations</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <StatCard label="Assigned Clients" value={data?.clientCount} icon={Building2} color="text-purple-400" />
        <StatCard label="Total Assets" value={data?.assetCount} icon={Server} />
        <StatCard label="Open Findings" value={data?.openFindingCount} icon={Bug}
          color={data?.openFindingCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Critical Findings" value={data?.criticalCount} icon={AlertTriangle}
          color={data?.criticalCount > 0 ? "text-red-400" : undefined} />
        <StatCard label="Total Findings" value={data?.findingCount} icon={Bug} />
        <StatCard label="Active Scans" value={data?.activeScans} icon={Radar} color="text-blue-400" />
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-sm font-medium">Your Clients</h3>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Open</th>
              <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
            </tr>
          </thead>
          <tbody>
            {clients.length === 0 && (
              <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-muted-foreground">
                No clients assigned yet. Contact your Super Admin.
              </td></tr>
            )}
            {clients.map((c: any) => (
              <tr key={c.id} className="border-b border-border/50 hover:bg-accent/30">
                <td className="px-4 py-2.5 font-medium">{c.name}</td>
                <td className="px-4 py-2.5"><Badge variant="outline" className="text-xs capitalize">{c.plan}</Badge></td>
                <td className="px-4 py-2.5 text-right tabular-nums">{c.assetCount}</td>
                <td className="px-4 py-2.5 text-right tabular-nums">{c.openFindingCount}</td>
                <td className="px-4 py-2.5 text-right tabular-nums">
                  {c.criticalCount > 0 ? <span className="text-red-400 font-semibold">{c.criticalCount}</span>
                    : <span className="text-muted-foreground">0</span>}
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                    c.isActive ? "bg-green-500/15 text-green-400 border-green-500/30"
                      : "bg-muted text-muted-foreground border-border")}>
                    {c.isActive ? "Active" : "Inactive"}
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
  if (user?.role === "client") return <ClientDashboard />;
  return <AdminDashboard />;
}
