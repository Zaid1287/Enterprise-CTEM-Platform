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
  AlertTriangle, Building2, Users, Users2, Shield, Target, ArrowRight,
  ShieldAlert, Activity, Globe, Clock, CheckCircle2, XCircle, Loader2, Briefcase,
  Globe2, Crosshair, ShieldOff,
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

/* ─── Shared AI Mapper banner (shown on every role dashboard) ─── */
function AiMapperBanner({ adminLink = false }: { adminLink?: boolean }) {
  const { aiMapperEnabled } = useAuth();
  const { data: stats, isLoading } = useQuery({
    queryKey: ["ai-mapper-stats"],
    queryFn: () => apiFetch<{ total: number; critical: number; high: number; noAuth: number; activeScans: number }>(`${BASE}/api/ai-mapper/stats`),
    enabled: aiMapperEnabled,
    staleTime: 30_000,
  });

  if (!aiMapperEnabled) return null;

  return (
    <div className="rounded-xl border border-violet-500/20 bg-gradient-to-r from-violet-950/40 via-purple-950/20 to-slate-900/40 p-4">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-violet-500/15 border border-violet-500/25 flex items-center justify-center shrink-0">
            <Globe2 className="w-4 h-4 text-violet-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold">AI Mapper</h3>
            <p className="text-[11px] text-muted-foreground">Exposed AI infrastructure discovered across the internet</p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {adminLink && (
            <Link href="/ai-mapper/admin" className="text-xs text-muted-foreground hover:text-foreground transition-colors">
              Admin view
            </Link>
          )}
          <Link href="/ai-mapper" className="inline-flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300 font-medium transition-colors">
            Open AI Mapper <ArrowRight className="w-3 h-3" />
          </Link>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Total Endpoints",  value: stats?.total,       icon: Globe2,    color: "text-blue-400"   },
          { label: "Critical Risk",    value: stats?.critical,    icon: AlertTriangle, color: "text-red-400" },
          { label: "No Auth",          value: stats?.noAuth,      icon: ShieldOff, color: "text-yellow-400" },
          { label: "Active Scans",     value: stats?.activeScans, icon: Crosshair, color: "text-green-400"  },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-black/20 rounded-lg px-3 py-2.5 border border-white/5">
            <div className="flex items-center gap-1.5 mb-0.5">
              <Icon className={cn("w-3 h-3", color)} />
              <p className="text-[10px] text-muted-foreground">{label}</p>
            </div>
            <p className={cn("text-xl font-bold tabular-nums", color)}>
              {isLoading ? "—" : (value ?? 0).toLocaleString()}
            </p>
          </div>
        ))}
      </div>
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

function FpStatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; cls: string }> = {
    submitted:   { label: "Pending",     cls: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" },
    in_progress: { label: "In Progress", cls: "bg-blue-500/15   text-blue-400   border-blue-500/30"   },
    confirmed:   { label: "Confirmed FP", cls: "bg-green-500/15  text-green-400  border-green-500/30"  },
    rejected:    { label: "Rejected",    cls: "bg-red-500/15    text-red-400    border-red-500/30"    },
    none:        { label: "None",        cls: "bg-muted         text-muted-foreground border-border"   },
  };
  const s = map[status] ?? map.none;
  return <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium border", s.cls)}>{s.label}</span>;
}

/* ─── Queue Health Widget (shown on admin dashboard) ──────────────────────── */
function QueueHealthWidget() {
  const { data, isLoading } = useQuery({
    queryKey: ["queue-status-widget"],
    queryFn: () => apiFetch<any>(`${BASE}/api/queues/status`),
    staleTime: 10_000,
    refetchInterval: 15_000,
  });

  if (isLoading || !data) return null;

  const db = data.dbStats ?? {};
  const inP = data.inProcess ?? {};
  const totalFinished = (db.completed ?? 0) + (db.failed ?? 0) + (db.cancelled ?? 0);
  const successRate = totalFinished > 0 ? Math.round(((db.completed ?? 0) / totalFinished) * 100) : null;
  const isRedis = data.mode === "redis";
  const depthWarning = data.depthWarning;

  return (
    <div className={cn(
      "rounded-xl border p-4",
      depthWarning ? "border-amber-500/30 bg-amber-500/5" : "border-border bg-card",
    )}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {depthWarning && <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />}
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Scan Queue Health</p>
          <span className={cn(
            "text-[10px] px-1.5 py-0.5 rounded font-medium border",
            isRedis ? "border-green-500/30 bg-green-500/10 text-green-400" : "border-blue-500/30 bg-blue-500/10 text-blue-400",
          )}>
            {isRedis ? "Redis" : "In-memory"}
          </span>
        </div>
        <Link href="/queue-monitor" className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-0.5 transition-colors">
          View monitor <ArrowRight className="w-2.5 h-2.5" />
        </Link>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Running",     value: inP.activeScans ?? db.running ?? 0,  icon: Activity,     color: (inP.activeScans ?? 0) > 0 ? "text-blue-400" : "text-muted-foreground" },
          { label: "In Queue",    value: inP.pendingCount ?? db.pending ?? 0, icon: Clock,         color: (inP.pendingCount ?? 0) > 0 ? "text-yellow-400" : "text-muted-foreground" },
          { label: "Success Rate",value: successRate !== null ? `${successRate}%` : "—", icon: CheckCircle2, color: successRate !== null && successRate >= 90 ? "text-green-400" : "text-amber-400" },
          { label: "Failed",      value: db.failed ?? 0,  icon: XCircle, color: (db.failed ?? 0) > 0 ? "text-red-400" : "text-muted-foreground" },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-black/20 rounded-lg px-3 py-2.5 border border-white/5">
            <div className="flex items-center gap-1.5 mb-0.5">
              <Icon className={cn("w-3 h-3", color)} />
              <p className="text-[10px] text-muted-foreground">{label}</p>
            </div>
            <p className={cn("text-xl font-bold tabular-nums", color)}>{value}</p>
          </div>
        ))}
      </div>
      {depthWarning && (
        <p className="text-[10px] text-amber-400 mt-2">
          Queue backing up — {(inP.activeScans ?? 0)} active + {(inP.pendingCount ?? 0)} pending exceeds threshold
        </p>
      )}
    </div>
  );
}

/* ─── Super Admin Dashboard ─────────────────────────── */
function SuperAdminDashboard() {
  const { user, threatIntelEnabled } = useAuth();
  const { data, isLoading } = useQuery({
    queryKey: ["platform-overview"],
    queryFn: () => apiFetch<any>(`${BASE}/api/dashboard/platform-overview`),
    staleTime: 30_000,
  });
  const { data: tiData } = useQuery({
    queryKey: ["ti-dashboard-summary"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dashboard`),
    staleTime: 120_000,
    enabled: !!threatIntelEnabled,
  });

  if (isLoading) return <DashboardSkeleton cards={12} />;
  const d = data ?? {};
  const tenants: any[] = d.tenants ?? [];
  const riskTrend: any[] = d.riskTrend ?? [];
  const severityBreakdown: any[] = d.severityBreakdown ?? [];
  const clientRiskRankings: any[] = d.clientRiskRankings ?? [];
  const assetRiskRankings: any[] = d.assetRiskRankings ?? [];
  const amPortfolio: any[] = d.amPortfolio ?? [];
  const recentAlerts: any[] = d.recentAlerts ?? [];
  const fpData = d.falsePositives ?? { submitted: 0, in_progress: 0, confirmed: 0, rejected: 0 };
  const fpFindings: any[] = d.falsePositiveFindings ?? [];

  const riskColor = d.platformRiskScore >= 70 ? "text-red-400" : d.platformRiskScore >= 40 ? "text-amber-400" : "text-green-400";

  return (
    <div className="space-y-5">
      {/* Hero Banner */}
      <div className="rounded-2xl overflow-hidden bg-gradient-to-r from-slate-900 via-purple-950 to-slate-900 border border-purple-500/20 p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-5 h-5 text-purple-400" />
              <span className="text-xs font-medium text-purple-300 uppercase tracking-widest">Super Admin</span>
            </div>
            <h1 className="text-2xl font-bold text-white">Platform Command Center</h1>
            <p className="text-sm text-slate-400 mt-1">Complete visibility across all client organizations</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-0.5">Platform Risk Score</p>
            <p className={cn("text-4xl font-black tabular-nums", riskColor)}>{d.platformRiskScore ?? "—"}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">{d.activeTenantCount ?? 0} active organizations</p>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-4 gap-3">
          {[
            { label: "Total Clients", value: d.tenantCount, color: "text-purple-300" },
            { label: "Account Managers", value: d.amCount, color: "text-blue-300" },
            { label: "Total Assets", value: d.assetCount, color: "text-cyan-300" },
            { label: "Critical Risk Assets", value: d.clientsAtCriticalRisk, color: "text-red-300" },
          ].map(s => (
            <div key={s.label} className="bg-white/5 rounded-xl px-4 py-3 border border-white/10">
              <p className="text-[10px] text-slate-400 uppercase tracking-wide">{s.label}</p>
              <p className={cn("text-xl font-bold tabular-nums mt-0.5", s.color)}>{s.value ?? "—"}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Row 1 — 4 primary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Clients" value={d.tenantCount} icon={Building2}
          sub={`${d.activeTenantCount ?? 0} active`} color="text-purple-400" />
        <StatCard label="Account Managers" value={d.amCount} icon={Users} color="text-blue-400" />
        <StatCard label="Critical Risk Assets" value={d.clientsAtCriticalRisk} icon={ShieldAlert}
          color={d.clientsAtCriticalRisk > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Total Client Assets" value={d.assetCount} icon={Server} />
      </div>

      {/* Row 2 — 4 secondary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Critical Vulnerabilities" value={d.criticalCount} icon={AlertTriangle}
          color={d.criticalCount > 0 ? "text-red-400" : undefined} />
        <StatCard label="Open Alerts" value={d.openAlertsCount} icon={Bell}
          color={d.openAlertsCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Brand Threats" value={d.brandThreatsCount} icon={Globe}
          color={d.brandThreatsCount > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Takedown Requests" value={d.takedownsCount} icon={Shield} color="text-cyan-400" />
      </div>

      {/* Row 3 — 4 tertiary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="New Vulns (7D)" value={d.newVulns7D} icon={TrendingUp}
          color={d.newVulns7D > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Resolved Vulns (7D)" value={d.resolvedVulns7D} icon={CheckCircle2}
          color={d.resolvedVulns7D > 0 ? "text-green-400" : undefined} />
        <StatCard label="Exposed Ports" value={d.exposedPortsCount} icon={Activity}
          color={d.exposedPortsCount > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Active Scans" value={d.activeScans} icon={Radar} color="text-blue-400" />
      </div>

      {/* Row 4 — additional stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Open Findings" value={d.openFindingCount} icon={Bug}
          color={d.openFindingCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="High Findings" value={d.highCount} icon={AlertTriangle}
          color={d.highCount > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Platform Risk Score" value={d.platformRiskScore ?? "—"} icon={Activity}
          color={riskColor} sub="out of 100" />
        <StatCard label="Team Members" value={d.userCount} icon={Users} color="text-violet-400"
          sub="across all tenants" />
      </div>

      <AiMapperBanner adminLink />

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Platform Risk Score Trend (14 days)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={riskTrend}>
              <defs>
                <linearGradient id="saRiskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => v?.slice(5)} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                labelStyle={{ color: "#94a3b8" }} />
              <Area type="monotone" dataKey="value" stroke="#a855f7" strokeWidth={2} fill="url(#saRiskGrad)" name="Risk Score" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Severity Breakdown</h3>
          {severityBreakdown.length === 0 ? (
            <div className="flex items-center justify-center h-40 text-sm text-muted-foreground">No findings yet</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityBreakdown} dataKey="count" nameKey="severity" cx="50%" cy="50%" innerRadius={45} outerRadius={70}>
                    {severityBreakdown.map((e: any) => <Cell key={e.severity} fill={SEVERITY_COLORS[e.severity] ?? "#64748b"} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                    formatter={(v: any, name: any) => [v, capitalize(name)]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-2 space-y-1.5">
                {severityBreakdown.map((s: any) => (
                  <div key={s.severity} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-sm" style={{ background: SEVERITY_COLORS[s.severity] }} />
                      <span className="capitalize text-muted-foreground">{s.severity}</span>
                    </div>
                    <span className="font-semibold tabular-nums">{s.count}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Asset Risk Rankings + Client Risk Rankings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Asset Risk Rankings */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" /> Asset Risk Rankings
            </h3>
            <span className="text-xs text-muted-foreground">top {assetRiskRankings.length} assets</span>
          </div>
          <div className="divide-y divide-border/50">
            {assetRiskRankings.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">No risk data yet — run a scan to populate</div>
            ) : assetRiskRankings.map((a: any, idx: number) => (
              <div key={a.id} className="px-4 py-3 hover:bg-accent/30 transition-colors">
                <div className="flex items-start justify-between mb-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono text-muted-foreground/50 w-4 shrink-0">#{idx + 1}</span>
                    <div className="min-w-0">
                      <p className="text-xs font-medium truncate">{a.name}</p>
                      <p className="text-[10px] text-muted-foreground capitalize">{a.type} · <span className="text-muted-foreground/70">{a.tenantName}</span></p>
                    </div>
                  </div>
                  <span className={cn("ml-2 shrink-0 text-xs px-2 py-0.5 rounded font-semibold border capitalize", riskLevelBg(a.riskLevel))}>
                    {a.riskScore != null ? a.riskScore : "—"}
                  </span>
                </div>
                <div className="ml-6">
                  <div className="h-1.5 bg-accent rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all"
                      style={{ width: `${a.riskScore ?? 0}%`, background: (a.riskScore ?? 0) >= 70 ? "#ef4444" : (a.riskScore ?? 0) >= 40 ? "#f97316" : "#eab308" }} />
                  </div>
                </div>
                {a.criticalCount > 0 && (
                  <p className="ml-6 text-[10px] text-red-400 mt-0.5">{a.criticalCount} critical · {a.openFindingCount} open</p>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Client Risk Rankings */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Target className="w-4 h-4 text-purple-400" /> Client Risk Rankings
            </h3>
            <span className="text-xs text-muted-foreground">{clientRiskRankings.length} clients</span>
          </div>
          <div className="divide-y divide-border/50">
            {clientRiskRankings.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">No clients yet</div>
            ) : clientRiskRankings.slice(0, 6).map((c: any, idx: number) => (
              <div key={c.id} className="px-4 py-3 hover:bg-accent/30 transition-colors">
                <div className="flex items-start justify-between mb-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono text-muted-foreground/50 w-4 shrink-0">#{idx + 1}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{c.name}</p>
                      <p className="text-[10px] text-muted-foreground">{c.assetCount} assets · {c.openFindingCount} open · <span className="capitalize">{c.plan}</span></p>
                    </div>
                  </div>
                  <span className={cn("ml-2 shrink-0 text-xs px-2 py-0.5 rounded font-semibold border capitalize", riskLevelBg(c.riskLevel))}>
                    {c.riskScore > 0 ? c.riskScore : "—"}
                  </span>
                </div>
                <div className="ml-6">
                  <div className="h-1.5 bg-accent rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all"
                      style={{ width: `${c.riskScore}%`, background: c.riskScore >= 70 ? "#ef4444" : c.riskScore >= 40 ? "#f97316" : "#eab308" }} />
                  </div>
                </div>
                {c.criticalCount > 0 && (
                  <p className="ml-6 text-[10px] text-red-400 mt-0.5">{c.criticalCount} critical finding{c.criticalCount !== 1 ? "s" : ""}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Threat Intelligence Summary (shown when TI module is active) ────── */}
      {threatIntelEnabled && tiData && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-orange-400" /> Threat Intelligence Summary
            </h3>
            <Link href="/threat-intel">
              <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
                Open TI <ArrowRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
          <div className="p-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "IOCs",               value: tiData.totals?.iocs         ?? 0, color: "text-orange-400" },
              { label: "Threat Actors",      value: tiData.totals?.actors       ?? 0, color: "text-purple-400" },
              { label: "Asset Correlations", value: tiData.totals?.correlations ?? 0, color: "text-green-400" },
              { label: "Active Exploitation",value: tiData.totals?.criticalCorrelations ?? 0, color: "text-red-400" },
            ].map(s => (
              <div key={s.label} className="bg-muted/30 border border-border rounded-lg px-3 py-2.5">
                <p className={cn("text-xl font-bold tabular-nums", s.color)}>{Number(s.value).toLocaleString()}</p>
                <p className="text-[10px] text-muted-foreground mt-0.5">{s.label}</p>
              </div>
            ))}
          </div>
          {(tiData.topActors ?? []).length > 0 && (
            <div className="px-4 pb-4">
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-2">Top Correlated Actors</p>
              <div className="space-y-1.5">
                {(tiData.topActors as any[]).slice(0, 3).map((a: any) => (
                  <a key={a.id} href={`/threat-intel/actors/${a.id}`}
                    className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/40 transition-colors text-xs group">
                    <div className="flex items-center gap-2 min-w-0">
                      <Users className="w-3 h-3 text-purple-400 shrink-0" />
                      <span className="font-medium truncate group-hover:text-primary transition-colors">{a.name}</span>
                      {a.country && <span className="text-muted-foreground/60 shrink-0">{a.country}</span>}
                    </div>
                    <span className={cn("font-bold tabular-nums shrink-0 ml-3 text-sm",
                      Number(a.riskScore) >= 70 ? "text-red-400" : Number(a.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400")}>
                      {Math.round(Number(a.riskScore ?? 0))}
                    </span>
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent Alerts */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Bell className="w-4 h-4 text-amber-400" /> Recent Alerts
          </h3>
          <Link href="/alerts">
            <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </span>
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-border/50">
          {recentAlerts.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground col-span-2">
              <Bell className="w-7 h-7 mx-auto mb-2 opacity-30" /> No unread alerts
            </div>
          ) : recentAlerts.map((a: any) => (
            <Link key={a.id} href={`/alerts/${a.id}`}>
              <div className="px-4 py-3 transition-colors hover:bg-accent/30 bg-primary/[0.03] cursor-pointer">
                <div className="flex items-start gap-2.5">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-xs font-medium truncate flex-1">{a.title}</p>
                      <SeverityBadge severity={a.severity} />
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-1">
                      <Building2 className="w-2.5 h-2.5 shrink-0" />
                      {a.clientName} · {new Date(a.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4 text-muted-foreground" /> Quick Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link href="/takedowns">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-purple-500/50 hover:bg-purple-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-purple-500/15 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-purple-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-purple-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Submitted Takedowns</p>
              <p className="text-2xl font-black tabular-nums text-purple-400 mt-1">{d.takedownsCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Manage takedown requests</p>
            </div>
          </Link>
          <Link href="/brand-threats">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-orange-500/50 hover:bg-orange-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-orange-500/15 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-orange-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-orange-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Brand Threats</p>
              <p className="text-2xl font-black tabular-nums text-orange-400 mt-1">{d.brandThreatsCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Active brand threat scans</p>
            </div>
          </Link>
          <Link href="/findings">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-red-500/50 hover:bg-red-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                  <Bug className="w-5 h-5 text-red-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-red-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Vulnerabilities</p>
              <p className="text-2xl font-black tabular-nums text-red-400 mt-1">{d.criticalCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Critical open vulnerabilities</p>
            </div>
          </Link>
        </div>
      </div>

      {/* ── False Positive Status ──────────────────────────────────────────── */}
      <div>
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Status
        </h3>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <StatCard label="Pending" value={fpData.submitted} icon={Clock}
            color={fpData.submitted > 0 ? "text-yellow-400" : undefined} />
          <StatCard label="In Progress" value={fpData.in_progress ?? 0} icon={Clock}
            color={(fpData.in_progress ?? 0) > 0 ? "text-blue-400" : undefined} />
          <StatCard label="Confirmed FPs" value={fpData.confirmed} icon={CheckCircle2}
            color={fpData.confirmed > 0 ? "text-green-400" : undefined} />
          <StatCard label="Rejected" value={fpData.rejected} icon={XCircle}
            color={fpData.rejected > 0 ? "text-red-400" : undefined} />
        </div>
        {fpFindings.length > 0 ? (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Findings
              </h4>
              <span className="text-xs text-muted-foreground">{fpFindings.length} finding{fpFindings.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-accent/20">
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Severity</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding Status</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">FP Status</th>
                    <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {fpFindings.map((f: any) => (
                    <tr key={f.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                      <td className="px-4 py-3 max-w-[260px]">
                        <Link href={`/findings/${f.id}`}>
                          <p className="text-xs font-medium hover:text-primary transition-colors cursor-pointer line-clamp-2">{f.title}</p>
                        </Link>
                        {f.cveId && <p className="text-[10px] text-muted-foreground font-mono mt-0.5">{f.cveId}</p>}
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-xs text-muted-foreground truncate max-w-[120px]">{f.assetName}</p>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-[10px] font-semibold capitalize px-1.5 py-0.5 rounded border"
                          style={{
                            background: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}22`,
                            color: SEVERITY_COLORS[f.severity] ?? "#64748b",
                            borderColor: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}44`,
                          }}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-[10px] capitalize text-muted-foreground">{(f.status ?? "").replace(/_/g, " ")}</span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <FpStatusBadge status={f.falsePositiveStatus ?? "none"} />
                      </td>
                      <td className="px-4 py-3 text-right text-[10px] text-muted-foreground whitespace-nowrap">
                        {new Date(f.updatedAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl px-4 py-8 text-center text-sm text-muted-foreground">
            No false positive findings submitted yet.
          </div>
        )}
      </div>

      {/* AM Portfolio */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-muted-foreground" /> Account Manager Portfolio
          </h3>
          <span className="text-xs text-muted-foreground">{amPortfolio.length} account managers</span>
        </div>
        {amPortfolio.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">No account manager assignments configured yet.</div>
        ) : (
          <div className="divide-y divide-border/50">
            {amPortfolio.map((am: any) => (
              <div key={am.amId} className="px-4 py-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 rounded-full bg-blue-500/15 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-bold text-blue-400">{am.amName.charAt(0).toUpperCase()}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold truncate">{am.amName}</p>
                    <p className="text-xs text-muted-foreground truncate">{am.amEmail}</p>
                  </div>
                  <Badge variant="outline" className="text-xs flex-shrink-0">
                    {am.clientCount} {am.clientCount === 1 ? "client" : "clients"}
                  </Badge>
                </div>
                {am.clients.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 ml-12">
                    {am.clients.map((c: any) => (
                      <div key={c.id} className="bg-accent/30 border border-border/50 rounded-lg px-3 py-2">
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-medium truncate">{c.name}</p>
                          <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium border flex-shrink-0",
                            c.isActive
                              ? "bg-green-500/15 text-green-400 border-green-500/30"
                              : "bg-muted text-muted-foreground border-border")}>
                            {c.isActive ? "Active" : "Inactive"}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 mt-1 flex-wrap mb-1.5">
                          <span className="text-[10px] text-muted-foreground">{c.assetCount} assets</span>
                          {c.criticalCount > 0 && <span className="text-[10px] text-red-400 font-medium">{c.criticalCount} critical</span>}
                          {c.openFindingCount > 0 && <span className="text-[10px] text-amber-400">{c.openFindingCount} open</span>}
                        </div>
                        {c.assets?.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {c.assets.map((a: any) => (
                              <span key={a.id} className="inline-flex items-center gap-1 text-[10px] bg-accent/60 border border-border/40 rounded px-1.5 py-0.5">
                                <span className="capitalize text-muted-foreground">{a.type}</span>
                                <span className="font-medium text-foreground truncate max-w-[80px]">{a.name}</span>
                                {a.riskLevel === "critical" && <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />}
                                {a.riskLevel === "high" && <span className="w-1.5 h-1.5 rounded-full bg-orange-500 flex-shrink-0" />}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground ml-12">No clients assigned.</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Full Client Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Building2 className="w-4 h-4 text-muted-foreground" /> All Client Organizations
          </h3>
          <span className="text-xs text-muted-foreground">{tenants.length} organizations</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-accent/20">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Organization</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Users</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Open</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Total Scans</th>
                <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              </tr>
            </thead>
            <tbody>
              {tenants.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-10 text-center text-sm text-muted-foreground">
                  No client organizations yet.
                </td></tr>
              )}
              {tenants.map((t: any) => (
                <tr key={t.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-3">
                    <p className="font-medium text-sm">{t.name}</p>
                    <p className="text-[10px] text-muted-foreground">{t.slug}</p>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-sm">{t.userCount}</td>
                  <td className="px-4 py-3 text-right tabular-nums text-sm">{t.assetCount}</td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {t.openFindingCount > 0
                      ? <span className="text-amber-400 font-semibold">{t.openFindingCount}</span>
                      : <span className="text-muted-foreground/50">0</span>}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">
                    {t.criticalCount > 0
                      ? <span className="text-red-400 font-bold">{t.criticalCount}</span>
                      : <span className="text-muted-foreground/50">0</span>}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-sm">
                    {(t.scanCount ?? 0) > 0
                      ? <span className="font-medium">{t.scanCount}</span>
                      : <span className="text-muted-foreground/50">0</span>}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                      t.isActive
                        ? "bg-green-500/15 text-green-400 border-green-500/30"
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
  const fpData     = data?.falsePositives ?? { submitted: 0, in_progress: 0, confirmed: 0, rejected: 0 };
  const fpFindings: any[] = data?.falsePositiveFindings ?? [];

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

      <AiMapperBanner adminLink />

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
                      {a.riskLevel ?? "—"}
                    </span>
                  </div>
                  <div className="ml-6">
                    <RiskBar score={a.riskScore ?? 0} level={a.riskLevel ?? "low"} />
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
                No unread alerts
              </div>
            ) : recentAlerts.map((a: any) => (
              <Link key={a.id} href={`/alerts/${a.id}`}>
                <div className="px-4 py-3 transition-colors hover:bg-accent/30 bg-primary/[0.03] cursor-pointer">
                  <div className="flex items-start gap-2.5">
                    <div className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-xs font-medium truncate flex-1">{a.title}</p>
                        <SeverityBadge severity={a.severity} />
                      </div>
                      <p className="text-[10px] text-muted-foreground mt-0.5 flex items-center gap-1">
                        <Building2 className="w-2.5 h-2.5 shrink-0" />
                        {a.clientName} · {new Date(a.createdAt).toLocaleDateString()}
                      </p>
                    </div>
                    <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                  </div>
                </div>
              </Link>
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

      {/* ── False Positive Status ────────────────────────────────────────── */}
      <div>
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Status
        </h3>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <StatCard label="Pending" value={fpData.submitted} icon={Clock}
            color={fpData.submitted > 0 ? "text-yellow-400" : undefined} />
          <StatCard label="In Progress" value={fpData.in_progress ?? 0} icon={Clock}
            color={(fpData.in_progress ?? 0) > 0 ? "text-blue-400" : undefined} />
          <StatCard label="Confirmed FPs" value={fpData.confirmed} icon={CheckCircle2}
            color={fpData.confirmed > 0 ? "text-green-400" : undefined} />
          <StatCard label="Rejected" value={fpData.rejected} icon={XCircle}
            color={fpData.rejected > 0 ? "text-red-400" : undefined} />
        </div>
        {fpFindings.length > 0 ? (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Findings
              </h4>
              <span className="text-xs text-muted-foreground">{fpFindings.length} finding{fpFindings.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-accent/20">
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Severity</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding Status</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">FP Status</th>
                    <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {fpFindings.map((f: any) => (
                    <tr key={f.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                      <td className="px-4 py-3 max-w-[260px]">
                        <Link href={`/findings/${f.id}`}>
                          <p className="text-xs font-medium hover:text-primary transition-colors cursor-pointer line-clamp-2">{f.title}</p>
                        </Link>
                        {f.cveId && <p className="text-[10px] text-muted-foreground font-mono mt-0.5">{f.cveId}</p>}
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-xs text-muted-foreground truncate max-w-[120px]">{f.assetName}</p>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-[10px] font-semibold capitalize px-1.5 py-0.5 rounded border"
                          style={{
                            background: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}22`,
                            color: SEVERITY_COLORS[f.severity] ?? "#64748b",
                            borderColor: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}44`,
                          }}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize",
                          f.status === "open" ? "bg-amber-500/15 text-amber-400 border-amber-500/30" :
                          f.status === "false_positive" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                          f.status === "mitigated" ? "bg-green-500/15 text-green-400 border-green-500/30" :
                          "bg-muted text-muted-foreground border-border")}>
                          {f.status?.replace(/_/g, " ")}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <FpStatusBadge status={f.falsePositiveStatus ?? "none"} />
                      </td>
                      <td className="px-4 py-3 text-right text-[11px] text-muted-foreground whitespace-nowrap">
                        {new Date(f.updatedAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl px-4 py-8 text-center">
            <CheckCircle2 className="w-7 h-7 mx-auto mb-2 text-green-400/50" />
            <p className="text-sm text-muted-foreground">No false positive submissions across client portfolio</p>
          </div>
        )}
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
  const { user } = useAuth();
  const { data, isLoading } = useQuery({
    queryKey: ["admin-overview"],
    queryFn: () => apiFetch<any>(`${BASE}/api/dashboard/admin-overview`),
    staleTime: 30_000,
  });
  const { data: assetBreakdown } = useGetAssetBreakdown({
    query: { queryKey: getGetAssetBreakdownQueryKey() },
  });

  if (isLoading) return <DashboardSkeleton cards={12} />;
  const d = data ?? {};
  const riskTrend: any[] = d.riskTrend ?? [];
  const severityBreakdown: any[] = d.severityBreakdown ?? [];
  const assetRiskRankings: any[] = d.assetRiskRankings ?? [];
  const amPortfolioAdmin: any[] = d.amPortfolio ?? [];
  const recentAlerts: any[] = d.recentAlerts ?? [];
  const clientRiskRankings: any[] = d.clientRiskRankings ?? [];
  const allClientOrganizations: any[] = d.allClientOrganizations ?? [];
  const fpData = d.falsePositives ?? { submitted: 0, in_progress: 0, confirmed: 0, rejected: 0 };
  const fpFindings: any[] = d.falsePositiveFindings ?? [];

  const riskColor = d.riskScore >= 70 ? "text-red-400" : d.riskScore >= 40 ? "text-amber-400" : "text-green-400";

  return (
    <div className="space-y-5">
      {/* Hero Banner */}
      <div className="rounded-2xl overflow-hidden bg-gradient-to-r from-slate-900 via-blue-950 to-slate-900 border border-blue-500/20 p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-5 h-5 text-blue-400" />
              <span className="text-xs font-medium text-blue-300 uppercase tracking-widest">Admin Dashboard</span>
            </div>
            <h1 className="text-2xl font-bold text-white">Security Command Center</h1>
            <p className="text-sm text-slate-400 mt-1">Your organization's full threat exposure at a glance</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-500 uppercase tracking-wide mb-0.5">Risk Score</p>
            <p className={cn("text-4xl font-black tabular-nums", riskColor)}>{d.riskScore ?? "—"}</p>
            <p className="text-[10px] text-slate-500 mt-0.5">{d.assetCount ?? 0} assets monitored</p>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-4 gap-3">
          {[
            { label: "Total Assets", value: d.assetCount, color: "text-blue-300" },
            { label: "Critical Vulns", value: d.criticalCount, color: "text-red-300" },
            { label: "Open Findings", value: d.openFindingCount, color: "text-amber-300" },
            { label: "Open Alerts", value: d.openAlertsCount, color: "text-orange-300" },
          ].map(s => (
            <div key={s.label} className="bg-white/5 rounded-xl px-4 py-3 border border-white/10">
              <p className="text-[10px] text-slate-400 uppercase tracking-wide">{s.label}</p>
              <p className={cn("text-xl font-bold tabular-nums mt-0.5", s.color)}>{s.value ?? "—"}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Row 0 — AM / Client metrics (only shown when AM portfolio data exists) */}
      {(d.amCount > 0 || d.totalClients > 0) && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Account Managers" value={d.amCount ?? 0} icon={Users} color="text-blue-400" />
          <StatCard label="Total Clients" value={d.totalClients ?? 0} icon={Building2} color="text-purple-400" />
          <StatCard label="Critical Risk Assets" value={d.criticalClients ?? 0} icon={ShieldAlert}
            color={(d.criticalClients ?? 0) > 0 ? "text-red-400" : undefined} />
          <StatCard label="Active Scans" value={d.activeScans ?? 0} icon={Radar} color="text-blue-400" />
        </div>
      )}

      {/* Row 1 — 4 primary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Assets" value={d.assetCount} icon={Server} />
        <StatCard label="Critical Vulnerabilities" value={d.criticalCount} icon={AlertTriangle}
          color={d.criticalCount > 0 ? "text-red-400" : undefined} />
        <StatCard label="Open Findings" value={d.openFindingCount} icon={Bug}
          color={d.openFindingCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="Risk Score" value={d.riskScore} icon={TrendingUp} color={riskColor} />
      </div>

      {/* Row 2 — 4 secondary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Open Alerts" value={d.openAlertsCount} icon={Bell}
          color={d.openAlertsCount > 0 ? "text-amber-400" : undefined} />
        <StatCard label="New Vulns (7D)" value={d.newVulns7D} icon={TrendingUp}
          color={d.newVulns7D > 0 ? "text-red-400" : "text-green-400"} />
        <StatCard label="Resolved Vulns (7D)" value={d.resolvedVulns7D} icon={CheckCircle2}
          color={d.resolvedVulns7D > 0 ? "text-green-400" : undefined} />
        <StatCard label="Brand Threats" value={d.brandThreatsCount} icon={Globe}
          color={d.brandThreatsCount > 0 ? "text-orange-400" : undefined} />
      </div>

      {/* Row 3 — 4 tertiary stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Exposed Ports" value={d.exposedPortsCount} icon={Activity}
          color={d.exposedPortsCount > 0 ? "text-orange-400" : undefined} />
        <StatCard label="High Findings" value={d.highCount} icon={Bug}
          color={d.highCount > 0 ? "text-orange-400" : undefined} />
        <StatCard label="Takedown Requests" value={d.takedownsCount} icon={Shield} color="text-cyan-400" />
        <StatCard label="Team Members" value={d.userCount} icon={Users2} color="text-violet-400" />
      </div>

      <AiMapperBanner />

      {/* Queue Health Widget */}
      <QueueHealthWidget />

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Risk Score Trend (14 days)</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={riskTrend}>
              <defs>
                <linearGradient id="adminRiskGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(217 33% 17%)" />
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 10 }} tickFormatter={(v) => v?.slice(5)} />
              <YAxis tick={{ fill: "#64748b", fontSize: 10 }} domain={[0, 100]} />
              <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                labelStyle={{ color: "#94a3b8" }} />
              <Area type="monotone" dataKey="value" stroke="#3b82f6" strokeWidth={2} fill="url(#adminRiskGrad)" name="Risk Score" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-4">Severity Breakdown</h3>
          {severityBreakdown.length === 0 ? (
            <div className="flex items-center justify-center h-40 text-sm text-muted-foreground">No findings yet</div>
          ) : (
            <>
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={severityBreakdown} dataKey="count" nameKey="severity" cx="50%" cy="50%" innerRadius={45} outerRadius={70}>
                    {severityBreakdown.map((e: any) => <Cell key={e.severity} fill={SEVERITY_COLORS[e.severity] ?? "#64748b"} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: "hsl(222 47% 11%)", border: "1px solid hsl(217 33% 17%)", borderRadius: "8px", fontSize: "12px" }}
                    formatter={(v: any, name: any) => [v, capitalize(name)]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="mt-2 space-y-1.5">
                {severityBreakdown.map((s: any) => (
                  <div key={s.severity} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-sm" style={{ background: SEVERITY_COLORS[s.severity] }} />
                      <span className="capitalize text-muted-foreground">{s.severity}</span>
                    </div>
                    <span className="font-semibold tabular-nums">{s.count}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {/* Asset Risk Rankings + Client Risk Rankings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Asset Risk Rankings */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Target className="w-4 h-4 text-blue-400" /> Asset Risk Rankings
            </h3>
            <Link href="/assets">
              <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
                View all <ArrowRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
          <div className="divide-y divide-border/50">
            {assetRiskRankings.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                <Target className="w-7 h-7 mx-auto mb-2 opacity-30" />
                No risk scores computed yet
              </div>
            ) : assetRiskRankings.map((a: any, idx: number) => (
              <Link key={a.assetId} href={`/assets/${a.assetId}`}>
                <div className="px-4 py-3 hover:bg-accent/30 cursor-pointer transition-colors">
                  <div className="flex items-start justify-between mb-1.5">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] font-mono text-muted-foreground/50 w-4 shrink-0">#{idx + 1}</span>
                      <div className="min-w-0">
                        <p className="text-sm font-medium truncate">{a.assetName}</p>
                        <p className="text-[10px] text-muted-foreground capitalize">{a.assetType} · {a.findingsCount} finding{a.findingsCount !== 1 ? "s" : ""}</p>
                      </div>
                    </div>
                    <span className={cn("ml-2 shrink-0 text-xs px-2 py-0.5 rounded font-semibold border capitalize", riskLevelBg(a.riskLevel))}>
                      {a.riskScore}
                    </span>
                  </div>
                  <div className="ml-6">
                    <div className="h-1.5 bg-accent rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all"
                        style={{ width: `${a.riskScore}%`, background: a.riskScore >= 70 ? "#ef4444" : a.riskScore >= 40 ? "#f97316" : "#eab308" }} />
                    </div>
                  </div>
                  {a.criticalCount > 0 && (
                    <p className="ml-6 text-[10px] text-red-400 mt-0.5">{a.criticalCount} critical</p>
                  )}
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Client Risk Rankings */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="text-sm font-medium flex items-center gap-2">
              <Building2 className="w-4 h-4 text-purple-400" /> Client Risk Rankings
            </h3>
            <span className="text-xs text-muted-foreground">{clientRiskRankings.length} client{clientRiskRankings.length !== 1 ? "s" : ""}</span>
          </div>
          <div className="divide-y divide-border/50">
            {clientRiskRankings.length === 0 ? (
              <div className="px-4 py-8 text-center text-sm text-muted-foreground">
                <Building2 className="w-7 h-7 mx-auto mb-2 opacity-30" />
                No clients assigned to account managers yet
              </div>
            ) : clientRiskRankings.map((c: any, idx: number) => (
              <div key={c.tenantId} className="px-4 py-3">
                <div className="flex items-start justify-between mb-1.5">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-mono text-muted-foreground/50 w-4 shrink-0">#{idx + 1}</span>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">{c.tenantName}</p>
                      <p className="text-[10px] text-muted-foreground">{c.assetCount} asset{c.assetCount !== 1 ? "s" : ""} · {c.openFindingCount} open</p>
                    </div>
                  </div>
                  <span className={cn("ml-2 shrink-0 text-xs px-2 py-0.5 rounded font-semibold border capitalize", riskLevelBg(c.riskLevel))}>
                    {c.avgRisk}
                  </span>
                </div>
                <div className="ml-6">
                  <div className="h-1.5 bg-accent rounded-full overflow-hidden">
                    <div className="h-full rounded-full transition-all"
                      style={{ width: `${c.avgRisk}%`, background: c.avgRisk >= 70 ? "#ef4444" : c.avgRisk >= 40 ? "#f97316" : "#eab308" }} />
                  </div>
                </div>
                {c.criticalCount > 0 && (
                  <p className="ml-6 text-[10px] text-red-400 mt-0.5">{c.criticalCount} critical finding{c.criticalCount !== 1 ? "s" : ""}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Alerts */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Bell className="w-4 h-4 text-amber-400" /> Recent Alerts
          </h3>
          <Link href="/alerts">
            <span className="text-xs text-primary hover:underline cursor-pointer flex items-center gap-1">
              View all <ArrowRight className="w-3 h-3" />
            </span>
          </Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 divide-border/50 [&>*]:border-b [&>*]:border-border/50">
          {recentAlerts.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground col-span-2">
              <Bell className="w-7 h-7 mx-auto mb-2 opacity-30" /> No unread alerts
            </div>
          ) : recentAlerts.map((a: any) => (
            <Link key={a.id} href={`/alerts/${a.id}`}>
              <div className="px-4 py-3 transition-colors hover:bg-accent/30 bg-primary/[0.03] cursor-pointer">
                <div className="flex items-start gap-2.5">
                  <div className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-xs font-medium truncate flex-1">{a.title}</p>
                      <SeverityBadge severity={a.severity} />
                    </div>
                    <p className="text-[10px] text-muted-foreground mt-0.5">
                      {new Date(a.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <ArrowRight className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
                </div>
              </div>
            </Link>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div>
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <Activity className="w-4 h-4 text-muted-foreground" /> Quick Actions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link href="/takedowns">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-cyan-500/50 hover:bg-cyan-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-cyan-500/15 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-cyan-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Submitted Takedowns</p>
              <p className="text-2xl font-black tabular-nums text-cyan-400 mt-1">{d.takedownsCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Manage takedown requests</p>
            </div>
          </Link>
          <Link href="/brand-threats">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-orange-500/50 hover:bg-orange-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-orange-500/15 flex items-center justify-center">
                  <Globe className="w-5 h-5 text-orange-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-orange-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Brand Threats</p>
              <p className="text-2xl font-black tabular-nums text-orange-400 mt-1">{d.brandThreatsCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Active brand threat scans</p>
            </div>
          </Link>
          <Link href="/findings">
            <div className="bg-card border border-border rounded-xl p-4 hover:border-red-500/50 hover:bg-red-500/5 transition-all cursor-pointer group">
              <div className="flex items-center justify-between mb-3">
                <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                  <Bug className="w-5 h-5 text-red-400" />
                </div>
                <ArrowRight className="w-4 h-4 text-muted-foreground group-hover:text-red-400 transition-colors" />
              </div>
              <p className="text-sm font-semibold">Vulnerabilities</p>
              <p className="text-2xl font-black tabular-nums text-red-400 mt-1">{d.criticalCount ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-0.5">Critical open vulnerabilities</p>
            </div>
          </Link>
        </div>
      </div>

      {/* All Client Organizations */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Building2 className="w-4 h-4 text-muted-foreground" /> All Client Organizations
          </h3>
          <span className="text-xs text-muted-foreground">{allClientOrganizations.length} organization{allClientOrganizations.length !== 1 ? "s" : ""}</span>
        </div>
        {allClientOrganizations.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-muted-foreground">
            <Building2 className="w-7 h-7 mx-auto mb-2 opacity-30" />
            No client organizations assigned to account managers yet
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-accent/20">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Organization</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                  <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                  <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Open</th>
                  <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                  <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Avg Risk</th>
                  <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                </tr>
              </thead>
              <tbody>
                {allClientOrganizations.map((t: any) => (
                  <tr key={t.tenantId} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-sm">{t.tenantName}</p>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-sm">{t.assetCount}</td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      {t.openFindingCount > 0
                        ? <span className="text-amber-400 font-semibold">{t.openFindingCount}</span>
                        : <span className="text-muted-foreground/50">0</span>}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      {t.criticalCount > 0
                        ? <span className="text-red-400 font-bold">{t.criticalCount}</span>
                        : <span className="text-muted-foreground/50">0</span>}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      <span className={cn("font-semibold", t.avgRisk >= 70 ? "text-red-400" : t.avgRisk >= 40 ? "text-orange-400" : "text-green-400")}>
                        {t.avgRisk}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                        t.isActive
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : "bg-muted text-muted-foreground border-border")}>
                        {t.isActive ? "Active" : "Inactive"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* AM Portfolio */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-muted-foreground" /> Account Manager Portfolio
          </h3>
          <span className="text-xs text-muted-foreground">{amPortfolioAdmin.length} account managers</span>
        </div>
        {amPortfolioAdmin.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            <Briefcase className="w-7 h-7 mx-auto mb-2 opacity-30" />
            No account managers configured yet
          </div>
        ) : (
          <div className="divide-y divide-border/50">
            {amPortfolioAdmin.map((am: any) => (
              <div key={am.amId} className="px-4 py-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 rounded-full bg-blue-500/15 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-bold text-blue-400">{am.amName.charAt(0).toUpperCase()}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold truncate">{am.amName}</p>
                    <p className="text-xs text-muted-foreground truncate">{am.amEmail}</p>
                  </div>
                  <Badge variant="outline" className="text-xs flex-shrink-0">
                    {am.clientCount ?? 0} {(am.clientCount ?? 0) === 1 ? "client" : "clients"}
                  </Badge>
                </div>
                {(am.clients?.length ?? 0) > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 ml-12">
                    {am.clients.map((c: any) => (
                      <div key={c.id} className="bg-accent/30 border border-border/50 rounded-lg px-3 py-2">
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <p className="text-xs font-medium truncate">{c.name}</p>
                          <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium border flex-shrink-0",
                            c.isActive
                              ? "bg-green-500/15 text-green-400 border-green-500/30"
                              : "bg-muted text-muted-foreground border-border")}>
                            {c.isActive ? "Active" : "Inactive"}
                          </span>
                        </div>
                        <div className="flex items-center gap-3 flex-wrap mb-1.5">
                          <span className="text-[10px] text-muted-foreground">{c.assetCount} assets</span>
                          {c.criticalCount > 0 && <span className="text-[10px] text-red-400 font-medium">{c.criticalCount} critical</span>}
                          {c.openFindingCount > 0 && <span className="text-[10px] text-amber-400">{c.openFindingCount} open</span>}
                        </div>
                        {c.assets?.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {c.assets.map((a: any) => (
                              <span key={a.id} className="inline-flex items-center gap-1 text-[10px] bg-accent/60 border border-border/40 rounded px-1.5 py-0.5">
                                <span className="capitalize text-muted-foreground">{a.type}</span>
                                <span className="font-medium text-foreground truncate max-w-[80px]">{a.name}</span>
                                {a.riskLevel === "critical" && <span className="w-1.5 h-1.5 rounded-full bg-red-500 flex-shrink-0" />}
                                {a.riskLevel === "high" && <span className="w-1.5 h-1.5 rounded-full bg-orange-500 flex-shrink-0" />}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground ml-12">No clients assigned.</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── False Positive Status ──────────────────────────────────────────── */}
      <div>
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Status
        </h3>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <StatCard label="Pending" value={fpData.submitted} icon={Clock}
            color={fpData.submitted > 0 ? "text-yellow-400" : undefined} />
          <StatCard label="In Progress" value={fpData.in_progress ?? 0} icon={Clock}
            color={(fpData.in_progress ?? 0) > 0 ? "text-blue-400" : undefined} />
          <StatCard label="Confirmed FPs" value={fpData.confirmed} icon={CheckCircle2}
            color={fpData.confirmed > 0 ? "text-green-400" : undefined} />
          <StatCard label="Rejected" value={fpData.rejected} icon={XCircle}
            color={fpData.rejected > 0 ? "text-red-400" : undefined} />
        </div>
        {fpFindings.length > 0 ? (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border flex items-center justify-between">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <XCircle className="w-4 h-4 text-yellow-400" /> False Positive Findings
              </h4>
              <span className="text-xs text-muted-foreground">{fpFindings.length} finding{fpFindings.length !== 1 ? "s" : ""}</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-accent/20">
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Severity</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">Finding Status</th>
                    <th className="text-center px-4 py-2.5 text-xs font-medium text-muted-foreground">FP Status</th>
                    <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {fpFindings.map((f: any) => (
                    <tr key={f.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                      <td className="px-4 py-3 max-w-[260px]">
                        <Link href={`/findings/${f.id}`}>
                          <p className="text-xs font-medium hover:text-primary transition-colors cursor-pointer line-clamp-2">{f.title}</p>
                        </Link>
                        {f.cveId && <p className="text-[10px] text-muted-foreground font-mono mt-0.5">{f.cveId}</p>}
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-xs text-muted-foreground truncate max-w-[120px]">{f.assetName}</p>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-[10px] font-semibold capitalize px-1.5 py-0.5 rounded border"
                          style={{
                            background: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}22`,
                            color: SEVERITY_COLORS[f.severity] ?? "#64748b",
                            borderColor: `${SEVERITY_COLORS[f.severity] ?? "#64748b"}44`,
                          }}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-[10px] capitalize text-muted-foreground">{(f.status ?? "").replace(/_/g, " ")}</span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <FpStatusBadge status={f.falsePositiveStatus ?? "none"} />
                      </td>
                      <td className="px-4 py-3 text-right text-[10px] text-muted-foreground whitespace-nowrap">
                        {new Date(f.updatedAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <div className="bg-card border border-border rounded-xl px-4 py-8 text-center text-sm text-muted-foreground">
            No false positive findings submitted yet.
          </div>
        )}
      </div>

      {/* Asset Type Breakdown */}
      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-sm font-medium mb-4">Asset Type Breakdown</h3>
        <ResponsiveContainer width="100%" height={130}>
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
  if (user?.role === "super_admin" || user?.role === "admin") return <SuperAdminDashboard />;
  if (user?.role === "account_manager") return <AccountManagerDashboard />;
  if (user?.role === "client") return <ClientDashboardPage />;
  return <AdminDashboard />;
}
