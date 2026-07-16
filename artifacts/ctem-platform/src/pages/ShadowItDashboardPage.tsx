import { useState } from "react";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  EyeOff, Globe, Network, Shield, RefreshCw, AlertTriangle,
  CheckCircle2, XCircle, Clock, ArrowRight, Users, Building2,
  ChevronRight, Bell, TrendingUp, Activity, Wifi, Package,
  Zap, Lock, Radio, Monitor, Cpu, HardDrive, Printer,
  BarChart3, Plus, ExternalLink, Loader2,
} from "lucide-react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
} from "recharts";
import { cn } from "@/lib/utils";

interface DashboardData {
  shadowAssets: { total: number; critical: number; high: number; pending: number };
  shadowSaas: { total: number; unsanctioned: number; critical: number };
  idpConnections: Array<{
    id: number; provider: string; displayName: string; isActive: boolean;
    lastSyncStatus: string; lastSyncAt: string | null; syncedApps: number; syncedUsers: number; lastSyncError: string | null;
  }>;
  oauthApps: {
    total: number; critical: number; high: number; medium: number; low: number;
    topRisky: Array<{ id: number; displayName: string; riskLevel: string; riskScore: number; provider: string; userCount: number; isSanctioned: boolean }>;
  };
  networkDevices: { total: number; new: number; byType: Record<string, number> };
}

interface AlertRule {
  id: number; name: string; triggerType: string;
  channel: string; isActive: boolean;
}

const PROVIDER_META: Record<string, { label: string; bg: string; icon: string }> = {
  google_workspace: { label: "Google Workspace", bg: "bg-blue-500",   icon: "G" },
  microsoft_graph:  { label: "Microsoft Entra",  bg: "bg-sky-500",    icon: "M" },
  okta:             { label: "Okta",              bg: "bg-indigo-500", icon: "O" },
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e",
};

const RISK_BG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low:      "bg-green-500/10 text-green-400 border-green-500/20",
};

const DEVICE_ICONS: Record<string, React.ReactNode> = {
  workstation: <Monitor className="w-3.5 h-3.5" />,
  server:      <Cpu className="w-3.5 h-3.5" />,
  printer:     <Printer className="w-3.5 h-3.5" />,
  router:      <Radio className="w-3.5 h-3.5" />,
  switch:      <Network className="w-3.5 h-3.5" />,
  nas:         <HardDrive className="w-3.5 h-3.5" />,
  iot:         <Wifi className="w-3.5 h-3.5" />,
  unknown:     <Globe className="w-3.5 h-3.5" />,
};

const DEVICE_LABELS: Record<string, string> = {
  workstation: "Workstations", server: "Servers", printer: "Printers",
  router: "Routers", switch: "Switches", nas: "NAS / Storage",
  iot: "IoT Devices", unknown: "Unknown",
};

function formatSync(dt: string | null): string {
  if (!dt) return "Never synced";
  const d = new Date(dt);
  const mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 2) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ShadowItDashboardPage() {
  const [syncing, setSyncing] = useState<number | null>(null);

  const { data, isLoading, refetch, isFetching } = useQuery<DashboardData>({
    queryKey: ["shadow-it-dashboard"],
    queryFn: () => apiFetch("/api/shadow-it/dashboard"),
    refetchInterval: 30_000,
  });

  const { data: alertRules } = useQuery<AlertRule[]>({
    queryKey: ["shadow-it-alert-rules-count"],
    queryFn: () => apiFetch<AlertRule[]>("/api/alerts/rules"),
    select: (rows) => rows.filter((r) => r.triggerType === "shadow_it_discovered"),
  });

  const syncConnection = async (id: number) => {
    setSyncing(id);
    try {
      await apiFetch(`/api/shadow-it/idp-connections/${id}/sync`, { method: "POST" });
      await refetch();
    } catch { /* handled by apiFetch */ }
    setSyncing(null);
  };

  const riskPieData = data ? [
    { name: "Critical", value: data.oauthApps.critical, fill: RISK_COLORS.critical },
    { name: "High",     value: data.oauthApps.high,     fill: RISK_COLORS.high },
    { name: "Medium",   value: data.oauthApps.medium,   fill: RISK_COLORS.medium },
    { name: "Low",      value: data.oauthApps.low,      fill: RISK_COLORS.low },
  ].filter(d => d.value > 0) : [];

  const totalRisk = (data?.shadowAssets.critical ?? 0) + (data?.shadowAssets.high ?? 0);
  const riskScore = data
    ? Math.min(100, Math.round(
        ((data.shadowAssets.critical * 25 + data.shadowAssets.high * 15 +
          data.oauthApps.critical * 10 + data.shadowSaas.unsanctioned * 5) /
         Math.max(1, data.shadowAssets.total + data.oauthApps.total + data.shadowSaas.total)) * 10
      ))
    : 0;

  return (
    <div className="flex flex-col h-full min-h-0 overflow-y-auto bg-background">
      {/* ── Hero Header ───────────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden border-b border-border bg-gradient-to-br from-purple-950/40 via-background to-background px-6 py-6 shrink-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-purple-500/5 via-transparent to-transparent pointer-events-none" />
        <div className="relative flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="p-1.5 rounded-lg bg-purple-500/15 border border-purple-500/20">
                <EyeOff className="h-5 w-5 text-purple-400" />
              </div>
              <h1 className="text-xl font-bold tracking-tight">Shadow IT Dashboard</h1>
              {isFetching && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
            </div>
            <p className="text-sm text-muted-foreground">
              Unsanctioned apps, OAuth risk exposure, and unmanaged network devices — across your IdP and infrastructure
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link href="/shadow-it/alerts">
              <Button variant="outline" size="sm" className="h-8 gap-1.5 border-purple-500/30 text-purple-400 hover:bg-purple-500/10">
                <Bell className="h-3.5 w-3.5" /> Alert Rules
              </Button>
            </Link>
            <Button
              variant="outline" size="sm" className="h-8 gap-1.5"
              onClick={() => refetch()} disabled={isFetching}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </div>

        {/* Risk Score Band */}
        {data && (
          <div className="relative mt-5 flex items-center gap-6 bg-card/60 border border-border backdrop-blur-sm rounded-xl px-5 py-3">
            <div className="flex items-center gap-3">
              <div className={cn(
                "h-10 w-10 rounded-full flex items-center justify-center font-bold text-sm tabular-nums border-2",
                riskScore >= 70 ? "bg-red-500/15 border-red-500/30 text-red-400" :
                riskScore >= 40 ? "bg-orange-500/15 border-orange-500/30 text-orange-400" :
                riskScore >= 20 ? "bg-yellow-500/15 border-yellow-500/30 text-yellow-400" :
                                  "bg-green-500/15 border-green-500/30 text-green-400"
              )}>
                {riskScore}
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground uppercase tracking-wide font-semibold">Exposure Score</p>
                <p className="text-xs font-medium">
                  {riskScore >= 70 ? "High exposure — immediate action needed" :
                   riskScore >= 40 ? "Moderate exposure — review flagged items" :
                   riskScore >= 20 ? "Low exposure — monitor regularly" :
                   "Minimal exposure"}
                </p>
              </div>
            </div>
            <div className="h-6 w-px bg-border" />
            <div className="flex items-center gap-5 text-sm">
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-red-500 shrink-0" />
                <span className="text-muted-foreground">{totalRisk} high-risk assets</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-yellow-500 shrink-0" />
                <span className="text-muted-foreground">{data.shadowAssets.pending} pending review</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-orange-500 shrink-0" />
                <span className="text-muted-foreground">{data.shadowSaas.unsanctioned} unsanctioned SaaS</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full bg-blue-500 shrink-0" />
                <span className="text-muted-foreground">{data.networkDevices.new} new devices</span>
              </span>
            </div>
          </div>
        )}
      </div>

      <div className="flex-1 p-6 space-y-6">
        {/* ── KPI Cards ─────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
          {[
            {
              label: "Shadow Assets",
              value: data?.shadowAssets.total ?? 0,
              sub1: `${data?.shadowAssets.critical ?? 0} critical`,
              sub2: `${data?.shadowAssets.high ?? 0} high`,
              icon: <Globe className="h-5 w-5" />,
              href: "/shadow-it/assets",
              accent: "from-orange-500/20 to-orange-500/5",
              border: "border-orange-500/20",
              iconBg: "bg-orange-500/15 text-orange-400",
              badge: (data?.shadowAssets.pending ?? 0) > 0 ? `${data?.shadowAssets.pending} pending` : undefined,
              badgeColor: "bg-yellow-500/15 text-yellow-400 border-yellow-500/20",
            },
            {
              label: "OAuth Apps",
              value: data?.oauthApps.total ?? 0,
              sub1: `${data?.oauthApps.critical ?? 0} critical`,
              sub2: `${data?.oauthApps.high ?? 0} high risk`,
              icon: <Shield className="h-5 w-5" />,
              href: "/shadow-it/saas",
              accent: "from-red-500/20 to-red-500/5",
              border: "border-red-500/20",
              iconBg: "bg-red-500/15 text-red-400",
              badge: (data?.oauthApps.critical ?? 0) > 0 ? `${data?.oauthApps.critical} critical` : undefined,
              badgeColor: "bg-red-500/15 text-red-400 border-red-500/20",
            },
            {
              label: "Unsanctioned SaaS",
              value: data?.shadowSaas.unsanctioned ?? 0,
              sub1: `of ${data?.shadowSaas.total ?? 0} total apps`,
              sub2: "require review",
              icon: <Package className="h-5 w-5" />,
              href: "/shadow-it/saas",
              accent: "from-yellow-500/20 to-yellow-500/5",
              border: "border-yellow-500/20",
              iconBg: "bg-yellow-500/15 text-yellow-400",
              badge: undefined,
              badgeColor: "",
            },
            {
              label: "Network Devices",
              value: data?.networkDevices.total ?? 0,
              sub1: `${data?.networkDevices.new ?? 0} newly discovered`,
              sub2: `${Object.keys(data?.networkDevices.byType ?? {}).length} device types`,
              icon: <Network className="h-5 w-5" />,
              href: "/shadow-it/network",
              accent: "from-blue-500/20 to-blue-500/5",
              border: "border-blue-500/20",
              iconBg: "bg-blue-500/15 text-blue-400",
              badge: (data?.networkDevices.new ?? 0) > 0 ? `${data?.networkDevices.new} new` : undefined,
              badgeColor: "bg-blue-500/15 text-blue-400 border-blue-500/20",
            },
          ].map((c) => (
            <Link key={c.label} href={c.href}>
              <div className={cn(
                "group relative overflow-hidden rounded-xl border bg-gradient-to-br cursor-pointer transition-all duration-200",
                "hover:shadow-lg hover:scale-[1.01]",
                c.accent, c.border,
                "bg-card"
              )}>
                <div className="p-5">
                  <div className="flex items-start justify-between mb-3">
                    <div className={cn("p-2 rounded-lg", c.iconBg)}>{c.icon}</div>
                    {c.badge && (
                      <span className={cn("text-[10px] font-semibold px-2 py-0.5 rounded-full border", c.badgeColor)}>
                        {c.badge}
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">{c.label}</p>
                  <p className="text-3xl font-bold tabular-nums mb-2">
                    {isLoading ? <span className="text-muted-foreground/30">—</span> : c.value}
                  </p>
                  <div className="flex flex-col gap-0.5">
                    <p className="text-xs text-muted-foreground">{c.sub1}</p>
                    <p className="text-xs text-muted-foreground/60">{c.sub2}</p>
                  </div>
                  <div className="absolute bottom-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
                    <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>

        {/* ── Middle Row: IdP + OAuth Pie + Network ──────────────────────── */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">

          {/* IdP Connections */}
          <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-2">
                <Building2 className="h-4 w-4 text-purple-400" />
                <h3 className="text-sm font-semibold">IdP Connections</h3>
                {data?.idpConnections.length ? (
                  <span className="text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 px-1.5 py-0.5 rounded font-medium">
                    {data.idpConnections.length}
                  </span>
                ) : null}
              </div>
              <Link href="/shadow-it/saas">
                <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground">
                  Manage <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            </div>
            <div className="flex-1 p-4 space-y-2">
              {isLoading && (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
                </div>
              )}
              {!isLoading && data?.idpConnections.length === 0 && (
                <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
                  <div className="p-3 rounded-full bg-muted">
                    <Building2 className="h-6 w-6 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">No IdP connections</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Connect Google Workspace, Entra, or Okta</p>
                  </div>
                  <Link href="/shadow-it/saas">
                    <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                      <Plus className="h-3 w-3" /> Configure IdP
                    </Button>
                  </Link>
                </div>
              )}
              {data?.idpConnections.map((conn) => {
                const meta = PROVIDER_META[conn.provider];
                const isOk = conn.lastSyncStatus === "success";
                const isErr = conn.lastSyncStatus === "failed";
                return (
                  <div key={conn.id} className="flex items-center gap-3 p-3 rounded-lg bg-accent/30 border border-border/50 hover:bg-accent/50 transition-colors">
                    <div className={cn("h-9 w-9 rounded-lg flex items-center justify-center text-white text-sm font-bold shrink-0", meta?.bg ?? "bg-muted")}>
                      {meta?.icon ?? conn.provider[0].toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{conn.displayName}</p>
                      <p className="text-xs text-muted-foreground">
                        {conn.syncedApps} apps · {conn.syncedUsers} users · {formatSync(conn.lastSyncAt)}
                      </p>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {isOk  && <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />}
                      {isErr && <XCircle className="h-3.5 w-3.5 text-red-400" />}
                      {!isOk && !isErr && <Clock className="h-3.5 w-3.5 text-muted-foreground" />}
                      <Button
                        size="sm" variant="ghost"
                        className="h-7 w-7 p-0"
                        disabled={syncing === conn.id}
                        onClick={() => syncConnection(conn.id)}
                        title="Sync now"
                      >
                        <RefreshCw className={cn("h-3 w-3", syncing === conn.id && "animate-spin")} />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* OAuth Risk Distribution */}
          <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-red-400" />
                <h3 className="text-sm font-semibold">OAuth Scope Risk</h3>
              </div>
              <Link href="/shadow-it/saas">
                <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground">
                  Review <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            </div>
            <div className="flex-1 p-4 flex flex-col items-center justify-center">
              {riskPieData.length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-8 text-center">
                  <div className="p-3 rounded-full bg-muted">
                    <Shield className="h-6 w-6 text-muted-foreground" />
                  </div>
                  <p className="text-sm text-muted-foreground">No OAuth apps discovered</p>
                  <p className="text-xs text-muted-foreground/60">Connect an IdP to start discovery</p>
                </div>
              ) : (
                <>
                  <ResponsiveContainer width="100%" height={160}>
                    <PieChart>
                      <Pie
                        data={riskPieData}
                        cx="50%" cy="50%"
                        innerRadius={45} outerRadius={70}
                        dataKey="value"
                        strokeWidth={2}
                        stroke="hsl(var(--card))"
                      >
                        {riskPieData.map((entry, i) => (
                          <Cell key={i} fill={entry.fill} />
                        ))}
                      </Pie>
                      <Tooltip
                        formatter={(v: number) => [`${v} apps`, ""]}
                        contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 w-full mt-1">
                    {riskPieData.map(d => (
                      <div key={d.name} className="flex items-center gap-2 text-xs">
                        <div className="h-2 w-2 rounded-full shrink-0" style={{ background: d.fill }} />
                        <span className="text-muted-foreground">{d.name}</span>
                        <span className="font-semibold ml-auto tabular-nums">{d.value}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Network Devices */}
          <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div className="flex items-center gap-2">
                <Radio className="h-4 w-4 text-blue-400" />
                <h3 className="text-sm font-semibold">Network Devices</h3>
                {data?.networkDevices.new ? (
                  <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded font-medium">
                    {data.networkDevices.new} new
                  </span>
                ) : null}
              </div>
              <Link href="/shadow-it/network">
                <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground">
                  Scan <ChevronRight className="h-3 w-3" />
                </Button>
              </Link>
            </div>
            <div className="flex-1 p-4">
              {Object.keys(data?.networkDevices.byType ?? {}).length === 0 ? (
                <div className="flex flex-col items-center gap-3 py-8 text-center">
                  <div className="p-3 rounded-full bg-muted">
                    <Wifi className="h-6 w-6 text-muted-foreground" />
                  </div>
                  <p className="text-sm text-muted-foreground">No network scan performed</p>
                  <Link href="/shadow-it/network">
                    <Button size="sm" variant="outline" className="h-7 text-xs gap-1">
                      <Activity className="h-3 w-3" /> Run Scan
                    </Button>
                  </Link>
                </div>
              ) : (
                <div className="space-y-2">
                  {Object.entries(data!.networkDevices.byType)
                    .sort(([, a], [, b]) => (b as number) - (a as number))
                    .map(([type, cnt]) => {
                      const total = data!.networkDevices.total;
                      const pct = total > 0 ? Math.round(((cnt as number) / total) * 100) : 0;
                      return (
                        <div key={type} className="space-y-1">
                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-1.5 text-muted-foreground">
                              {DEVICE_ICONS[type] ?? <Globe className="w-3.5 h-3.5" />}
                              {DEVICE_LABELS[type] ?? type}
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="font-semibold tabular-nums">{cnt as number}</span>
                              <span className="text-muted-foreground/50 tabular-nums w-7 text-right">{pct}%</span>
                            </div>
                          </div>
                          <div className="h-1.5 rounded-full bg-accent overflow-hidden">
                            <div
                              className="h-full rounded-full bg-blue-500/60 transition-all"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Alert Rules Banner ─────────────────────────────────────────────── */}
        <div className={cn(
          "rounded-xl border p-4 flex items-center justify-between gap-4",
          (!alertRules || alertRules.length === 0)
            ? "bg-amber-500/8 border-amber-500/25"
            : "bg-green-500/8 border-green-500/25"
        )}>
          <div className="flex items-center gap-3 min-w-0">
            {(!alertRules || alertRules.length === 0) ? (
              <>
                <div className="p-2 rounded-lg bg-amber-500/15 shrink-0">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-amber-400">No Shadow IT alert rules configured</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Discoveries are being logged, but you won't receive notifications. Create a rule to get alerted immediately.
                  </p>
                </div>
              </>
            ) : (
              <>
                <div className="p-2 rounded-lg bg-green-500/15 shrink-0">
                  <Bell className="h-4 w-4 text-green-400" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-green-400">
                    {alertRules.filter(r => r.isActive).length} active alert rule{alertRules.filter(r => r.isActive).length !== 1 ? "s" : ""}
                  </p>
                  <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                    {alertRules.map(r => (
                      <span key={r.id} className={cn(
                        "text-[10px] font-medium px-2 py-0.5 rounded border",
                        r.isActive
                          ? "bg-green-500/10 text-green-400 border-green-500/20"
                          : "bg-muted text-muted-foreground border-border"
                      )}>
                        {r.name}
                      </span>
                    ))}
                  </div>
                </div>
              </>
            )}
          </div>
          <Link href="/shadow-it/alerts">
            <Button
              size="sm"
              className={cn(
                "h-8 gap-1.5 shrink-0",
                (!alertRules || alertRules.length === 0)
                  ? "bg-amber-500 hover:bg-amber-600 text-black"
                  : "variant-outline border-green-500/30 text-green-400 hover:bg-green-500/10 bg-transparent border"
              )}
            >
              {(!alertRules || alertRules.length === 0) ? (
                <><Plus className="h-3.5 w-3.5" /> Create Rule</>
              ) : (
                <><ExternalLink className="h-3.5 w-3.5" /> Manage Rules</>
              )}
            </Button>
          </Link>
        </div>

        {/* ── Top Risky OAuth Apps ───────────────────────────────────────────── */}
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-border">
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-orange-400" />
              <h3 className="text-sm font-semibold">Top Risky OAuth Apps</h3>
              {data?.oauthApps.topRisky.length ? (
                <span className="text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded font-medium">
                  {data.oauthApps.topRisky.length}
                </span>
              ) : null}
            </div>
            <Link href="/shadow-it/saas">
              <Button variant="ghost" size="sm" className="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground">
                See all <ArrowRight className="h-3 w-3" />
              </Button>
            </Link>
          </div>

          {(!data?.oauthApps.topRisky || data.oauthApps.topRisky.length === 0) ? (
            <div className="flex flex-col items-center gap-3 py-12 text-center">
              <div className="p-3 rounded-full bg-muted">
                <Lock className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="text-sm text-muted-foreground">No OAuth apps discovered yet</p>
              <p className="text-xs text-muted-foreground/60">Connect an IdP to begin OAuth app risk analysis</p>
            </div>
          ) : (
            <div className="divide-y divide-border">
              {data.oauthApps.topRisky.map((app, idx) => (
                <div key={app.id} className="flex items-center gap-4 px-5 py-3.5 hover:bg-accent/30 transition-colors">
                  <span className="text-xs text-muted-foreground/40 tabular-nums w-5 text-right shrink-0">
                    {idx + 1}
                  </span>
                  <div className="h-8 w-8 rounded-lg bg-gradient-to-br from-accent to-muted flex items-center justify-center text-xs font-bold shrink-0 border border-border">
                    {app.displayName.slice(0, 2).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{app.displayName}</p>
                    <p className="text-xs text-muted-foreground">
                      {PROVIDER_META[app.provider]?.label ?? app.provider}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    {!app.isSanctioned && (
                      <span className="text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded font-medium">
                        Unsanctioned
                      </span>
                    )}
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Users className="h-3 w-3" />
                      <span className="tabular-nums">{app.userCount}</span>
                    </div>
                    <div className="flex items-center gap-1.5 min-w-[80px] justify-end">
                      <div className="h-1 flex-1 rounded-full bg-accent overflow-hidden max-w-[40px]">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${app.riskScore}%`,
                            background: RISK_COLORS[app.riskLevel] ?? "#888",
                          }}
                        />
                      </div>
                      <span
                        className={cn("text-[10px] px-2 py-0.5 rounded border font-semibold capitalize", RISK_BG[app.riskLevel])}
                      >
                        {app.riskLevel}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Quick Nav Footer ───────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pb-2">
          {[
            { href: "/shadow-it/assets",  icon: <Globe className="h-4 w-4" />,   label: "Shadow Assets",    desc: "Unapproved infrastructure" },
            { href: "/shadow-it/saas",    icon: <Package className="h-4 w-4" />, label: "SaaS & OAuth",     desc: "App inventory & IdP sync" },
            { href: "/shadow-it/network", icon: <Wifi className="h-4 w-4" />,    label: "Network Scanner",  desc: "Internal device discovery" },
            { href: "/shadow-it/alerts",  icon: <Bell className="h-4 w-4" />,    label: "Alert Rules",      desc: "Notification configuration" },
          ].map((n) => (
            <Link key={n.href} href={n.href}>
              <div className="group flex items-center gap-3 p-3.5 rounded-xl border border-border bg-card hover:bg-accent/40 hover:border-primary/30 transition-all cursor-pointer">
                <div className="p-1.5 rounded-lg bg-primary/10 text-primary group-hover:bg-primary/20 transition-colors shrink-0">
                  {n.icon}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{n.label}</p>
                  <p className="text-[11px] text-muted-foreground truncate">{n.desc}</p>
                </div>
                <ChevronRight className="h-3.5 w-3.5 text-muted-foreground/40 ml-auto shrink-0 group-hover:text-muted-foreground transition-colors" />
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
