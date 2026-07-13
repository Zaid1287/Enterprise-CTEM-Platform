import { useState } from "react";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  EyeOff, Globe, Network, Shield, RefreshCw, AlertTriangle,
  CheckCircle2, XCircle, Clock, ArrowRight, Users, Building2,
  ChevronRight, Bell,
} from "lucide-react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";

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

const PROVIDER_META: Record<string, { label: string; color: string; icon: string }> = {
  google_workspace: { label: "Google Workspace", color: "#4285F4", icon: "G" },
  microsoft_graph:  { label: "Microsoft Entra ID", color: "#00A4EF", icon: "M" },
  okta:             { label: "Okta", color: "#007DC1", icon: "O" },
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#6b7280",
};

const DEVICE_TYPE_LABELS: Record<string, string> = {
  workstation: "Workstations", server: "Servers", printer: "Printers",
  router: "Routers", switch: "Switches", nas: "NAS / Storage",
  iot: "IoT Devices", unknown: "Unknown",
};

interface AlertRule {
  id: number; name: string; triggerType: string;
  channel: string; isActive: boolean;
}

export default function ShadowItDashboardPage() {
  const [syncing, setSyncing] = useState<number | null>(null);

  const { data, isLoading, refetch } = useQuery<DashboardData>({
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

  const deviceBarData = data
    ? Object.entries(data.networkDevices.byType).map(([type, count]) => ({
        name: DEVICE_TYPE_LABELS[type] ?? type, count,
      }))
    : [];

  return (
    <AppLayout>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <EyeOff className="h-6 w-6 text-purple-500" />
              Shadow IT Dashboard
            </h1>
            <p className="text-muted-foreground mt-1 text-sm">
              Unsanctioned apps, IdP OAuth risk, and internal network exposure
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            {
              label: "Shadow Assets",
              value: data?.shadowAssets.total ?? 0,
              sub: `${data?.shadowAssets.pending ?? 0} pending review`,
              icon: <Globe className="h-5 w-5 text-orange-500" />,
              href: "/shadow-it/assets",
              color: "border-orange-200",
            },
            {
              label: "OAuth Apps",
              value: data?.oauthApps.total ?? 0,
              sub: `${data?.oauthApps.critical ?? 0} critical risk`,
              icon: <Shield className="h-5 w-5 text-red-500" />,
              href: "/shadow-it/saas",
              color: "border-red-200",
            },
            {
              label: "Unsanctioned SaaS",
              value: data?.shadowSaas.unsanctioned ?? 0,
              sub: `of ${data?.shadowSaas.total ?? 0} total`,
              icon: <AlertTriangle className="h-5 w-5 text-yellow-500" />,
              href: "/shadow-it/saas",
              color: "border-yellow-200",
            },
            {
              label: "Network Devices",
              value: data?.networkDevices.total ?? 0,
              sub: `${data?.networkDevices.new ?? 0} new`,
              icon: <Network className="h-5 w-5 text-blue-500" />,
              href: "/shadow-it/network",
              color: "border-blue-200",
            },
          ].map((c) => (
            <Link key={c.label} href={c.href}>
              <Card className={`cursor-pointer hover:shadow-md transition-shadow border ${c.color}`}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="text-sm text-muted-foreground">{c.label}</p>
                      <p className="text-3xl font-bold mt-1">
                        {isLoading ? "—" : c.value}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">{c.sub}</p>
                    </div>
                    {c.icon}
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* IdP Connections */}
          <Card className="md:col-span-1">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-base">IdP Connections</CardTitle>
              <Link href="/shadow-it/saas">
                <Button variant="ghost" size="sm">
                  Manage <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent className="space-y-3">
              {isLoading && <p className="text-sm text-muted-foreground">Loading…</p>}
              {!isLoading && data?.idpConnections.length === 0 && (
                <div className="text-center py-6">
                  <Building2 className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                  <p className="text-sm text-muted-foreground">No IdP connections configured.</p>
                  <Link href="/shadow-it/saas">
                    <Button size="sm" variant="outline" className="mt-3">Configure IdP</Button>
                  </Link>
                </div>
              )}
              {data?.idpConnections.map((conn) => {
                const meta = PROVIDER_META[conn.provider];
                const isSuccess = conn.lastSyncStatus === "success";
                const isFailed = conn.lastSyncStatus === "failed";
                return (
                  <div key={conn.id} className="flex items-center justify-between p-3 rounded-lg border bg-card">
                    <div className="flex items-center gap-3">
                      <div
                        className="h-8 w-8 rounded-full flex items-center justify-center text-white text-sm font-bold"
                        style={{ background: meta?.color ?? "#888" }}
                      >
                        {meta?.icon ?? conn.provider[0].toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{conn.displayName}</p>
                        <p className="text-xs text-muted-foreground">
                          {conn.syncedApps} apps · {conn.syncedUsers} users
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {isSuccess && <CheckCircle2 className="h-4 w-4 text-green-500" />}
                      {isFailed && <XCircle className="h-4 w-4 text-red-500" />}
                      {conn.lastSyncStatus === "never" && <Clock className="h-4 w-4 text-muted-foreground" />}
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={syncing === conn.id}
                        onClick={() => syncConnection(conn.id)}
                      >
                        <RefreshCw className={`h-3 w-3 ${syncing === conn.id ? "animate-spin" : ""}`} />
                      </Button>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          {/* OAuth Risk Distribution */}
          <Card className="md:col-span-1">
            <CardHeader className="pb-2">
              <CardTitle className="text-base">OAuth Scope Risk</CardTitle>
              <CardDescription className="text-xs">Distribution across all discovered apps</CardDescription>
            </CardHeader>
            <CardContent>
              {riskPieData.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-sm text-muted-foreground">
                  No OAuth apps discovered yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={riskPieData} cx="50%" cy="50%" outerRadius={60} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false}>
                      {riskPieData.map((entry, i) => (
                        <Cell key={i} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip formatter={(v: number) => [`${v} apps`, ""]} />
                  </PieChart>
                </ResponsiveContainer>
              )}
              {riskPieData.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2 justify-center">
                  {riskPieData.map(d => (
                    <div key={d.name} className="flex items-center gap-1 text-xs">
                      <div className="h-2 w-2 rounded-full" style={{ background: d.fill }} />
                      {d.name}: {d.value}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Network Device Types */}
          <Card className="md:col-span-1">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-base">Network Devices</CardTitle>
              <Link href="/shadow-it/network">
                <Button variant="ghost" size="sm">
                  View all <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              </Link>
            </CardHeader>
            <CardContent>
              {deviceBarData.length === 0 ? (
                <div className="h-40 flex items-center justify-center text-sm text-muted-foreground">
                  No network scan performed yet
                </div>
              ) : (
                <ResponsiveContainer width="100%" height={160}>
                  <BarChart data={deviceBarData} layout="vertical" margin={{ left: 8, right: 8 }}>
                    <XAxis type="number" tick={{ fontSize: 10 }} />
                    <YAxis type="category" dataKey="name" width={80} tick={{ fontSize: 10 }} />
                    <CartesianGrid strokeDasharray="3 3" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Alert Rules Summary */}
        <Card className="border-purple-200">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <div>
              <CardTitle className="text-base flex items-center gap-2">
                <Bell className="h-4 w-4 text-purple-500" />
                Shadow IT Alert Rules
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                Notifications for new shadow assets, OAuth apps, and network devices
              </CardDescription>
            </div>
            <Link href="/shadow-it/alerts">
              <Button variant="outline" size="sm">
                Configure <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            {!alertRules || alertRules.length === 0 ? (
              <div className="flex items-center gap-3 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200">
                <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />
                <div className="text-sm">
                  <span className="font-medium">No alert rules configured.</span>
                  {" "}Shadow IT discoveries are being logged but you won't receive any notifications.{" "}
                  <Link href="/shadow-it/alerts">
                    <span className="text-primary underline cursor-pointer">Create a rule →</span>
                  </Link>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2">
                  <div className="h-8 w-8 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
                    <Bell className="h-4 w-4 text-green-600" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">
                      {alertRules.filter((r) => r.isActive).length} active rule{alertRules.filter((r) => r.isActive).length !== 1 ? "s" : ""}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {alertRules.map((r) => r.channel).filter((v, i, a) => a.indexOf(v) === i).join(", ")}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2 ml-2">
                  {alertRules.map((r) => (
                    <Badge
                      key={r.id}
                      variant={r.isActive ? "default" : "outline"}
                      className="text-xs"
                    >
                      {r.name}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Top Risky OAuth Apps */}
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-base">Top Risky OAuth Apps</CardTitle>
            <Link href="/shadow-it/saas">
              <Button variant="ghost" size="sm">
                See all <ArrowRight className="h-4 w-4 ml-1" />
              </Button>
            </Link>
          </CardHeader>
          <CardContent>
            {(!data?.oauthApps.topRisky || data.oauthApps.topRisky.length === 0) ? (
              <p className="text-sm text-muted-foreground py-4 text-center">
                Connect an IdP to start discovering OAuth apps
              </p>
            ) : (
              <div className="space-y-2">
                {data.oauthApps.topRisky.map((app) => (
                  <div key={app.id} className="flex items-center justify-between p-3 rounded-lg border">
                    <div className="flex items-center gap-3">
                      <div className="h-8 w-8 rounded bg-muted flex items-center justify-center text-xs font-bold">
                        {app.displayName.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <p className="text-sm font-medium">{app.displayName}</p>
                        <p className="text-xs text-muted-foreground capitalize">
                          {PROVIDER_META[app.provider]?.label ?? app.provider} · {app.userCount} user{app.userCount !== 1 ? "s" : ""}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {!app.isSanctioned && (
                        <Badge variant="outline" className="text-xs border-orange-300 text-orange-600">Unsanctioned</Badge>
                      )}
                      <div className="flex items-center gap-1">
                        <Users className="h-3 w-3 text-muted-foreground" />
                        <span className="text-xs">{app.userCount}</span>
                      </div>
                      <Badge
                        className="text-xs capitalize text-white"
                        style={{ background: RISK_COLORS[app.riskLevel] ?? "#888" }}
                      >
                        {app.riskLevel}
                      </Badge>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}
