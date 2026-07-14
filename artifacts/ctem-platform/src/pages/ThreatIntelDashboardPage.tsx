import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield, Crosshair, Users, Layers, Bug, Radio, AlertTriangle,
  RefreshCw, Loader2, CheckCircle2, XCircle, Clock, Activity,
  Globe, Zap,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const FEED_META: Record<string, string> = {
  alienvault_otx: "AlienVault OTX",
  abuseipdb: "AbuseIPDB",
  greynoise: "GreyNoise",
  threatfox: "ThreatFox",
  malwarebazaar: "MalwareBazaar",
  urlhaus: "URLhaus",
  phishtank: "PhishTank",
  cisa_kev: "CISA KEV",
  mitre_attack: "MITRE ATT&CK",
  nvd_cve: "NVD CVE",
};

const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", unknown: "#6b7280",
};

function StatCard({ icon: Icon, label, value, sub, color = "text-primary" }: {
  icon: any; label: string; value: number | string; sub?: string; color?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-xl p-4 flex items-start gap-3">
      <div className={cn("p-2 rounded-lg bg-muted/50 shrink-0", color)}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="min-w-0">
        <p className="text-2xl font-bold tabular-nums">{typeof value === "number" ? value.toLocaleString() : value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
        {sub && <p className="text-[11px] text-muted-foreground/60 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

export default function ThreatIntelDashboardPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const [correlating, setCorrelating] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-dashboard"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dashboard`),
    staleTime: 60_000,
  });

  const { data: feedData, refetch: refetchFeeds } = useQuery({
    queryKey: ["ti-feeds"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/feeds/status`),
    staleTime: 60_000,
    enabled: isAdmin,
  });

  const { data: malwareData } = useQuery({
    queryKey: ["ti-malware-top"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/malware?limit=8`),
    staleTime: 120_000,
  });

  const triggerCorrelate = useCallback(async () => {
    setCorrelating(true);
    try {
      await apiFetch(`${BASE}/api/threat-intel/correlate`, { method: "POST" });
      setTimeout(() => { setCorrelating(false); refetch(); }, 4000);
    } catch { setCorrelating(false); }
  }, [refetch]);

  const triggerRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await apiFetch(`${BASE}/api/threat-intel/feeds/refresh`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({}) });
      setTimeout(() => { setRefreshing(false); refetchFeeds?.(); refetch(); }, 3000);
    } catch { setRefreshing(false); }
  }, [refetch, refetchFeeds]);

  const t = data?.totals ?? {};
  const topActors = data?.topActors ?? [];
  const feeds: any[] = feedData?.feeds ?? [];
  const severityDist: { severity: string; count: number }[] = data?.severityDistribution ?? [];
  const monthlyC2: { month: string; count: number }[] = data?.monthlyC2 ?? [];
  const topMalware: any[] = (malwareData?.malware ?? []).slice(0, 8);

  const pieData = ["critical", "high", "medium", "low"]
    .map(s => ({ name: s, value: Number(severityDist.find(r => r.severity === s)?.count ?? 0) }))
    .filter(d => d.value > 0);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-xl bg-primary/10 border border-primary/20">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-bold">Threat Intelligence</h1>
            <p className="text-xs text-muted-foreground">Global threat database & asset correlation</p>
          </div>
        </div>
        {isAdmin && (
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={triggerCorrelate} disabled={correlating}>
              {correlating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1.5" />}
              Correlate Assets
            </Button>
            <Button size="sm" variant="outline" onClick={triggerRefresh} disabled={refreshing}>
              {refreshing ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
              Refresh Feeds
            </Button>
          </div>
        )}
      </div>

      {/* Stat grid */}
      {isLoading ? (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard icon={Crosshair}     label="IOCs"               value={t.iocs        ?? 0} color="text-orange-400" />
          <StatCard icon={Users}         label="Threat Actors"      value={t.actors      ?? 0} color="text-purple-400" />
          <StatCard icon={Layers}        label="Campaigns"          value={t.campaigns   ?? 0} color="text-blue-400" />
          <StatCard icon={Bug}           label="Malware Families"   value={t.malware     ?? 0} color="text-yellow-400" />
          <StatCard icon={Radio}         label="C2 Servers"         value={t.c2          ?? 0} sub={`${t.c2Active ?? 0} active`} color="text-red-400" />
          <StatCard icon={AlertTriangle} label="KEV CVEs"           value={t.kevCves     ?? 0} color="text-red-400" />
          <StatCard icon={Activity}      label="Asset Correlations" value={t.correlations ?? 0} sub={`${t.criticalCorrelations ?? 0} active exploitation`} color="text-green-400" />
          <StatCard icon={Zap}           label="Active Threats"     value={t.criticalCorrelations ?? 0} sub="correlated to assets" color="text-red-500" />
        </div>
      )}

      {/* Row: Top threat actors + IOC severity pie */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top threat actors */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold">Top Threat Actors by Risk</h2>
          </div>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : topActors.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No threat actors loaded — run a feed refresh</p>
          ) : (
            <div className="space-y-1.5">
              {topActors.slice(0, 8).map((a: any) => (
                <a key={a.id} href={`/threat-intel/actors/${a.id}`}
                  className="flex items-center justify-between p-2.5 rounded-lg hover:bg-muted/40 transition-colors group">
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate group-hover:text-primary transition-colors">{a.name}</p>
                    <p className="text-[11px] text-muted-foreground">{a.country ?? "Unknown"} · {a.motivation ?? "Unknown motivation"}</p>
                  </div>
                  <div className="text-right shrink-0 ml-3">
                    <p className={cn("text-sm font-bold tabular-nums", Number(a.riskScore) >= 70 ? "text-red-400" : Number(a.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400")}>
                      {Math.round(Number(a.riskScore ?? 0))}
                    </p>
                    <p className="text-[10px] text-muted-foreground">risk score</p>
                  </div>
                </a>
              ))}
            </div>
          )}
        </div>

        {/* IOC severity donut */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold">IOC Severity Distribution</h2>
          </div>
          {isLoading ? (
            <div className="flex justify-center py-4"><Skeleton className="w-40 h-40 rounded-full" /></div>
          ) : pieData.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No IOC data — feed refresh required</p>
          ) : (
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" nameKey="name">
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? "#6b7280"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 11 }}
                    formatter={(v: any, name: string) => [Number(v).toLocaleString(), name]}
                  />
                  <Legend iconType="circle" iconSize={8} wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Row: Monthly C2 trend + Top malware families */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Monthly C2 trend */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold">C2 Servers — Monthly Trend</h2>
          </div>
          {isLoading ? (
            <Skeleton className="h-36 w-full" />
          ) : monthlyC2.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No C2 history yet</p>
          ) : (
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={monthlyC2} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
                  <XAxis dataKey="month" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 11 }}
                    cursor={{ fill: "hsl(var(--muted)/0.4)" }}
                  />
                  <Bar dataKey="count" fill="#ef4444" radius={[3, 3, 0, 0]} name="C2 servers" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Top malware families */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Bug className="w-4 h-4 text-yellow-400" />
            <h2 className="text-sm font-semibold">Top Malware Families</h2>
          </div>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-8 w-full" />)}</div>
          ) : topMalware.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No malware data — run a feed refresh</p>
          ) : (
            <div className="space-y-2">
              {topMalware.map((m: any) => (
                <div key={m.id} className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize shrink-0",
                      m.malwareType === "ransomware" ? "text-red-400 bg-red-500/10 border-red-500/20" :
                      m.malwareType === "trojan" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                      "text-muted-foreground bg-muted border-border",
                    )}>
                      {m.malwareType ?? "malware"}
                    </span>
                    <span className="font-medium truncate">{m.name}</span>
                  </div>
                  <span className={cn("font-bold tabular-nums shrink-0 ml-2",
                    Number(m.riskScore) >= 70 ? "text-red-400" : Number(m.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400",
                  )}>
                    {Math.round(Number(m.riskScore ?? 0))}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Feed status (admin only — feeds/status is now admin-gated) */}
      {isAdmin && (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold">Feed Status</h2>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
            {feeds.length === 0
              ? Array.from({ length: 10 }).map((_, i) => <Skeleton key={i} className="h-16 rounded-lg" />)
              : feeds.map((f: any) => {
                const ok = f.status === "completed";
                const running = f.status === "running";
                const never = f.status === "never";
                return (
                  <div key={f.source} className={cn(
                    "rounded-lg border p-2.5 space-y-1",
                    ok ? "border-green-500/20 bg-green-500/5" : running ? "border-blue-500/20 bg-blue-500/5" : never ? "border-border bg-muted/20" : "border-red-500/20 bg-red-500/5",
                  )}>
                    <div className="flex items-center gap-1.5">
                      {ok ? <CheckCircle2 className="w-3 h-3 text-green-400 shrink-0" />
                          : running ? <Loader2 className="w-3 h-3 text-blue-400 shrink-0 animate-spin" />
                          : never ? <Clock className="w-3 h-3 text-muted-foreground shrink-0" />
                          : <XCircle className="w-3 h-3 text-red-400 shrink-0" />}
                      <p className="text-[11px] font-semibold truncate">{FEED_META[f.source] ?? f.source}</p>
                    </div>
                    {f.recordsAdded > 0 && <p className="text-[10px] text-muted-foreground">+{Number(f.recordsAdded).toLocaleString()} records</p>}
                    {never && <p className="text-[10px] text-muted-foreground">Never run</p>}
                    {f.completedAt && <p className="text-[10px] text-muted-foreground/60">{new Date(f.completedAt).toLocaleDateString()}</p>}
                    {f.error && <p className="text-[10px] text-red-400/70 truncate">{f.error}</p>}
                  </div>
                );
              })
            }
          </div>
        </div>
      )}

      {/* Recent C2 */}
      {(data?.recentC2 ?? []).length > 0 && (
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold">Recent Active C2 Servers</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2 pr-4 font-medium text-muted-foreground">IP</th>
                  <th className="text-left py-2 pr-4 font-medium text-muted-foreground">Malware</th>
                  <th className="text-left py-2 pr-4 font-medium text-muted-foreground">Country</th>
                  <th className="text-left py-2 font-medium text-muted-foreground">Discovered</th>
                </tr>
              </thead>
              <tbody>
                {(data?.recentC2 as any[]).slice(0, 8).map((c: any) => (
                  <tr key={c.id} className="border-b border-border/30 hover:bg-muted/20">
                    <td className="py-2 pr-4 font-mono text-red-400">{c.ip}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{c.malwareFamily ?? "Unknown"}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{c.country ?? "—"}</td>
                    <td className="py-2 text-muted-foreground/60">{c.discoveredAt ? new Date(c.discoveredAt).toLocaleDateString() : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
