import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Shield, Crosshair, Users, Layers, Bug, Radio, AlertTriangle,
  RefreshCw, Loader2, CheckCircle2, XCircle, Clock, Activity,
  Globe, Zap, Target, Cloud, GitBranch, Filter,
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
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6", unknown: "#6b7280",
};

function sevBadge(s: string | null | undefined) {
  const sev = (s ?? "unknown").toLowerCase();
  return cn(
    "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize shrink-0",
    sev === "critical" ? "text-red-400 bg-red-500/10 border-red-500/20"
    : sev === "high" ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
    : sev === "medium" ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
    : sev === "low" ? "text-green-400 bg-green-500/10 border-green-500/20"
    : "text-muted-foreground bg-muted border-border",
  );
}

function exploitBadge(status: string) {
  return cn(
    "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize shrink-0",
    status === "active" ? "text-red-400 bg-red-500/10 border-red-500/20"
    : status === "poc" ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
    : "text-muted-foreground bg-muted border-border",
  );
}

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
  const isSuperAdmin = user?.role === "super_admin";
  const [correlating, setCorrelating] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);

  const dashUrl = tenantFilter && isSuperAdmin
    ? `${BASE}/api/threat-intel/dashboard?tenantId=${tenantFilter}`
    : `${BASE}/api/threat-intel/dashboard`;

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["ti-dashboard", tenantFilter],
    queryFn: () => apiFetch<any>(dashUrl),
    staleTime: 60_000,
    retry: 1,
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

  const { data: ttpsData } = useQuery({
    queryKey: ["ti-ttps-top"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/ttps?limit=12`),
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
  const topTtps: any[] = (ttpsData?.ttps ?? []).slice(0, 12);
  const recentC2List: any[] = (data?.recentC2 ?? []);

  // New extended sections
  const topActorsWithHits: { name: string; asset_count: number; correlation_count: number }[] = data?.topActorsWithHits ?? [];
  const activeIocMatches: { value: string; type: string; severity: string; hit_count: number; match_count: number }[] = data?.activeIocMatches ?? [];
  const mostTargetedCves: { cve_id: string; hit_count: number; match_count: number; cvss: number | null; severity: string | null; isKev: boolean; epss: number | null }[] = data?.mostTargetedCves ?? [];
  const recentCorrelations: any[] = data?.recentCorrelations ?? [];
  const tenants: { id: number; name: string }[] = data?.tenants ?? [];

  // Derive C2 geography from recentC2
  const c2ByCountry = Object.entries(
    recentC2List.reduce<Record<string, number>>((acc, c) => {
      const key = c.country ?? "Unknown";
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {})
  ).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([country, count]) => ({ country, count }));

  const pieData = ["critical", "high", "medium", "low"]
    .map(s => ({ name: s, value: Number(severityDist.find(r => r.severity === s)?.count ?? 0) }))
    .filter(d => d.value > 0);

  const selectedTenantName = tenants.find(t => t.id === tenantFilter)?.name;

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
            <p className="text-xs text-muted-foreground">
              Global threat database &amp; asset correlation
              {selectedTenantName && (
                <span className="ml-2 px-1.5 py-0.5 rounded bg-primary/10 text-primary text-[10px] font-medium">
                  {selectedTenantName}
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Tenant filter — super_admin only */}
          {isSuperAdmin && tenants.length > 0 && (
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-muted-foreground" />
              <select
                className="text-xs bg-card border border-border rounded-md px-2 py-1.5 text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                value={tenantFilter ?? ""}
                onChange={e => setTenantFilter(e.target.value ? Number(e.target.value) : null)}
              >
                <option value="">All tenants</option>
                {tenants.map(t => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
            </div>
          )}
          {isAdmin && (
            <>
              <Button size="sm" variant="outline" onClick={triggerCorrelate} disabled={correlating}>
                {correlating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Activity className="w-3.5 h-3.5 mr-1.5" />}
                Run Correlation
              </Button>
              <Button size="sm" variant="outline" onClick={triggerRefresh} disabled={refreshing}>
                {refreshing ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
                Refresh Feeds
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Error state */}
      {isError && (
        <div className="flex items-center gap-3 p-4 rounded-xl border border-red-500/20 bg-red-500/5 text-red-400">
          <XCircle className="w-5 h-5 shrink-0" />
          <div>
            <p className="text-sm font-semibold">Failed to load dashboard data</p>
            <p className="text-xs text-red-400/70 mt-0.5">
              {(error as any)?.message ?? "An unexpected error occurred. Try refreshing."}
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="ml-auto text-xs px-3 py-1.5 rounded-lg border border-red-500/30 hover:bg-red-500/10 transition-colors shrink-0"
          >
            Retry
          </button>
        </div>
      )}

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

      {/* ── NEW: Top Actors with Asset Hit Counts + Active IOC Matches ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top threat actors with asset hit counts */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold">Top Threat Actors — Asset Hit Counts</h2>
          </div>
          <p className="text-[11px] text-muted-foreground -mt-1">Actors matched across your correlated assets</p>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
          ) : topActorsWithHits.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No actor correlations yet — run correlation to populate</p>
          ) : (
            <div className="space-y-1.5">
              {topActorsWithHits.map((a, idx) => (
                <div key={a.name} className="flex items-center gap-3 p-2 rounded-lg hover:bg-muted/30 transition-colors">
                  <span className="text-[11px] text-muted-foreground/50 w-4 shrink-0 text-right">{idx + 1}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-medium truncate">{a.name}</p>
                    <p className="text-[11px] text-muted-foreground">{a.correlation_count} correlation{a.correlation_count !== 1 ? "s" : ""}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={cn("text-sm font-bold tabular-nums", a.asset_count >= 5 ? "text-red-400" : a.asset_count >= 2 ? "text-orange-400" : "text-yellow-400")}>
                      {a.asset_count}
                    </p>
                    <p className="text-[10px] text-muted-foreground">asset{a.asset_count !== 1 ? "s" : ""}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Active IOC Matches */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold">Active IOC Matches</h2>
          </div>
          <p className="text-[11px] text-muted-foreground -mt-1">IOCs correlated against your assets</p>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
          ) : activeIocMatches.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No IOC matches yet — run correlation to populate</p>
          ) : (
            <div className="space-y-1.5">
              {activeIocMatches.slice(0, 8).map((ioc, idx) => (
                <div key={`${ioc.value}-${idx}`} className="flex items-center gap-2 p-2 rounded-lg hover:bg-muted/30 transition-colors">
                  <span className={sevBadge(ioc.severity)}>{ioc.severity ?? "?"}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border shrink-0 uppercase font-mono">
                    {ioc.type ?? "ioc"}
                  </span>
                  <span className="text-xs font-mono truncate flex-1 min-w-0">{ioc.value}</span>
                  <div className="text-right shrink-0">
                    <span className={cn("text-xs font-bold tabular-nums", ioc.hit_count >= 3 ? "text-red-400" : ioc.hit_count >= 2 ? "text-orange-400" : "text-yellow-400")}>
                      {ioc.hit_count}
                    </span>
                    <span className="text-[10px] text-muted-foreground ml-0.5">hits</span>
                  </div>
                </div>
              ))}
              {activeIocMatches.length > 8 && (
                <p className="text-[11px] text-muted-foreground text-center pt-1">
                  +{activeIocMatches.length - 8} more IOC matches
                </p>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ── NEW: Most Targeted CVEs + Recent Correlations Feed ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Most Targeted CVEs */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold">Most Targeted CVEs</h2>
          </div>
          <p className="text-[11px] text-muted-foreground -mt-1">CVEs with most asset hits in correlations</p>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-9 w-full" />)}</div>
          ) : mostTargetedCves.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No CVE correlations yet — run correlation to populate</p>
          ) : (
            <div className="space-y-1.5">
              {mostTargetedCves.map((cve, idx) => (
                <div key={cve.cve_id} className="flex items-center gap-2 p-2 rounded-lg hover:bg-muted/30 transition-colors">
                  <span className="text-[11px] text-muted-foreground/50 w-4 shrink-0 text-right">{idx + 1}</span>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs font-mono font-semibold text-blue-400 hover:underline truncate"
                      >
                        {cve.cve_id}
                      </a>
                      {cve.isKev && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold shrink-0">KEV</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-0.5">
                      {cve.severity && <span className={sevBadge(cve.severity)}>{cve.severity}</span>}
                      {cve.cvss != null && <span className="text-[10px] text-muted-foreground">CVSS {Number(cve.cvss).toFixed(1)}</span>}
                      {cve.epss != null && <span className="text-[10px] text-muted-foreground">EPSS {(Number(cve.epss) * 100).toFixed(1)}%</span>}
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <span className={cn("text-sm font-bold tabular-nums", cve.hit_count >= 5 ? "text-red-400" : cve.hit_count >= 2 ? "text-orange-400" : "text-yellow-400")}>
                      {cve.hit_count}
                    </span>
                    <p className="text-[10px] text-muted-foreground">asset{cve.hit_count !== 1 ? "s" : ""}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Correlations Feed */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-green-400" />
            <h2 className="text-sm font-semibold">Recent Correlations</h2>
          </div>
          <p className="text-[11px] text-muted-foreground -mt-1">Latest threat intelligence matches against assets</p>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
          ) : recentCorrelations.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No correlations yet — run correlation to populate</p>
          ) : (
            <div className="space-y-2 overflow-y-auto max-h-72">
              {recentCorrelations.map((c: any) => {
                const actors: any[] = Array.isArray(c.matchedActors) ? c.matchedActors : [];
                const iocs: any[] = Array.isArray(c.matchedIocs) ? c.matchedIocs : [];
                // matchedCves stores MatchedCve objects {cveId, cvss, ...} — extract the cveId string
                const cves: string[] = Array.isArray(c.matchedCves)
                  ? c.matchedCves.map((item: any) => typeof item === "string" ? item : (item?.cveId ?? "")).filter(Boolean)
                  : [];
                return (
                  <div key={c.id} className="border border-border/50 rounded-lg p-2.5 hover:bg-muted/20 transition-colors">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium truncate">{c.assetName ?? `Asset #${c.assetId}`}</p>
                        {c.findingTitle && (
                          <p className="text-[11px] text-muted-foreground truncate">{c.findingTitle}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <span className={exploitBadge(c.exploitationStatus)}>{c.exploitationStatus}</span>
                        {c.findingSeverity && <span className={sevBadge(c.findingSeverity)}>{c.findingSeverity}</span>}
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1 mt-1.5">
                      {actors.slice(0, 2).map((a: any, i: number) => (
                        <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                          {typeof a === "string" ? a : (a?.name ?? "actor")}
                        </span>
                      ))}
                      {iocs.length > 0 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 border border-orange-500/20">
                          {iocs.length} IOC{iocs.length !== 1 ? "s" : ""}
                        </span>
                      )}
                      {cves.slice(0, 2).map((cveId: string, i: number) => (
                        <span key={i} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-mono">
                          {cveId}
                        </span>
                      ))}
                      {cves.length > 2 && (
                        <span className="text-[10px] text-muted-foreground">+{cves.length - 2} CVEs</span>
                      )}
                    </div>
                    <p className="text-[10px] text-muted-foreground/60 mt-1">
                      {c.correlatedAt ? new Date(c.correlatedAt).toLocaleString() : ""}
                      {c.threatScore != null && (
                        <span className="ml-2 font-medium text-muted-foreground">score {Number(c.threatScore).toFixed(0)}</span>
                      )}
                    </p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Row: Top threat actors (by risk score) + IOC severity pie */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top threat actors by risk score */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Users className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold">Top Threat Actors by Risk Score</h2>
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

      {/* Row: Top TTPs + C2 Geography */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Top ATT&CK TTPs */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-yellow-400" />
            <h2 className="text-sm font-semibold">Top ATT&amp;CK TTPs</h2>
          </div>
          {isLoading ? (
            <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-7 w-full" />)}</div>
          ) : topTtps.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No TTP data — run a feed refresh</p>
          ) : (
            <div className="space-y-1">
              {topTtps.map((t: any) => (
                <div key={t.id} className="flex items-center justify-between text-xs py-1.5 border-b border-border/30">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-blue-400 text-[10px] shrink-0 w-20">{t.mitreId}</span>
                    <span className="truncate font-medium">{t.name}</span>
                  </div>
                  <span className="text-muted-foreground/60 text-[10px] shrink-0 ml-2 capitalize">{t.tactic}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* C2 Geography */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold">C2 Server Geography</h2>
          </div>
          {isLoading ? (
            <Skeleton className="h-36 w-full" />
          ) : c2ByCountry.length === 0 ? (
            <p className="text-xs text-muted-foreground py-4 text-center">No C2 geography data yet</p>
          ) : (
            <div className="h-36">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={c2ByCountry} layout="vertical" margin={{ top: 0, right: 16, left: 0, bottom: 0 }}>
                  <XAxis type="number" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="country" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} width={70} />
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 11 }}
                    cursor={{ fill: "hsl(var(--muted)/0.4)" }}
                  />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 3, 3, 0]} name="C2 servers" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
          {c2ByCountry.length === 0 && recentC2List.length > 0 && (
            <p className="text-[10px] text-muted-foreground">{recentC2List.length} C2 servers (no country data)</p>
          )}
        </div>
      </div>

      {/* Cloud / Infrastructure Exposure */}
      <div className="bg-card border border-border rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <Cloud className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold">Infrastructure Exposure Overview</h2>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total IOCs",         value: t.iocs         ?? 0, color: "text-orange-400", sub: "indicators of compromise" },
            { label: "C2 Infrastructure",  value: t.c2           ?? 0, color: "text-red-400",    sub: `${t.c2Active ?? 0} currently active` },
            { label: "KEV Vulnerabilities",value: t.kevCves      ?? 0, color: "text-red-400",    sub: "CISA known exploited" },
            { label: "Correlated Findings",value: t.correlations ?? 0, color: "text-green-400",  sub: `${t.criticalCorrelations ?? 0} active exploitation` },
          ].map(s => (
            <div key={s.label} className="bg-muted/30 border border-border rounded-lg p-3">
              <p className={cn("text-xl font-bold tabular-nums", s.color)}>{Number(s.value).toLocaleString()}</p>
              <p className="text-xs font-medium mt-0.5">{s.label}</p>
              <p className="text-[10px] text-muted-foreground">{s.sub}</p>
            </div>
          ))}
        </div>
        {/* IOC severity breakdown bar */}
        {pieData.length > 0 && (
          <div className="pt-1">
            <p className="text-[10px] text-muted-foreground mb-2">IOC severity breakdown</p>
            <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
              {pieData.map(d => (
                <div
                  key={d.name}
                  title={`${d.name}: ${d.value.toLocaleString()}`}
                  style={{
                    flex: d.value,
                    background: d.name === "critical" ? "#ef4444" : d.name === "high" ? "#f97316" : d.name === "medium" ? "#eab308" : "#22c55e",
                  }}
                />
              ))}
            </div>
            <div className="flex gap-4 mt-1.5">
              {pieData.map(d => (
                <div key={d.name} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                  <div className="w-2 h-2 rounded-full" style={{ background: d.name === "critical" ? "#ef4444" : d.name === "high" ? "#f97316" : d.name === "medium" ? "#eab308" : "#22c55e" }} />
                  <span className="capitalize">{d.name}</span>
                  <span className="text-muted-foreground/60">{d.value.toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Feed status (admin only) */}
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
