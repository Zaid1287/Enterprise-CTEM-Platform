import { useQuery } from "@tanstack/react-query";
import { useState, useMemo, useEffect, useRef } from "react";
import {
  Activity, Server, AlertTriangle, Zap, Clock, RefreshCw,
  ShieldX, Wifi, WifiOff, RotateCcw, TrendingDown, Timer,
  Radio, CircleDot, Network, Database, Globe, Shield,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";

/* ─── Types ─────────────────────────────────────────────────────────── */
interface TrendPoint {
  minute: string;
  requests: number;
  avgLatencyMs: number;
  wafCount: number;
  retryCount: number;
  count429: number;
  count403: number;
}
interface TelemetryStats {
  window: string;
  generatedAt: string;
  requests: {
    totalRequests: number; avgLatencyMs: number; p95LatencyMs: number;
    count429: number; count403: number; countWaf: number; countCaptcha: number;
    totalRetries: number; avgBytesDownloaded: number; reqPerSecond: number;
  };
  retryQueueSize: number;
  trend: TrendPoint[];
  proxies: { activeProxies: number; coolingProxies: number; inactiveProxies: number; avgHealthScore: number };
  circuits: { open: number; total: number; details: Array<{ host: string; state: string; failures: number; lastFailure: number }> };
  rateLimiters: Array<{ host: string; tokens: number; lastRefill: number }>;
  dnsResolvers: Array<{ ip: string; avgMs: number; failures: number; successes: number }>;
  hostStats?: Record<string, { lastStatus: number | null; reqPerSec: number }>;
}
interface Proxy {
  id: number; ip: string; port: number; label: string | null; type: string; country: string | null; asn: string | null;
  healthScore: number; successCount: number; failCount: number; count429: number; count403: number;
  avgLatencyMs: number | null; status: "active" | "cooldown" | "inactive";
  lastTestedAt: string | null; requestsToday: number;
}
interface WaterfallEvent {
  id: string; ts: number; method: string; url: string;
  statusCode?: number; latencyMs?: number; proxyId?: number;
  wafDetected?: boolean; captchaDetected?: boolean; retries?: number;
  target?: string; degradedMode?: boolean;
}

/* ─── API ────────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs() });
  if (!r.ok) throw new Error("Request failed");
  return r.json();
}

/* ─── StatCard ────────────────────────────────────────────────────────── */
function StatCard({ label, value, icon: Icon, color = "blue", sub, accent }: {
  label: string; value: string | number; icon: React.ElementType;
  color?: string; sub?: string; accent?: string;
}) {
  const colorMap: Record<string, { bg: string; icon: string; border: string }> = {
    green:  { bg: "bg-green-500/10",  icon: "text-green-500",  border: "border-l-green-500"  },
    amber:  { bg: "bg-amber-500/10",  icon: "text-amber-500",  border: "border-l-amber-500"  },
    red:    { bg: "bg-red-500/10",    icon: "text-red-500",    border: "border-l-red-500"    },
    blue:   { bg: "bg-blue-500/10",   icon: "text-blue-500",   border: "border-l-blue-500"   },
    indigo: { bg: "bg-indigo-500/10", icon: "text-indigo-500", border: "border-l-indigo-500" },
    purple: { bg: "bg-purple-500/10", icon: "text-purple-500", border: "border-l-purple-500" },
    slate:  { bg: "bg-slate-500/10",  icon: "text-slate-400",  border: "border-l-slate-400"  },
  };
  const c = colorMap[color] ?? colorMap.blue;
  return (
    <div className={cn("rounded-xl border bg-card p-4 flex items-start gap-3 border-l-4", c.border)}>
      <div className={cn("p-2 rounded-lg shrink-0", c.bg)}>
        <Icon className={cn("w-4 h-4", c.icon)} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-muted-foreground truncate">{label}</p>
        <p className={cn("text-2xl font-bold leading-tight mt-0.5 tabular-nums", accent ?? c.icon)}>{value}</p>
        {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

/* ─── StatusBadge ─────────────────────────────────────────────────────── */
function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; className: string }> = {
    active:   { label: "Healthy",      className: "bg-green-500/15 text-green-600 border-green-500/30" },
    cooldown: { label: "Cooling Down", className: "bg-amber-500/15 text-amber-600 border-amber-500/30" },
    inactive: { label: "Inactive",     className: "bg-red-500/15 text-red-600 border-red-500/30" },
    open:     { label: "Open",         className: "bg-red-500/15 text-red-600 border-red-500/30" },
    closed:   { label: "Closed",       className: "bg-green-500/15 text-green-600 border-green-500/30" },
    half_open:{ label: "Half-Open",    className: "bg-amber-500/15 text-amber-600 border-amber-500/30" },
  };
  const s = map[status] ?? { label: status, className: "bg-muted text-muted-foreground" };
  return <Badge variant="outline" className={cn("text-xs font-medium", s.className)}>{s.label}</Badge>;
}

/* ─── Waterfall Widget ──────────────────────────────────────────────── */
function WaterfallWidget() {
  const [events, setEvents] = useState<WaterfallEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const url = `${BASE()}/api/scan-telemetry/stream`;
    const es = new EventSource(url + `?token=${encodeURIComponent(token ?? "")}`);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    const parse = (e: MessageEvent, degradedMode?: boolean) => {
      try {
        const data = JSON.parse(e.data);
        const event: WaterfallEvent = {
          id: `${Date.now()}-${Math.random()}`,
          ts: data.ts ?? Date.now(), method: data.method ?? "GET",
          url: data.url ?? "", statusCode: data.statusCode, latencyMs: data.latencyMs,
          proxyId: data.proxyId, wafDetected: data.wafDetected, captchaDetected: data.captchaDetected,
          retries: data.retries, target: data.target, degradedMode: degradedMode ?? data.degradedMode,
        };
        setEvents(prev => [event, ...prev].slice(0, 100));
      } catch { /* ignore */ }
    };
    es.addEventListener("telemetry:request", (e: MessageEvent) => parse(e));
    es.addEventListener("telemetry:degraded_mode", (e: MessageEvent) => parse(e, true));
    return () => { es.close(); setConnected(false); };
  }, []);

  const statusColor = (code?: number) => {
    if (!code) return "text-muted-foreground";
    if (code >= 200 && code < 300) return "text-green-600";
    if (code === 429) return "text-amber-500";
    if (code >= 400) return "text-red-500";
    if (code >= 500) return "text-red-600";
    return "text-muted-foreground";
  };

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="px-5 py-4 border-b flex items-center justify-between bg-muted/20">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/15 border border-blue-500/25">
            <Radio className="w-4 h-4 text-blue-500" />
          </div>
          <div>
            <h2 className="text-sm font-semibold">Real-Time Request Waterfall</h2>
            <p className="text-xs text-muted-foreground">Live stream of HTTP requests from the orchestration engine</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {events.length > 0 && (
            <Button variant="ghost" size="sm" className="h-7 text-xs px-2" onClick={() => setEvents([])}>
              Clear
            </Button>
          )}
          <Badge
            variant="outline"
            className={cn("text-xs gap-1.5 px-2.5 py-1", connected
              ? "bg-green-500/15 text-green-600 border-green-500/30"
              : "bg-muted text-muted-foreground"
            )}
          >
            <CircleDot className={cn("w-2.5 h-2.5", connected && "animate-pulse")} />
            {connected ? "Live" : "Connecting…"}
          </Badge>
        </div>
      </div>
      <div ref={listRef} className="overflow-y-auto" style={{ maxHeight: 340 }}>
        {events.length === 0 ? (
          <div className="px-4 py-16 text-center">
            <Radio className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">Waiting for scan traffic</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Start a scan to see live HTTP requests here</p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-muted/80 backdrop-blur-sm border-b z-10">
              <tr className="text-muted-foreground">
                <th className="px-3 py-2 text-left font-medium w-24">Time</th>
                <th className="px-3 py-2 text-left font-medium w-12">Method</th>
                <th className="px-3 py-2 text-left font-medium">URL</th>
                <th className="px-3 py-2 text-right font-medium w-14">Status</th>
                <th className="px-3 py-2 text-right font-medium w-20">Latency</th>
                <th className="px-3 py-2 text-right font-medium w-14">Retries</th>
                <th className="px-3 py-2 text-left font-medium w-24">Flags</th>
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev.id} className={cn(
                  "border-b last:border-0 transition-colors",
                  ev.degradedMode ? "bg-orange-500/8" : ev.wafDetected ? "bg-red-500/5" : ev.captchaDetected ? "bg-amber-500/5" : "hover:bg-muted/30"
                )}>
                  <td className="px-3 py-1.5 text-muted-foreground tabular-nums font-mono">
                    {new Date(ev.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                  </td>
                  <td className="px-3 py-1.5 font-mono font-semibold">{ev.method}</td>
                  <td className="px-3 py-1.5 font-mono max-w-0 truncate" title={ev.url}>
                    {ev.url.replace(/^https?:\/\//, "").slice(0, 80)}
                  </td>
                  <td className={cn("px-3 py-1.5 text-right font-mono font-bold", statusColor(ev.statusCode))}>
                    {ev.statusCode ?? "—"}
                  </td>
                  <td className="px-3 py-1.5 text-right text-muted-foreground tabular-nums">
                    {ev.latencyMs != null ? `${Math.round(ev.latencyMs)}ms` : "—"}
                  </td>
                  <td className="px-3 py-1.5 text-right">
                    {(ev.retries ?? 0) > 0 ? <span className="text-amber-500 font-semibold">{ev.retries}</span> : "—"}
                  </td>
                  <td className="px-3 py-1.5">
                    <div className="flex gap-1 flex-wrap">
                      {ev.degradedMode && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-orange-500/10 text-orange-600 border-orange-500/30">DEGRADED</Badge>}
                      {ev.wafDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-red-500/10 text-red-600 border-red-500/30">WAF</Badge>}
                      {ev.captchaDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-amber-500/10 text-amber-600 border-amber-500/30">CAPTCHA</Badge>}
                      {ev.proxyId && !ev.wafDetected && !ev.captchaDetected && !ev.degradedMode && (
                        <Badge variant="outline" className="text-[10px] px-1 py-0 bg-blue-500/10 text-blue-600 border-blue-500/30">Proxy</Badge>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

/* ─── Section Header ──────────────────────────────────────────────────── */
function SectionHeader({ icon: Icon, color, title, subtitle, badge }: {
  icon: React.ElementType; color: string; title: string; subtitle?: string;
  badge?: React.ReactNode;
}) {
  const colorMap: Record<string, { bg: string; icon: string; border: string }> = {
    blue:   { bg: "bg-blue-500/15",   icon: "text-blue-500",   border: "border-blue-500/25"   },
    green:  { bg: "bg-green-500/15",  icon: "text-green-500",  border: "border-green-500/25"  },
    red:    { bg: "bg-red-500/15",    icon: "text-red-500",    border: "border-red-500/25"    },
    amber:  { bg: "bg-amber-500/15",  icon: "text-amber-500",  border: "border-amber-500/25"  },
    indigo: { bg: "bg-indigo-500/15", icon: "text-indigo-500", border: "border-indigo-500/25" },
    purple: { bg: "bg-purple-500/15", icon: "text-purple-500", border: "border-purple-500/25" },
  };
  const c = colorMap[color] ?? colorMap.blue;
  return (
    <div className="px-5 py-4 border-b flex items-center justify-between bg-muted/20">
      <div className="flex items-center gap-3">
        <div className={cn("p-2 rounded-lg border", c.bg, c.border)}>
          <Icon className={cn("w-4 h-4", c.icon)} />
        </div>
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
        </div>
      </div>
      {badge}
    </div>
  );
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanOrchestrationPage() {
  const { data: stats, isLoading, refetch, dataUpdatedAt } = useQuery<TelemetryStats>({
    queryKey: ["scan-telemetry-stats"],
    queryFn: () => api("/api/scan-telemetry/stats"),
    refetchInterval: 5_000,
  });

  const { data: proxies } = useQuery<Proxy[]>({
    queryKey: ["scan-proxies-list"],
    queryFn: () => api("/api/scan-proxies"),
    refetchInterval: 10_000,
  });

  const trendData = (stats?.trend ?? []).map(t => ({
    time: new Date(t.minute).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    "Requests":   t.requests,
    "Retries":    t.retryCount,
    "WAF Hits":   t.wafCount,
    "429 Rate":   t.count429,
    "403 Block":  t.count403,
  }));

  const r = stats?.requests;
  const p = stats?.proxies;

  type ProxySortKey = "healthScore" | "successPct" | "count429" | "count403" | "avgLatencyMs" | "requestsToday";
  const [proxySort, setProxySort] = useState<{ key: ProxySortKey; dir: "asc" | "desc" }>({ key: "healthScore", dir: "desc" });

  const sortedProxies = useMemo(() => {
    if (!proxies) return [];
    const arr = [...proxies];
    arr.sort((a, b) => {
      let av: number, bv: number;
      if (proxySort.key === "successPct") {
        const ta = (a.successCount ?? 0) + (a.failCount ?? 0);
        const tb = (b.successCount ?? 0) + (b.failCount ?? 0);
        av = ta > 0 ? a.successCount / ta : -1;
        bv = tb > 0 ? b.successCount / tb : -1;
      } else {
        av = (a[proxySort.key] as number | null) ?? -1;
        bv = (b[proxySort.key] as number | null) ?? -1;
      }
      return proxySort.dir === "asc" ? av - bv : bv - av;
    });
    return arr;
  }, [proxies, proxySort]);

  const toggleSort = (key: ProxySortKey) =>
    setProxySort(s => s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "desc" });

  const SortTh = ({ col, label, align = "right" }: { col: ProxySortKey; label: string; align?: "left" | "right" }) => (
    <th className={`px-4 py-2.5 text-${align} font-medium cursor-pointer select-none hover:text-foreground whitespace-nowrap`} onClick={() => toggleSort(col)}>
      {label}{proxySort.key === col ? (proxySort.dir === "desc" ? " ↓" : " ↑") : ""}
    </th>
  );

  interface TargetHealth { host: string; circuitState: string; failures: number; lastStatus: number | null; reqPerSec: number; }
  const targetHealth: TargetHealth[] = [];
  const seenHosts = new Set<string>();
  const hs = stats?.hostStats ?? {};
  for (const c of (stats?.circuits?.details ?? [])) {
    if (!seenHosts.has(c.host)) {
      seenHosts.add(c.host);
      targetHealth.push({ host: c.host, circuitState: c.state, failures: c.failures, lastStatus: hs[c.host]?.lastStatus ?? null, reqPerSec: hs[c.host]?.reqPerSec ?? 0 });
    }
  }
  for (const rl of (stats?.rateLimiters ?? [])) {
    if (!seenHosts.has(rl.host)) {
      seenHosts.add(rl.host);
      targetHealth.push({ host: rl.host, circuitState: "closed", failures: 0, lastStatus: hs[rl.host]?.lastStatus ?? null, reqPerSec: hs[rl.host]?.reqPerSec ?? 0 });
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-violet-500/15 border border-violet-500/25">
            <Network className="w-6 h-6 text-violet-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Scan Orchestration Dashboard</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Live view of HTTP orchestration — proxy health, rate limiting, circuit breakers &amp; telemetry
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {dataUpdatedAt > 0 && (
            <span className="text-xs text-muted-foreground hidden sm:block">
              Updated {new Date(dataUpdatedAt).toLocaleTimeString()} · auto every 5s
            </span>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* ── Top stat row: Proxy Pool ── */}
      <div>
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Proxy Pool Status</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-4">
          {isLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
          ) : (
            <>
              <StatCard label="Healthy Proxies"    value={p?.activeProxies ?? 0}    icon={Wifi}    color="green" sub="accepting requests" />
              <StatCard label="Cooling Down"        value={p?.coolingProxies ?? 0}   icon={Clock}   color="amber" sub="temporary pause" />
              <StatCard label="Inactive Proxies"    value={p?.inactiveProxies ?? 0}  icon={WifiOff} color="red" sub="health check failed" />
              <StatCard label="Avg Health Score"
                value={p?.avgHealthScore != null ? `${Math.round(p.avgHealthScore)}` : "—"}
                icon={Activity}
                color={!p?.avgHealthScore || p.avgHealthScore >= 70 ? "green" : p.avgHealthScore >= 40 ? "amber" : "red"}
                sub="pool average" />
            </>
          )}
        </div>
      </div>

      {/* ── Second stat row: Request Metrics ── */}
      <div>
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Request Metrics (Last 30 min)</p>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          {isLoading ? (
            Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
          ) : (
            <>
              <StatCard label="Requests / sec"   value={r?.reqPerSecond ?? 0}                               icon={Zap}        color="blue"   sub="last 60 s" />
              <StatCard label="Avg Latency"       value={r?.avgLatencyMs != null ? `${r.avgLatencyMs}ms` : "—"} icon={Timer}  color="indigo" sub={`p95: ${r?.p95LatencyMs != null ? `${r.p95LatencyMs}ms` : "—"}`} />
              <StatCard label="429 Rate Limited"  value={r?.count429 ?? 0}                                   icon={TrendingDown} color={r?.count429 ? "amber" : "slate"} sub="rate limited" />
              <StatCard label="403 Blocked"       value={r?.count403 ?? 0}                                   icon={Shield}     color={r?.count403 ? "red" : "slate"} sub="access denied" />
              <StatCard label="Open Circuits"     value={`${stats?.circuits?.open ?? 0} / ${stats?.circuits?.total ?? 0}`} icon={ShieldX} color={stats?.circuits?.open ? "red" : "green"} sub={`${stats?.retryQueueSize ?? 0} in retry queue`} />
            </>
          )}
        </div>
      </div>

      {/* ── Live Waterfall ── */}
      <WaterfallWidget />

      {/* ── Charts ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border bg-card overflow-hidden">
          <SectionHeader icon={Activity} color="blue" title="Request Volume Trend" subtitle="Requests, retries and WAF hits — last 30 minutes" />
          <div className="p-5">
            {trendData.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center gap-2">
                <Activity className="w-8 h-8 text-muted-foreground/30" />
                <p className="text-xs text-muted-foreground">No data yet — start a scan to populate this chart</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="Requests" stroke="#6366f1" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="Retries"  stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                  <Line type="monotone" dataKey="WAF Hits" stroke="#ef4444" strokeWidth={1.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="rounded-xl border bg-card overflow-hidden">
          <SectionHeader icon={AlertTriangle} color="amber" title="Blocking Trend" subtitle="429 rate-limited and 403 blocked responses — last 30 minutes" />
          <div className="p-5">
            {trendData.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center gap-2">
                <AlertTriangle className="w-8 h-8 text-muted-foreground/30" />
                <p className="text-xs text-muted-foreground">No data yet.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={220}>
                <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                  <YAxis tick={{ fontSize: 10 }} />
                  <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="429 Rate"  stroke="#f59e0b" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="403 Block" stroke="#ef4444" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* ── Target Blocking Health ── */}
      {targetHealth.length > 0 && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <SectionHeader icon={ShieldX} color="red" title="Target Blocking Health" subtitle="Hosts with active circuit breakers or rate limiting — sourced from runtime state" />
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <th className="px-5 py-2.5 text-left font-medium">Target Host</th>
                  <th className="px-5 py-2.5 text-left font-medium">Circuit State</th>
                  <th className="px-5 py-2.5 text-right font-medium">Failures</th>
                  <th className="px-5 py-2.5 text-right font-medium">Last Status</th>
                  <th className="px-5 py-2.5 text-right font-medium">Current Rate (req/s)</th>
                </tr>
              </thead>
              <tbody>
                {targetHealth.map((t, i) => {
                  const sc = t.lastStatus;
                  const scClass = sc == null ? "text-muted-foreground" : sc >= 500 ? "text-red-500 font-semibold" : sc >= 400 ? "text-amber-500 font-semibold" : "text-green-600 font-semibold";
                  return (
                    <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="px-5 py-3 font-mono text-xs">{t.host}</td>
                      <td className="px-5 py-3"><StatusBadge status={t.circuitState} /></td>
                      <td className="px-5 py-3 text-right text-xs">{t.failures}</td>
                      <td className={`px-5 py-3 text-right text-xs font-mono ${scClass}`}>{sc ?? "—"}</td>
                      <td className="px-5 py-3 text-right text-xs">{t.reqPerSec > 0 ? `${t.reqPerSec}` : "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Proxy Health Overview ── */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <SectionHeader icon={Globe} color="green" title="Proxy Health Overview" subtitle="Top 20 proxies sorted by health score — click column headers to re-sort" />
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th className="px-5 py-2.5 text-left font-medium">IP Address</th>
                <th className="px-5 py-2.5 text-left font-medium">Label</th>
                <th className="px-5 py-2.5 text-left font-medium">Class</th>
                <th className="px-5 py-2.5 text-left font-medium">Country</th>
                <SortTh col="healthScore"   label="Health" />
                <SortTh col="successPct"    label="Success %" />
                <SortTh col="count429"      label="429s" />
                <SortTh col="count403"      label="403s" />
                <SortTh col="avgLatencyMs"  label="Avg Latency" />
                <SortTh col="requestsToday" label="Req Today" />
                <th className="px-5 py-2.5 text-left font-medium">Last Used</th>
                <th className="px-5 py-2.5 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {!proxies || proxies.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-5 py-12 text-center">
                    <Globe className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
                    <p className="text-sm text-muted-foreground">No proxies configured</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">Add proxies in Proxy / IP Pool Management</p>
                  </td>
                </tr>
              ) : sortedProxies.slice(0, 20).map(proxy => {
                const tot = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = tot > 0 ? Math.round(proxy.successCount / tot * 100) : null;
                return (
                  <tr key={proxy.id} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                    <td className="px-5 py-3 font-mono text-xs">{proxy.ip}</td>
                    <td className="px-5 py-3 text-xs text-muted-foreground">{proxy.label ?? "—"}</td>
                    <td className="px-5 py-3"><Badge variant="outline" className="text-xs capitalize">{proxy.type}</Badge></td>
                    <td className="px-5 py-3 text-xs">{proxy.country ?? "—"}</td>
                    <td className="px-5 py-3 text-right">
                      <span className={cn("font-bold text-sm tabular-nums", proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500")}>
                        {proxy.healthScore}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-right text-xs">
                      {successPct != null ? (
                        <span className={successPct >= 80 ? "text-green-600" : successPct >= 50 ? "text-amber-500" : "text-red-500"}>{successPct}%</span>
                      ) : "—"}
                    </td>
                    <td className="px-5 py-3 text-right text-xs">{proxy.count429 ?? 0}</td>
                    <td className="px-5 py-3 text-right text-xs">{proxy.count403 ?? 0}</td>
                    <td className="px-5 py-3 text-right text-xs text-muted-foreground">
                      {proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}
                    </td>
                    <td className="px-5 py-3 text-right text-xs">
                      {proxy.requestsToday > 0 ? proxy.requestsToday.toLocaleString() : "—"}
                    </td>
                    <td className="px-5 py-3 text-xs text-muted-foreground">
                      {proxy.lastTestedAt ? new Date(proxy.lastTestedAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—"}
                    </td>
                    <td className="px-5 py-3"><StatusBadge status={proxy.status} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Circuit Breakers + DNS side by side ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Circuit Breakers */}
        {(stats?.circuits?.details?.length ?? 0) > 0 && (
          <div className="rounded-xl border bg-card overflow-hidden">
            <SectionHeader
              icon={ShieldX}
              color="red"
              title="Circuit Breaker States"
              subtitle="Per-host circuit breaker state from the orchestration layer"
              badge={
                stats!.circuits.open > 0 ? (
                  <Badge variant="outline" className="bg-red-500/15 text-red-600 border-red-500/30 text-xs">
                    {stats!.circuits.open} open
                  </Badge>
                ) : undefined
              }
            />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                    <th className="px-5 py-2.5 text-left font-medium">Target Host</th>
                    <th className="px-5 py-2.5 text-left font-medium">State</th>
                    <th className="px-5 py-2.5 text-right font-medium">Failures</th>
                    <th className="px-5 py-2.5 text-left font-medium">Last Failure</th>
                  </tr>
                </thead>
                <tbody>
                  {stats!.circuits.details.map((c, i) => (
                    <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="px-5 py-3 font-mono text-xs">{c.host}</td>
                      <td className="px-5 py-3"><StatusBadge status={c.state} /></td>
                      <td className="px-5 py-3 text-right text-xs">{c.failures}</td>
                      <td className="px-5 py-3 text-xs text-muted-foreground">
                        {c.lastFailure ? new Date(c.lastFailure).toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* DNS Resolvers */}
        {(stats?.dnsResolvers?.length ?? 0) > 0 && (
          <div className="rounded-xl border bg-card overflow-hidden">
            <SectionHeader icon={Database} color="indigo" title="DNS Resolver Pool" subtitle="Performance of upstream DNS resolvers" />
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                    <th className="px-5 py-2.5 text-left font-medium">Resolver IP</th>
                    <th className="px-5 py-2.5 text-right font-medium">Avg Latency</th>
                    <th className="px-5 py-2.5 text-right font-medium">Successes</th>
                    <th className="px-5 py-2.5 text-right font-medium">Failures</th>
                  </tr>
                </thead>
                <tbody>
                  {stats!.dnsResolvers.map((d, i) => (
                    <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="px-5 py-3 font-mono text-xs">{d.ip}</td>
                      <td className="px-5 py-3 text-right text-xs">{d.avgMs != null ? `${Math.round(d.avgMs)}ms` : "—"}</td>
                      <td className="px-5 py-3 text-right text-xs text-green-600 font-semibold">{d.successes}</td>
                      <td className="px-5 py-3 text-right text-xs text-red-500 font-semibold">{d.failures}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
