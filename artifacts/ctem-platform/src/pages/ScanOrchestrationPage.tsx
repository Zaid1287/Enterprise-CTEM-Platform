import { useQuery } from "@tanstack/react-query";
import {
  Activity, Server, AlertTriangle, Zap, Clock, RefreshCw,
  ShieldX, Wifi, WifiOff, CheckCircle2, XCircle, RotateCcw,
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
interface TelemetryStats {
  window: string;
  generatedAt: string;
  requests: {
    totalRequests: number; avgLatencyMs: number; p95LatencyMs: number;
    count429: number; count403: number; countWaf: number; countCaptcha: number;
    totalRetries: number; avgBytesDownloaded: number; reqPerSecond: number;
  };
  retryQueueSize: number;
  trend: Array<{ minute: string; requests: number; avgLatencyMs: number; wafCount: number; retryCount: number }>;
  proxies: { activeProxies: number; coolingProxies: number; inactiveProxies: number; avgHealthScore: number };
  circuits: { open: number; total: number; details: Array<{ host: string; state: string; failures: number; lastFailure: number }> };
  rateLimiters: Array<{ host: string; tokens: number; lastRefill: number }>;
  dnsResolvers: Array<{ ip: string; avgMs: number; failures: number; successes: number }>;
}
interface Proxy {
  id: number; ip: string; label: string | null; type: string; country: string | null; asn: string | null;
  healthScore: number; successCount: number; failCount: number; count429: number; count403: number;
  avgLatencyMs: number | null; status: "active" | "cooldown" | "inactive"; lastTestedAt: string | null;
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
function StatCard({ label, value, icon: Icon, color = "text-foreground", sub }: {
  label: string; value: string | number; icon: React.ElementType; color?: string; sub?: string;
}) {
  return (
    <div className="rounded-xl border bg-card p-4 flex items-start gap-3">
      <div className="p-2 rounded-lg bg-muted">
        <Icon className={cn("w-4 h-4", color)} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-muted-foreground truncate">{label}</p>
        <p className={cn("text-xl font-bold leading-tight mt-0.5", color)}>{value}</p>
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
    "Requests": t.requests,
    "429s": 0,
    "WAF Hits": t.wafCount,
    "Retries": t.retryCount,
    "Avg Latency (ms)": t.avgLatencyMs,
  }));

  const r = stats?.requests;
  const p = stats?.proxies;

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan Orchestration Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Live view of HTTP orchestration layer — proxy health, rate limiting, circuit breakers, telemetry
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </Button>
      </div>

      {/* Last updated */}
      {dataUpdatedAt > 0 && (
        <p className="text-xs text-muted-foreground">
          Last updated: {new Date(dataUpdatedAt).toLocaleTimeString()} · Auto-refreshes every 5s
        </p>
      )}

      {/* Stat widgets */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        {isLoading ? (
          Array.from({ length: 7 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)
        ) : (
          <>
            <StatCard label="Healthy Proxies"   value={p?.activeProxies ?? 0}    icon={Wifi}         color="text-green-600" />
            <StatCard label="Cooling Proxies"   value={p?.coolingProxies ?? 0}   icon={Clock}        color="text-amber-500" />
            <StatCard label="Inactive Proxies"  value={p?.inactiveProxies ?? 0}  icon={WifiOff}      color="text-red-500" />
            <StatCard label="Requests / sec"    value={r?.reqPerSecond ?? 0}     icon={Zap}          color="text-blue-500" sub="last 5 min" />
            <StatCard label="Avg Latency"       value={r?.avgLatencyMs != null ? `${r.avgLatencyMs}ms` : "—"} icon={Activity}  color="text-purple-500" sub={r?.p95LatencyMs != null ? `p95: ${r.p95LatencyMs}ms` : undefined} />
            <StatCard label="Open Circuits"     value={stats?.circuits?.open ?? 0} icon={ShieldX}    color={stats?.circuits?.open ? "text-red-500" : "text-green-600"} sub={`${stats?.circuits?.total ?? 0} total`} />
            <StatCard label="Retry Queue"       value={stats?.retryQueueSize ?? 0} icon={RotateCcw}  color={stats?.retryQueueSize ? "text-amber-500" : "text-muted-foreground"} sub="last 5 min" />
          </>
        )}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request trend */}
        <div className="rounded-xl border bg-card p-4">
          <h2 className="text-sm font-semibold mb-3">Request Trend (last 60 min)</h2>
          {trendData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No data yet — requests will appear here once scans run.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="Requests"        stroke="#3b82f6" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Retries"         stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                <Line type="monotone" dataKey="WAF Hits"        stroke="#ef4444" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Latency trend */}
        <div className="rounded-xl border bg-card p-4">
          <h2 className="text-sm font-semibold mb-3">Avg Latency Trend (ms, last 60 min)</h2>
          {trendData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No data yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="Avg Latency (ms)" stroke="#8b5cf6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Proxy Health Table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-4 py-3 border-b">
          <h2 className="text-sm font-semibold">Proxy Health Scores</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th className="px-4 py-2 text-left font-medium">IP Address</th>
                <th className="px-4 py-2 text-left font-medium">Label</th>
                <th className="px-4 py-2 text-left font-medium">Type</th>
                <th className="px-4 py-2 text-left font-medium">Country</th>
                <th className="px-4 py-2 text-right font-medium">Health Score</th>
                <th className="px-4 py-2 text-right font-medium">Avg Latency</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-left font-medium">Last Tested</th>
              </tr>
            </thead>
            <tbody>
              {!proxies || proxies.length === 0 ? (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-xs text-muted-foreground">No proxies configured. Add proxies in Settings → Proxy Management.</td></tr>
              ) : proxies.slice(0, 20).map(proxy => (
                <tr key={proxy.id} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                  <td className="px-4 py-2 font-mono text-xs">{proxy.ip}</td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">{proxy.label ?? "—"}</td>
                  <td className="px-4 py-2"><Badge variant="outline" className="text-xs">{proxy.type}</Badge></td>
                  <td className="px-4 py-2 text-xs">{proxy.country ?? "—"}</td>
                  <td className="px-4 py-2 text-right">
                    <span className={cn("font-semibold", proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500")}>
                      {proxy.healthScore}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right text-xs text-muted-foreground">
                    {proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}
                  </td>
                  <td className="px-4 py-2"><StatusBadge status={proxy.status} /></td>
                  <td className="px-4 py-2 text-xs text-muted-foreground">
                    {proxy.lastTestedAt ? new Date(proxy.lastTestedAt).toLocaleString() : "Never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Circuit Breakers */}
      {(stats?.circuits?.details?.length ?? 0) > 0 && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="px-4 py-3 border-b flex items-center justify-between">
            <h2 className="text-sm font-semibold">Circuit Breaker States</h2>
            {stats!.circuits.open > 0 && (
              <Badge variant="outline" className="bg-red-500/15 text-red-600 border-red-500/30 text-xs">
                {stats!.circuits.open} open
              </Badge>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Target Host</th>
                  <th className="px-4 py-2 text-left font-medium">State</th>
                  <th className="px-4 py-2 text-right font-medium">Failures</th>
                  <th className="px-4 py-2 text-left font-medium">Last Failure</th>
                </tr>
              </thead>
              <tbody>
                {stats!.circuits.details.map((c, i) => (
                  <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                    <td className="px-4 py-2 font-mono text-xs">{c.host}</td>
                    <td className="px-4 py-2"><StatusBadge status={c.state} /></td>
                    <td className="px-4 py-2 text-right text-xs">{c.failures}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">
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
          <div className="px-4 py-3 border-b">
            <h2 className="text-sm font-semibold">DNS Resolver Pool</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Resolver IP</th>
                  <th className="px-4 py-2 text-right font-medium">Avg Latency</th>
                  <th className="px-4 py-2 text-right font-medium">Successes</th>
                  <th className="px-4 py-2 text-right font-medium">Failures</th>
                </tr>
              </thead>
              <tbody>
                {stats!.dnsResolvers.map((d, i) => (
                  <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                    <td className="px-4 py-2 font-mono text-xs">{d.ip}</td>
                    <td className="px-4 py-2 text-right text-xs">{d.avgMs != null ? `${Math.round(d.avgMs)}ms` : "—"}</td>
                    <td className="px-4 py-2 text-right text-xs text-green-600">{d.successes}</td>
                    <td className="px-4 py-2 text-right text-xs text-red-500">{d.failures}</td>
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
