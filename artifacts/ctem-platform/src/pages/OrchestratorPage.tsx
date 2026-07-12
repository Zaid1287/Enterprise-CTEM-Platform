import { useState, useEffect, useRef, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity, Server, AlertTriangle, Zap, Clock, RefreshCw,
  ShieldX, Wifi, WifiOff, RotateCcw, TrendingDown, Timer,
  Radio, CircleDot, Plus, Trash2, Pencil, Loader2, TestTube2,
  Upload, Check, X, KeyRound, Eye, EyeOff, ChevronDown, ChevronRight,
  Monitor, Smartphone, Globe, Save, Info,
  Download, Filter, Search, Shield,
} from "lucide-react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Tooltip as UITooltip, TooltipContent, TooltipTrigger,
} from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";
import { useAuth } from "@/hooks/useAuth";

/* ─── Shared API helper ──────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs(), ...opts });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error((e as any).error ?? "Request failed"); }
  return r.json();
}

/* ─── Types ──────────────────────────────────────────────────────────── */
interface TrendPoint {
  minute: string; requests: number; avgLatencyMs: number;
  wafCount: number; retryCount: number; count429: number; count403: number;
}
interface TelemetryStats {
  window: string; generatedAt: string;
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
  id: number; ip: string; port: number; label: string | null; type: string;
  country: string | null; asn: string | null; username: string | null; hasAuth: boolean;
  healthScore: number; successCount: number; failCount: number;
  count429: number; count403: number; avgLatencyMs: number | null;
  status: "active" | "cooldown" | "inactive"; lastTestedAt: string | null;
  requestsToday?: number;
}
interface BulkResult {
  imported: number; failed: number; total: number;
  results: Array<{ ip: string; port: number; ok: boolean; latencyMs?: number; error?: string }>;
}
interface FingerprintProfile {
  id: number; name: string; headers: Record<string, string>;
  isActive: boolean; createdAt: string; updatedAt: string;
}
interface TelemetryRow {
  id: number; url: string; method: string; proxyIp: string | null;
  fingerprintProfileId: number | null; statusCode: number | null; latencyMs: number | null;
  retries: number; delayMs: number | null; backoffMs: number | null;
  wafDetected: boolean; captchaDetected: boolean; bytesDownloaded: number | null; createdAt: string;
}
interface TelemetryResponse { rows: TelemetryRow[]; total: number; page: number; limit: number; }
interface WaterfallEvent {
  id: string; ts: number; method: string; url: string; statusCode?: number;
  latencyMs?: number; proxyId?: number; wafDetected?: boolean;
  captchaDetected?: boolean; retries?: number; degradedMode?: boolean;
}

/* ─── Shared sub-components ──────────────────────────────────────────── */
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

function ProxyStatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; icon: React.ElementType; cls: string }> = {
    active:   { label: "Healthy",      icon: Wifi,    cls: "bg-green-500/15 text-green-600 border-green-500/30" },
    cooldown: { label: "Cooling Down", icon: Clock,   cls: "bg-amber-500/15 text-amber-600 border-amber-500/30" },
    inactive: { label: "Inactive",     icon: WifiOff, cls: "bg-red-500/15 text-red-600 border-red-500/30" },
  };
  const s = map[status] ?? { label: status, icon: RefreshCw, cls: "bg-muted text-muted-foreground" };
  const Icon = s.icon;
  return (
    <Badge variant="outline" className={cn("text-xs font-medium gap-1", s.cls)}>
      <Icon className="w-3 h-3" />{s.label}
    </Badge>
  );
}

function CircuitBadge({ state }: { state: string }) {
  const map: Record<string, string> = {
    open:      "bg-red-500/15 text-red-600 border-red-500/30",
    closed:    "bg-green-500/15 text-green-600 border-green-500/30",
    half_open: "bg-amber-500/15 text-amber-600 border-amber-500/30",
  };
  return (
    <Badge variant="outline" className={cn("text-xs font-medium", map[state] ?? "bg-muted text-muted-foreground")}>
      {state === "half_open" ? "Half-Open" : state.charAt(0).toUpperCase() + state.slice(1)}
    </Badge>
  );
}

function StatusCode({ code }: { code: number | null }) {
  if (code == null) return <span className="text-muted-foreground text-xs">—</span>;
  const cls = code >= 500 ? "text-red-500" : code >= 400 ? "text-amber-500" : code >= 300 ? "text-blue-500" : "text-green-600";
  return <span className={cn("font-mono text-xs font-semibold", cls)}>{code}</span>;
}

/* ─── TAB 1: Dashboard ───────────────────────────────────────────────── */
function WaterfallWidget() {
  const [events, setEvents] = useState<WaterfallEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const url = `${BASE()}/api/scan-telemetry/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    const parseWaterfallEvent = (e: MessageEvent, degradedMode?: boolean): void => {
      try {
        const data = JSON.parse(e.data);
        const event: WaterfallEvent = {
          id: `${Date.now()}-${Math.random()}`,
          ts: data.ts ?? Date.now(), method: data.method ?? "GET", url: data.url ?? "",
          statusCode: data.statusCode, latencyMs: data.latencyMs,
          proxyId: data.proxyId, wafDetected: data.wafDetected,
          captchaDetected: data.captchaDetected, retries: data.retries,
          degradedMode: degradedMode ?? data.degradedMode,
        };
        setEvents(prev => [event, ...prev].slice(0, 100));
      } catch { /* ignore */ }
    };
    es.addEventListener("telemetry:request", (e: MessageEvent) => parseWaterfallEvent(e));
    es.addEventListener("telemetry:degraded_mode", (e: MessageEvent) => parseWaterfallEvent(e, true));
    return () => { es.close(); setConnected(false); };
  }, []);

  const statusColor = (code?: number) => {
    if (!code) return "text-muted-foreground";
    if (code >= 200 && code < 300) return "text-green-600";
    if (code === 429) return "text-amber-500";
    if (code >= 400) return "text-red-500";
    return "text-muted-foreground";
  };

  return (
    <div className="rounded-xl border bg-card overflow-hidden">
      <div className="px-4 py-3 border-b flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="w-4 h-4 text-blue-500" />
          <h2 className="text-sm font-semibold">Real-Time Request Waterfall</h2>
        </div>
        <div className="flex items-center gap-2">
          {events.length > 0 && (
            <Button variant="ghost" size="sm" className="h-6 text-xs px-2" onClick={() => setEvents([])}>Clear</Button>
          )}
          <Badge variant="outline" className={cn("text-xs gap-1", connected
            ? "bg-green-500/15 text-green-600 border-green-500/30"
            : "bg-muted text-muted-foreground")}>
            <CircleDot className={cn("w-2.5 h-2.5", connected && "animate-pulse")} />
            {connected ? "Live" : "Connecting…"}
          </Badge>
        </div>
      </div>
      <div ref={listRef} className="overflow-y-auto" style={{ maxHeight: 280 }}>
        {events.length === 0 ? (
          <div className="px-4 py-10 text-center text-xs text-muted-foreground">
            Waiting for requests… Start a scan to see live traffic here.
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-muted/60 backdrop-blur-sm border-b z-10">
              <tr className="text-muted-foreground">
                <th className="px-3 py-2 text-left font-medium w-20">Time</th>
                <th className="px-3 py-2 text-left font-medium w-12">Method</th>
                <th className="px-3 py-2 text-left font-medium">URL</th>
                <th className="px-3 py-2 text-right font-medium w-14">Status</th>
                <th className="px-3 py-2 text-right font-medium w-16">Latency</th>
                <th className="px-3 py-2 text-right font-medium w-12">Retries</th>
                <th className="px-3 py-2 text-left font-medium w-24">Flags</th>
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev.id} className={cn(
                  "border-b last:border-0 transition-colors",
                  ev.degradedMode ? "bg-orange-500/8" : ev.wafDetected ? "bg-red-500/5" : ev.captchaDetected ? "bg-amber-500/5" : "hover:bg-muted/30"
                )}>
                  <td className="px-3 py-1.5 text-muted-foreground tabular-nums">
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
                      {ev.degradedMode && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-orange-500/10 text-orange-600 border-orange-500/30" title="Orchestrator bootstrap failed — request used plain fetch() with no proxy or fingerprint rotation">DEGRADED</Badge>}
                      {ev.wafDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-red-500/10 text-red-600 border-red-500/30">WAF</Badge>}
                      {ev.captchaDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-amber-500/10 text-amber-600 border-amber-500/30">CAPTCHA</Badge>}
                      {ev.proxyId && !ev.wafDetected && !ev.captchaDetected && !ev.degradedMode && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-blue-500/10 text-blue-600 border-blue-500/30">Proxy</Badge>}
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

function DashboardTab() {
  const { data: stats, isLoading, refetch, dataUpdatedAt } = useQuery<TelemetryStats>({
    queryKey: ["orch-telemetry-stats"],
    queryFn: () => api("/api/scan-telemetry/stats"),
    refetchInterval: 30_000,
  });

  const trendData = (stats?.trend ?? []).map(t => ({
    time: new Date(t.minute).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    "Requests": t.requests, "Retries": t.retryCount,
    "WAF Hits": t.wafCount, "429 Rate": t.count429, "403 Block": t.count403,
  }));

  const r = stats?.requests;
  const p = stats?.proxies;

  /* Circuit + target health */
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

  const dns = stats?.dnsResolvers ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          {dataUpdatedAt > 0 ? `Last updated: ${new Date(dataUpdatedAt).toLocaleTimeString()} · Auto-refreshes every 30s` : "Loading…"}
        </p>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" />Refresh
        </Button>
      </div>

      {/* Stat cards — last 60-min overview */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 gap-3">
        {isLoading ? Array.from({ length: 12 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />) : (
          <>
            <StatCard label="Total Requests"    value={(r?.totalRequests ?? 0).toLocaleString()} icon={Activity}    color="text-blue-500"    sub="last 60 min" />
            <StatCard label="Avg Latency"       value={r?.avgLatencyMs != null ? `${r.avgLatencyMs}ms` : "—"} icon={Timer} color="text-indigo-500" sub={`p95: ${r?.p95LatencyMs != null ? `${r.p95LatencyMs}ms` : "—"}`} />
            <StatCard label="429 Rate Limited"  value={r?.count429 ?? 0}         icon={TrendingDown} color={r?.count429 ? "text-amber-500" : "text-muted-foreground"} sub="last 60 min" />
            <StatCard label="WAF Detections"    value={r?.countWaf ?? 0}         icon={Shield}      color={r?.countWaf ? "text-red-500" : "text-muted-foreground"}    sub="last 60 min" />
            <StatCard label="Captcha Hits"      value={r?.countCaptcha ?? 0}     icon={AlertTriangle} color={r?.countCaptcha ? "text-amber-500" : "text-muted-foreground"} sub="last 60 min" />
            <StatCard label="Open Circuits"     value={stats?.circuits?.open ?? 0} icon={ShieldX}   color={stats?.circuits?.open ? "text-red-500" : "text-green-600"} sub={`${stats?.circuits?.total ?? 0} total`} />
          </>
        )}
      </div>
      {/* Secondary row: proxy health + throughput + queue */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        {isLoading ? Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />) : (
          <>
            <StatCard label="Healthy Proxies"  value={p?.activeProxies ?? 0}    icon={Wifi}        color="text-green-600" />
            <StatCard label="Cooling Proxies"  value={p?.coolingProxies ?? 0}   icon={Clock}       color="text-amber-500" />
            <StatCard label="Inactive Proxies" value={p?.inactiveProxies ?? 0}  icon={WifiOff}     color="text-red-500" />
            <StatCard label="Requests / sec"   value={r?.reqPerSecond ?? 0}     icon={Zap}         color="text-blue-500" sub="live" />
            <StatCard label="Retry Queue"      value={stats?.retryQueueSize ?? 0} icon={RotateCcw} color={stats?.retryQueueSize ? "text-amber-500" : "text-muted-foreground"} sub="live" />
          </>
        )}
      </div>

      {/* Waterfall */}
      <WaterfallWidget />

      {/* Trend charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border bg-card p-4">
          <h2 className="text-sm font-semibold mb-3">Request Volume Trend (last 30 min)</h2>
          {trendData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No data yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="Requests" stroke="#3b82f6" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="Retries"  stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                <Line type="monotone" dataKey="WAF Hits" stroke="#ef4444" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="rounded-xl border bg-card p-4">
          <h2 className="text-sm font-semibold mb-3">429 / 403 Blocking Trend (last 30 min)</h2>
          {trendData.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-muted-foreground">No data yet.</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={trendData} margin={{ left: -20, right: 8 }}>
                <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
                <XAxis dataKey="time" tick={{ fontSize: 10 }} />
                <YAxis tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ fontSize: 11 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
                <Line type="monotone" dataKey="429 Rate"  stroke="#f59e0b" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="403 Block" stroke="#ef4444" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* DNS Resolvers */}
      {dns.length > 0 && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="px-4 py-3 border-b">
            <h2 className="text-sm font-semibold">DNS Resolver Health</h2>
            <p className="text-xs text-muted-foreground mt-0.5">Latency and failure counts per resolver from runtime state</p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Resolver IP</th>
                  <th className="px-4 py-2 text-right font-medium">Avg Latency</th>
                  <th className="px-4 py-2 text-right font-medium">Successes</th>
                  <th className="px-4 py-2 text-right font-medium">Failures</th>
                  <th className="px-4 py-2 text-right font-medium">Success Rate</th>
                </tr>
              </thead>
              <tbody>
                {dns.map((d, i) => {
                  const total = d.successes + d.failures;
                  const rate = total > 0 ? Math.round((d.successes / total) * 100) : null;
                  return (
                    <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                      <td className="px-4 py-2 font-mono text-xs">{d.ip}</td>
                      <td className="px-4 py-2 text-right text-xs">{d.avgMs > 0 ? `${Math.round(d.avgMs)}ms` : "—"}</td>
                      <td className="px-4 py-2 text-right text-xs text-green-600">{d.successes}</td>
                      <td className={cn("px-4 py-2 text-right text-xs", d.failures > 0 ? "text-red-500 font-semibold" : "text-muted-foreground")}>{d.failures}</td>
                      <td className="px-4 py-2 text-right text-xs">
                        {rate != null ? (
                          <span className={rate >= 90 ? "text-green-600 font-semibold" : rate >= 70 ? "text-amber-500 font-semibold" : "text-red-500 font-semibold"}>
                            {rate}%
                          </span>
                        ) : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Circuit Breaker Status */}
      {(stats?.circuits?.details ?? []).length > 0 && (
        <div className="rounded-xl border bg-card overflow-hidden">
          <div className="px-4 py-3 border-b">
            <h2 className="text-sm font-semibold">Circuit Breaker Status</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              {stats!.circuits.open} open / {stats!.circuits.total} total circuits
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                  <th className="px-4 py-2 text-left font-medium">Target Host</th>
                  <th className="px-4 py-2 text-left font-medium">State</th>
                  <th className="px-4 py-2 text-right font-medium">Failures</th>
                  <th className="px-4 py-2 text-right font-medium">Last Status</th>
                  <th className="px-4 py-2 text-right font-medium">Req/s</th>
                </tr>
              </thead>
              <tbody>
                {targetHealth.map((t, i) => (
                  <tr key={i} className="border-b last:border-0 hover:bg-muted/30">
                    <td className="px-4 py-2 font-mono text-xs">{t.host}</td>
                    <td className="px-4 py-2"><CircuitBadge state={t.circuitState} /></td>
                    <td className="px-4 py-2 text-right text-xs">{t.failures}</td>
                    <td className="px-4 py-2 text-right"><StatusCode code={t.lastStatus} /></td>
                    <td className="px-4 py-2 text-right text-xs">{t.reqPerSec > 0 ? t.reqPerSec : "—"}</td>
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

/* ─── TAB 2: Proxy Pool ──────────────────────────────────────────────── */
function ProxyDialog({ open, onClose, initial }: { open: boolean; onClose: () => void; initial?: Proxy }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [ip, setIp]           = useState(initial?.ip ?? "");
  const [port, setPort]       = useState(String(initial?.port ?? "3128"));
  const [label, setLabel]     = useState(initial?.label ?? "");
  const [type, setType]       = useState(initial?.type ?? "http");
  const [country, setCountry] = useState(initial?.country ?? "");
  const [asn, setAsn]         = useState(initial?.asn ?? "");
  const [username, setUsername] = useState(initial?.username ?? "");
  const [password, setPassword] = useState("");
  const [showPwd, setShowPwd]   = useState(false);
  const isEdit = !!initial;

  const saveMut = useMutation({
    mutationFn: (body: object) =>
      isEdit
        ? api(`/api/scan-proxies/${initial!.id}`, { method: "PATCH", body: JSON.stringify(body) })
        : api("/api/scan-proxies", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orch-proxies"] }); toast({ title: isEdit ? "Proxy updated" : "Proxy added" }); onClose(); },
    onError: (e: Error) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const handleSubmit = () => {
    if (!ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    const body: Record<string, any> = {
      ip: ip.trim(), port: parseInt(port, 10), label: label || undefined,
      type, country: country || undefined, asn: asn || undefined, username: username || undefined,
    };
    if (password) body.password = password;
    saveMut.mutate(body);
  };

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader><DialogTitle>{isEdit ? "Edit Proxy" : "Add Proxy"}</DialogTitle></DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>IP Address *</Label>
              <Input placeholder="1.2.3.4" value={ip} onChange={e => setIp(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>Port</Label>
              <Input placeholder="3128" value={port} onChange={e => setPort(e.target.value)} type="number" />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>Label</Label>
            <Input placeholder="e.g. DE Datacenter 1" value={label} onChange={e => setLabel(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Proxy Class</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="datacenter">Datacenter</SelectItem>
                  <SelectItem value="residential">Residential</SelectItem>
                  <SelectItem value="isp">ISP</SelectItem>
                  <SelectItem value="mobile">Mobile</SelectItem>
                  <SelectItem value="socks5">SOCKS5</SelectItem>
                  <SelectItem value="http">HTTP (Generic)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Country</Label>
              <Input placeholder="DE" maxLength={3} value={country} onChange={e => setCountry(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>ASN / Provider</Label>
            <Input placeholder="e.g. Hetzner" value={asn} onChange={e => setAsn(e.target.value)} />
          </div>
          <div className="border-t pt-3">
            <div className="flex items-center gap-1.5 mb-3">
              <KeyRound className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-xs font-medium text-muted-foreground">Authentication (optional)</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>Username</Label>
                <Input placeholder="user" value={username} onChange={e => setUsername(e.target.value)} autoComplete="off" />
              </div>
              <div className="space-y-1.5">
                <Label>{isEdit ? "New Password" : "Password"}</Label>
                <div className="relative">
                  <Input type={showPwd ? "text" : "password"} placeholder={isEdit ? "leave blank to keep" : "pass"}
                    value={password} onChange={e => setPassword(e.target.value)} autoComplete="new-password" className="pr-8" />
                  <button type="button" className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" onClick={() => setShowPwd(v => !v)}>
                    {showPwd ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>
            </div>
            {isEdit && initial?.hasAuth && !password && (
              <p className="text-xs text-muted-foreground mt-1.5">Credentials already set. Leave blank to keep the existing password.</p>
            )}
          </div>
          {!isEdit && (
            <p className="text-xs text-muted-foreground bg-blue-500/10 border border-blue-500/20 rounded-lg px-3 py-2">
              A live TCP ping test will run on save. Status will reflect the result immediately.
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saveMut.isPending}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={saveMut.isPending}>
            {saveMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            {isEdit ? "Save Changes" : "Add & Test"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function BulkImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [text, setText]   = useState("");
  const [result, setResult] = useState<BulkResult | null>(null);
  const [loading, setLoading] = useState(false);

  const handleImport = async () => {
    if (!text.trim()) { toast({ title: "Paste proxy list first", variant: "destructive" }); return; }
    setLoading(true);
    try {
      const res = await api<BulkResult>("/api/scan-proxies/bulk", { method: "POST", body: JSON.stringify({ proxies: text }) });
      setResult(res);
      qc.invalidateQueries({ queryKey: ["orch-proxies"] });
      toast({ title: `Imported ${res.imported} proxies`, description: `${res.failed} failed.` });
    } catch (e: any) {
      toast({ title: "Bulk import failed", description: e.message, variant: "destructive" });
    } finally { setLoading(false); }
  };

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) { onClose(); setResult(null); setText(""); } }}>
      <DialogContent className="max-w-lg">
        <DialogHeader><DialogTitle>Bulk Import Proxies</DialogTitle></DialogHeader>
        <div className="space-y-4 py-2">
          {!result ? (
            <>
              <p className="text-sm text-muted-foreground">Paste one proxy per line. Supported formats:</p>
              <div className="bg-muted/50 rounded-lg px-3 py-2 font-mono text-xs text-muted-foreground space-y-0.5">
                <div>ip:port</div>
                <div>ip:port:username:password</div>
                <div>ip:port:username:password:label</div>
              </div>
              <Textarea placeholder={"1.2.3.4:8080\n5.6.7.8:3128:user:secret"} value={text}
                onChange={e => setText(e.target.value)} rows={8} className="font-mono text-xs" />
            </>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-lg border bg-green-500/10 p-3">
                  <p className="text-2xl font-bold text-green-600">{result.imported}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Imported</p>
                </div>
                <div className="rounded-lg border bg-red-500/10 p-3">
                  <p className="text-2xl font-bold text-red-500">{result.failed}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Failed</p>
                </div>
                <div className="rounded-lg border bg-muted p-3">
                  <p className="text-2xl font-bold">{result.total}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Total</p>
                </div>
              </div>
              <div className="max-h-40 overflow-y-auto space-y-1">
                {result.results.map((r, i) => (
                  <div key={i} className={cn("flex items-center gap-2 text-xs px-2 py-1 rounded", r.ok ? "bg-green-500/5" : "bg-red-500/5")}>
                    {r.ok ? <Check className="w-3 h-3 text-green-600 shrink-0" /> : <X className="w-3 h-3 text-red-500 shrink-0" />}
                    <span className="font-mono">{r.ip}:{r.port}</span>
                    {r.ok && r.latencyMs != null && <span className="text-muted-foreground ml-auto">{r.latencyMs}ms</span>}
                    {!r.ok && r.error && <span className="text-red-500 ml-auto truncate max-w-32" title={r.error}>{r.error}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          {!result ? (
            <>
              <Button variant="ghost" onClick={onClose} disabled={loading}>Cancel</Button>
              <Button onClick={handleImport} disabled={loading || !text.trim()}>
                {loading && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Import & Test
              </Button>
            </>
          ) : (
            <Button onClick={() => { onClose(); setResult(null); setText(""); }}>Done</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ProxiesTab() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showAdd, setShowAdd]         = useState(false);
  const [showBulk, setShowBulk]       = useState(false);
  const [editProxy, setEditProxy]     = useState<Proxy | null>(null);
  const [testingId, setTestingId]     = useState<number | null>(null);
  const [deleteId, setDeleteId]       = useState<number | null>(null);
  const [selectedProxy, setSelectedProxy] = useState<number | null>(null);
  const [filterSearch, setFilterSearch]   = useState("");
  const [filterStatus, setFilterStatus]   = useState("all");
  const [filterType, setFilterType]       = useState("all");

  const { data: proxies = [], isLoading } = useQuery<Proxy[]>({
    queryKey: ["orch-proxies"],
    queryFn: () => api("/api/scan-proxies"),
    refetchInterval: 30_000,
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api(`/api/scan-proxies/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orch-proxies"] }); toast({ title: "Proxy removed" }); setDeleteId(null); },
    onError: () => toast({ title: "Delete failed", variant: "destructive" }),
  });

  const testProxy = async (proxy: Proxy) => {
    setTestingId(proxy.id);
    try {
      const url = `/api/scan-proxies/${proxy.id}/health?testUrl=${encodeURIComponent("http://example.com")}`;
      const result = await api<{
        reachable: boolean; authOk?: boolean; httpStatus?: number; latencyMs?: number; error?: string;
      }>(url);
      qc.invalidateQueries({ queryKey: ["orch-proxies"] });
      if (!result.reachable) {
        toast({ title: "Proxy unreachable", description: result.error ?? "TCP connection failed.", variant: "destructive" });
      } else if (proxy.hasAuth && result.authOk === false) {
        toast({ title: "Auth Failed", description: result.error ?? `Proxy rejected credentials (HTTP ${result.httpStatus ?? "?"})`, variant: "destructive" });
      } else if (proxy.hasAuth && result.authOk) {
        toast({ title: "Auth OK", description: `Credentials accepted — latency ${result.latencyMs ?? "?"}ms` });
      } else {
        toast({ title: "Proxy reachable", description: `Latency: ${result.latencyMs ?? "?"}ms` });
      }
    } catch { toast({ title: "Health check failed", variant: "destructive" }); }
    finally { setTestingId(null); }
  };

  const activeCount   = proxies.filter(p => p.status === "active").length;
  const cooldownCount = proxies.filter(p => p.status === "cooldown").length;
  const inactiveCount = proxies.filter(p => p.status === "inactive").length;
  const totalToday    = proxies.reduce((a, p) => a + (p.requestsToday ?? 0), 0);
  const avgHealth     = proxies.length > 0
    ? Math.round(proxies.reduce((a, p) => a + (p.healthScore ?? 0), 0) / proxies.length) : 0;

  const uniqueTypes = [...new Set(proxies.map(p => p.type))];

  const filteredProxies = proxies.filter(p => {
    if (filterStatus !== "all" && p.status !== filterStatus) return false;
    if (filterType   !== "all" && p.type   !== filterType)   return false;
    if (filterSearch) {
      const q = filterSearch.toLowerCase();
      return p.ip.includes(q) || (p.label ?? "").toLowerCase().includes(q) || (p.country ?? "").toLowerCase().includes(q);
    }
    return true;
  });

  const hasFilters = filterSearch !== "" || filterStatus !== "all" || filterType !== "all";
  const clearFilters = () => { setFilterSearch(""); setFilterStatus("all"); setFilterType("all"); };

  const statTiles = [
    { label: "Total Proxies",  value: proxies.length,  icon: Wifi,     color: "text-primary",   bg: "bg-primary/10" },
    { label: "Healthy",        value: activeCount,     icon: Wifi,     color: "text-green-500", bg: "bg-green-500/10" },
    { label: "Cooling Down",   value: cooldownCount,   icon: Clock,    color: "text-amber-500", bg: "bg-amber-500/10" },
    { label: "Inactive",       value: inactiveCount,   icon: WifiOff,  color: "text-red-500",   bg: "bg-red-500/10" },
    {
      label: "Avg Health", icon: Shield,
      value: proxies.length > 0 ? `${avgHealth}%` : "—",
      color: avgHealth >= 70 ? "text-green-500" : avgHealth >= 40 ? "text-amber-500" : "text-red-500",
      bg: "bg-muted",
    },
    { label: "Requests Today", value: totalToday,      icon: Activity, color: "text-blue-500",  bg: "bg-blue-500/10" },
  ];

  return (
    <div className="space-y-5">
      {/* 6-tile stat bar — full width */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-3">
        {statTiles.map(s => (
          <div key={s.label} className="rounded-xl border bg-card p-4 flex items-center gap-3">
            <div className={cn("p-2.5 rounded-lg shrink-0", s.bg)}>
              <s.icon className={cn("w-4 h-4", s.color)} />
            </div>
            <div>
              <p className={cn("text-2xl font-bold tabular-nums leading-none", s.color)}>{s.value}</p>
              <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Filter + action bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative min-w-[220px] flex-1">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
          <Input
            className="pl-8 h-9 text-sm"
            placeholder="Search by IP, label, or country…"
            value={filterSearch}
            onChange={e => setFilterSearch(e.target.value)}
          />
        </div>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="h-9 w-[150px]"><SelectValue placeholder="All Statuses" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="active">Healthy</SelectItem>
            <SelectItem value="cooldown">Cooling Down</SelectItem>
            <SelectItem value="inactive">Inactive</SelectItem>
          </SelectContent>
        </Select>
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="h-9 w-[130px]"><SelectValue placeholder="All Types" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {(uniqueTypes.length > 0 ? uniqueTypes : ["http", "https", "socks4", "socks5"]).map(t => (
              <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {hasFilters && (
          <Button variant="ghost" size="sm" className="h-9 text-muted-foreground gap-1" onClick={clearFilters}>
            <X className="w-3.5 h-3.5" /> Clear
          </Button>
        )}
        <div className="flex-1" />
        {isSuperAdmin && (
          <>
            <Button variant="outline" onClick={() => setShowBulk(true)} className="gap-1.5 h-9" size="sm">
              <Upload className="w-4 h-4" /> Bulk Import
            </Button>
            <Button onClick={() => setShowAdd(true)} className="gap-1.5 h-9" size="sm">
              <Plus className="w-4 h-4" /> Add Proxy
            </Button>
          </>
        )}
      </div>

      {/* Count line */}
      {!isLoading && proxies.length > 0 && (
        <p className="text-xs text-muted-foreground -mt-1">
          Showing <span className="font-medium text-foreground">{filteredProxies.length}</span> of {proxies.length} proxies
          {hasFilters && " (filtered)"}
          {selectedProxy != null && " — click the highlighted row again to collapse details"}
        </p>
      )}

      {/* Proxy table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-[11px] text-muted-foreground uppercase tracking-wide">
                <th className="px-4 py-3 text-left font-semibold">IP : Port</th>
                <th className="px-4 py-3 text-left font-semibold">Label</th>
                <th className="px-4 py-3 text-left font-semibold">Type</th>
                <th className="px-4 py-3 text-left font-semibold">Country</th>
                <th className="px-5 py-3 text-center font-semibold w-36">Health Score</th>
                <th className="px-4 py-3 text-right font-semibold">Success %</th>
                <th className="px-4 py-3 text-right font-semibold">429s</th>
                <th className="px-4 py-3 text-right font-semibold">403s</th>
                <th className="px-4 py-3 text-right font-semibold">Avg Latency</th>
                <th className="px-4 py-3 text-left font-semibold">Status</th>
                <th className="px-4 py-3 text-right font-semibold">Today</th>
                <th className="px-4 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b">
                  {Array.from({ length: 12 }).map((__, j) => (
                    <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                  ))}
                </tr>
              )) : filteredProxies.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-4 py-16 text-center">
                    <div className="flex flex-col items-center gap-3 text-muted-foreground">
                      <WifiOff className="w-10 h-10 opacity-20" />
                      <p className="text-sm font-medium">
                        {proxies.length === 0
                          ? (isSuperAdmin ? "No proxies configured — click \"Add Proxy\" to get started" : "No proxies configured.")
                          : "No proxies match the current filters."}
                      </p>
                      {proxies.length > 0 && (
                        <Button variant="outline" size="sm" onClick={clearFilters}>Clear filters</Button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : filteredProxies.map(proxy => {
                const total      = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = total > 0 ? Math.round((proxy.successCount / total) * 100) : null;
                const hColor     = proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500";
                const hBarColor  = proxy.healthScore >= 70 ? "#16a34a" : proxy.healthScore >= 30 ? "#f59e0b" : "#ef4444";
                const isSelected = selectedProxy === proxy.id;
                return (
                  <Fragment key={proxy.id}>
                    <tr
                      className={cn(
                        "border-b transition-colors cursor-pointer select-none",
                        isSelected ? "bg-primary/5 border-primary/20" : "hover:bg-muted/30 last:border-0"
                      )}
                      onClick={() => setSelectedProxy(isSelected ? null : proxy.id)}
                    >
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs font-semibold">{proxy.ip}</span>
                        <span className="font-mono text-xs text-muted-foreground">:{proxy.port}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground max-w-[110px] truncate" title={proxy.label ?? undefined}>{proxy.label ?? "—"}</td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] font-mono uppercase tracking-wider bg-muted px-1.5 py-0.5 rounded border border-border/50">{proxy.type}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">{proxy.country ?? "—"}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center justify-center gap-2">
                          <div className="w-20 h-2 rounded-full bg-muted overflow-hidden flex-shrink-0">
                            <div className="h-full rounded-full" style={{ width: `${proxy.healthScore}%`, background: hBarColor }} />
                          </div>
                          <span className={cn("text-xs font-bold tabular-nums w-6 text-right", hColor)}>{proxy.healthScore}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-right">
                        {successPct != null
                          ? <span className={cn("text-xs font-semibold", successPct >= 80 ? "text-green-600" : successPct >= 50 ? "text-amber-500" : "text-red-500")}>{successPct}%</span>
                          : <span className="text-xs text-muted-foreground">—</span>}
                      </td>
                      <td className={cn("px-4 py-3 text-right text-xs font-mono", proxy.count429 > 0 ? "text-amber-500 font-bold" : "text-muted-foreground")}>{proxy.count429}</td>
                      <td className={cn("px-4 py-3 text-right text-xs font-mono", proxy.count403 > 0 ? "text-red-500 font-bold" : "text-muted-foreground")}>{proxy.count403}</td>
                      <td className="px-4 py-3 text-right text-xs font-mono text-muted-foreground">{proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}</td>
                      <td className="px-4 py-3"><ProxyStatusBadge status={proxy.status} /></td>
                      <td className="px-4 py-3 text-right text-xs font-mono text-muted-foreground">{proxy.requestsToday ?? 0}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                          <Button variant="ghost" size="icon" className="w-7 h-7"
                            title={proxy.hasAuth ? "Test connectivity & verify credentials" : "Test connectivity"}
                            onClick={() => testProxy(proxy)} disabled={testingId === proxy.id}>
                            {testingId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube2 className="w-3.5 h-3.5" />}
                          </Button>
                          {isSuperAdmin && (
                            <>
                              <Button variant="ghost" size="icon" className="w-7 h-7" title="Edit" onClick={() => setEditProxy(proxy)}>
                                <Pencil className="w-3.5 h-3.5" />
                              </Button>
                              <Button variant="ghost" size="icon" className="w-7 h-7 text-destructive hover:text-destructive" title="Delete"
                                onClick={() => setDeleteId(proxy.id)} disabled={deleteMut.isPending && deleteId === proxy.id}>
                                {deleteMut.isPending && deleteId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                              </Button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                    {isSelected && (
                      <tr className="border-b bg-muted/20">
                        <td colSpan={12} className="px-6 py-5">
                          <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-3">Proxy Detail — {proxy.ip}:{proxy.port}</p>
                          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-x-6 gap-y-4">
                            {[
                              { label: "Total Requests", value: total,                    color: "" },
                              { label: "Successes",      value: proxy.successCount ?? 0,  color: "text-green-500" },
                              { label: "Failures",       value: proxy.failCount ?? 0,     color: "text-red-500" },
                              { label: "Rate Limits (429)", value: proxy.count429,        color: proxy.count429 > 0 ? "text-amber-500" : "" },
                              { label: "Blocked (403)",  value: proxy.count403,           color: proxy.count403 > 0 ? "text-red-500" : "" },
                              { label: "Avg Latency",    value: proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—", color: "" },
                              { label: "Requests Today", value: proxy.requestsToday ?? 0, color: "text-blue-500" },
                            ].map(stat => (
                              <div key={stat.label}>
                                <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">{stat.label}</p>
                                <p className={cn("text-lg font-bold tabular-nums", stat.color || "text-foreground")}>{stat.value}</p>
                              </div>
                            ))}
                          </div>
                          <div className="flex items-center gap-6 mt-4 pt-3 border-t border-border/40 flex-wrap">
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">Auth:</span>
                              {proxy.hasAuth
                                ? <span className="text-xs text-green-500 flex items-center gap-1"><KeyRound className="w-3 h-3" /> Authenticated</span>
                                : <span className="text-xs text-muted-foreground">None</span>}
                            </div>
                            {proxy.asn && (
                              <div><span className="text-[10px] text-muted-foreground uppercase tracking-wide">ASN: </span>
                              <span className="text-xs font-medium">{proxy.asn}</span></div>
                            )}
                            {proxy.lastTestedAt && (
                              <div><span className="text-[10px] text-muted-foreground uppercase tracking-wide">Last Tested: </span>
                              <span className="text-xs font-medium">{new Date(proxy.lastTestedAt).toLocaleString()}</span></div>
                            )}
                            {proxy.username && (
                              <div><span className="text-[10px] text-muted-foreground uppercase tracking-wide">Username: </span>
                              <span className="text-xs font-mono">{proxy.username}</span></div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Delete confirm dialog */}
      <Dialog open={deleteId != null} onOpenChange={v => { if (!v) setDeleteId(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader><DialogTitle>Remove Proxy</DialogTitle></DialogHeader>
          <p className="text-sm text-muted-foreground py-2">Are you sure you want to remove this proxy from the pool? This action cannot be undone.</p>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDeleteId(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => deleteId != null && deleteMut.mutate(deleteId)} disabled={deleteMut.isPending}>
              {deleteMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {showAdd && <ProxyDialog open onClose={() => setShowAdd(false)} />}
      {editProxy && <ProxyDialog open onClose={() => setEditProxy(null)} initial={editProxy} />}
      {showBulk && <BulkImportDialog open onClose={() => setShowBulk(false)} />}
    </div>
  );
}

/* ─── TAB 3: Fingerprints ────────────────────────────────────────────── */
const FINGERPRINT_DEFAULTS: Record<string, Record<string, string>> = {
  "Chrome 137 / Windows 10": {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none",
    "Sec-CH-UA": '"Not_A Brand";v="8", "Chromium";v="137", "Google Chrome";v="137"',
    "Sec-CH-UA-Mobile": "?0", "Sec-CH-UA-Platform": '"Windows"',
  },
  "Firefox 128 / Linux": {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive", "Upgrade-Insecure-Requests": "1",
  },
};

const ALL_HEADER_KEYS = [
  "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection",
  "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform",
  "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Upgrade-Insecure-Requests", "DNT",
];

function FingerprintEditDialog({ profile, onClose }: { profile: FingerprintProfile; onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [headers, setHeaders] = useState<Record<string, string>>(profile.headers ?? {});
  const [isActive, setIsActive] = useState(profile.isActive);

  const patchMut = useMutation({
    mutationFn: (body: object) => api(`/api/scan-fingerprints/${profile.id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orch-fingerprints"] }); toast({ title: "Profile updated" }); onClose(); },
    onError: (e: Error) => toast({ title: "Update failed", description: e.message, variant: "destructive" }),
  });

  return (
    <Dialog open onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader><DialogTitle>Edit: {profile.name}</DialogTitle></DialogHeader>
        <div className="space-y-3 py-2">
          <div className="flex items-center gap-3">
            <Switch checked={isActive} onCheckedChange={setIsActive} id="active-toggle" />
            <Label htmlFor="active-toggle">Active (used in rotation)</Label>
          </div>
          <p className="text-xs text-muted-foreground">Edit header values below. Empty values omit the header.</p>
          <div className="space-y-2.5">
            {ALL_HEADER_KEYS.map(key => (
              <div key={key} className="grid grid-cols-[180px_1fr] gap-2 items-center">
                <Label className="text-xs font-mono">{key}</Label>
                <Input className="text-xs font-mono h-8" value={headers[key] ?? ""} placeholder="(omitted)"
                  onChange={e => setHeaders(h => ({ ...h, [key]: e.target.value }))} />
              </div>
            ))}
          </div>
        </div>
        <DialogFooter className="gap-2">
          <Button variant="outline" className="mr-auto text-xs" onClick={() => {
            const d = FINGERPRINT_DEFAULTS[profile.name];
            if (d) setHeaders(d); else toast({ title: "No default for this profile", variant: "destructive" });
          }}>Reset to Default</Button>
          <Button variant="ghost" onClick={onClose} disabled={patchMut.isPending}>Cancel</Button>
          <Button onClick={() => patchMut.mutate({ headers, isActive })} disabled={patchMut.isPending}>
            {patchMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            Save Changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function FingerprintsTab() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const [expanded, setExpanded]     = useState<number | null>(null);
  const [editProfile, setEditProfile] = useState<FingerprintProfile | null>(null);

  const { data: profiles = [], isLoading } = useQuery<FingerprintProfile[]>({
    queryKey: ["orch-fingerprints"],
    queryFn: () => api("/api/scan-fingerprints"),
  });

  const activeCount = profiles.filter(p => p.isActive).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1.5 px-3 py-1">
          <Check className="w-3.5 h-3.5" />{activeCount} Active
        </Badge>
        <Badge variant="outline" className="bg-muted text-muted-foreground gap-1.5 px-3 py-1">
          {profiles.length - activeCount} Inactive
        </Badge>
        <p className="text-xs text-muted-foreground ml-auto">
          {isSuperAdmin ? "Click a row to expand headers. Use the edit button to modify." : "Click a row to expand headers."}
        </p>
      </div>

      <div className="rounded-xl border bg-card overflow-hidden">
        {isLoading ? Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="px-4 py-3 border-b last:border-0 flex items-center gap-3">
            <Skeleton className="w-6 h-6 rounded" />
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-5 w-16 ml-auto" />
          </div>
        )) : profiles.length === 0 ? (
          <div className="px-4 py-10 text-center text-sm text-muted-foreground">No fingerprint profiles found.</div>
        ) : profiles.map(profile => {
          const isOpen = expanded === profile.id;
          const n = profile.name.toLowerCase();
          const ProfileIcon = (n.includes("mobile") || n.includes("android") || n.includes("ios"))
            ? Smartphone : n.includes("safari") && n.includes("mac") ? Globe : Monitor;

          return (
            <div key={profile.id} className="border-b last:border-0">
              <div className="px-4 py-3 flex items-center gap-3 cursor-pointer hover:bg-muted/30 transition-colors"
                onClick={() => setExpanded(isOpen ? null : profile.id)}>
                <ProfileIcon className="w-4 h-4 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium">{profile.name}</p>
                  <p className="text-xs text-muted-foreground">{Object.keys(profile.headers ?? {}).length} headers defined</p>
                </div>
                <div className="flex items-center gap-2">
                  {profile.isActive
                    ? <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1 text-xs"><Check className="w-3 h-3" />Active</Badge>
                    : <Badge variant="outline" className="bg-muted text-muted-foreground gap-1 text-xs"><X className="w-3 h-3" />Inactive</Badge>}
                  {isSuperAdmin && (
                    <Button variant="ghost" size="icon" className="w-7 h-7" onClick={e => { e.stopPropagation(); setEditProfile(profile); }}>
                      <Pencil className="w-3.5 h-3.5" />
                    </Button>
                  )}
                  {isOpen ? <ChevronDown className="w-4 h-4 text-muted-foreground" /> : <ChevronRight className="w-4 h-4 text-muted-foreground" />}
                </div>
              </div>
              {isOpen && (
                <div className="px-4 pb-4 pt-1 bg-muted/20">
                  <div className="rounded-lg border overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="border-b bg-muted/50">
                          <th className="px-3 py-2 text-left font-semibold text-muted-foreground">Header</th>
                          <th className="px-3 py-2 text-left font-semibold text-muted-foreground">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(profile.headers ?? {}).map(([key, val]) => (
                          <tr key={key} className="border-b last:border-0 hover:bg-muted/30">
                            <td className="px-3 py-1.5 font-mono text-primary/80 whitespace-nowrap">{key}</td>
                            <td className="px-3 py-1.5 font-mono text-muted-foreground break-all">{val}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
      {editProfile && <FingerprintEditDialog profile={editProfile} onClose={() => setEditProfile(null)} />}
    </div>
  );
}

/* ─── TAB 4: Config ──────────────────────────────────────────────────── */
interface KnobDef {
  key: string; label: string; description: string;
  type: "boolean" | "integer" | "select"; options?: string[]; min?: number; max?: number;
  defaultValue?: string;
}

const KNOBS: KnobDef[] = [
  { key: "enabled",                 type: "boolean", label: "Enable Orchestration Engine",   description: "Master switch. When off, orchestratedFetch falls back to direct fetch." },
  { key: "use_proxies",             type: "boolean", label: "Use Proxy Pool",                description: "Route outbound scan requests through the configured proxy/IP pool." },
  { key: "require_proxies",         type: "boolean", label: "Require Proxies",               description: "When enabled, scans that cannot route through a proxy will abort instead of falling back to a direct connection.", defaultValue: "false" },
  { key: "rotate_fingerprints",     type: "boolean", label: "Rotate Browser Fingerprints",   description: "Cycle through active fingerprint profiles on each request." },
  { key: "adaptive_rate_limit",     type: "boolean", label: "Adaptive Rate Limiting",        description: "Dynamically throttle per-host request rate when 429/503 responses are observed." },
  { key: "proxy_health_scoring",    type: "boolean", label: "Enable Proxy Health Scoring",   description: "Track success rate and latency per proxy; weight selection accordingly." },
  { key: "circuit_breaker_enabled", type: "boolean", label: "Enable Circuit Breakers",       description: "Open circuit for a host after repeated failures; auto-closes after cool-down period." },
  { key: "log_all_requests",        type: "boolean", label: "Log All Requests to Telemetry", description: "Write every HTTP request to the telemetry table. Disable to reduce DB writes." },
  { key: "proxy_rotation_strategy", type: "select",  label: "Proxy Rotation Strategy",       description: "Algorithm used to pick the next proxy from the pool.", options: ["round-robin", "healthiest-first", "random"] },
  { key: "resolver_rotation_strategy", type: "select", label: "DNS Resolver Rotation",       description: "Algorithm used to select a DNS resolver from the pool.", options: ["round-robin", "random", "failover"] },
  { key: "fingerprint_rotation_strategy", type: "select", label: "Browser Profile Rotation", description: "How browser fingerprint profiles are cycled across requests.", options: ["round-robin", "random"] },
  { key: "scan_delay_intensity",    type: "select",  label: "Scan Delay Intensity",          description: "Inter-request delay profile — passive (300–900 ms) is stealthiest.", options: ["passive", "endpoint-discovery", "dir-fuzzing", "heavy-enumeration", "vuln-scan"] },
  { key: "max_requests_per_host",   type: "integer", label: "Max Requests per Host",         description: "Total request cap per target hostname per scan run.", min: 1, max: 100000 },
  { key: "max_requests_per_proxy",  type: "integer", label: "Max Requests per Proxy",        description: "Maximum requests routed through one proxy before rotating.", min: 1, max: 10000 },
  { key: "max_concurrent_requests", type: "integer", label: "Max Concurrent Requests",       description: "Global concurrency cap across all proxies and target hosts.", min: 1, max: 500 },
  { key: "proxy_health_threshold",  type: "integer", label: "Health Score Threshold",        description: "Minimum proxy health score (0–100) to stay active.", min: 0, max: 100 },
  { key: "proxy_cooldown_minutes",  type: "integer", label: "Cooldown Duration (min)",       description: "Minutes a proxy stays in cooldown after falling below health threshold.", min: 1, max: 1440 },
  { key: "retry_base_delay_ms",     type: "integer", label: "Retry Base Delay (ms)",         description: "Initial delay before the first retry; doubles each subsequent attempt.", min: 100, max: 10000 },
  { key: "max_retries",             type: "integer", label: "Max Retries per Request",       description: "Number of retry attempts before giving up on a request.", min: 0, max: 10 },
  { key: "max_backoff_ms",          type: "integer", label: "Max Backoff (ms)",              description: "Upper bound on exponential retry backoff delay between attempts.", min: 500, max: 60000 },
];

function ConfigTab() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const isAdminOrSA = user?.role === "super_admin" || user?.role === "admin";
  const [values, setValues] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);

  const { data, isLoading } = useQuery<{ config: Record<string, string> }>({
    queryKey: ["orch-config"],
    queryFn: () => api("/api/orchestrator-config"),
    enabled: isAdminOrSA,
  });

  useEffect(() => {
    if (data?.config) { setValues(data.config); setDirty(false); }
  }, [data]);

  const saveMut = useMutation({
    mutationFn: (updates: Record<string, string>) =>
      api("/api/orchestrator-config", { method: "PATCH", body: JSON.stringify(updates) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orch-config"] }); toast({ title: "Configuration saved", description: "Changes take effect within 60 seconds." }); setDirty(false); },
    onError: (e: Error) => toast({ title: "Save failed", description: e.message, variant: "destructive" }),
  });

  const set = (key: string, val: string) => { setValues(v => ({ ...v, [key]: val })); setDirty(true); };

  const renderKnob = (k: KnobDef) => {
    const val = values[k.key] ?? k.defaultValue ?? "";
    if (k.type === "boolean") {
      return <Switch checked={val !== "false"} onCheckedChange={v => set(k.key, v ? "true" : "false")} />;
    }
    if (k.type === "select") {
      return (
        <Select value={val} onValueChange={v => set(k.key, v)}>
          <SelectTrigger className="w-44"><SelectValue placeholder="Select…" /></SelectTrigger>
          <SelectContent>{k.options!.map(o => <SelectItem key={o} value={o}>{o}</SelectItem>)}</SelectContent>
        </Select>
      );
    }
    return <Input type="number" className="w-36 h-8 text-sm" value={val} min={k.min} max={k.max} onChange={e => set(k.key, e.target.value)} />;
  };

  const boolKnobs  = KNOBS.filter(k => k.type === "boolean");
  const otherKnobs = KNOBS.filter(k => k.type !== "boolean");

  return (
    <div className="space-y-5">
      {/* Save bar */}
      <div className="flex items-center gap-3 justify-between">
        <div>
          {dirty ? (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-700 dark:text-amber-400">
              <Info className="w-3.5 h-3.5 shrink-0" /> Unsaved changes — click Save to apply.
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">Changes are applied within 60 seconds of saving.</p>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["orch-config"] })} className="gap-1.5">
            <RefreshCw className="w-3.5 h-3.5" />Reload
          </Button>
          <Button size="sm" onClick={() => saveMut.mutate(values)} disabled={!dirty || saveMut.isPending} className="gap-1.5">
            {saveMut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
            Save Changes
          </Button>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Left: Feature Toggles */}
        <div className="rounded-xl border bg-card p-5 space-y-1">
          <h2 className="text-sm font-semibold mb-4">Feature Toggles</h2>
          {isLoading ? Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between py-2.5">
              <Skeleton className="h-4 w-48" /><Skeleton className="h-6 w-10 rounded-full" />
            </div>
          )) : boolKnobs.map((k, idx) => (
            <div key={k.key} className={cn("flex items-center justify-between gap-4 py-2.5", idx < boolKnobs.length - 1 && "border-b border-border/50")}>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <Label className="text-sm font-medium">{k.label}</Label>
                  <UITooltip>
                    <TooltipTrigger asChild><Info className="w-3.5 h-3.5 text-muted-foreground cursor-help shrink-0" /></TooltipTrigger>
                    <TooltipContent className="max-w-xs text-xs">{k.description}</TooltipContent>
                  </UITooltip>
                </div>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">{k.key}</p>
              </div>
              {renderKnob(k)}
            </div>
          ))}
        </div>

        {/* Right: Parameters & Strategies */}
        <div className="rounded-xl border bg-card p-5 space-y-1">
          <h2 className="text-sm font-semibold mb-4">Parameters &amp; Strategies</h2>
          {isLoading ? Array.from({ length: 11 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between py-2.5">
              <Skeleton className="h-4 w-52" /><Skeleton className="h-8 w-36 rounded" />
            </div>
          )) : otherKnobs.map((k, idx) => (
            <div key={k.key} className={cn("flex items-center justify-between gap-4 py-2.5", idx < otherKnobs.length - 1 && "border-b border-border/50")}>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <Label className="text-sm font-medium">{k.label}</Label>
                  <UITooltip>
                    <TooltipTrigger asChild><Info className="w-3.5 h-3.5 text-muted-foreground cursor-help shrink-0" /></TooltipTrigger>
                    <TooltipContent className="max-w-xs text-xs">{k.description}</TooltipContent>
                  </UITooltip>
                </div>
                <p className="text-xs text-muted-foreground font-mono mt-0.5">{k.key}{k.min != null ? ` (${k.min}–${k.max})` : ""}</p>
              </div>
              {renderKnob(k)}
            </div>
          ))}

          <div className="rounded-lg bg-blue-500/5 border border-blue-500/20 px-3 py-2.5 text-xs text-muted-foreground mt-4">
            <strong className="text-foreground">Note:</strong> Config reloads every 60 seconds — changes take effect within one minute.
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── TAB 5: Telemetry Log ───────────────────────────────────────────── */
function buildQs(p: { page: number; proxyIp: string; host: string; dateFrom: string; dateTo: string; status: string; waf: boolean; captcha: boolean }) {
  const q = new URLSearchParams({ page: String(p.page), limit: "50" });
  if (p.proxyIp)  q.set("proxyIp",  p.proxyIp);
  if (p.host)     q.set("host",     p.host);
  if (p.dateFrom) q.set("dateFrom", p.dateFrom);
  if (p.dateTo)   q.set("dateTo",   p.dateTo);
  if (p.status !== "all") q.set("status", p.status);
  if (p.waf)     q.set("waf",     "1");
  if (p.captcha) q.set("captcha", "1");
  return q.toString();
}

function exportCsv(rows: TelemetryRow[]) {
  const cols: Array<keyof TelemetryRow> = ["createdAt","method","url","proxyIp","fingerprintProfileId","statusCode","latencyMs","retries","delayMs","backoffMs","wafDetected","captchaDetected","bytesDownloaded"];
  const header = cols.join(",");
  const lines = rows.map(r => cols.map(c => { const v = r[c]; if (typeof v === "string" && (v.includes(",") || v.includes('"'))) return `"${v.replace(/"/g, '""')}"`;  return v ?? ""; }).join(","));
  const blob = new Blob([header + "\n" + lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = `scan-telemetry-${new Date().toISOString().slice(0,10)}.csv`; a.click();
  URL.revokeObjectURL(url);
}

function TelemetryLogTab() {
  const [page, setPage]                   = useState(1);
  const [filterHost, setFilterHost]       = useState("");
  const [filterProxyIp, setFilterProxyIp] = useState("");
  const [filterStatus, setFilterStatus]   = useState("all");
  const [filterWaf, setFilterWaf]         = useState(false);
  const [filterCaptcha, setFilterCaptcha] = useState(false);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo]     = useState("");

  const qs = buildQs({ page, proxyIp: filterProxyIp, host: filterHost, dateFrom, dateTo, status: filterStatus, waf: filterWaf, captcha: filterCaptcha });

  const { data, isLoading, refetch, isFetching } = useQuery<TelemetryResponse>({
    queryKey: ["orch-telemetry-log", qs],
    queryFn: () => api(`/api/scan-telemetry?${qs}`),
    refetchInterval: 15_000,
  });

  const rows  = data?.rows ?? [];
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / 50));
  const hasFilters = !!(filterHost || filterProxyIp || filterStatus !== "all" || filterWaf || filterCaptcha || dateFrom || dateTo);

  const clearFilters = () => {
    setFilterHost(""); setFilterProxyIp(""); setFilterStatus("all");
    setFilterWaf(false); setFilterCaptcha(false); setDateFrom(""); setDateTo(""); setPage(1);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <p className="text-sm text-muted-foreground">{total.toLocaleString()} total records (server-filtered)</p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportCsv(rows)} className="gap-1.5" disabled={rows.length === 0}>
            <Download className="w-3.5 h-3.5" />Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5" disabled={isFetching}>
            {isFetching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}Refresh
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="rounded-xl border bg-card p-3 space-y-2.5">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs w-52" placeholder="Filter by target host…"
              value={filterHost} onChange={e => { setFilterHost(e.target.value); setPage(1); }} />
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs w-36" placeholder="Proxy IP…"
              value={filterProxyIp} onChange={e => { setFilterProxyIp(e.target.value); setPage(1); }} />
          </div>
          <Select value={filterStatus} onValueChange={v => { setFilterStatus(v); setPage(1); }}>
            <SelectTrigger className="h-8 w-36 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="2xx">2xx Success</SelectItem>
              <SelectItem value="4xx">4xx Client Error</SelectItem>
              <SelectItem value="403">403 Forbidden</SelectItem>
              <SelectItem value="429">429 Rate Limited</SelectItem>
              <SelectItem value="5xx">5xx Server Error</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex items-center gap-2">
            <Switch id="waf-f" checked={filterWaf} onCheckedChange={setFilterWaf} />
            <Label htmlFor="waf-f" className="text-xs cursor-pointer">WAF only</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="cap-f" checked={filterCaptcha} onCheckedChange={setFilterCaptcha} />
            <Label htmlFor="cap-f" className="text-xs cursor-pointer">Captcha only</Label>
          </div>
          {hasFilters && <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={clearFilters}>Clear</Button>}
          <span className="ml-auto text-xs text-muted-foreground">{rows.length} shown (page {page})</span>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-muted-foreground w-12 shrink-0">From:</span>
          <Input type="datetime-local" className="h-8 text-xs w-52" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1); }} />
          <span className="text-xs text-muted-foreground">To:</span>
          <Input type="datetime-local" className="h-8 text-xs w-52" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1); }} />
          {(dateFrom || dateTo) && <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setDateFrom(""); setDateTo(""); setPage(1); }}>Clear dates</Button>}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/40 text-muted-foreground">
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Timestamp</th>
                <th className="px-3 py-2.5 text-left font-medium">Method</th>
                <th className="px-3 py-2.5 text-left font-medium">Target</th>
                <th className="px-3 py-2.5 text-left font-medium">URL (truncated)</th>
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Proxy IP</th>
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Fingerprint</th>
                <th className="px-3 py-2.5 text-right font-medium">Status</th>
                <th className="px-3 py-2.5 text-right font-medium">Latency</th>
                <th className="px-3 py-2.5 text-right font-medium">Retries</th>
                <th className="px-3 py-2.5 text-center font-medium">WAF</th>
                <th className="px-3 py-2.5 text-center font-medium">Captcha</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? Array.from({ length: 10 }).map((_, i) => (
                <tr key={i} className="border-b">
                  {Array.from({ length: 11 }).map((__, j) => (
                    <td key={j} className="px-3 py-2"><Skeleton className="h-3.5 w-full" /></td>
                  ))}
                </tr>
              )) : rows.length === 0 ? (
                <tr>
                  <td colSpan={11} className="px-3 py-12 text-center text-muted-foreground">
                    {total === 0 ? "No telemetry yet — records appear once scans run." : "No records match the current filters."}
                  </td>
                </tr>
              ) : rows.map(row => {
                let domain = row.url;
                try { domain = new URL(row.url).hostname; } catch { domain = row.url.split("/")[0] ?? row.url; }
                let truncUrl = row.url.slice(0, 80);
                try { const u = new URL(row.url); const p = u.pathname.length > 60 ? u.pathname.slice(0, 57) + "…" : u.pathname; truncUrl = u.search ? p + u.search.slice(0, 20) + "…" : p; } catch { /* ignore */ }
                return (
                  <tr key={row.id} className={cn("border-b last:border-0 hover:bg-muted/30 transition-colors", row.wafDetected && "bg-red-500/5")}>
                    <td className="px-3 py-2 whitespace-nowrap font-mono text-muted-foreground">{new Date(row.createdAt).toLocaleString()}</td>
                    <td className="px-3 py-2"><Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0">{row.method}</Badge></td>
                    <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">
                      <button className="hover:underline text-left" onClick={() => { setFilterHost(domain); setPage(1); }}>{domain}</button>
                    </td>
                    <td className="px-3 py-2 max-w-xs truncate font-mono text-muted-foreground text-[11px]" title={row.url}>{truncUrl}</td>
                    <td className="px-3 py-2 font-mono whitespace-nowrap">
                      {row.proxyIp
                        ? <button className="text-blue-500 hover:underline" onClick={() => { setFilterProxyIp(row.proxyIp!); setPage(1); }}>{row.proxyIp}</button>
                        : <span className="text-muted-foreground/50">direct</span>}
                    </td>
                    <td className="px-3 py-2">
                      {row.fingerprintProfileId != null
                        ? <Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0">#{row.fingerprintProfileId}</Badge>
                        : <span className="text-muted-foreground/50">—</span>}
                    </td>
                    <td className="px-3 py-2 text-right"><StatusCode code={row.statusCode} /></td>
                    <td className="px-3 py-2 text-right text-muted-foreground">{row.latencyMs != null ? `${row.latencyMs}ms` : "—"}</td>
                    <td className="px-3 py-2 text-right">{row.retries > 0 ? <span className="text-amber-500 font-semibold">{row.retries}</span> : <span className="text-muted-foreground">0</span>}</td>
                    <td className="px-3 py-2 text-center">{row.wafDetected ? <Shield className="w-3.5 h-3.5 text-red-500 mx-auto" /> : <span className="text-muted-foreground/30">—</span>}</td>
                    <td className="px-3 py-2 text-center">{row.captchaDetected ? <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mx-auto" /> : <span className="text-muted-foreground/30">—</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {pages > 1 && (
          <div className="px-4 py-3 border-t flex items-center justify-between bg-muted/20">
            <span className="text-xs text-muted-foreground">Page {page} of {pages} · {total.toLocaleString()} records</span>
            <div className="flex gap-1.5">
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Previous</Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= pages} onClick={() => setPage(p => Math.min(pages, p + 1))}>Next</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── WAF Dashboard Tab ───────────────────────────────────────────────── */
interface WafDayPoint {
  date: string; totalRequests: number; wafHits: number;
  bypassSuccesses: number; captchaHits: number; directSuccesses: number;
  bypassRate: number | null; wafRate: number;
}
interface WafHostRow {
  hostname: string; totalRequests: number; wafHits: number;
  bypassSuccesses: number; captchaHits: number; directSuccesses: number;
  bypassRate: number | null; wafRate: number;
}
interface WafStatsResp {
  days: number; sinceDate: string;
  totals: WafDayPoint & { bypassRate: number | null; wafRate: number };
  trend: WafDayPoint[];
  hostSummary: WafHostRow[];
}

function WafDashboardTab() {
  const [days, setDays] = useState(30);
  const { data, isLoading, refetch } = useQuery<WafStatsResp>({
    queryKey: ["waf-bypass-stats", days],
    queryFn: () => api(`/api/waf-bypass-stats?days=${days}`),
  });

  const trend   = data?.trend ?? [];
  const hosts   = data?.hostSummary ?? [];
  const totals  = data?.totals;

  return (
    <div className="space-y-5">
      {/* Controls */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="font-semibold text-base">WAF Bypass Dashboard</h2>
          <p className="text-xs text-muted-foreground mt-0.5">Real observed WAF detection and bypass outcomes from the scan orchestrator</p>
        </div>
        <div className="flex items-center gap-2">
          <Select value={String(days)} onValueChange={v => setDays(Number(v))}>
            <SelectTrigger className="h-8 text-xs w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="14">Last 14 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </Button>
        </div>
      </div>

      {/* Summary tiles */}
      {totals && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Total Requests",    value: totals.totalRequests.toLocaleString(), color: "text-foreground" },
            { label: "WAF Hits",          value: totals.wafHits.toLocaleString(),       color: "text-red-500" },
            { label: "Bypass Successes",  value: totals.bypassSuccesses.toLocaleString(), color: "text-emerald-500" },
            { label: "Captcha Hits",      value: totals.captchaHits.toLocaleString(),   color: "text-amber-500" },
            { label: "Bypass Rate",       value: totals.bypassRate != null ? `${totals.bypassRate}%` : "—", color: "text-blue-500" },
          ].map(s => (
            <div key={s.label} className="border rounded-lg p-3">
              <div className={cn("text-xl font-bold tabular-nums", s.color)}>{s.value}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Trend chart */}
      {isLoading ? (
        <Skeleton className="h-56 w-full" />
      ) : trend.length === 0 ? (
        <div className="border rounded-lg p-8 text-center text-muted-foreground text-sm">
          No WAF stats yet — run scans to populate data
        </div>
      ) : (
        <div className="border rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">WAF Hit Rate &amp; Bypass Rate — daily trend</h3>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trend} margin={{ top: 4, right: 12, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--muted))" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis tickFormatter={v => `${v}%`} tick={{ fontSize: 11 }} />
              <Tooltip formatter={(v: number) => `${v}%`} />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Line dataKey="wafRate"    name="WAF Hit %"    stroke="#ef4444" dot={false} strokeWidth={1.5} />
              <Line dataKey="bypassRate" name="Bypass Rate %" stroke="#10b981" dot={false} strokeWidth={1.5} connectNulls />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Per-hostname table */}
      {hosts.length > 0 && (
        <div className="border rounded-lg overflow-hidden">
          <div className="px-4 py-2.5 border-b bg-muted/30">
            <span className="text-sm font-medium">By Hostname</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-muted-foreground bg-muted/20 border-b">
                  <th className="px-3 py-2 text-left">Hostname</th>
                  <th className="px-3 py-2 text-right">Requests</th>
                  <th className="px-3 py-2 text-right">WAF Hits</th>
                  <th className="px-3 py-2 text-right">WAF %</th>
                  <th className="px-3 py-2 text-right">Bypass</th>
                  <th className="px-3 py-2 text-right">Bypass %</th>
                  <th className="px-3 py-2 text-right">Captcha</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map(h => (
                  <tr key={h.hostname} className="border-b last:border-b-0 hover:bg-muted/10 transition-colors">
                    <td className="px-3 py-2 font-mono text-xs">{h.hostname}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{h.totalRequests.toLocaleString()}</td>
                    <td className="px-3 py-2 text-right tabular-nums text-red-500">{h.wafHits}</td>
                    <td className="px-3 py-2 text-right tabular-nums">{h.wafRate}%</td>
                    <td className="px-3 py-2 text-right tabular-nums text-emerald-500">{h.bypassSuccesses}</td>
                    <td className="px-3 py-2 text-right tabular-nums">
                      {h.bypassRate != null ? (
                        <span className={cn("font-medium", h.bypassRate >= 60 ? "text-emerald-500" : h.bypassRate >= 30 ? "text-amber-500" : "text-red-500")}>
                          {h.bypassRate}%
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-amber-500">{h.captchaHits}</td>
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

/* ─── Dry-Run Test Tab ───────────────────────────────────────────────── */
interface DryRunResult {
  url: string; hostname: string; statusCode: number | null; latencyMs: number;
  wafDetected: boolean; bypassSuccess: boolean; retries: number; error: string | null;
  responseHeaders: Record<string, string>; bodyExcerpt: string;
  proxyUsed: boolean; profileUsed: number | null; circuitBreakerState: string | null;
  historicalBypassRate: number | null; historicalWafHits: number;
  testedAt: string;
}

function DryRunTab() {
  const { toast } = useToast();
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<DryRunResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [showHeaders, setShowHeaders] = useState(false);
  const [showBody, setShowBody] = useState(false);

  async function runTest() {
    if (!url.trim()) { toast({ title: "URL required", variant: "destructive" }); return; }
    setLoading(true); setResult(null);
    try {
      const r = await api<DryRunResult>("/api/orchestrator/test-bypass", {
        method: "POST",
        body: JSON.stringify({ url: url.trim() }),
      });
      setResult(r);
    } catch (e: any) {
      toast({ title: "Test failed", description: e.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }

  const statusConfig = result ? (
    result.error
      ? { label: "Request Error",  icon: X,       color: "text-red-500",     bg: "bg-red-500/10",     border: "border-red-500/20"    }
      : result.wafDetected && !result.bypassSuccess
      ? { label: "WAF Blocked",    icon: ShieldX,  color: "text-amber-500",  bg: "bg-amber-500/10",   border: "border-amber-500/20"  }
      : result.wafDetected && result.bypassSuccess
      ? { label: "Bypassed WAF",   icon: Shield,   color: "text-blue-500",   bg: "bg-blue-500/10",    border: "border-blue-500/20"   }
      : { label: "Clean Success",  icon: Check,    color: "text-emerald-500", bg: "bg-emerald-500/10", border: "border-emerald-500/20" }
  ) : null;

  return (
    <div className="space-y-6 w-full">
      {/* Header */}
      <div>
        <h2 className="font-semibold text-base">Dry-Run Bypass Test</h2>
        <p className="text-xs text-muted-foreground mt-0.5">
          Send a real HTTP request through the full orchestrator stack — proxy routing, fingerprint selection,
          WAF detection — without creating scans or findings.
        </p>
      </div>

      {/* Input card — full width */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-end gap-3">
          <div className="flex-1 space-y-1.5">
            <Label className="text-sm font-medium">Target URL</Label>
            <Input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && runTest()}
              placeholder="https://example.com or example.com"
              className="font-mono text-sm h-10"
            />
          </div>
          <Button onClick={runTest} disabled={loading} size="default" className="h-10 px-6 shrink-0">
            {loading ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <TestTube2 className="w-4 h-4 mr-2" />}
            {loading ? "Testing…" : "Run Test"}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground mt-2.5">
          Real request sent through your configured orchestrator (proxy pool, fingerprint rotation, WAF bypass). No scans or findings are created.
        </p>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="rounded-xl border border-border bg-card p-8 flex flex-col items-center justify-center gap-3 text-sm text-muted-foreground">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <div className="text-center">
            <p className="font-medium text-foreground">Sending request through orchestrator…</p>
            <p className="text-xs mt-0.5">Selecting proxy, rotating fingerprint, detecting WAF…</p>
          </div>
        </div>
      )}

      {/* Results — full width 2-column layout */}
      {result && statusConfig && (
        <div className="space-y-4">
          {/* Status banner */}
          <div className={cn("rounded-xl border p-4 flex items-center justify-between flex-wrap gap-3", statusConfig.bg, statusConfig.border)}>
            <div className="flex items-center gap-3">
              <div className={cn("w-10 h-10 rounded-full flex items-center justify-center border", statusConfig.bg, statusConfig.border)}>
                <statusConfig.icon className={cn("w-5 h-5", statusConfig.color)} />
              </div>
              <div>
                <p className={cn("font-bold text-base", statusConfig.color)}>{statusConfig.label}</p>
                <p className="text-xs text-muted-foreground">Tested {new Date(result.testedAt).toLocaleString()} · {result.hostname}</p>
              </div>
            </div>
            <div className="flex items-center gap-4 text-sm">
              {result.statusCode != null && (
                <div className="text-center">
                  <p className={cn("text-xl font-bold font-mono", result.statusCode < 400 ? "text-emerald-500" : "text-red-500")}>
                    {result.statusCode}
                  </p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">HTTP</p>
                </div>
              )}
              <div className="text-center">
                <p className="text-xl font-bold">{result.latencyMs}</p>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide">ms</p>
              </div>
              {result.retries > 0 && (
                <div className="text-center">
                  <p className="text-xl font-bold">{result.retries}</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">retr{result.retries === 1 ? "y" : "ies"}</p>
                </div>
              )}
            </div>
          </div>

          {/* Detail grid — 6 cards full width */}
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
            {[
              { label: "Hostname",              value: result.hostname },
              { label: "Proxy Used",            value: result.proxyUsed ? "Yes" : "No" },
              { label: "Profile Used",          value: result.profileUsed != null ? `#${result.profileUsed}` : "None" },
              { label: "Circuit Breaker",       value: result.circuitBreakerState ?? "—" },
              { label: "WAF Hits (7d)",         value: String(result.historicalWafHits) },
              { label: "Bypass Rate (7d)",      value: result.historicalBypassRate != null ? `${result.historicalBypassRate}%` : "—" },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl border border-border bg-card px-4 py-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">{label}</p>
                <p className="font-semibold text-sm truncate">{value}</p>
              </div>
            ))}
          </div>

          {/* Two-column: headers + body */}
          {(Object.keys(result.responseHeaders).length > 0 || result.bodyExcerpt || result.error) && (
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              {/* Response Headers */}
              {Object.keys(result.responseHeaders).length > 0 && (
                <div className="rounded-xl border border-border bg-card overflow-hidden">
                  <button
                    onClick={() => setShowHeaders(h => !h)}
                    className="w-full px-4 py-3 text-xs font-semibold text-left flex items-center gap-2 hover:bg-muted/30 transition-colors border-b border-border"
                  >
                    {showHeaders ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Response Headers
                    <span className="ml-auto bg-muted text-muted-foreground text-[10px] px-1.5 py-0.5 rounded-full font-bold">
                      {Object.keys(result.responseHeaders).length}
                    </span>
                  </button>
                  {showHeaders && (
                    <div className="p-4 space-y-1.5 text-xs font-mono max-h-64 overflow-y-auto">
                      {Object.entries(result.responseHeaders).map(([k, v]) => (
                        <div key={k} className="flex gap-2 overflow-hidden">
                          <span className="text-muted-foreground shrink-0 min-w-0">{k}:</span>
                          <span className="truncate text-foreground/80">{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Body excerpt */}
              {result.bodyExcerpt && (
                <div className="rounded-xl border border-border bg-card overflow-hidden">
                  <button
                    onClick={() => setShowBody(b => !b)}
                    className="w-full px-4 py-3 text-xs font-semibold text-left flex items-center gap-2 hover:bg-muted/30 transition-colors border-b border-border"
                  >
                    {showBody ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                    Response Body (first 600 chars)
                  </button>
                  {showBody && (
                    <pre className="p-4 text-xs font-mono whitespace-pre-wrap break-all text-muted-foreground max-h-64 overflow-y-auto">
                      {result.bodyExcerpt}
                    </pre>
                  )}
                </div>
              )}

              {/* Error */}
              {result.error && (
                <div className="rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-xs text-red-400 font-mono col-span-full">
                  {result.error}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── A/B Profiles Tab ───────────────────────────────────────────────── */
interface ProfileStatRow {
  profileId: number; name: string; isActive: boolean;
  totalUses: number; successes: number; wafBlocked: number;
  lastUsedAt: string | null; successRate: number | null;
  wafBlockRate: number | null; ucb1Score: number | null;
  status: "untested" | "excellent" | "good" | "poor";
}
interface ProfileStatsResp { profiles: ProfileStatRow[]; totalUses: number; }

function AbProfilesTab() {
  const { data, isLoading, refetch } = useQuery<ProfileStatsResp>({
    queryKey: ["fingerprint-profile-stats"],
    queryFn: () => api("/api/fingerprint-profile-stats"),
    refetchInterval: 60_000,
  });

  const profiles = data?.profiles ?? [];

  const statusBadge = (s: ProfileStatRow["status"]) => {
    const map: Record<string, string> = {
      untested: "bg-muted text-muted-foreground",
      excellent: "bg-emerald-500/15 text-emerald-600",
      good:      "bg-blue-500/15 text-blue-600",
      poor:      "bg-red-500/15 text-red-600",
    };
    return (
      <span className={cn("text-xs px-2 py-0.5 rounded-full font-medium capitalize", map[s] ?? map.untested)}>
        {s}
      </span>
    );
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="font-semibold text-base">A/B Profile Performance</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            UCB1 bandit scores — the orchestrator auto-selects the best-performing fingerprint profile
            for each request, balancing exploitation and exploration (10% random)
          </p>
        </div>
        <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => refetch()}>
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12 w-full" />)}</div>
      ) : profiles.length === 0 ? (
        <div className="border rounded-lg p-8 text-center text-muted-foreground text-sm">
          No fingerprint profiles found — add profiles in the Fingerprints tab
        </div>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-muted-foreground bg-muted/20 border-b">
                  <th className="px-3 py-2 text-left">Profile</th>
                  <th className="px-3 py-2 text-center">Status</th>
                  <th className="px-3 py-2 text-right">Total Uses</th>
                  <th className="px-3 py-2 text-right">Success Rate</th>
                  <th className="px-3 py-2 text-right">WAF Block Rate</th>
                  <th className="px-3 py-2 text-right">UCB1 Score</th>
                  <th className="px-3 py-2 text-left">Last Used</th>
                </tr>
              </thead>
              <tbody>
                {profiles.map(p => (
                  <tr key={p.profileId} className="border-b last:border-b-0 hover:bg-muted/10 transition-colors">
                    <td className="px-3 py-2.5">
                      <div className="font-medium">{p.name}</div>
                      <div className="text-xs text-muted-foreground">#{p.profileId} · {p.isActive ? "Active" : "Inactive"}</div>
                    </td>
                    <td className="px-3 py-2.5 text-center">{statusBadge(p.status)}</td>
                    <td className="px-3 py-2.5 text-right tabular-nums">{p.totalUses.toLocaleString()}</td>
                    <td className="px-3 py-2.5 text-right tabular-nums">
                      {p.successRate != null ? (
                        <span className={cn("font-medium", p.successRate >= 80 ? "text-emerald-500" : p.successRate >= 50 ? "text-amber-500" : "text-red-500")}>
                          {p.successRate}%
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums">
                      {p.wafBlockRate != null ? (
                        <span className={cn("font-medium", p.wafBlockRate <= 5 ? "text-emerald-500" : p.wafBlockRate <= 20 ? "text-amber-500" : "text-red-500")}>
                          {p.wafBlockRate}%
                        </span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="px-3 py-2.5 text-right tabular-nums font-mono text-xs">
                      {p.ucb1Score != null
                        ? <span className="font-bold text-blue-500">{p.ucb1Score.toFixed(3)}</span>
                        : <span className="text-emerald-500 font-bold">∞</span>}
                    </td>
                    <td className="px-3 py-2.5 text-xs text-muted-foreground">
                      {p.lastUsedAt ? new Date(p.lastUsedAt).toLocaleString() : "Never"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="px-4 py-2 border-t bg-muted/20 text-xs text-muted-foreground">
            UCB1 = success_rate + √2 × √(ln(N) / uses). Profiles with ∞ score (untested) are always explored first.
            N = {(data?.totalUses ?? 0).toLocaleString()} total requests.
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Auto-Tuner Tab ─────────────────────────────────────────────────── */
interface TuningLogRow {
  id: number; tenantId: number; action: string; oldValue: string | null;
  newValue: string | null; reason: string; wafRatePct: number | null;
  windowHours: number | null; createdAt: string;
}
interface TunerStatusResp {
  currentMultiplier: number; currentBypassStrategy: string;
  wafRate24h: number | null; totalRequests24h: number; wafHits24h: number;
  log: TuningLogRow[];
}

function AutoTunerTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [running, setRunning] = useState(false);

  const { data, isLoading, refetch } = useQuery<TunerStatusResp>({
    queryKey: ["orchestrator-tuning-log"],
    queryFn: () => api("/api/orchestrator/tuning-log"),
    refetchInterval: 60_000,
  });

  async function triggerManual() {
    setRunning(true);
    try {
      await api("/api/orchestrator/run-tuner", { method: "POST" });
      toast({ title: "Auto-tuner cycle completed", description: "Config may have been adjusted." });
      await refetch();
      qc.invalidateQueries({ queryKey: ["waf-bypass-stats"] });
    } catch (e: any) {
      toast({ title: "Tuner run failed", description: e.message, variant: "destructive" });
    } finally {
      setRunning(false);
    }
  }

  const actionLabel: Record<string, string> = {
    increase_delay_multiplier: "Increased delay multiplier",
    decrease_delay_multiplier: "Decreased delay multiplier",
    enable_waf_bypass:         "Enabled WAF bypass",
    disable_waf_bypass:        "Disabled WAF bypass",
    no_change:                 "No change",
  };

  const actionColor: Record<string, string> = {
    increase_delay_multiplier: "text-amber-500",
    decrease_delay_multiplier: "text-emerald-500",
    enable_waf_bypass:         "text-blue-500",
    disable_waf_bypass:        "text-muted-foreground",
    no_change:                 "text-muted-foreground",
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="font-semibold text-base">Auto-Tuner</h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Automatically adjusts scan delay and WAF bypass strategy based on observed block rates.
            Runs every 10 minutes in the background.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" /> Refresh
          </Button>
          <Button size="sm" className="h-8 gap-1.5" onClick={triggerManual} disabled={running}>
            {running ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            Run Now
          </Button>
        </div>
      </div>

      {/* Current state */}
      {data && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: "Delay Multiplier",     value: `×${data.currentMultiplier.toFixed(2)}`, sub: "scan_delay_multiplier" },
            { label: "WAF Bypass Strategy",  value: data.currentBypassStrategy || "none",   sub: "waf_bypass_strategy" },
            { label: "WAF Rate (24h)",        value: data.wafRate24h != null ? `${data.wafRate24h}%` : "—", sub: `${data.wafHits24h} hits / ${data.totalRequests24h} reqs` },
            { label: "Next Auto-Tune",        value: "Every 10 min",                         sub: "beatScheduler interval" },
          ].map(s => (
            <div key={s.label} className="border rounded-lg p-3">
              <div className="text-base font-bold tabular-nums">{s.value}</div>
              <div className="text-xs font-medium mt-0.5">{s.label}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.sub}</div>
            </div>
          ))}
        </div>
      )}

      {/* Thresholds legend */}
      <div className="border rounded-lg p-4 text-xs space-y-1.5">
        <div className="font-medium text-sm mb-2">Tuning Thresholds</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
          {[
            { cond: "WAF rate &gt; 60%", action: "Enable bypass + increase delay ×1.5", color: "text-red-500" },
            { cond: "WAF rate &gt; 30%", action: "Enable bypass (delay unchanged)", color: "text-amber-500" },
            { cond: "WAF rate &lt; 15%", action: "Decrease delay ×0.85 (min ×0.5)", color: "text-emerald-500" },
            { cond: "WAF rate &lt; 5% for 48h", action: "Disable bypass strategy", color: "text-blue-500" },
          ].map(t => (
            <div key={t.cond} className="flex gap-2">
              <span className={cn("shrink-0 font-mono", t.color)} dangerouslySetInnerHTML={{ __html: t.cond }} />
              <span className="text-muted-foreground">→ {t.action}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Tuning log */}
      {isLoading ? (
        <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 w-full" />)}</div>
      ) : (data?.log ?? []).length === 0 ? (
        <div className="border rounded-lg p-8 text-center text-muted-foreground text-sm">
          No tuning actions yet — the auto-tuner will fire after enough WAF data accumulates
        </div>
      ) : (
        <div className="border rounded-lg overflow-hidden">
          <div className="px-4 py-2.5 border-b bg-muted/30 flex items-center justify-between">
            <span className="text-sm font-medium">Recent Tuning Actions</span>
            <span className="text-xs text-muted-foreground">{data!.log.length} records</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-muted-foreground bg-muted/20 border-b">
                  <th className="px-3 py-2 text-left">Time</th>
                  <th className="px-3 py-2 text-left">Action</th>
                  <th className="px-3 py-2 text-right">Old Value</th>
                  <th className="px-3 py-2 text-right">New Value</th>
                  <th className="px-3 py-2 text-right">WAF Rate</th>
                  <th className="px-3 py-2 text-left">Reason</th>
                </tr>
              </thead>
              <tbody>
                {data!.log.map(row => (
                  <tr key={row.id} className="border-b last:border-b-0 hover:bg-muted/10 transition-colors">
                    <td className="px-3 py-2 text-xs text-muted-foreground whitespace-nowrap">
                      {new Date(row.createdAt).toLocaleString()}
                    </td>
                    <td className={cn("px-3 py-2 font-medium text-xs", actionColor[row.action] ?? "text-foreground")}>
                      {actionLabel[row.action] ?? row.action}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs text-muted-foreground">
                      {row.oldValue ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-xs font-bold">
                      {row.newValue ?? "—"}
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-xs">
                      {row.wafRatePct != null ? `${row.wafRatePct.toFixed(1)}%` : "—"}
                    </td>
                    <td className="px-3 py-2 text-xs text-muted-foreground max-w-xs truncate" title={row.reason}>
                      {row.reason}
                    </td>
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

/* ─── Tab definitions ────────────────────────────────────────────────── */
type TabKey = "dashboard" | "proxies" | "fingerprints" | "config" | "logs" | "waf-dashboard" | "dry-run" | "ab-profiles" | "auto-tuner";

interface TabDef { key: TabKey; label: string; superAdminOnly?: boolean; }

const TABS: TabDef[] = [
  { key: "dashboard",     label: "Dashboard" },
  { key: "proxies",       label: "Proxy Pool" },
  { key: "fingerprints",  label: "Fingerprints" },
  { key: "config",        label: "Config" },
  { key: "logs",          label: "Telemetry Log" },
  { key: "waf-dashboard", label: "WAF Dashboard" },
  { key: "dry-run",       label: "Dry-Run Test" },
  { key: "ab-profiles",   label: "A/B Profiles" },
  { key: "auto-tuner",    label: "Auto-Tuner" },
];

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function OrchestratorPage() {
  const { user } = useAuth();
  const isAdminOrSA = user?.role === "super_admin" || user?.role === "admin";
  const [tab, setTab] = useState<TabKey>("dashboard");

  const visibleTabs = TABS.filter(t => !t.superAdminOnly || isAdminOrSA);

  return (
    <div className="p-6 space-y-6 w-full">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Scan Orchestration</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Proxy pool, browser fingerprints, engine config, circuit breakers and request telemetry
        </p>
      </div>

      {/* Tab bar */}
      <div className="border-b">
        <div className="flex gap-1 -mb-px">
          {visibleTabs.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={cn(
                "px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap",
                tab === t.key
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-muted-foreground/40"
              )}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {tab === "dashboard"     && <DashboardTab />}
      {tab === "proxies"       && <ProxiesTab />}
      {tab === "fingerprints"  && <FingerprintsTab />}
      {tab === "config"        && <ConfigTab />}
      {tab === "logs"          && <TelemetryLogTab />}
      {tab === "waf-dashboard" && <WafDashboardTab />}
      {tab === "dry-run"       && <DryRunTab />}
      {tab === "ab-profiles"   && <AbProfilesTab />}
      {tab === "auto-tuner"    && <AutoTunerTab />}
    </div>
  );
}
