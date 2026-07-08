import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Activity, Server, AlertTriangle, Zap, Clock, RefreshCw,
  ShieldX, Wifi, WifiOff, RotateCcw, TrendingDown, Timer,
  Radio, CircleDot, Plus, Trash2, Pencil, Loader2, TestTube2,
  Upload, Check, X, KeyRound, Eye, EyeOff, ChevronDown, ChevronRight,
  Monitor, Smartphone, Globe, Save, Info, ShieldOff,
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
  captchaDetected?: boolean; retries?: number;
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
    es.addEventListener("telemetry:request", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        const event: WaterfallEvent = {
          id: `${Date.now()}-${Math.random()}`,
          ts: data.ts ?? Date.now(), method: data.method ?? "GET", url: data.url ?? "",
          statusCode: data.statusCode, latencyMs: data.latencyMs,
          proxyId: data.proxyId, wafDetected: data.wafDetected,
          captchaDetected: data.captchaDetected, retries: data.retries,
        };
        setEvents(prev => [event, ...prev].slice(0, 100));
      } catch { /* ignore */ }
    });
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
                  ev.wafDetected ? "bg-red-500/5" : ev.captchaDetected ? "bg-amber-500/5" : "hover:bg-muted/30"
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
                    <div className="flex gap-1">
                      {ev.wafDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-red-500/10 text-red-600 border-red-500/30">WAF</Badge>}
                      {ev.captchaDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-amber-500/10 text-amber-600 border-amber-500/30">CAPTCHA</Badge>}
                      {ev.proxyId && !ev.wafDetected && !ev.captchaDetected && <Badge variant="outline" className="text-[10px] px-1 py-0 bg-blue-500/10 text-blue-600 border-blue-500/30">Proxy</Badge>}
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
  const [showAdd, setShowAdd]   = useState(false);
  const [showBulk, setShowBulk] = useState(false);
  const [editProxy, setEditProxy] = useState<Proxy | null>(null);
  const [testingId, setTestingId] = useState<number | null>(null);
  const [deleteId, setDeleteId]   = useState<number | null>(null);

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
      const result = await api<{ reachable: boolean; latencyMs?: number }>(`/api/scan-proxies/${proxy.id}/health`);
      qc.invalidateQueries({ queryKey: ["orch-proxies"] });
      if (result.reachable) {
        toast({ title: "Proxy reachable", description: `Latency: ${result.latencyMs ?? "?"}ms` });
      } else {
        toast({ title: "Proxy unreachable", description: "TCP connection failed.", variant: "destructive" });
      }
    } catch { toast({ title: "Health check failed", variant: "destructive" }); }
    finally { setTestingId(null); }
  };

  const activeCount   = proxies.filter(p => p.status === "active").length;
  const cooldownCount = proxies.filter(p => p.status === "cooldown").length;
  const inactiveCount = proxies.filter(p => p.status === "inactive").length;

  return (
    <div className="space-y-5">
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-3 flex-wrap">
          <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1.5 px-3 py-1">
            <Wifi className="w-3.5 h-3.5" />{activeCount} Healthy
          </Badge>
          <Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-500/25 gap-1.5 px-3 py-1">
            <Clock className="w-3.5 h-3.5" />{cooldownCount} Cooling
          </Badge>
          <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-500/25 gap-1.5 px-3 py-1">
            <WifiOff className="w-3.5 h-3.5" />{inactiveCount} Inactive
          </Badge>
        </div>
        {isSuperAdmin && (
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setShowBulk(true)} className="gap-1.5" size="sm">
              <Upload className="w-4 h-4" />Bulk Import
            </Button>
            <Button onClick={() => setShowAdd(true)} className="gap-1.5" size="sm">
              <Plus className="w-4 h-4" />Add Proxy
            </Button>
          </div>
        )}
      </div>

      {/* Proxy table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th className="px-4 py-3 text-left font-medium">IP : Port</th>
                <th className="px-4 py-3 text-left font-medium">Label</th>
                <th className="px-4 py-3 text-left font-medium">Class</th>
                <th className="px-4 py-3 text-left font-medium">Country</th>
                <th className="px-4 py-3 text-right font-medium">Health</th>
                <th className="px-4 py-3 text-right font-medium">Success %</th>
                <th className="px-4 py-3 text-right font-medium">429s</th>
                <th className="px-4 py-3 text-right font-medium">403s</th>
                <th className="px-4 py-3 text-right font-medium">Avg Latency</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-right font-medium">Today</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b">
                  {Array.from({ length: 12 }).map((__, j) => (
                    <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                  ))}
                </tr>
              )) : proxies.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-4 py-12 text-center text-muted-foreground text-sm">
                    No proxies configured.{isSuperAdmin && " Click \"Add Proxy\" to add one."}
                  </td>
                </tr>
              ) : proxies.map(proxy => {
                const total = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = total > 0 ? Math.round((proxy.successCount / total) * 100) : null;
                const hColor = proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500";
                return (
                  <tr key={proxy.id} className="border-b last:border-0 hover:bg-muted/30">
                    <td className="px-4 py-3 font-mono text-xs">{proxy.ip}:{proxy.port}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{proxy.label ?? "—"}</td>
                    <td className="px-4 py-3 text-xs capitalize">{proxy.type}</td>
                    <td className="px-4 py-3 text-xs">{proxy.country ?? "—"}</td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${proxy.healthScore}%`, background: proxy.healthScore >= 70 ? "#16a34a" : proxy.healthScore >= 30 ? "#f59e0b" : "#ef4444" }} />
                        </div>
                        <span className={cn("text-xs font-bold tabular-nums w-6", hColor)}>{proxy.healthScore}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right text-xs">{successPct != null ? `${successPct}%` : "—"}</td>
                    <td className={cn("px-4 py-3 text-right text-xs", proxy.count429 > 0 ? "text-amber-500 font-semibold" : "")}>{proxy.count429}</td>
                    <td className={cn("px-4 py-3 text-right text-xs", proxy.count403 > 0 ? "text-red-500 font-semibold" : "")}>{proxy.count403}</td>
                    <td className="px-4 py-3 text-right text-xs text-muted-foreground">{proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}</td>
                    <td className="px-4 py-3"><ProxyStatusBadge status={proxy.status} /></td>
                    <td className="px-4 py-3 text-right text-xs text-muted-foreground">{proxy.requestsToday ?? 0}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="icon" className="w-7 h-7" title="Test Health"
                          onClick={() => testProxy(proxy)} disabled={testingId === proxy.id}>
                          {testingId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube2 className="w-3.5 h-3.5" />}
                        </Button>
                        {isSuperAdmin && (
                          <>
                            <Button variant="ghost" size="icon" className="w-7 h-7" title="Edit"
                              onClick={() => setEditProxy(proxy)}>
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
}

const KNOBS: KnobDef[] = [
  { key: "enabled",                 type: "boolean", label: "Enable Orchestration Engine",   description: "Master switch. When off, orchestratedFetch falls back to direct fetch." },
  { key: "use_proxies",             type: "boolean", label: "Use Proxy Pool",                description: "Route outbound scan requests through the configured proxy/IP pool." },
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
  const isSuperAdmin = user?.role === "super_admin";
  const [values, setValues] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);

  const { data, isLoading } = useQuery<{ config: Record<string, string> }>({
    queryKey: ["orch-config"],
    queryFn: () => api("/api/orchestrator-config"),
    enabled: isSuperAdmin,
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

  if (!isSuperAdmin) {
    return (
      <div className="flex flex-col items-center gap-4 text-center py-16 max-w-md mx-auto">
        <div className="p-4 rounded-full bg-destructive/10"><ShieldOff className="w-10 h-10 text-destructive" /></div>
        <h2 className="text-xl font-bold">Access Restricted</h2>
        <p className="text-sm text-muted-foreground">Orchestrator configuration is limited to super administrators.</p>
      </div>
    );
  }

  const set = (key: string, val: string) => { setValues(v => ({ ...v, [key]: val })); setDirty(true); };

  const renderKnob = (k: KnobDef) => {
    const val = values[k.key] ?? "";
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
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center gap-2 justify-end">
        <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["orch-config"] })} className="gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" />Reload
        </Button>
        <Button size="sm" onClick={() => saveMut.mutate(values)} disabled={!dirty || saveMut.isPending} className="gap-1.5">
          {saveMut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          Save Changes
        </Button>
      </div>

      {dirty && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          You have unsaved changes. Click "Save Changes" to apply.
        </div>
      )}

      <div className="rounded-xl border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold">Feature Toggles</h2>
        {isLoading ? Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="flex items-center justify-between">
            <Skeleton className="h-4 w-48" /><Skeleton className="h-6 w-10 rounded-full" />
          </div>
        )) : boolKnobs.map(k => (
          <div key={k.key} className="flex items-center justify-between gap-4">
            <div className="min-w-0">
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

      <div className="rounded-xl border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold">Parameters &amp; Strategies</h2>
        {isLoading ? Array.from({ length: 11 }).map((_, i) => (
          <div key={i} className="flex items-center justify-between">
            <Skeleton className="h-4 w-52" /><Skeleton className="h-8 w-36 rounded" />
          </div>
        )) : otherKnobs.map(k => (
          <div key={k.key} className="flex items-center justify-between gap-4">
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
      </div>

      <div className="rounded-lg border bg-blue-500/5 border-blue-500/20 px-4 py-3 text-xs text-muted-foreground">
        <strong className="text-foreground">Note:</strong> Changes are written immediately to the database.
        The orchestrator reloads its config cache every 60 seconds, so new settings take effect within one minute.
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

/* ─── Tab definitions ────────────────────────────────────────────────── */
type TabKey = "dashboard" | "proxies" | "fingerprints" | "config" | "logs";

interface TabDef { key: TabKey; label: string; superAdminOnly?: boolean; }

const TABS: TabDef[] = [
  { key: "dashboard",    label: "Dashboard" },
  { key: "proxies",      label: "Proxy Pool" },
  { key: "fingerprints", label: "Fingerprints" },
  { key: "config",       label: "Config",      superAdminOnly: true },
  { key: "logs",         label: "Telemetry Log" },
];

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function OrchestratorPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const [tab, setTab] = useState<TabKey>("dashboard");

  const visibleTabs = TABS.filter(t => !t.superAdminOnly || isSuperAdmin);

  return (
    <div className="p-6 space-y-6 max-w-screen-2xl mx-auto">
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
      {tab === "dashboard"    && <DashboardTab />}
      {tab === "proxies"      && <ProxiesTab />}
      {tab === "fingerprints" && <FingerprintsTab />}
      {tab === "config"       && <ConfigTab />}
      {tab === "logs"         && <TelemetryLogTab />}
    </div>
  );
}
