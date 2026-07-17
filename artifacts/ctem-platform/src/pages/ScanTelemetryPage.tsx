import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  RefreshCw, Download, Filter, Search, AlertTriangle, Shield,
  Loader2, Activity, Zap, Clock, XCircle, Radio,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";

/* ─── Types ─────────────────────────────────────────────────────────── */
interface TelemetryRow {
  id: number;
  url: string;
  method: string;
  proxyIp: string | null;
  fingerprintProfileId: number | null;
  statusCode: number | null;
  latencyMs: number | null;
  retries: number;
  delayMs: number | null;
  backoffMs: number | null;
  wafDetected: boolean;
  captchaDetected: boolean;
  bytesDownloaded: number | null;
  degradedMode: boolean;
  createdAt: string;
}

interface TelemetryResponse {
  rows: TelemetryRow[];
  total: number;
  page: number;
  limit: number;
}

/* ─── Helpers ────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs() });
  if (!r.ok) throw new Error("Request failed");
  return r.json();
}

function extractDomain(url: string): string {
  try { return new URL(url).hostname; }
  catch { return url.split("/")[0] ?? url; }
}

function formatBytes(b: number | null): string {
  if (b == null) return "—";
  if (b < 1024) return `${b}B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)}KB`;
  return `${(b / 1024 / 1024).toFixed(2)}MB`;
}

/* ─── Status code badge ──────────────────────────────────────────────── */
function StatusCode({ code }: { code: number | null }) {
  if (code == null) return <span className="text-muted-foreground text-xs">—</span>;
  const cls =
    code >= 500 ? "bg-red-500/15 text-red-500 border-red-500/25"
    : code >= 400 ? "bg-amber-500/15 text-amber-600 border-amber-500/25"
    : code >= 300 ? "bg-blue-500/15 text-blue-600 border-blue-500/25"
    : "bg-green-500/15 text-green-600 border-green-500/25";
  return (
    <Badge variant="outline" className={cn("font-mono text-[11px] px-1.5 py-0 font-bold", cls)}>{code}</Badge>
  );
}

/* ─── Method badge ───────────────────────────────────────────────────── */
function MethodBadge({ method }: { method: string }) {
  const colors: Record<string, string> = {
    GET:    "bg-blue-500/10 text-blue-600 border-blue-500/25",
    POST:   "bg-green-500/10 text-green-600 border-green-500/25",
    PUT:    "bg-amber-500/10 text-amber-600 border-amber-500/25",
    PATCH:  "bg-purple-500/10 text-purple-600 border-purple-500/25",
    DELETE: "bg-red-500/10 text-red-600 border-red-500/25",
  };
  return (
    <Badge variant="outline" className={cn("font-mono text-[10px] px-1.5 py-0", colors[method] ?? "bg-muted text-muted-foreground")}>
      {method}
    </Badge>
  );
}

/* ─── CSV export ─────────────────────────────────────────────────────── */
function exportCsv(rows: TelemetryRow[]) {
  const cols: Array<keyof TelemetryRow> = [
    "createdAt","method","url","proxyIp","fingerprintProfileId",
    "statusCode","latencyMs","retries","delayMs","backoffMs","wafDetected","captchaDetected","bytesDownloaded",
  ];
  const header = cols.join(",");
  const lines = rows.map(r =>
    cols.map(c => {
      const v = r[c];
      if (typeof v === "string" && (v.includes(",") || v.includes('"')))
        return `"${v.replace(/"/g, '""')}"`;
      return v ?? "";
    }).join(",")
  );
  const blob = new Blob([header + "\n" + lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `scan-telemetry-${new Date().toISOString().slice(0,10)}.csv`; a.click();
  URL.revokeObjectURL(url);
}

function buildQs(p: {
  page: number; proxyIp: string; host: string; dateFrom: string; dateTo: string;
  status: string; waf: boolean; captcha: boolean;
}) {
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

/* ─── Stat Card ──────────────────────────────────────────────────────── */
function StatCard({ label, value, icon: Icon, color, sub }: {
  label: string; value: string | number; icon: React.ElementType; color: string; sub?: string;
}) {
  const colorMap: Record<string, { bg: string; icon: string; border: string }> = {
    blue:   { bg: "bg-blue-500/10",   icon: "text-blue-500",   border: "border-l-blue-500"   },
    green:  { bg: "bg-green-500/10",  icon: "text-green-500",  border: "border-l-green-500"  },
    amber:  { bg: "bg-amber-500/10",  icon: "text-amber-500",  border: "border-l-amber-500"  },
    red:    { bg: "bg-red-500/10",    icon: "text-red-500",    border: "border-l-red-500"    },
    orange: { bg: "bg-orange-500/10", icon: "text-orange-500", border: "border-l-orange-500" },
    indigo: { bg: "bg-indigo-500/10", icon: "text-indigo-500", border: "border-l-indigo-500" },
  };
  const c = colorMap[color] ?? colorMap.blue;
  return (
    <div className={cn("rounded-xl border bg-card p-4 flex items-start gap-3 border-l-4", c.border)}>
      <div className={cn("p-2 rounded-lg shrink-0", c.bg)}>
        <Icon className={cn("w-4 h-4", c.icon)} />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-muted-foreground truncate">{label}</p>
        <p className={cn("text-2xl font-bold leading-tight mt-0.5 tabular-nums", c.icon)}>{value}</p>
        {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanTelemetryPage() {
  const [page, setPage]               = useState(1);
  const [filterHost, setFilterHost]   = useState("");
  const [filterProxyIp, setFilterProxyIp] = useState("");
  const [filterStatus, setFilterStatus]   = useState("all");
  const [filterWaf, setFilterWaf]         = useState(false);
  const [filterCaptcha, setFilterCaptcha] = useState(false);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo,   setDateTo]   = useState("");

  const qs = buildQs({ page, proxyIp: filterProxyIp, host: filterHost, dateFrom, dateTo, status: filterStatus, waf: filterWaf, captcha: filterCaptcha });

  const { data, isLoading, refetch, isFetching } = useQuery<TelemetryResponse>({
    queryKey: ["scan-telemetry", qs],
    queryFn:  () => api(`/api/scan-telemetry?${qs}`),
    refetchInterval: 15_000,
  });

  const allRows = data?.rows ?? [];
  const total   = data?.total ?? 0;
  const pages   = Math.max(1, Math.ceil(total / 50));

  const wafCount     = allRows.filter(r => r.wafDetected).length;
  const captchaCount = allRows.filter(r => r.captchaDetected).length;
  const degradedCount = allRows.filter(r => r.degradedMode).length;
  const avgLatency   = allRows.length > 0
    ? Math.round(allRows.filter(r => r.latencyMs != null).reduce((s, r) => s + (r.latencyMs ?? 0), 0) / Math.max(1, allRows.filter(r => r.latencyMs != null).length))
    : null;

  const clearFilters = () => {
    setFilterHost(""); setFilterProxyIp(""); setFilterStatus("all");
    setFilterWaf(false); setFilterCaptcha(false); setDateFrom(""); setDateTo(""); setPage(1);
  };
  const hasFilters = filterHost || filterProxyIp || filterStatus !== "all" || filterWaf || filterCaptcha || dateFrom || dateTo;

  return (
    <div className="p-6 space-y-6">

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 rounded-xl bg-indigo-500/15 border border-indigo-500/25">
            <Activity className="w-6 h-6 text-indigo-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Scan Request Telemetry</h1>
            <p className="text-sm text-muted-foreground mt-0.5">
              Every HTTP request made by the orchestration engine · {total.toLocaleString()} total records
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={() => exportCsv(allRows)} className="gap-1.5" disabled={allRows.length === 0}>
            <Download className="w-3.5 h-3.5" /> Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5" disabled={isFetching}>
            {isFetching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Refresh
          </Button>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard label="Total Records"    value={total.toLocaleString()}                        icon={Radio}        color="indigo" sub="all time" />
        <StatCard label="Avg Latency"      value={avgLatency != null ? `${avgLatency}ms` : "—"}  icon={Zap}          color="blue"   sub="current page" />
        <StatCard label="WAF Detections"   value={wafCount}                                       icon={Shield}       color={wafCount > 0 ? "red" : "green"} sub="on current page" />
        <StatCard label="CAPTCHA Triggers" value={captchaCount}                                   icon={AlertTriangle} color={captchaCount > 0 ? "amber" : "green"} sub="on current page" />
        <StatCard label="Degraded Mode"   value={degradedCount}                                   icon={XCircle}      color={degradedCount > 0 ? "orange" : "green"} sub="no proxy/fingerprint" />
      </div>

      {/* ── Filter Bar ── */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="px-5 py-3 border-b bg-muted/20 flex items-center gap-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <span className="text-sm font-medium">Filters</span>
          {hasFilters && (
            <Button variant="ghost" size="sm" className="h-6 text-xs ml-auto px-2 text-muted-foreground" onClick={clearFilters}>
              Clear all
            </Button>
          )}
        </div>
        <div className="px-5 py-4 space-y-4">
          {/* Row 1: text filters + status */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
              <Input
                className="pl-8 h-8 text-xs w-56"
                placeholder="Filter by target host…"
                value={filterHost}
                onChange={e => { setFilterHost(e.target.value); setPage(1); }}
              />
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
              <Input
                className="pl-8 h-8 text-xs w-40"
                placeholder="Proxy IP…"
                value={filterProxyIp}
                onChange={e => { setFilterProxyIp(e.target.value); setPage(1); }}
              />
            </div>
            <Select value={filterStatus} onValueChange={v => { setFilterStatus(v); setPage(1); }}>
              <SelectTrigger className="h-8 w-40 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="2xx">2xx Success</SelectItem>
                <SelectItem value="4xx">4xx Client Error</SelectItem>
                <SelectItem value="403">403 Forbidden</SelectItem>
                <SelectItem value="429">429 Rate Limited</SelectItem>
                <SelectItem value="5xx">5xx Server Error</SelectItem>
              </SelectContent>
            </Select>
            <div className="flex items-center gap-2 pl-2 border-l">
              <Switch id="waf-filter" checked={filterWaf} onCheckedChange={v => { setFilterWaf(v); setPage(1); }} />
              <Label htmlFor="waf-filter" className="text-xs cursor-pointer flex items-center gap-1">
                <Shield className="w-3 h-3 text-red-500" /> WAF only
              </Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch id="cap-filter" checked={filterCaptcha} onCheckedChange={v => { setFilterCaptcha(v); setPage(1); }} />
              <Label htmlFor="cap-filter" className="text-xs cursor-pointer flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-amber-500" /> Captcha only
              </Label>
            </div>
            <span className="ml-auto text-xs text-muted-foreground">{allRows.length} shown · page {page} of {pages}</span>
          </div>
          {/* Row 2: date range */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> Date range:
            </span>
            <Input type="datetime-local" className="h-8 text-xs w-52" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1); }} />
            <span className="text-xs text-muted-foreground">→</span>
            <Input type="datetime-local" className="h-8 text-xs w-52" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1); }} />
            {(dateFrom || dateTo) && (
              <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setDateFrom(""); setDateTo(""); setPage(1); }}>
                Clear dates
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* ── Table ── */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/40 text-muted-foreground">
                <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">Timestamp</th>
                <th className="px-4 py-2.5 text-left font-medium">Method</th>
                <th className="px-4 py-2.5 text-left font-medium">Target</th>
                <th className="px-4 py-2.5 text-left font-medium">Path</th>
                <th className="px-4 py-2.5 text-left font-medium whitespace-nowrap">Proxy IP</th>
                <th className="px-4 py-2.5 text-left font-medium">FP</th>
                <th className="px-4 py-2.5 text-center font-medium">Status</th>
                <th className="px-4 py-2.5 text-right font-medium">Latency</th>
                <th className="px-4 py-2.5 text-right font-medium">Retries</th>
                <th className="px-4 py-2.5 text-right font-medium">Delay</th>
                <th className="px-4 py-2.5 text-right font-medium">Bytes</th>
                <th className="px-4 py-2.5 text-center font-medium">Flags</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 12 }).map((_, i) => (
                  <tr key={i} className="border-b">
                    {Array.from({ length: 12 }).map((__, j) => (
                      <td key={j} className="px-4 py-2.5"><Skeleton className="h-3.5 w-full" /></td>
                    ))}
                  </tr>
                ))
              ) : allRows.length === 0 ? (
                <tr>
                  <td colSpan={12} className="px-4 py-20 text-center">
                    <Activity className="w-10 h-10 text-muted-foreground/20 mx-auto mb-3" />
                    <p className="text-sm font-medium text-muted-foreground">
                      {total === 0 ? "No telemetry recorded yet" : "No records match the current filters"}
                    </p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      {total === 0 ? "Records will appear here once scans run." : "Try adjusting or clearing your filters."}
                    </p>
                    {hasFilters && (
                      <Button size="sm" variant="outline" className="mt-4 gap-1.5 text-xs" onClick={clearFilters}>
                        Clear Filters
                      </Button>
                    )}
                  </td>
                </tr>
              ) : allRows.map(row => {
                const domain = extractDomain(row.url);
                const truncUrl = (() => {
                  try {
                    const u = new URL(row.url);
                    const p = u.pathname.length > 50 ? u.pathname.slice(0, 47) + "…" : u.pathname;
                    return u.search ? p + u.search.slice(0, 15) + "…" : p;
                  } catch { return row.url.slice(0, 60); }
                })();

                return (
                  <tr
                    key={row.id}
                    className={cn(
                      "border-b last:border-0 hover:bg-muted/30 transition-colors",
                      row.degradedMode ? "bg-orange-500/5" : row.wafDetected ? "bg-red-500/4" : row.captchaDetected ? "bg-amber-500/4" : ""
                    )}
                  >
                    <td className="px-4 py-2.5 whitespace-nowrap font-mono text-muted-foreground text-[11px]">
                      {new Date(row.createdAt).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </td>
                    <td className="px-4 py-2.5">
                      <MethodBadge method={row.method} />
                    </td>
                    <td className="px-4 py-2.5 font-mono text-muted-foreground whitespace-nowrap">
                      <button
                        className="hover:text-foreground hover:underline text-left transition-colors"
                        onClick={() => { setFilterHost(domain); setPage(1); }}
                        title={`Filter by ${domain}`}
                      >
                        {domain}
                      </button>
                    </td>
                    <td className="px-4 py-2.5 max-w-xs font-mono text-muted-foreground truncate" title={row.url}>
                      {truncUrl || "—"}
                    </td>
                    <td className="px-4 py-2.5 font-mono whitespace-nowrap">
                      {row.proxyIp
                        ? <button className="text-blue-500 hover:underline hover:text-blue-600 transition-colors" onClick={() => { setFilterProxyIp(row.proxyIp!); setPage(1); }} title="Filter by this proxy">{row.proxyIp}</button>
                        : <span className="text-muted-foreground/40 italic text-[11px]">direct</span>
                      }
                    </td>
                    <td className="px-4 py-2.5">
                      {row.fingerprintProfileId != null
                        ? <Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0 bg-purple-500/10 text-purple-600 border-purple-500/25">#{row.fingerprintProfileId}</Badge>
                        : <span className="text-muted-foreground/40">—</span>
                      }
                    </td>
                    <td className="px-4 py-2.5 text-center">
                      <StatusCode code={row.statusCode} />
                    </td>
                    <td className="px-4 py-2.5 text-right tabular-nums">
                      {row.latencyMs != null
                        ? <span className={cn(row.latencyMs > 5000 ? "text-red-500 font-semibold" : row.latencyMs > 2000 ? "text-amber-500" : "text-muted-foreground")}>
                            {row.latencyMs > 999 ? `${(row.latencyMs / 1000).toFixed(1)}s` : `${row.latencyMs}ms`}
                          </span>
                        : <span className="text-muted-foreground/40">—</span>
                      }
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      {row.retries > 0
                        ? <span className="text-amber-500 font-bold">{row.retries}×</span>
                        : <span className="text-muted-foreground/40">—</span>
                      }
                    </td>
                    <td className="px-4 py-2.5 text-right text-muted-foreground">
                      {row.delayMs != null ? `${row.delayMs}ms` : <span className="text-muted-foreground/40">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-right text-muted-foreground">
                      {formatBytes(row.bytesDownloaded)}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center justify-center gap-1 flex-wrap">
                        {row.degradedMode && (
                          <Badge variant="outline" className="text-[10px] px-1 py-0 bg-orange-500/10 text-orange-600 border-orange-500/30" title="Orchestrator bootstrap failed — no proxy or fingerprint rotation">DEGRADED</Badge>
                        )}
                        {row.wafDetected && (
                          <Badge variant="outline" className="text-[10px] px-1 py-0 bg-red-500/10 text-red-600 border-red-500/30">WAF</Badge>
                        )}
                        {row.captchaDetected && (
                          <Badge variant="outline" className="text-[10px] px-1 py-0 bg-amber-500/10 text-amber-600 border-amber-500/30">CAPTCHA</Badge>
                        )}
                        {!row.degradedMode && !row.wafDetected && !row.captchaDetected && (
                          <span className="text-muted-foreground/30">—</span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div className="px-5 py-3 border-t flex items-center justify-between bg-muted/20">
            <span className="text-xs text-muted-foreground">
              Page {page} of {pages} · <span className="font-medium">{total.toLocaleString()}</span> total records
            </span>
            <div className="flex items-center gap-1.5">
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1} onClick={() => setPage(1)}>«</Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>Previous</Button>
              <div className="px-3 py-1 text-xs bg-muted rounded-md font-medium">{page}</div>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= pages} onClick={() => setPage(p => Math.min(pages, p + 1))}>Next</Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= pages} onClick={() => setPage(pages)}>»</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
