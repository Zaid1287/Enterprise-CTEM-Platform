import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  RefreshCw, Download, Filter, Search, AlertTriangle, Shield, Loader2,
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

/* ─── Status code badge ──────────────────────────────────────────────── */
function StatusCode({ code }: { code: number | null }) {
  if (code == null) return <span className="text-muted-foreground text-xs">—</span>;
  const cls =
    code >= 500 ? "text-red-500"
    : code >= 400 ? "text-amber-500"
    : code >= 300 ? "text-blue-500"
    : "text-green-600";
  return <span className={cn("font-mono text-xs font-semibold", cls)}>{code}</span>;
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

/* ─── Build query string ─────────────────────────────────────────────── */
function buildQs(p: {
  page: number; proxyIp: string; dateFrom: string; dateTo: string;
  status: string; waf: boolean; captcha: boolean;
}) {
  const q = new URLSearchParams({ page: String(p.page), limit: "50" });
  if (p.proxyIp)  q.set("proxyIp",  p.proxyIp);
  if (p.dateFrom) q.set("dateFrom", p.dateFrom);
  if (p.dateTo)   q.set("dateTo",   p.dateTo);
  if (p.status !== "all") q.set("status", p.status);
  return q.toString();
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanTelemetryPage() {
  const [page, setPage]         = useState(1);
  const [searchUrl, setSearchUrl]   = useState("");
  const [filterDomain, setFilterDomain] = useState("");
  const [filterProxyIp, setFilterProxyIp] = useState("");
  const [filterStatus, setFilterStatus]   = useState("all");
  const [filterWaf, setFilterWaf]         = useState(false);
  const [filterCaptcha, setFilterCaptcha] = useState(false);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo,   setDateTo]   = useState("");

  /* Server-side filters pushed to backend */
  const qs = buildQs({ page, proxyIp: filterProxyIp, dateFrom, dateTo, status: filterStatus, waf: filterWaf, captcha: filterCaptcha });

  const { data, isLoading, refetch, isFetching } = useQuery<TelemetryResponse>({
    queryKey: ["scan-telemetry", qs],
    queryFn:  () => api(`/api/scan-telemetry?${qs}`),
    refetchInterval: 15_000,
  });

  const allRows = data?.rows ?? [];
  const total   = data?.total ?? 0;
  const pages   = Math.max(1, Math.ceil(total / 50));

  /* Client-side secondary filters (URL text + domain + waf + captcha) */
  const filtered = allRows.filter(r => {
    if (searchUrl    && !r.url.toLowerCase().includes(searchUrl.toLowerCase())) return false;
    if (filterDomain && !extractDomain(r.url).toLowerCase().includes(filterDomain.toLowerCase())) return false;
    if (filterWaf    && !r.wafDetected) return false;
    if (filterCaptcha && !r.captchaDetected) return false;
    return true;
  });

  const clearFilters = () => {
    setSearchUrl(""); setFilterDomain(""); setFilterProxyIp(""); setFilterStatus("all");
    setFilterWaf(false); setFilterCaptcha(false); setDateFrom(""); setDateTo(""); setPage(1);
  };
  const hasFilters = searchUrl || filterDomain || filterProxyIp || filterStatus !== "all" || filterWaf || filterCaptcha || dateFrom || dateTo;

  return (
    <div className="p-6 space-y-5 max-w-screen-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan Request Telemetry</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Every HTTP request made by the orchestration engine — {total.toLocaleString()} total records (filtered)
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => exportCsv(filtered)} className="gap-1.5" disabled={filtered.length === 0}>
            <Download className="w-3.5 h-3.5" /> Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5" disabled={isFetching}>
            {isFetching ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Refresh
          </Button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="rounded-xl border bg-card p-3 space-y-2.5">
        <div className="flex items-center gap-3 flex-wrap">
          <Filter className="w-4 h-4 text-muted-foreground shrink-0" />

          {/* URL filter (client-side) */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs w-52" placeholder="Filter by URL…"
              value={searchUrl} onChange={e => setSearchUrl(e.target.value)} />
          </div>

          {/* Domain filter (client-side) */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs w-40" placeholder="Domain filter…"
              value={filterDomain} onChange={e => setFilterDomain(e.target.value)} />
          </div>

          {/* Proxy IP filter (server-side) */}
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input className="pl-8 h-8 text-xs w-36" placeholder="Proxy IP…"
              value={filterProxyIp}
              onChange={e => { setFilterProxyIp(e.target.value); setPage(1); }} />
          </div>

          {/* Status filter (server-side) */}
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
            <Switch id="waf-filter" checked={filterWaf} onCheckedChange={setFilterWaf} />
            <Label htmlFor="waf-filter" className="text-xs cursor-pointer">WAF only</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="cap-filter" checked={filterCaptcha} onCheckedChange={setFilterCaptcha} />
            <Label htmlFor="cap-filter" className="text-xs cursor-pointer">Captcha only</Label>
          </div>

          {hasFilters && (
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={clearFilters}>Clear</Button>
          )}
          <span className="ml-auto text-xs text-muted-foreground">{filtered.length} shown (page {page})</span>
        </div>

        {/* Date range row (server-side) */}
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-muted-foreground w-12 shrink-0">From:</span>
          <Input type="datetime-local" className="h-8 text-xs w-52"
            value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(1); }} />
          <span className="text-xs text-muted-foreground">To:</span>
          <Input type="datetime-local" className="h-8 text-xs w-52"
            value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(1); }} />
          {(dateFrom || dateTo) && (
            <Button variant="ghost" size="sm" className="h-7 text-xs"
              onClick={() => { setDateFrom(""); setDateTo(""); setPage(1); }}>
              Clear dates
            </Button>
          )}
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
                <th className="px-3 py-2.5 text-left font-medium">Domain</th>
                <th className="px-3 py-2.5 text-left font-medium">URL Path</th>
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Proxy IP</th>
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Fingerprint</th>
                <th className="px-3 py-2.5 text-right font-medium">Status</th>
                <th className="px-3 py-2.5 text-right font-medium">Latency</th>
                <th className="px-3 py-2.5 text-right font-medium">Retries</th>
                <th className="px-3 py-2.5 text-right font-medium">Delay</th>
                <th className="px-3 py-2.5 text-right font-medium">Backoff</th>
                <th className="px-3 py-2.5 text-center font-medium">WAF</th>
                <th className="px-3 py-2.5 text-center font-medium">Captcha</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => (
                  <tr key={i} className="border-b">
                    {Array.from({ length: 13 }).map((__, j) => (
                      <td key={j} className="px-3 py-2"><Skeleton className="h-3.5 w-full" /></td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={13} className="px-3 py-12 text-center text-muted-foreground">
                    {total === 0
                      ? "No telemetry yet — records appear once scans run."
                      : "No records match the current filters."}
                  </td>
                </tr>
              ) : filtered.map(row => {
                const domain = extractDomain(row.url);
                const path   = (() => { try { return new URL(row.url).pathname; } catch { return row.url; } })();
                return (
                  <tr key={row.id} className={cn(
                    "border-b last:border-0 hover:bg-muted/30 transition-colors",
                    row.wafDetected && "bg-red-500/5",
                  )}>
                    <td className="px-3 py-2 whitespace-nowrap font-mono text-muted-foreground">
                      {new Date(row.createdAt).toLocaleString()}
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0">{row.method}</Badge>
                    </td>
                    <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">{domain}</td>
                    <td className="px-3 py-2 max-w-xs truncate font-mono text-muted-foreground" title={row.url}>{path}</td>
                    <td className="px-3 py-2 font-mono whitespace-nowrap">
                      {row.proxyIp
                        ? <button
                            className="text-blue-500 hover:underline"
                            onClick={() => { setFilterProxyIp(row.proxyIp!); setPage(1); }}
                            title="Filter by this proxy"
                          >{row.proxyIp}</button>
                        : <span className="text-muted-foreground/50">direct</span>
                      }
                    </td>
                    <td className="px-3 py-2">
                      {row.fingerprintProfileId != null
                        ? <Badge variant="outline" className="font-mono text-[10px] px-1.5 py-0">#{row.fingerprintProfileId}</Badge>
                        : <span className="text-muted-foreground/50">—</span>
                      }
                    </td>
                    <td className="px-3 py-2 text-right"><StatusCode code={row.statusCode} /></td>
                    <td className="px-3 py-2 text-right text-muted-foreground">
                      {row.latencyMs != null ? `${row.latencyMs}ms` : "—"}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {row.retries > 0
                        ? <span className="text-amber-500 font-semibold">{row.retries}</span>
                        : <span className="text-muted-foreground">0</span>
                      }
                    </td>
                    <td className="px-3 py-2 text-right text-muted-foreground">
                      {row.delayMs != null ? `${row.delayMs}ms` : "—"}
                    </td>
                    <td className="px-3 py-2 text-right text-muted-foreground">
                      {row.backoffMs != null ? `${row.backoffMs}ms` : "—"}
                    </td>
                    <td className="px-3 py-2 text-center">
                      {row.wafDetected
                        ? <Shield className="w-3.5 h-3.5 text-red-500 mx-auto" />
                        : <span className="text-muted-foreground/30">—</span>
                      }
                    </td>
                    <td className="px-3 py-2 text-center">
                      {row.captchaDetected
                        ? <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mx-auto" />
                        : <span className="text-muted-foreground/30">—</span>
                      }
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {pages > 1 && (
          <div className="px-4 py-3 border-t flex items-center justify-between bg-muted/20">
            <span className="text-xs text-muted-foreground">
              Page {page} of {pages} · {total.toLocaleString()} records (server-filtered)
            </span>
            <div className="flex gap-1.5">
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}>Previous</Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= pages}
                onClick={() => setPage(p => Math.min(pages, p + 1))}>Next</Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
