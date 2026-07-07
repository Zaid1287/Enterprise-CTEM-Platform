import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  RefreshCw, Download, Filter, Search, CheckCircle2, XCircle,
  AlertTriangle, Shield, Loader2,
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

/* ─── API ────────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs() });
  if (!r.ok) throw new Error("Request failed");
  return r.json();
}

/* ─── Status badge ───────────────────────────────────────────────────── */
function StatusCode({ code }: { code: number | null }) {
  if (code == null) return <span className="text-muted-foreground text-xs">—</span>;
  const cls = code >= 500 ? "text-red-500" : code >= 400 ? "text-amber-500" : code >= 300 ? "text-blue-500" : "text-green-600";
  return <span className={cn("font-mono text-xs font-semibold", cls)}>{code}</span>;
}

/* ─── CSV export helper ──────────────────────────────────────────────── */
function exportCsv(rows: TelemetryRow[]) {
  const cols: Array<keyof TelemetryRow> = [
    "createdAt", "method", "url", "proxyIp", "statusCode", "latencyMs",
    "retries", "delayMs", "backoffMs", "wafDetected", "captchaDetected", "bytesDownloaded",
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
  a.href = url;
  a.download = `scan-telemetry-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanTelemetryPage() {
  const [page, setPage] = useState(1);
  const LIMIT = 50;

  // Filters (client-side on current page for now; server-side filter via query params in future)
  const [searchUrl, setSearchUrl] = useState("");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterWaf, setFilterWaf] = useState(false);
  const [filterCaptcha, setFilterCaptcha] = useState(false);

  const { data, isLoading, refetch, isFetching } = useQuery<TelemetryResponse>({
    queryKey: ["scan-telemetry", page],
    queryFn: () => api(`/api/scan-telemetry?page=${page}&limit=${LIMIT}`),
    refetchInterval: 15_000,
  });

  const allRows = data?.rows ?? [];
  const total   = data?.total ?? 0;
  const pages   = Math.max(1, Math.ceil(total / LIMIT));

  const filtered = allRows.filter(r => {
    if (searchUrl && !r.url.toLowerCase().includes(searchUrl.toLowerCase())) return false;
    if (filterWaf && !r.wafDetected) return false;
    if (filterCaptcha && !r.captchaDetected) return false;
    if (filterStatus === "2xx" && (r.statusCode == null || r.statusCode < 200 || r.statusCode >= 300)) return false;
    if (filterStatus === "4xx" && (r.statusCode == null || r.statusCode < 400 || r.statusCode >= 500)) return false;
    if (filterStatus === "429" && r.statusCode !== 429) return false;
    if (filterStatus === "403" && r.statusCode !== 403) return false;
    if (filterStatus === "5xx" && (r.statusCode == null || r.statusCode < 500)) return false;
    return true;
  });

  return (
    <div className="p-6 space-y-5 max-w-screen-2xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Scan Request Telemetry</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Every HTTP request made by the orchestration engine — {total.toLocaleString()} total records
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
      <div className="flex items-center gap-3 flex-wrap rounded-xl border bg-card p-3">
        <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            className="pl-8 h-8 text-xs w-60"
            placeholder="Filter by URL…"
            value={searchUrl}
            onChange={e => { setSearchUrl(e.target.value); setPage(1); }}
          />
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
          <Switch id="waf-filter" checked={filterWaf} onCheckedChange={setFilterWaf} />
          <Label htmlFor="waf-filter" className="text-xs cursor-pointer">WAF only</Label>
        </div>
        <div className="flex items-center gap-2">
          <Switch id="cap-filter" checked={filterCaptcha} onCheckedChange={setFilterCaptcha} />
          <Label htmlFor="cap-filter" className="text-xs cursor-pointer">Captcha only</Label>
        </div>
        {(searchUrl || filterStatus !== "all" || filterWaf || filterCaptcha) && (
          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setSearchUrl(""); setFilterStatus("all"); setFilterWaf(false); setFilterCaptcha(false); }}>
            Clear
          </Button>
        )}
        <span className="ml-auto text-xs text-muted-foreground">{filtered.length} shown</span>
      </div>

      {/* Table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b bg-muted/40 text-muted-foreground">
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Timestamp</th>
                <th className="px-3 py-2.5 text-left font-medium">Method</th>
                <th className="px-3 py-2.5 text-left font-medium">URL</th>
                <th className="px-3 py-2.5 text-left font-medium whitespace-nowrap">Proxy IP</th>
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
                    {Array.from({ length: 11 }).map((__, j) => (
                      <td key={j} className="px-3 py-2"><Skeleton className="h-3.5 w-full" /></td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={11} className="px-3 py-12 text-center text-muted-foreground">
                    {total === 0
                      ? "No telemetry yet — records appear once scans run."
                      : "No records match the current filters."}
                  </td>
                </tr>
              ) : filtered.map(row => (
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
                  <td className="px-3 py-2 max-w-xs truncate font-mono" title={row.url}>
                    {row.url.replace(/^https?:\/\//, "")}
                  </td>
                  <td className="px-3 py-2 font-mono text-muted-foreground whitespace-nowrap">
                    {row.proxyIp ?? <span className="text-muted-foreground/50">direct</span>}
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
                      ? <Shield className="w-3.5 h-3.5 text-red-500 mx-auto" aria-label="WAF detected" />
                      : <span className="text-muted-foreground/30">—</span>
                    }
                  </td>
                  <td className="px-3 py-2 text-center">
                    {row.captchaDetected
                      ? <AlertTriangle className="w-3.5 h-3.5 text-amber-500 mx-auto" aria-label="Captcha detected" />
                      : <span className="text-muted-foreground/30">—</span>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {pages > 1 && (
          <div className="px-4 py-3 border-t flex items-center justify-between bg-muted/20">
            <span className="text-xs text-muted-foreground">
              Page {page} of {pages} · {total.toLocaleString()} total records
            </span>
            <div className="flex gap-1.5">
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>
                Previous
              </Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" disabled={page >= pages} onClick={() => setPage(p => Math.min(pages, p + 1))}>
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
