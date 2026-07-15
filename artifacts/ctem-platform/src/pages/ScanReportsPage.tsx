import { useState } from "react";
import { Link, useLocation } from "wouter";
import {
  useListScans, useGetToolPipeline, useListAssets,
  getListScansQueryKey, getGetToolPipelineQueryKey,
} from "@workspace/api-client-react";
import {
  Zap, Shield, Network, AlertTriangle, CheckCircle2, Clock,
  Loader2, XCircle, Search, Filter, ExternalLink, RefreshCw,
  Calendar, Timer, Database, ChevronsLeft, ChevronsRight, ChevronLeft, ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import RunScanDialog from "@/components/scan/RunScanDialog";
import { useQueryClient } from "@tanstack/react-query";

const statusConfig: Record<string, { cls: string; icon: React.ElementType; label: string }> = {
  completed: { cls: "bg-green-500/10 text-green-400 border-green-500/30", icon: CheckCircle2, label: "Completed" },
  running:   { cls: "bg-blue-500/10 text-blue-400 border-blue-500/30",  icon: Loader2,      label: "Running" },
  pending:   { cls: "bg-amber-500/10 text-amber-400 border-amber-500/30", icon: Clock,       label: "Pending" },
  failed:    { cls: "bg-red-500/10 text-red-400 border-red-500/30",     icon: XCircle,      label: "Failed" },
  cancelled: { cls: "bg-muted text-muted-foreground border-border",      icon: XCircle,      label: "Cancelled" },
};

function formatDur(startedAt: string, completedAt: string): string {
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  const sec = Math.max(0, Math.round(ms / 1000));
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

function formatRelative(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ScanReportsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [showRunScan, setShowRunScan] = useState(false);
  const qc = useQueryClient();

  const { data: scansRaw, isLoading, refetch } = useListScans({} as any, {
    query: {
      queryKey: getListScansQueryKey({} as any),
      staleTime: 0,
      refetchInterval: (q) => {
        const data = q.state.data as any[];
        if (!data || data?.some((s: any) => s.status === "running" || s.status === "pending")) return 4000;
        return 30_000;
      },
    },
  });
  const { data: pipelineData } = useGetToolPipeline({ query: { queryKey: getGetToolPipelineQueryKey() } });
  const { data: assetsData } = useListAssets();

  const PAGE_SIZE = 10;
  const [page, setPage] = useState(1);

  const allScans = (scansRaw as any[]) ?? [];
  const pipeline = (pipelineData as any[]) ?? [];
  const allAssets = (assetsData as any[]) ?? [];

  const pipelineTools = pipeline.map((s: any) => ({
    id: s.toolId, name: s.toolName, category: s.toolCategory, isActive: s.isEnabled,
  }));

  const filtered = allScans.filter((s: any) => {
    const matchSearch = !search || s.name?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const totalCompleted = allScans.filter((s: any) => s.status === "completed").length;
  const totalRunning   = allScans.filter((s: any) => s.status === "running").length;
  const totalFindings  = allScans.reduce((acc: number, s: any) => acc + (s.findingsCount ?? 0), 0);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Scan Reports</h1>
          <p className="text-sm text-muted-foreground">
            {allScans.length} pipeline scan{allScans.length !== 1 ? "s" : ""} ·{" "}
            {totalFindings} total findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          <Button size="sm" onClick={() => setShowRunScan(true)} className="bg-primary/90 hover:bg-primary">
            <Zap className="w-3.5 h-3.5 mr-1.5" /> Run New Scan
          </Button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-green-500/10 flex items-center justify-center">
            <CheckCircle2 className="w-4.5 h-4.5 text-green-400" />
          </div>
          <div>
            <p className="text-lg font-bold">{totalCompleted}</p>
            <p className="text-xs text-muted-foreground">Completed</p>
          </div>
        </div>
        <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-500/10 flex items-center justify-center">
            <Loader2 className={cn("w-4.5 h-4.5 text-blue-400", totalRunning > 0 && "animate-spin")} />
          </div>
          <div>
            <p className="text-lg font-bold">{totalRunning}</p>
            <p className="text-xs text-muted-foreground">Running Now</p>
          </div>
        </div>
        <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-orange-500/10 flex items-center justify-center">
            <AlertTriangle className="w-4.5 h-4.5 text-orange-400" />
          </div>
          <div>
            <p className="text-lg font-bold">{totalFindings}</p>
            <p className="text-xs text-muted-foreground">Total Findings</p>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="Search scans…"
            className="pl-8 h-8 text-sm"
          />
        </div>
        <Select value={statusFilter} onValueChange={v => { setStatusFilter(v); setPage(1); }}>
          <SelectTrigger className="w-36 h-8 text-sm">
            <Filter className="w-3.5 h-3.5 mr-1.5 text-muted-foreground" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="cancelled">Cancelled</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Scan list */}
      <div className="space-y-2">
        {isLoading && [...Array(4)].map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}

        {!isLoading && filtered.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-10 text-center">
            <Shield className="w-10 h-10 text-muted-foreground mx-auto mb-3 opacity-40" />
            <p className="text-sm font-medium">
              {allScans.length === 0 ? "No scans yet" : "No scans match your filters"}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {allScans.length === 0
                ? "Run your first pipeline scan to see results here"
                : "Try adjusting the search or status filter"}
            </p>
            {allScans.length === 0 && (
              <Button size="sm" className="mt-4" onClick={() => setShowRunScan(true)}>
                <Zap className="w-3.5 h-3.5 mr-1.5" /> Run First Scan
              </Button>
            )}
          </div>
        )}

        {paginated.map((scan: any) => {
          const cfg = statusConfig[scan.status] ?? statusConfig.cancelled;
          const StatusIcon = cfg.icon;
          const isRunning = scan.status === "running" || scan.status === "pending";
          const hasReport = scan.status === "completed";
          const findings = scan.findingsCount ?? 0;

          return (
            <div
              key={scan.id}
              className="bg-card border border-border rounded-xl p-4 hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => navigate(`/scan-reports/${scan.id}`)}
            >
              <div className="flex items-start gap-4">
                {/* Status icon */}
                <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border", cfg.cls)}>
                  <StatusIcon className={cn("w-5 h-5", isRunning && "animate-spin")} />
                </div>

                {/* Main info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className="text-sm font-semibold truncate">
                      {scan.name ?? `Scan Report — ${new Date(scan.createdAt ?? scan.startedAt).toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" })}`}
                    </p>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium shrink-0", cfg.cls)}>
                      {cfg.label}
                    </span>
                    {isRunning && (
                      <span className="text-[10px] text-blue-400 animate-pulse">Live…</span>
                    )}
                  </div>

                  {/* Meta row */}
                  <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-muted-foreground">
                    {scan.startedAt && (
                      <span className="flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(scan.startedAt).toLocaleString()}
                        <span className="text-muted-foreground/60">({formatRelative(scan.startedAt)})</span>
                      </span>
                    )}
                    {scan.completedAt && scan.startedAt && (
                      <span className="flex items-center gap-1">
                        <Timer className="w-3 h-3" />
                        {formatDur(scan.startedAt, scan.completedAt)}
                      </span>
                    )}
                    {(scan.assetIds?.length ?? 0) > 0 && (
                      <span className="flex items-center gap-1">
                        <Database className="w-3 h-3" />
                        {scan.assetIds?.length ?? 0} asset{(scan.assetIds?.length ?? 0) !== 1 ? "s" : ""}
                      </span>
                    )}
                  </div>

                  {/* Findings summary */}
                  {(hasReport || findings > 0) && (
                    <div className="flex gap-2 mt-2.5">
                      {findings > 0 ? (
                        <>
                          <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/25 px-2 py-0.5 rounded-full flex items-center gap-1">
                            <AlertTriangle className="w-2.5 h-2.5" />
                            {findings} finding{findings !== 1 ? "s" : ""}
                          </span>
                          <span className="text-[10px] bg-accent/40 text-muted-foreground border border-border px-2 py-0.5 rounded-full flex items-center gap-1">
                            <Network className="w-2.5 h-2.5" />
                            View full report →
                          </span>
                        </>
                      ) : (
                        <span className="text-[10px] bg-green-500/10 text-green-400 border border-green-500/25 px-2 py-0.5 rounded-full flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5" />
                          No findings
                        </span>
                      )}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="shrink-0">
                  {hasReport ? (
                    <Link href={`/scan-reports/${scan.id}`}>
                      <Button size="sm" className="h-8 text-xs bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25" variant="ghost">
                        <ExternalLink className="w-3.5 h-3.5 mr-1.5" />
                        View Report
                      </Button>
                    </Link>
                  ) : isRunning ? (
                    <Link href={`/scan-reports/${scan.id}`}>
                      <Button size="sm" variant="outline" className="h-8 text-xs border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                        <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
                        Live View
                      </Button>
                    </Link>
                  ) : (
                    <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground" disabled>
                      No Report
                    </Button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-1 gap-2 flex-wrap">
          <p className="text-xs text-muted-foreground">
            Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length} scans
          </p>
          <div className="flex items-center gap-1">
            {/* Go to first */}
            <Button
              size="sm" variant="outline" className="h-7 w-7 p-0"
              disabled={page === 1} onClick={() => setPage(1)}
              title="First page"
            >
              <ChevronsLeft className="w-3.5 h-3.5" />
            </Button>
            {/* Previous */}
            <Button
              size="sm" variant="outline" className="h-7 w-7 p-0"
              disabled={page === 1} onClick={() => setPage(p => p - 1)}
              title="Previous page"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>

            {/* Smart page numbers */}
            {(() => {
              const SIBLING = 2;
              const pages: (number | "...")[] = [];
              const rangeStart = Math.max(2, page - SIBLING);
              const rangeEnd   = Math.min(totalPages - 1, page + SIBLING);

              pages.push(1);
              if (rangeStart > 2) pages.push("...");
              for (let i = rangeStart; i <= rangeEnd; i++) pages.push(i);
              if (rangeEnd < totalPages - 1) pages.push("...");
              if (totalPages > 1) pages.push(totalPages);

              return pages.map((p, idx) =>
                p === "..." ? (
                  <span key={`ellipsis-${idx}`} className="h-7 w-6 flex items-center justify-center text-xs text-muted-foreground select-none">
                    …
                  </span>
                ) : (
                  <Button
                    key={p}
                    size="sm"
                    variant={p === page ? "default" : "outline"}
                    className="h-7 w-7 p-0 text-xs"
                    onClick={() => setPage(p)}
                  >
                    {p}
                  </Button>
                )
              );
            })()}

            {/* Next */}
            <Button
              size="sm" variant="outline" className="h-7 w-7 p-0"
              disabled={page === totalPages} onClick={() => setPage(p => p + 1)}
              title="Next page"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
            {/* Go to last */}
            <Button
              size="sm" variant="outline" className="h-7 w-7 p-0"
              disabled={page === totalPages} onClick={() => setPage(totalPages)}
              title="Last page"
            >
              <ChevronsRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}

      {/* Run Scan Dialog */}
      <RunScanDialog
        open={showRunScan}
        onOpenChange={setShowRunScan}
        pipelineTools={pipelineTools}
        assets={allAssets.map((a: any) => ({ id: a.id, name: a.name, value: a.value, type: a.type, verificationStatus: a.verificationStatus }))}
        onRunComplete={scanId => {
          qc.invalidateQueries({ queryKey: getListScansQueryKey({} as any) });
          navigate(`/scan-reports/${scanId}`);
        }}
      />
    </div>
  );
}
