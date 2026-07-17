import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Newspaper, Search, RefreshCw, ExternalLink, Calendar,
  Loader2, CheckCircle2, XCircle, Clock, X, Radio,
  ChevronDown, AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

/* ── Severity styles ─────────────────────────────────────────────────────── */
const SEV: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/25",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/25",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/25",
  info:     "text-muted-foreground bg-muted border-border",
};

/* ── Source badge styles ─────────────────────────────────────────────────── */
const SOURCE_STYLE: Record<string, string> = {
  hackernews:       "text-red-400 bg-red-500/10 border-red-500/20",
  bleepingcomputer: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  krebsonsecurity:  "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  darkreading:      "text-purple-400 bg-purple-500/10 border-purple-500/20",
  securityweek:     "text-blue-400 bg-blue-500/10 border-blue-500/20",
  cybersecuritynews:"text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
  grahamcluley:     "text-green-400 bg-green-500/10 border-green-500/20",
  sans_isc:         "text-pink-400 bg-pink-500/10 border-pink-500/20",
};

/* ── Daily auto-refresh status ───────────────────────────────────────────── */
function DailyRefreshBadge({ sources }: { sources: any[] }) {
  const completedAts = sources
    .map(s => s.completedAt ? new Date(s.completedAt).getTime() : null)
    .filter(Boolean) as number[];

  if (completedAts.length === 0) return null;

  const mostRecent = Math.max(...completedAts);
  const nextRun = mostRecent + 24 * 3_600_000;
  const now = Date.now();
  const diffMs = nextRun - now;

  let label: string;
  if (diffMs <= 0) {
    label = "Next auto-refresh: any moment";
  } else {
    const hrs = Math.floor(diffMs / 3_600_000);
    const mins = Math.floor((diffMs % 3_600_000) / 60_000);
    label = hrs > 0 ? `Next auto-refresh in ${hrs}h ${mins}m` : `Next auto-refresh in ${mins}m`;
  }

  return (
    <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-500/10 border border-green-500/20 text-[10px] text-green-400">
      <Radio className="w-3 h-3 shrink-0" />
      <span>{label}</span>
    </div>
  );
}

/* ── Source status panel ─────────────────────────────────────────────────── */
function SourceStatusPanel({
  sources,
  onRefreshSource,
  refreshingSource,
  isAdmin,
}: {
  sources: any[];
  onRefreshSource: (id?: string) => void;
  refreshingSource: string | null;
  isAdmin: boolean;
}) {
  const statusIcon = (status: string) => {
    if (status === "completed") return <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />;
    if (status === "failed")    return <XCircle className="w-3.5 h-3.5 text-red-400" />;
    if (status === "running")   return <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />;
    return <Clock className="w-3.5 h-3.5 text-muted-foreground/50" />;
  };

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio className="w-3.5 h-3.5 text-primary" />
          <span className="text-xs font-semibold">News Sources</span>
          <span className="text-[10px] text-muted-foreground">({sources.length} configured)</span>
        </div>
        {isAdmin && (
          <Button size="sm" variant="outline" className="h-6 text-[10px] px-2"
            onClick={() => onRefreshSource(undefined)}
            disabled={refreshingSource === "all"}>
            {refreshingSource === "all"
              ? <Loader2 className="w-3 h-3 animate-spin mr-1" />
              : <RefreshCw className="w-3 h-3 mr-1" />}
            Fetch All
          </Button>
        )}
      </div>

      {/* Daily auto-refresh indicator */}
      {sources.some(s => s.completedAt) && (
        <div className="px-4 pt-2.5 pb-1">
          <DailyRefreshBadge sources={sources} />
        </div>
      )}

      <div className="divide-y divide-border/50">
        {sources.map(s => (
          <div key={s.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 min-w-0">
              {statusIcon(s.status)}
              <div className="min-w-0">
                <p className="text-xs font-medium truncate">{s.displayName}</p>
                <p className="text-[10px] text-muted-foreground truncate">
                  {s.status === "never"
                    ? "Never fetched"
                    : s.status === "running"
                    ? "Fetching…"
                    : s.status === "failed"
                    ? `Error: ${s.error ?? "unknown"}`
                    : s.completedAt
                    ? `${s.recordsAdded} new · ${new Date(s.completedAt).toLocaleString()}`
                    : "Unknown"}
                </p>
              </div>
            </div>
            {isAdmin && (
              <Button size="sm" variant="ghost" className="h-6 text-[10px] px-2 shrink-0"
                onClick={() => onRefreshSource(s.id)}
                disabled={!!refreshingSource}>
                {refreshingSource === s.id
                  ? <Loader2 className="w-3 h-3 animate-spin" />
                  : <RefreshCw className="w-3 h-3" />}
              </Button>
            )}
          </div>
        ))}
        {sources.length === 0 && (
          <div className="px-4 py-4 text-center text-xs text-muted-foreground">Loading sources…</div>
        )}
      </div>
    </div>
  );
}

/* ── News article card ───────────────────────────────────────────────────── */
function NewsCard({ n }: { n: any }) {
  const srcStyle = SOURCE_STYLE[n.source] ?? "text-muted-foreground bg-muted border-border";
  const sevStyle = SEV[n.severity] ?? SEV.info;

  const date = n.publishedAt || n.createdAt;

  return (
    <div className="bg-card border border-border rounded-xl p-4 space-y-2.5 hover:border-primary/30 transition-colors">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-1.5 mb-1">
            {/* Source badge */}
            <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium shrink-0", srcStyle)}>
              {n.sourceName ?? n.source}
            </span>
            {/* Severity badge */}
            {n.severity && n.severity !== "info" && (
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize shrink-0", sevStyle)}>
                {n.severity}
              </span>
            )}
          </div>
          <p className="font-semibold text-sm leading-snug">{n.title}</p>
        </div>
        {/* Date */}
        {date && (
          <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1 shrink-0 mt-1">
            <Calendar className="w-2.5 h-2.5" />
            {new Date(date).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
          </span>
        )}
      </div>

      {/* Summary */}
      {n.summary && (
        <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">{n.summary}</p>
      )}

      {/* CVEs */}
      {n.cves?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {(n.cves as string[]).slice(0, 5).map((c: string) => (
            <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 font-mono">{c}</span>
          ))}
        </div>
      )}

      {/* Tags */}
      {n.tags?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {(n.tags as string[]).slice(0, 6).map((t: string) => (
            <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{t}</span>
          ))}
        </div>
      )}

      {/* Actors */}
      {n.actors?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {(n.actors as string[]).slice(0, 3).map((a: string) => (
            <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">{a}</span>
          ))}
        </div>
      )}

      {/* Read more */}
      {n.url && (
        <a href={n.url} target="_blank" rel="noopener noreferrer"
          className="text-[11px] text-primary hover:underline flex items-center gap-1 mt-1">
          Read full article <ExternalLink className="w-3 h-3" />
        </a>
      )}
    </div>
  );
}

/* ── Main page ──────────────────────────────────────────────────────────── */
export default function ThreatIntelNewsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [page, setPage] = useState(0);
  const [showSources, setShowSources] = useState(true);
  const [refreshingSource, setRefreshingSource] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const L = 20;

  /* ── Queries ── */
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-news", q, severity, source, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q)        p.set("q", q);
      if (severity) p.set("severity", severity);
      if (source)   p.set("source", source);
      return apiFetch<any>(`${BASE}/api/threat-intel/news?${p}`);
    },
    staleTime: 30_000,
  });

  const { data: sourcesData, refetch: refetchSources } = useQuery({
    queryKey: ["ti-news-sources"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/news/sources`),
    staleTime: 10_000,
    refetchInterval: refreshingSource ? 5_000 : false,
  });

  const sources: any[] = sourcesData?.sources ?? [];
  const news: any[] = data?.news ?? [];
  const total = data?.total ?? 0;
  const hasFilters = !!(q || severity || source);

  /* ── Refresh mutation ── */
  const refreshMutation = useMutation({
    mutationFn: (sourceId?: string) =>
      apiFetch<any>(`${BASE}/api/threat-intel/news/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source: sourceId }),
      }),
    onSuccess: (_, sourceId) => {
      setRefreshingSource(sourceId ?? "all");
      toast({
        title: "Fetching news…",
        description: sourceId
          ? `Pulling latest articles from ${sources.find(s => s.id === sourceId)?.displayName ?? sourceId}…`
          : "Pulling from all 8 cybersecurity news sources. This takes 15–30s.",
      });
      // Poll for completion
      pollingRef.current = setInterval(async () => {
        await refetchSources();
        const updated = (await qc.fetchQuery({ queryKey: ["ti-news-sources"], queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/news/sources`) })).sources as any[];
        const relevant = sourceId ? updated.filter(s => s.id === sourceId) : updated;
        const allDone = relevant.every(s => s.status !== "running" && s.status !== "never" || s.completedAt);
        const anyDone = relevant.some(s => s.status === "completed");
        if (anyDone || allDone) {
          clearInterval(pollingRef.current!);
          setRefreshingSource(null);
          await refetch();
          toast({ title: "News updated", description: `Latest threat intelligence articles loaded.` });
        }
      }, 4_000);
    },
    onError: () => {
      setRefreshingSource(null);
      toast({ title: "Refresh failed", variant: "destructive" });
    },
  });

  // Cleanup polling on unmount
  useEffect(() => () => { if (pollingRef.current) clearInterval(pollingRef.current); }, []);

  // Stop polling after 120s max
  useEffect(() => {
    if (!refreshingSource) return;
    const maxTimer = setTimeout(() => {
      clearInterval(pollingRef.current!);
      setRefreshingSource(null);
      refetch();
    }, 120_000);
    return () => clearTimeout(maxTimer);
  }, [refreshingSource]);

  return (
    <div className="p-6 space-y-4">

      {/* ── Header ── */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Newspaper className="w-5 h-5 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Threat News</h1>
            <p className="text-xs text-muted-foreground">
              {total.toLocaleString()} articles from {sources.length} cybersecurity sources
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button size="sm"
              onClick={() => refreshMutation.mutate(undefined)}
              disabled={!!refreshingSource || refreshMutation.isPending}>
              {(refreshingSource === "all" || refreshMutation.isPending)
                ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
              Fetch Latest News
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* ── Live fetch banner ── */}
      {refreshingSource && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
          <Loader2 className="w-4 h-4 animate-spin shrink-0" />
          <span>Fetching latest cybersecurity news from {refreshingSource === "all" ? "all sources" : sources.find(s => s.id === refreshingSource)?.displayName ?? refreshingSource}… articles will appear shortly.</span>
        </div>
      )}

      {/* ── Empty state with call-to-action ── */}
      {!isLoading && total === 0 && !refreshingSource && (
        <div className="rounded-xl border border-border bg-card p-8 text-center space-y-3">
          <Newspaper className="w-10 h-10 text-muted-foreground/30 mx-auto" />
          <p className="text-sm font-medium">No news articles yet</p>
          <p className="text-xs text-muted-foreground max-w-sm mx-auto">
            News is fetched live from 8 real cybersecurity sources including The Hacker News, BleepingComputer,
            Krebs on Security, Dark Reading, and more.
          </p>
          {isAdmin ? (
            <Button size="sm" onClick={() => refreshMutation.mutate(undefined)} disabled={refreshMutation.isPending} className="mt-2">
              {refreshMutation.isPending
                ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                : <RefreshCw className="w-3.5 h-3.5 mr-1.5" />}
              Fetch News Now
            </Button>
          ) : (
            <p className="text-xs text-muted-foreground">Ask an admin to run the first news fetch.</p>
          )}
        </div>
      )}

      {/* ── Main layout: Sources panel + Articles ── */}
      <div className="flex gap-4 items-start">

        {/* ── Sources sidebar ── */}
        <div className={cn("w-64 shrink-0 space-y-2 hidden lg:block", !showSources && "lg:hidden")}>
          <SourceStatusPanel
            sources={sources}
            onRefreshSource={id => refreshMutation.mutate(id)}
            refreshingSource={refreshingSource}
            isAdmin={isAdmin}
          />
          {/* Source quick-filter chips */}
          {sources.length > 0 && (
            <div className="bg-card border border-border rounded-xl p-3 space-y-1.5">
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Filter by Source</p>
              <button
                onClick={() => { setSource(""); setPage(0); }}
                className={cn("w-full text-left text-xs px-2 py-1 rounded transition-colors", !source ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted/40")}>
                All sources
              </button>
              {sources.map(s => (
                <button key={s.id}
                  onClick={() => { setSource(source === s.id ? "" : s.id); setPage(0); }}
                  className={cn("w-full text-left text-xs px-2 py-1 rounded transition-colors flex items-center justify-between",
                    source === s.id ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted/40")}>
                  <span className="truncate">{s.displayName}</span>
                  {source === s.id && <X className="w-3 h-3 shrink-0" />}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Articles column ── */}
        <div className="flex-1 min-w-0 space-y-3">

          {/* Filters row */}
          <div className="flex flex-wrap gap-2">
            <div className="relative flex-1 min-w-48">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input placeholder="Search articles…" value={q}
                onChange={e => { setQ(e.target.value); setPage(0); }}
                className="h-8 pl-8 text-xs" />
            </div>
            <Select value={severity || "all"} onValueChange={v => { setSeverity(v === "all" ? "" : v); setPage(0); }}>
              <SelectTrigger className="h-8 w-36 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All severity</SelectItem>
                {["critical", "high", "medium", "low", "info"].map(s => (
                  <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {/* Mobile source select */}
            <Select value={source || "all"} onValueChange={v => { setSource(v === "all" ? "" : v); setPage(0); }}>
              <SelectTrigger className="h-8 w-44 text-xs lg:hidden"><SelectValue placeholder="Source" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All sources</SelectItem>
                {sources.map(s => <SelectItem key={s.id} value={s.id}>{s.displayName}</SelectItem>)}
              </SelectContent>
            </Select>
            {hasFilters && (
              <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
                onClick={() => { setQ(""); setSeverity(""); setSource(""); setPage(0); }}>
                <X className="w-3.5 h-3.5 mr-1" />Clear
              </Button>
            )}
          </div>

          {/* Source + severity filter indicators */}
          {(source || severity) && (
            <div className="flex flex-wrap gap-1.5">
              {source && (
                <div className={cn("flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-medium", SOURCE_STYLE[source] ?? "bg-muted border-border text-muted-foreground")}>
                  {sources.find(s => s.id === source)?.displayName ?? source}
                  <button onClick={() => { setSource(""); setPage(0); }}><X className="w-2.5 h-2.5" /></button>
                </div>
              )}
              {severity && (
                <div className={cn("flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-semibold capitalize", SEV[severity] ?? SEV.info)}>
                  {severity}
                  <button onClick={() => { setSeverity(""); setPage(0); }}><X className="w-2.5 h-2.5" /></button>
                </div>
              )}
            </div>
          )}

          {/* Article list */}
          {isLoading
            ? Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)
            : news.map((n: any) => <NewsCard key={n.id} n={n} />)
          }

          {!isLoading && news.length === 0 && total > 0 && (
            <div className="text-center py-8 text-sm text-muted-foreground">
              No articles match your filters.
            </div>
          )}

          {/* Pagination */}
          {total > L && (
            <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
              <span>Showing {page * L + 1}–{Math.min((page + 1) * L, total)} of {total.toLocaleString()}</span>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</Button>
                <Button size="sm" variant="outline" disabled={(page + 1) * L >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
