import { useState, useEffect, useRef } from "react";
import { SmartPagination } from "@/components/ui/SmartPagination";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Eye, RefreshCw, Shield, AlertTriangle, Calendar, Search,
  Loader2, ExternalLink, X, Globe, Server, CheckCircle2,
  Clock, Radio, Building2, ChevronLeft, ChevronRight,
  Activity, Database, Lock, Filter, TrendingUp, Zap,
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

/* ── Severity config ─────────────────────────────────────────────────────── */
const SEV: Record<string, { badge: string; row: string; bar: string; dot: string; glow: string }> = {
  critical: { badge: "text-red-400 bg-red-500/10 border-red-500/30",     row: "border-l-red-500",    bar: "bg-red-500",    dot: "bg-red-400",    glow: "shadow-red-500/20" },
  high:     { badge: "text-orange-400 bg-orange-500/10 border-orange-500/30", row: "border-l-orange-500", bar: "bg-orange-500", dot: "bg-orange-400", glow: "shadow-orange-500/20" },
  medium:   { badge: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30", row: "border-l-yellow-500", bar: "bg-yellow-400", dot: "bg-yellow-400", glow: "shadow-yellow-500/20" },
  low:      { badge: "text-green-400 bg-green-500/10 border-green-500/30",  row: "border-l-green-500",  bar: "bg-green-500",  dot: "bg-green-400",  glow: "shadow-green-500/20" },
};

/* ── Source config ───────────────────────────────────────────────────────── */
const SRC: Record<string, { badge: string; icon: string; color: string }> = {
  "HIBP":      { badge: "text-blue-400 bg-blue-500/10 border-blue-500/20",       icon: "💧", color: "text-blue-400" },
  "URLScan":   { badge: "text-purple-400 bg-purple-500/10 border-purple-500/20",  icon: "🔍", color: "text-purple-400" },
  "ThreatFox": { badge: "text-red-400 bg-red-500/10 border-red-500/20",           icon: "🦊", color: "text-red-400" },
  "URLHaus":   { badge: "text-orange-400 bg-orange-500/10 border-orange-500/20",  icon: "🏠", color: "text-orange-400" },
  "crt.sh":    { badge: "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",        icon: "🔒", color: "text-cyan-400" },
};

const MENTION_TYPE_LABEL: Record<string, string> = {
  data_breach:      "Data Breach",
  malware_ioc:      "Malware IOC",
  malicious_host:   "Malicious Host",
  malicious_url:    "Malicious URL",
  lookalike_domain: "Lookalike Domain",
  general:          "Mention",
};

/* ── Mention card ────────────────────────────────────────────────────────── */
function MentionCard({ m }: { m: any }) {
  const sev = m.severity ?? m.riskLevel ?? "medium";
  const sevMeta = SEV[sev] ?? SEV.medium;
  const src = m.source ?? m.sourceType ?? "";
  const srcMeta = SRC[src];
  const url = m.sourceUrl ?? m.url ?? "";
  const snippet = m.content ?? m.snippet ?? "";
  const title = m.title ?? m.sourceType ?? src ?? "Unknown Finding";

  return (
    <div className={cn(
      "bg-card border border-l-4 rounded-xl overflow-hidden transition-all hover:shadow-lg",
      sevMeta.row, sevMeta.glow,
    )}>
      <div className="p-4 space-y-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {srcMeta ? (
              <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold shrink-0", srcMeta.badge)}>
                {srcMeta.icon} {src}
              </span>
            ) : src ? (
              <span className="text-[10px] px-2 py-0.5 rounded-full border bg-muted border-border text-muted-foreground font-medium">{src}</span>
            ) : null}
            <span className="text-[10px] text-muted-foreground/60 bg-muted/40 border border-border/50 px-1.5 py-0.5 rounded-full">
              {MENTION_TYPE_LABEL[m.mentionType] ?? m.mentionType ?? "Mention"}
            </span>
            {m.isVerified && (
              <span className="text-[10px] text-green-400 flex items-center gap-0.5 font-medium">
                <CheckCircle2 className="w-2.5 h-2.5" />Verified
              </span>
            )}
          </div>
          <div className="flex flex-col items-end gap-1 shrink-0">
            <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize", sevMeta.badge)}>{sev}</span>
            {(m.detectedAt ?? m.createdAt) && (
              <span className="text-[10px] text-muted-foreground/50 flex items-center gap-1">
                <Calendar className="w-2.5 h-2.5" />
                {new Date(m.detectedAt ?? m.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
              </span>
            )}
          </div>
        </div>

        <div>
          <p className="font-semibold text-sm leading-snug">{title}</p>
          {m.assetDomain && (
            <p className="text-[10px] font-mono text-muted-foreground/60 flex items-center gap-1 mt-0.5">
              <Globe className="w-2.5 h-2.5" />{m.assetDomain}
              {m.tenantName && <span className="text-muted-foreground/40">· {m.tenantName}</span>}
            </p>
          )}
        </div>

        {snippet && (
          <div className="bg-muted/30 border border-border/40 rounded-lg p-2.5">
            <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">{snippet}</p>
          </div>
        )}

        {m.keywords?.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {(m.keywords as string[]).slice(0, 6).map((k: string) => (
              <span key={k} className="text-[9px] px-1.5 py-0.5 rounded-full bg-red-500/8 border border-red-500/20 text-red-400 font-mono">{k}</span>
            ))}
            {m.keywords.length > 6 && <span className="text-[9px] text-muted-foreground/40 self-center">+{m.keywords.length - 6}</span>}
          </div>
        )}

        {url && (
          <a href={url} target="_blank" rel="noopener noreferrer"
            className="text-[11px] text-primary hover:underline flex items-center gap-1 w-fit">
            View source <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
    </div>
  );
}

/* ── Asset sidebar ───────────────────────────────────────────────────────── */
function AssetsSidebar({
  assets, selectedDomain, onSelect, totalFindings,
}: {
  assets: any[];
  selectedDomain: string;
  onSelect: (d: string) => void;
  totalFindings: number;
}) {
  const sorted = [...assets].sort((a, b) => b.mentionCount - a.mentionCount);
  const maxCount = sorted[0]?.mentionCount ?? 1;

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden flex flex-col">
      {/* Header */}
      <div className="px-3 py-2.5 border-b border-border bg-muted/20 flex items-center gap-2">
        <Server className="w-3.5 h-3.5 text-primary shrink-0" />
        <span className="text-xs font-semibold flex-1">Monitored Assets</span>
        <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded tabular-nums">{assets.length}</span>
      </div>

      {/* All assets row */}
      <button
        onClick={() => onSelect("")}
        className={cn(
          "w-full text-left px-3 py-2.5 flex items-center justify-between text-xs transition-colors border-b border-border/40",
          !selectedDomain ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted/30",
        )}>
        <span className="font-medium flex items-center gap-1.5">
          <Globe className="w-3 h-3" />All assets
        </span>
        <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded tabular-nums", !selectedDomain ? "bg-primary/20 text-primary" : "text-muted-foreground")}>
          {totalFindings.toLocaleString()}
        </span>
      </button>

      {/* Per-asset rows */}
      <div className="divide-y divide-border/30 overflow-y-auto" style={{ maxHeight: "calc(100vh - 420px)" }}>
        {sorted.map(a => {
          const isSelected = selectedDomain === a.domain;
          const pct = maxCount > 0 ? Math.round((a.mentionCount / maxCount) * 100) : 0;
          return (
            <button key={a.id}
              onClick={() => onSelect(isSelected ? "" : (a.domain ?? ""))}
              className={cn(
                "w-full text-left px-3 py-2.5 flex flex-col gap-1.5 transition-colors group",
                isSelected ? "bg-primary/10" : "hover:bg-muted/20",
              )}>
              <div className="flex items-start justify-between gap-1.5">
                <div className="min-w-0 flex-1">
                  <p className={cn("font-mono text-[10px] truncate font-semibold leading-tight", isSelected ? "text-primary" : "text-foreground")}>
                    {a.domain ?? a.value ?? a.name}
                  </p>
                  {(a.tenantName || a.type) && (
                    <p className="text-[9px] text-muted-foreground/50 mt-0.5 truncate">{[a.tenantName, a.type].filter(Boolean).join(" · ")}</p>
                  )}
                </div>
                <span className={cn(
                  "text-[10px] px-1.5 py-0.5 rounded shrink-0 font-bold tabular-nums mt-0.5",
                  a.mentionCount >= 5 ? "bg-red-500/15 border border-red-500/20 text-red-400"
                    : a.mentionCount > 0 ? "bg-orange-500/10 border border-orange-500/20 text-orange-400"
                    : "text-muted-foreground/30",
                )}>{a.mentionCount}</span>
              </div>
              {/* mini progress bar */}
              {a.mentionCount > 0 && (
                <div className="w-full h-0.5 rounded-full bg-muted/40 overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all", a.mentionCount >= 5 ? "bg-red-500" : "bg-orange-500")}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              )}
            </button>
          );
        })}
        {assets.length === 0 && (
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">
            <Server className="w-6 h-6 mx-auto mb-2 opacity-20" />
            No monitored assets
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Source breakdown sidebar card ───────────────────────────────────────── */
function SourcesSidebar({ counts, active, onToggle }: { counts: Record<string, number>; active: string; onToggle: (s: string) => void }) {
  const entries = Object.entries(counts).sort(([, a], [, b]) => b - a);
  if (entries.length === 0) return null;
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-3 py-2.5 border-b border-border bg-muted/20 flex items-center gap-2">
        <Filter className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
        <span className="text-xs font-semibold">Sources</span>
      </div>
      <div className="p-2 space-y-0.5">
        {entries.map(([s, cnt]) => {
          const meta = SRC[s];
          const isActive = active === s;
          return (
            <button key={s}
              onClick={() => onToggle(s)}
              className={cn(
                "w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs transition-colors",
                isActive ? (meta?.badge ?? "bg-muted border border-border text-foreground") : "text-muted-foreground hover:bg-muted/40",
              )}>
              <span className="flex items-center gap-2">
                <span className="text-sm">{meta?.icon ?? "•"}</span>
                <span className="font-medium">{s}</span>
              </span>
              <span className="font-bold tabular-nums">{cnt}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ── Main page ───────────────────────────────────────────────────────────── */
export default function ThreatIntelDarkWebPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSrc] = useState("");
  const [assetDomain, setAssetDomain] = useState("");
  const [page, setPage] = useState(0);
  const [scanning, setScanning] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const L = 20;

  /* ── Queries ── */
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-dark-web", q, severity, source, assetDomain, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q)           p.set("q", q);
      if (severity)    p.set("severity", severity);
      if (source)      p.set("source", source);
      if (assetDomain) p.set("assetDomain", assetDomain);
      return apiFetch<any>(`${BASE}/api/threat-intel/dark-web?${p}`);
    },
    staleTime: 30_000,
  });

  const { data: assetsData, isLoading: assetsLoading } = useQuery({
    queryKey: ["ti-dark-web-assets"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dark-web/assets`),
    staleTime: 60_000,
  });

  const mentions: any[] = data?.mentions ?? [];
  const total = data?.total ?? 0;
  const allAssets: any[] = assetsData?.assets ?? [];
  const lastRun = data?.lastRun ?? null;
  const hasFilters = !!(q || severity || source || assetDomain);

  /* Stat counts — use server-provided counts when available, fall back to page slice */
  const critCount = data?.severityCounts?.critical ?? mentions.filter(m => (m.severity ?? m.riskLevel) === "critical").length;
  const highCount = data?.severityCounts?.high ?? mentions.filter(m => (m.severity ?? m.riskLevel) === "high").length;
  const verCount  = mentions.filter(m => m.isVerified).length;
  const totalMentionsAcrossAll = allAssets.reduce((s: number, a: any) => s + (a.mentionCount ?? 0), 0);

  /* Source breakdown from current page */
  const sourceCounts: Record<string, number> = {};
  for (const m of mentions) { const s = m.source ?? m.sourceType ?? "?"; sourceCounts[s] = (sourceCounts[s] ?? 0) + 1; }

  /* ── Scan mutation ── */
  const scanMutation = useMutation({
    mutationFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dark-web/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
    onSuccess: () => {
      setScanning(true);
      toast({ title: "Dark web scan started", description: "Checking HIBP, URLScan, ThreatFox, URLHaus & crt.sh. Results appear within 1–2 minutes." });
      pollingRef.current = setInterval(async () => {
        try {
          const result = await qc.fetchQuery({
            queryKey: ["ti-dark-web-poll"],
            queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dark-web?limit=1&offset=0`),
          });
          const run = result?.lastRun;
          if (run && run.status !== "running") {
            clearInterval(pollingRef.current!);
            setScanning(false);
            await refetch();
            await qc.invalidateQueries({ queryKey: ["ti-dark-web-assets"] });
            toast({ title: "Dark web scan complete", description: `${run.recordsAdded ?? 0} new findings detected.` });
          }
        } catch {}
      }, 5_000);
    },
    onError: () => { setScanning(false); toast({ title: "Scan failed", variant: "destructive" }); },
  });

  useEffect(() => () => { if (pollingRef.current) clearInterval(pollingRef.current); }, []);
  useEffect(() => {
    if (!scanning) return;
    const t = setTimeout(() => { clearInterval(pollingRef.current!); setScanning(false); refetch(); }, 180_000);
    return () => clearTimeout(t);
  }, [scanning]);

  const pages = Math.ceil(total / L);
  const clearFilters = () => { setQ(""); setSeverity(""); setSrc(""); setAssetDomain(""); setPage(0); };

  /* ── Determine layout mode ── */
  /* Always show the two-column layout if any assets are monitored (or loading).
     Never hide the sidebar just because the selected asset has 0 findings. */
  const showLayout = assetsLoading || allAssets.length > 0 || total > 0 || isLoading;

  return (
    <div className="p-6 space-y-5">

      {/* ── Page Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5 mb-1.5">
            <div className="p-2 rounded-xl bg-purple-500/15 border border-purple-500/25">
              <Eye className="w-5 h-5 text-purple-400" />
            </div>
            <h1 className="text-xl font-bold tracking-tight">Dark Web Monitoring</h1>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            <span className="text-xs">
              {totalMentionsAcrossAll.toLocaleString()} total findings across {allAssets.length} monitored assets
            </span>
            {lastRun?.completedAt && (
              <span className="flex items-center gap-1 text-[11px]">
                <Clock className="w-3 h-3" />
                Last scan: {new Date(lastRun.completedAt).toLocaleString()}
                {lastRun.recordsAdded > 0 && <span className="text-green-400 ml-1">+{lastRun.recordsAdded} new</span>}
              </span>
            )}
            {!lastRun && <span className="text-[11px] flex items-center gap-1 text-muted-foreground/70"><Clock className="w-3 h-3" />Never scanned</span>}
            {lastRun?.status === "running" && (
              <span className="text-[11px] text-blue-400 flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" />Scanning…</span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0 pt-1">
          {isAdmin && (
            <Button size="sm"
              onClick={() => scanMutation.mutate()}
              disabled={scanning || scanMutation.isPending}
              className={cn("gap-1.5 text-xs", scanning || scanMutation.isPending ? "" : "bg-purple-600 hover:bg-purple-700 text-white border-purple-600")}>
              {scanning || scanMutation.isPending
                ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Scanning…</>
                : <><Radio className="w-3.5 h-3.5" />Run Scan</>}
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()} className="h-9 w-9 p-0">
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* ── Scanning banner ── */}
      {scanning && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-purple-500/10 border border-purple-500/30 text-xs text-purple-300">
          <div className="w-2 h-2 rounded-full bg-purple-400 animate-pulse shrink-0" />
          <span className="font-semibold">Live scan in progress</span>
          <span className="text-purple-400/50">·</span>
          <span className="text-purple-400/80">Checking HIBP, URLScan, ThreatFox, URLHaus &amp; crt.sh for exposures and data breaches…</span>
        </div>
      )}

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border bg-card px-4 py-3 flex flex-col gap-1">
          <div className="flex items-center justify-between">
            <Database className="w-4 h-4 text-muted-foreground/60" />
            <span className="text-[9px] text-muted-foreground uppercase tracking-wide">Total</span>
          </div>
          <p className="text-2xl font-bold tabular-nums">{totalMentionsAcrossAll.toLocaleString()}</p>
          <p className="text-[11px] text-muted-foreground">Total Findings</p>
        </div>
        <div className="rounded-xl border border-l-4 border-red-500/20 border-l-red-500 bg-red-500/5 px-4 py-3 flex flex-col gap-1">
          <div className="flex items-center justify-between">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-[9px] text-red-400/70 uppercase tracking-wide">Critical</span>
          </div>
          <p className="text-2xl font-bold tabular-nums text-red-400">{critCount}</p>
          <p className="text-[11px] text-muted-foreground">Critical Severity</p>
        </div>
        <div className="rounded-xl border border-l-4 border-orange-500/20 border-l-orange-500 bg-orange-500/5 px-4 py-3 flex flex-col gap-1">
          <div className="flex items-center justify-between">
            <Activity className="w-4 h-4 text-orange-400" />
            <span className="text-[9px] text-orange-400/70 uppercase tracking-wide">High</span>
          </div>
          <p className="text-2xl font-bold tabular-nums text-orange-400">{highCount}</p>
          <p className="text-[11px] text-muted-foreground">High Severity</p>
        </div>
        <div className="rounded-xl border border-l-4 border-green-500/20 border-l-green-500 bg-green-500/5 px-4 py-3 flex flex-col gap-1">
          <div className="flex items-center justify-between">
            <CheckCircle2 className="w-4 h-4 text-green-400" />
            <span className="text-[9px] text-green-400/70 uppercase tracking-wide">Verified</span>
          </div>
          <p className="text-2xl font-bold tabular-nums text-green-400">{verCount}</p>
          <p className="text-[11px] text-muted-foreground">Verified Threats</p>
        </div>
      </div>

      {/* ── Main layout ─────────────────────────────────────────────────────── */}
      {showLayout ? (
        <div className="flex gap-4 items-start">

          {/* ── Left sidebar — ALWAYS VISIBLE once assets load ── */}
          <div className="w-60 shrink-0 hidden lg:flex flex-col gap-3">
            {assetsLoading ? (
              <Skeleton className="h-80 rounded-xl" />
            ) : (
              <AssetsSidebar
                assets={allAssets}
                selectedDomain={assetDomain}
                onSelect={d => { setAssetDomain(d); setPage(0); }}
                totalFindings={totalMentionsAcrossAll}
              />
            )}

            {/* Sources filter — shown when there are results */}
            {!isLoading && Object.keys(sourceCounts).length > 0 && (
              <SourcesSidebar
                counts={sourceCounts}
                active={source}
                onToggle={s => { setSrc(source === s ? "" : s); setPage(0); }}
              />
            )}

            {/* Legend */}
            <div className="bg-card border border-border rounded-xl p-3 space-y-2">
              <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Intelligence Sources</p>
              <div className="space-y-1.5">
                {Object.entries(SRC).map(([name, meta]) => (
                  <div key={name} className="flex items-center gap-2 text-[10px]">
                    <span>{meta.icon}</span>
                    <span className={cn("font-medium", meta.color)}>{name}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Main content column ── */}
          <div className="flex-1 min-w-0 space-y-4">

            {/* Filter bar */}
            <div className="flex flex-wrap gap-2">
              <div className="relative flex-1 min-w-44">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
                <Input placeholder="Search findings…" value={q}
                  onChange={e => { setQ(e.target.value); setPage(0); }}
                  className="h-9 pl-8 text-sm" />
              </div>
              <Select value={severity || "all"} onValueChange={v => { setSeverity(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-9 w-32 text-sm"><SelectValue placeholder="Severity" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severity</SelectItem>
                  {["critical", "high", "medium", "low"].map(s => (
                    <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {/* Mobile-only pickers */}
              <Select value={source || "all"} onValueChange={v => { setSrc(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-9 w-32 text-sm lg:hidden"><SelectValue placeholder="Source" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All sources</SelectItem>
                  {Object.keys(SRC).map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
              <Select value={assetDomain || "all"} onValueChange={v => { setAssetDomain(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-9 w-40 text-sm lg:hidden"><SelectValue placeholder="Asset" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All assets</SelectItem>
                  {allAssets.map((a: any) => <SelectItem key={a.id} value={a.domain ?? ""}>{a.domain ?? a.name}</SelectItem>)}
                </SelectContent>
              </Select>
              {hasFilters && (
                <Button size="sm" variant="ghost" className="h-9 text-xs text-muted-foreground gap-1.5" onClick={clearFilters}>
                  <X className="w-3.5 h-3.5" />Clear filters
                </Button>
              )}
            </div>

            {/* Active filter chips */}
            {(assetDomain || source) && (
              <div className="flex flex-wrap gap-1.5">
                {assetDomain && (
                  <div className="flex items-center gap-1 text-[10px] px-2.5 py-1 rounded-lg border bg-primary/5 border-primary/20 text-primary font-mono">
                    <Globe className="w-2.5 h-2.5" />{assetDomain}
                    <button onClick={() => { setAssetDomain(""); setPage(0); }} className="ml-0.5 hover:text-foreground opacity-60 hover:opacity-100">
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </div>
                )}
                {source && (
                  <div className={cn("flex items-center gap-1 text-[10px] px-2.5 py-1 rounded-lg border font-medium", SRC[source]?.badge ?? "bg-muted border-border text-muted-foreground")}>
                    {SRC[source]?.icon} {source}
                    <button onClick={() => { setSrc(""); setPage(0); }} className="ml-0.5 opacity-60 hover:opacity-100"><X className="w-2.5 h-2.5" /></button>
                  </div>
                )}
              </div>
            )}

            {/* Results count */}
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-muted-foreground">
                {isLoading ? "Loading…" : total > 0
                  ? `Showing ${Math.min(page * L + 1, total)}–${Math.min((page + 1) * L, total)} of ${total.toLocaleString()} findings`
                  : hasFilters ? "No findings match current filters" : assetDomain ? `No findings for ${assetDomain}` : "No findings yet"}
              </p>
              {assetDomain && (
                <Button size="sm" variant="ghost" className="h-7 text-[11px] text-muted-foreground gap-1" onClick={() => { setAssetDomain(""); setPage(0); }}>
                  <ChevronLeft className="w-3 h-3" />All assets
                </Button>
              )}
            </div>

            {/* Findings list or empty state — sidebar STAYS VISIBLE in both cases */}
            {isLoading ? (
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-36 rounded-xl" />)}
              </div>
            ) : mentions.length > 0 ? (
              <div className="space-y-3">
                {mentions.map((m: any) => <MentionCard key={m.id} m={m} />)}
              </div>
            ) : (
              /* ── Empty state lives INSIDE the content column so sidebar stays visible ── */
              <div className="flex flex-col items-center justify-center py-16 gap-4 text-center bg-card border border-border/60 rounded-xl">
                {assetDomain ? (
                  <>
                    <div className="p-4 rounded-2xl bg-green-500/10 border border-green-500/20">
                      <Shield className="w-8 h-8 text-green-400" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold text-foreground">No findings for this asset</p>
                      <p className="text-xs text-muted-foreground mt-1 max-w-xs mx-auto leading-relaxed">
                        <span className="font-mono font-medium text-primary">{assetDomain}</span> has no dark web findings
                        {hasFilters ? " matching your current filters." : " in any monitored intelligence source."}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="outline" className="text-xs gap-1.5" onClick={() => { setAssetDomain(""); setPage(0); }}>
                        <ChevronLeft className="w-3.5 h-3.5" />View all assets
                      </Button>
                      {hasFilters && (
                        <Button size="sm" variant="ghost" className="text-xs text-muted-foreground gap-1.5" onClick={clearFilters}>
                          <X className="w-3.5 h-3.5" />Clear filters
                        </Button>
                      )}
                    </div>
                  </>
                ) : hasFilters ? (
                  <>
                    <div className="p-4 rounded-2xl bg-muted border border-border">
                      <Lock className="w-8 h-8 text-muted-foreground/40" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">No findings match your filters</p>
                      <p className="text-xs text-muted-foreground mt-1">Try adjusting severity, source, or search term.</p>
                    </div>
                    <Button size="sm" variant="outline" className="text-xs gap-1.5" onClick={clearFilters}>
                      <X className="w-3.5 h-3.5" />Clear all filters
                    </Button>
                  </>
                ) : !scanning ? (
                  <>
                    <div className="p-4 rounded-2xl bg-green-500/10 border border-green-500/20">
                      <Shield className="w-8 h-8 text-green-400" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">No dark web findings</p>
                      <p className="text-xs text-muted-foreground mt-1 max-w-sm mx-auto leading-relaxed">
                        Dark web monitoring checks HIBP, URLScan, ThreatFox, URLHaus, and crt.sh for exposures across your monitored assets.
                      </p>
                    </div>
                    {isAdmin && (
                      <Button size="sm"
                        onClick={() => scanMutation.mutate()}
                        disabled={scanning || scanMutation.isPending}
                        className="bg-purple-600 hover:bg-purple-700 text-white text-xs gap-1.5">
                        <Radio className="w-3.5 h-3.5" />Run First Scan
                      </Button>
                    )}
                  </>
                ) : null}
              </div>
            )}

            {/* Pagination */}
            <SmartPagination
              page={page + 1}
              totalPages={pages}
              totalItems={total}
              pageSize={L}
              itemLabel="findings"
              onPageChange={p => setPage(p - 1)}
            />
          </div>
        </div>
      ) : (
        /* ── Global empty state — only when zero assets and never scanned ── */
        <div className="flex flex-col items-center justify-center py-24 gap-5 text-center">
          <div className="p-5 rounded-2xl bg-purple-500/10 border border-purple-500/20">
            <Eye className="w-10 h-10 text-purple-400" />
          </div>
          <div>
            <p className="text-base font-bold">Dark Web Monitoring</p>
            <p className="text-sm text-muted-foreground mt-1.5 max-w-md mx-auto leading-relaxed">
              Monitor your assets against dark web intelligence sources — HIBP data breaches, URLScan malicious detections, ThreatFox malware IOCs, URLHaus, and crt.sh lookalike domains.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row items-center gap-2">
            {isAdmin && (
              <Button size="sm"
                onClick={() => scanMutation.mutate()}
                disabled={scanning || scanMutation.isPending}
                className="bg-purple-600 hover:bg-purple-700 text-white gap-1.5">
                {scanning || scanMutation.isPending
                  ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Scanning…</>
                  : <><Radio className="w-3.5 h-3.5" />Run First Scan</>}
              </Button>
            )}
          </div>
          <div className="grid grid-cols-3 sm:grid-cols-5 gap-3 mt-2">
            {Object.entries(SRC).map(([name, meta]) => (
              <div key={name} className="flex flex-col items-center gap-1.5 px-3 py-2.5 rounded-xl bg-card border border-border text-center">
                <span className="text-xl">{meta.icon}</span>
                <span className={cn("text-[10px] font-semibold", meta.color)}>{name}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
