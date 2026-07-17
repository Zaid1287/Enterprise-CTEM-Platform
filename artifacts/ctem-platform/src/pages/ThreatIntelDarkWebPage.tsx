import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Eye, RefreshCw, Shield, AlertTriangle, Calendar, Search,
  Loader2, ExternalLink, X, Globe, Server, CheckCircle2,
  Clock, Radio, Building2, ChevronRight,
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
  low:      "text-green-400 bg-green-500/10 border-green-500/25",
};
const SEV_CARD: Record<string, string> = {
  critical: "border-red-500/30 bg-red-500/5",
  high:     "border-orange-500/30 bg-orange-500/5",
  medium:   "border-yellow-500/20 bg-card",
  low:      "border-border bg-card",
};

/* ── Source badge styles ─────────────────────────────────────────────────── */
const SRC_STYLE: Record<string, string> = {
  "HIBP":      "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "URLScan":   "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "ThreatFox": "text-red-400 bg-red-500/10 border-red-500/20",
  "URLHaus":   "text-orange-400 bg-orange-500/10 border-orange-500/20",
  "crt.sh":    "text-cyan-400 bg-cyan-500/10 border-cyan-500/20",
};

/* ── Mention type label ──────────────────────────────────────────────────── */
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
  const src = m.source ?? m.sourceType ?? "";
  const url = m.sourceUrl ?? m.url ?? "";
  const snippet = m.content ?? m.snippet ?? "";
  const title = m.title ?? m.sourceType ?? src ?? "Unknown";

  return (
    <div className={cn("border rounded-xl p-4 space-y-2.5 transition-colors", SEV_CARD[sev] ?? SEV_CARD.medium)}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-1.5 mb-1">
            <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium shrink-0", SRC_STYLE[src] ?? "text-muted-foreground bg-muted border-border")}>
              {src}
            </span>
            <span className="text-[10px] text-muted-foreground/60 bg-muted/40 border border-border/50 px-1.5 py-0.5 rounded">
              {MENTION_TYPE_LABEL[m.mentionType] ?? m.mentionType ?? "Mention"}
            </span>
            {m.isVerified && (
              <span className="text-[10px] text-green-400 flex items-center gap-0.5">
                <CheckCircle2 className="w-2.5 h-2.5" />Verified
              </span>
            )}
          </div>
          <p className="font-semibold text-sm leading-snug">{title}</p>
          {m.assetDomain && (
            <p className="text-[10px] font-mono text-muted-foreground/70 flex items-center gap-1">
              <Globe className="w-2.5 h-2.5" />{m.assetDomain}
              {m.tenantName && <span className="ml-1 text-muted-foreground/40">· {m.tenantName}</span>}
            </p>
          )}
        </div>
        <div className="flex flex-col items-end gap-1.5 shrink-0">
          <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", SEV[sev] ?? SEV.medium)}>
            {sev}
          </span>
          {(m.detectedAt ?? m.createdAt) && (
            <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
              <Calendar className="w-2.5 h-2.5" />
              {new Date(m.detectedAt ?? m.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" })}
            </span>
          )}
        </div>
      </div>

      {snippet && (
        <div className="bg-muted/30 border border-border/40 rounded-lg p-2.5">
          <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">{snippet}</p>
        </div>
      )}

      {m.keywords?.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {(m.keywords as string[]).slice(0, 8).map((k: string) => (
            <span key={k} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{k}</span>
          ))}
        </div>
      )}

      {url && (
        <a href={url} target="_blank" rel="noopener noreferrer"
          className="text-[11px] text-primary hover:underline flex items-center gap-1">
          View source <ExternalLink className="w-3 h-3" />
        </a>
      )}
    </div>
  );
}

/* ── Assets panel ────────────────────────────────────────────────────────── */
function AssetsPanel({
  assets,
  selectedDomain,
  onSelect,
}: {
  assets: any[];
  selectedDomain: string;
  onSelect: (d: string) => void;
}) {
  const sorted = [...assets].sort((a, b) => b.mentionCount - a.mentionCount);

  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="px-4 py-3 border-b border-border flex items-center gap-2">
        <Server className="w-3.5 h-3.5 text-primary" />
        <span className="text-xs font-semibold">Monitored Assets</span>
        <span className="text-[10px] text-muted-foreground ml-auto">{assets.length} total</span>
      </div>
      <div className="divide-y divide-border/50 max-h-96 overflow-y-auto">
        <button
          onClick={() => onSelect("")}
          className={cn("w-full text-left px-4 py-2.5 flex items-center justify-between text-xs transition-colors",
            !selectedDomain ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted/30")}>
          All assets
          <span className="text-[10px] text-muted-foreground">{assets.reduce((s, a) => s + a.mentionCount, 0)} mentions</span>
        </button>
        {sorted.map(a => (
          <button key={a.id}
            onClick={() => onSelect(selectedDomain === a.domain ? "" : (a.domain ?? ""))}
            className={cn("w-full text-left px-4 py-2.5 flex items-center justify-between gap-2 text-xs transition-colors",
              selectedDomain === a.domain ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted/30")}>
            <div className="min-w-0 flex-1">
              <p className="font-mono truncate text-[10px]">{a.domain ?? a.value ?? a.name}</p>
              {a.tenantName && <p className="text-[9px] text-muted-foreground/50 mt-0.5">{a.tenantName} · {a.type}</p>}
            </div>
            {a.mentionCount > 0
              ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 shrink-0">{a.mentionCount}</span>
              : <span className="text-[10px] text-muted-foreground/30 shrink-0">0</span>}
          </button>
        ))}
        {assets.length === 0 && (
          <div className="px-4 py-4 text-center text-xs text-muted-foreground">No assets found</div>
        )}
      </div>
    </div>
  );
}

/* ── Summary stats ───────────────────────────────────────────────────────── */
function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className={cn("rounded-xl border p-3 text-center", color)}>
      <p className="text-xl font-bold">{value.toLocaleString()}</p>
      <p className="text-[10px] mt-0.5 text-muted-foreground capitalize">{label}</p>
    </div>
  );
}

/* ── Last scan badge ─────────────────────────────────────────────────────── */
function LastScanBadge({ lastRun }: { lastRun: any }) {
  if (!lastRun) return <span className="text-[10px] text-muted-foreground/50 flex items-center gap-1"><Clock className="w-3 h-3" />Never scanned</span>;
  if (lastRun.status === "running") return <span className="text-[10px] text-blue-400 flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin" />Scanning…</span>;
  if (lastRun.completedAt) return (
    <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
      <Clock className="w-3 h-3" />
      Last scanned: {new Date(lastRun.completedAt).toLocaleString()}
      {lastRun.recordsAdded > 0 && <span className="text-green-400 ml-1">+{lastRun.recordsAdded} new</span>}
    </span>
  );
  return null;
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

  // Derived stats from all data (not just current page)
  const critCount = mentions.filter(m => (m.severity ?? m.riskLevel) === "critical").length;
  const highCount  = mentions.filter(m => (m.severity ?? m.riskLevel) === "high").length;
  const verCount   = mentions.filter(m => m.isVerified).length;

  /* ── Scan mutation ── */
  const scanMutation = useMutation({
    mutationFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dark-web/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
    onSuccess: () => {
      setScanning(true);
      toast({ title: "Dark web scan started", description: "Scanning all assets across HIBP, URLScan, ThreatFox & crt.sh. Results appear within 1–2 minutes." });
      // Poll until lastRun status changes from running to completed
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
            toast({ title: "Dark web scan complete", description: `Scan finished. ${run.recordsAdded ?? 0} new findings detected.` });
          }
        } catch {}
      }, 5_000);
    },
    onError: () => {
      setScanning(false);
      toast({ title: "Scan failed", variant: "destructive" });
    },
  });

  // Cleanup polling
  useEffect(() => () => { if (pollingRef.current) clearInterval(pollingRef.current); }, []);

  // Auto-stop polling after 3min
  useEffect(() => {
    if (!scanning) return;
    const t = setTimeout(() => { clearInterval(pollingRef.current!); setScanning(false); refetch(); }, 180_000);
    return () => clearTimeout(t);
  }, [scanning]);

  // Stats per source for breakdown
  const sourceCounts: Record<string, number> = {};
  for (const m of mentions) { const s = m.source ?? m.sourceType ?? "?"; sourceCounts[s] = (sourceCounts[s] ?? 0) + 1; }

  return (
    <div className="p-6 space-y-4">

      {/* ── Header ── */}
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Eye className="w-5 h-5 text-purple-400" />
          <div>
            <h1 className="text-xl font-bold">Dark Web Monitoring</h1>
            <div className="flex items-center gap-3 mt-0.5">
              <p className="text-xs text-muted-foreground">{total.toLocaleString()} findings across {allAssets.length} monitored assets</p>
              <LastScanBadge lastRun={lastRun} />
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button size="sm"
              onClick={() => scanMutation.mutate()}
              disabled={scanning || scanMutation.isPending}>
              {scanning || scanMutation.isPending
                ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                : <Radio className="w-3.5 h-3.5 mr-1.5" />}
              Run Scan
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* ── Scanning banner ── */}
      {scanning && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-purple-500/10 border border-purple-500/20 text-xs text-purple-300">
          <Loader2 className="w-4 h-4 animate-spin shrink-0" />
          <span>Scanning all assets against HIBP, URLScan, ThreatFox, URLHaus, and crt.sh for dark web exposures and data breaches…</span>
        </div>
      )}

      {/* ── Stats row ── */}
      {total > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <StatCard label="Total Findings" value={total} color="border-border bg-card" />
          <StatCard label="Critical" value={critCount} color="border-red-500/20 bg-red-500/5" />
          <StatCard label="High" value={highCount} color="border-orange-500/20 bg-orange-500/5" />
          <StatCard label="Verified" value={verCount} color="border-green-500/20 bg-green-500/5" />
        </div>
      )}

      {/* ── Empty state ── */}
      {!isLoading && total === 0 && !scanning && (
        <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
          <div className="p-4 rounded-2xl bg-green-500/10 border border-green-500/20">
            <Shield className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <p className="text-sm font-semibold">
              {hasFilters ? "No findings match your filters" : "No dark web findings yet"}
            </p>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm mx-auto">
              {hasFilters
                ? "Try adjusting your filters to see more results."
                : "Dark web monitoring checks all your assets against HIBP data breaches, URLScan malicious detections, ThreatFox malware IOCs, URLHaus, and crt.sh lookalike domains."}
            </p>
          </div>
          {isAdmin && !hasFilters && (
            <Button size="sm" onClick={() => scanMutation.mutate()} disabled={scanning || scanMutation.isPending}>
              {scanning || scanMutation.isPending
                ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />
                : <Radio className="w-3.5 h-3.5 mr-1.5" />}
              Run First Scan
            </Button>
          )}
        </div>
      )}

      {/* ── Main layout ── */}
      {(total > 0 || isLoading || assetsLoading) && (
        <div className="flex gap-4 items-start">

          {/* Assets sidebar */}
          <div className="w-64 shrink-0 hidden lg:block">
            {assetsLoading
              ? <Skeleton className="h-64 rounded-xl" />
              : <AssetsPanel assets={allAssets} selectedDomain={assetDomain} onSelect={d => { setAssetDomain(d); setPage(0); }} />
            }
          </div>

          {/* Findings column */}
          <div className="flex-1 min-w-0 space-y-3">

            {/* Filters */}
            <div className="flex flex-wrap gap-2">
              <div className="relative flex-1 min-w-48">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input placeholder="Search findings…" value={q}
                  onChange={e => { setQ(e.target.value); setPage(0); }}
                  className="h-8 pl-8 text-xs" />
              </div>
              <Select value={severity || "all"} onValueChange={v => { setSeverity(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All severity</SelectItem>
                  {["critical", "high", "medium", "low"].map(s => (
                    <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={source || "all"} onValueChange={v => { setSrc(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Source" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All sources</SelectItem>
                  {["HIBP", "URLScan", "ThreatFox", "URLHaus", "crt.sh"].map(s => (
                    <SelectItem key={s} value={s}>{s}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {/* Mobile asset filter */}
              <Select value={assetDomain || "all"} onValueChange={v => { setAssetDomain(v === "all" ? "" : v); setPage(0); }}>
                <SelectTrigger className="h-8 w-40 text-xs lg:hidden"><SelectValue placeholder="Asset" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All assets</SelectItem>
                  {allAssets.map(a => <SelectItem key={a.id} value={a.domain ?? ""}>{a.domain ?? a.name}</SelectItem>)}
                </SelectContent>
              </Select>
              {hasFilters && (
                <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
                  onClick={() => { setQ(""); setSeverity(""); setSrc(""); setAssetDomain(""); setPage(0); }}>
                  <X className="w-3.5 h-3.5 mr-1" />Clear
                </Button>
              )}
            </div>

            {/* Active filter chips */}
            {(assetDomain || source) && (
              <div className="flex flex-wrap gap-1.5">
                {assetDomain && (
                  <div className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border bg-muted border-border text-muted-foreground font-mono">
                    <Globe className="w-2.5 h-2.5" />{assetDomain}
                    <button onClick={() => { setAssetDomain(""); setPage(0); }}><X className="w-2.5 h-2.5" /></button>
                  </div>
                )}
                {source && (
                  <div className={cn("flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border font-medium", SRC_STYLE[source] ?? "bg-muted border-border text-muted-foreground")}>
                    {source}
                    <button onClick={() => { setSrc(""); setPage(0); }}><X className="w-2.5 h-2.5" /></button>
                  </div>
                )}
              </div>
            )}

            {/* Source breakdown chips */}
            {Object.keys(sourceCounts).length > 1 && (
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(sourceCounts).map(([s, cnt]) => (
                  <button key={s}
                    onClick={() => { setSrc(source === s ? "" : s); setPage(0); }}
                    className={cn("text-[10px] px-2 py-0.5 rounded border flex items-center gap-1 transition-colors", source === s ? (SRC_STYLE[s] ?? "bg-muted border-border text-foreground") : "bg-muted/30 border-border/50 text-muted-foreground hover:bg-muted/60")}>
                    {s} <span className="font-semibold">{cnt}</span>
                  </button>
                ))}
              </div>
            )}

            {/* Findings list */}
            {isLoading
              ? Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-36 rounded-xl" />)
              : mentions.map((m: any) => <MentionCard key={m.id} m={m} />)
            }

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
      )}
    </div>
  );
}
