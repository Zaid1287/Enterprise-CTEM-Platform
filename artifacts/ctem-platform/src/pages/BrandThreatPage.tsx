import { useState } from "react";
import { useLocation } from "wouter";
import {
  useListBrandThreats, useCreateBrandThreatScan, useDeleteBrandThreatScan,
  getListBrandThreatsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert, Plus, Trash2, Loader2, Globe, AlertTriangle,
  CheckCircle2, Clock, XCircle, RefreshCw, Eye, Zap, Shield,
  TrendingUp, Activity, Search, ChevronRight, Fish, Database, Target,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const RISK_META: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25",    dot: "bg-red-400" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25", dot: "bg-orange-400" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/25", dot: "bg-yellow-400" },
  low:      { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/25",  dot: "bg-green-400" },
};

const STATUS_CONFIG: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  pending: { icon: <Clock className="w-3.5 h-3.5" />,                          label: "Queued",   color: "text-muted-foreground" },
  running: { icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />,           label: "Scanning", color: "text-blue-400" },
  done:    { icon: <CheckCircle2 className="w-3.5 h-3.5" />,                   label: "Complete", color: "text-green-400" },
  error:   { icon: <XCircle className="w-3.5 h-3.5" />,                        label: "Error",    color: "text-red-400" },
};

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [domain, setDomain] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { mutateAsync } = useCreateBrandThreatScan();
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setSubmitting(true);
    try {
      await mutateAsync({ data: { domain: domain.trim() } });
      toast({ title: "Scan started", description: `Running brand threat scan for ${domain.trim()}` });
      onSuccess();
    } catch {
      toast({ title: "Failed to start scan", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-card border border-border rounded-2xl w-full max-w-md shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-primary" />
            </div>
            <h2 className="text-base font-semibold">New Brand Threat Scan</h2>
          </div>
          <p className="text-xs text-muted-foreground mt-2 ml-11 leading-relaxed">
            Full intelligence pipeline: typosquatting via dnstwist engine, RDAP enrichment,
            GeoIP, VirusTotal reputation, PhishTank/OpenPhish/Google Safe Browsing phishing feeds,
            HIBP data leak check, CT abuse detection, and brand abuse scanning.
          </p>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider mb-2 block">Target Domain</label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                type="text"
                placeholder="example.com"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                className="w-full bg-background border border-border rounded-lg pl-8 pr-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40 font-mono"
                autoFocus
              />
            </div>
            <p className="text-[10px] text-muted-foreground/60 mt-1.5">Enter a root domain without protocol — e.g. acme.com</p>
          </div>
          <div className="grid grid-cols-3 gap-2">
            {[
              { icon: <Globe className="w-3 h-3" />,    label: "Typosquatting",  sub: "dnstwist + DNS" },
              { icon: <Fish className="w-3 h-3" />,     label: "Phishing feeds", sub: "PhishTank · OpenPhish" },
              { icon: <Database className="w-3 h-3" />, label: "Data leaks",     sub: "HIBP breach lookup" },
            ].map(item => (
              <div key={item.label} className="bg-background/80 border border-border/50 rounded-xl p-2.5 text-center">
                <div className="flex justify-center mb-1 text-muted-foreground">{item.icon}</div>
                <p className="text-[10px] font-semibold">{item.label}</p>
                <p className="text-[9px] text-muted-foreground/60 leading-tight mt-0.5">{item.sub}</p>
              </div>
            ))}
          </div>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} className="flex-1">Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting || !domain.trim()} className="flex-1">
              {submitting ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 mr-1.5" />}
              Start Scan
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ScanCard({ scan, onDelete, onView, deleting }: {
  scan: any; onDelete: (id: number) => void; onView: (id: number) => void; deleting: boolean;
}) {
  const status = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const risk   = RISK_META[scan.phishingRisk] ?? RISK_META.low;
  const liveCount = scan.liveCount ?? 0;
  const mxCount   = scan.registeredCount ?? 0;
  const isActive  = scan.status === "running" || scan.status === "pending";

  return (
    <div className={cn(
      "bg-card border rounded-2xl overflow-hidden transition-all hover:shadow-lg hover:-translate-y-0.5",
      isActive ? "border-blue-500/30" : "border-border",
    )}>
      {/* Card top strip — risk color */}
      <div className={cn(
        "h-1 w-full",
        scan.status === "done" ? (
          scan.phishingRisk === "critical" ? "bg-red-500" :
          scan.phishingRisk === "high"     ? "bg-orange-500" :
          scan.phishingRisk === "medium"   ? "bg-yellow-500" : "bg-green-500"
        ) : isActive ? "bg-blue-500 animate-pulse" : "bg-muted"
      )} />

      <div className="p-5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <span className="text-sm font-semibold font-mono truncate">{scan.domain}</span>
              {scan.pipelineScanId && (
                <span className="text-[10px] bg-violet-500/10 text-violet-400 border border-violet-500/20 px-1.5 py-0.5 rounded-full flex items-center gap-0.5 shrink-0">
                  <Zap className="w-2.5 h-2.5" /> Auto
                </span>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground mt-1">{formatDate(scan.createdAt)}</p>
          </div>
          {/* Status pill */}
          <span className={cn("flex items-center gap-1 text-[11px] font-medium shrink-0", status.color)}>
            {status.icon}
            {status.label}
          </span>
        </div>

        {/* Stats row — only when done */}
        {scan.status === "done" && (
          <div className="grid grid-cols-3 gap-2 mb-3">
            <div className="bg-background rounded-xl p-2.5 text-center">
              <p className="text-[10px] text-muted-foreground mb-0.5">Live</p>
              <p className={cn("text-base font-bold tabular-nums", liveCount > 0 ? "text-red-400" : "text-green-400")}>
                {liveCount}
              </p>
            </div>
            <div className="bg-background rounded-xl p-2.5 text-center">
              <p className="text-[10px] text-muted-foreground mb-0.5">Phishing</p>
              <p className={cn("text-base font-bold tabular-nums", (scan.phishingCount ?? 0) > 0 ? "text-red-400" : "text-muted-foreground")}>
                {scan.phishingCount ?? 0}
              </p>
            </div>
            <div className="bg-background rounded-xl p-2.5 text-center">
              <p className="text-[10px] text-muted-foreground mb-0.5">Leaks</p>
              <p className={cn("text-base font-bold tabular-nums", (scan.dataLeakCount ?? 0) > 0 ? "text-orange-400" : "text-muted-foreground")}>
                {scan.dataLeakCount ?? 0}
              </p>
            </div>
          </div>
        )}
        {scan.status === "done" && (scan.brandAbuseCount ?? 0) > 0 && (
          <div className="mb-3 flex items-center gap-2 bg-orange-500/5 border border-orange-500/20 rounded-lg px-3 py-2">
            <Target className="w-3 h-3 text-orange-400 shrink-0" />
            <p className="text-[11px] text-orange-400 font-medium">{scan.brandAbuseCount} brand abuse finding{scan.brandAbuseCount !== 1 ? "s" : ""}</p>
          </div>
        )}

        {/* Running progress */}
        {isActive && (
          <div className="mb-4 bg-blue-500/5 border border-blue-500/20 rounded-xl p-3 flex items-center gap-2.5">
            <Loader2 className="w-4 h-4 animate-spin text-blue-400 shrink-0" />
            <div>
              <p className="text-xs font-medium text-blue-400">Full intelligence scan in progress</p>
              <p className="text-[10px] text-muted-foreground">
                {scan.totalPermutations > 0
                  ? `${scan.totalPermutations} permutations · RDAP + GeoIP + VT + phishing feeds + HIBP…`
                  : "Generating permutations + running intelligence engines…"}
              </p>
            </div>
          </div>
        )}

        {/* Error */}
        {scan.status === "error" && (
          <div className="mb-4 bg-red-500/5 border border-red-500/20 rounded-xl p-3 flex items-center gap-2">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
            <p className="text-xs text-red-400 truncate">{scan.error ?? "Scan failed"}</p>
          </div>
        )}

        {/* Footer row */}
        <div className="flex items-center justify-between gap-2">
          {scan.status === "done" && scan.phishingRisk ? (
            <span className={cn(
              "text-[11px] font-semibold px-2.5 py-1 rounded-full border capitalize",
              risk.color, risk.bg, risk.border,
            )}>
              {scan.phishingRisk} phishing risk
            </span>
          ) : <div />}

          <div className="flex items-center gap-1">
            {scan.status === "done" && (
              <Button size="sm" variant="ghost" onClick={() => onView(scan.id)} className="h-7 text-xs gap-1">
                View <ChevronRight className="w-3 h-3" />
              </Button>
            )}
            <Button
              size="sm" variant="ghost"
              onClick={() => onDelete(scan.id)}
              disabled={deleting}
              className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
            >
              {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function BrandThreatPage() {
  const [, navigate] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showModal, setShowModal] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [search, setSearch] = useState("");

  const { data: scans, isLoading, refetch } = useListBrandThreats({
    query: { queryKey: getListBrandThreatsQueryKey(), refetchInterval: (query: any) => {
      const list = (query?.state?.data as any[]) ?? [];
      return list.some((s: any) => s.status === "running" || s.status === "pending") ? 4000 : false;
    }},
  });
  const { mutateAsync: deleteScan } = useDeleteBrandThreatScan();

  async function handleDelete(id: number) {
    if (!confirm("Delete this brand threat scan and all its results?")) return;
    setDeletingId(id);
    try {
      await deleteScan({ id });
      queryClient.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
      toast({ title: "Scan deleted" });
    } catch {
      toast({ title: "Failed to delete scan", variant: "destructive" });
    } finally {
      setDeletingId(null);
    }
  }

  const scanList = (scans as any[]) ?? [];
  const filtered = search.trim()
    ? scanList.filter((s: any) => s.domain.includes(search.trim().toLowerCase()))
    : scanList;

  const totalLive     = scanList.reduce((n: number, s: any) => n + (s.liveCount ?? 0), 0);
  const totalPhishing = scanList.reduce((n: number, s: any) => n + (s.phishingCount ?? 0), 0);
  const totalLeaks    = scanList.reduce((n: number, s: any) => n + (s.dataLeakCount ?? 0), 0);
  const activeScans   = scanList.filter((s: any) => s.status === "running" || s.status === "pending").length;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Top hero bar ──────────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-card via-card to-background border-b border-border px-6 py-5">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">Brand Threat Intelligence</h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                Typosquatting · Phishing detection · Data leaks · Brand abuse · CT monitoring
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()} className="h-8">
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
              Refresh
            </Button>
            <Button size="sm" onClick={() => setShowModal(true)} className="h-8">
              <Plus className="w-3.5 h-3.5 mr-1.5" />
              New Scan
            </Button>
          </div>
        </div>

        {/* Stat strip */}
        {scanList.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
            <div className="flex items-center gap-3 bg-background/60 border border-border rounded-xl px-4 py-3">
              <Globe className="w-4 h-4 text-muted-foreground shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Domains Scanned</p>
                <p className="text-xl font-bold leading-tight">{new Set(scanList.map((s: any) => s.domain)).size}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-red-500/20 rounded-xl px-4 py-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Live Threats</p>
                <p className={cn("text-xl font-bold leading-tight", totalLive > 0 ? "text-red-400" : "")}>{totalLive}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-orange-500/20 rounded-xl px-4 py-3">
              <Fish className="w-4 h-4 text-orange-400 shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Phishing Detected</p>
                <p className={cn("text-xl font-bold leading-tight", totalPhishing > 0 ? "text-orange-400" : "")}>{totalPhishing}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-border rounded-xl px-4 py-3">
              {activeScans > 0
                ? <Activity className="w-4 h-4 text-blue-400 shrink-0" />
                : <Database className="w-4 h-4 text-muted-foreground shrink-0" />}
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                  {activeScans > 0 ? "Active Scans" : "Data Leaks"}
                </p>
                <p className={cn("text-xl font-bold leading-tight", activeScans > 0 ? "text-blue-400" : totalLeaks > 0 ? "text-yellow-400" : "")}>
                  {activeScans > 0 ? activeScans : totalLeaks}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Main content ───────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : scanList.length === 0 ? (
          /* ── Empty state ── */
          <div className="flex flex-col items-center justify-center h-96 text-center">
            <div className="relative mb-6">
              <div className="w-20 h-20 rounded-2xl bg-primary/5 border border-primary/10 flex items-center justify-center">
                <ShieldAlert className="w-9 h-9 text-primary/40" />
              </div>
              <div className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-card border border-border flex items-center justify-center">
                <Plus className="w-3.5 h-3.5 text-muted-foreground" />
              </div>
            </div>
            <h2 className="text-base font-semibold mb-1">No brand threat scans yet</h2>
            <p className="text-sm text-muted-foreground max-w-md mb-6">
              Start a scan to detect domains impersonating your brand via typosquatting, homoglyph substitution,
              TLD swaps, and other deception techniques.
            </p>
            <Button onClick={() => setShowModal(true)}>
              <Shield className="w-4 h-4 mr-2" />
              Run First Scan
            </Button>
            <p className="text-xs text-muted-foreground/50 mt-3">
              Scans also auto-trigger when you run an Asset or Domain Scan
            </p>
          </div>
        ) : (
          <>
            {/* Search bar */}
            <div className="flex items-center gap-3 mb-5">
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Filter by domain…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="w-full bg-background border border-border rounded-lg pl-8 pr-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                />
              </div>
              <span className="text-xs text-muted-foreground">
                {filtered.length} scan{filtered.length !== 1 ? "s" : ""}
              </span>
            </div>

            {/* Cards grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {filtered.map((scan: any) => (
                <ScanCard
                  key={scan.id}
                  scan={scan}
                  onDelete={handleDelete}
                  onView={id => navigate(`/brand-threats/${id}`)}
                  deleting={deletingId === scan.id}
                />
              ))}
            </div>

            {filtered.length === 0 && (
              <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
                No scans match "{search}"
              </div>
            )}
          </>
        )}
      </div>

      {showModal && (
        <NewScanModal
          onClose={() => setShowModal(false)}
          onSuccess={() => {
            setShowModal(false);
            queryClient.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
          }}
        />
      )}
    </div>
  );
}
