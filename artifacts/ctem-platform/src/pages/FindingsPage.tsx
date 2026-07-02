import { useState, useMemo, useRef, useEffect } from "react";
import { Link, useLocation, useSearch } from "wouter";
import {
  useListFindings, useUpdateFinding, getListFindingsQueryKey,
  useListFindingComments, useCreateFindingComment, getListFindingCommentsQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient } from "@tanstack/react-query";
import {
  Search, ExternalLink, ChevronLeft, ChevronRight, X,
  ShieldAlert, Globe, Network, Server, Cpu, Smartphone,
  FileText, Code2, Camera, AlignLeft, Tag, Info,
  CheckCircle2, Clock, AlertCircle, XCircle, Minus,
  MessageSquare, Send, Loader2, Sparkles, RefreshCw, ShieldOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, capitalize, formatDate } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const STATUSES = ["open", "in_progress", "accepted_risk", "false_positive", "mitigated", "auto_mitigated"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 25;

// ── Helpers ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-muted text-muted-foreground border-border",
};

const STATUS_COLOR: Record<string, string> = {
  open:            "bg-red-500/10 text-red-400 border-red-500/30",
  in_progress:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  accepted_risk:   "bg-amber-500/10 text-amber-400 border-amber-500/30",
  false_positive:  "bg-muted text-muted-foreground border-border",
  mitigated:       "bg-green-500/10 text-green-400 border-green-500/30",
  auto_mitigated:  "bg-teal-500/10 text-teal-400 border-teal-500/30",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  open:           AlertCircle,
  in_progress:    Clock,
  accepted_risk:  Info,
  false_positive: Minus,
  mitigated:      CheckCircle2,
  auto_mitigated: RefreshCw,
};

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  domain:       Globe,
  subdomain:    Network,
  ip:           Server,
  cidr:         Network,
  url:          Globe,
  api:          Code2,
  ssl_cert:     ShieldAlert,
  cloud_asset:  Cpu,
  host:         Server,
  sentinelware: Server,
  mobile_app:   Smartphone,
};

function assetTypeLabel(t: string | null) {
  if (!t) return "—";
  if (t === "sentinelware") return "Sentinelware";
  return capitalize(t.replace(/_/g, " "));
}

/** Compute importance score 0-100 from CVE data, with severity-based fallback */
function importanceScore(f: any): number | null {
  const SEV: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 10 };
  const cvss = typeof f.cvss === "number" ? f.cvss : parseFloat(f.cvss ?? "");
  const epss = typeof f.epss === "number" ? f.epss : parseFloat(f.epss ?? "");
  if (!isNaN(cvss) && !isNaN(epss)) return Math.round(cvss * 10 * 0.5 + epss * 100 * 0.3 + (f.isKev ? 20 : 0));
  if (!isNaN(cvss)) return Math.round(cvss * 10);
  return SEV[f.severity ?? ""] ?? null;
}

// ── Score Badge ─────────────────────────────────────────────────────────────

function ScoreBadge({ score, label }: { score: number | null; label: string }) {
  if (score === null) return <span className="text-xs text-muted-foreground/40">—</span>;
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : score >= 20 ? "text-blue-400" : "text-muted-foreground";
  return <span className={cn("text-xs font-mono font-semibold", color)} title={label}>{score}</span>;
}

// ── Delta Badge — "NEW" / "RE-CONFIRMED" / "GONE" ──────────────────────────

function DeltaBadge({ f }: { f: any }) {
  if (f.status === "auto_mitigated")
    return <span className="text-[9px] px-1.5 py-0.5 rounded bg-teal-500/15 text-teal-400 border border-teal-500/25 font-bold uppercase shrink-0">GONE</span>;
  if (f.isNewSinceLastScan)
    return <span className="text-[9px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold uppercase shrink-0">NEW</span>;
  if (f.lastSeenAt && f.previousScanId)
    return <span className="text-[9px] px-1.5 py-0.5 rounded bg-sky-500/10 text-sky-400 border border-sky-500/20 font-semibold uppercase shrink-0">✓</span>;
  return null;
}

// ── Suppress Modal ──────────────────────────────────────────────────────────

function SuppressModal({ finding, onClose, onDone }: { finding: any; onClose: () => void; onDone: () => void }) {
  const [matchType, setMatchType] = useState<string>(finding.cve ? "cve_id" : "title_contains");
  const [note, setNote] = useState("");
  const [applyToAsset, setApplyToAsset] = useState(true);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  async function submit() {
    setLoading(true); setErr("");
    try {
      await apiFetch(`/api/findings/${finding.id}/suppress`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ matchType, note, applyToAsset }),
      });
      onDone();
      onClose();
    } catch (e: any) {
      setErr(e.message ?? "Error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <ShieldOff className="w-4 h-4 text-amber-400" />
            Confirm False Positive + Suppress
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>

        <p className="text-xs text-muted-foreground mb-4">
          This marks <span className="font-medium text-foreground">{finding.title}</span> as a false positive and adds a suppression rule so future scans skip matching findings automatically.
        </p>

        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Suppression rule type</label>
            <Select value={matchType} onValueChange={setMatchType}>
              <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                {finding.cve && <SelectItem value="cve_id">By CVE/Finding ID — suppress this exact ID ({finding.cve})</SelectItem>}
                <SelectItem value="title_contains">By title — suppress findings with similar title</SelectItem>
                <SelectItem value="url_exact">By URL — suppress this exact URL</SelectItem>
                <SelectItem value="url_pattern">By URL pattern — suppress URLs containing this substring</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Note (optional)</label>
            <Input
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="Why is this a false positive?"
              className="h-8 text-xs"
            />
          </div>

          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" checked={applyToAsset} onChange={e => setApplyToAsset(e.target.checked)} className="rounded" />
            <span className="text-xs text-muted-foreground">Only apply to this asset ({finding.assetName ?? finding.assetValue ?? "current asset"})</span>
          </label>

          {err && <p className="text-xs text-red-400">{err}</p>}
        </div>

        <div className="flex gap-2 mt-5 justify-end">
          <Button size="sm" variant="outline" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={submit} disabled={loading} className="bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30">
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <ShieldOff className="w-3.5 h-3.5 mr-1" />}
            Confirm False Positive
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── Comments Panel ──────────────────────────────────────────────────────────

function CommentsPanel({ findingId }: { findingId: number }) {
  const qc = useQueryClient();
  const { data: comments, isLoading } = useListFindingComments(findingId, {
    query: { queryKey: getListFindingCommentsQueryKey(findingId), staleTime: 0 },
  });
  const createComment = useCreateFindingComment();
  const [text, setText] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [comments]);

  const list = (comments as any[]) ?? [];

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    await createComment.mutateAsync({ findingId, data: { content: text.trim() } as any });
    setText("");
    qc.invalidateQueries({ queryKey: getListFindingCommentsQueryKey(findingId) });
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto space-y-2 min-h-0 pb-2">
        {isLoading && <Skeleton className="h-12 w-full" />}
        {!isLoading && list.length === 0 && (
          <p className="text-xs text-muted-foreground/60 mt-1">Add a comment to document analysis notes or remediation status.</p>
        )}
        {list.map((c: any) => (
          <div key={c.id} className="bg-muted/30 rounded-lg p-2.5 text-xs">
            <div className="flex items-center justify-between mb-1">
              <span className="font-medium text-foreground text-[11px]">{c.authorName ?? "User"}</span>
              <span className="text-muted-foreground/60 text-[10px]">{formatDate(c.createdAt)}</span>
            </div>
            <p className="text-muted-foreground leading-relaxed">{c.content}</p>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <form onSubmit={submit} className="flex gap-2 pt-2 border-t border-border mt-2 flex-shrink-0">
        <Input
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Add a comment..."
          className="h-8 text-xs flex-1"
        />
        <Button type="submit" size="sm" className="h-8" disabled={createComment.isPending || !text.trim()}>
          {createComment.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
        </Button>
      </form>
    </div>
  );
}

// ── Drawer Mode ─────────────────────────────────────────────────────────────
type DrawerMode = "metadata" | "headers" | "screenshots" | "comments" | null;

// ── Finding Drawer ──────────────────────────────────────────────────────────
function FindingDrawer({
  finding,
  initialMode,
  onClose,
  onSuppress,
}: {
  finding: any;
  initialMode: DrawerMode;
  onClose: () => void;
  onSuppress: (f: any) => void;
}) {
  const [activeTab, setActiveTab] = useState<DrawerMode>(initialMode ?? "metadata");
  useEffect(() => { if (initialMode) setActiveTab(initialMode); }, [initialMode]);

  const tabs: { key: DrawerMode; label: string; icon: React.ElementType }[] = [
    { key: "metadata",    label: "Details",     icon: FileText },
    { key: "headers",     label: "Headers",     icon: AlignLeft },
    { key: "screenshots", label: "Screenshots", icon: Camera },
    { key: "comments",    label: "Comments",    icon: MessageSquare },
  ];

  const evidence = (() => {
    try { return JSON.parse(finding.evidence ?? "{}") as Record<string, unknown>; } catch { return {}; }
  })();
  const headers = (evidence as any).headers ?? {};

  return (
    <div className="fixed inset-0 z-40 flex justify-end" onClick={onClose}>
      <div
        className="w-full max-w-2xl h-full bg-card border-l border-border flex flex-col shadow-2xl overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between p-4 border-b border-border bg-muted/20 flex-shrink-0">
          <div className="flex-1 min-w-0 pr-4">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              {finding.isKev && <span className="text-[9px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold">KEV</span>}
              <DeltaBadge f={finding} />
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border", SEV_COLOR[finding.severity] ?? SEV_COLOR.info)}>
                {finding.severity}
              </span>
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold uppercase border", STATUS_COLOR[finding.status] ?? "")}>
                {finding.status?.replace(/_/g, " ")}
              </span>
            </div>
            <h2 className="text-sm font-semibold text-foreground leading-snug">{finding.title}</h2>
            {finding.cve && <p className="text-xs font-mono text-amber-400/80 mt-0.5">{finding.cve}</p>}
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            <Button
              size="sm"
              variant="ghost"
              className="h-7 text-[10px] px-2 text-amber-400 hover:text-amber-300 hover:bg-amber-500/10"
              onClick={() => onSuppress(finding)}
              title="Confirm false positive and add to suppression list"
            >
              <ShieldOff className="w-3.5 h-3.5 mr-1" />
              Suppress
            </Button>
            <button onClick={onClose} className="p-1.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border flex-shrink-0">
          {tabs.map(t => {
            const Icon = t.icon;
            return (
              <button
                key={t.key}
                onClick={() => setActiveTab(t.key)}
                className={cn(
                  "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors border-b-2",
                  activeTab === t.key
                    ? "border-primary text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {activeTab === "metadata" && (
            <div className="space-y-4 text-xs">
              {/* Delta diff row */}
              {(finding.isNewSinceLastScan || finding.previousScanId || finding.lastSeenAt || finding.consecutiveMissedScans > 0) && (
                <div className="bg-muted/30 rounded-lg p-3 space-y-1.5">
                  <p className="text-[11px] font-semibold text-foreground mb-2">Scan History</p>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-1">
                    {finding.firstSeenScanId && <><span className="text-muted-foreground">First seen in scan</span><span>#{finding.firstSeenScanId}</span></>}
                    {finding.previousScanId   && <><span className="text-muted-foreground">Previous scan</span><span>#{finding.previousScanId}</span></>}
                    {finding.lastSeenAt       && <><span className="text-muted-foreground">Last confirmed</span><span>{formatDate(finding.lastSeenAt)}</span></>}
                    <span className="text-muted-foreground">Consecutive misses</span><span>{finding.consecutiveMissedScans ?? 0}</span>
                    <span className="text-muted-foreground">Status</span>
                    <span className="flex items-center gap-1">
                      {finding.isNewSinceLastScan && <span className="text-emerald-400 font-bold">NEW this scan</span>}
                      {!finding.isNewSinceLastScan && finding.lastSeenAt && finding.previousScanId && <span className="text-sky-400">Re-confirmed this scan</span>}
                      {finding.status === "auto_mitigated" && <span className="text-teal-400">Auto-mitigated (not seen in recent scans)</span>}
                    </span>
                  </div>
                </div>
              )}

              {/* Description */}
              {finding.description && (
                <div>
                  <p className="text-[11px] font-semibold text-foreground mb-1">Description</p>
                  <p className="text-muted-foreground leading-relaxed">{finding.description}</p>
                </div>
              )}

              {/* Remediation */}
              {finding.remediation && (
                <div>
                  <p className="text-[11px] font-semibold text-foreground mb-1">Remediation</p>
                  <p className="text-muted-foreground leading-relaxed">{finding.remediation}</p>
                </div>
              )}

              {/* Metrics grid */}
              <div className="grid grid-cols-2 gap-x-4 gap-y-1.5">
                {finding.cvss != null && <><span className="text-muted-foreground">CVSS</span><span className="font-mono">{finding.cvss}</span></>}
                {finding.epss != null && <><span className="text-muted-foreground">EPSS</span><span className="font-mono">{(finding.epss * 100).toFixed(2)}%</span></>}
                {finding.cwe  && <><span className="text-muted-foreground">CWE</span><span className="font-mono">{finding.cwe}</span></>}
                {finding.assetName  && <><span className="text-muted-foreground">Asset</span><span>{finding.assetName}</span></>}
                {finding.assetValue && <><span className="text-muted-foreground">Target</span><span className="font-mono">{finding.assetValue}</span></>}
                <span className="text-muted-foreground">Tenant</span><span>{finding.tenantName ?? "—"}</span>
              </div>

              {/* Evidence */}
              {finding.evidence && Object.keys(evidence).length > 0 && (
                <div>
                  <p className="text-[11px] font-semibold text-foreground mb-1">Evidence</p>
                  <pre className="bg-muted/40 rounded p-2 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {activeTab === "headers" && (
            <div className="space-y-2 text-xs">
              {Object.keys(headers).length === 0
                ? <p className="text-muted-foreground/60">No HTTP header data available for this finding.</p>
                : Object.entries(headers).map(([k, v]) => (
                    <div key={k} className="flex gap-2 items-start bg-muted/20 rounded px-2 py-1.5">
                      <span className="font-mono text-primary/80 shrink-0 min-w-[180px]">{k}</span>
                      <span className="font-mono text-muted-foreground break-all">{String(v)}</span>
                    </div>
                  ))
              }
            </div>
          )}

          {activeTab === "screenshots" && (
            <div className="text-xs text-muted-foreground/60">
              Screenshot data is available in the Asset Detail view for the associated asset.
            </div>
          )}

          {activeTab === "comments" && (
            <CommentsPanel findingId={finding.id} />
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function FindingsPage() {
  const [, navigate] = useLocation();
  const searchStr = useSearch();
  const [search, setSearch]   = useState(() => {
    const p = new URLSearchParams(searchStr);
    return p.get("search") ?? "";
  });
  const [severity, setSeverity] = useState(() => {
    const p = new URLSearchParams(searchStr);
    return p.get("severity") ?? "";
  });
  const [status, setStatus]   = useState("");
  const [newOnly, setNewOnly] = useState(false);        // filter: isNewSinceLastScan
  const [staleOnly, setStaleOnly] = useState(false);   // filter: consecutiveMissedScans > 0
  const [page, setPage]       = useState(1);
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const { user } = useAuth();

  const [drawerFinding, setDrawerFinding] = useState<any>(null);
  const [drawerMode, setDrawerMode]       = useState<DrawerMode>(null);
  const [suppressTarget, setSuppressTarget] = useState<any>(null);

  const qc = useQueryClient();
  const updateFinding = useUpdateFinding();

  const handleStatusChange = async (findingId: number, newStatus: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await updateFinding.mutateAsync({ findingId, data: { status: newStatus } as any });
    qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
  };

  function openDrawer(finding: any, mode: DrawerMode) {
    setDrawerFinding(finding);
    setDrawerMode(mode);
  }
  function closeDrawer() { setDrawerMode(null); setDrawerFinding(null); }

  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";

  const params = {
    search: search || undefined,
    severity: severity || undefined,
    status: status || undefined,
    ...(isPrivileged && tenantFilter ? { tenantId: tenantFilter } : {}),
  };

  const { data: findings, isLoading } = useListFindings(params as any, {
    query: {
      queryKey: getListFindingsQueryKey(params as any),
      staleTime: 0,
      refetchOnWindowFocus: true,
      refetchInterval: 30_000,
    },
  });

  const allList = (findings as any[]) ?? [];

  // Client-side delta filters (applied after server fetch)
  const list = useMemo(() => {
    let l = allList;
    if (newOnly)   l = l.filter((f: any) => f.isNewSinceLastScan);
    if (staleOnly) l = l.filter((f: any) => (f.consecutiveMissedScans ?? 0) > 0);
    return l;
  }, [allList, newOnly, staleOnly]);

  const totalPages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  const paginated  = list.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Summary counts
  const counts = useMemo(() => ({
    critical:    allList.filter((f: any) => f.severity === "critical").length,
    high:        allList.filter((f: any) => f.severity === "high").length,
    open:        allList.filter((f: any) => f.status === "open").length,
    kev:         allList.filter((f: any) => f.isKev).length,
    newThisScan: allList.filter((f: any) => f.isNewSinceLastScan).length,
    reconfirmed: allList.filter((f: any) => !f.isNewSinceLastScan && f.lastSeenAt && f.previousScanId).length,
    stale:       allList.filter((f: any) => (f.consecutiveMissedScans ?? 0) > 0).length,
  }), [allList]);

  function resetPage() { setPage(1); }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Vulnerability Findings</h1>
          <p className="text-sm text-muted-foreground">{allList.length} findings across all assets</p>
        </div>
      </div>

      {/* Summary chips */}
      <div className="flex gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs">
          <span className="font-bold text-red-400">{counts.critical}</span>
          <span className="text-red-400/80">Critical</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/20 text-xs">
          <span className="font-bold text-orange-400">{counts.high}</span>
          <span className="text-orange-400/80">High</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-muted border border-border text-xs">
          <span className="font-bold text-foreground">{counts.open}</span>
          <span className="text-muted-foreground">Open</span>
        </div>
        {counts.kev > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 border border-red-500/30 text-xs">
            <span className="font-bold text-red-400">{counts.kev}</span>
            <span className="text-red-400/80">KEV</span>
          </div>
        )}
        {/* Delta chips */}
        {counts.newThisScan > 0 && (
          <button
            onClick={() => { setNewOnly(v => !v); setStaleOnly(false); resetPage(); }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors",
              newOnly
                ? "bg-emerald-500/25 border-emerald-500/40 text-emerald-300"
                : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20"
            )}
          >
            <Sparkles className="w-3 h-3" />
            <span className="font-bold">{counts.newThisScan}</span>
            <span className="text-emerald-400/80">New This Scan</span>
          </button>
        )}
        {counts.reconfirmed > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-500/10 border border-sky-500/20 text-xs">
            <span className="font-bold text-sky-400">{counts.reconfirmed}</span>
            <span className="text-sky-400/80">Re-confirmed</span>
          </div>
        )}
        {counts.stale > 0 && (
          <button
            onClick={() => { setStaleOnly(v => !v); setNewOnly(false); resetPage(); }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs transition-colors",
              staleOnly
                ? "bg-amber-500/25 border-amber-500/40 text-amber-300"
                : "bg-amber-500/10 border-amber-500/20 text-amber-400 hover:bg-amber-500/20"
            )}
          >
            <span className="font-bold">{counts.stale}</span>
            <span className="text-amber-400/80">Missed Scans</span>
          </button>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        <div className="relative flex-1 min-w-48 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={e => { setSearch(e.target.value); resetPage(); }}
            placeholder="Search findings..."
            className="pl-8 h-8 text-sm"
          />
        </div>
        <Select value={severity || "_all_"} onValueChange={v => { setSeverity(v === "_all_" ? "" : v); resetPage(); }}>
          <SelectTrigger className="w-34 h-8 text-sm"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All Severities</SelectItem>
            {SEVERITIES.map(s => <SelectItem key={s} value={s}>{capitalize(s)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={status || "_all_"} onValueChange={v => { setStatus(v === "_all_" ? "" : v); resetPage(); }}>
          <SelectTrigger className="w-40 h-8 text-sm"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All Statuses</SelectItem>
            {STATUSES.map(s => <SelectItem key={s} value={s}>{capitalize(s.replace(/_/g, " "))}</SelectItem>)}
          </SelectContent>
        </Select>
        {/* Delta quick-filters */}
        <Button
          size="sm"
          variant={newOnly ? "default" : "outline"}
          className={cn("h-8 text-xs gap-1.5", newOnly && "bg-emerald-600 text-white hover:bg-emerald-700 border-emerald-700")}
          onClick={() => { setNewOnly(v => !v); setStaleOnly(false); resetPage(); }}
        >
          <Sparkles className="w-3.5 h-3.5" />
          New Only
        </Button>
        <Button
          size="sm"
          variant={staleOnly ? "default" : "outline"}
          className={cn("h-8 text-xs gap-1.5", staleOnly && "bg-amber-600 text-white hover:bg-amber-700 border-amber-700")}
          onClick={() => { setStaleOnly(v => !v); setNewOnly(false); resetPage(); }}
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Missed Scans
        </Button>
        <Button variant="outline" size="sm" onClick={() => { setSeverity(""); setStatus(""); setSearch(""); setTenantFilter(null); setNewOnly(false); setStaleOnly(false); resetPage(); }}>
          Clear
        </Button>
        {isPrivileged && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); resetPage(); }} />}
      </div>

      {/* Active filter hint */}
      {(newOnly || staleOnly) && (
        <div className="flex items-center gap-2 text-xs">
          <span className="text-muted-foreground">Showing:</span>
          {newOnly   && <span className="text-emerald-400 font-medium">✦ new findings from latest scan</span>}
          {staleOnly && <span className="text-amber-400 font-medium">⚠ findings missed in recent scans</span>}
          <span className="text-muted-foreground">({list.length} result{list.length !== 1 ? "s" : ""})</span>
        </div>
      )}

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[1200px]">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground w-[260px]">Title</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset Detail</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset Type</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset</th>
                {isPrivileged && <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Client</th>}
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Severity</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">ASM Score</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">First Scan</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Last Seen</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Imp. Score</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Status</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">CVE</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(8)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(12)].map((_, j) => (
                    <td key={j} className="px-3 py-3"><Skeleton className="h-4" /></td>
                  ))}
                </tr>
              ))}

              {!isLoading && paginated.map((f: any) => {
                const TypeIcon = ASSET_TYPE_ICON[f.assetType ?? ""] ?? Globe;
                const StatusIcon = STATUS_ICON[f.status] ?? Minus;
                const impScore = importanceScore(f);

                return (
                  <tr key={f.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors group cursor-pointer" onClick={() => openDrawer(f, "metadata")}>
                    {/* Title + delta badge */}
                    <td className="px-3 py-2.5 max-w-[260px]">
                      <div className="flex items-start gap-1.5">
                        {f.isKev && (
                          <span className="text-[9px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold shrink-0 mt-0.5">KEV</span>
                        )}
                        <DeltaBadge f={f} />
                        <span className="font-medium text-foreground line-clamp-2 text-xs leading-snug">{f.title}</span>
                      </div>
                    </td>

                    {/* Asset Detail (value) */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs font-mono text-primary/90">{f.assetValue ?? "—"}</span>
                    </td>

                    {/* Asset Type */}
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <TypeIcon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        <span className="text-xs text-muted-foreground">{assetTypeLabel(f.assetType)}</span>
                      </div>
                    </td>

                    {/* Asset Name */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground truncate max-w-[100px] block">{f.assetName ?? "—"}</span>
                    </td>

                    {/* Client Tenant (admin/SA only) */}
                    {isPrivileged && (
                      <td className="px-3 py-2.5">
                        <span className="text-xs text-muted-foreground truncate max-w-[100px] block">{(f as any).tenantName ?? "—"}</span>
                      </td>
                    )}

                    {/* Severity */}
                    <td className="px-3 py-2.5">
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border", SEV_COLOR[f.severity] ?? SEV_COLOR.info)}>
                        {f.severity}
                      </span>
                    </td>

                    {/* ASM Score */}
                    <td className="px-3 py-2.5">
                      <ScoreBadge score={f.riskScore != null ? Math.round(f.riskScore) : null} label="Attack Surface Management Score" />
                    </td>

                    {/* First Scan (finding createdAt = first time found) */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">{formatDate(f.createdAt)}</span>
                    </td>

                    {/* Last Seen (lastSeenAt from delta tracking) */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">
                        {f.lastSeenAt ? formatDate(f.lastSeenAt) : "—"}
                      </span>
                    </td>

                    {/* Importance Score */}
                    <td className="px-3 py-2.5">
                      <ScoreBadge score={impScore} label="Importance Score (derived from CVSS, EPSS, KEV)" />
                    </td>

                    {/* Status — inline dropdown */}
                    <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                      <select
                        value={f.status ?? "open"}
                        onChange={e => handleStatusChange(f.id, e.target.value, e as any)}
                        className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase cursor-pointer bg-transparent outline-none",
                          STATUS_COLOR[f.status] ?? "border-border text-muted-foreground"
                        )}
                      >
                        {STATUSES.map(s => (
                          <option key={s} value={s} className="bg-card text-foreground normal-case">
                            {s.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                    </td>

                    {/* CVE */}
                    <td className="px-3 py-2.5">
                      {f.cve ? (
                        <span className="text-xs font-mono text-amber-400/90">{f.cve}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground/40">—</span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "metadata"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors font-medium"
                          title="View Details"
                        >
                          <FileText className="w-3 h-3" />
                          <span className="hidden xl:inline">Details</span>
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "comments"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-accent/60 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors font-medium"
                          title="Comments"
                        >
                          <MessageSquare className="w-3 h-3" />
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); setSuppressTarget(f); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors font-medium"
                          title="Confirm false positive + suppress"
                        >
                          <ShieldOff className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}

              {!isLoading && list.length === 0 && (
                <tr>
                  <td colSpan={13} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No findings match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {!isLoading && totalPages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <p className="text-xs text-muted-foreground">
            Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, list.length)} of {list.length} findings
          </p>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" className="h-7 px-2" disabled={page === 1} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              const p = totalPages <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= totalPages - 3 ? totalPages - 6 + i : page - 3 + i;
              if (p < 1 || p > totalPages) return null;
              return (
                <Button key={p} size="sm" variant={p === page ? "default" : "outline"} className="h-7 w-7 p-0 text-xs" onClick={() => setPage(p)}>{p}</Button>
              );
            })}
            <Button size="sm" variant="outline" className="h-7 px-2" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}

      {/* Finding Drawer */}
      {drawerFinding && drawerMode && (
        <FindingDrawer
          finding={drawerFinding}
          initialMode={drawerMode}
          onClose={closeDrawer}
          onSuppress={(f) => { setSuppressTarget(f); }}
        />
      )}

      {/* Suppress Modal */}
      {suppressTarget && (
        <SuppressModal
          finding={suppressTarget}
          onClose={() => setSuppressTarget(null)}
          onDone={() => {
            qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
            setSuppressTarget(null);
            closeDrawer();
          }}
        />
      )}
    </div>
  );
}
