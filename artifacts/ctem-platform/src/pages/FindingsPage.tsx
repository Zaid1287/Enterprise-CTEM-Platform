import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { Link, useLocation, useSearch } from "wouter";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useListFindings, useUpdateFinding, getListFindingsQueryKey,
  useListFindingComments, useCreateFindingComment, getListFindingCommentsQueryKey,
  useListAssetGroups, useGetAssetGroupMembers,
  getListAssetGroupsQueryKey, getGetAssetGroupMembersQueryKey,
  useListAssetScreenshots, getListAssetScreenshotsQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient, useQuery } from "@tanstack/react-query";
import {
  Search, ExternalLink, ChevronLeft, ChevronRight, X,
  ShieldAlert, Globe, Network, Server, Cpu, Smartphone,
  FileText, Code2, Camera, Tag, Info,
  CheckCircle2, Clock, AlertCircle, XCircle, Minus,
  MessageSquare, Send, Loader2, Sparkles, RefreshCw, ShieldOff, Layers, Brain,
  Shield, Target, Users, Bug, AlertTriangle,
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

/**
 * Importance score 0–100.
 * Weighted: CVSS (0–50 pts) + EPSS (0–30 pts) + KEV bonus (20 pts) = max 100.
 * Falls back to severity label only when no CVSS, EPSS, or KEV data exists.
 * SINGLE SOURCE OF TRUTH — keep in sync with FindingDetailPage.tsx.
 */
function importanceScore(f: any): number | null {
  const SEV: Record<string, number> = { critical: 85, high: 65, medium: 40, low: 20, info: 10 };
  const cvssRaw = typeof f.cvss === "number" ? f.cvss : parseFloat(String(f.cvss ?? ""));
  const epssRaw = typeof f.epss === "number" ? f.epss : parseFloat(String(f.epss ?? ""));
  const cvssVal = isNaN(cvssRaw) ? 0 : cvssRaw;
  const epssVal = isNaN(epssRaw) ? 0 : epssRaw;
  const kevPts  = f.isKev ? 20 : 0;
  if (cvssVal === 0 && epssVal === 0 && !f.isKev) return SEV[f.severity ?? ""] ?? null;
  return Math.min(100, Math.round(cvssVal * 5 + epssVal * 30 + kevPts));
}

// ── Score Badge ─────────────────────────────────────────────────────────────

function ScoreBadge({ score, label }: { score: number | null; label: string }) {
  if (score === null) return <span className="text-xs text-muted-foreground/40">—</span>;
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : score >= 20 ? "text-blue-400" : "text-muted-foreground";
  return <span className={cn("text-xs font-mono font-semibold", color)} title={label}>{score}</span>;
}

// ── Threat Score Badge ───────────────────────────────────────────────────────

const TI_EXPLOIT_MAP: Record<string, { label: string; cls: string }> = {
  active:    { label: "Active",    cls: "bg-red-500/20 text-red-400 border-red-500/30" },
  confirmed: { label: "Confirmed", cls: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  potential: { label: "Potential", cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  unknown:   { label: "Unknown",   cls: "bg-muted text-muted-foreground/60 border-border" },
};

function ThreatScoreBadge({
  score,
  exploitationStatus,
  onClick,
}: {
  score: number | null;
  exploitationStatus: string | null;
  onClick: (e: React.MouseEvent) => void;
}) {
  if (score === null) return <span className="text-xs text-muted-foreground/40">—</span>;
  const rounded = Math.round(score);
  const numColor =
    rounded >= 80 ? "text-red-400" :
    rounded >= 60 ? "text-orange-400" :
    rounded >= 40 ? "text-yellow-400" :
    rounded >= 20 ? "text-blue-400" :
    "text-muted-foreground";
  const es = TI_EXPLOIT_MAP[exploitationStatus ?? "unknown"] ?? TI_EXPLOIT_MAP.unknown;
  return (
    <button
      onClick={(e) => { e.stopPropagation(); onClick(e); }}
      className="flex items-center gap-1 group/tib"
      title={`Threat Intel correlation score: ${rounded}/100 · ${es.label} exploitation · Click to open Threat Intel tab`}
    >
      <span className={cn("text-xs font-mono font-bold group-hover/tib:underline", numColor)}>
        {rounded}
      </span>
      <span className={cn("text-[9px] px-1 py-0.5 rounded font-semibold border", es.cls)}>
        {es.label}
      </span>
    </button>
  );
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
type DrawerMode = "metadata" | "screenshots" | "comments" | "ai" | "threat-intel" | null;

// ── Exploitation status badge ─────────────────────────────────────────────────
function ExploitationBadge({ status }: { status: string }) {
  const MAP: Record<string, { label: string; cls: string }> = {
    active:    { label: "Active", cls: "bg-red-500/20 text-red-400 border-red-500/30" },
    confirmed: { label: "Confirmed", cls: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
    potential: { label: "Potential", cls: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
    unknown:   { label: "Unknown", cls: "bg-muted text-muted-foreground border-border" },
  };
  const s = MAP[status] ?? MAP.unknown;
  return (
    <span className={cn("text-[9px] px-1.5 py-0.5 rounded font-semibold border", s.cls)}>
      {s.label}
    </span>
  );
}

// ── Threat Intel Tab ─────────────────────────────────────────────────────────
function ThreatIntelTab({ finding }: { finding: any }) {
  const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const { data: moduleData } = useQuery({
    queryKey: ["ti-module"],
    queryFn: () => apiFetch<{ isEnabled: boolean }>(`${BASE}/api/threat-intel/module`),
    staleTime: 60_000,
  });

  const {
    data: corrData,
    isLoading: corrLoading,
    refetch,
  } = useQuery({
    queryKey: ["ti-correlations-finding", finding.id],
    queryFn: () =>
      apiFetch<{ correlations: any[] }>(
        `${BASE}/api/threat-intel/correlations/finding/${finding.id}`,
      ),
    enabled: moduleData?.isEnabled !== false,
    staleTime: 30_000,
  });

  const [correlating, setCorrelating] = useState(false);
  const [aiText, setAiText]           = useState("");
  const [aiLoading, setAiLoading]     = useState(false);
  const [aiNoKey, setAiNoKey]         = useState(false);

  const corr = corrData?.correlations?.[0] ?? null;

  const triggerCorrelation = async () => {
    setCorrelating(true);
    try {
      await apiFetch(`${BASE}/api/threat-intel/correlate`, { method: "POST" });
      setTimeout(async () => { await refetch(); setCorrelating(false); }, 3500);
    } catch { setCorrelating(false); }
  };

  const triggerAiExplain = useCallback(async () => {
    if (aiLoading) return;
    setAiText(""); setAiLoading(true); setAiNoKey(false);
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    try {
      const resp = await fetch(`${BASE}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: "explain-ti-correlation", findingId: finding.id }),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n"); buf = parts.pop() ?? "";
        for (const line of parts) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.noKey) setAiNoKey(true);
            if (d.text) { accumulated += d.text; setAiText(accumulated); }
          } catch { /* ignore */ }
        }
      }
    } catch { setAiText("Failed to load AI analysis."); }
    setAiLoading(false);
  }, [finding.id, BASE]);

  if (!moduleData) {
    return <div className="space-y-2"><Skeleton className="h-12 w-full" /><Skeleton className="h-8 w-3/4" /></div>;
  }

  if (!moduleData.isEnabled) {
    return (
      <div className="flex flex-col items-center justify-center py-10 gap-3 text-center">
        <Shield className="w-8 h-8 text-muted-foreground/30" />
        <p className="text-sm font-medium text-foreground">Threat Intelligence not enabled</p>
        <p className="text-xs text-muted-foreground">Enable the TI module to correlate this finding against the global threat database.</p>
        <a href="/threat-intel">
          <Button size="sm" variant="outline">Go to Threat Intel →</Button>
        </a>
      </div>
    );
  }

  if (corrLoading) {
    return <div className="space-y-2"><Skeleton className="h-16 w-full" /><Skeleton className="h-12 w-3/4" /><Skeleton className="h-10 w-full" /></div>;
  }

  if (!corr) {
    return (
      <div className="flex flex-col items-center py-10 gap-3 text-center">
        <Shield className="w-8 h-8 text-muted-foreground/30" />
        <p className="text-sm font-medium">No correlation data yet</p>
        <p className="text-xs text-muted-foreground max-w-[220px]">
          Run correlation to match this finding against the TI database (IOCs, threat actors, CVE intel, C2 servers).
        </p>
        {isAdmin && (
          <Button size="sm" onClick={triggerCorrelation} disabled={correlating}>
            {correlating
              ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Correlating…</>
              : <><Shield className="w-3.5 h-3.5 mr-1.5" />Correlate Now</>}
          </Button>
        )}
      </div>
    );
  }

  const actors    = (corr.matchedActors    as any[]) ?? [];
  const iocs      = (corr.matchedIocs      as any[]) ?? [];
  const cves      = (corr.matchedCves      as any[]) ?? [];
  const malware   = (corr.matchedMalware   as any[]) ?? [];
  const campaigns = (corr.matchedCampaigns as any[]) ?? [];
  const basis     = (corr.correlationBasis as string[]) ?? [];

  return (
    <div className="space-y-4 text-xs">
      {/* ── Threat score header ── */}
      <div className="flex items-center justify-between p-3 rounded-xl border bg-muted/20">
        <div className="flex items-center gap-3">
          <div className={cn(
            "w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold text-white shrink-0",
            corr.threatScore >= 70 ? "bg-red-500" : corr.threatScore >= 40 ? "bg-orange-500" : "bg-yellow-500",
          )}>
            {corr.threatScore}
          </div>
          <div>
            <p className="text-[11px] font-semibold">Threat Score</p>
            <p className="text-[10px] text-muted-foreground">TI correlation</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ExploitationBadge status={corr.exploitationStatus} />
          {isAdmin && (
            <Button
              size="sm" variant="ghost" className="h-6 w-6 p-0 text-muted-foreground"
              onClick={() => refetch()} disabled={correlating} title="Re-correlate"
            >
              <RefreshCw className={cn("w-3 h-3", correlating && "animate-spin")} />
            </Button>
          )}
        </div>
      </div>

      {/* ── Risk boost ── */}
      {corr.riskBoost > 0 && (
        <div className="flex items-center gap-2 text-[10px] text-amber-400/90 bg-amber-500/8 border border-amber-500/20 rounded-lg px-3 py-2">
          <AlertTriangle className="w-3 h-3 shrink-0" />
          TI correlation adds <strong>+{corr.riskBoost}</strong> risk boost to this finding's score
        </div>
      )}

      {/* ── Matched threat actors ── */}
      {actors.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-2 flex items-center gap-1.5">
            <Users className="w-3.5 h-3.5 text-purple-400" />
            Threat Actors ({actors.length})
          </p>
          <div className="space-y-1.5">
            {actors.map((a: any, i: number) => (
              <div key={i} className="flex items-start justify-between bg-purple-500/5 border border-purple-500/15 rounded-lg px-3 py-2 gap-2">
                <div className="min-w-0">
                  <p className="font-semibold text-[11px] truncate">{a.name}</p>
                  <p className="text-muted-foreground text-[10px]">{a.country ?? "Unknown origin"} · {a.motivation ?? "Unknown motivation"}</p>
                  <p className="text-purple-400/70 text-[10px] italic">{a.matchReason}</p>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-[10px] font-semibold text-orange-400">Risk {Math.round(a.riskScore ?? 0)}</p>
                  {a.mitreId && <p className="text-[9px] text-muted-foreground font-mono">{a.mitreId}</p>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Linked campaigns ── */}
      {campaigns.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-2 flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            Linked Campaigns ({campaigns.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {campaigns.map((c: any, i: number) => (
              <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">
                {c.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── CVE intelligence ── */}
      {cves.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-2 flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
            CVE Intelligence
          </p>
          {cves.map((c: any, i: number) => (
            <div key={i} className="bg-red-500/5 border border-red-500/15 rounded-lg px-3 py-2 space-y-1.5">
              <div className="flex items-center justify-between">
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`}
                  target="_blank" rel="noopener noreferrer"
                  className="font-mono text-[11px] text-amber-400 hover:underline"
                >
                  {c.cveId}
                </a>
                <div className="flex gap-1.5">
                  {c.isKev && (
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold">KEV</span>
                  )}
                  <ExploitationBadge status={c.exploitationStatus} />
                </div>
              </div>
              <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
                {c.cvss  != null && <span>CVSS: <span className="text-foreground font-mono">{c.cvss}</span></span>}
                {c.epss  != null && <span>EPSS: <span className="text-foreground font-mono">{(c.epss * 100).toFixed(2)}%</span></span>}
                {c.patchAvailable && <span className="text-green-400">✓ Patch available</span>}
              </div>
              {c.linkedActors?.length > 0 && (
                <p className="text-[10px] text-muted-foreground">
                  Linked actors: <span className="text-foreground">{c.linkedActors.slice(0, 3).join(", ")}{c.linkedActors.length > 3 ? ` +${c.linkedActors.length - 3}` : ""}</span>
                </p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* ── Matched IOCs ── */}
      {iocs.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-2 flex items-center gap-1.5">
            <Target className="w-3.5 h-3.5 text-orange-400" />
            Matched IOCs ({iocs.length})
          </p>
          <div className="space-y-1.5">
            {iocs.map((ioc: any, i: number) => (
              <div key={i} className="flex items-start justify-between bg-orange-500/5 border border-orange-500/15 rounded-lg px-3 py-2 gap-2">
                <div className="min-w-0">
                  <p className="font-mono text-[10px] text-foreground truncate">{ioc.type}: {ioc.value}</p>
                  <p className="text-muted-foreground text-[10px]">{(ioc.sources as string[])?.join(", ") ?? "unknown source"}</p>
                  <p className="text-orange-400/70 text-[10px] italic">{ioc.matchReason}</p>
                </div>
                <div className="text-right shrink-0">
                  <span className={cn(
                    "text-[9px] px-1.5 py-0.5 rounded font-semibold border capitalize",
                    ioc.severity === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                    ioc.severity === "high"     ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                                                  "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
                  )}>
                    {ioc.severity}
                  </span>
                  <p className="text-[10px] text-muted-foreground mt-0.5">Score: {Math.round(ioc.threatScore ?? 0)}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Linked malware ── */}
      {malware.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-2 flex items-center gap-1.5">
            <Bug className="w-3.5 h-3.5 text-yellow-400" />
            Linked Malware ({malware.length})
          </p>
          <div className="flex flex-wrap gap-1.5">
            {malware.map((m: any, i: number) => (
              <span key={i} className="text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">
                {m.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Correlation basis ── */}
      {basis.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold mb-1 text-muted-foreground">Match Basis</p>
          <div className="flex flex-wrap gap-1">
            {basis.map((b, i) => (
              <span key={i} className="text-[9px] px-1.5 py-0.5 bg-muted rounded font-mono text-muted-foreground">
                {b.replace(/_/g, " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── AI Threat Analysis ── */}
      <div className="border-t border-border pt-3">
        <div className="flex items-center justify-between mb-2">
          <p className="text-[11px] font-semibold flex items-center gap-1.5">
            <Brain className="w-3.5 h-3.5 text-violet-400" />
            AI Threat Analysis
          </p>
          <Button
            size="sm" variant="ghost"
            className="h-6 text-[10px] px-2 text-muted-foreground hover:text-foreground"
            onClick={() => { setAiText(""); triggerAiExplain(); }}
            disabled={aiLoading}
          >
            {aiText
              ? <RefreshCw className={cn("w-3 h-3", aiLoading && "animate-spin")} />
              : aiLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : "Analyse →"}
          </Button>
        </div>
        {aiNoKey && (
          <div className="flex items-center gap-2 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded-lg px-2.5 py-1.5 mb-2">
            <Sparkles className="w-3 h-3 shrink-0" />
            Template response — <a href="/settings/account" className="underline ml-0.5">add API key</a> for AI analysis
          </div>
        )}
        {aiLoading && !aiText ? (
          <div className="space-y-1.5">
            <Skeleton className="h-3 w-full" />
            <Skeleton className="h-3 w-4/5" />
            <Skeleton className="h-3 w-3/4" />
            <div className="flex items-center gap-1 text-[10px] text-muted-foreground/50 mt-2">
              <Sparkles className="w-3 h-3 animate-pulse text-primary" />
              Analysing threat context…
            </div>
          </div>
        ) : aiText ? (
          <div className="bg-muted/20 border border-border/40 rounded-xl p-3">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                h2: ({ children }) => <h2 className="text-xs font-bold mt-2 mb-1 text-foreground">{children}</h2>,
                h3: ({ children }) => <h3 className="text-[11px] font-semibold mt-1.5 mb-0.5 text-foreground/90">{children}</h3>,
                p: ({ children }) => <p className="text-[11px] text-muted-foreground mb-1 leading-relaxed">{children}</p>,
                ul: ({ children }) => <ul className="list-disc pl-3 space-y-0.5 mb-1">{children}</ul>,
                ol: ({ children }) => <ol className="list-decimal pl-3 space-y-0.5 mb-1">{children}</ol>,
                li: ({ children }) => <li className="text-[11px] text-muted-foreground">{children}</li>,
                strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 text-[11px]">{children}</a>,
              }}
            >
              {aiText}
            </ReactMarkdown>
            {aiLoading && <span className="inline-block w-1.5 h-3.5 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
          </div>
        ) : null}
      </div>

      {/* ── Correlated timestamp ── */}
      <p className="text-[10px] text-muted-foreground/40 text-right">
        Correlated {new Date(corr.correlatedAt).toLocaleString()}
        {isAdmin && (
          <button
            onClick={triggerCorrelation}
            disabled={correlating}
            className="ml-2 underline underline-offset-2 hover:text-muted-foreground"
          >
            {correlating ? "re-correlating…" : "re-correlate"}
          </button>
        )}
      </p>
    </div>
  );
}

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
  const [, navigate] = useLocation();
  const qcDrawer = useQueryClient();
  const updateDrawerFinding = useUpdateFinding();
  const [localSeverity, setLocalSeverity] = useState<string>(finding.severity ?? "medium");
  const [sevSaving, setSevSaving] = useState(false);

  useEffect(() => { setLocalSeverity(finding.severity ?? "medium"); }, [finding.id, finding.severity]);

  async function handleSeverityChange(newSev: string) {
    if (newSev === localSeverity || sevSaving) return;
    setSevSaving(true);
    try {
      await updateDrawerFinding.mutateAsync({ findingId: finding.id, data: { severity: newSev } as any });
      setLocalSeverity(newSev);
      qcDrawer.invalidateQueries({ queryKey: getListFindingsQueryKey() });
    } catch { /* toast shown by mutation cache */ }
    finally { setSevSaving(false); }
  }

  // Real screenshots from DB for this finding's asset
  const { data: drawerScreenshots } = useListAssetScreenshots(
    finding.assetId,
    { query: { queryKey: getListAssetScreenshotsQueryKey(finding.assetId), enabled: !!finding.assetId } },
  );

  const [activeTab, setActiveTab] = useState<DrawerMode>(initialMode ?? "metadata");
  useEffect(() => { if (initialMode) setActiveTab(initialMode); }, [initialMode]);

  const tabs: { key: DrawerMode; label: string; icon: React.ElementType }[] = [
    { key: "metadata",     label: "Details",      icon: FileText },
    { key: "screenshots",  label: "Screenshots",  icon: Camera },
    { key: "comments",     label: "Comments",     icon: MessageSquare },
    { key: "ai",           label: "Ask AI",       icon: Brain },
    { key: "threat-intel", label: "Threat Intel", icon: Shield },
  ];

  // ── AI tab state ────────────────────────────────────────────────────────────
  const [aiText, setAiText]       = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiNoKey, setAiNoKey]     = useState(false);
  const [aiModel, setAiModel]     = useState<string | null>(null);
  const [aiUsage, setAiUsage]     = useState<{ totalTokens: number } | null>(null);
  const aiAbortRef                = useRef(false);

  const BASE_AI = import.meta.env.BASE_URL.replace(/\/$/, "");

  const triggerAiExplain = useCallback(async () => {
    if (aiLoading) return;
    aiAbortRef.current = false;
    setAiText(""); setAiLoading(true); setAiNoKey(false); setAiModel(null); setAiUsage(null);
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    try {
      const resp = await fetch(`${BASE_AI}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: "explain-finding", findingId: finding.id }),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        if (aiAbortRef.current) { reader.cancel(); break; }
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.noKey) setAiNoKey(true);
            if (d.provider) setAiModel(d.provider);
            if (d.text) { accumulated += d.text; setAiText(accumulated); }
            if (d.usage) setAiUsage({ totalTokens: d.usage.totalTokens ?? 0 });
          } catch { /* ignore */ }
        }
      }
    } catch { setAiText(accumulated || "Failed to load AI analysis. Please try again."); }
    setAiLoading(false);
  }, [finding.id, BASE_AI]);

  // Auto-trigger on first visit to AI tab
  useEffect(() => {
    if (activeTab === "ai" && !aiText && !aiLoading) {
      triggerAiExplain();
    }
  }, [activeTab]);

  const evidence = (() => {
    try { return JSON.parse(finding.evidence ?? "{}") as Record<string, unknown>; } catch { return {}; }
  })();

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
              {/* Severity selector — upgrade / downgrade */}
              <select
                value={localSeverity}
                onChange={e => handleSeverityChange(e.target.value)}
                disabled={sevSaving}
                title="Change severity (recalculates risk score)"
                className={cn(
                  "text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border cursor-pointer bg-transparent outline-none",
                  sevSaving ? "opacity-50" : "",
                  SEV_COLOR[localSeverity] ?? SEV_COLOR.info,
                )}
              >
                {SEVERITIES.map(s => (
                  <option key={s} value={s} className="bg-card text-foreground normal-case font-normal">
                    {s}
                  </option>
                ))}
              </select>
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-semibold uppercase border", STATUS_COLOR[finding.status] ?? "")}>
                {finding.status?.replace(/_/g, " ")}
              </span>
            </div>
            <h2 className="text-sm font-semibold text-foreground leading-snug">{finding.title}</h2>
            {finding.cve && <p className="text-xs font-mono text-amber-400/80 mt-0.5">{finding.cve}</p>}
          </div>
          <div className="flex items-center gap-1.5 flex-shrink-0">
            {/* Open full detail page */}
            <Button
              size="sm"
              variant="ghost"
              className="h-7 text-[10px] px-2 text-primary hover:text-primary hover:bg-primary/10"
              onClick={() => { onClose(); navigate(`/findings/${finding.id}`); }}
              title="Open full detail page"
            >
              <ExternalLink className="w-3.5 h-3.5 mr-1" />
              Full Page
            </Button>
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

          {activeTab === "screenshots" && (
            <div className="space-y-3">
              {!finding.assetId ? (
                <p className="text-xs text-muted-foreground/60 text-center py-8">No asset linked to this finding.</p>
              ) : !drawerScreenshots ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground/40" />
                </div>
              ) : (drawerScreenshots as any[]).length === 0 ? (
                <div className="rounded-lg border border-border bg-muted/20 p-6 flex flex-col items-center gap-3 text-center">
                  <Camera className="w-8 h-8 text-muted-foreground/30" />
                  <div>
                    <p className="text-sm font-medium text-foreground">No screenshots yet</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      Screenshots are captured during active scans. Run a scan on this asset to generate them.
                    </p>
                  </div>
                  <button
                    onClick={() => { onClose(); navigate(`/assets/${finding.assetId}`); }}
                    className="text-xs text-primary hover:text-primary/80 underline underline-offset-2 font-medium"
                  >
                    Go to asset →
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  {(drawerScreenshots as any[]).map((s: any) => (
                    <div key={s.id} className="rounded-lg border border-border overflow-hidden bg-muted/10">
                      {s.screenshotData ? (
                        <img
                          src={`data:image/png;base64,${s.screenshotData}`}
                          alt={s.title ?? s.url ?? "Screenshot"}
                          className="w-full object-cover max-h-72"
                        />
                      ) : (
                        <div className="h-28 flex items-center justify-center bg-muted/30">
                          <Camera className="w-8 h-8 text-muted-foreground/30" />
                        </div>
                      )}
                      <div className="px-3 py-2 space-y-0.5">
                        {s.title && <p className="text-xs font-medium text-foreground truncate">{s.title}</p>}
                        {s.url && (
                          <a href={s.url} target="_blank" rel="noopener noreferrer"
                            className="text-[10px] text-primary/70 hover:text-primary truncate block font-mono">
                            {s.url}
                          </a>
                        )}
                        <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                          {s.statusCode && <span className={cn("font-mono", s.statusCode < 400 ? "text-green-400" : "text-red-400")}>HTTP {s.statusCode}</span>}
                          {s.capturedAt && <span>{formatDate(s.capturedAt)}</span>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "comments" && (
            <CommentsPanel findingId={finding.id} />
          )}

          {activeTab === "threat-intel" && (
            <ThreatIntelTab finding={finding} />
          )}

          {activeTab === "ai" && (
            <div className="space-y-3">
              {/* Header row */}
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  <Brain className="w-3.5 h-3.5 text-primary" />
                  <span className="text-[11px] font-semibold">AI Vulnerability Analysis</span>
                  {aiModel && !aiLoading && (
                    <span className="text-[9px] text-green-400/70 font-mono">⚡ {aiModel}</span>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  {aiUsage && !aiLoading && (
                    <span className="text-[9px] text-muted-foreground/40">~{aiUsage.totalTokens.toLocaleString()} tokens</span>
                  )}
                  <Button
                    size="sm" variant="ghost"
                    className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
                    onClick={() => { setAiText(""); triggerAiExplain(); }}
                    disabled={aiLoading}
                    title="Regenerate"
                  >
                    <RefreshCw className={cn("w-3 h-3", aiLoading && "animate-spin")} />
                  </Button>
                  <a
                    href={`/ai-copilot?findingId=${finding.id}&action=explain`}
                    className="text-[9px] text-primary/70 hover:text-primary underline underline-offset-2 whitespace-nowrap"
                  >
                    Full view →
                  </a>
                </div>
              </div>

              {/* No-key warning */}
              {aiNoKey && !aiLoading && (
                <div className="flex items-center gap-2 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded-lg px-2.5 py-1.5">
                  <Sparkles className="w-3 h-3 shrink-0" />
                  Template response — <a href="/settings/account" className="underline ml-0.5">add an API key</a> for real AI analysis.
                </div>
              )}

              {/* Streaming content */}
              <div className="bg-muted/20 border border-border/40 rounded-xl p-3 min-h-32">
                {aiLoading && !aiText ? (
                  <div className="space-y-2">
                    <Skeleton className="h-3 w-3/4" />
                    <Skeleton className="h-3 w-full" />
                    <Skeleton className="h-3 w-5/6" />
                    <div className="flex items-center gap-1.5 text-[10px] text-muted-foreground/50 mt-3">
                      <Sparkles className="w-3 h-3 animate-pulse text-primary" />
                      Analysing vulnerability…
                    </div>
                  </div>
                ) : (
                  <>
                    <ReactMarkdown
                      remarkPlugins={[remarkGfm]}
                      components={{
                        h2: ({ children }) => <h2 className="text-xs font-bold mt-3 mb-1.5 text-foreground">{children}</h2>,
                        h3: ({ children }) => <h3 className="text-[11px] font-semibold mt-2 mb-1 text-foreground/90">{children}</h3>,
                        p: ({ children }) => <p className="text-[11px] text-muted-foreground mb-1.5 leading-relaxed">{children}</p>,
                        ul: ({ children }) => <ul className="list-disc pl-4 space-y-0.5 mb-1.5">{children}</ul>,
                        ol: ({ children }) => <ol className="list-decimal pl-4 space-y-0.5 mb-1.5">{children}</ol>,
                        li: ({ children }) => <li className="text-[11px] text-muted-foreground">{children}</li>,
                        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                        code: ({ children }) => <code className="font-mono text-[10px] bg-muted/60 px-1 rounded text-primary">{children}</code>,
                        blockquote: ({ children }) => <blockquote className="border-l-2 border-primary/30 pl-2 my-1.5 italic text-muted-foreground text-[11px]">{children}</blockquote>,
                        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 text-[11px]">{children}</a>,
                      }}
                    >
                      {aiText}
                    </ReactMarkdown>
                    {aiLoading && <span className="inline-block w-1.5 h-3.5 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
                  </>
                )}
              </div>

              {/* Quick actions */}
              {!aiLoading && aiText && (
                <div className="flex flex-wrap gap-1.5">
                  <a
                    href={`/ai-copilot?findingId=${finding.id}&action=remediation`}
                    className="text-[10px] border border-border/50 rounded-full px-2.5 py-0.5 hover:bg-accent transition-colors text-muted-foreground hover:text-foreground"
                  >
                    Get Remediation Plan →
                  </a>
                  <a
                    href={`/ai-copilot?findingId=${finding.id}&action=chat`}
                    className="text-[10px] border border-border/50 rounded-full px-2.5 py-0.5 hover:bg-accent transition-colors text-muted-foreground hover:text-foreground"
                  >
                    Chat about this finding →
                  </a>
                  {finding.cve && (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                      target="_blank" rel="noopener noreferrer"
                      className="text-[10px] border border-border/50 rounded-full px-2.5 py-0.5 hover:bg-accent transition-colors text-muted-foreground hover:text-foreground"
                    >
                      NVD: {finding.cve} ↗
                    </a>
                  )}
                </div>
              )}
            </div>
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
  const [groupFilter, setGroupFilter]   = useState<number | null>(null);
  const { user } = useAuth();

  const { data: allGroups } = useListAssetGroups({
    query: { queryKey: getListAssetGroupsQueryKey() },
  });
  const { data: groupMembersRaw } = useGetAssetGroupMembers(groupFilter ?? 0, {
    query: {
      queryKey: getGetAssetGroupMembersQueryKey(groupFilter ?? 0),
      enabled: groupFilter !== null,
    },
  });
  const groupMemberIdSet = useMemo(() => {
    if (groupFilter === null || !groupMembersRaw) return null;
    return new Set((groupMembersRaw as any[]).map((m: any) => m.assetId ?? m.id));
  }, [groupFilter, groupMembersRaw]);

  const groupList = (allGroups as any[]) ?? [];

  const [sortBy, setSortBy] = useState<string>("");

  const BASE_PAGE = import.meta.env.BASE_URL.replace(/\/$/, "");

  const { data: tiModuleData } = useQuery({
    queryKey: ["ti-module"],
    queryFn: () => apiFetch<{ isEnabled: boolean }>(`${BASE_PAGE}/api/threat-intel/module`),
    staleTime: 60_000,
  });
  const tiEnabled = tiModuleData?.isEnabled === true;

  const [drawerFinding, setDrawerFinding] = useState<any>(null);
  const [drawerMode, setDrawerMode]       = useState<DrawerMode>(null);
  const [suppressTarget, setSuppressTarget] = useState<any>(null);
  // False-positive reason modal
  const [fpTarget, setFpTarget]   = useState<{ id: number } | null>(null);
  const [fpReason, setFpReason]   = useState("");
  const [fpSaving, setFpSaving]   = useState(false);

  const qc = useQueryClient();
  const updateFinding = useUpdateFinding();

  const handleStatusChange = async (findingId: number, newStatus: string, e: React.MouseEvent) => {
    e.stopPropagation();
    // Intercept false_positive — ask for a reason first
    if (newStatus === "false_positive") {
      setFpReason("");
      setFpTarget({ id: findingId });
      return;
    }
    await updateFinding.mutateAsync({ findingId, data: { status: newStatus } as any });
    qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
  };

  const submitFalsePositive = async () => {
    if (!fpTarget) return;
    setFpSaving(true);
    try {
      await updateFinding.mutateAsync({ findingId: fpTarget.id, data: { status: "false_positive", fpNote: fpReason.trim() || undefined } as any });
      qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
      setFpTarget(null);
    } finally {
      setFpSaving(false);
    }
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

  // Client-side delta + group filters (applied after server fetch)
  const list = useMemo(() => {
    let l = allList;
    if (groupMemberIdSet) l = l.filter((f: any) => groupMemberIdSet.has(f.assetId));
    if (newOnly)          l = l.filter((f: any) => f.isNewSinceLastScan);
    if (staleOnly)        l = l.filter((f: any) => (f.consecutiveMissedScans ?? 0) > 0);
    if (sortBy === "threat_score") {
      l = [...l].sort((a: any, b: any) => (b.tiScore ?? -1) - (a.tiScore ?? -1));
    } else if (sortBy === "severity") {
      const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      l = [...l].sort((a: any, b: any) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
    } else if (sortBy === "risk_score") {
      l = [...l].sort((a: any, b: any) => (b.riskScore ?? 0) - (a.riskScore ?? 0));
    }
    return l;
  }, [allList, groupMemberIdSet, newOnly, staleOnly, sortBy]);

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
        {/* Group filter */}
        {groupList.length > 0 && (
          <Select
            value={groupFilter !== null ? String(groupFilter) : "_all_"}
            onValueChange={v => { setGroupFilter(v === "_all_" ? null : Number(v)); resetPage(); }}
          >
            <SelectTrigger className="w-44 h-8 text-sm gap-1.5">
              <Layers className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <SelectValue placeholder="All Groups" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="_all_">All Groups</SelectItem>
              {groupList.map((g: any) => (
                <SelectItem key={g.id} value={String(g.id)}>
                  {g.name}
                  <span className="ml-1.5 text-muted-foreground text-xs">({g.assetCount})</span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Select value={sortBy || "_none_"} onValueChange={v => { setSortBy(v === "_none_" ? "" : v); resetPage(); }}>
          <SelectTrigger className="w-44 h-8 text-sm"><SelectValue placeholder="Sort by…" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_none_">Default order</SelectItem>
            <SelectItem value="severity">Severity (high first)</SelectItem>
            <SelectItem value="risk_score">Risk Score (high first)</SelectItem>
            {tiEnabled && <SelectItem value="threat_score">Threat Score (high first)</SelectItem>}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => { setSeverity(""); setStatus(""); setSearch(""); setTenantFilter(null); setGroupFilter(null); setNewOnly(false); setStaleOnly(false); setSortBy(""); resetPage(); }}>
          Clear
        </Button>
        {isPrivileged && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); setGroupFilter(null); resetPage(); }} />}
      </div>

      {/* Active filter hint */}
      {(newOnly || staleOnly || groupFilter !== null) && (
        <div className="flex items-center gap-2 text-xs flex-wrap">
          <span className="text-muted-foreground">Showing:</span>
          {groupFilter !== null && (
            <span className="inline-flex items-center gap-1 text-primary font-medium">
              <Layers className="w-3 h-3" />
              {groupList.find((g: any) => g.id === groupFilter)?.name ?? "Group"}
            </span>
          )}
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
                {tiEnabled && (
                  <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground whitespace-nowrap">
                    <span className="flex items-center gap-1">
                      <Target className="w-3 h-3 text-violet-400" />
                      Threat Score
                    </span>
                  </th>
                )}
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Status</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">CVE</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(8)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(tiEnabled ? 13 : 12)].map((_, j) => (
                    <td key={j} className="px-3 py-3"><Skeleton className="h-4" /></td>
                  ))}
                </tr>
              ))}

              {!isLoading && paginated.map((f: any) => {
                const TypeIcon = ASSET_TYPE_ICON[f.assetType ?? ""] ?? Globe;
                const StatusIcon = STATUS_ICON[f.status] ?? Minus;
                const impScore = importanceScore(f);

                return (
                  <tr key={f.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors group cursor-pointer" onClick={() => navigate(`/findings/${f.id}`)}>
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

                    {/* Threat Score (TI module) */}
                    {tiEnabled && (
                      <td className="px-3 py-2.5">
                        <ThreatScoreBadge
                          score={f.tiScore ?? null}
                          exploitationStatus={f.tiExploitationStatus ?? null}
                          onClick={() => openDrawer(f, "threat-intel")}
                        />
                      </td>
                    )}

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
                        {/* Details — opens sidebar drawer; Full Page link is inside the drawer */}
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "metadata"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors font-medium"
                          title="View details in sidebar"
                        >
                          <FileText className="w-3 h-3" />
                          <span>Details</span>
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
                  <td colSpan={tiEnabled ? 14 : 13} className="px-4 py-10 text-center text-sm text-muted-foreground">
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

      {/* False-Positive Reason Modal */}
      {fpTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setFpTarget(null)}>
          <div className="bg-card border border-border rounded-xl shadow-2xl w-full max-w-md mx-4 p-6" onClick={e => e.stopPropagation()}>
            <div className="flex items-start gap-3 mb-4">
              <div className="p-2 rounded-lg bg-muted/50 flex-shrink-0">
                <Minus className="w-4 h-4 text-muted-foreground" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-foreground">Mark as False Positive</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  Explain why you believe this is not a real vulnerability. This reason is stored and visible to reviewers.
                </p>
              </div>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-xs font-medium text-foreground block mb-1.5">
                  Reason <span className="text-muted-foreground font-normal">(optional but recommended)</span>
                </label>
                <textarea
                  value={fpReason}
                  onChange={e => setFpReason(e.target.value)}
                  placeholder="e.g. This endpoint is behind authentication and not publicly accessible. The scanner detected it as open but it requires a valid session token..."
                  rows={4}
                  maxLength={2000}
                  className="w-full rounded-lg border border-border bg-muted/30 px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground/50 outline-none focus:border-primary/50 resize-none"
                  autoFocus
                />
                <p className="text-[10px] text-muted-foreground/60 mt-1 text-right">{fpReason.length}/2000</p>
              </div>

              <div className="flex gap-2 pt-1">
                <button
                  onClick={() => setFpTarget(null)}
                  className="flex-1 px-3 py-2 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-accent transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={submitFalsePositive}
                  disabled={fpSaving}
                  className="flex-1 px-3 py-2 rounded-lg bg-primary text-primary-foreground text-xs font-semibold hover:bg-primary/90 transition-colors disabled:opacity-50"
                >
                  {fpSaving ? "Saving…" : "Confirm False Positive"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
