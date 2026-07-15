import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  ListChecks, CheckCircle2, XCircle, Clock, Search,
  ExternalLink, Loader2, ShieldCheck, ShieldX, AlertTriangle,
  RefreshCw, Info, SlidersHorizontal, Hourglass, RotateCcw,
  MessageSquare, User, Calendar, Building2, Shield, Quote,
  ChevronDown, ChevronUp, Pencil, Plus,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

type FpAction = "confirm" | "reject" | "in_progress" | "reopen" | "reconfirm";

interface FpFinding {
  id: number;
  title: string;
  severity: string;
  status: string;
  assetId: number;
  assetName: string | null;
  assetValue: string | null;
  tenantId: number;
  tenantName: string | null;
  cve: string | null;
  cvss: number | null;
  isFalsePositive: boolean;
  falsePositiveStatus: string;
  fpNote: string | null;
  fpSubmittedBy: number | null;
  fpSubmittedByName: string | null;
  fpSubmittedAt: string | null;
  fpReviewedBy: number | null;
  fpReviewedByName: string | null;
  fpReviewedAt: string | null;
  updatedAt: string;
}

interface FpListResponse {
  findings: FpFinding[];
  total: number;
}

// ── Severity ─────────────────────────────────────────────────────────────────

const SEV_CONFIG: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: "bg-red-500/10",    text: "text-red-400",    border: "border-red-500/30",    dot: "bg-red-500" },
  high:     { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30", dot: "bg-orange-500" },
  medium:   { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/30", dot: "bg-yellow-400" },
  low:      { bg: "bg-blue-500/10",   text: "text-blue-400",   border: "border-blue-500/30",   dot: "bg-blue-400" },
  info:     { bg: "bg-slate-500/10",  text: "text-slate-400",  border: "border-slate-500/30",  dot: "bg-slate-400" },
};

function SevBadge({ severity }: { severity: string }) {
  const c = SEV_CONFIG[severity] ?? SEV_CONFIG.info;
  return (
    <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border", c.bg, c.text, c.border)}>
      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", c.dot)} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

// ── FP Status ─────────────────────────────────────────────────────────────────

const FP_STATUS = {
  submitted:   { label: "Pending Review", icon: Clock,        pill: "bg-amber-500/15 text-amber-300 border-amber-500/30",        leftBorder: "border-l-amber-500" },
  in_progress: { label: "In Progress",    icon: Hourglass,    pill: "bg-blue-500/15 text-blue-300 border-blue-500/30",          leftBorder: "border-l-blue-500" },
  confirmed:   { label: "Confirmed FP",   icon: CheckCircle2, pill: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30", leftBorder: "border-l-emerald-500" },
  rejected:    { label: "Rejected",       icon: XCircle,      pill: "bg-red-500/15 text-red-300 border-red-500/30",             leftBorder: "border-l-red-500" },
} as const;

function FpPill({ status }: { status: string }) {
  const cfg = FP_STATUS[status as keyof typeof FP_STATUS];
  if (!cfg) return <span className="text-xs text-muted-foreground/40">—</span>;
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border whitespace-nowrap", cfg.pill)}>
      <Icon className="w-3 h-3 flex-shrink-0" /> {cfg.label}
    </span>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtDateTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ── Action config ─────────────────────────────────────────────────────────────

const ACTION_CONFIG: Record<FpAction, {
  title: string; description: string; notePlaceholder: string;
  btnLabel: string; btnClass: string; warning?: string;
}> = {
  confirm: {
    title: "Confirm False Positive",
    description: "Confirming marks this finding as a verified false positive and removes it from the active vulnerability count.",
    notePlaceholder: "e.g. Verified — expected behaviour in our environment. Scanner triggers on our CDN headers.",
    btnLabel: "Confirm FP",
    btnClass: "bg-emerald-600 hover:bg-emerald-700 text-white",
    warning: "The finding will be set to confirmed false positive and removed from active tracking.",
  },
  reconfirm: {
    title: "Re-confirm False Positive",
    description: "Re-confirming restores this finding to confirmed false positive after it was previously rejected.",
    notePlaceholder: "e.g. Further investigation confirms this is still a false positive.",
    btnLabel: "Re-confirm FP",
    btnClass: "bg-emerald-600 hover:bg-emerald-700 text-white",
    warning: "The finding will be restored to confirmed false positive status.",
  },
  reject: {
    title: "Reject False Positive",
    description: "Rejecting reverts this finding to open status for active re-investigation.",
    notePlaceholder: "e.g. Real vulnerability — verified via manual testing. Needs immediate remediation.",
    btnLabel: "Reject",
    btnClass: "bg-red-600 hover:bg-red-700 text-white",
  },
  in_progress: {
    title: "Mark as In Progress",
    description: "Mark this FP submission as under active review.",
    notePlaceholder: "e.g. Currently investigating with the client team.",
    btnLabel: "Mark In Progress",
    btnClass: "bg-blue-600 hover:bg-blue-700 text-white",
  },
  reopen: {
    title: "Re-open for Review",
    description: "Send this finding back to pending review.",
    notePlaceholder: "e.g. Needs a second opinion before finalising the decision.",
    btnLabel: "Re-open",
    btnClass: "bg-amber-600 hover:bg-amber-700 text-white",
  },
};

// ── Action Buttons ────────────────────────────────────────────────────────────

const ACTION_BTN: Record<string, string> = {
  confirm:  "text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10 hover:border-emerald-500/50",
  reject:   "text-red-400 border-red-500/30 hover:bg-red-500/10 hover:border-red-500/50",
  progress: "text-blue-400 border-blue-500/30 hover:bg-blue-500/10 hover:border-blue-500/50",
  reopen:   "text-amber-400 border-amber-500/30 hover:bg-amber-500/10 hover:border-amber-500/50",
};

function ABtn({ variant, children, onClick }: { variant: string; children: React.ReactNode; onClick: () => void }) {
  return (
    <button onClick={onClick} className={cn("flex items-center gap-1 px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold transition-all whitespace-nowrap", ACTION_BTN[variant] ?? "")}>
      {children}
    </button>
  );
}

// ── Row component ─────────────────────────────────────────────────────────────

function FpRow({
  f, canReview, showTenant, expanded, onExpand, onAction, onEditNote,
}: {
  f: FpFinding; canReview: boolean; showTenant: boolean;
  expanded: boolean; onExpand: () => void;
  onAction: (f: FpFinding, a: FpAction) => void;
  onEditNote: (f: FpFinding) => void;
}) {
  const statusCfg = FP_STATUS[f.falsePositiveStatus as keyof typeof FP_STATUS];

  return (
    <div className={cn(
      "border border-border border-l-4 rounded-xl overflow-hidden transition-all",
      statusCfg?.leftBorder ?? "border-l-border",
      expanded ? "shadow-md shadow-black/10" : "hover:shadow-sm hover:shadow-black/5",
    )}>
      {/* ── Main row ─────────────────────────────────────────────────────── */}
      <div
        className="grid items-start gap-3 px-5 py-4 bg-card cursor-pointer select-none"
        style={{ gridTemplateColumns: showTenant
          ? "minmax(0,2fr) minmax(0,0.9fr) minmax(0,0.9fr) 150px 140px auto"
          : "minmax(0,2fr) minmax(0,1fr) 150px 140px auto" }}
        onClick={onExpand}
      >
        {/* 1 — Finding title + badges + fpNote preview */}
        <div className="min-w-0 space-y-1.5">
          <div className="flex items-start gap-2">
            <Link href={`/findings/${f.id}`} onClick={e => e.stopPropagation()}>
              <span className="text-sm font-medium text-foreground hover:text-primary transition-colors cursor-pointer leading-snug line-clamp-2">
                {f.title}
              </span>
            </Link>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <SevBadge severity={f.severity} />
            {f.cve && (
              <span className="text-[10px] font-mono text-amber-400/80 bg-amber-500/10 border border-amber-500/20 px-1.5 py-0.5 rounded">
                {f.cve}
              </span>
            )}
            {f.cvss != null && (
              <span className="text-[10px] text-muted-foreground bg-muted/40 border border-border/40 px-1.5 py-0.5 rounded">
                CVSS {f.cvss.toFixed(1)}
              </span>
            )}
          </div>

          {/* ── Analyst reason — ALWAYS visible inline ─────────────────── */}
          {f.fpNote ? (
            <div
              className="flex items-start gap-1.5 rounded-lg bg-primary/5 border border-primary/15 px-3 py-2 mt-1"
              onClick={e => e.stopPropagation()}
            >
              <Quote className="w-3 h-3 text-primary/50 flex-shrink-0 mt-0.5" />
              <div className="min-w-0">
                <p className="text-[10px] font-bold uppercase tracking-wider text-primary/50 mb-0.5">Analyst Reason</p>
                <p className="text-xs text-foreground/80 leading-relaxed italic line-clamp-2">
                  {f.fpNote}
                </p>
                {f.fpNote.length > 120 && !expanded && (
                  <p className="text-[10px] text-primary/50 mt-0.5">Expand to read full reason ↓</p>
                )}
              </div>
              <button
                onClick={() => onEditNote(f)}
                className="ml-auto flex-shrink-0 p-1 rounded hover:bg-primary/10 text-primary/40 hover:text-primary/70 transition-colors"
                title="Edit reason"
              >
                <Pencil className="w-3 h-3" />
              </button>
            </div>
          ) : (
            <button
              onClick={(e) => { e.stopPropagation(); onEditNote(f); }}
              className="flex items-center gap-1.5 text-[10px] text-muted-foreground/40 hover:text-muted-foreground/70 transition-colors mt-0.5 italic"
            >
              <Plus className="w-2.5 h-2.5" />
              Add analyst reason
            </button>
          )}
        </div>

        {/* 2 — Asset */}
        <div className="min-w-0 pt-0.5">
          <Link href={`/assets/${f.assetId}`} onClick={e => e.stopPropagation()}>
            <p className="text-xs font-medium text-foreground/80 hover:text-primary transition-colors cursor-pointer truncate">
              {f.assetName ?? f.assetValue ?? `Asset #${f.assetId}`}
            </p>
          </Link>
          {f.assetValue && f.assetName && (
            <p className="text-[10px] text-muted-foreground/60 truncate mt-0.5">{f.assetValue}</p>
          )}
        </div>

        {/* 3 — Tenant (admin/SA) */}
        {showTenant && (
          <div className="min-w-0 pt-0.5">
            <p className="text-xs text-muted-foreground truncate">{f.tenantName ?? `#${f.tenantId}`}</p>
          </div>
        )}

        {/* 4 — FP Status */}
        <div className="pt-0.5">
          <FpPill status={f.falsePositiveStatus} />
        </div>

        {/* 5 — Submitted */}
        <div className="pt-0.5">
          <p className="text-xs text-foreground/70 truncate">{f.fpSubmittedByName ?? "—"}</p>
          <p className="text-[10px] text-muted-foreground/60 mt-0.5">{fmtDate(f.fpSubmittedAt)}</p>
        </div>

        {/* 6 — Actions + expand toggle */}
        <div className="flex items-start justify-end gap-1.5 pt-0.5">
          {canReview && (
            <div className="flex flex-wrap items-center gap-1 justify-end" onClick={e => e.stopPropagation()}>
              {f.falsePositiveStatus === "submitted" && (<>
                <ABtn variant="confirm"   onClick={() => onAction(f, "confirm")}><ShieldCheck className="w-3 h-3" /> Confirm</ABtn>
                <ABtn variant="progress"  onClick={() => onAction(f, "in_progress")}><Hourglass className="w-3 h-3" /> In Progress</ABtn>
                <ABtn variant="reject"    onClick={() => onAction(f, "reject")}><ShieldX className="w-3 h-3" /> Reject</ABtn>
              </>)}
              {f.falsePositiveStatus === "in_progress" && (<>
                <ABtn variant="confirm"  onClick={() => onAction(f, "confirm")}><ShieldCheck className="w-3 h-3" /> Confirm</ABtn>
                <ABtn variant="reject"   onClick={() => onAction(f, "reject")}><ShieldX className="w-3 h-3" /> Reject</ABtn>
                <ABtn variant="reopen"   onClick={() => onAction(f, "reopen")}><RotateCcw className="w-3 h-3" /> Re-open</ABtn>
              </>)}
              {f.falsePositiveStatus === "confirmed" && (<>
                <ABtn variant="reopen" onClick={() => onAction(f, "reopen")}><RotateCcw className="w-3 h-3" /> Re-open</ABtn>
                <ABtn variant="reject" onClick={() => onAction(f, "reject")}><XCircle className="w-3 h-3" /> Reject</ABtn>
              </>)}
              {f.falsePositiveStatus === "rejected" && (<>
                <ABtn variant="confirm" onClick={() => onAction(f, "reconfirm")}><CheckCircle2 className="w-3 h-3" /> Re-confirm</ABtn>
                <ABtn variant="reopen"  onClick={() => onAction(f, "reopen")}><RotateCcw className="w-3 h-3" /> Re-open</ABtn>
              </>)}
            </div>
          )}
          <Link href={`/findings/${f.id}`} onClick={e => e.stopPropagation()}>
            <button className="p-1.5 rounded-lg hover:bg-accent text-muted-foreground/40 hover:text-foreground transition-colors" title="Open full finding">
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </Link>
          <button className="p-1.5 rounded-lg hover:bg-accent text-muted-foreground/30 hover:text-foreground transition-colors">
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* ── Expanded detail ───────────────────────────────────────────────── */}
      {expanded && (
        <div className="border-t border-border/40 bg-muted/10 px-5 py-4 grid grid-cols-2 gap-6">
          {/* Full analyst reason */}
          <div>
            <div className="flex items-center gap-2 mb-2">
              <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground/50 flex items-center gap-1.5">
                <Quote className="w-3 h-3" /> Analyst Reason
              </p>
              <button
                onClick={() => onEditNote(f)}
                className="flex items-center gap-1 text-[10px] text-primary/60 hover:text-primary transition-colors ml-auto"
              >
                <Pencil className="w-3 h-3" />
                {f.fpNote ? "Edit reason" : "Add reason"}
              </button>
            </div>
            {f.fpNote ? (
              <p className="text-sm text-foreground/80 leading-relaxed bg-card rounded-lg border border-border/50 px-4 py-3 italic">
                "{f.fpNote}"
              </p>
            ) : (
              <button
                onClick={() => onEditNote(f)}
                className="w-full text-left text-sm text-muted-foreground/40 italic bg-card rounded-lg border border-dashed border-border/50 px-4 py-3 hover:border-primary/30 hover:text-muted-foreground/60 transition-colors"
              >
                No reason provided — click to add one
              </button>
            )}
          </div>

          {/* Submission / Review metadata */}
          <div>
            <p className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground/50 mb-2 flex items-center gap-1.5">
              <User className="w-3 h-3" /> Submission Details
            </p>
            <div className="space-y-1.5 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span className="w-24 text-muted-foreground/50 flex-shrink-0">Submitted by</span>
                <span className="text-foreground/80 font-medium">{f.fpSubmittedByName ?? "—"}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-24 text-muted-foreground/50 flex-shrink-0">Submitted at</span>
                <span className="text-foreground/80">{fmtDateTime(f.fpSubmittedAt)}</span>
              </div>
              {f.fpReviewedByName && (<>
                <div className="flex items-center gap-2">
                  <span className="w-24 text-muted-foreground/50 flex-shrink-0">Reviewed by</span>
                  <span className="text-foreground/80 font-medium">{f.fpReviewedByName}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-24 text-muted-foreground/50 flex-shrink-0">Reviewed at</span>
                  <span className="text-foreground/80">{fmtDateTime(f.fpReviewedAt)}</span>
                </div>
              </>)}
              {showTenant && f.tenantName && (
                <div className="flex items-center gap-2">
                  <span className="w-24 text-muted-foreground/50 flex-shrink-0">Client</span>
                  <span className="text-foreground/80">{f.tenantName}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Stat tile ─────────────────────────────────────────────────────────────────

function StatTile({
  label, sublabel, count, icon: Icon, color, active, onClick,
}: {
  label: string; sublabel: string; count: number; icon: React.ElementType;
  color: { icon: string; iconBg: string; activeRing: string; activeBg: string; activeNum: string };
  active: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "relative text-left rounded-xl border p-5 transition-all overflow-hidden",
        active
          ? cn("border", color.activeRing, color.activeBg, "shadow-sm")
          : "border-border bg-card hover:border-border/80 hover:shadow-sm",
      )}
    >
      <div className="flex items-start justify-between mb-3">
        <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center", color.iconBg)}>
          <Icon className={cn("w-5 h-5", color.icon)} />
        </div>
        {active && (
          <span className={cn("text-[9px] font-black uppercase tracking-widest py-0.5 px-1.5 rounded-md border", color.icon, color.activeRing, color.activeBg)}>
            Active
          </span>
        )}
      </div>
      <div className={cn("text-3xl font-bold tabular-nums leading-none mb-1.5", active ? color.activeNum : "text-foreground")}>
        {count}
      </div>
      <div className="text-xs font-semibold text-foreground/70">{label}</div>
      <div className="text-[10px] text-muted-foreground/50 mt-0.5">{sublabel}</div>
    </button>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function FalsePositivesPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const role = user?.role ?? "client";
  const canReview = role === "super_admin" || role === "admin" || role === "account_manager";
  const showTenant = role === "super_admin" || role === "admin";

  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  // Review action dialog
  const [reviewing, setReviewing]   = useState<{ finding: FpFinding; action: FpAction } | null>(null);
  const [reviewNote, setReviewNote] = useState("");

  // Edit/add analyst reason dialog
  const [editNoteTarget, setEditNoteTarget] = useState<FpFinding | null>(null);
  const [editNoteText, setEditNoteText]     = useState("");
  const [editNoteSaving, setEditNoteSaving] = useState(false);

  const qParams = new URLSearchParams({ limit: "200" });
  if (statusFilter !== "all") qParams.set("status", statusFilter);
  if (severityFilter !== "all") qParams.set("severity", severityFilter);
  if (search.trim()) qParams.set("search", search.trim());

  const { data, isLoading, refetch, isFetching } = useQuery<FpListResponse>({
    queryKey: ["false-positives", statusFilter, severityFilter, search],
    queryFn: () => apiFetch<FpListResponse>(`/api/findings/false-positives?${qParams}`),
    staleTime: 20_000,
  });

  const findings   = data?.findings ?? [];
  const submitted  = findings.filter(f => f.falsePositiveStatus === "submitted").length;
  const inProgress = findings.filter(f => f.falsePositiveStatus === "in_progress").length;
  const confirmed  = findings.filter(f => f.falsePositiveStatus === "confirmed").length;
  const rejected   = findings.filter(f => f.falsePositiveStatus === "rejected").length;

  // ── Review mutation (confirm/reject/in_progress/reopen) ──────────────────
  const reviewMut = useMutation({
    mutationFn: ({ id, action, note }: { id: number; action: FpAction; note: string }) =>
      apiFetch<{ ok: boolean }>(`/api/findings/${id}/fp-status`, {
        method: "PATCH",
        body: JSON.stringify({ action, note: note.trim() || undefined }),
      }),
    onSuccess: (_, vars) => {
      const messages: Record<FpAction, { title: string; description: string }> = {
        confirm:     { title: "Confirmed as false positive",    description: "Finding confirmed and closed."                   },
        reconfirm:   { title: "Re-confirmed as false positive", description: "Finding restored to confirmed FP."               },
        reject:      { title: "False positive rejected",        description: "Finding reverted to open for re-investigation."  },
        in_progress: { title: "Marked as in progress",         description: "Finding is now under active review."             },
        reopen:      { title: "Re-opened for review",          description: "Finding sent back to pending review."            },
      };
      const msg = messages[vars.action];
      toast({ title: msg.title, description: msg.description });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      setReviewing(null);
      setReviewNote("");
    },
    onError: () => toast({ title: "Review failed", description: "Could not update the finding.", variant: "destructive" }),
  });

  // ── Update fpNote mutation ────────────────────────────────────────────────
  const updateNoteMut = useMutation({
    mutationFn: ({ id, fpNote }: { id: number; fpNote: string }) =>
      apiFetch(`/api/findings/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ fpNote }),
      }),
    onSuccess: () => {
      toast({ title: "Reason saved", description: "The analyst reason has been updated." });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      setEditNoteTarget(null);
      setEditNoteText("");
      setEditNoteSaving(false);
    },
    onError: () => {
      toast({ title: "Save failed", description: "Could not save the reason.", variant: "destructive" });
      setEditNoteSaving(false);
    },
  });

  const openReview = useCallback((finding: FpFinding, action: FpAction) => {
    setReviewNote("");
    setReviewing({ finding, action });
  }, []);

  const openEditNote = useCallback((finding: FpFinding) => {
    setEditNoteText(finding.fpNote ?? "");
    setEditNoteTarget(finding);
  }, []);

  const saveNote = () => {
    if (!editNoteTarget) return;
    setEditNoteSaving(true);
    updateNoteMut.mutate({ id: editNoteTarget.id, fpNote: editNoteText });
  };

  const clearFilters = () => { setStatusFilter("all"); setSeverityFilter("all"); setSearch(""); };
  const hasFilters = statusFilter !== "all" || severityFilter !== "all" || search !== "";
  const actionCfg = reviewing ? ACTION_CONFIG[reviewing.action] : null;

  return (
    <div className="flex flex-col gap-5 min-h-full">

      {/* ── Page header — NOT sticky (Navbar above already handles the top bar) ── */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center flex-shrink-0">
            <ListChecks className="w-4.5 h-4.5 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight leading-tight">False Positives</h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              {canReview ? "Review & manage FP submissions from your analysts" : "Track your false positive submissions"}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {submitted > 0 && (
            <span className="flex items-center gap-1.5 text-xs font-medium text-amber-400 bg-amber-500/10 border border-amber-500/20 px-3 py-1.5 rounded-full">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              {submitted} pending review
            </span>
          )}
          {inProgress > 0 && (
            <span className="text-xs font-medium text-blue-400 bg-blue-500/10 border border-blue-500/20 px-3 py-1.5 rounded-full">
              {inProgress} in review
            </span>
          )}
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-1.5 h-9 text-xs">
            <RefreshCw className={cn("w-3.5 h-3.5", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* ── Stat tiles ────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-4">
        <StatTile label="Pending Review" sublabel="Awaiting reviewer action" count={submitted} icon={Clock}
          color={{ icon: "text-amber-400", iconBg: "bg-amber-500/10", activeRing: "border-amber-500/40", activeBg: "bg-amber-500/5", activeNum: "text-amber-400" }}
          active={statusFilter === "submitted"} onClick={() => setStatusFilter(s => s === "submitted" ? "all" : "submitted")} />
        <StatTile label="In Progress" sublabel="Under active review" count={inProgress} icon={Hourglass}
          color={{ icon: "text-blue-400", iconBg: "bg-blue-500/10", activeRing: "border-blue-500/40", activeBg: "bg-blue-500/5", activeNum: "text-blue-400" }}
          active={statusFilter === "in_progress"} onClick={() => setStatusFilter(s => s === "in_progress" ? "all" : "in_progress")} />
        <StatTile label="Confirmed FP" sublabel="Verified false positives" count={confirmed} icon={CheckCircle2}
          color={{ icon: "text-emerald-400", iconBg: "bg-emerald-500/10", activeRing: "border-emerald-500/40", activeBg: "bg-emerald-500/5", activeNum: "text-emerald-400" }}
          active={statusFilter === "confirmed"} onClick={() => setStatusFilter(s => s === "confirmed" ? "all" : "confirmed")} />
        <StatTile label="Rejected" sublabel="Reverted to open / not FP" count={rejected} icon={XCircle}
          color={{ icon: "text-red-400", iconBg: "bg-red-500/10", activeRing: "border-red-500/40", activeBg: "bg-red-500/5", activeNum: "text-red-400" }}
          active={statusFilter === "rejected"} onClick={() => setStatusFilter(s => s === "rejected" ? "all" : "rejected")} />
      </div>

      {/* ── Client info banner ───────────────────────────────────────────── */}
      {role === "client" && (
        <div className="flex items-start gap-3 rounded-xl border border-blue-500/20 bg-blue-500/5 px-5 py-3.5">
          <Info className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
          <p className="text-sm text-blue-300/90">
            Mark findings as false positives from the{" "}
            <Link href="/findings" className="underline underline-offset-2 hover:text-blue-200 font-medium">Findings page</Link>.
            An admin or account manager will review each submission.
          </p>
        </div>
      )}

      {/* ── Filter bar ───────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <Input className="pl-9 h-9 text-sm" placeholder="Search by title or CVE…" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-9 w-44 gap-1.5 text-sm flex-shrink-0">
            <SlidersHorizontal className="w-3.5 h-3.5 text-muted-foreground" />
            <SelectValue placeholder="FP Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="submitted">Pending Review</SelectItem>
            <SelectItem value="in_progress">In Progress</SelectItem>
            <SelectItem value="confirmed">Confirmed FP</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="h-9 w-36 text-sm flex-shrink-0">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        {hasFilters && (
          <Button variant="ghost" size="sm" className="h-9 text-xs text-muted-foreground hover:text-foreground flex-shrink-0" onClick={clearFilters}>
            Clear
          </Button>
        )}
        <span className="text-xs text-muted-foreground/50 tabular-nums ml-auto flex-shrink-0">
          {findings.length} result{findings.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* ── Column headers ───────────────────────────────────────────────── */}
      {!isLoading && findings.length > 0 && (
        <div
          className="grid items-center gap-3 px-5 py-1.5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground/40"
          style={{ gridTemplateColumns: showTenant
            ? "minmax(0,2fr) minmax(0,0.9fr) minmax(0,0.9fr) 150px 140px auto"
            : "minmax(0,2fr) minmax(0,1fr) 150px 140px auto" }}
        >
          <span>Finding / Analyst Reason</span>
          <span>Asset</span>
          {showTenant && <span>Client</span>}
          <span>FP Status</span>
          <span>Submitted By</span>
          <span className="text-right">Actions</span>
        </div>
      )}

      {/* ── Content ──────────────────────────────────────────────────────── */}
      {isLoading ? (
        <div className="flex flex-col items-center justify-center gap-3 text-muted-foreground py-24">
          <Loader2 className="w-7 h-7 animate-spin opacity-40" />
          <span className="text-sm">Loading false positive submissions…</span>
        </div>
      ) : findings.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border/50 flex flex-col items-center justify-center py-24 text-center gap-4">
          <div className="w-16 h-16 rounded-2xl bg-muted/20 border border-border/30 flex items-center justify-center">
            <ShieldCheck className="w-8 h-8 text-muted-foreground/20" />
          </div>
          <div>
            <p className="text-base font-semibold text-foreground/60">No false positive submissions found</p>
            <p className="text-sm text-muted-foreground/50 mt-1.5">
              {hasFilters ? "Try clearing your filters to see all results" : "Mark findings as false positives from the Findings page"}
            </p>
          </div>
          {hasFilters && (
            <Button variant="outline" size="sm" onClick={clearFilters} className="gap-1.5">
              <RefreshCw className="w-3.5 h-3.5" /> Clear filters
            </Button>
          )}
        </div>
      ) : (
        <div className="flex flex-col gap-2 pb-6">
          {findings.map(f => (
            <FpRow
              key={f.id}
              f={f}
              canReview={canReview}
              showTenant={showTenant}
              expanded={expandedId === f.id}
              onExpand={() => setExpandedId(expandedId === f.id ? null : f.id)}
              onAction={openReview}
              onEditNote={openEditNote}
            />
          ))}
        </div>
      )}

      {/* ── Edit / Add Analyst Reason dialog ─────────────────────────────── */}
      <Dialog open={!!editNoteTarget} onOpenChange={o => { if (!o) { setEditNoteTarget(null); setEditNoteText(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Quote className="w-5 h-5 text-primary/60" />
              {editNoteTarget?.fpNote ? "Edit Analyst Reason" : "Add Analyst Reason"}
            </DialogTitle>
            <DialogDescription className="text-sm leading-relaxed">
              Explain why this finding is a false positive. This reason is visible to all reviewers on the False Positives page.
            </DialogDescription>
          </DialogHeader>

          {editNoteTarget && (
            <div className="space-y-4 py-1">
              {/* Finding context */}
              <div className="rounded-xl border border-border bg-muted/20 p-3.5">
                <p className="text-sm font-semibold leading-snug line-clamp-2">{editNoteTarget.title}</p>
                <div className="flex flex-wrap items-center gap-1.5 mt-2">
                  <SevBadge severity={editNoteTarget.severity} />
                  <FpPill status={editNoteTarget.falsePositiveStatus} />
                </div>
              </div>

              {/* Reason textarea */}
              <div className="space-y-1.5">
                <Label className="text-sm flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-muted-foreground" />
                  Reason <span className="text-muted-foreground font-normal">(shown inline on this page)</span>
                </Label>
                <Textarea
                  className="resize-none text-sm min-h-[100px]"
                  rows={4}
                  placeholder="e.g. This endpoint is behind authentication. The scanner detected it as open but it requires a valid session token to access any data…"
                  value={editNoteText}
                  onChange={e => setEditNoteText(e.target.value)}
                  maxLength={2000}
                  autoFocus
                />
                <p className="text-[10px] text-muted-foreground/40 text-right">{editNoteText.length}/2000</p>
              </div>
            </div>
          )}

          <DialogFooter className="gap-2 pt-2">
            <Button variant="outline" size="sm" onClick={() => { setEditNoteTarget(null); setEditNoteText(""); }}>
              Cancel
            </Button>
            {editNoteTarget?.fpNote && (
              <Button variant="ghost" size="sm" className="text-destructive hover:text-destructive" onClick={() => {
                setEditNoteSaving(true);
                updateNoteMut.mutate({ id: editNoteTarget.id, fpNote: "" });
              }}>
                Clear reason
              </Button>
            )}
            <Button
              size="sm"
              disabled={editNoteSaving || updateNoteMut.isPending}
              onClick={saveNote}
              className="gap-1.5 bg-primary hover:bg-primary/90"
            >
              {(editNoteSaving || updateNoteMut.isPending) ? <Loader2 className="w-4 h-4 animate-spin" /> : "Save reason"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Review action dialog ──────────────────────────────────────────── */}
      <Dialog open={!!reviewing} onOpenChange={o => { if (!o) { setReviewing(null); setReviewNote(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              {reviewing?.action === "confirm"     && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reconfirm"   && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reject"      && <><XCircle     className="w-5 h-5 text-red-400"      />{actionCfg?.title}</>}
              {reviewing?.action === "in_progress" && <><Hourglass   className="w-5 h-5 text-blue-400"    />{actionCfg?.title}</>}
              {reviewing?.action === "reopen"      && <><RotateCcw   className="w-5 h-5 text-amber-400"   />{actionCfg?.title}</>}
            </DialogTitle>
            <DialogDescription className="text-sm leading-relaxed">{actionCfg?.description}</DialogDescription>
          </DialogHeader>

          {reviewing && (
            <div className="space-y-4 py-1">
              {/* Finding summary */}
              <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-3">
                <p className="text-sm font-semibold leading-snug">{reviewing.finding.title}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <SevBadge severity={reviewing.finding.severity} />
                  <FpPill status={reviewing.finding.falsePositiveStatus} />
                  {reviewing.finding.cve && (
                    <span className="text-[10px] font-mono text-amber-400/80 bg-amber-500/10 border border-amber-500/20 px-1.5 py-0.5 rounded">
                      {reviewing.finding.cve}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-1.5 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1.5">
                    <Shield className="w-3 h-3 flex-shrink-0" />
                    <span className="truncate">{reviewing.finding.assetName ?? reviewing.finding.assetValue ?? `Asset #${reviewing.finding.assetId}`}</span>
                  </div>
                  {reviewing.finding.tenantName && (
                    <div className="flex items-center gap-1.5">
                      <Building2 className="w-3 h-3 flex-shrink-0" />
                      <span className="truncate">{reviewing.finding.tenantName}</span>
                    </div>
                  )}
                  {reviewing.finding.fpSubmittedByName && (
                    <div className="flex items-center gap-1.5">
                      <User className="w-3 h-3 flex-shrink-0" />
                      <span>Submitted by <strong className="text-foreground/70">{reviewing.finding.fpSubmittedByName}</strong></span>
                    </div>
                  )}
                  <div className="flex items-center gap-1.5">
                    <Calendar className="w-3 h-3 flex-shrink-0" />
                    <span>{fmtDateTime(reviewing.finding.fpSubmittedAt)}</span>
                  </div>
                </div>
                {/* Show analyst reason inside the review dialog */}
                {reviewing.finding.fpNote && (
                  <div className="rounded-lg border border-primary/15 bg-primary/5 px-3 py-2.5 flex items-start gap-2">
                    <Quote className="w-3.5 h-3.5 text-primary/60 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-primary/50 mb-0.5">Analyst Reason</p>
                      <p className="text-xs text-foreground/80 leading-relaxed">{reviewing.finding.fpNote}</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Reviewer note */}
              <div className="space-y-1.5">
                <Label className="text-sm flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-muted-foreground" />
                  Reviewer Note <span className="text-muted-foreground font-normal">(optional)</span>
                </Label>
                <Textarea
                  className="resize-none text-sm min-h-[80px]"
                  rows={3}
                  placeholder={actionCfg?.notePlaceholder ?? ""}
                  value={reviewNote}
                  onChange={e => setReviewNote(e.target.value)}
                  maxLength={2000}
                  autoFocus
                />
                <p className="text-[10px] text-muted-foreground/40 text-right">{reviewNote.length}/2000</p>
              </div>

              {actionCfg?.warning && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-300 leading-relaxed">
                  <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>{actionCfg.warning}</span>
                </div>
              )}
            </div>
          )}

          <DialogFooter className="gap-2 pt-2">
            <Button variant="outline" size="sm" onClick={() => { setReviewing(null); setReviewNote(""); }}>
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={reviewMut.isPending}
              className={cn("gap-1.5", actionCfg?.btnClass)}
              onClick={() => {
                if (!reviewing) return;
                reviewMut.mutate({ id: reviewing.finding.id, action: reviewing.action, note: reviewNote });
              }}
            >
              {reviewMut.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : actionCfg?.btnLabel}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
