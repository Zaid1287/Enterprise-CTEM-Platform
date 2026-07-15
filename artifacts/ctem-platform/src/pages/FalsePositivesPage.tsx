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
  MessageSquare, User, Calendar, Building2, Shield, ChevronRight,
  Quote,
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

// ── Severity ────────────────────────────────────────────────────────────────

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
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-semibold border", c.bg, c.text, c.border)}>
      <span className={cn("w-1.5 h-1.5 rounded-full flex-shrink-0", c.dot)} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

// ── FP Status ───────────────────────────────────────────────────────────────

const FP_STATUS_CONFIG = {
  submitted: {
    label: "Pending Review",
    icon: Clock,
    pill: "bg-amber-500/10 text-amber-300 border-amber-500/25",
    cardBorder: "border-l-amber-500/60",
    cardBg: "bg-amber-500/[0.02]",
    dot: "bg-amber-400",
  },
  in_progress: {
    label: "In Progress",
    icon: Hourglass,
    pill: "bg-blue-500/10 text-blue-300 border-blue-500/25",
    cardBorder: "border-l-blue-500/60",
    cardBg: "bg-blue-500/[0.02]",
    dot: "bg-blue-400",
  },
  confirmed: {
    label: "Confirmed FP",
    icon: CheckCircle2,
    pill: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25",
    cardBorder: "border-l-emerald-500/60",
    cardBg: "bg-emerald-500/[0.02]",
    dot: "bg-emerald-400",
  },
  rejected: {
    label: "Rejected",
    icon: XCircle,
    pill: "bg-red-500/10 text-red-300 border-red-500/25",
    cardBorder: "border-l-red-500/60",
    cardBg: "bg-red-500/[0.02]",
    dot: "bg-red-400",
  },
};

function FpStatusPill({ status }: { status: string }) {
  const cfg = FP_STATUS_CONFIG[status as keyof typeof FP_STATUS_CONFIG];
  if (!cfg) return <span className="text-xs text-muted-foreground/50">—</span>;
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border", cfg.pill)}>
      <Icon className="w-3 h-3" /> {cfg.label}
    </span>
  );
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}
function fmtDateTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

// ── Action config ────────────────────────────────────────────────────────────

const ACTION_CONFIG: Record<FpAction, {
  title: string;
  description: string;
  notePlaceholder: string;
  btnLabel: string;
  btnClass: string;
  warning?: string;
}> = {
  confirm: {
    title: "Confirm False Positive",
    description: "Confirming marks this finding as a verified false positive and closes it from active vulnerability tracking.",
    notePlaceholder: "e.g. Verified — expected behaviour in our environment. The scanner triggers on our CDN headers.",
    btnLabel: "Confirm FP",
    btnClass: "bg-emerald-600 hover:bg-emerald-700 text-white",
    warning: "The finding will be set to false_positive and removed from the active vulnerability count. Future identical findings from scans will be suppressed automatically.",
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
    description: "Mark this FP submission as under active review. The finding remains in false_positive status.",
    notePlaceholder: "e.g. Currently investigating this with the client team. Awaiting environment confirmation.",
    btnLabel: "Mark In Progress",
    btnClass: "bg-blue-600 hover:bg-blue-700 text-white",
  },
  reopen: {
    title: "Re-open for Review",
    description: "Send this finding back to pending review so a reviewer can confirm, reject, or mark as in progress.",
    notePlaceholder: "e.g. Needs a second opinion before finalising the decision.",
    btnLabel: "Re-open",
    btnClass: "bg-amber-600 hover:bg-amber-700 text-white",
  },
};

// ── FP Card ──────────────────────────────────────────────────────────────────

function FpCard({
  f,
  canReview,
  showTenant,
  onAction,
}: {
  f: FpFinding;
  canReview: boolean;
  showTenant: boolean;
  onAction: (finding: FpFinding, action: FpAction) => void;
}) {
  const statusCfg = FP_STATUS_CONFIG[f.falsePositiveStatus as keyof typeof FP_STATUS_CONFIG];

  return (
    <div className={cn(
      "rounded-xl border border-border border-l-4 bg-card overflow-hidden transition-shadow hover:shadow-md hover:shadow-black/10",
      statusCfg?.cardBorder ?? "border-l-border",
    )}>
      {/* ── Card header ─────────────────────────────────────────────────── */}
      <div className={cn("px-5 py-4 flex items-start justify-between gap-4", statusCfg?.cardBg)}>
        <div className="flex-1 min-w-0">
          {/* Title row */}
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <Link href={`/findings/${f.id}`}>
                <span className="text-sm font-semibold text-foreground hover:text-primary transition-colors cursor-pointer leading-snug block">
                  {f.title}
                </span>
              </Link>
              <div className="flex flex-wrap items-center gap-2 mt-2">
                <SevBadge severity={f.severity} />
                <FpStatusPill status={f.falsePositiveStatus} />
                {f.cve && (
                  <span className="text-[11px] font-mono text-amber-400/80 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded">
                    {f.cve}
                  </span>
                )}
                {f.cvss != null && (
                  <span className="text-[11px] text-muted-foreground bg-muted/40 px-2 py-0.5 rounded border border-border/50">
                    CVSS {f.cvss.toFixed(1)}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Quick link */}
        <Link href={`/findings/${f.id}`}>
          <button className="flex-shrink-0 p-1.5 rounded-lg hover:bg-accent text-muted-foreground hover:text-foreground transition-colors" title="View full finding">
            <ExternalLink className="w-4 h-4" />
          </button>
        </Link>
      </div>

      {/* ── Meta strip ──────────────────────────────────────────────────── */}
      <div className="px-5 py-3 border-t border-border/40 bg-muted/10 flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Shield className="w-3.5 h-3.5 flex-shrink-0" />
          <Link href={`/assets/${f.assetId}`}>
            <span className="hover:text-foreground transition-colors cursor-pointer">
              {f.assetName ?? f.assetValue ?? `Asset #${f.assetId}`}
            </span>
          </Link>
          {f.assetValue && f.assetName && (
            <span className="text-muted-foreground/50 truncate max-w-[160px]">· {f.assetValue}</span>
          )}
        </div>
        {showTenant && f.tenantName && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <Building2 className="w-3.5 h-3.5 flex-shrink-0" />
            <span>{f.tenantName}</span>
          </div>
        )}
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <User className="w-3.5 h-3.5 flex-shrink-0" />
          <span>Submitted by <strong className="text-foreground/70">{f.fpSubmittedByName ?? "Unknown"}</strong></span>
          <span className="text-muted-foreground/50">·</span>
          <Calendar className="w-3 h-3 flex-shrink-0" />
          <span>{fmtDate(f.fpSubmittedAt)}</span>
        </div>
        {f.fpReviewedByName && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
            <span>Reviewed by <strong className="text-foreground/70">{f.fpReviewedByName}</strong> · {fmtDate(f.fpReviewedAt)}</span>
          </div>
        )}
      </div>

      {/* ── Analyst reason (fpNote) ──────────────────────────────────────── */}
      {f.fpNote && (
        <div className="px-5 py-3.5 border-t border-border/40 bg-muted/5">
          <div className="flex items-start gap-3">
            <div className="flex-shrink-0 mt-0.5">
              <div className="w-7 h-7 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
                <Quote className="w-3.5 h-3.5 text-primary/70" />
              </div>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/60 mb-1">
                Analyst Reason
              </p>
              <p className="text-sm text-foreground/80 leading-relaxed">
                {f.fpNote}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ── Action row ──────────────────────────────────────────────────── */}
      {canReview && (
        <div className="px-5 py-3 border-t border-border/40 flex items-center justify-between gap-3">
          <span className="text-[11px] text-muted-foreground/50 italic">
            {f.falsePositiveStatus === "submitted" && "Awaiting review — take an action to progress this submission."}
            {f.falsePositiveStatus === "in_progress" && "Currently under review — confirm, reject, or re-open."}
            {f.falsePositiveStatus === "confirmed" && "Confirmed as false positive — re-open or reject to change."}
            {f.falsePositiveStatus === "rejected" && "Rejected — re-confirm if further investigation shows it is a false positive."}
          </span>

          <div className="flex items-center gap-1.5 flex-shrink-0">
            {f.falsePositiveStatus === "submitted" && (
              <>
                <ActionBtn variant="confirm" onClick={() => onAction(f, "confirm")}>
                  <ShieldCheck className="w-3.5 h-3.5" /> Confirm
                </ActionBtn>
                <ActionBtn variant="progress" onClick={() => onAction(f, "in_progress")}>
                  <Hourglass className="w-3.5 h-3.5" /> In Progress
                </ActionBtn>
                <ActionBtn variant="reject" onClick={() => onAction(f, "reject")}>
                  <ShieldX className="w-3.5 h-3.5" /> Reject
                </ActionBtn>
              </>
            )}
            {f.falsePositiveStatus === "in_progress" && (
              <>
                <ActionBtn variant="confirm" onClick={() => onAction(f, "confirm")}>
                  <ShieldCheck className="w-3.5 h-3.5" /> Confirm
                </ActionBtn>
                <ActionBtn variant="reject" onClick={() => onAction(f, "reject")}>
                  <ShieldX className="w-3.5 h-3.5" /> Reject
                </ActionBtn>
                <ActionBtn variant="reopen" onClick={() => onAction(f, "reopen")}>
                  <RotateCcw className="w-3.5 h-3.5" /> Re-open
                </ActionBtn>
              </>
            )}
            {f.falsePositiveStatus === "confirmed" && (
              <>
                <ActionBtn variant="reopen" onClick={() => onAction(f, "reopen")}>
                  <RotateCcw className="w-3.5 h-3.5" /> Re-open
                </ActionBtn>
                <ActionBtn variant="reject" onClick={() => onAction(f, "reject")}>
                  <XCircle className="w-3.5 h-3.5" /> Reject
                </ActionBtn>
              </>
            )}
            {f.falsePositiveStatus === "rejected" && (
              <>
                <ActionBtn variant="confirm" onClick={() => onAction(f, "reconfirm")}>
                  <CheckCircle2 className="w-3.5 h-3.5" /> Re-confirm
                </ActionBtn>
                <ActionBtn variant="reopen" onClick={() => onAction(f, "reopen")}>
                  <RotateCcw className="w-3.5 h-3.5" /> Re-open
                </ActionBtn>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function ActionBtn({ variant, onClick, children }: {
  variant: "confirm" | "reject" | "progress" | "reopen";
  onClick: () => void;
  children: React.ReactNode;
}) {
  const cls: Record<string, string> = {
    confirm:  "text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10 hover:border-emerald-500/50 hover:text-emerald-300",
    reject:   "text-red-400 border-red-500/30 hover:bg-red-500/10 hover:border-red-500/50 hover:text-red-300",
    progress: "text-blue-400 border-blue-500/30 hover:bg-blue-500/10 hover:border-blue-500/50 hover:text-blue-300",
    reopen:   "text-amber-400 border-amber-500/30 hover:bg-amber-500/10 hover:border-amber-500/50 hover:text-amber-300",
  };
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-[11px] font-semibold transition-all",
        cls[variant],
      )}
    >
      {children}
    </button>
  );
}

// ── Stat Card ────────────────────────────────────────────────────────────────

function StatCard({
  label, count, icon: Icon, active, color, onClick,
}: {
  label: string; count: number; icon: React.ElementType;
  active: boolean; color: { ring: string; bg: string; text: string; activeBg: string; activeBorder: string };
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "relative text-left rounded-xl border p-5 transition-all group overflow-hidden",
        active
          ? cn("shadow-sm", color.activeBorder, color.activeBg)
          : "border-border bg-card hover:shadow-sm",
      )}
    >
      {/* Background accent */}
      <div className={cn(
        "absolute top-0 right-0 w-20 h-20 rounded-full blur-2xl opacity-0 group-hover:opacity-100 transition-opacity",
        active ? "opacity-100" : "",
        color.bg,
      )} />
      <div className="relative">
        <div className="flex items-start justify-between mb-4">
          <div className={cn("w-10 h-10 rounded-xl flex items-center justify-center", color.bg, color.ring, "border")}>
            <Icon className={cn("w-5 h-5", color.text)} />
          </div>
          {active && (
            <span className={cn("text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded-full border", color.text, color.activeBorder, color.activeBg)}>
              Active filter
            </span>
          )}
        </div>
        <div className={cn("text-4xl font-bold tabular-nums mb-1", active ? color.text : "text-foreground")}>{count}</div>
        <div className="text-xs text-muted-foreground font-medium">{label}</div>
      </div>
    </button>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

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
  const [reviewing, setReviewing] = useState<{ finding: FpFinding; action: FpAction } | null>(null);
  const [reviewNote, setReviewNote] = useState("");

  const qParams = new URLSearchParams({ limit: "200" });
  if (statusFilter !== "all") qParams.set("status", statusFilter);
  if (severityFilter !== "all") qParams.set("severity", severityFilter);
  if (search.trim()) qParams.set("search", search.trim());

  const { data, isLoading, refetch, isFetching } = useQuery<FpListResponse>({
    queryKey: ["false-positives", statusFilter, severityFilter, search],
    queryFn: () => apiFetch<FpListResponse>(`/api/findings/false-positives?${qParams}`),
    staleTime: 20_000,
  });

  const findings = data?.findings ?? [];
  const submitted  = findings.filter(f => f.falsePositiveStatus === "submitted").length;
  const inProgress = findings.filter(f => f.falsePositiveStatus === "in_progress").length;
  const confirmed  = findings.filter(f => f.falsePositiveStatus === "confirmed").length;
  const rejected   = findings.filter(f => f.falsePositiveStatus === "rejected").length;
  const total      = findings.length;

  const reviewMut = useMutation({
    mutationFn: ({ id, action, note }: { id: number; action: FpAction; note: string }) =>
      apiFetch<{ ok: boolean }>(`/api/findings/${id}/fp-status`, {
        method: "PATCH",
        body: JSON.stringify({ action, note: note.trim() || undefined }),
      }),
    onSuccess: (_, vars) => {
      const messages: Record<FpAction, { title: string; description: string }> = {
        confirm:     { title: "Confirmed as false positive", description: "Finding confirmed and closed." },
        reconfirm:   { title: "Re-confirmed as false positive", description: "Finding restored to confirmed FP." },
        reject:      { title: "False positive rejected", description: "Finding reverted to open for re-investigation." },
        in_progress: { title: "Marked as in progress", description: "Finding is now under active review." },
        reopen:      { title: "Re-opened for review", description: "Finding sent back to pending review." },
      };
      const msg = messages[vars.action];
      toast({ title: msg.title, description: msg.description });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      qc.invalidateQueries({ queryKey: ["platform-overview"] });
      qc.invalidateQueries({ queryKey: ["admin-overview"] });
      qc.invalidateQueries({ queryKey: ["am-overview"] });
      setReviewing(null);
      setReviewNote("");
    },
    onError: () => toast({ title: "Review failed", description: "Could not update the finding.", variant: "destructive" }),
  });

  const openReview = useCallback((finding: FpFinding, action: FpAction) => {
    setReviewNote("");
    setReviewing({ finding, action });
  }, []);

  const clearFilters = () => { setStatusFilter("all"); setSeverityFilter("all"); setSearch(""); };
  const hasFilters = statusFilter !== "all" || severityFilter !== "all" || search !== "";
  const actionCfg = reviewing ? ACTION_CONFIG[reviewing.action] : null;

  return (
    <div className="min-h-screen flex flex-col bg-background">

      {/* ── Sticky header ────────────────────────────────────────────────── */}
      <div className="border-b border-border/60 bg-card/40 backdrop-blur-md sticky top-0 z-10">
        <div className="px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 border border-primary/20 flex items-center justify-center shadow-sm">
              <ListChecks className="w-4.5 h-4.5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">False Positives</h1>
              <p className="text-xs text-muted-foreground">
                {canReview
                  ? "Review & manage FP submissions — confirm, reject, or track as in-progress"
                  : "Track your false positive submissions and their review status"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground/60 font-mono bg-muted/30 px-2.5 py-1 rounded-lg border border-border/50">
              {total} total
            </span>
            <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching} className="gap-1.5 h-8 text-xs">
              <RefreshCw className={cn("w-3.5 h-3.5", isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <div className="flex-1 px-6 py-6 space-y-6 max-w-6xl mx-auto w-full">

        {/* ── Stat cards ───────────────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard
            label="Awaiting review"
            count={submitted}
            icon={Clock}
            active={statusFilter === "submitted"}
            color={{ ring: "border-amber-500/30", bg: "bg-amber-500/10", text: "text-amber-400", activeBg: "bg-amber-500/5", activeBorder: "border-amber-500/50" }}
            onClick={() => setStatusFilter(s => s === "submitted" ? "all" : "submitted")}
          />
          <StatCard
            label="Under active review"
            count={inProgress}
            icon={Hourglass}
            active={statusFilter === "in_progress"}
            color={{ ring: "border-blue-500/30", bg: "bg-blue-500/10", text: "text-blue-400", activeBg: "bg-blue-500/5", activeBorder: "border-blue-500/50" }}
            onClick={() => setStatusFilter(s => s === "in_progress" ? "all" : "in_progress")}
          />
          <StatCard
            label="Verified false positives"
            count={confirmed}
            icon={CheckCircle2}
            active={statusFilter === "confirmed"}
            color={{ ring: "border-emerald-500/30", bg: "bg-emerald-500/10", text: "text-emerald-400", activeBg: "bg-emerald-500/5", activeBorder: "border-emerald-500/50" }}
            onClick={() => setStatusFilter(s => s === "confirmed" ? "all" : "confirmed")}
          />
          <StatCard
            label="Reverted / not FP"
            count={rejected}
            icon={XCircle}
            active={statusFilter === "rejected"}
            color={{ ring: "border-red-500/30", bg: "bg-red-500/10", text: "text-red-400", activeBg: "bg-red-500/5", activeBorder: "border-red-500/50" }}
            onClick={() => setStatusFilter(s => s === "rejected" ? "all" : "rejected")}
          />
        </div>

        {/* ── Client info ──────────────────────────────────────────────── */}
        {role === "client" && (
          <div className="flex items-start gap-3 rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
            <Info className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
            <p className="text-sm text-blue-300/90">
              Mark findings as false positives from the{" "}
              <Link href="/findings" className="underline underline-offset-2 hover:text-blue-200 font-medium">Findings page</Link>
              {" "}using the Status column. An admin or account manager will review and confirm or reject each submission here.
            </p>
          </div>
        )}

        {/* ── Filters ──────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <Input className="pl-9 h-9 text-sm" placeholder="Search finding title, CVE…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="h-9 w-44 gap-1.5 text-sm">
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
            <SelectTrigger className="h-9 w-36 text-sm">
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
            <Button variant="ghost" size="sm" className="h-9 text-xs text-muted-foreground hover:text-foreground" onClick={clearFilters}>
              Clear filters
            </Button>
          )}
          <div className="ml-auto text-xs text-muted-foreground tabular-nums">
            {findings.length} result{findings.length !== 1 ? "s" : ""}
          </div>
        </div>

        {/* ── Content ──────────────────────────────────────────────────── */}
        {isLoading ? (
          <div className="flex flex-col items-center justify-center h-64 gap-3 text-muted-foreground">
            <Loader2 className="w-7 h-7 animate-spin opacity-40" />
            <span className="text-sm">Loading false positive submissions…</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border/60 bg-card/20 flex flex-col items-center justify-center py-24 text-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-muted/20 border border-border/40 flex items-center justify-center">
              <ShieldCheck className="w-8 h-8 text-muted-foreground/25" />
            </div>
            <div>
              <p className="text-base font-semibold text-foreground/70">No false positive submissions found</p>
              <p className="text-sm text-muted-foreground/60 mt-1.5 max-w-sm mx-auto">
                {hasFilters
                  ? "Try clearing your filters to see all results"
                  : "Mark findings as false positives from the Findings page. They will appear here for review."}
              </p>
            </div>
            {hasFilters && (
              <Button variant="outline" size="sm" onClick={clearFilters} className="mt-1 gap-1.5">
                <RefreshCw className="w-3.5 h-3.5" /> Clear filters
              </Button>
            )}
          </div>
        ) : (
          <div className="space-y-3">
            {/* Section header */}
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground/60">
                {statusFilter !== "all"
                  ? `${FP_STATUS_CONFIG[statusFilter as keyof typeof FP_STATUS_CONFIG]?.label ?? statusFilter} — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`
                  : `All submissions — ${findings.length} finding${findings.length !== 1 ? "s" : ""}`}
              </h2>
              {canReview && submitted > 0 && (
                <span className="flex items-center gap-1.5 text-xs text-amber-400 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                  {submitted} pending review
                </span>
              )}
            </div>

            {/* Cards */}
            {findings.map(f => (
              <FpCard
                key={f.id}
                f={f}
                canReview={canReview}
                showTenant={showTenant}
                onAction={openReview}
              />
            ))}
          </div>
        )}
      </div>

      {/* ── Review dialog ────────────────────────────────────────────────── */}
      <Dialog open={!!reviewing} onOpenChange={o => { if (!o) { setReviewing(null); setReviewNote(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              {reviewing?.action === "confirm"     && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reconfirm"   && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reject"      && <><XCircle className="w-5 h-5 text-red-400" />{actionCfg?.title}</>}
              {reviewing?.action === "in_progress" && <><Hourglass className="w-5 h-5 text-blue-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reopen"      && <><RotateCcw className="w-5 h-5 text-amber-400" />{actionCfg?.title}</>}
            </DialogTitle>
            <DialogDescription className="text-sm leading-relaxed">
              {actionCfg?.description}
            </DialogDescription>
          </DialogHeader>

          {reviewing && (
            <div className="space-y-4 py-1">

              {/* Finding summary */}
              <div className="rounded-xl border border-border bg-muted/20 p-4 space-y-3">
                <p className="text-sm font-semibold leading-snug">{reviewing.finding.title}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <SevBadge severity={reviewing.finding.severity} />
                  <FpStatusPill status={reviewing.finding.falsePositiveStatus} />
                  {reviewing.finding.cve && (
                    <span className="text-[11px] font-mono text-amber-400/80 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded">
                      {reviewing.finding.cve}
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <div className="flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 flex-shrink-0" />
                    <span className="truncate">{reviewing.finding.assetName ?? reviewing.finding.assetValue ?? `Asset #${reviewing.finding.assetId}`}</span>
                  </div>
                  {reviewing.finding.tenantName && (
                    <div className="flex items-center gap-1.5">
                      <Building2 className="w-3.5 h-3.5 flex-shrink-0" />
                      <span className="truncate">{reviewing.finding.tenantName}</span>
                    </div>
                  )}
                  {reviewing.finding.fpSubmittedByName && (
                    <div className="flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 flex-shrink-0" />
                      <span>Submitted by <strong className="text-foreground/70">{reviewing.finding.fpSubmittedByName}</strong></span>
                    </div>
                  )}
                  <div className="flex items-center gap-1.5">
                    <Calendar className="w-3.5 h-3.5 flex-shrink-0" />
                    <span>{fmtDateTime(reviewing.finding.fpSubmittedAt)}</span>
                  </div>
                </div>

                {/* Analyst reason inside dialog */}
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
                  Review Note <span className="text-muted-foreground font-normal">(optional)</span>
                </Label>
                <Textarea
                  className="resize-none text-sm min-h-[90px]"
                  rows={3}
                  placeholder={actionCfg?.notePlaceholder ?? ""}
                  value={reviewNote}
                  onChange={e => setReviewNote(e.target.value)}
                  autoFocus
                />
                <p className="text-[10px] text-muted-foreground/50 text-right">{reviewNote.length}/2000</p>
              </div>

              {/* Warning */}
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
