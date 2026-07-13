import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { Badge } from "@/components/ui/badge";
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
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border", c.bg, c.text, c.border)}>
      <span className={cn("w-1.5 h-1.5 rounded-full", c.dot)} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

function FpStatusPill({ status }: { status: string }) {
  if (status === "submitted")
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-amber-500/10 text-amber-300 border border-amber-500/25">
        <Clock className="w-3 h-3" /> Pending Review
      </span>
    );
  if (status === "in_progress")
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-500/10 text-blue-300 border border-blue-500/25">
        <Hourglass className="w-3 h-3" /> In Progress
      </span>
    );
  if (status === "confirmed")
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/25">
        <CheckCircle2 className="w-3 h-3" /> Confirmed FP
      </span>
    );
  if (status === "rejected")
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/10 text-red-300 border border-red-500/25">
        <XCircle className="w-3 h-3" /> Rejected
      </span>
    );
  return <span className="text-xs text-muted-foreground/50">—</span>;
}

function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

function fmtDateTime(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

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
    description: "Confirming marks this finding as a verified false positive and closes it.",
    notePlaceholder: "e.g. Verified — expected behaviour in our environment.",
    btnLabel: "Confirm FP",
    btnClass: "bg-emerald-600 hover:bg-emerald-700 text-white",
    warning: "The finding status will be set to false_positive and removed from the active vulnerability count. Future identical findings from scans will be suppressed automatically.",
  },
  reconfirm: {
    title: "Re-confirm False Positive",
    description: "Re-confirming restores this finding to confirmed false positive after it was rejected.",
    notePlaceholder: "e.g. Further review confirmed — still a false positive.",
    btnLabel: "Re-confirm FP",
    btnClass: "bg-emerald-600 hover:bg-emerald-700 text-white",
    warning: "The finding will be restored to confirmed false positive status.",
  },
  reject: {
    title: "Reject False Positive",
    description: "Rejecting reverts this finding to open status for re-investigation.",
    notePlaceholder: "e.g. Real vulnerability, needs immediate remediation.",
    btnLabel: "Reject",
    btnClass: "bg-red-600 hover:bg-red-700 text-white",
  },
  in_progress: {
    title: "Mark as In Progress",
    description: "Mark this FP submission as under active review. The finding stays in false_positive status.",
    notePlaceholder: "e.g. Currently investigating this finding with the client.",
    btnLabel: "Mark In Progress",
    btnClass: "bg-blue-600 hover:bg-blue-700 text-white",
  },
  reopen: {
    title: "Re-open for Review",
    description: "Send this finding back to pending review. A reviewer can then confirm, reject, or mark as in progress.",
    notePlaceholder: "e.g. Needs a second opinion before finalising.",
    btnLabel: "Re-open",
    btnClass: "bg-amber-600 hover:bg-amber-700 text-white",
  },
};

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
  const submitted   = findings.filter(f => f.falsePositiveStatus === "submitted").length;
  const inProgress  = findings.filter(f => f.falsePositiveStatus === "in_progress").length;
  const confirmed   = findings.filter(f => f.falsePositiveStatus === "confirmed").length;
  const rejected    = findings.filter(f => f.falsePositiveStatus === "rejected").length;
  const total       = findings.length;

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
    <div className="min-h-screen flex flex-col">

      {/* ── Top header bar ─────────────────────────────────────────────────── */}
      <div className="border-b border-border/60 bg-card/30 backdrop-blur-sm sticky top-0 z-10">
        <div className="px-6 py-4 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center">
              <ListChecks className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-semibold tracking-tight">False Positives</h1>
              <p className="text-xs text-muted-foreground">
                {canReview ? "Review & manage FP submissions across all clients" : "Track your false positive submissions"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="text-xs font-mono">{total} total</Badge>
            <Button
              variant="outline"
              size="sm"
              onClick={() => refetch()}
              disabled={isFetching}
              className="gap-1.5 h-8"
            >
              <RefreshCw className={cn("w-3.5 h-3.5", isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </div>
      </div>

      <div className="flex-1 p-6 space-y-6">

        {/* ── Stats row ─────────────────────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          {/* Pending */}
          <button
            onClick={() => setStatusFilter(s => s === "submitted" ? "all" : "submitted")}
            className={cn(
              "text-left rounded-xl border p-5 transition-all group",
              statusFilter === "submitted"
                ? "border-amber-500/60 bg-amber-500/8 shadow-[0_0_0_1px_rgba(245,158,11,0.15)]"
                : "border-border bg-card hover:border-amber-500/40 hover:bg-amber-500/5"
            )}
          >
            <div className="flex items-start justify-between mb-3">
              <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center transition-colors",
                statusFilter === "submitted" ? "bg-amber-500/20" : "bg-amber-500/10 group-hover:bg-amber-500/15")}>
                <Clock className="w-5 h-5 text-amber-400" />
              </div>
              <span className="text-xs text-amber-400/70 font-medium uppercase tracking-wider">Pending</span>
            </div>
            <div className="text-4xl font-bold tabular-nums">{submitted}</div>
            <div className="text-sm text-muted-foreground mt-1">Awaiting review</div>
            {statusFilter === "submitted" && <div className="mt-2 text-xs text-amber-400/70">Filtered ✓</div>}
          </button>

          {/* In Progress */}
          <button
            onClick={() => setStatusFilter(s => s === "in_progress" ? "all" : "in_progress")}
            className={cn(
              "text-left rounded-xl border p-5 transition-all group",
              statusFilter === "in_progress"
                ? "border-blue-500/60 bg-blue-500/8 shadow-[0_0_0_1px_rgba(59,130,246,0.15)]"
                : "border-border bg-card hover:border-blue-500/40 hover:bg-blue-500/5"
            )}
          >
            <div className="flex items-start justify-between mb-3">
              <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center transition-colors",
                statusFilter === "in_progress" ? "bg-blue-500/20" : "bg-blue-500/10 group-hover:bg-blue-500/15")}>
                <Hourglass className="w-5 h-5 text-blue-400" />
              </div>
              <span className="text-xs text-blue-400/70 font-medium uppercase tracking-wider">In Progress</span>
            </div>
            <div className="text-4xl font-bold tabular-nums">{inProgress}</div>
            <div className="text-sm text-muted-foreground mt-1">Under active review</div>
            {statusFilter === "in_progress" && <div className="mt-2 text-xs text-blue-400/70">Filtered ✓</div>}
          </button>

          {/* Confirmed */}
          <button
            onClick={() => setStatusFilter(s => s === "confirmed" ? "all" : "confirmed")}
            className={cn(
              "text-left rounded-xl border p-5 transition-all group",
              statusFilter === "confirmed"
                ? "border-emerald-500/60 bg-emerald-500/8 shadow-[0_0_0_1px_rgba(16,185,129,0.15)]"
                : "border-border bg-card hover:border-emerald-500/40 hover:bg-emerald-500/5"
            )}
          >
            <div className="flex items-start justify-between mb-3">
              <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center transition-colors",
                statusFilter === "confirmed" ? "bg-emerald-500/20" : "bg-emerald-500/10 group-hover:bg-emerald-500/15")}>
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>
              <span className="text-xs text-emerald-400/70 font-medium uppercase tracking-wider">Confirmed</span>
            </div>
            <div className="text-4xl font-bold tabular-nums">{confirmed}</div>
            <div className="text-sm text-muted-foreground mt-1">Verified false positives</div>
            {statusFilter === "confirmed" && <div className="mt-2 text-xs text-emerald-400/70">Filtered ✓</div>}
          </button>

          {/* Rejected */}
          <button
            onClick={() => setStatusFilter(s => s === "rejected" ? "all" : "rejected")}
            className={cn(
              "text-left rounded-xl border p-5 transition-all group",
              statusFilter === "rejected"
                ? "border-red-500/60 bg-red-500/8 shadow-[0_0_0_1px_rgba(239,68,68,0.15)]"
                : "border-border bg-card hover:border-red-500/40 hover:bg-red-500/5"
            )}
          >
            <div className="flex items-start justify-between mb-3">
              <div className={cn("w-10 h-10 rounded-lg flex items-center justify-center transition-colors",
                statusFilter === "rejected" ? "bg-red-500/20" : "bg-red-500/10 group-hover:bg-red-500/15")}>
                <XCircle className="w-5 h-5 text-red-400" />
              </div>
              <span className="text-xs text-red-400/70 font-medium uppercase tracking-wider">Rejected</span>
            </div>
            <div className="text-4xl font-bold tabular-nums">{rejected}</div>
            <div className="text-sm text-muted-foreground mt-1">Reverted / not FP</div>
            {statusFilter === "rejected" && <div className="mt-2 text-xs text-red-400/70">Filtered ✓</div>}
          </button>
        </div>

        {/* ── Client info banner ────────────────────────────────────────────── */}
        {role === "client" && (
          <div className="flex items-start gap-3 rounded-xl border border-blue-500/20 bg-blue-500/5 p-4">
            <Info className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
            <div className="text-sm text-blue-300/90">
              Mark findings as false positives from the{" "}
              <Link href="/findings" className="underline underline-offset-2 hover:text-blue-200">Findings page</Link>.
              An admin or account manager will review and confirm or reject each submission.
            </div>
          </div>
        )}

        {/* ── Filters ─────────────────────────────────────────────────────── */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[260px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <Input
              className="pl-9 h-9"
              placeholder="Search finding title or CVE…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="h-9 w-48 gap-1.5">
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
            <SelectTrigger className="h-9 w-36">
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
          <div className="ml-auto text-sm text-muted-foreground">
            {findings.length} result{findings.length !== 1 ? "s" : ""}
          </div>
        </div>

        {/* ── Main content ─────────────────────────────────────────────────── */}
        {isLoading ? (
          <div className="flex items-center justify-center h-64 gap-3 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin" />
            <span>Loading false positives…</span>
          </div>
        ) : findings.length === 0 ? (
          <div className="rounded-xl border border-dashed border-border bg-card/30 flex flex-col items-center justify-center py-20 text-center gap-3">
            <div className="w-14 h-14 rounded-full bg-muted/20 flex items-center justify-center">
              <ShieldCheck className="w-7 h-7 text-muted-foreground/30" />
            </div>
            <div>
              <p className="text-base font-medium text-muted-foreground">No false positive submissions found</p>
              <p className="text-sm text-muted-foreground/60 mt-1">
                {hasFilters
                  ? "Try clearing your filters to see all results"
                  : "Mark findings as false positives from the Findings page"}
              </p>
            </div>
            {hasFilters && (
              <Button variant="outline" size="sm" onClick={clearFilters} className="mt-2">Clear filters</Button>
            )}
          </div>
        ) : (
          <div className="rounded-xl border border-border overflow-hidden">
            {/* Table header */}
            <div className={cn(
              "grid gap-4 px-5 py-3 bg-muted/30 border-b border-border/50 text-xs font-medium text-muted-foreground uppercase tracking-wide",
              showTenant
                ? "grid-cols-[2fr_1.2fr_0.7fr_0.9fr_1fr_1fr_1fr_auto]"
                : "grid-cols-[2fr_1.2fr_0.9fr_1fr_1fr_1fr_auto]"
            )}>
              <span>Finding</span>
              <span>Asset</span>
              {showTenant && <span>Tenant</span>}
              <span>Severity</span>
              <span>FP Status</span>
              <span>Submitted By</span>
              <span>Reviewed By</span>
              {canReview && <span className="text-right">Actions</span>}
            </div>

            {/* Rows */}
            <div className="divide-y divide-border/30">
              {findings.map(f => (
                <div
                  key={f.id}
                  className={cn(
                    "grid gap-4 px-5 py-4 hover:bg-muted/10 transition-colors",
                    showTenant
                      ? "grid-cols-[2fr_1.2fr_0.7fr_0.9fr_1fr_1fr_1fr_auto]"
                      : "grid-cols-[2fr_1.2fr_0.9fr_1fr_1fr_1fr_auto]"
                  )}
                >
                  {/* Finding title + CVE + note */}
                  <div className="min-w-0">
                    <Link href={`/findings/${f.id}`}>
                      <span className="font-medium text-sm hover:text-primary transition-colors cursor-pointer line-clamp-2 leading-snug">
                        {f.title}
                      </span>
                    </Link>
                    <div className="flex items-center gap-2 mt-1">
                      {f.cve && (
                        <span className="text-xs font-mono text-muted-foreground/70 bg-muted/30 px-1.5 py-0.5 rounded">
                          {f.cve}
                        </span>
                      )}
                      {f.cvss != null && (
                        <span className="text-xs text-muted-foreground/60">CVSS {f.cvss.toFixed(1)}</span>
                      )}
                    </div>
                    {f.fpNote && (
                      <p className="text-xs text-muted-foreground/60 mt-1 italic line-clamp-1">"{f.fpNote}"</p>
                    )}
                  </div>

                  {/* Asset */}
                  <div className="min-w-0 flex flex-col justify-center">
                    <Link href={`/assets/${f.assetId}`}>
                      <span className="text-sm hover:text-primary transition-colors cursor-pointer truncate block">
                        {f.assetName ?? f.assetValue ?? `Asset #${f.assetId}`}
                      </span>
                    </Link>
                    {f.assetValue && f.assetName && (
                      <span className="text-xs text-muted-foreground/60 truncate">{f.assetValue}</span>
                    )}
                  </div>

                  {/* Tenant (SA/Admin only) */}
                  {showTenant && (
                    <div className="flex items-center min-w-0">
                      <span className="text-xs text-muted-foreground truncate">{f.tenantName ?? `#${f.tenantId}`}</span>
                    </div>
                  )}

                  {/* Severity */}
                  <div className="flex items-center">
                    <SevBadge severity={f.severity} />
                  </div>

                  {/* FP Status */}
                  <div className="flex items-center">
                    <FpStatusPill status={f.falsePositiveStatus} />
                  </div>

                  {/* Submitted by */}
                  <div className="flex flex-col justify-center min-w-0">
                    <span className="text-sm truncate">{f.fpSubmittedByName ?? <span className="text-muted-foreground/40 text-xs">—</span>}</span>
                    <span className="text-xs text-muted-foreground/60">{fmtDate(f.fpSubmittedAt)}</span>
                  </div>

                  {/* Reviewed by */}
                  <div className="flex flex-col justify-center min-w-0">
                    {f.fpReviewedByName ? (
                      <>
                        <span className="text-sm truncate">{f.fpReviewedByName}</span>
                        <span className="text-xs text-muted-foreground/60">{fmtDate(f.fpReviewedAt)}</span>
                      </>
                    ) : (
                      <span className="text-xs text-muted-foreground/35">Not reviewed</span>
                    )}
                  </div>

                  {/* Actions */}
                  {canReview && (
                    <div className="flex items-center justify-end gap-1">
                      {/* Submitted → Confirm, In Progress, Reject */}
                      {f.falsePositiveStatus === "submitted" && (
                        <>
                          <Button size="sm" variant="outline"
                            className="h-7 px-2 text-xs gap-1 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10 hover:border-emerald-500/50"
                            onClick={() => openReview(f, "confirm")}>
                            <ShieldCheck className="w-3 h-3" /> Confirm
                          </Button>
                          <Button size="sm" variant="outline"
                            className="h-7 px-2 text-xs gap-1 text-blue-400 border-blue-500/30 hover:bg-blue-500/10 hover:border-blue-500/50"
                            onClick={() => openReview(f, "in_progress")}>
                            <Hourglass className="w-3 h-3" /> Progress
                          </Button>
                          <Button size="sm" variant="outline"
                            className="h-7 px-2 text-xs gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10 hover:border-red-500/50"
                            onClick={() => openReview(f, "reject")}>
                            <ShieldX className="w-3 h-3" /> Reject
                          </Button>
                        </>
                      )}
                      {/* In Progress → Confirm, Reject, Re-open */}
                      {f.falsePositiveStatus === "in_progress" && (
                        <>
                          <Button size="sm" variant="outline"
                            className="h-7 px-2 text-xs gap-1 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/10 hover:border-emerald-500/50"
                            onClick={() => openReview(f, "confirm")}>
                            <ShieldCheck className="w-3 h-3" /> Confirm
                          </Button>
                          <Button size="sm" variant="outline"
                            className="h-7 px-2 text-xs gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10 hover:border-red-500/50"
                            onClick={() => openReview(f, "reject")}>
                            <ShieldX className="w-3 h-3" /> Reject
                          </Button>
                          <Button size="sm" variant="ghost"
                            className="h-7 px-2 text-xs gap-1 text-amber-400/70 hover:text-amber-400 hover:bg-amber-500/10"
                            onClick={() => openReview(f, "reopen")}>
                            <RotateCcw className="w-3 h-3" /> Re-open
                          </Button>
                        </>
                      )}
                      {/* Confirmed → Re-open, Reject */}
                      {f.falsePositiveStatus === "confirmed" && (
                        <>
                          <Button size="sm" variant="ghost"
                            className="h-7 px-2 text-xs gap-1 text-amber-400/70 hover:text-amber-400 hover:bg-amber-500/10"
                            onClick={() => openReview(f, "reopen")}>
                            <RotateCcw className="w-3 h-3" /> Re-open
                          </Button>
                          <Button size="sm" variant="ghost"
                            className="h-7 px-2 text-xs gap-1 text-red-400/70 hover:text-red-400 hover:bg-red-500/10"
                            onClick={() => openReview(f, "reject")}>
                            <XCircle className="w-3 h-3" /> Reject
                          </Button>
                        </>
                      )}
                      {/* Rejected → Re-confirm, Re-open */}
                      {f.falsePositiveStatus === "rejected" && (
                        <>
                          <Button size="sm" variant="ghost"
                            className="h-7 px-2 text-xs gap-1 text-emerald-400/70 hover:text-emerald-400 hover:bg-emerald-500/10"
                            onClick={() => openReview(f, "reconfirm")}>
                            <CheckCircle2 className="w-3 h-3" /> Re-confirm
                          </Button>
                          <Button size="sm" variant="ghost"
                            className="h-7 px-2 text-xs gap-1 text-amber-400/70 hover:text-amber-400 hover:bg-amber-500/10"
                            onClick={() => openReview(f, "reopen")}>
                            <RotateCcw className="w-3 h-3" /> Re-open
                          </Button>
                        </>
                      )}
                      <Link href={`/findings/${f.id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                    </div>
                  )}
                  {!canReview && (
                    <div className="flex items-center justify-end">
                      <Link href={`/findings/${f.id}`}>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Footer */}
            <div className="px-5 py-3 bg-muted/20 border-t border-border/50 flex items-center justify-between text-xs text-muted-foreground">
              <span>Showing {findings.length} false positive{findings.length !== 1 ? "s" : ""}</span>
              {canReview && submitted > 0 && (
                <span className="text-amber-400">{submitted} pending review</span>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ── Review dialog ─────────────────────────────────────────────────── */}
      <Dialog open={!!reviewing} onOpenChange={o => { if (!o) { setReviewing(null); setReviewNote(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              {reviewing?.action === "confirm" && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reconfirm" && <><CheckCircle2 className="w-5 h-5 text-emerald-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reject" && <><XCircle className="w-5 h-5 text-red-400" />{actionCfg?.title}</>}
              {reviewing?.action === "in_progress" && <><Hourglass className="w-5 h-5 text-blue-400" />{actionCfg?.title}</>}
              {reviewing?.action === "reopen" && <><RotateCcw className="w-5 h-5 text-amber-400" />{actionCfg?.title}</>}
            </DialogTitle>
            <DialogDescription className="text-sm">
              {actionCfg?.description}
            </DialogDescription>
          </DialogHeader>

          {reviewing && (
            <div className="space-y-4 py-1">
              {/* Finding summary card */}
              <div className="rounded-lg border border-border bg-muted/20 p-4 space-y-2">
                <p className="text-sm font-medium leading-snug">{reviewing.finding.title}</p>
                <div className="flex items-center gap-2 flex-wrap">
                  <SevBadge severity={reviewing.finding.severity} />
                  <span className="text-xs text-muted-foreground">·</span>
                  <span className="text-xs text-muted-foreground">
                    {reviewing.finding.assetName ?? reviewing.finding.assetValue ?? `Asset #${reviewing.finding.assetId}`}
                  </span>
                  {reviewing.finding.tenantName && (
                    <>
                      <span className="text-xs text-muted-foreground">·</span>
                      <span className="text-xs text-muted-foreground">{reviewing.finding.tenantName}</span>
                    </>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">Current status:</span>
                  <FpStatusPill status={reviewing.finding.falsePositiveStatus} />
                </div>
                {reviewing.finding.fpSubmittedByName && (
                  <p className="text-xs text-muted-foreground">
                    Submitted by <span className="font-medium text-foreground/70">{reviewing.finding.fpSubmittedByName}</span>
                    {" "}on {fmtDateTime(reviewing.finding.fpSubmittedAt)}
                  </p>
                )}
              </div>

              {/* Note */}
              <div className="space-y-1.5">
                <Label className="text-sm">
                  Review Note <span className="text-muted-foreground font-normal">(optional)</span>
                </Label>
                <Textarea
                  className="resize-none text-sm"
                  rows={3}
                  placeholder={actionCfg?.notePlaceholder ?? ""}
                  value={reviewNote}
                  onChange={e => setReviewNote(e.target.value)}
                />
              </div>

              {/* Warning */}
              {actionCfg?.warning && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>{actionCfg.warning}</span>
                </div>
              )}
            </div>
          )}

          <DialogFooter className="gap-2">
            <Button variant="outline" size="sm" onClick={() => { setReviewing(null); setReviewNote(""); }}>
              Cancel
            </Button>
            <Button
              size="sm"
              disabled={reviewMut.isPending}
              className={actionCfg?.btnClass}
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
