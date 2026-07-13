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
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  ListChecks, CheckCircle2, XCircle, Clock, Search, Filter,
  ExternalLink, Loader2, ShieldCheck, ShieldX, AlertTriangle,
  ChevronDown, RefreshCw, Info,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface FpFinding {
  id: number;
  title: string;
  severity: string;
  status: string;
  assetId: number;
  assetName: string | null;
  assetDomain: string | null;
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

// ── Severity badge ────────────────────────────────────────────────────────────
function SevBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical" ? "bg-red-500/20 text-red-400 border-red-500/30" :
    severity === "high"     ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
    severity === "medium"   ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" :
    severity === "low"      ? "bg-blue-500/20 text-blue-400 border-blue-500/30" :
                              "bg-slate-500/20 text-slate-400 border-slate-500/30";
  return <Badge variant="outline" className={cn("capitalize text-xs", cls)}>{severity}</Badge>;
}

// ── FP Status badge ───────────────────────────────────────────────────────────
function FpStatusBadge({ status }: { status: string }) {
  if (status === "submitted")
    return <Badge variant="outline" className="bg-amber-500/15 text-amber-400 border-amber-500/30 gap-1 text-xs"><Clock className="w-3 h-3" />Pending Review</Badge>;
  if (status === "confirmed")
    return <Badge variant="outline" className="bg-green-500/15 text-green-400 border-green-500/30 gap-1 text-xs"><CheckCircle2 className="w-3 h-3" />Confirmed FP</Badge>;
  if (status === "rejected")
    return <Badge variant="outline" className="bg-red-500/15 text-red-400 border-red-500/30 gap-1 text-xs"><XCircle className="w-3 h-3" />Rejected</Badge>;
  return <Badge variant="outline" className="text-xs text-muted-foreground">Unknown</Badge>;
}

function fmtDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

// ── Main page ────────────────────────────────────────────────────────────────
export default function FalsePositivesPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const role = user?.role ?? "client";
  const canReview = role === "super_admin" || role === "admin" || role === "account_manager";

  // Filters
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [search, setSearch] = useState("");

  // Review dialog state
  const [reviewing, setReviewing] = useState<{ finding: FpFinding; action: "confirm" | "reject" } | null>(null);
  const [reviewNote, setReviewNote] = useState("");

  const qParams = new URLSearchParams();
  if (statusFilter !== "all") qParams.set("status", statusFilter);
  if (severityFilter !== "all") qParams.set("severity", severityFilter);
  if (search.trim()) qParams.set("search", search.trim());
  qParams.set("limit", "200");

  const { data, isLoading, refetch } = useQuery<FpListResponse>({
    queryKey: ["false-positives", statusFilter, severityFilter, search],
    queryFn: () => apiFetch<FpListResponse>(`/api/findings/false-positives?${qParams}`),
    staleTime: 30_000,
  });

  const findings = data?.findings ?? [];

  // ── Stats ─────────────────────────────────────────────────────────────────
  const submitted = findings.filter(f => f.falsePositiveStatus === "submitted").length;
  const confirmed = findings.filter(f => f.falsePositiveStatus === "confirmed").length;
  const rejected  = findings.filter(f => f.falsePositiveStatus === "rejected").length;

  // ── Review mutation ───────────────────────────────────────────────────────
  const reviewMut = useMutation({
    mutationFn: ({ id, action, note }: { id: number; action: string; note: string }) =>
      apiFetch<{ ok: boolean }>(`/api/findings/${id}/fp-status`, {
        method: "PATCH",
        body: JSON.stringify({ action, note: note.trim() || undefined }),
      }),
    onSuccess: (_, vars) => {
      toast({
        title: vars.action === "confirm" ? "False positive confirmed" : "False positive rejected",
        description: vars.action === "confirm"
          ? "Finding confirmed as false positive and marked resolved."
          : "Finding rejected — status reset to open for re-investigation.",
      });
      qc.invalidateQueries({ queryKey: ["false-positives"] });
      setReviewing(null);
      setReviewNote("");
    },
    onError: () => toast({ title: "Review failed", description: "Could not update the finding. Please try again.", variant: "destructive" }),
  });

  const openReview = useCallback((finding: FpFinding, action: "confirm" | "reject") => {
    setReviewNote("");
    setReviewing({ finding, action });
  }, []);

  const submitReview = () => {
    if (!reviewing) return;
    reviewMut.mutate({ id: reviewing.finding.id, action: reviewing.action, note: reviewNote });
  };

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className="p-6 space-y-6 max-w-screen-xl mx-auto">

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ListChecks className="w-6 h-6 text-primary" />
            False Positives
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            {canReview
              ? "Review, confirm, or reject false positive submissions from all clients."
              : "View and submit false positive requests for your assigned findings."}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="gap-1.5">
          <RefreshCw className="w-3.5 h-3.5" /> Refresh
        </Button>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-3 gap-4">
        <div
          className={cn("rounded-xl border p-4 cursor-pointer transition-colors", statusFilter === "submitted"
            ? "border-amber-500/50 bg-amber-500/10" : "border-border bg-card hover:border-amber-500/30")}
          onClick={() => setStatusFilter(s => s === "submitted" ? "all" : "submitted")}
        >
          <div className="flex items-center gap-2 text-amber-400 mb-1">
            <Clock className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Pending Review</span>
          </div>
          <div className="text-3xl font-bold">{submitted}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Awaiting confirmation</div>
        </div>

        <div
          className={cn("rounded-xl border p-4 cursor-pointer transition-colors", statusFilter === "confirmed"
            ? "border-green-500/50 bg-green-500/10" : "border-border bg-card hover:border-green-500/30")}
          onClick={() => setStatusFilter(s => s === "confirmed" ? "all" : "confirmed")}
        >
          <div className="flex items-center gap-2 text-green-400 mb-1">
            <CheckCircle2 className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Confirmed</span>
          </div>
          <div className="text-3xl font-bold">{confirmed}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Verified false positives</div>
        </div>

        <div
          className={cn("rounded-xl border p-4 cursor-pointer transition-colors", statusFilter === "rejected"
            ? "border-red-500/50 bg-red-500/10" : "border-border bg-card hover:border-red-500/30")}
          onClick={() => setStatusFilter(s => s === "rejected" ? "all" : "rejected")}
        >
          <div className="flex items-center gap-2 text-red-400 mb-1">
            <XCircle className="w-4 h-4" />
            <span className="text-xs font-medium uppercase tracking-wide">Rejected</span>
          </div>
          <div className="text-3xl font-bold">{rejected}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Reverted to open</div>
        </div>
      </div>

      {/* Role hint for clients */}
      {role === "client" && (
        <div className="flex items-start gap-2 rounded-lg border border-blue-500/20 bg-blue-500/5 p-3 text-sm text-blue-300">
          <Info className="w-4 h-4 mt-0.5 shrink-0" />
          <span>You can mark findings as false positives from the <Link href="/findings" className="underline underline-offset-2">Findings page</Link>. An admin or account manager will review and confirm or reject each submission.</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            className="pl-8 h-8 text-sm"
            placeholder="Search findings…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-8 w-40 text-sm">
            <Filter className="w-3.5 h-3.5 mr-1.5" /><SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="submitted">Pending Review</SelectItem>
            <SelectItem value="confirmed">Confirmed FP</SelectItem>
            <SelectItem value="rejected">Rejected</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="h-8 w-36 text-sm">
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
        {(statusFilter !== "all" || severityFilter !== "all" || search) && (
          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => { setStatusFilter("all"); setSeverityFilter("all"); setSearch(""); }}>
            Clear filters
          </Button>
        )}
        <span className="text-xs text-muted-foreground ml-auto">{findings.length} result{findings.length !== 1 ? "s" : ""}</span>
      </div>

      {/* Table */}
      <div className="rounded-xl border border-border overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-40 gap-2 text-muted-foreground">
            <Loader2 className="w-5 h-5 animate-spin" /> Loading false positives…
          </div>
        ) : findings.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center gap-2">
            <ShieldCheck className="w-10 h-10 text-muted-foreground/30" />
            <p className="text-muted-foreground text-sm">No false positive submissions found</p>
            <p className="text-xs text-muted-foreground/60">
              {statusFilter !== "all" ? "Try clearing your filters" : "Mark findings as false positives from the Findings page"}
            </p>
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="border-b border-border/50">
                <TableHead className="text-xs font-medium py-2.5">Finding</TableHead>
                <TableHead className="text-xs font-medium py-2.5">Asset</TableHead>
                {(role === "super_admin" || role === "admin") && (
                  <TableHead className="text-xs font-medium py-2.5">Tenant</TableHead>
                )}
                <TableHead className="text-xs font-medium py-2.5">Severity</TableHead>
                <TableHead className="text-xs font-medium py-2.5">FP Status</TableHead>
                <TableHead className="text-xs font-medium py-2.5">Submitted By</TableHead>
                <TableHead className="text-xs font-medium py-2.5">Submitted</TableHead>
                <TableHead className="text-xs font-medium py-2.5">Reviewed By</TableHead>
                {canReview && <TableHead className="text-xs font-medium py-2.5 text-right">Actions</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map(f => (
                <TableRow key={f.id} className="border-b border-border/30 hover:bg-muted/20">
                  <TableCell className="py-2.5 max-w-xs">
                    <div className="flex items-start gap-1.5">
                      <div>
                        <Link href={`/findings/${f.id}`} className="text-sm font-medium hover:text-primary transition-colors line-clamp-1">
                          {f.title}
                        </Link>
                        {f.cve && (
                          <span className="text-xs text-muted-foreground font-mono">{f.cve}</span>
                        )}
                        {f.fpNote && (
                          <p className="text-xs text-muted-foreground mt-0.5 italic line-clamp-1">Note: {f.fpNote}</p>
                        )}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="py-2.5">
                    <Link href={`/assets/${f.assetId}`} className="text-sm hover:text-primary transition-colors">
                      {f.assetName ?? f.assetDomain ?? `Asset #${f.assetId}`}
                    </Link>
                    {f.assetDomain && f.assetName && (
                      <div className="text-xs text-muted-foreground">{f.assetDomain}</div>
                    )}
                  </TableCell>
                  {(role === "super_admin" || role === "admin") && (
                    <TableCell className="py-2.5">
                      <span className="text-xs text-muted-foreground">{f.tenantName ?? `Tenant #${f.tenantId}`}</span>
                    </TableCell>
                  )}
                  <TableCell className="py-2.5">
                    <SevBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="py-2.5">
                    <FpStatusBadge status={f.falsePositiveStatus} />
                  </TableCell>
                  <TableCell className="py-2.5">
                    <span className="text-sm text-muted-foreground">
                      {f.fpSubmittedByName ?? "—"}
                    </span>
                  </TableCell>
                  <TableCell className="py-2.5">
                    <span className="text-xs text-muted-foreground">{fmtDate(f.fpSubmittedAt)}</span>
                  </TableCell>
                  <TableCell className="py-2.5">
                    {f.fpReviewedByName ? (
                      <div>
                        <span className="text-sm text-muted-foreground">{f.fpReviewedByName}</span>
                        <div className="text-xs text-muted-foreground/60">{fmtDate(f.fpReviewedAt)}</div>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground/40">Not reviewed</span>
                    )}
                  </TableCell>
                  {canReview && (
                    <TableCell className="py-2.5 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {f.falsePositiveStatus === "submitted" && (
                          <>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2.5 text-xs gap-1 text-green-400 border-green-500/30 hover:bg-green-500/10"
                              onClick={() => openReview(f, "confirm")}
                            >
                              <ShieldCheck className="w-3.5 h-3.5" /> Confirm
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-7 px-2.5 text-xs gap-1 text-red-400 border-red-500/30 hover:bg-red-500/10"
                              onClick={() => openReview(f, "reject")}
                            >
                              <ShieldX className="w-3.5 h-3.5" /> Reject
                            </Button>
                          </>
                        )}
                        {f.falsePositiveStatus === "confirmed" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 px-2.5 text-xs gap-1 text-red-400 hover:bg-red-500/10"
                            onClick={() => openReview(f, "reject")}
                          >
                            <XCircle className="w-3 h-3" /> Reopen
                          </Button>
                        )}
                        {f.falsePositiveStatus === "rejected" && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 px-2.5 text-xs gap-1 text-green-400 hover:bg-green-500/10"
                            onClick={() => openReview(f, "confirm")}
                          >
                            <CheckCircle2 className="w-3 h-3" /> Re-confirm
                          </Button>
                        )}
                        <Link href={`/findings/${f.id}`}>
                          <Button size="sm" variant="ghost" className="h-7 w-7 p-0">
                            <ExternalLink className="w-3.5 h-3.5" />
                          </Button>
                        </Link>
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {/* Review dialog */}
      <Dialog open={!!reviewing} onOpenChange={o => { if (!o) { setReviewing(null); setReviewNote(""); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {reviewing?.action === "confirm"
                ? <><CheckCircle2 className="w-5 h-5 text-green-400" /> Confirm False Positive</>
                : <><XCircle className="w-5 h-5 text-red-400" /> Reject False Positive</>}
            </DialogTitle>
            <DialogDescription>
              {reviewing?.action === "confirm"
                ? "Confirming marks this finding as a verified false positive and resolves it. Future identical findings will be suppressed."
                : "Rejecting reverts this finding to open status for re-investigation."}
            </DialogDescription>
          </DialogHeader>

          {reviewing && (
            <div className="space-y-3 py-1">
              <div className="rounded-lg border border-border bg-muted/30 p-3 space-y-1">
                <p className="text-sm font-medium line-clamp-2">{reviewing.finding.title}</p>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <SevBadge severity={reviewing.finding.severity} />
                  <span>·</span>
                  <span>{reviewing.finding.assetName ?? reviewing.finding.assetDomain ?? `Asset #${reviewing.finding.assetId}`}</span>
                  {reviewing.finding.tenantName && <><span>·</span><span>{reviewing.finding.tenantName}</span></>}
                </div>
                {reviewing.finding.fpSubmittedByName && (
                  <p className="text-xs text-muted-foreground">
                    Submitted by <span className="font-medium">{reviewing.finding.fpSubmittedByName}</span> on {fmtDate(reviewing.finding.fpSubmittedAt)}
                  </p>
                )}
              </div>
              <div>
                <Label className="text-xs">Review Note <span className="text-muted-foreground">(optional)</span></Label>
                <Textarea
                  className="mt-1 text-sm resize-none"
                  rows={3}
                  placeholder={reviewing.action === "confirm"
                    ? "e.g. Verified — this is expected behaviour in our environment."
                    : "e.g. This is a real vulnerability, needs remediation."}
                  value={reviewNote}
                  onChange={e => setReviewNote(e.target.value)}
                />
              </div>
              {reviewing.action === "confirm" && (
                <div className="flex items-start gap-2 rounded-md border border-amber-500/20 bg-amber-500/5 p-2.5 text-xs text-amber-300">
                  <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>The finding status will be set to <strong>false_positive</strong> and removed from the active vulnerability count.</span>
                </div>
              )}
            </div>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => { setReviewing(null); setReviewNote(""); }}>Cancel</Button>
            <Button
              onClick={submitReview}
              disabled={reviewMut.isPending}
              className={cn(reviewing?.action === "confirm"
                ? "bg-green-600 hover:bg-green-700 text-white"
                : "bg-red-600 hover:bg-red-700 text-white")}
            >
              {reviewMut.isPending && <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />}
              {reviewing?.action === "confirm" ? "Confirm False Positive" : "Reject & Reopen"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
