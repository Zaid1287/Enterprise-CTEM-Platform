import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2, XCircle, Clock, Mail, Building2, User, Phone,
  Users, MessageSquare, Loader2, ChevronDown, ChevronUp,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn, formatDate } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

interface AccessRequest {
  id: number;
  fullName: string;
  companyName: string;
  email: string;
  jobTitle: string | null;
  teamSize: string | null;
  phone: string | null;
  message: string | null;
  status: "pending" | "approved" | "rejected";
  reviewedByUserId: string | null;
  reviewNotes: string | null;
  createdAt: string;
}

const STATUS_MAP: Record<string, { label: string; icon: React.ElementType; cls: string }> = {
  pending:  { label: "Pending",  icon: Clock,        cls: "bg-amber-500/10 text-amber-400 border-amber-500/30"  },
  approved: { label: "Approved", icon: CheckCircle2, cls: "bg-green-500/10 text-green-400 border-green-500/30"  },
  rejected: { label: "Rejected", icon: XCircle,      cls: "bg-red-500/10   text-red-400   border-red-500/30"    },
};

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_MAP[status] ?? STATUS_MAP.pending;
  const Icon = s.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium border", s.cls)}>
      <Icon className="w-3 h-3" />{s.label}
    </span>
  );
}

export default function AccessRequestsPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [reviewNotes, setReviewNotes] = useState<Record<number, string>>({});
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const { data: requests = [], isLoading } = useQuery<AccessRequest[]>({
    queryKey: ["access-requests"],
    queryFn: () => apiFetch(`${BASE}/api/auth/access-requests`),
    staleTime: 30_000,
  });

  const reviewMutation = useMutation({
    mutationFn: ({ id, status, notes }: { id: number; status: string; notes: string }) =>
      apiFetch(`${BASE}/api/auth/access-requests/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ status, reviewNotes: notes || null }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["access-requests"] });
      toast({ title: "Review saved" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const filtered = statusFilter === "all" ? requests : requests.filter(r => r.status === statusFilter);

  const counts = {
    all: requests.length,
    pending: requests.filter(r => r.status === "pending").length,
    approved: requests.filter(r => r.status === "approved").length,
    rejected: requests.filter(r => r.status === "rejected").length,
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold tracking-tight">Access Requests</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Review and action incoming requests to join the platform.
        </p>
      </div>

      {/* Filter tabs */}
      <div className="flex items-center gap-1 bg-card border border-border rounded-lg p-1 w-fit">
        {(["all", "pending", "approved", "rejected"] as const).map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={cn(
              "px-3 py-1.5 text-xs font-medium rounded-md transition-colors capitalize",
              statusFilter === s
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            {s} {counts[s] > 0 && <span className="ml-1 opacity-70">({counts[s]})</span>}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-12 text-center">
          <Clock className="w-10 h-10 text-muted-foreground/30 mx-auto mb-3" />
          <p className="text-muted-foreground text-sm">No {statusFilter !== "all" ? statusFilter : ""} requests yet.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map(req => {
            const isExpanded = expandedId === req.id;
            const notes = reviewNotes[req.id] ?? req.reviewNotes ?? "";
            return (
              <div key={req.id} className="bg-card border border-border rounded-xl overflow-hidden">
                {/* Header row */}
                <div
                  className="flex items-center gap-4 px-4 py-3.5 cursor-pointer hover:bg-accent/20 transition-colors select-none"
                  onClick={() => setExpandedId(isExpanded ? null : req.id)}
                >
                  <div className="w-9 h-9 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 text-sm font-semibold text-primary">
                    {req.fullName.charAt(0).toUpperCase()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm">{req.fullName}</span>
                      {req.jobTitle && <span className="text-xs text-muted-foreground">· {req.jobTitle}</span>}
                    </div>
                    <div className="flex items-center gap-3 mt-0.5 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1"><Building2 className="w-3 h-3" />{req.companyName}</span>
                      <span className="flex items-center gap-1"><Mail className="w-3 h-3" />{req.email}</span>
                      {req.teamSize && <span className="flex items-center gap-1"><Users className="w-3 h-3" />{req.teamSize}</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 shrink-0">
                    <StatusBadge status={req.status} />
                    <span className="text-xs text-muted-foreground hidden sm:block">{formatDate(req.createdAt)}</span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                  </div>
                </div>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="border-t border-border px-4 py-4 space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                      {req.phone && (
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <Phone className="w-3.5 h-3.5 shrink-0" />
                          <span>{req.phone}</span>
                        </div>
                      )}
                      {req.teamSize && (
                        <div className="flex items-center gap-2 text-muted-foreground">
                          <Users className="w-3.5 h-3.5 shrink-0" />
                          <span>{req.teamSize} employees</span>
                        </div>
                      )}
                    </div>

                    {req.message && (
                      <div className="rounded-lg border border-border bg-accent/20 p-3 text-sm text-muted-foreground">
                        <div className="flex items-center gap-1.5 mb-1.5 text-foreground text-xs font-medium">
                          <MessageSquare className="w-3.5 h-3.5" /> Their message
                        </div>
                        <p className="leading-relaxed whitespace-pre-wrap">{req.message}</p>
                      </div>
                    )}

                    <div className="space-y-2">
                      <label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Review notes</label>
                      <Textarea
                        value={notes}
                        onChange={e => setReviewNotes(p => ({ ...p, [req.id]: e.target.value }))}
                        placeholder="Add internal notes about this request…"
                        rows={2}
                        className="resize-none text-sm"
                      />
                    </div>

                    {req.status === "pending" && (
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          className="bg-green-600 hover:bg-green-700 text-white"
                          disabled={reviewMutation.isPending}
                          onClick={() => reviewMutation.mutate({ id: req.id, status: "approved", notes })}
                        >
                          {reviewMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <CheckCircle2 className="w-3.5 h-3.5 mr-1.5" />}
                          Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={reviewMutation.isPending}
                          onClick={() => reviewMutation.mutate({ id: req.id, status: "rejected", notes })}
                        >
                          {reviewMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <XCircle className="w-3.5 h-3.5 mr-1.5" />}
                          Reject
                        </Button>
                      </div>
                    )}
                    {req.status !== "pending" && (
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={reviewMutation.isPending}
                          onClick={() => reviewMutation.mutate({ id: req.id, status: "pending", notes })}
                        >
                          Reset to Pending
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={reviewMutation.isPending}
                          onClick={() => reviewMutation.mutate({ id: req.id, status: req.status, notes })}
                        >
                          Save Notes
                        </Button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
