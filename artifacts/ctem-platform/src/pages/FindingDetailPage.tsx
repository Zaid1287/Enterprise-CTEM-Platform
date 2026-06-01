import { useState } from "react";
import { useParams, useLocation } from "wouter";
import {
  useGetFinding, useUpdateFinding, useListFindingComments, useCreateFindingComment,
  useExplainFinding, useGetRemediation,
  getGetFindingQueryKey, getListFindingCommentsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, MessageSquare, Brain, Wrench, Send } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";

const STATUSES = ["open", "in_progress", "accepted_risk", "false_positive", "mitigated"];

export default function FindingDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const queryClient = useQueryClient();

  const [comment, setComment] = useState("");
  const [aiContent, setAiContent] = useState<string | null>(null);
  const [aiType, setAiType] = useState<"explanation" | "remediation" | null>(null);
  const [remSteps, setRemSteps] = useState<any | null>(null);

  const { data: finding, isLoading } = useGetFinding(id, {
    query: { enabled: !!id, queryKey: getGetFindingQueryKey(id) },
  });
  const { data: comments } = useListFindingComments(id, {
    query: { enabled: !!id, queryKey: getListFindingCommentsQueryKey(id) },
  });
  const updateFinding = useUpdateFinding();
  const addComment = useCreateFindingComment();
  const explainMutation = useExplainFinding();
  const remediationMutation = useGetRemediation();

  const f = finding as any;

  const handleStatusChange = async (status: string) => {
    await updateFinding.mutateAsync({ findingId: id, data: { status } });
    queryClient.invalidateQueries({ queryKey: getGetFindingQueryKey(id) });
  };

  const handleComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!comment.trim()) return;
    await addComment.mutateAsync({ findingId: id, data: { content: comment } });
    queryClient.invalidateQueries({ queryKey: getListFindingCommentsQueryKey(id) });
    setComment("");
  };

  const handleExplain = async () => {
    setAiType("explanation");
    setAiContent(null);
    const res = await explainMutation.mutateAsync({ findingId: id } as any);
    setAiContent((res as any).content);
  };

  const handleRemediation = async () => {
    setAiType("remediation");
    setRemSteps(null);
    const res = await remediationMutation.mutateAsync({ findingId: id } as any);
    setRemSteps(res as any);
  };

  if (isLoading) return <div className="space-y-4">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}</div>;
  if (!f) return <div className="text-muted-foreground">Finding not found</div>;

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/findings")}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Findings
        </Button>
      </div>

      {/* Header */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              {f.isKev && <span className="text-xs bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-bold">KEV</span>}
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", severityBgColor(f.severity))}>{f.severity}</span>
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(f.status))}>{capitalize(f.status)}</span>
            </div>
            <h1 className="text-base font-semibold">{f.title}</h1>
            <p className="text-sm text-muted-foreground mt-1">Asset: {f.assetName ?? f.assetId}</p>
          </div>
          <Select value={f.status} onValueChange={handleStatusChange}>
            <SelectTrigger className="w-36 h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map(s => <SelectItem key={s} value={s}>{capitalize(s)}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          {[
            { label: "CVE", value: f.cve ?? "N/A" },
            { label: "CVSS", value: f.cvss?.toFixed(1) ?? "—" },
            { label: "EPSS", value: f.epss != null ? `${(f.epss * 100).toFixed(1)}%` : "—" },
            { label: "CWE", value: f.cwe ?? "—" },
          ].map(m => (
            <div key={m.label} className="bg-accent/40 rounded-lg p-3 text-center">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{m.label}</p>
              <p className="text-sm font-bold font-mono mt-0.5">{m.value}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Description */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-2">Description</h3>
          <p className="text-sm text-muted-foreground leading-relaxed">{f.description ?? "No description available."}</p>
          {f.remediation && (
            <>
              <h3 className="text-sm font-medium mt-4 mb-2">Remediation</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">{f.remediation}</p>
            </>
          )}
          {f.evidence && (
            <>
              <h3 className="text-sm font-medium mt-4 mb-2">Evidence</h3>
              <pre className="text-xs font-mono text-muted-foreground bg-accent/40 p-3 rounded-lg overflow-x-auto">{f.evidence}</pre>
            </>
          )}
        </div>

        {/* AI Analysis */}
        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-3">AI Analysis</h3>
          <div className="flex gap-2 mb-3">
            <Button variant="outline" size="sm" onClick={handleExplain} disabled={explainMutation.isPending}>
              <Brain className="w-3.5 h-3.5 mr-1.5" />
              {explainMutation.isPending ? "Analyzing..." : "Explain"}
            </Button>
            <Button variant="outline" size="sm" onClick={handleRemediation} disabled={remediationMutation.isPending}>
              <Wrench className="w-3.5 h-3.5 mr-1.5" />
              {remediationMutation.isPending ? "Generating..." : "Remediation"}
            </Button>
          </div>

          {aiType === "explanation" && aiContent && (
            <div className="text-xs text-muted-foreground bg-accent/30 rounded-lg p-3 max-h-64 overflow-y-auto leading-relaxed whitespace-pre-wrap">
              {aiContent}
            </div>
          )}
          {aiType === "remediation" && remSteps && (
            <div className="space-y-2">
              <div className="flex gap-3 text-xs">
                <span className="text-muted-foreground">Priority:</span>
                <span className="font-medium">{remSteps.priority}</span>
              </div>
              <div className="flex gap-3 text-xs">
                <span className="text-muted-foreground">Effort:</span>
                <span className="font-medium">{remSteps.estimatedEffort}</span>
              </div>
              <ol className="space-y-1.5 mt-2">
                {remSteps.steps?.map((step: string, i: number) => (
                  <li key={i} className="flex gap-2 text-xs text-muted-foreground">
                    <span className="text-primary font-bold shrink-0">{i + 1}.</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {!aiContent && !remSteps && (
            <p className="text-xs text-muted-foreground">Click Explain or Remediation to get AI-powered analysis.</p>
          )}
        </div>
      </div>

      {/* Comments */}
      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-sm font-medium mb-3 flex items-center gap-2">
          <MessageSquare className="w-4 h-4" /> Comments ({(comments as any[])?.length ?? 0})
        </h3>
        <div className="space-y-3 mb-4 max-h-48 overflow-y-auto">
          {(comments as any[] ?? []).map((c: any) => (
            <div key={c.id} className="bg-accent/30 rounded-lg p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-medium">{c.authorName}</span>
                <span className="text-[10px] text-muted-foreground">{formatDateTime(c.createdAt)}</span>
              </div>
              <p className="text-xs text-muted-foreground">{c.content}</p>
            </div>
          ))}
          {(comments as any[] ?? []).length === 0 && (
            <p className="text-xs text-muted-foreground">No comments yet.</p>
          )}
        </div>
        <form onSubmit={handleComment} className="flex gap-2">
          <Textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Add a comment..."
            className="text-sm resize-none h-16"
          />
          <Button type="submit" size="icon" disabled={addComment.isPending || !comment.trim()}>
            <Send className="w-4 h-4" />
          </Button>
        </form>
      </div>
    </div>
  );
}
