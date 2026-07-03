import { useState, useEffect } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useListFindings, useListComplianceControls,
  useExplainFinding, useGetRemediation, useGenerateExecutiveSummary, useGetComplianceGuidance,
  getListFindingsQueryKey, getListComplianceControlsQueryKey,
} from "@workspace/api-client-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Brain, Zap, FileText, ShieldCheck, AlertTriangle, Sparkles, Clock, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

/* ─── AI Status banner ───────────────────────────────────────────────────── */
interface AiStatusData { llmEnabled: boolean; model: string; }

/* ─── Markdown renderer ─────────────────────────────────────────────────── */
function AiMarkdown({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        h2: ({ children }) => <h2 className="text-base font-bold mt-4 mb-2 text-foreground">{children}</h2>,
        h3: ({ children }) => <h3 className="text-sm font-semibold mt-3 mb-1.5 text-foreground/90">{children}</h3>,
        p: ({ children }) => <p className="text-sm text-muted-foreground mb-2 leading-relaxed">{children}</p>,
        ul: ({ children }) => <ul className="list-disc pl-5 space-y-1 mb-2">{children}</ul>,
        ol: ({ children }) => <ol className="list-decimal pl-5 space-y-1 mb-2">{children}</ol>,
        li: ({ children }) => <li className="text-sm text-muted-foreground">{children}</li>,
        strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
        code: ({ children }) => <code className="font-mono text-xs bg-muted/60 px-1 py-0.5 rounded text-primary">{children}</code>,
        blockquote: ({ children }) => <blockquote className="border-l-2 border-primary/40 pl-3 my-2 text-muted-foreground italic">{children}</blockquote>,
        table: ({ children }) => <div className="overflow-x-auto my-3"><table className="text-xs w-full border-collapse">{children}</table></div>,
        thead: ({ children }) => <thead className="bg-muted/40">{children}</thead>,
        th: ({ children }) => <th className="px-3 py-1.5 text-left font-semibold text-foreground border border-border/40">{children}</th>,
        td: ({ children }) => <td className="px-3 py-1.5 text-muted-foreground border border-border/40">{children}</td>,
        a: ({ href, children }) => <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 hover:text-primary/80">{children}</a>,
        hr: () => <hr className="border-border/40 my-3" />,
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

function AiResult({ content, isLoading }: { content: string | null; isLoading: boolean }) {
  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(6)].map((_, i) => (
          <Skeleton key={i} className="h-4" style={{ width: `${70 + (i % 3) * 10}%` }} />
        ))}
        <p className="text-xs text-muted-foreground mt-3 flex items-center gap-1.5">
          <Sparkles className="w-3 h-3 animate-pulse" /> AI is analysing…
        </p>
      </div>
    );
  }
  if (!content) {
    return <p className="text-sm text-muted-foreground">Select options above and click generate.</p>;
  }
  return <AiMarkdown content={content} />;
}

/* ─── Severity badge ─────────────────────────────────────────────────────── */
function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "border-red-500/40 text-red-400",
    high:     "border-orange-500/40 text-orange-400",
    medium:   "border-yellow-500/40 text-yellow-400",
    low:      "border-blue-500/40 text-blue-400",
    info:     "border-muted text-muted-foreground",
  };
  return (
    <Badge variant="outline" className={cn("text-[9px] capitalize shrink-0", colors[severity] ?? "border-muted text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════ */
export default function AiCopilotPage() {
  const [selectedFinding, setSelectedFinding] = useState<string>("");
  const [selectedControl, setSelectedControl] = useState<string>("");
  const [explanation, setExplanation] = useState<string | null>(null);
  const [remediation, setRemediation] = useState<any | null>(null);
  const [execSummary, setExecSummary] = useState<string | null>(null);
  const [compliance, setCompliance] = useState<string | null>(null);
  const [generatedAt, setGeneratedAt] = useState<Record<string, string>>({});

  const { data: findings } = useListFindings({} as any, {
    query: { queryKey: getListFindingsQueryKey({} as any) },
  });
  const { data: controls } = useListComplianceControls({} as any, {
    query: { queryKey: getListComplianceControlsQueryKey({} as any) },
  });

  const explainMutation     = useExplainFinding();
  const remediationMutation = useGetRemediation();
  const execSummaryMutation = useGenerateExecutiveSummary();
  const complianceMutation  = useGetComplianceGuidance();

  const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
  const [aiStatus, setAiStatus] = useState<AiStatusData | null>(null);

  useEffect(() => {
    fetch(`${BASE}/api/ai/status`, {
      headers: { Authorization: `Bearer ${sessionStorage.getItem("ctem_token") ?? ""}` },
    })
      .then(r => r.json())
      .then((d: AiStatusData) => setAiStatus(d))
      .catch(() => setAiStatus({ llmEnabled: false, model: "" }));
  }, [BASE]);

  const handleExplain = async () => {
    if (!selectedFinding) return;
    setExplanation(null);
    const res = await explainMutation.mutateAsync({ data: { findingId: parseInt(selectedFinding) } } as any);
    setExplanation((res as any).content);
    setGeneratedAt(p => ({ ...p, explain: (res as any).generatedAt ?? new Date().toISOString() }));
  };

  const handleRemediation = async () => {
    if (!selectedFinding) return;
    setRemediation(null);
    const res = await remediationMutation.mutateAsync({ data: { findingId: parseInt(selectedFinding) } } as any);
    setRemediation(res);
    setGeneratedAt(p => ({ ...p, remediation: new Date().toISOString() }));
  };

  const handleExecSummary = async () => {
    setExecSummary(null);
    const res = await execSummaryMutation.mutateAsync({ data: {} } as any);
    setExecSummary((res as any).content);
    setGeneratedAt(p => ({ ...p, executive: (res as any).generatedAt ?? new Date().toISOString() }));
  };

  const handleComplianceGuidance = async () => {
    if (!selectedControl) return;
    setCompliance(null);
    const res = await complianceMutation.mutateAsync({ data: { controlId: parseInt(selectedControl) } } as any);
    setCompliance((res as any).content);
    setGeneratedAt(p => ({ ...p, compliance: (res as any).generatedAt ?? new Date().toISOString() }));
  };

  const selectedFindingObj = (findings as any[] ?? []).find((f: any) => String(f.id) === selectedFinding);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            AI Security Copilot
          </h1>
          <p className="text-sm text-muted-foreground">AI-powered vulnerability analysis, remediation, and compliance guidance</p>
        </div>
        {aiStatus && (
          <div className={cn(
            "flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-full border font-medium",
            aiStatus.llmEnabled
              ? "border-green-500/30 bg-green-500/10 text-green-400"
              : "border-amber-500/30 bg-amber-500/10 text-amber-400",
          )}>
            <span className={cn("w-1.5 h-1.5 rounded-full", aiStatus.llmEnabled ? "bg-green-400 animate-pulse" : "bg-amber-400")} />
            {aiStatus.llmEnabled ? `GPT-4o-mini active` : "Template mode"}
          </div>
        )}
      </div>

      {/* LLM not configured warning — only when OPENAI_API_KEY is missing */}
      {aiStatus !== null && !aiStatus.llmEnabled && (
        <div className="flex items-start gap-3 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30">
          <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
          <div className="space-y-1">
            <p className="text-sm font-medium text-amber-300">AI Copilot running in template mode</p>
            <p className="text-xs text-amber-400/80 leading-relaxed">
              No <code className="font-mono bg-amber-500/10 px-1 rounded">OPENAI_API_KEY</code> is configured.
              All 4 functions still work using structured templates — they just won't have LLM-generated insight.
            </p>
            <p className="text-xs text-amber-400/60 mt-1">
              To enable AI: Go to <strong>Settings → Platform Settings → API Keys</strong> and add your OpenAI key,
              or add <code className="font-mono">OPENAI_API_KEY</code> to Replit Secrets.
            </p>
          </div>
        </div>
      )}

      <Tabs defaultValue="explain">
        <TabsList className="h-9">
          <TabsTrigger value="explain"     className="text-xs gap-1.5"><Zap className="w-3.5 h-3.5" /> Finding Analysis</TabsTrigger>
          <TabsTrigger value="remediation" className="text-xs gap-1.5"><Brain className="w-3.5 h-3.5" /> Remediation Plan</TabsTrigger>
          <TabsTrigger value="executive"   className="text-xs gap-1.5"><FileText className="w-3.5 h-3.5" /> Executive Summary</TabsTrigger>
          <TabsTrigger value="compliance"  className="text-xs gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Compliance Guidance</TabsTrigger>
        </TabsList>

        {/* ── Tab 1: Finding Analysis ─────────────────────────────────────── */}
        <TabsContent value="explain" className="mt-4 space-y-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div>
              <p className="text-sm font-medium">Explain a vulnerability finding</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Get a detailed analysis of what a finding means, its technical nature, and business impact.
              </p>
            </div>

            {/* Finding selector */}
            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={setSelectedFinding}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a finding to analyse…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {(findings as any[] ?? [])
                    .sort((a: any, b: any) => {
                      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
                    })
                    .map((f: any) => (
                      <SelectItem key={f.id} value={String(f.id)}>
                        <span className={cn("text-xs font-mono mr-1.5",
                          f.severity === "critical" ? "text-red-400" :
                          f.severity === "high"     ? "text-orange-400" :
                          f.severity === "medium"   ? "text-yellow-400" : "text-muted-foreground"
                        )}>[{f.severity.toUpperCase()}]</span>
                        {f.title.slice(0, 65)}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleExplain} disabled={!selectedFinding || explainMutation.isPending}
                className="shrink-0">
                {explainMutation.isPending ? "Analysing…" : "Explain"}
              </Button>
            </div>

            {/* Selected finding context pill */}
            {selectedFindingObj && (
              <div className="flex items-center gap-2 text-xs text-muted-foreground bg-muted/30 rounded-lg px-3 py-2">
                <SeverityBadge severity={selectedFindingObj.severity} />
                <span className="truncate">{selectedFindingObj.title}</span>
                {selectedFindingObj.cve && (
                  <span className="font-mono text-blue-400 shrink-0">{selectedFindingObj.cve}</span>
                )}
                {selectedFindingObj.isKev && (
                  <Badge variant="outline" className="text-[9px] border-red-500/40 text-red-400 shrink-0">KEV</Badge>
                )}
              </div>
            )}

            {/* Output */}
            <div className="bg-accent/20 border border-border/40 rounded-xl p-4 min-h-40">
              <AiResult content={explanation} isLoading={explainMutation.isPending} />
              {explanation && generatedAt.explain && (
                <p className="text-[10px] text-muted-foreground/50 mt-3 flex items-center gap-1">
                  <Clock className="w-2.5 h-2.5" />
                  Generated {new Date(generatedAt.explain).toLocaleTimeString()}
                  {" · "}model: {aiStatus?.llmEnabled ? "gpt-4o-mini" : "template"}
                </p>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── Tab 2: Remediation Plan ─────────────────────────────────────── */}
        <TabsContent value="remediation" className="mt-4 space-y-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div>
              <p className="text-sm font-medium">Generate a step-by-step remediation plan</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Get prioritised, actionable steps to fix the vulnerability with time estimates and references.
              </p>
            </div>

            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={setSelectedFinding}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a finding…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {(findings as any[] ?? [])
                    .sort((a: any, b: any) => {
                      const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                      return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
                    })
                    .map((f: any) => (
                      <SelectItem key={f.id} value={String(f.id)}>
                        <span className={cn("text-xs font-mono mr-1.5",
                          f.severity === "critical" ? "text-red-400" :
                          f.severity === "high"     ? "text-orange-400" : "text-muted-foreground"
                        )}>[{f.severity.toUpperCase()}]</span>
                        {f.title.slice(0, 65)}
                      </SelectItem>
                    ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleRemediation} disabled={!selectedFinding || remediationMutation.isPending}
                className="shrink-0">
                {remediationMutation.isPending ? "Generating…" : "Generate Plan"}
              </Button>
            </div>

            <div className="bg-accent/20 border border-border/40 rounded-xl p-4 min-h-40">
              {remediationMutation.isPending ? (
                <div className="space-y-2">
                  {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-4" style={{ width: `${60 + (i % 3) * 15}%` }} />)}
                  <p className="text-xs text-muted-foreground mt-2 flex items-center gap-1.5">
                    <Sparkles className="w-3 h-3 animate-pulse" /> Generating remediation plan…
                  </p>
                </div>
              ) : remediation ? (
                <div className="space-y-4">
                  {/* Priority + effort */}
                  <div className="flex flex-wrap gap-3">
                    <div className="bg-muted/40 rounded-lg px-3 py-2 text-xs">
                      <p className="text-muted-foreground">Priority</p>
                      <p className="font-semibold text-foreground mt-0.5">{remediation.priority}</p>
                    </div>
                    <div className="bg-muted/40 rounded-lg px-3 py-2 text-xs">
                      <p className="text-muted-foreground">Estimated Effort</p>
                      <p className="font-semibold text-foreground mt-0.5">{remediation.estimatedEffort}</p>
                    </div>
                  </div>

                  {/* Steps */}
                  <ol className="space-y-2.5">
                    {remediation.steps?.map((step: string, i: number) => (
                      <li key={i} className="flex gap-3 text-sm">
                        <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/15 text-primary flex items-center justify-center text-xs font-bold">
                          {i + 1}
                        </span>
                        <span className="text-muted-foreground leading-relaxed pt-0.5">{step}</span>
                      </li>
                    ))}
                  </ol>

                  {/* References */}
                  {remediation.references?.filter(Boolean).length > 0 && (
                    <div className="border-t border-border/40 pt-3">
                      <p className="text-xs font-medium text-muted-foreground mb-1.5">References</p>
                      <ul className="space-y-1">
                        {remediation.references.filter(Boolean).map((ref: string, i: number) => (
                          <li key={i} className="flex items-center gap-1.5">
                            <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" />
                            <a href={ref} target="_blank" rel="noopener noreferrer"
                              className="text-xs text-primary hover:underline truncate">
                              {ref}
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">Select a finding and click Generate Plan.</p>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── Tab 3: Executive Summary ────────────────────────────────────── */}
        <TabsContent value="executive" className="mt-4 space-y-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-sm font-medium">AI-generated executive security briefing</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  CISO-level summary of your organisation's current security posture across all findings.
                  No selection needed — it reads your entire finding database.
                </p>
              </div>
              <Button size="sm" onClick={handleExecSummary} disabled={execSummaryMutation.isPending} className="shrink-0">
                {execSummaryMutation.isPending ? "Generating…" : "Generate Summary"}
              </Button>
            </div>
            <div className="bg-accent/20 border border-border/40 rounded-xl p-4 min-h-48">
              <AiResult content={execSummary} isLoading={execSummaryMutation.isPending} />
              {execSummary && generatedAt.executive && (
                <p className="text-[10px] text-muted-foreground/50 mt-3 flex items-center gap-1">
                  <Clock className="w-2.5 h-2.5" />
                  Generated {new Date(generatedAt.executive).toLocaleString()}
                </p>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── Tab 4: Compliance Guidance ──────────────────────────────────── */}
        <TabsContent value="compliance" className="mt-4 space-y-3">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div>
              <p className="text-sm font-medium">Get AI guidance for a compliance control</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                Implementation steps, evidence requirements, and common pitfalls for any framework control.
              </p>
            </div>

            <div className="flex gap-2">
              <Select value={selectedControl} onValueChange={setSelectedControl}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a compliance control…" />
                </SelectTrigger>
                <SelectContent className="max-h-72">
                  {(controls as any[] ?? []).map((c: any) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      <span className="text-xs font-mono text-muted-foreground mr-1.5">{c.frameworkName}</span>
                      {c.controlId}: {c.title.slice(0, 50)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleComplianceGuidance} disabled={!selectedControl || complianceMutation.isPending}
                className="shrink-0">
                {complianceMutation.isPending ? "Analysing…" : "Get Guidance"}
              </Button>
            </div>

            <div className="bg-accent/20 border border-border/40 rounded-xl p-4 min-h-40">
              <AiResult content={compliance} isLoading={complianceMutation.isPending} />
              {compliance && generatedAt.compliance && (
                <p className="text-[10px] text-muted-foreground/50 mt-3 flex items-center gap-1">
                  <Clock className="w-2.5 h-2.5" />
                  Generated {new Date(generatedAt.compliance).toLocaleTimeString()}
                </p>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
