import { useState, useEffect } from "react";
import {
  useListFindings, useListComplianceControls,
  useExplainFinding, useGetRemediation, useGenerateExecutiveSummary, useGetComplianceGuidance,
  getListFindingsQueryKey, getListComplianceControlsQueryKey,
} from "@workspace/api-client-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Brain, Zap, FileText, ShieldCheck, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

function AiResult({ content, isLoading }: { content: string | null; isLoading: boolean }) {
  if (isLoading) return <div className="space-y-2">{[...Array(6)].map((_, i) => <Skeleton key={i} className="h-4" />)}</div>;
  if (!content) return <p className="text-sm text-muted-foreground">Select options above and click generate.</p>;
  return (
    <div className="prose prose-invert prose-sm max-w-none">
      <pre className="whitespace-pre-wrap text-sm text-foreground font-sans leading-relaxed">{content}</pre>
    </div>
  );
}

export default function AiCopilotPage() {
  const [selectedFinding, setSelectedFinding] = useState<string>("");
  const [selectedControl, setSelectedControl] = useState<string>("");
  const [explanation, setExplanation] = useState<string | null>(null);
  const [remediation, setRemediation] = useState<any | null>(null);
  const [execSummary, setExecSummary] = useState<string | null>(null);
  const [compliance, setCompliance] = useState<string | null>(null);

  const { data: findings } = useListFindings({} as any, {
    query: { queryKey: getListFindingsQueryKey({} as any) },
  });
  const { data: controls } = useListComplianceControls({} as any, {
    query: { queryKey: getListComplianceControlsQueryKey({} as any) },
  });

  const explainMutation = useExplainFinding();
  const remediationMutation = useGetRemediation();
  const execSummaryMutation = useGenerateExecutiveSummary();
  const complianceMutation = useGetComplianceGuidance();

  const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
  const [aiStatus, setAiStatus] = useState<{ available: boolean; model: string; provider: string } | null>(null);

  useEffect(() => {
    fetch(`${BASE}/api/ai/status`)
      .then(r => r.json())
      .then(d => setAiStatus(d))
      .catch(() => setAiStatus({ available: false, model: "", provider: "" }));
  }, [BASE]);

  const handleExplain = async () => {
    if (!selectedFinding) return;
    setExplanation(null);
    const res = await explainMutation.mutateAsync({ data: { findingId: parseInt(selectedFinding) } } as any);
    setExplanation((res as any).content);
  };

  const handleRemediation = async () => {
    if (!selectedFinding) return;
    setRemediation(null);
    const res = await remediationMutation.mutateAsync({ data: { findingId: parseInt(selectedFinding) } } as any);
    setRemediation(res);
  };

  const handleExecSummary = async () => {
    setExecSummary(null);
    const res = await execSummaryMutation.mutateAsync({ data: {} } as any);
    setExecSummary((res as any).content);
  };

  const handleComplianceGuidance = async () => {
    if (!selectedControl) return;
    setCompliance(null);
    const res = await complianceMutation.mutateAsync({ data: { controlId: parseInt(selectedControl) } } as any);
    setCompliance((res as any).content);
  };

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2">
          <Brain className="w-5 h-5 text-primary" />
          AI Security Copilot
        </h1>
        <p className="text-sm text-muted-foreground">AI-powered security analysis and guidance</p>
      </div>

      {aiStatus !== null && !aiStatus.available && (
        <div className="flex items-start gap-3 p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
          <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm font-medium text-amber-300">AI Copilot is not configured</p>
            <p className="text-xs text-amber-400/70 mt-0.5">
              Add an <code className="font-mono">OPENAI_API_KEY</code> to Platform Settings → API Keys to enable AI-powered analysis.
            </p>
          </div>
        </div>
      )}

      <Tabs defaultValue="explain">
        <TabsList className="h-9">
          <TabsTrigger value="explain" className="text-xs gap-1.5"><Zap className="w-3.5 h-3.5" /> Finding Analysis</TabsTrigger>
          <TabsTrigger value="remediation" className="text-xs gap-1.5"><Brain className="w-3.5 h-3.5" /> Remediation</TabsTrigger>
          <TabsTrigger value="executive" className="text-xs gap-1.5"><FileText className="w-3.5 h-3.5" /> Executive Summary</TabsTrigger>
          <TabsTrigger value="compliance" className="text-xs gap-1.5"><ShieldCheck className="w-3.5 h-3.5" /> Compliance Guidance</TabsTrigger>
        </TabsList>

        <TabsContent value="explain" className="mt-4 space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-sm font-medium">Get AI explanation of a vulnerability finding</p>
            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={setSelectedFinding}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a finding..." />
                </SelectTrigger>
                <SelectContent>
                  {(findings as any[] ?? []).map((f: any) => (
                    <SelectItem key={f.id} value={String(f.id)}>
                      [{f.severity.toUpperCase()}] {f.title.slice(0, 60)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleExplain} disabled={!selectedFinding || explainMutation.isPending}>
                {explainMutation.isPending ? "Analyzing..." : "Explain"}
              </Button>
            </div>
            <div className="bg-accent/30 rounded-lg p-4 min-h-32">
              <AiResult content={explanation} isLoading={explainMutation.isPending} />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="remediation" className="mt-4 space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-sm font-medium">AI-generated step-by-step remediation plan</p>
            <div className="flex gap-2">
              <Select value={selectedFinding} onValueChange={setSelectedFinding}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a finding..." />
                </SelectTrigger>
                <SelectContent>
                  {(findings as any[] ?? []).map((f: any) => (
                    <SelectItem key={f.id} value={String(f.id)}>
                      [{f.severity.toUpperCase()}] {f.title.slice(0, 60)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleRemediation} disabled={!selectedFinding || remediationMutation.isPending}>
                {remediationMutation.isPending ? "Generating..." : "Generate Plan"}
              </Button>
            </div>
            <div className="bg-accent/30 rounded-lg p-4 min-h-32">
              {remediationMutation.isPending ? (
                <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-4" />)}</div>
              ) : remediation ? (
                <div className="space-y-3">
                  <div className="flex gap-6 text-sm">
                    <div><span className="text-muted-foreground">Priority: </span><span className="font-medium">{remediation.priority}</span></div>
                    <div><span className="text-muted-foreground">Effort: </span><span className="font-medium">{remediation.estimatedEffort}</span></div>
                  </div>
                  <ol className="space-y-2">
                    {remediation.steps?.map((step: string, i: number) => (
                      <li key={i} className="flex gap-2.5 text-sm text-muted-foreground">
                        <span className="text-primary font-bold shrink-0 w-5">{i + 1}.</span>
                        <span>{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground">Select a finding and click Generate Plan.</p>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="executive" className="mt-4 space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium">AI-generated executive security summary</p>
              <Button size="sm" onClick={handleExecSummary} disabled={execSummaryMutation.isPending}>
                {execSummaryMutation.isPending ? "Generating..." : "Generate Summary"}
              </Button>
            </div>
            <div className="bg-accent/30 rounded-lg p-4 min-h-48">
              <AiResult content={execSummary} isLoading={execSummaryMutation.isPending} />
            </div>
          </div>
        </TabsContent>

        <TabsContent value="compliance" className="mt-4 space-y-4">
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-sm font-medium">Get guidance for achieving compliance with a specific control</p>
            <div className="flex gap-2">
              <Select value={selectedControl} onValueChange={setSelectedControl}>
                <SelectTrigger className="flex-1 h-9 text-sm">
                  <SelectValue placeholder="Select a control..." />
                </SelectTrigger>
                <SelectContent>
                  {(controls as any[] ?? []).map((c: any) => (
                    <SelectItem key={c.id} value={String(c.id)}>
                      {c.frameworkName} — {c.controlId}: {c.title.slice(0, 50)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button size="sm" onClick={handleComplianceGuidance} disabled={!selectedControl || complianceMutation.isPending}>
                {complianceMutation.isPending ? "Analyzing..." : "Get Guidance"}
              </Button>
            </div>
            <div className="bg-accent/30 rounded-lg p-4 min-h-32">
              <AiResult content={compliance} isLoading={complianceMutation.isPending} />
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
