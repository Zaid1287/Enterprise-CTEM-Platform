import { useRoute, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import { useToast } from "@/hooks/use-toast";
import {
  ArrowLeft, Zap, Loader2, CheckCircle2, XCircle, AlertTriangle,
  Info, ShieldOff, Globe, Lock, Key, Server, Eye
} from "lucide-react";

interface AttackResult {
  testName: string;
  severity: "critical" | "high" | "medium" | "info";
  passed: boolean;
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response: { status: number; headers: Record<string, string>; body: string };
  remediationGuidance: string;
}

interface AttackRun {
  id: number;
  status: string;
  progress: number;
  results: AttackResult[];
  startedAt?: string;
  completedAt?: string;
}

interface AiEndpoint {
  id: number; ip: string; port: number; hostname?: string; url: string;
  protocol: string; framework?: string; authStatus: string;
  riskScore: number; riskLevel: string; country?: string; org?: string; city?: string;
  models?: string[]; tools?: { name: string; description?: string }[];
  systemPromptLeaked: boolean; systemPromptContent?: string;
  corsPolicy?: string; hasTls: boolean; signupEnabled: boolean;
  firstSeenAt: string; lastSeenAt?: string;
}

const SEV_ICON: Record<string, React.ElementType> = {
  critical: AlertTriangle, high: ShieldOff, medium: Info, info: Info,
};
const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", info: "text-slate-400",
};
const SEV_BG: Record<string, string> = {
  critical: "bg-red-500/10 border-red-500/30", high: "bg-orange-500/10 border-orange-500/30",
  medium: "bg-yellow-500/10 border-yellow-500/30", info: "bg-slate-500/10 border-slate-500/30",
};

export default function AiMapperEndpointDetailPage() {
  const [, params] = useRoute("/ai-mapper/endpoints/:id");
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const epId = Number(params?.id);

  const [attackRunId, setAttackRunId] = useState<number | null>(null);
  const [selectedResult, setSelectedResult] = useState<AttackResult | null>(null);

  const { data: ep, isLoading } = useQuery<AiEndpoint>({
    queryKey: ["ai-mapper-endpoint", epId],
    queryFn: () => apiFetch(`/api/ai-mapper/endpoints/${epId}`),
  });

  const { data: attackRun } = useQuery<AttackRun>({
    queryKey: ["ai-mapper-attack", attackRunId],
    queryFn: () => apiFetch(`/api/ai-mapper/attacks/${attackRunId}`),
    enabled: attackRunId != null,
    refetchInterval: (query) => {
      const d = query.state.data as AttackRun | undefined;
      if (!d || d.status === "running") return 2000;
      return false;
    },
  });

  const launchAttack = useMutation({
    mutationFn: () => apiFetch(`/api/ai-mapper/endpoints/${epId}/attack`, { method: "POST" }),
    onSuccess: (data: any) => {
      setAttackRunId(data.attackRunId);
      toast({ title: "Attack suite started" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  if (isLoading || !ep) return (
    <div className="flex items-center justify-center h-64">
      <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
    </div>
  );

  const results = attackRun?.results ?? [];
  const passed  = results.filter(r => r.passed).length;
  const failed  = results.filter(r => !r.passed).length;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => navigate(-1 as any)}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div className="flex-1">
          <h1 className="text-xl font-bold font-mono">{ep.ip}:{ep.port}</h1>
          <p className="text-sm text-muted-foreground">{ep.hostname ?? ep.url}</p>
        </div>
        <Button
          onClick={() => launchAttack.mutate()}
          disabled={launchAttack.isPending || attackRun?.status === "running"}
          variant="destructive"
          size="sm"
        >
          {launchAttack.isPending || attackRun?.status === "running"
            ? <Loader2 className="w-4 h-4 animate-spin mr-2" />
            : <Zap className="w-4 h-4 mr-2" />
          }
          {attackRun ? "Running…" : "Launch Attack Suite"}
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left: risk + info */}
        <div className="space-y-4">
          <Card>
            <CardContent className="py-5 flex flex-col items-center gap-3">
              <RiskScoreGauge score={ep.riskScore} size="lg" />
              <div className="grid grid-cols-2 gap-2 w-full text-xs">
                <div className="bg-muted/40 rounded p-2">
                  <p className="text-muted-foreground">Auth</p>
                  <p className={`font-semibold ${ep.authStatus === "none" ? "text-red-400" : "text-green-400"}`}>
                    {ep.authStatus}
                  </p>
                </div>
                <div className="bg-muted/40 rounded p-2">
                  <p className="text-muted-foreground">CORS</p>
                  <p className={`font-semibold ${ep.corsPolicy === "open" ? "text-orange-400" : "text-green-400"}`}>
                    {ep.corsPolicy ?? "unknown"}
                  </p>
                </div>
                <div className="bg-muted/40 rounded p-2">
                  <p className="text-muted-foreground">TLS</p>
                  <p className={`font-semibold ${ep.hasTls ? "text-green-400" : "text-red-400"}`}>
                    {ep.hasTls ? "Yes" : "No"}
                  </p>
                </div>
                <div className="bg-muted/40 rounded p-2">
                  <p className="text-muted-foreground">Signup</p>
                  <p className={`font-semibold ${ep.signupEnabled ? "text-orange-400" : "text-slate-400"}`}>
                    {ep.signupEnabled ? "Open" : "Disabled"}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm">Infrastructure</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              {[
                { label: "Protocol",  value: ep.protocol },
                { label: "Framework", value: ep.framework ?? "—" },
                { label: "Country",   value: ep.country ?? "—" },
                { label: "City",      value: ep.city ?? "—" },
                { label: "Org",       value: ep.org ?? "—" },
                { label: "First Seen", value: new Date(ep.firstSeenAt).toLocaleDateString() },
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between gap-2">
                  <span className="text-muted-foreground shrink-0">{label}</span>
                  <span className="font-medium text-right truncate max-w-40">{value}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: models, tools, prompt, attack */}
        <div className="col-span-2 space-y-4">
          {/* Models */}
          {(ep.models?.length ?? 0) > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Exposed Models ({ep.models!.length})</CardTitle></CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-1.5">
                  {ep.models!.map(m => (
                    <Badge key={m} variant="outline" className="font-mono text-xs">{m}</Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* MCP Tools */}
          {(ep.tools?.length ?? 0) > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">MCP Tools ({ep.tools!.length})</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1.5">
                  {ep.tools!.map(t => (
                    <div key={t.name} className="flex items-start gap-2 text-sm">
                      <Key className="w-3.5 h-3.5 mt-0.5 text-purple-400 shrink-0" />
                      <div>
                        <span className="font-mono font-medium">{t.name}</span>
                        {t.description && <p className="text-xs text-muted-foreground">{t.description}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* System prompt leak */}
          {ep.systemPromptLeaked && (
            <Card className="border-red-500/40">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-red-400 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" /> System Prompt Leaked
                </CardTitle>
              </CardHeader>
              <CardContent>
                {ep.systemPromptContent
                  ? <pre className="text-xs font-mono bg-muted/50 rounded p-3 max-h-40 overflow-auto whitespace-pre-wrap">{ep.systemPromptContent}</pre>
                  : <p className="text-sm text-muted-foreground">System prompt was confirmed exposed but content was not captured.</p>
                }
              </CardContent>
            </Card>
          )}

          {/* Attack results */}
          {(attackRun || launchAttack.isPending) && (
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">Attack Suite Results</CardTitle>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {attackRun?.status === "running" && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                    {results.length > 0 && <><span className="text-green-400">{passed} passed</span> · <span className="text-red-400">{failed} failed</span></>}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {results.length === 0 && attackRun?.status === "running" && (
                  <p className="text-sm text-muted-foreground animate-pulse">Running tests…</p>
                )}
                {results.map((r, i) => {
                  const Icon = SEV_ICON[r.severity] ?? Info;
                  return (
                    <div key={i} className={`rounded-lg border p-3 ${SEV_BG[r.severity]}`}>
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className={`w-4 h-4 shrink-0 ${SEV_COLOR[r.severity]}`} />
                        <span className="font-medium text-sm flex-1">{r.testName}</span>
                        {r.passed
                          ? <CheckCircle2 className="w-4 h-4 text-green-400" />
                          : <XCircle className="w-4 h-4 text-red-400" />
                        }
                      </div>
                      <p className="text-xs text-muted-foreground pl-6 mb-1.5">{r.remediationGuidance}</p>
                      <button
                        className="text-xs text-primary/70 hover:text-primary pl-6 flex items-center gap-1"
                        onClick={() => setSelectedResult(selectedResult?.testName === r.testName ? null : r)}
                      >
                        <Eye className="w-3 h-3" />
                        {selectedResult?.testName === r.testName ? "Hide" : "Show"} request/response
                      </button>
                      {selectedResult?.testName === r.testName && (
                        <div className="mt-2 ml-6 space-y-2">
                          <div>
                            <p className="text-xs font-semibold text-muted-foreground mb-1">Request</p>
                            <pre className="text-xs font-mono bg-black/30 rounded p-2 overflow-x-auto max-h-28 whitespace-pre-wrap">
                              {`${r.request.method} ${r.request.url}\n${r.request.body ?? ""}`}
                            </pre>
                          </div>
                          <div>
                            <p className="text-xs font-semibold text-muted-foreground mb-1">Response ({r.response.status})</p>
                            <pre className="text-xs font-mono bg-black/30 rounded p-2 overflow-x-auto max-h-32 whitespace-pre-wrap">
                              {r.response.body.slice(0, 1000)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {!attackRun && !launchAttack.isPending && (
            <Card className="border-dashed">
              <CardContent className="py-10 text-center">
                <Zap className="w-8 h-8 mx-auto mb-3 text-muted-foreground opacity-40" />
                <p className="font-medium text-sm">No attack runs yet</p>
                <p className="text-xs text-muted-foreground mt-1">Launch the attack suite to test this endpoint for MCP, Ollama, and OpenAI-compat vulnerabilities</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
