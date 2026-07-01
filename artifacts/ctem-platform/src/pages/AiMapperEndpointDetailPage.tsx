import { useRoute, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAiMapperWs } from "@/hooks/useAiMapperWs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import { useToast } from "@/hooks/use-toast";
import {
  ArrowLeft, Zap, Loader2, CheckCircle2, XCircle, AlertTriangle,
  Info, ShieldOff, Key, Eye,
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

interface McpTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, { type?: string; description?: string }>;
    required?: string[];
  };
}

interface AiEndpoint {
  id: number; ip: string; port: number; hostname?: string; url: string;
  protocol: string; framework?: string; authStatus: string;
  riskScore: number; riskLevel: string; country?: string; org?: string; city?: string;
  models?: string[]; tools?: McpTool[];
  systemPromptLeaked: boolean; systemPromptContent?: string;
  corsPolicy?: string; hasTls: boolean; signupEnabled: boolean;
  firstSeenAt: string; lastSeenAt?: string;
}

const TOOL_RISK_PATTERNS: Array<{ pattern: RegExp; level: "critical" | "high" | "medium" | "low"; label: string }> = [
  { pattern: /exec|shell|run_command|bash|cmd|eval/i,         level: "critical", label: "Remote Execution" },
  { pattern: /file|read_file|write_file|fs|path|directory/i,  level: "high",     label: "File System Access" },
  { pattern: /http|fetch|request|webhook|curl|url/i,          level: "high",     label: "External Network" },
  { pattern: /database|sql|query|db|mongo|redis/i,            level: "high",     label: "Database Access" },
  { pattern: /email|smtp|send_mail|message/i,                 level: "medium",   label: "Email / Messaging" },
  { pattern: /search|browse|web|scrape/i,                     level: "medium",   label: "Web Access" },
];

function classifyTool(name: string): { level: "critical" | "high" | "medium" | "low"; label: string } {
  for (const p of TOOL_RISK_PATTERNS) {
    if (p.pattern.test(name)) return { level: p.level, label: p.label };
  }
  return { level: "low", label: "Data / Compute" };
}

const TOOL_RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const UNCENSORED_PATTERNS = /uncensor|abliterat|dolphin|wizard|goat|evil|jailbreak/i;

function parseModelSize(name: string): string | null {
  const m = name.match(/(\d+(?:\.\d+)?)\s*[bBmM]/);
  if (!m) return null;
  const n = parseFloat(m[1]);
  const unit = name[m.index! + m[0].length - 1].toUpperCase();
  return unit === "B" ? `${n}B params` : `${n}M params`;
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

  const attackIsRunning = attackRun?.status === "running";
  useAiMapperWs({
    url: attackRunId != null && attackIsRunning ? `/api/ai-mapper/attacks/${attackRunId}/ws` : null,
    sseUrl: attackRunId != null && attackIsRunning ? `/api/ai-mapper/attacks/${attackRunId}/stream` : null,
    enabled: attackRunId != null && attackIsRunning,
    onMessage: (msg: any) => {
      if (msg?.type === "done") {
        qc.invalidateQueries({ queryKey: ["ai-mapper-attack", attackRunId] });
      } else if (msg?.testName) {
        qc.setQueryData<AttackRun>(["ai-mapper-attack", attackRunId], (prev) =>
          prev ? { ...prev, results: [...(prev.results ?? []), msg as AttackResult] } : prev
        );
      }
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
  const passed   = results.filter(r => r.passed).length;
  const failed   = results.filter(r => !r.passed).length;
  const critical = results.filter(r => !r.passed && r.severity === "critical").length;
  const high     = results.filter(r => !r.passed && r.severity === "high").length;
  const medium   = results.filter(r => !r.passed && r.severity === "medium").length;
  const isDone  = attackRun?.status === "completed";

  return (
    <div className="p-6 space-y-6 w-full">
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
          {attackRun?.status === "running" ? "Running…" : "Launch Attack Suite"}
        </Button>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left column: risk gauge + security tiles + infrastructure */}
        <div className="space-y-4">
          <Card>
            <CardContent className="py-5 flex flex-col items-center gap-3">
              <RiskScoreGauge
                score={ep.riskScore}
                size="lg"
                factors={[
                  { label: "Authentication",   value: ep.authStatus === "none" ? "None (−3.0)" : ep.authStatus,   highlight: ep.authStatus === "none" ? "bad" : "good" },
                  { label: "TLS/HTTPS",        value: ep.hasTls ? "Enabled" : "Missing (−1.0)",                   highlight: ep.hasTls ? "good" : "bad" },
                  { label: "CORS Policy",      value: ep.corsPolicy === "open" ? "Open (−1.5)" : (ep.corsPolicy ?? "unknown"), highlight: ep.corsPolicy === "open" ? "warn" : "neutral" },
                  { label: "Prompt Leaked",    value: ep.systemPromptLeaked ? "Yes (−1.0)" : "No",                highlight: ep.systemPromptLeaked ? "warn" : "good" },
                  { label: "Open Signup",      value: ep.signupEnabled ? "Yes (−0.5)" : "No",                     highlight: ep.signupEnabled ? "warn" : "neutral" },
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm">Infrastructure</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              {[
                { label: "Protocol",   value: ep.protocol },
                { label: "Framework",  value: ep.framework ?? "—" },
                { label: "Country",    value: ep.country ?? "—" },
                { label: "City",       value: ep.city ?? "—" },
                { label: "Org",        value: ep.org ?? "—" },
                { label: "First Seen", value: new Date(ep.firstSeenAt).toLocaleDateString() },
                ...(ep.lastSeenAt ? [{ label: "Last Seen", value: new Date(ep.lastSeenAt).toLocaleDateString() }] : []),
              ].map(({ label, value }) => (
                <div key={label} className="flex justify-between gap-2">
                  <span className="text-muted-foreground shrink-0">{label}</span>
                  <span className="font-medium text-right truncate max-w-40">{value}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right 2 columns: tabbed Models / MCP Tools / System Prompt + Attack */}
        <div className="col-span-2 space-y-4">
          {/* Tabbed endpoint info */}
          <Card>
            <CardContent className="pt-4 pb-4">
              <Tabs defaultValue="models">
                <TabsList className="w-full mb-3">
                  <TabsTrigger value="models" className="flex-1">
                    Models {(ep.models?.length ?? 0) > 0 && <span className="ml-1.5 text-xs opacity-70">({ep.models!.length})</span>}
                  </TabsTrigger>
                  <TabsTrigger value="tools" className="flex-1">
                    MCP Tools {(ep.tools?.length ?? 0) > 0 && <span className="ml-1.5 text-xs opacity-70">({ep.tools!.length})</span>}
                  </TabsTrigger>
                  <TabsTrigger value="prompt" className="flex-1">
                    System Prompt
                    {ep.systemPromptLeaked && <span className="ml-1.5 w-1.5 h-1.5 rounded-full bg-red-400 inline-block" />}
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="models">
                  {(ep.models?.length ?? 0) === 0 ? (
                    <p className="text-sm text-muted-foreground py-4 text-center">No models discovered</p>
                  ) : (
                    <div className="space-y-2 max-h-52 overflow-y-auto">
                      {ep.models!.map(m => {
                        const isUncensored = UNCENSORED_PATTERNS.test(m);
                        const size = parseModelSize(m);
                        return (
                          <div key={m} className="flex items-center gap-2 px-3 py-2 rounded-md bg-muted/40 border border-border">
                            <span className="font-mono text-sm flex-1 truncate">{m}</span>
                            {size && <span className="text-xs text-muted-foreground shrink-0">{size}</span>}
                            {isUncensored && (
                              <Badge className="text-xs bg-red-500/20 text-red-400 border-red-500/30 shrink-0">
                                ⚠ Uncensored
                              </Badge>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="tools">
                  {(ep.tools?.length ?? 0) === 0 ? (
                    <p className="text-sm text-muted-foreground py-4 text-center">No MCP tools discovered</p>
                  ) : (
                    <div className="space-y-2 max-h-52 overflow-y-auto">
                      {ep.tools!.map(t => {
                        const risk = classifyTool(t.name);
                        const props = t.inputSchema?.properties ?? {};
                        const propList = Object.entries(props);
                        const required = new Set(t.inputSchema?.required ?? []);
                        return (
                          <div key={t.name} className="rounded-md border border-border bg-muted/30 p-3 space-y-1.5">
                            <div className="flex items-center gap-2">
                              <Key className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                              <span className="font-mono font-medium text-sm flex-1">{t.name}</span>
                              <Badge className={`text-xs border ${TOOL_RISK_BADGE[risk.level]}`}>{risk.label}</Badge>
                            </div>
                            {t.description && (
                              <p className="text-xs text-muted-foreground">{t.description}</p>
                            )}
                            {propList.length > 0 && (
                              <div className="mt-1.5 space-y-0.5">
                                <p className="text-xs font-medium text-muted-foreground">Input parameters:</p>
                                {propList.map(([k, v]) => (
                                  <div key={k} className="flex items-baseline gap-1.5 text-xs pl-2">
                                    <span className="font-mono text-violet-400">{k}</span>
                                    {required.has(k) && <span className="text-red-400 text-[10px]">required</span>}
                                    <span className="text-muted-foreground">{v.type ?? "any"}</span>
                                    {v.description && <span className="text-muted-foreground truncate max-w-52">— {v.description}</span>}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="prompt">
                  {!ep.systemPromptLeaked ? (
                    <p className="text-sm text-muted-foreground py-4 text-center">No system prompt leak detected</p>
                  ) : (
                    <div>
                      <p className="text-xs text-red-400 flex items-center gap-1.5 mb-2">
                        <AlertTriangle className="w-3.5 h-3.5" /> System prompt was exposed
                      </p>
                      {ep.systemPromptContent
                        ? <pre className="text-xs font-mono bg-muted/50 rounded p-3 max-h-40 overflow-auto whitespace-pre-wrap">{ep.systemPromptContent}</pre>
                        : <p className="text-sm text-muted-foreground">Content was not captured during scanning.</p>
                      }
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Attack results */}
          {isDone && (
            <div className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-green-500/10 border border-green-500/30 text-green-400 text-sm">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>
                Attack suite completed —{" "}
                {critical > 0 && <><strong className="text-red-400">{critical} critical</strong>{" · "}</>}
                {high > 0     && <><strong className="text-orange-400">{high} high</strong>{" · "}</>}
                {medium > 0   && <><strong className="text-yellow-400">{medium} medium</strong>{" · "}</>}
                <strong>{failed} issue{failed !== 1 ? "s" : ""} found</strong>, {passed} passed
              </span>
            </div>
          )}

          {(attackRun || launchAttack.isPending) ? (
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">Attack Suite Results</CardTitle>
                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    {attackRun?.status === "running" && (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        <span>{attackRun.progress ?? 0}%</span>
                      </>
                    )}
                    {results.length > 0 && (
                      <><span className="text-green-400">{passed} passed</span> · <span className="text-red-400">{failed} failed</span></>
                    )}
                  </div>
                </div>
                {attackRun?.status === "running" && attackRun.progress != null && (
                  <Progress value={attackRun.progress} className="h-1 mt-1" />
                )}
              </CardHeader>
              <CardContent className="space-y-2">
                {results.length === 0 && attackRun?.status === "running" && (
                  <p className="text-sm text-muted-foreground animate-pulse">Running tests…</p>
                )}
                {results.map((r, i) => {
                  const Icon = SEV_ICON[r.severity] ?? Info;
                  const isOpen = selectedResult?.testName === r.testName;
                  return (
                    <div key={i} className={`rounded-lg border p-3 ${SEV_BG[r.severity]}`}>
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className={`w-4 h-4 shrink-0 ${SEV_COLOR[r.severity]}`} />
                        <span className="font-medium text-sm flex-1">{r.testName}</span>
                        <Badge variant="outline" className={`text-xs capitalize ${SEV_COLOR[r.severity]}`}>{r.severity}</Badge>
                        {r.passed
                          ? <CheckCircle2 className="w-4 h-4 text-green-400" />
                          : <XCircle className="w-4 h-4 text-red-400" />
                        }
                      </div>
                      <p className="text-xs text-muted-foreground pl-6 mb-1.5">{r.remediationGuidance}</p>
                      <button
                        className="text-xs text-primary/70 hover:text-primary pl-6 flex items-center gap-1"
                        onClick={() => setSelectedResult(isOpen ? null : r)}
                      >
                        <Eye className="w-3 h-3" />
                        {isOpen ? "Hide" : "Show"} request/response
                      </button>
                      {isOpen && (
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
          ) : (
            <Card className="border-dashed">
              <CardContent className="py-10 text-center">
                <Zap className="w-8 h-8 mx-auto mb-3 text-muted-foreground opacity-40" />
                <p className="font-medium text-sm">No attack runs yet</p>
                <p className="text-xs text-muted-foreground mt-1">Launch the attack suite to test this endpoint for MCP, Ollama, and OpenAI-compat vulnerabilities</p>
                <Button className="mt-4" size="sm" variant="destructive" onClick={() => launchAttack.mutate()}>
                  <Zap className="w-4 h-4 mr-2" /> Launch Attack Suite
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
