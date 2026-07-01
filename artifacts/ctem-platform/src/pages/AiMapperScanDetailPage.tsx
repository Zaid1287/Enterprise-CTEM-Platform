import { useRoute, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ArrowLeft, Server, ShieldOff, Globe, Loader2, XCircle, StopCircle, CheckCircle2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { useToast } from "@/hooks/use-toast";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import { useAiMapperWs } from "@/hooks/useAiMapperWs";
import { cn } from "@/lib/utils";

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/20 text-green-400 border-green-500/30",
};

const PHASES = [
  { label: "Passive Discovery",        band: [0,  20] },
  { label: "Port & HTTP Probing",      band: [20, 40] },
  { label: "Tech & Screenshot",        band: [40, 70] },
  { label: "Vulnerability Assessment", band: [70, 100] },
] as const;

function PhaseTimeline({ progress }: { progress: number }) {
  const currentPhase = PHASES.findIndex((_, i) => {
    const next = PHASES[i + 1];
    return progress < (next?.band[0] ?? 100);
  });
  const active = currentPhase === -1 ? PHASES.length - 1 : currentPhase;

  return (
    <div className="flex items-start gap-0 mt-4">
      {PHASES.map((phase, i) => {
        const done    = progress >= phase.band[1] + 1;
        const current = i === active && progress < 100;
        return (
          <div key={i} className="flex-1 flex flex-col items-center gap-1">
            <div className="flex items-center w-full">
              {i > 0 && (
                <div className={cn("h-0.5 flex-1 transition-colors", done || current ? "bg-violet-500" : "bg-border")} />
              )}
              <div className={cn(
                "w-7 h-7 rounded-full border-2 flex items-center justify-center shrink-0 transition-all",
                done    ? "border-violet-500 bg-violet-500 text-white" :
                current ? "border-violet-400 bg-violet-400/20 text-violet-400" :
                          "border-border bg-background text-muted-foreground/40",
              )}>
                {done ? <CheckCircle2 className="w-3.5 h-3.5" /> : <span className="text-xs font-bold">{i + 1}</span>}
              </div>
              {i < PHASES.length - 1 && (
                <div className={cn("h-0.5 flex-1 transition-colors", done ? "bg-violet-500" : "bg-border")} />
              )}
            </div>
            <span className={cn(
              "text-xs text-center leading-tight max-w-20 px-1",
              done ? "text-violet-400" : current ? "text-foreground" : "text-muted-foreground/50"
            )}>
              {phase.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

interface AiEndpoint {
  id: number; ip: string; port: number; hostname?: string; url: string;
  protocol: string; framework?: string; authStatus: string;
  riskScore: number; riskLevel: string; country?: string; org?: string;
  models?: string[]; tools?: { name: string }[];
  systemPromptLeaked: boolean;
}

interface AiMapperScan {
  id: number; title: string; status: string; progress: number;
  totalHosts?: number; liveHosts?: number; scannedHosts?: number; endpointCount?: number;
  createdAt: string; startedAt?: string; completedAt?: string;
  endpoints: AiEndpoint[];
}

export default function AiMapperScanDetailPage() {
  const [, params] = useRoute("/ai-mapper/scans/:id");
  const [, navigate] = useLocation();
  const scanId = Number(params?.id);
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: scan, isLoading } = useQuery<AiMapperScan>({
    queryKey: ["ai-mapper-scan", scanId],
    queryFn: () => apiFetch(`/api/ai-mapper/scans/${scanId}`),
    refetchInterval: (query) => {
      const d = query.state.data as AiMapperScan | undefined;
      if (!d || d.status === "running" || d.status === "pending") return 3000;
      return false;
    },
  });

  const isRunning = scan?.status === "running" || scan?.status === "pending";
  useAiMapperWs({
    url: isRunning ? `/api/ai-mapper/scans/${scanId}/ws` : null,
    enabled: isRunning,
    onMessage: (msg: any) => {
      if (msg?.type === "done") {
        qc.invalidateQueries({ queryKey: ["ai-mapper-scan", scanId] });
        qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      } else {
        qc.setQueryData<AiMapperScan>(["ai-mapper-scan", scanId], (prev) =>
          prev ? { ...prev, ...msg } : prev
        );
      }
    },
  });

  const cancelMutation = useMutation({
    mutationFn: () => apiFetch(`/api/ai-mapper/scans/${scanId}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-scan", scanId] });
      qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      toast({ title: "Scan cancelled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  if (isLoading || !scan) return (
    <div className="flex items-center justify-center h-64">
      <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
    </div>
  );

  const endpoints = scan.endpoints ?? [];
  const critical = endpoints.filter(e => e.riskLevel === "critical").length;
  const high     = endpoints.filter(e => e.riskLevel === "high").length;
  const noAuth   = endpoints.filter(e => e.authStatus === "none").length;

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="icon" onClick={() => navigate("/ai-mapper/scans")}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold">{scan.title}</h1>
          <p className="text-sm text-muted-foreground">Scan #{scan.id} · {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}</p>
        </div>
        <Badge variant="outline" className="capitalize">{scan.status}</Badge>
        {isRunning && (
          <Button
            variant="destructive"
            size="sm"
            onClick={() => cancelMutation.mutate()}
            disabled={cancelMutation.isPending}
          >
            {cancelMutation.isPending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <StopCircle className="w-3.5 h-3.5 mr-1.5" />}
            Cancel Scan
          </Button>
        )}
      </div>

      {isRunning && (
        <Card>
          <CardContent className="py-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">Scan in progress…</span>
              <span className="text-sm text-muted-foreground">{scan.progress ?? 0}%</span>
            </div>
            <Progress value={scan.progress ?? 0} className="h-2" />
            <div className="flex gap-6 mt-2.5 text-xs text-muted-foreground">
              {scan.totalHosts   != null && <span>Total: {scan.totalHosts}</span>}
              {scan.liveHosts    != null && <span>Live: {scan.liveHosts}</span>}
              {scan.scannedHosts != null && <span>Scanned: {scan.scannedHosts}</span>}
            </div>
            <PhaseTimeline progress={scan.progress ?? 0} />
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Endpoints Found", value: endpoints.length, icon: Server,   color: "text-blue-400" },
          { label: "Critical",        value: critical,          icon: XCircle,  color: "text-red-400" },
          { label: "High",            value: high,              icon: ShieldOff, color: "text-orange-400" },
          { label: "No Auth",         value: noAuth,            icon: Globe,    color: "text-yellow-400" },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="py-4">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-muted-foreground">{s.label}</span>
              </div>
              <p className="text-2xl font-bold">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Discovered Endpoints</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {endpoints.length === 0 ? (
            <div className="py-12 text-center text-muted-foreground text-sm">
              {scan.status === "completed" ? "No AI endpoints discovered" : "Endpoints will appear as the scan progresses…"}
            </div>
          ) : (
            <div className="divide-y divide-border">
              {endpoints.map(ep => (
                <div
                  key={ep.id}
                  className="flex items-center gap-4 px-5 py-3 hover:bg-muted/30 transition-colors cursor-pointer"
                  onClick={() => navigate(`/ai-mapper/endpoints/${ep.id}`)}
                >
                  <RiskScoreGauge score={ep.riskScore} size="sm" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium">{ep.ip}:{ep.port}</span>
                      {ep.hostname && <span className="text-xs text-muted-foreground truncate">{ep.hostname}</span>}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge variant="outline" className="text-xs">{ep.protocol}</Badge>
                      {ep.framework && <span className="text-xs text-muted-foreground">{ep.framework}</span>}
                      <Badge className={`text-xs border ${RISK_BADGE[ep.riskLevel] ?? ""}`}>{ep.riskLevel}</Badge>
                      {ep.authStatus === "none" && <Badge variant="destructive" className="text-xs">No Auth</Badge>}
                      {ep.systemPromptLeaked && <Badge variant="destructive" className="text-xs">Prompt Leaked</Badge>}
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground shrink-0">
                    {ep.country && <p>{ep.country}</p>}
                    {ep.org && <p className="truncate max-w-32">{ep.org}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
