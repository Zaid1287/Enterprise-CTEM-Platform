import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Plus, Trash2, Eye, Play, Clock, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { formatDistanceToNow } from "date-fns";

const STATUS_COLOR: Record<string, string> = {
  pending:   "bg-slate-500",
  running:   "bg-blue-500 animate-pulse",
  completed: "bg-green-500",
  failed:    "bg-red-500",
  cancelled: "bg-slate-400",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  pending:   Clock,
  running:   Loader2,
  completed: CheckCircle2,
  failed:    XCircle,
  cancelled: XCircle,
};

interface AiMapperScan {
  id: number;
  title: string;
  status: string;
  progress: number;
  totalHosts?: number;
  liveHosts?: number;
  scannedHosts?: number;
  endpointCount?: number;
  queryPresets?: string[];
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
}

interface ShodanPreset {
  id: string;
  label: string;
  protocol: string;
  query: string;
}

export default function AiMapperScansPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [title, setTitle] = useState("AI Surface Scan");
  const [selectedPresets, setSelectedPresets] = useState<string[]>([]);

  const { data: scans = [], isLoading } = useQuery<AiMapperScan[]>({
    queryKey: ["ai-mapper-scans"],
    queryFn: () => apiFetch("/api/ai-mapper/scans"),
    refetchInterval: (query) => {
      const d = query.state.data as AiMapperScan[] | undefined;
      if (!d || d.some(s => s.status === "running" || s.status === "pending")) return 5000;
      return false;
    },
  });

  const { data: presets = [] } = useQuery<ShodanPreset[]>({
    queryKey: ["ai-mapper-presets"],
    queryFn: () => apiFetch("/api/ai-mapper/query-presets"),
  });

  const createScan = useMutation({
    mutationFn: () => apiFetch("/api/ai-mapper/scans", {
      method: "POST",
      body: JSON.stringify({ title, queryPresets: selectedPresets }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      setShowNew(false);
      setTitle("AI Surface Scan");
      setSelectedPresets([]);
      toast({ title: "Scan started" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const cancelScan = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/ai-mapper/scans/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] }); toast({ title: "Scan cancelled" }); },
  });

  function togglePreset(id: string) {
    setSelectedPresets(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Surface Scans</h1>
          <p className="text-muted-foreground text-sm">Discover exposed AI infrastructure using Shodan queries and active probing</p>
        </div>
        <Button onClick={() => setShowNew(true)}>
          <Plus className="w-4 h-4 mr-2" /> New Scan
        </Button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-40">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : scans.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <Play className="w-10 h-10 mx-auto mb-3 text-muted-foreground opacity-40" />
            <p className="font-medium">No scans yet</p>
            <p className="text-sm text-muted-foreground mt-1">Start your first AI surface scan to discover exposed AI endpoints</p>
            <Button className="mt-4" onClick={() => setShowNew(true)}>
              <Plus className="w-4 h-4 mr-2" /> Start Scan
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-3">
          {scans.map(scan => {
            const Icon = STATUS_ICON[scan.status] ?? Clock;
            const isRunning = scan.status === "running" || scan.status === "pending";
            return (
              <Card key={scan.id} className="hover:border-primary/40 transition-colors cursor-pointer" onClick={() => navigate(`/ai-mapper/scans/${scan.id}`)}>
                <CardContent className="py-4 px-5">
                  <div className="flex items-start gap-4">
                    <div className={`mt-1 w-2.5 h-2.5 rounded-full shrink-0 ${STATUS_COLOR[scan.status] ?? "bg-slate-400"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-2">
                        <p className="font-medium truncate">{scan.title}</p>
                        <div className="flex items-center gap-2 shrink-0">
                          <Badge variant="outline" className="text-xs capitalize">{scan.status}</Badge>
                          <Button variant="ghost" size="icon" className="w-7 h-7" onClick={e => { e.stopPropagation(); navigate(`/ai-mapper/scans/${scan.id}`); }}>
                            <Eye className="w-3.5 h-3.5" />
                          </Button>
                          {isRunning && (
                            <Button variant="ghost" size="icon" className="w-7 h-7 text-red-400 hover:text-red-300" onClick={e => { e.stopPropagation(); cancelScan.mutate(scan.id); }}>
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          )}
                        </div>
                      </div>

                      {isRunning && (
                        <div className="mt-2">
                          <Progress value={scan.progress ?? 0} className="h-1.5" />
                          <p className="text-xs text-muted-foreground mt-1">{scan.progress ?? 0}% complete</p>
                        </div>
                      )}

                      <div className="flex items-center gap-4 mt-1.5 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1"><Icon className={`w-3 h-3 ${scan.status === "running" ? "animate-spin" : ""}`} /> {scan.status}</span>
                        {scan.endpointCount != null && <span>{scan.endpointCount} endpoints found</span>}
                        {scan.liveHosts != null && <span>{scan.liveHosts} live hosts</span>}
                        <span>{formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      <Dialog open={showNew} onOpenChange={setShowNew}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>New AI Surface Scan</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label>Scan Title</Label>
              <Input value={title} onChange={e => setTitle(e.target.value)} placeholder="AI Surface Scan" />
            </div>
            <div className="space-y-2">
              <Label>Shodan Query Presets <span className="text-muted-foreground font-normal">(all if none selected)</span></Label>
              <div className="grid grid-cols-1 gap-1.5 max-h-56 overflow-y-auto pr-1">
                {presets.map(p => (
                  <button
                    key={p.id}
                    onClick={() => togglePreset(p.id)}
                    className={`text-left px-3 py-2 rounded-md border text-sm transition-colors ${
                      selectedPresets.includes(p.id)
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border hover:border-primary/50 hover:bg-muted/40"
                    }`}
                  >
                    <div className="font-medium">{p.label}</div>
                    <div className="text-xs text-muted-foreground font-mono">{p.query}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNew(false)}>Cancel</Button>
            <Button onClick={() => createScan.mutate()} disabled={createScan.isPending}>
              {createScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
              Start Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
