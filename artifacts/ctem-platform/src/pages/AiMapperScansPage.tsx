import { useState, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAiMapperWs } from "@/hooks/useAiMapperWs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Plus, Trash2, Eye, Play, Clock, CheckCircle2, XCircle, Loader2,
  Server, Target, Search, ChevronRight, MapPin,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

function ScanLiveUpdater({ scanId, onConnectedChange }: {
  scanId: number;
  onConnectedChange: (id: number, connected: boolean) => void;
}) {
  const qc = useQueryClient();

  const { connected } = useAiMapperWs({
    url: `/api/ai-mapper/scans/${scanId}/ws`,
    onMessage: (msg: any) => {
      qc.setQueryData<AiMapperScan[]>(["ai-mapper-scans"], (prev) =>
        prev ? prev.map(s => s.id === scanId ? { ...s, ...msg } : s) : prev
      );
      if (msg?.status === "completed" || msg?.status === "failed") {
        qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      }
    },
  });

  useEffect(() => {
    onConnectedChange(scanId, connected);
    return () => onConnectedChange(scanId, false);
  }, [connected, scanId, onConnectedChange]);

  return null;
}

const STATUS_COLOR: Record<string, string> = {
  pending:   "bg-slate-500",
  running:   "bg-blue-500 animate-pulse",
  completed: "bg-green-500",
  failed:    "bg-red-500",
  cancelled: "bg-slate-400",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  pending: Clock, running: Loader2, completed: CheckCircle2,
  failed: XCircle, cancelled: XCircle,
};

interface AiMapperScan {
  id: number; title: string; status: string; progress: number;
  totalHosts?: number; liveHosts?: number; scannedHosts?: number;
  endpointCount?: number; queryPresets?: string[]; cidrScope?: string;
  createdAt: string; startedAt?: string; completedAt?: string;
}

interface ShodanPreset {
  id: string; label: string; protocol: string; query: string;
}

interface Asset {
  id: number; name: string; type: string; domain?: string;
  ip?: string; url?: string; status: string;
}

export default function AiMapperScansPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [wsConnectedSet, setWsConnectedSet] = useState<Set<number>>(new Set());
  const handleConnectedChange = useCallback((id: number, conn: boolean) => {
    setWsConnectedSet(prev => {
      const next = new Set(prev);
      if (conn) next.add(id); else next.delete(id);
      return next;
    });
  }, []);

  const [showNew, setShowNew]               = useState(false);
  const [dialogTab, setDialogTab]           = useState("presets");
  const [title, setTitle]                   = useState("AI Surface Scan");
  const [selectedPresets, setSelectedPresets] = useState<string[]>([]);
  const [cidrText, setCidrText]             = useState("");
  const [selectedAssets, setSelectedAssets] = useState<Set<number>>(new Set());
  const [assetSearch, setAssetSearch]       = useState("");

  const { data: scans = [], isLoading } = useQuery<AiMapperScan[]>({
    queryKey: ["ai-mapper-scans"],
    queryFn: () => apiFetch("/api/ai-mapper/scans"),
    refetchInterval: (query) => {
      const d = query.state.data as AiMapperScan[] | undefined;
      const hasRunning = !d || d.some(s => s.status === "running" || s.status === "pending");
      if (!hasRunning) return false;
      return wsConnectedSet.size > 0 ? 30_000 : 3_000;
    },
  });

  const { data: presets = [] } = useQuery<ShodanPreset[]>({
    queryKey: ["ai-mapper-presets"],
    queryFn: () => apiFetch("/api/ai-mapper/query-presets"),
  });

  const { data: assetsResp } = useQuery<{ data: Asset[] }>({
    queryKey: ["assets-brief"],
    queryFn: () => apiFetch("/api/assets?limit=200"),
    enabled: showNew,
  });
  const assets = assetsResp?.data ?? [];

  function buildCidrScope(): string | undefined {
    const lines: string[] = cidrText
      .split(/[\n,]+/)
      .map(s => s.trim())
      .filter(Boolean);
    if (selectedAssets.size > 0) {
      for (const id of selectedAssets) {
        const a = assets.find(x => x.id === id);
        if (!a) continue;
        const target = a.ip || a.domain;
        if (target && !lines.includes(target)) lines.push(target);
      }
    }
    return lines.length ? lines.join("\n") : undefined;
  }

  const createScan = useMutation({
    mutationFn: () => apiFetch("/api/ai-mapper/scans", {
      method: "POST",
      body: JSON.stringify({
        title,
        queryPresets: selectedPresets,
        cidrScope: buildCidrScope(),
      }),
    }),
    onSuccess: (data: any) => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      setShowNew(false);
      resetDialog();
      toast({ title: "Scan started" });
      if (data?.id) navigate(`/ai-mapper/scans/${data.id}`);
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const cancelScan = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/ai-mapper/scans/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      toast({ title: "Scan cancelled" });
    },
  });

  function resetDialog() {
    setTitle("AI Surface Scan");
    setSelectedPresets([]);
    setCidrText("");
    setSelectedAssets(new Set());
    setAssetSearch("");
    setDialogTab("presets");
  }

  function togglePreset(id: string) {
    setSelectedPresets(p => p.includes(id) ? p.filter(x => x !== id) : [...p, id]);
  }

  function toggleAsset(id: number) {
    setSelectedAssets(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  const filteredAssets = assets.filter(a =>
    !assetSearch ||
    a.name.toLowerCase().includes(assetSearch.toLowerCase()) ||
    (a.domain ?? "").toLowerCase().includes(assetSearch.toLowerCase()) ||
    (a.ip ?? "").includes(assetSearch)
  );

  const scopePreview = buildCidrScope();
  const scopeLines   = scopePreview?.split("\n").filter(Boolean) ?? [];

  return (
    <div className="p-6 space-y-5 w-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Surface Scans</h1>
          <p className="text-muted-foreground text-sm mt-0.5">
            Discover exposed AI infrastructure using Shodan queries and active probing
          </p>
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
            <p className="text-sm text-muted-foreground mt-1">
              Start your first AI surface scan to discover exposed AI endpoints
            </p>
            <Button className="mt-4" onClick={() => setShowNew(true)}>
              <Plus className="w-4 h-4 mr-2" /> Start Scan
            </Button>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-2">
          {scans.filter(s => s.status === "running").map(s => (
            <ScanLiveUpdater key={s.id} scanId={s.id} onConnectedChange={handleConnectedChange} />
          ))}
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 text-muted-foreground text-xs uppercase tracking-wide">
                  <th className="text-left px-4 py-2.5 w-8">Status</th>
                  <th className="text-left px-4 py-2.5">Title</th>
                  <th className="text-left px-4 py-2.5">Progress</th>
                  <th className="text-right px-4 py-2.5">Endpoints</th>
                  <th className="text-right px-4 py-2.5">Live Hosts</th>
                  <th className="text-right px-4 py-2.5">Targets</th>
                  <th className="text-left px-4 py-2.5">Created</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map(scan => {
                  const Icon = STATUS_ICON[scan.status] ?? Clock;
                  const isRunning = scan.status === "running" || scan.status === "pending";
                  return (
                    <tr
                      key={scan.id}
                      className="hover:bg-muted/30 cursor-pointer transition-colors"
                      onClick={() => navigate(`/ai-mapper/scans/${scan.id}`)}
                    >
                      <td className="px-4 py-3">
                        <div className={cn("w-2 h-2 rounded-full", STATUS_COLOR[scan.status] ?? "bg-slate-400")} />
                      </td>
                      <td className="px-4 py-3">
                        <p className="font-medium truncate max-w-56">{scan.title}</p>
                        <p className="text-xs text-muted-foreground capitalize flex items-center gap-1 mt-0.5">
                          <Icon className={cn("w-3 h-3", scan.status === "running" && "animate-spin")} />
                          {scan.status}
                        </p>
                      </td>
                      <td className="px-4 py-3 min-w-36">
                        {isRunning ? (
                          <div>
                            <Progress value={scan.progress ?? 0} className="h-1.5 w-28" />
                            <p className="text-xs text-muted-foreground mt-1">{scan.progress ?? 0}%</p>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            {scan.status === "completed" ? "100%" : "—"}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {scan.endpointCount != null
                          ? <span className="font-medium text-violet-400">{scan.endpointCount.toLocaleString()}</span>
                          : <span className="text-muted-foreground">—</span>
                        }
                      </td>
                      <td className="px-4 py-3 text-right text-muted-foreground">
                        {scan.liveHosts != null ? scan.liveHosts.toLocaleString() : "—"}
                      </td>
                      <td className="px-4 py-3 text-right text-muted-foreground text-xs">
                        {scan.cidrScope
                          ? scan.cidrScope.split("\n").filter(Boolean).length
                          : <span className="text-muted-foreground/40">—</span>
                        }
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1" onClick={e => e.stopPropagation()}>
                          <Button
                            variant="ghost" size="icon" className="w-7 h-7"
                            onClick={() => navigate(`/ai-mapper/scans/${scan.id}`)}
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </Button>
                          {isRunning && (
                            <Button
                              variant="ghost" size="icon"
                              className="w-7 h-7 text-red-400 hover:text-red-300"
                              onClick={() => cancelScan.mutate(scan.id)}
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── New Scan Dialog ──────────────────────────────────────────────────── */}
      <Dialog open={showNew} onOpenChange={open => { if (!open) { setShowNew(false); resetDialog(); } }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>New AI Surface Scan</DialogTitle>
          </DialogHeader>

          <div className="space-y-4 py-1">
            {/* Title */}
            <div className="space-y-1.5">
              <Label>Scan Title</Label>
              <Input value={title} onChange={e => setTitle(e.target.value)} placeholder="AI Surface Scan" />
            </div>

            {/* Tabs: Targets + Presets */}
            <Tabs value={dialogTab} onValueChange={setDialogTab}>
              <TabsList className="w-full">
                <TabsTrigger value="presets" className="flex-1">
                  <Server className="w-3.5 h-3.5 mr-1.5" />
                  Shodan Presets
                  {selectedPresets.length > 0 && (
                    <span className="ml-1.5 bg-primary text-primary-foreground text-xs rounded-full w-4 h-4 inline-flex items-center justify-center">
                      {selectedPresets.length}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="assets" className="flex-1">
                  <MapPin className="w-3.5 h-3.5 mr-1.5" />
                  Add Assets
                  {selectedAssets.size > 0 && (
                    <span className="ml-1.5 bg-primary text-primary-foreground text-xs rounded-full w-4 h-4 inline-flex items-center justify-center">
                      {selectedAssets.size}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="cidr" className="flex-1">
                  <Target className="w-3.5 h-3.5 mr-1.5" />
                  CIDR / IP Scope
                  {cidrText.trim() && <span className="ml-1.5 w-1.5 h-1.5 rounded-full bg-violet-400 inline-block" />}
                </TabsTrigger>
              </TabsList>

              {/* Shodan Presets Tab */}
              <TabsContent value="presets" className="mt-3">
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs text-muted-foreground">
                    Select presets. If none selected, all protocols are queried.
                  </p>
                  <div className="flex gap-2 shrink-0">
                    <button
                      className="text-xs text-primary hover:underline"
                      onClick={() => setSelectedPresets(presets.map(p => p.id))}
                    >
                      Select All
                    </button>
                    {selectedPresets.length > 0 && (
                      <button
                        className="text-xs text-muted-foreground hover:text-foreground"
                        onClick={() => setSelectedPresets([])}
                      >
                        Clear ({selectedPresets.length})
                      </button>
                    )}
                  </div>
                </div>
                <div className="max-h-64 overflow-y-auto pr-1 space-y-3">
                  {Array.from(new Set(presets.map(p => p.protocol))).map(proto => (
                    <div key={proto}>
                      <div className="flex items-center justify-between mb-1">
                        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{proto}</p>
                        <button
                          className="text-xs text-primary/70 hover:text-primary"
                          onClick={() => {
                            const ids = presets.filter(p => p.protocol === proto).map(p => p.id);
                            const allSelected = ids.every(id => selectedPresets.includes(id));
                            setSelectedPresets(prev =>
                              allSelected ? prev.filter(id => !ids.includes(id)) : [...new Set([...prev, ...ids])]
                            );
                          }}
                        >
                          {presets.filter(p => p.protocol === proto).every(p => selectedPresets.includes(p.id)) ? "Deselect" : "Select all"}
                        </button>
                      </div>
                      <div className="grid grid-cols-1 gap-1.5">
                        {presets.filter(p => p.protocol === proto).map(p => (
                          <button
                            key={p.id}
                            onClick={() => togglePreset(p.id)}
                            className={cn(
                              "text-left px-3 py-2 rounded-md border text-sm transition-colors",
                              selectedPresets.includes(p.id)
                                ? "border-primary bg-primary/10 text-primary"
                                : "border-border hover:border-primary/40 hover:bg-muted/40"
                            )}
                          >
                            <div className="font-medium text-xs">{p.label}</div>
                            <div className="text-xs text-muted-foreground font-mono mt-0.5 truncate">{p.query}</div>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </TabsContent>

              {/* Asset Selector Tab */}
              <TabsContent value="assets" className="mt-3">
                <p className="text-xs text-muted-foreground mb-2">
                  Select assets from your inventory. Their IPs and domains will be added as scan targets.
                </p>
                <div className="relative mb-2">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <Input
                    value={assetSearch}
                    onChange={e => setAssetSearch(e.target.value)}
                    placeholder="Search assets…"
                    className="pl-8 h-8 text-sm"
                  />
                </div>
                {assets.length === 0 ? (
                  <div className="py-8 text-center text-sm text-muted-foreground">
                    <Server className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    No assets in inventory yet
                  </div>
                ) : (
                  <div className="max-h-56 overflow-y-auto space-y-1 pr-1">
                    {filteredAssets.map(a => {
                      const target = a.ip || a.domain;
                      const isSelected = selectedAssets.has(a.id);
                      return (
                        <button
                          key={a.id}
                          onClick={() => toggleAsset(a.id)}
                          disabled={!target}
                          className={cn(
                            "w-full text-left px-3 py-2 rounded-md border text-sm transition-colors",
                            !target && "opacity-40 cursor-not-allowed",
                            isSelected
                              ? "border-primary bg-primary/10 text-primary"
                              : "border-border hover:border-primary/40 hover:bg-muted/40"
                          )}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <div>
                              <div className="font-medium text-xs">{a.name}</div>
                              <div className="text-xs text-muted-foreground font-mono">
                                {target ?? "No IP or domain — cannot scan"}
                              </div>
                            </div>
                            <Badge variant="outline" className="text-xs capitalize shrink-0">{a.type}</Badge>
                          </div>
                        </button>
                      );
                    })}
                    {filteredAssets.length === 0 && (
                      <p className="py-4 text-center text-sm text-muted-foreground">No assets match</p>
                    )}
                  </div>
                )}
                {selectedAssets.size > 0 && (
                  <button
                    className="mt-2 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => setSelectedAssets(new Set())}
                  >
                    Deselect {selectedAssets.size} asset{selectedAssets.size !== 1 ? "s" : ""}
                  </button>
                )}
              </TabsContent>

              {/* CIDR Scope Tab */}
              <TabsContent value="cidr" className="mt-3">
                <p className="text-xs text-muted-foreground mb-2">
                  Optionally restrict the scan to specific IP addresses or CIDR ranges (one per line).
                  When combined with asset selection, both are merged.
                </p>
                <Textarea
                  value={cidrText}
                  onChange={e => setCidrText(e.target.value)}
                  placeholder={"192.168.1.0/24\n10.0.0.15\n203.0.113.0/28"}
                  rows={5}
                  className="font-mono text-xs resize-none"
                />
              </TabsContent>
            </Tabs>

            {/* Scope summary */}
            {scopeLines.length > 0 && (
              <div className="bg-muted/30 border border-border rounded-lg px-3 py-2.5">
                <p className="text-xs font-medium mb-1 flex items-center gap-1.5">
                  <Target className="w-3.5 h-3.5 text-violet-400" />
                  Scan scope — {scopeLines.length} target{scopeLines.length !== 1 ? "s" : ""}
                </p>
                <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
                  {scopeLines.slice(0, 20).map((line, i) => (
                    <span key={i} className="font-mono text-xs bg-background border border-border rounded px-1.5 py-0.5">
                      {line}
                    </span>
                  ))}
                  {scopeLines.length > 20 && (
                    <span className="text-xs text-muted-foreground py-0.5">+{scopeLines.length - 20} more</span>
                  )}
                </div>
              </div>
            )}

            {scopeLines.length === 0 && (
              <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg px-3 py-2.5 text-xs text-blue-400/80">
                <strong>Global scan:</strong> No scope defined — Shodan will be queried globally for AI endpoints.
                Add assets or CIDR ranges above to target specific infrastructure.
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowNew(false); resetDialog(); }}>Cancel</Button>
            <Button onClick={() => createScan.mutate()} disabled={createScan.isPending || !title.trim()}>
              {createScan.isPending
                ? <Loader2 className="w-4 h-4 animate-spin mr-2" />
                : <Play className="w-4 h-4 mr-2" />}
              Start Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
