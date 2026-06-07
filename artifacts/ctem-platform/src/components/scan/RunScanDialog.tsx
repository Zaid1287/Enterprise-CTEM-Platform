import { useState, useEffect } from "react";
import { useRunPipelineScan, useCreateScanSchedule } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import {
  ChevronDown, ChevronRight, Zap, Calendar, Clock, Check, X, Settings2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

interface PipelineTool {
  id: number;
  name: string;
  category: string;
  isActive: boolean;
}

interface Asset {
  id: number;
  name: string;
  value: string;
  type: string;
}

interface AssetConfig {
  assetId: number;
  toolIds: number[];
  included: boolean;
  expanded: boolean;
}

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pipelineTools: PipelineTool[];
  assets: Asset[];
  onRunComplete: (scanId: number) => void;
  preSelectedAssetIds?: number[];
}

const DAYS_OF_WEEK = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const categoryColor: Record<string, string> = {
  recon: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  vuln_scan: "bg-red-500/15 text-red-400 border-red-500/30",
  port_scan: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  ssl_check: "bg-green-500/15 text-green-400 border-green-500/30",
  web_recon: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  osint: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

export default function RunScanDialog({ open, onOpenChange, pipelineTools, assets, onRunComplete, preSelectedAssetIds }: Props) {
  const { user } = useAuth();
  const isClient = user?.role === "client";
  const [step, setStep] = useState<1 | 2>(1);
  const [scanName, setScanName] = useState("");
  const [assetConfigs, setAssetConfigs] = useState<AssetConfig[]>([]);
  const [scheduleMode, setScheduleMode] = useState<"now" | "schedule">("now");
  const [frequency, setFrequency] = useState("daily");
  const [runTime, setRunTime] = useState("09:00");
  const [dayOfWeek, setDayOfWeek] = useState(1);
  const [dayOfMonth, setDayOfMonth] = useState(1);
  const [scheduleName, setScheduleName] = useState("");
  const [saveSchedule, setSaveSchedule] = useState(false);
  const [isRunning, setIsRunning] = useState(false);

  const runPipeline = useRunPipelineScan();
  const createSchedule = useCreateScanSchedule();

  const enabledTools = pipelineTools.filter(t => t.isActive);

  useEffect(() => {
    if (open) {
      setStep(1);
      setScanName("");
      setScheduleMode("now");
      setIsRunning(false);
      setSaveSchedule(false);
      setAssetConfigs(assets.map(a => {
        const preSelected = preSelectedAssetIds ? preSelectedAssetIds.includes(a.id) : false;
        // Client role: auto-select all tools (no per-tool control)
        const toolIds = isClient ? enabledTools.map(t => t.id) : enabledTools.map(t => t.id);
        return { assetId: a.id, toolIds, included: preSelected, expanded: preSelected };
      }));
    }
  }, [open, assets.length, enabledTools.length]);

  const includedConfigs = assetConfigs.filter(c => c.included);
  const canProceed = includedConfigs.length > 0 && includedConfigs.every(c => c.toolIds.length > 0);

  function toggleAsset(id: number) {
    setAssetConfigs(prev => prev.map(c =>
      c.assetId === id ? { ...c, included: !c.included, expanded: !c.included } : c
    ));
  }

  function toggleExpand(id: number) {
    setAssetConfigs(prev => prev.map(c => c.assetId === id ? { ...c, expanded: !c.expanded } : c));
  }

  function toggleTool(assetId: number, toolId: number) {
    setAssetConfigs(prev => prev.map(c => {
      if (c.assetId !== assetId) return c;
      const has = c.toolIds.includes(toolId);
      return { ...c, toolIds: has ? c.toolIds.filter(id => id !== toolId) : [...c.toolIds, toolId] };
    }));
  }

  function selectAllTools(assetId: number, all: boolean) {
    setAssetConfigs(prev => prev.map(c =>
      c.assetId === assetId ? { ...c, toolIds: all ? enabledTools.map(t => t.id) : [] } : c
    ));
  }

  function selectAllAssets(all: boolean) {
    setAssetConfigs(prev => prev.map(c => ({ ...c, included: all })));
  }

  function autoScanName(): string {
    const dateStr = new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
    if (includedConfigs.length === 1) {
      const asset = assets.find(a => a.id === includedConfigs[0].assetId);
      const label = asset?.value || asset?.name || "Asset";
      return `${label} Scan Report — ${dateStr}`;
    }
    return `${includedConfigs.length} Assets Scan Report — ${dateStr}`;
  }

  async function handleRun(andSchedule = false) {
    if (!canProceed) return;
    setIsRunning(true);
    try {
      const configs = includedConfigs.map(c => ({ assetId: c.assetId, toolIds: c.toolIds }));
      const finalName = scanName.trim() || autoScanName();

      if (andSchedule && saveSchedule) {
        await createSchedule.mutateAsync({
          data: {
            name: scheduleName || finalName || `Pipeline Schedule`,
            assetToolConfig: configs,
            frequency, runTime,
            ...(frequency === "weekly" ? { dayOfWeek } : {}),
            ...(frequency === "monthly" ? { dayOfMonth } : {}),
          } as any,
        });
      }

      if (scheduleMode === "now" || andSchedule) {
        const result = await runPipeline.mutateAsync({
          data: { name: finalName, assetToolConfig: configs } as any,
        });
        onRunComplete((result as any).scanId);
        onOpenChange(false);
      } else {
        await createSchedule.mutateAsync({
          data: {
            name: scheduleName || `Pipeline Schedule`,
            assetToolConfig: configs,
            frequency, runTime,
            ...(frequency === "weekly" ? { dayOfWeek } : {}),
            ...(frequency === "monthly" ? { dayOfMonth } : {}),
          } as any,
        });
        onOpenChange(false);
      }
    } finally {
      setIsRunning(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={o => { if (!isRunning) onOpenChange(o); }}>
      <DialogContent className="max-w-2xl max-h-[90vh] flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-primary" />
            {step === 1 ? (isClient ? "Select Assets" : "Select Assets & Tools") : "Schedule Configuration"}
          </DialogTitle>
          <div className="flex items-center gap-1 mt-2">
            {[1, 2].map(s => (
              <div key={s} className={cn("flex items-center gap-1 text-xs", s === step ? "text-foreground" : "text-muted-foreground")}>
                <div className={cn("w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold border", s === step ? "bg-primary border-primary text-white" : s < step ? "bg-primary/20 border-primary/40 text-primary" : "bg-muted border-border")}>{s}</div>
                <span>{s === 1 ? (isClient ? "Assets" : "Assets & Tools") : "Schedule"}</span>
                {s < 2 && <ChevronRight className="w-3 h-3 mx-1" />}
              </div>
            ))}
          </div>
        </DialogHeader>

        {isRunning ? (
          <div className="py-14 flex flex-col items-center gap-4 flex-1">
            <div className="w-14 h-14 border-4 border-primary border-t-transparent rounded-full animate-spin" />
            <div className="text-center">
              <p className="font-medium">Running pipeline scan…</p>
              <p className="text-xs text-muted-foreground mt-1">
                Scanning {includedConfigs.length} asset{includedConfigs.length !== 1 ? "s" : ""} · this may take a moment
              </p>
            </div>
          </div>
        ) : step === 1 ? (
          <div className="flex-1 overflow-y-auto space-y-4 pr-1">
            {/* Scan name */}
            <div>
              <Label className="text-xs mb-1.5 block">Scan Name (optional)</Label>
              <Input
                placeholder={`e.g. example.com Scan Report — ${new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" })}`}
                value={scanName}
                onChange={e => setScanName(e.target.value)}
                className="text-sm"
              />
            </div>

            {/* Asset + tool selector */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <Label className="text-xs">{isClient ? "Select Assets" : "Assets & Tool Selection"}</Label>
                <div className="flex gap-2 text-[10px]">
                  <button className="text-primary hover:underline" onClick={() => selectAllAssets(true)}>Select all</button>
                  <span className="text-muted-foreground">·</span>
                  <button className="text-muted-foreground hover:text-foreground" onClick={() => selectAllAssets(false)}>Clear</button>
                </div>
              </div>

              <div className="border border-border rounded-lg divide-y divide-border/50 max-h-72 overflow-y-auto">
                {assets.length === 0 ? (
                  <div className="p-4 text-center text-xs text-muted-foreground">No assets found.</div>
                ) : assets.map(asset => {
                  const cfg = assetConfigs.find(c => c.assetId === asset.id);
                  if (!cfg) return null;
                  const selectedCount = cfg.toolIds.length;
                  const totalCount = enabledTools.length;

                  return (
                    <div key={asset.id} className={cn("transition-colors", cfg.included ? "bg-primary/5" : "")}>
                      <div className="flex items-center gap-3 px-3 py-2.5">
                        <button
                          onClick={() => toggleAsset(asset.id)}
                          className={cn("w-4 h-4 rounded border-2 flex items-center justify-center shrink-0 transition-colors",
                            cfg.included ? "bg-primary border-primary" : "border-muted-foreground hover:border-foreground")}
                        >
                          {cfg.included && <Check className="w-2.5 h-2.5 text-white" />}
                        </button>

                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium truncate">{asset.name}</p>
                          <p className="text-[10px] text-muted-foreground font-mono truncate">{asset.value}</p>
                        </div>

                        <span className="text-[10px] bg-accent/60 text-muted-foreground rounded px-1.5 py-0.5 shrink-0">{asset.type}</span>

                        {cfg.included && !isClient && (
                          <span className={cn("text-[10px] px-1.5 py-0.5 rounded border shrink-0",
                            selectedCount === 0 ? "bg-red-500/15 text-red-400 border-red-500/30" :
                            selectedCount < totalCount ? "bg-amber-500/15 text-amber-400 border-amber-500/30" :
                            "bg-green-500/15 text-green-400 border-green-500/30"
                          )}>
                            {selectedCount}/{totalCount} tools
                          </span>
                        )}

                        {cfg.included && !isClient && (
                          <button onClick={() => toggleExpand(asset.id)} className="text-muted-foreground hover:text-foreground shrink-0">
                            {cfg.expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                          </button>
                        )}
                      </div>

                      {cfg.included && cfg.expanded && enabledTools.length > 0 && !isClient && (
                        <div className="px-3 pb-3 border-t border-border/40 bg-accent/10">
                          <div className="flex items-center justify-between py-1.5 mb-1">
                            <p className="text-[10px] text-muted-foreground font-medium">Select tools for this asset</p>
                            <div className="flex gap-2 text-[10px]">
                              <button className="text-primary hover:underline" onClick={() => selectAllTools(asset.id, true)}>All</button>
                              <span className="text-muted-foreground">·</span>
                              <button className="text-muted-foreground hover:text-foreground" onClick={() => selectAllTools(asset.id, false)}>None</button>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-1.5">
                            {enabledTools.map(tool => {
                              const checked = cfg.toolIds.includes(tool.id);
                              return (
                                <button
                                  key={tool.id}
                                  onClick={() => toggleTool(asset.id, tool.id)}
                                  className={cn(
                                    "flex items-center gap-2 text-left rounded-md px-2 py-1.5 border text-xs transition-colors",
                                    checked ? "bg-primary/10 border-primary/30 text-foreground" : "bg-card border-border text-muted-foreground hover:text-foreground"
                                  )}
                                >
                                  <div className={cn("w-3 h-3 rounded border shrink-0 flex items-center justify-center",
                                    checked ? "bg-primary border-primary" : "border-muted-foreground")}>
                                    {checked && <Check className="w-2 h-2 text-white" />}
                                  </div>
                                  <span className="truncate font-medium">{tool.name}</span>
                                  <span className={cn("text-[9px] px-1 rounded border ml-auto shrink-0", categoryColor[tool.category] ?? "bg-muted border-border text-muted-foreground")}>
                                    {tool.category}
                                  </span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Summary */}
            {includedConfigs.length > 0 && (
              <div className="bg-accent/30 rounded-lg px-3 py-2.5 text-xs text-muted-foreground">
                <span className="text-foreground font-medium">{includedConfigs.length}</span> asset{includedConfigs.length !== 1 ? "s" : ""} selected
                {!isClient && (
                  <>&nbsp;·&nbsp;{includedConfigs.map(c => `${c.toolIds.length} tool${c.toolIds.length !== 1 ? "s" : ""}`).join(", ")}</>
                )}
              </div>
            )}
          </div>
        ) : (
          /* Step 2: Schedule */
          <div className="flex-1 overflow-y-auto space-y-5 pr-1">
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={() => setScheduleMode("now")}
                className={cn("flex items-center gap-3 rounded-xl border p-4 text-left transition-colors",
                  scheduleMode === "now" ? "border-primary bg-primary/10" : "border-border hover:bg-accent/40")}
              >
                <Zap className={cn("w-5 h-5 shrink-0", scheduleMode === "now" ? "text-primary" : "text-muted-foreground")} />
                <div>
                  <p className="text-sm font-medium">Run Now</p>
                  <p className="text-xs text-muted-foreground">Execute immediately</p>
                </div>
              </button>
              <button
                onClick={() => { setScheduleMode("schedule"); setSaveSchedule(true); }}
                className={cn("flex items-center gap-3 rounded-xl border p-4 text-left transition-colors",
                  scheduleMode === "schedule" ? "border-primary bg-primary/10" : "border-border hover:bg-accent/40")}
              >
                <Calendar className={cn("w-5 h-5 shrink-0", scheduleMode === "schedule" ? "text-primary" : "text-muted-foreground")} />
                <div>
                  <p className="text-sm font-medium">Schedule</p>
                  <p className="text-xs text-muted-foreground">Set a recurring scan</p>
                </div>
              </button>
            </div>

            {scheduleMode === "now" && (
              <div className="flex items-start gap-2 bg-accent/30 rounded-lg p-3">
                <input
                  type="checkbox" id="also-schedule" checked={saveSchedule}
                  onChange={e => setSaveSchedule(e.target.checked)}
                  className="mt-0.5 accent-primary"
                />
                <label htmlFor="also-schedule" className="text-sm cursor-pointer">
                  Also save as a recurring schedule
                </label>
              </div>
            )}

            {(scheduleMode === "schedule" || saveSchedule) && (
              <div className="space-y-4 bg-card border border-border rounded-xl p-4">
                <div>
                  <Label className="text-xs mb-1.5 block">Schedule Name</Label>
                  <Input
                    placeholder="e.g. Daily Production Scan"
                    value={scheduleName}
                    onChange={e => setScheduleName(e.target.value)}
                    className="text-sm"
                  />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs mb-1.5 block">Frequency</Label>
                    <Select value={frequency} onValueChange={setFrequency}>
                      <SelectTrigger className="text-sm h-9">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="daily">Daily</SelectItem>
                        <SelectItem value="weekly">Weekly</SelectItem>
                        <SelectItem value="monthly">Monthly</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label className="text-xs mb-1.5 block flex items-center gap-1.5">
                      <Clock className="w-3 h-3" /> Time
                    </Label>
                    <Input type="time" value={runTime} onChange={e => setRunTime(e.target.value)} className="text-sm h-9" />
                  </div>
                </div>

                {frequency === "weekly" && (
                  <div>
                    <Label className="text-xs mb-1.5 block">Day of Week</Label>
                    <Select value={String(dayOfWeek)} onValueChange={v => setDayOfWeek(Number(v))}>
                      <SelectTrigger className="text-sm h-9">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {DAYS_OF_WEEK.map((d, i) => <SelectItem key={i} value={String(i)}>{d}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                {frequency === "monthly" && (
                  <div>
                    <Label className="text-xs mb-1.5 block">Day of Month</Label>
                    <Select value={String(dayOfMonth)} onValueChange={v => setDayOfMonth(Number(v))}>
                      <SelectTrigger className="text-sm h-9">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                          <SelectItem key={d} value={String(d)}>{d}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                  <Settings2 className="w-3 h-3" />
                  Applies to {includedConfigs.length} selected asset{includedConfigs.length !== 1 ? "s" : ""}
                </p>
              </div>
            )}
          </div>
        )}

        {!isRunning && (
          <DialogFooter className="mt-4 gap-2">
            {step === 1 ? (
              <>
                <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
                <Button onClick={() => setStep(2)} disabled={!canProceed} className="bg-primary/90 hover:bg-primary">
                  Next: Schedule <ChevronRight className="w-3.5 h-3.5 ml-1" />
                </Button>
              </>
            ) : (
              <>
                <Button variant="outline" onClick={() => setStep(1)}>← Back</Button>
                {scheduleMode === "schedule" ? (
                  <>
                    <Button variant="outline" onClick={() => handleRun(false)} disabled={isRunning}>
                      Save Schedule Only
                    </Button>
                    <Button onClick={() => handleRun(true)} disabled={isRunning} className="bg-primary/90 hover:bg-primary">
                      <Zap className="w-3.5 h-3.5 mr-1.5" />
                      Save & Run Now
                    </Button>
                  </>
                ) : (
                  <Button onClick={() => handleRun(saveSchedule)} disabled={isRunning} className="bg-primary/90 hover:bg-primary">
                    <Zap className="w-3.5 h-3.5 mr-1.5" />
                    {saveSchedule ? "Run Now & Save Schedule" : "Run Now"}
                  </Button>
                )}
              </>
            )}
          </DialogFooter>
        )}
      </DialogContent>
    </Dialog>
  );
}
