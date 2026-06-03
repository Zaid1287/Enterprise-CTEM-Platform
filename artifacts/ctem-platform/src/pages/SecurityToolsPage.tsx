import { useState } from "react";
import {
  useListSecurityTools, useCreateSecurityTool, useDeleteSecurityTool, useUpdateSecurityTool,
  useRunSecurityTool, useGetToolPipeline, useSetToolPipeline, useListToolRuns, useGetToolRun,
  getListSecurityToolsQueryKey, getGetToolPipelineQueryKey, getListToolRunsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Plus, Trash2, Play, GitBranch, ChevronUp, ChevronDown, Settings2,
  Terminal, Clock, CheckCircle2, XCircle, RefreshCw, ExternalLink,
  ArrowRight, ToggleLeft, ToggleRight, Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn, capitalize, formatDateTime } from "@/lib/utils";

const CATEGORIES = ["recon", "vuln_scan", "port_scan", "ssl_check", "web_recon", "osint"];

const categoryColor: Record<string, string> = {
  recon: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  vuln_scan: "bg-red-500/15 text-red-400 border-red-500/30",
  port_scan: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  ssl_check: "bg-green-500/15 text-green-400 border-green-500/30",
  web_recon: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  osint: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const statusIcon = (status: string) => {
  if (status === "completed") return <CheckCircle2 className="w-4 h-4 text-green-500" />;
  if (status === "failed") return <XCircle className="w-4 h-4 text-red-500" />;
  if (status === "running") return <div className="w-3.5 h-3.5 border-2 border-primary border-t-transparent rounded-full animate-spin" />;
  return <Clock className="w-4 h-4 text-muted-foreground" />;
};

type Tab = "tools" | "pipeline" | "runs";

const emptyForm = { name: "", githubUrl: "", category: "recon", description: "", runCommand: "" };

export default function SecurityToolsPage() {
  const [tab, setTab] = useState<Tab>("tools");
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState({ ...emptyForm });
  const [runningId, setRunningId] = useState<number | null>(null);
  const [selectedRun, setSelectedRun] = useState<number | null>(null);
  const [pipelineDirty, setPipelineDirty] = useState(false);
  const [localPipeline, setLocalPipeline] = useState<any[]>([]);
  const qc = useQueryClient();

  const { data: toolsData, isLoading: toolsLoading } = useListSecurityTools();
  const { data: pipelineData, isLoading: pipelineLoading } = useGetToolPipeline({
    query: { queryKey: getGetToolPipelineQueryKey() },
  });
  const { data: runsData, isLoading: runsLoading } = useListToolRuns({}, {
    query: { queryKey: getListToolRunsQueryKey({}) },
  });
  const { data: runDetail } = useGetToolRun(selectedRun!, {
    query: { enabled: !!selectedRun },
  });

  const tools = (toolsData as any[]) ?? [];
  const pipeline = (pipelineData as any[]) ?? [];
  const runs = (runsData as any[]) ?? [];

  const createTool = useCreateSecurityTool();
  const deleteTool = useDeleteSecurityTool();
  const updateTool = useUpdateSecurityTool();
  const runTool = useRunSecurityTool();
  const setPipeline = useSetToolPipeline();

  // Sync local pipeline from server when tab changes or data loads
  const effectivePipeline = pipelineDirty ? localPipeline : pipeline;

  const handleAddTool = async (e: React.FormEvent) => {
    e.preventDefault();
    await createTool.mutateAsync({ data: { ...form } as any });
    qc.invalidateQueries({ queryKey: getListSecurityToolsQueryKey() });
    setShowAdd(false);
    setForm({ ...emptyForm });
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this tool? This will also remove it from the pipeline.")) return;
    await deleteTool.mutateAsync({ toolId: id });
    qc.invalidateQueries({ queryKey: getListSecurityToolsQueryKey() });
    qc.invalidateQueries({ queryKey: getGetToolPipelineQueryKey() });
  };

  const handleToggleActive = async (tool: any) => {
    await updateTool.mutateAsync({ toolId: tool.id, data: { isActive: !tool.isActive } as any });
    qc.invalidateQueries({ queryKey: getListSecurityToolsQueryKey() });
  };

  const handleRun = async (toolId: number) => {
    setRunningId(toolId);
    try {
      await runTool.mutateAsync({ toolId, data: {} as any });
      qc.invalidateQueries({ queryKey: getListToolRunsQueryKey({}) });
      setTab("runs");
    } finally {
      setRunningId(null);
    }
  };

  const initPipeline = () => {
    setLocalPipeline(pipeline.map(s => ({ ...s })));
    setPipelineDirty(true);
  };

  const movePipelineStep = (idx: number, dir: -1 | 1) => {
    if (!pipelineDirty) initPipeline();
    const arr = pipelineDirty ? [...localPipeline] : pipeline.map(s => ({ ...s }));
    const swap = idx + dir;
    if (swap < 0 || swap >= arr.length) return;
    [arr[idx], arr[swap]] = [arr[swap], arr[idx]];
    const reordered = arr.map((s, i) => ({ ...s, stepOrder: i + 1 }));
    setLocalPipeline(reordered);
    setPipelineDirty(true);
  };

  const togglePipelineStep = (idx: number) => {
    if (!pipelineDirty) initPipeline();
    const arr = pipelineDirty ? [...localPipeline] : pipeline.map(s => ({ ...s }));
    arr[idx] = { ...arr[idx], isEnabled: !arr[idx].isEnabled };
    setLocalPipeline(arr);
    setPipelineDirty(true);
  };

  const addToPipeline = async (tool: any) => {
    const steps = pipelineDirty ? localPipeline : pipeline;
    const alreadyIn = steps.some((s: any) => s.toolId === tool.id);
    if (alreadyIn) return;
    const newSteps = [...steps, {
      toolId: tool.id, toolName: tool.name, toolGithubUrl: tool.githubUrl,
      toolCategory: tool.category, stepOrder: steps.length + 1, isEnabled: true,
    }];
    setLocalPipeline(newSteps);
    setPipelineDirty(true);
  };

  const removeFromPipeline = (idx: number) => {
    const arr = pipelineDirty ? [...localPipeline] : pipeline.map(s => ({ ...s }));
    arr.splice(idx, 1);
    const reordered = arr.map((s, i) => ({ ...s, stepOrder: i + 1 }));
    setLocalPipeline(reordered);
    setPipelineDirty(true);
  };

  const savePipeline = async () => {
    await setPipeline.mutateAsync({
      data: {
        steps: effectivePipeline.map((s: any) => ({
          toolId: s.toolId,
          stepOrder: s.stepOrder,
          isEnabled: s.isEnabled,
        })),
      } as any,
    });
    qc.invalidateQueries({ queryKey: getGetToolPipelineQueryKey() });
    setPipelineDirty(false);
    setLocalPipeline([]);
  };

  const TABS: { key: Tab; label: string; icon: React.ElementType }[] = [
    { key: "tools", label: "Tool Library", icon: GitBranch },
    { key: "pipeline", label: "Pipeline", icon: Settings2 },
    { key: "runs", label: "Run History", icon: Terminal },
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Security Tools</h1>
          <p className="text-sm text-muted-foreground">Add GitHub-hosted tools, configure execution order, and run against assets</p>
        </div>
        {tab === "tools" && (
          <Button size="sm" onClick={() => setShowAdd(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> Add Tool
          </Button>
        )}
        {tab === "pipeline" && pipelineDirty && (
          <Button size="sm" onClick={savePipeline} disabled={setPipeline.isPending}>
            {setPipeline.isPending ? "Saving…" : "Save Pipeline"}
          </Button>
        )}
        {tab === "runs" && (
          <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: getListToolRunsQueryKey({}) })}>
            <RefreshCw className="w-3.5 h-3.5 mr-1" /> Refresh
          </Button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-accent/30 rounded-lg p-1 w-fit">
        {TABS.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-all",
              tab === t.key ? "bg-card text-foreground font-medium shadow-sm" : "text-muted-foreground hover:text-foreground"
            )}
          >
            <t.icon className="w-3.5 h-3.5" />
            {t.label}
            {t.key === "pipeline" && (
              <span className="ml-1 text-[10px] bg-primary/20 text-primary rounded-full px-1.5">{effectivePipeline.length}</span>
            )}
          </button>
        ))}
      </div>

      {/* ── Tool Library ── */}
      {tab === "tools" && (
        <div className="space-y-2">
          {toolsLoading && [...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
          {!toolsLoading && tools.length === 0 && (
            <div className="bg-card border border-border rounded-xl p-8 text-center">
              <GitBranch className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No tools yet. Add a GitHub-hosted security tool to get started.</p>
            </div>
          )}
          {tools.map((tool: any) => (
            <div key={tool.id} className="bg-card border border-border rounded-xl p-4 flex items-start gap-4">
              <div className="w-9 h-9 rounded-lg bg-accent/50 flex items-center justify-center shrink-0">
                <GitBranch className="w-4 h-4 text-primary" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="font-medium text-sm">{tool.name}</span>
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium", categoryColor[tool.category] ?? categoryColor.recon)}>
                    {tool.category}
                  </span>
                  {!tool.isActive && <span className="text-[10px] text-muted-foreground bg-accent/50 px-1.5 py-0.5 rounded">inactive</span>}
                </div>
                <a href={tool.githubUrl} target="_blank" rel="noopener noreferrer" className="text-xs text-primary hover:underline flex items-center gap-1">
                  <ExternalLink className="w-3 h-3" /> {tool.githubUrl}
                </a>
                {tool.description && <p className="text-xs text-muted-foreground mt-1">{tool.description}</p>}
                {tool.runCommand && (
                  <code className="text-[10px] font-mono bg-accent/60 text-foreground/80 px-1.5 py-0.5 rounded mt-1 inline-block">
                    {tool.runCommand}
                  </code>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Button
                  variant="ghost" size="sm"
                  className={cn("h-7 px-2 text-xs", tool.isActive ? "text-muted-foreground" : "text-green-500")}
                  onClick={() => handleToggleActive(tool)}
                  title={tool.isActive ? "Deactivate" : "Activate"}
                >
                  {tool.isActive ? <ToggleRight className="w-4 h-4 text-primary" /> : <ToggleLeft className="w-4 h-4" />}
                </Button>
                <Button
                  variant="ghost" size="sm"
                  className="h-7 px-2 text-xs text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                  onClick={() => { addToPipeline(tool); setTab("pipeline"); }}
                  title="Add to pipeline"
                >
                  <ArrowRight className="w-3.5 h-3.5 mr-1" /> Pipeline
                </Button>
                <Button
                  variant="ghost" size="sm"
                  className="h-7 px-2 text-xs text-green-500 hover:text-green-400 hover:bg-green-500/10"
                  disabled={runningId === tool.id || !tool.isActive}
                  onClick={() => handleRun(tool.id)}
                >
                  {runningId === tool.id
                    ? <div className="w-3.5 h-3.5 border-2 border-green-500 border-t-transparent rounded-full animate-spin mr-1" />
                    : <Play className="w-3.5 h-3.5 mr-1" />}
                  {runningId === tool.id ? "Running…" : "Run"}
                </Button>
                <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(tool.id)}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Pipeline ── */}
      {tab === "pipeline" && (
        <div className="space-y-3">
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-medium">Execution Order</h3>
                <p className="text-xs text-muted-foreground mt-0.5">Tools run in this sequence when executing a pipeline scan on an asset</p>
              </div>
              {pipelineDirty && (
                <span className="text-[10px] text-amber-400 bg-amber-500/10 border border-amber-500/30 px-2 py-1 rounded">Unsaved changes</span>
              )}
            </div>

            {pipelineLoading && [...Array(3)].map((_, i) => <Skeleton key={i} className="h-14 rounded-lg mb-2" />)}

            {!pipelineLoading && effectivePipeline.length === 0 && (
              <div className="text-center py-6 text-sm text-muted-foreground border border-dashed border-border rounded-lg">
                No tools in pipeline. Go to Tool Library and click <span className="font-medium text-foreground">→ Pipeline</span> to add them.
              </div>
            )}

            <div className="space-y-2">
              {effectivePipeline.map((step: any, idx: number) => (
                <div key={step.toolId} className={cn(
                  "flex items-center gap-3 bg-accent/20 border border-border rounded-lg px-3 py-2.5 transition-opacity",
                  !step.isEnabled && "opacity-50"
                )}>
                  <div className="flex flex-col gap-0.5">
                    <button onClick={() => movePipelineStep(idx, -1)} disabled={idx === 0}
                      className="text-muted-foreground hover:text-foreground disabled:opacity-20 disabled:cursor-not-allowed">
                      <ChevronUp className="w-3.5 h-3.5" />
                    </button>
                    <button onClick={() => movePipelineStep(idx, 1)} disabled={idx === effectivePipeline.length - 1}
                      className="text-muted-foreground hover:text-foreground disabled:opacity-20 disabled:cursor-not-allowed">
                      <ChevronDown className="w-3.5 h-3.5" />
                    </button>
                  </div>

                  <div className="w-7 h-7 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary shrink-0">
                    {idx + 1}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium">{step.toolName}</p>
                    <p className="text-[10px] text-muted-foreground truncate">{step.toolGithubUrl}</p>
                  </div>

                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium", categoryColor[step.toolCategory] ?? categoryColor.recon)}>
                    {step.toolCategory}
                  </span>

                  <button
                    onClick={() => togglePipelineStep(idx)}
                    className={cn("text-xs px-2 py-1 rounded transition-colors", step.isEnabled ? "text-green-500 hover:bg-green-500/10" : "text-muted-foreground hover:bg-accent")}
                    title={step.isEnabled ? "Disable step" : "Enable step"}
                  >
                    {step.isEnabled ? <ToggleRight className="w-4 h-4" /> : <ToggleLeft className="w-4 h-4" />}
                  </button>

                  <button onClick={() => removeFromPipeline(idx)} className="text-destructive hover:text-red-400 transition-colors">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Available tools not in pipeline */}
          {tools.filter((t: any) => !effectivePipeline.some((s: any) => s.toolId === t.id)).length > 0 && (
            <div className="bg-card border border-border rounded-xl p-4">
              <h3 className="text-sm font-medium mb-2 text-muted-foreground">Available tools (not in pipeline)</h3>
              <div className="flex flex-wrap gap-2">
                {tools.filter((t: any) => !effectivePipeline.some((s: any) => s.toolId === t.id)).map((tool: any) => (
                  <button
                    key={tool.id}
                    onClick={() => addToPipeline(tool)}
                    className="flex items-center gap-1.5 text-xs bg-accent/40 hover:bg-accent/80 border border-border rounded-lg px-2.5 py-1.5 transition-colors"
                  >
                    <Plus className="w-3 h-3" /> {tool.name}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Run History ── */}
      {tab === "runs" && (
        <div className="flex gap-4">
          <div className="flex-1 bg-card border border-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tool</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Started</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Duration</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {runsLoading && [...Array(5)].map((_, i) => (
                  <tr key={i} className="border-b border-border/50">
                    {[...Array(6)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
                  </tr>
                ))}
                {!runsLoading && runs.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-sm text-muted-foreground">
                      No runs yet. Run a tool from the Tool Library.
                    </td>
                  </tr>
                )}
                {runs.map((run: any) => {
                  const duration = run.startedAt && run.completedAt
                    ? `${((new Date(run.completedAt).getTime() - new Date(run.startedAt).getTime()) / 1000).toFixed(1)}s`
                    : "—";
                  return (
                    <tr
                      key={run.id}
                      className={cn("border-b border-border/50 hover:bg-accent/30 transition-colors cursor-pointer", selectedRun === run.id && "bg-accent/40")}
                      onClick={() => setSelectedRun(run.id === selectedRun ? null : run.id)}
                    >
                      <td className="px-4 py-2.5 font-medium">{run.toolName}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{run.assetName ?? "—"}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          {statusIcon(run.status)}
                          <span className="text-xs capitalize">{run.status}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{run.startedAt ? formatDateTime(run.startedAt) : "—"}</td>
                      <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground">{duration}</td>
                      <td className="px-4 py-2.5">
                        <Button variant="ghost" size="icon" className="h-7 w-7">
                          <Eye className="w-3.5 h-3.5" />
                        </Button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Output panel */}
          {selectedRun && (
            <div className="w-[420px] shrink-0 bg-card border border-border rounded-xl flex flex-col">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-primary" />
                  <span className="text-sm font-medium">Run Output</span>
                </div>
                <button onClick={() => setSelectedRun(null)} className="text-muted-foreground hover:text-foreground text-xs">✕</button>
              </div>
              {runDetail && (
                <div className="flex-1 p-3 overflow-auto">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs font-medium">{(runDetail as any).toolName}</span>
                    {(runDetail as any).assetName && (
                      <span className="text-[10px] text-muted-foreground">→ {(runDetail as any).assetName}</span>
                    )}
                    <span className="ml-auto">{statusIcon((runDetail as any).status)}</span>
                  </div>
                  <pre className="text-[11px] font-mono leading-5 text-green-400/90 bg-black/40 rounded-lg p-3 overflow-auto whitespace-pre-wrap max-h-[500px]">
                    {(runDetail as any).output ?? "No output"}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Add Tool Dialog */}
      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>Add Security Tool</DialogTitle></DialogHeader>
          <form onSubmit={handleAddTool} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Tool Name *</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="e.g. Nuclei, Subfinder, Nmap" required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">GitHub URL *</Label>
              <Input value={form.githubUrl} onChange={e => setForm(p => ({ ...p, githubUrl: e.target.value }))} placeholder="https://github.com/projectdiscovery/nuclei" required className="h-9 font-mono text-xs" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Category</Label>
              <Select value={form.category} onValueChange={v => setForm(p => ({ ...p, category: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {CATEGORIES.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Run Command (optional)</Label>
              <Input value={form.runCommand} onChange={e => setForm(p => ({ ...p, runCommand: e.target.value }))} placeholder="nuclei -u {target} -t cves/" className="h-9 font-mono text-xs" />
              <p className="text-[10px] text-muted-foreground">Use <code className="bg-accent px-1 rounded">{"{target}"}</code> as placeholder for the asset value</p>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} className="h-16 resize-none text-xs" placeholder="What does this tool do?" />
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowAdd(false)}>Cancel</Button>
              <Button type="submit" disabled={createTool.isPending}>{createTool.isPending ? "Adding…" : "Add Tool"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
