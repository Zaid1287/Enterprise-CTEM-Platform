import { useState, useMemo } from "react";
import { useLocation } from "wouter";

import {
  useListAssets, useCreateAsset, useDeleteAsset, useCheckAssetVerification,
  useListUsers, useGetToolPipeline, useListScans, useStopScan, useRunPipelineScan,
  getListAssetsQueryKey, getGetToolPipelineQueryKey, getListScansQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Search, Trash2, ExternalLink, RefreshCw, ShieldCheck, Zap, Square, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Checkbox } from "@/components/ui/checkbox";
import { cn, statusBadgeClass, capitalize, formatDate, riskLevelBg } from "@/lib/utils";
import { Link } from "wouter";
import RunScanDialog from "@/components/scan/RunScanDialog";

const ASSET_TYPES = ["domain", "subdomain", "url", "ip", "cidr", "api", "ssl_cert", "cloud_asset", "host", "mobile_app"];

const emptyForm = {
  name: "", type: "domain", value: "", description: "",
  assignedClientId: undefined as number | undefined,
  assignedAccountManagerId: undefined as number | undefined,
};

export default function AssetsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [newAsset, setNewAsset] = useState({ ...emptyForm });
  const [selectedToolIds, setSelectedToolIds] = useState<number[]>([]);
  const [runAfterAdd, setRunAfterAdd] = useState(false);
  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const [showRunScan, setShowRunScan] = useState(false);
  const [preSelectedAssetIds, setPreSelectedAssetIds] = useState<number[]>([]);
  const [stoppingId, setStoppingId] = useState<number | null>(null);
  const queryClient = useQueryClient();

  const params = { search: search || undefined, type: typeFilter || undefined };
  const { data: assets, isLoading } = useListAssets(params as any, {
    query: { queryKey: getListAssetsQueryKey(params as any) },
  });
  const { data: usersData } = useListUsers();
  const { data: pipelineData } = useGetToolPipeline({
    query: { queryKey: getGetToolPipelineQueryKey() },
  });
  const { data: scansData } = useListScans(
    { status: "running" } as any,
    { query: { queryKey: getListScansQueryKey({ status: "running" } as any), refetchInterval: 5000 } },
  );

  const users = (usersData as any[]) ?? [];
  const clients = users.filter((u: any) => u.role === "client");
  const accountManagers = users.filter((u: any) => u.role === "account_manager");
  const pipeline = (pipelineData as any[]) ?? [];
  const enabledTools = pipeline.filter((s: any) => s.isEnabled);
  const allAssets = (assets as any[]) ?? [];
  const runningScans = (scansData as any[]) ?? [];

  const runningByAsset = useMemo(() => {
    const map: Record<number, number> = {};
    for (const scan of runningScans) {
      for (const assetId of (scan.assetIds ?? [])) {
        map[assetId] = scan.id;
      }
    }
    return map;
  }, [runningScans]);

  const createAsset = useCreateAsset();
  const deleteAsset = useDeleteAsset();
  const verifyAsset = useCheckAssetVerification();
  const stopScan = useStopScan();
  const runPipeline = useRunPipelineScan();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: any = {
      name: newAsset.name,
      type: newAsset.type,
      value: newAsset.value,
      description: newAsset.description || undefined,
    };
    if (newAsset.assignedClientId) payload.assignedClientId = newAsset.assignedClientId;
    if (newAsset.assignedAccountManagerId) payload.assignedAccountManagerId = newAsset.assignedAccountManagerId;
    const created = await createAsset.mutateAsync({ data: payload } as any);
    await queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    setShowCreate(false);
    setNewAsset({ ...emptyForm });

    if (runAfterAdd && selectedToolIds.length > 0 && (created as any)?.id) {
      const newId = (created as any).id;
      const result = await runPipeline.mutateAsync({
        data: {
          name: `Scan – ${newAsset.name}`,
          assetToolConfigs: [{ assetId: newId, toolIds: selectedToolIds }],
        } as any,
      });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
      navigate(`/scan-reports/${(result as any).scanId}`);
    }

    setSelectedToolIds([]);
    setRunAfterAdd(false);
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this asset?")) return;
    await deleteAsset.mutateAsync({ assetId: id });
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
  };

  const handleVerify = async (id: number) => {
    setVerifyingId(id);
    try {
      await verifyAsset.mutateAsync({ assetId: id });
      queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    } finally {
      setVerifyingId(null);
    }
  };

  const handleStop = async (scanId: number) => {
    setStoppingId(scanId);
    try {
      await stopScan.mutateAsync({ scanId });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
    } finally {
      setStoppingId(null);
    }
  };

  function openRunScanOne(assetId: number) {
    setPreSelectedAssetIds([assetId]);
    setShowRunScan(true);
  }

  function openRunScanAll() {
    setPreSelectedAssetIds(allAssets.map((a: any) => a.id));
    setShowRunScan(true);
  }

  const pipelineTools = pipeline.map((s: any) => ({
    id: s.toolId, name: s.toolName, category: s.toolCategory, isActive: s.isEnabled,
  }));

  function toggleTool(toolId: number) {
    setSelectedToolIds(prev =>
      prev.includes(toolId) ? prev.filter(id => id !== toolId) : [...prev, toolId]
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Asset Inventory</h1>
          <p className="text-sm text-muted-foreground">{allAssets.length} assets tracked</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={openRunScanAll}
            disabled={allAssets.length === 0}
            className="border-primary/40 text-primary hover:bg-primary/10"
          >
            <Zap className="w-3.5 h-3.5 mr-1.5" /> Run Scan
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> Add Asset
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search assets..." className="pl-8 h-8 text-sm" />
        </div>
        <Select value={typeFilter || "_all_"} onValueChange={(v) => setTypeFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-sm">
            <SelectValue placeholder="All types" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All types</SelectItem>
            {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => { setSearch(""); setTypeFilter(""); }}>
          <RefreshCw className="w-3.5 h-3.5" />
        </Button>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Account Mgr</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Scan</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(9)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && allAssets.map((asset: any) => {
              const runningScanId = runningByAsset[asset.id];
              const isRunning = Boolean(runningScanId);
              return (
                <tr key={asset.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-2.5">
                    <Link href={`/assets/${asset.id}`}>
                      <span className="font-medium text-primary hover:underline cursor-pointer">{asset.name}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className="text-xs text-muted-foreground bg-accent/50 px-2 py-0.5 rounded">{asset.type}</span>
                  </td>
                  <td className="px-4 py-2.5 text-muted-foreground text-xs font-mono">{asset.value}</td>
                  <td className="px-4 py-2.5">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(asset.riskLevel))}>
                      {asset.riskLevel}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(asset.verificationStatus))}>
                      {asset.verificationStatus}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{asset.assignedClientName ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{asset.assignedAccountManagerName ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {isRunning
                      ? <span className="flex items-center gap-1 text-blue-400"><Loader2 className="w-3 h-3 animate-spin" /> Scanning…</span>
                      : formatDate(asset.lastScannedAt)
                    }
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1">
                      {isRunning ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-red-500 hover:text-red-400 hover:bg-red-500/10"
                          disabled={stoppingId === runningScanId}
                          onClick={() => handleStop(runningScanId)}
                        >
                          <Square className="w-3 h-3 mr-1 fill-current" />
                          {stoppingId === runningScanId ? "…" : "Stop"}
                        </Button>
                      ) : (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-primary hover:text-primary hover:bg-primary/10"
                          onClick={() => openRunScanOne(asset.id)}
                        >
                          <Zap className="w-3 h-3 mr-1" /> Run
                        </Button>
                      )}
                      {asset.verificationStatus !== "verified" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 px-2 text-xs text-green-500 hover:text-green-400 hover:bg-green-500/10"
                          disabled={verifyingId === asset.id}
                          onClick={() => handleVerify(asset.id)}
                        >
                          <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                          {verifyingId === asset.id ? "…" : "Verify"}
                        </Button>
                      )}
                      <Link href={`/assets/${asset.id}`}>
                        <Button variant="ghost" size="icon" className="h-7 w-7">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(asset.id)}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {!isLoading && allAssets.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-sm text-muted-foreground">
                  No assets found. Add your first asset to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Add Asset Dialog */}
      <Dialog open={showCreate} onOpenChange={(v) => { setShowCreate(v); if (!v) { setSelectedToolIds([]); setRunAfterAdd(false); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Add Asset</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name</Label>
              <Input value={newAsset.name} onChange={e => setNewAsset(p => ({ ...p, name: e.target.value }))} placeholder="Main Website" required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Type</Label>
              <Select value={newAsset.type} onValueChange={v => setNewAsset(p => ({ ...p, type: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Value (domain/IP/URL)</Label>
              <Input value={newAsset.value} onChange={e => setNewAsset(p => ({ ...p, value: e.target.value }))} placeholder="example.com" required className="h-9 font-mono text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input value={newAsset.description} onChange={e => setNewAsset(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Assign Client</Label>
                <Select
                  value={newAsset.assignedClientId?.toString() ?? "_none_"}
                  onValueChange={v => setNewAsset(p => ({ ...p, assignedClientId: v === "_none_" ? undefined : parseInt(v) }))}
                >
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {clients.map((u: any) => (
                      <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Account Manager</Label>
                <Select
                  value={newAsset.assignedAccountManagerId?.toString() ?? "_none_"}
                  onValueChange={v => setNewAsset(p => ({ ...p, assignedAccountManagerId: v === "_none_" ? undefined : parseInt(v) }))}
                >
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {accountManagers.map((u: any) => (
                      <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Tool Selection */}
            {enabledTools.length > 0 && (
              <div className="space-y-2 pt-1">
                <Label className="text-xs">Tools to run on this asset</Label>
                <div className="grid grid-cols-2 gap-1.5 max-h-36 overflow-y-auto pr-1">
                  {enabledTools.map((tool: any) => (
                    <label
                      key={tool.toolId}
                      className={cn(
                        "flex items-center gap-2 px-2.5 py-1.5 rounded-md border cursor-pointer text-xs transition-colors",
                        selectedToolIds.includes(tool.toolId)
                          ? "border-primary/50 bg-primary/10 text-primary"
                          : "border-border hover:border-border/80 hover:bg-accent/30 text-muted-foreground"
                      )}
                    >
                      <Checkbox
                        checked={selectedToolIds.includes(tool.toolId)}
                        onCheckedChange={() => toggleTool(tool.toolId)}
                        className="h-3.5 w-3.5"
                      />
                      {tool.toolName}
                    </label>
                  ))}
                </div>
                {selectedToolIds.length > 0 && (
                  <label className="flex items-center gap-2 cursor-pointer mt-1">
                    <Checkbox
                      checked={runAfterAdd}
                      onCheckedChange={(v) => setRunAfterAdd(Boolean(v))}
                      className="h-3.5 w-3.5"
                    />
                    <span className="text-xs text-muted-foreground">Run scan immediately after adding</span>
                  </label>
                )}
              </div>
            )}

            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createAsset.isPending || runPipeline.isPending}>
                {createAsset.isPending || runPipeline.isPending
                  ? (runPipeline.isPending ? "Starting scan…" : "Creating…")
                  : runAfterAdd && selectedToolIds.length > 0 ? "Add & Run Scan" : "Add Asset"
                }
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Run Scan Dialog */}
      <RunScanDialog
        open={showRunScan}
        onOpenChange={setShowRunScan}
        pipelineTools={pipelineTools}
        assets={allAssets.map((a: any) => ({ id: a.id, name: a.name, value: a.value, type: a.type }))}
        preSelectedAssetIds={preSelectedAssetIds}
        onRunComplete={scanId => navigate(`/scan-reports/${scanId}`)}
      />
    </div>
  );
}
