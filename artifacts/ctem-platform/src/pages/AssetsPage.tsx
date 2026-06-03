import { useState, useMemo } from "react";
import { useLocation } from "wouter";

import {
  useListAssets, useCreateAsset, useUpdateAsset, useDeleteAsset,
  useCheckAssetVerification, useListUsers, useGetToolPipeline,
  useListScans, useStopScan, useRunPipelineScan, useCreateScanSchedule,
  getListAssetsQueryKey, getGetToolPipelineQueryKey,
  getListScansQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Plus, Search, Trash2, ExternalLink, RefreshCw, ShieldCheck,
  Zap, Square, Loader2, Pencil, Clock, CalendarDays,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Checkbox } from "@/components/ui/checkbox";
import { cn, statusBadgeClass, capitalize, formatDate, riskLevelBg } from "@/lib/utils";
import { Link } from "wouter";
import RunScanDialog from "@/components/scan/RunScanDialog";

const ASSET_TYPES = ["domain", "subdomain", "url", "ip", "cidr", "api", "ssl_cert", "cloud_asset", "host", "mobile_app"];
const DAYS_OF_WEEK = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

const emptyForm = {
  name: "", type: "domain", value: "", description: "",
  assignedClientId: undefined as number | undefined,
  assignedAccountManagerId: undefined as number | undefined,
};

export default function AssetsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  // Create dialog
  const [showCreate, setShowCreate] = useState(false);
  const [newAsset, setNewAsset] = useState({ ...emptyForm });
  const [selectedToolIds, setSelectedToolIds] = useState<number[]>([]);
  const [runNow, setRunNow] = useState(false);
  const [schedFrequency, setSchedFrequency] = useState<"" | "daily" | "weekly" | "monthly">("");
  const [schedTime, setSchedTime] = useState("09:00");
  const [schedDayOfWeek, setSchedDayOfWeek] = useState(1);
  const [schedDayOfMonth, setSchedDayOfMonth] = useState(1);

  // Edit dialog
  const [showEdit, setShowEdit] = useState(false);
  const [editingAsset, setEditingAsset] = useState<any>(null);
  const [editForm, setEditForm] = useState({ ...emptyForm });

  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const [stoppingId, setStoppingId] = useState<number | null>(null);
  const [showRunScan, setShowRunScan] = useState(false);
  const [preSelectedAssetIds, setPreSelectedAssetIds] = useState<number[]>([]);
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

  // Map assetId → running scanId
  const runningByAsset = useMemo(() => {
    const map: Record<number, number> = {};
    for (const scan of runningScans) {
      for (const assetId of (scan.assetIds ?? [])) {
        map[assetId] = scan.id;
      }
    }
    return map;
  }, [runningScans]);

  const pipelineTools = pipeline.map((s: any) => ({
    id: s.toolId, name: s.toolName, category: s.toolCategory, isActive: s.isEnabled,
  }));

  const createAsset = useCreateAsset();
  const updateAsset = useUpdateAsset();
  const deleteAsset = useDeleteAsset();
  const verifyAsset = useCheckAssetVerification();
  const stopScan = useStopScan();
  const runPipeline = useRunPipelineScan();
  const createSchedule = useCreateScanSchedule();

  function resetCreateForm() {
    setNewAsset({ ...emptyForm });
    setSelectedToolIds([]);
    setRunNow(false);
    setSchedFrequency("");
    setSchedTime("09:00");
    setSchedDayOfWeek(1);
    setSchedDayOfMonth(1);
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: any = {
      name: newAsset.name, type: newAsset.type, value: newAsset.value,
      description: newAsset.description || undefined,
    };
    if (newAsset.assignedClientId) payload.assignedClientId = newAsset.assignedClientId;
    if (newAsset.assignedAccountManagerId) payload.assignedAccountManagerId = newAsset.assignedAccountManagerId;
    const created = await createAsset.mutateAsync({ data: payload } as any);
    await queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    const newId = (created as any)?.id;

    // Create schedule if frequency selected
    if (newId && selectedToolIds.length > 0 && schedFrequency) {
      await createSchedule.mutateAsync({
        data: {
          name: `${newAsset.name} – ${schedFrequency}`,
          assetToolConfig: [{ assetId: newId, toolIds: selectedToolIds }],
          frequency: schedFrequency,
          runTime: schedTime,
          dayOfWeek: schedFrequency === "weekly" ? schedDayOfWeek : undefined,
          dayOfMonth: schedFrequency === "monthly" ? schedDayOfMonth : undefined,
        } as any,
      });
    }

    // Run immediately if requested
    if (newId && runNow && selectedToolIds.length > 0) {
      const result = await runPipeline.mutateAsync({
        data: {
          name: `Scan – ${newAsset.name}`,
          assetToolConfigs: [{ assetId: newId, toolIds: selectedToolIds }],
        } as any,
      });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
      setShowCreate(false);
      resetCreateForm();
      navigate(`/scan-reports/${(result as any).scanId}`);
      return;
    }

    setShowCreate(false);
    resetCreateForm();
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingAsset) return;
    const payload: any = {
      name: editForm.name, type: editForm.type, value: editForm.value,
      description: editForm.description || undefined,
    };
    if (editForm.assignedClientId) payload.assignedClientId = editForm.assignedClientId;
    if (editForm.assignedAccountManagerId) payload.assignedAccountManagerId = editForm.assignedAccountManagerId;
    await updateAsset.mutateAsync({ assetId: editingAsset.id, data: payload } as any);
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    setShowEdit(false);
    setEditingAsset(null);
  };

  function openEdit(asset: any) {
    setEditingAsset(asset);
    setEditForm({
      name: asset.name ?? "",
      type: asset.type ?? "domain",
      value: asset.value ?? "",
      description: asset.description ?? "",
      assignedClientId: asset.assignedClientId,
      assignedAccountManagerId: asset.assignedAccountManagerId,
    });
    setShowEdit(true);
  }

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

  function toggleTool(toolId: number) {
    setSelectedToolIds(prev =>
      prev.includes(toolId) ? prev.filter(id => id !== toolId) : [...prev, toolId],
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Asset Inventory</h1>
          <p className="text-sm text-muted-foreground">{allAssets.length} assets tracked</p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm" variant="outline"
            onClick={() => { setPreSelectedAssetIds(allAssets.map((a: any) => a.id)); setShowRunScan(true); }}
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
          <Input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search assets…" className="pl-8 h-8 text-sm" />
        </div>
        <Select value={typeFilter || "_all_"} onValueChange={v => setTypeFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="All types" /></SelectTrigger>
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
            <tr className="border-b border-border bg-accent/20">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Scan</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Scan</th>
              <th className="px-4 py-2.5 text-xs font-medium text-muted-foreground text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(8)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && allAssets.map((asset: any) => {
              const runningScanId = runningByAsset[asset.id];
              const isRunning = Boolean(runningScanId);
              return (
                <tr key={asset.id} className="border-b border-border/50 hover:bg-accent/20 transition-colors">
                  <td className="px-4 py-3">
                    <Link href={`/assets/${asset.id}`}>
                      <span className="font-medium text-primary hover:underline cursor-pointer">{asset.name}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-muted-foreground bg-accent/50 px-2 py-0.5 rounded">{asset.type}</span>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground text-xs font-mono max-w-[160px] truncate">{asset.value}</td>
                  <td className="px-4 py-3">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(asset.riskLevel))}>
                      {asset.riskLevel}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(asset.verificationStatus))}>
                      {asset.verificationStatus}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                    {formatDate(asset.lastScannedAt)}
                  </td>

                  {/* Scan column */}
                  <td className="px-4 py-3">
                    {isRunning ? (
                      <div className="flex items-center gap-2">
                        <span className="flex items-center gap-1.5 text-xs text-blue-400 font-medium">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Scanning…
                        </span>
                        <Button
                          size="sm"
                          variant="destructive"
                          className="h-7 px-2.5 text-xs"
                          disabled={stoppingId === runningScanId}
                          onClick={() => handleStop(runningScanId)}
                        >
                          <Square className="w-3 h-3 mr-1 fill-current" />
                          {stoppingId === runningScanId ? "…" : "Stop"}
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        className="h-7 px-2.5 text-xs bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25"
                        variant="ghost"
                        onClick={() => { setPreSelectedAssetIds([asset.id]); setShowRunScan(true); }}
                      >
                        <Zap className="w-3 h-3 mr-1" /> Run Scan
                      </Button>
                    )}
                  </td>

                  {/* Actions column */}
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-foreground"
                        onClick={() => openEdit(asset)}
                        title="Edit asset"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </Button>
                      {asset.verificationStatus !== "verified" && (
                        <Button
                          variant="ghost" size="icon" className="h-7 w-7 text-green-500 hover:text-green-400"
                          disabled={verifyingId === asset.id}
                          onClick={() => handleVerify(asset.id)}
                          title="Verify asset"
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                        </Button>
                      )}
                      <Link href={`/assets/${asset.id}`}>
                        <Button variant="ghost" size="icon" className="h-7 w-7" title="View details">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                        onClick={() => handleDelete(asset.id)}
                        title="Delete asset"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {!isLoading && allAssets.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-10 text-center text-sm text-muted-foreground">
                  No assets found. Add your first asset to get started.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Add Asset Dialog ── */}
      <Dialog open={showCreate} onOpenChange={v => { setShowCreate(v); if (!v) resetCreateForm(); }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader><DialogTitle>Add Asset</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-4 mt-1">
            {/* Basic fields */}
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name</Label>
              <Input value={newAsset.name} onChange={e => setNewAsset(p => ({ ...p, name: e.target.value }))} placeholder="Main Website" required className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
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
                <Label className="text-xs">Value (domain / IP / URL)</Label>
                <Input value={newAsset.value} onChange={e => setNewAsset(p => ({ ...p, value: e.target.value }))} placeholder="example.com" required className="h-9 font-mono text-sm" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input value={newAsset.description} onChange={e => setNewAsset(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Assign Client</Label>
                <Select value={newAsset.assignedClientId?.toString() ?? "_none_"} onValueChange={v => setNewAsset(p => ({ ...p, assignedClientId: v === "_none_" ? undefined : parseInt(v) }))}>
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {clients.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Account Manager</Label>
                <Select value={newAsset.assignedAccountManagerId?.toString() ?? "_none_"} onValueChange={v => setNewAsset(p => ({ ...p, assignedAccountManagerId: v === "_none_" ? undefined : parseInt(v) }))}>
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {accountManagers.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Tool selection */}
            {enabledTools.length > 0 && (
              <div className="space-y-2 border-t border-border pt-3">
                <Label className="text-xs font-semibold flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-primary" /> Tools to run on this asset
                </Label>
                <div className="grid grid-cols-2 gap-1.5 max-h-36 overflow-y-auto pr-1">
                  {enabledTools.map((tool: any) => (
                    <label
                      key={tool.toolId}
                      className={cn(
                        "flex items-center gap-2 px-2.5 py-1.5 rounded-md border cursor-pointer text-xs transition-colors",
                        selectedToolIds.includes(tool.toolId)
                          ? "border-primary/50 bg-primary/10 text-primary"
                          : "border-border hover:bg-accent/30 text-muted-foreground",
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

                {/* Schedule — only shown when at least one tool selected */}
                {selectedToolIds.length > 0 && (
                  <div className="space-y-3 pt-2">
                    {/* Frequency */}
                    <div className="space-y-1.5">
                      <Label className="text-xs flex items-center gap-1.5">
                        <CalendarDays className="w-3.5 h-3.5" /> Scan Frequency
                      </Label>
                      <Select value={schedFrequency || "_none_"} onValueChange={v => setSchedFrequency(v === "_none_" ? "" : v as any)}>
                        <SelectTrigger className="h-9 text-sm"><SelectValue placeholder="No schedule (manual only)" /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="_none_">No schedule (manual only)</SelectItem>
                          <SelectItem value="daily">Daily</SelectItem>
                          <SelectItem value="weekly">Weekly</SelectItem>
                          <SelectItem value="monthly">Monthly</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    {/* Time + day — shown when frequency is set */}
                    {schedFrequency && (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                          <div className="space-y-1.5">
                            <Label className="text-xs flex items-center gap-1.5">
                              <Clock className="w-3.5 h-3.5" /> Run Time
                            </Label>
                            <Input
                              type="time"
                              value={schedTime}
                              onChange={e => setSchedTime(e.target.value)}
                              className="h-9"
                            />
                          </div>
                          {schedFrequency === "weekly" && (
                            <div className="space-y-1.5">
                              <Label className="text-xs">Day of Week</Label>
                              <Select value={schedDayOfWeek.toString()} onValueChange={v => setSchedDayOfWeek(parseInt(v))}>
                                <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                  {DAYS_OF_WEEK.map((d, i) => <SelectItem key={i} value={i.toString()}>{d}</SelectItem>)}
                                </SelectContent>
                              </Select>
                            </div>
                          )}
                          {schedFrequency === "monthly" && (
                            <div className="space-y-1.5">
                              <Label className="text-xs">Day of Month</Label>
                              <Select value={schedDayOfMonth.toString()} onValueChange={v => setSchedDayOfMonth(parseInt(v))}>
                                <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                                <SelectContent>
                                  {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                                    <SelectItem key={d} value={d.toString()}>Day {d}</SelectItem>
                                  ))}
                                </SelectContent>
                              </Select>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Run now checkbox */}
                    <label className="flex items-center gap-2 cursor-pointer">
                      <Checkbox checked={runNow} onCheckedChange={v => setRunNow(Boolean(v))} className="h-3.5 w-3.5" />
                      <span className="text-xs text-muted-foreground">Also run scan immediately after adding</span>
                    </label>
                  </div>
                )}
              </div>
            )}

            <DialogFooter className="mt-2">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createAsset.isPending || runPipeline.isPending || createSchedule.isPending}>
                {(createAsset.isPending || runPipeline.isPending || createSchedule.isPending)
                  ? "Saving…"
                  : runNow && selectedToolIds.length > 0
                    ? "Add & Run Scan"
                    : schedFrequency && selectedToolIds.length > 0
                      ? "Add & Schedule"
                      : "Add Asset"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Edit Asset Dialog ── */}
      <Dialog open={showEdit} onOpenChange={v => { setShowEdit(v); if (!v) setEditingAsset(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Edit Asset</DialogTitle></DialogHeader>
          <form onSubmit={handleEdit} className="space-y-3 mt-1">
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name</Label>
              <Input value={editForm.name} onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))} required className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Type</Label>
                <Select value={editForm.type} onValueChange={v => setEditForm(p => ({ ...p, type: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Value</Label>
                <Input value={editForm.value} onChange={e => setEditForm(p => ({ ...p, value: e.target.value }))} required className="h-9 font-mono text-sm" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Description</Label>
              <Input value={editForm.description} onChange={e => setEditForm(p => ({ ...p, description: e.target.value }))} className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Assign Client</Label>
                <Select value={editForm.assignedClientId?.toString() ?? "_none_"} onValueChange={v => setEditForm(p => ({ ...p, assignedClientId: v === "_none_" ? undefined : parseInt(v) }))}>
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {clients.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Account Manager</Label>
                <Select value={editForm.assignedAccountManagerId?.toString() ?? "_none_"} onValueChange={v => setEditForm(p => ({ ...p, assignedAccountManagerId: v === "_none_" ? undefined : parseInt(v) }))}>
                  <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {accountManagers.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <DialogFooter className="mt-3">
              <Button variant="outline" type="button" onClick={() => setShowEdit(false)}>Cancel</Button>
              <Button type="submit" disabled={updateAsset.isPending}>{updateAsset.isPending ? "Saving…" : "Save Changes"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Run Scan Dialog (multi-asset) ── */}
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
