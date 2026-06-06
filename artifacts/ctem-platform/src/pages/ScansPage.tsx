import { useState, useMemo } from "react";
import {
  useListScans, useCreateScan, useCancelScan,
  useListAssets, getListScansQueryKey, getListAssetsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, X, RefreshCw, CheckCircle2, Loader2, AlertCircle, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";

const SCAN_TYPES = ["passive", "active", "vulnerability", "full"];
const PAGE_SIZE = 10;

function ScanStatusIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (status === "running") return <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />;
  if (status === "failed") return <AlertCircle className="w-4 h-4 text-red-400" />;
  return <Clock className="w-4 h-4 text-muted-foreground" />;
}

function buildScanName(assetIds: number[], assetsList: any[]): string {
  const date = new Date().toLocaleDateString("en-US", { day: "numeric", month: "long", year: "numeric" });
  if (assetIds.length === 0) return `Scan Report – ${date}`;
  if (assetIds.length === 1) {
    const asset = assetsList.find(a => a.id === assetIds[0]);
    const label = asset?.value ?? asset?.name ?? `Asset #${assetIds[0]}`;
    return `${label} Scan Report – ${date}`;
  }
  const first = assetsList.find(a => a.id === assetIds[0]);
  const label = first?.value ?? first?.name ?? `Asset #${assetIds[0]}`;
  return `${label} +${assetIds.length - 1} more Scan Report – ${date}`;
}

export default function ScansPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [customName, setCustomName] = useState("");
  const [form, setForm] = useState({ type: "full", assetIds: [] as number[] });
  const [page, setPage] = useState(1);
  const queryClient = useQueryClient();

  const { data: scans, isLoading } = useListScans({} as any, {
    query: { queryKey: getListScansQueryKey({} as any) },
  });
  const { data: assets } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const createScan = useCreateScan();
  const cancelScan = useCancelScan();

  const assetsList = (assets as any[]) ?? [];
  const allScans = (scans as any[]) ?? [];

  // auto-generated name whenever selection changes
  const autoName = useMemo(
    () => buildScanName(form.assetIds, assetsList),
    [form.assetIds, assetsList],
  );
  const effectiveName = customName.trim() || autoName;

  const totalPages = Math.max(1, Math.ceil(allScans.length / PAGE_SIZE));
  const paginated = allScans.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.assetIds.length) {
      alert("Select at least one asset");
      return;
    }
    await createScan.mutateAsync({ data: { name: effectiveName, ...form } } as any);
    queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
    setShowCreate(false);
    setForm({ type: "full", assetIds: [] });
    setCustomName("");
  };

  const handleCancel = async (id: number) => {
    await cancelScan.mutateAsync({ scanId: id });
    queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
  };

  const toggleAsset = (id: number) => {
    setForm(prev => ({
      ...prev,
      assetIds: prev.assetIds.includes(id) ? prev.assetIds.filter(a => a !== id) : [...prev.assetIds, id],
    }));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Scan Management</h1>
          <p className="text-sm text-muted-foreground">{allScans.length} total scans</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries({ queryKey: getListScansQueryKey() })}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> New Scan
          </Button>
        </div>
      </div>

      <div className="grid gap-3">
        {isLoading && [...Array(3)].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
        {!isLoading && paginated.map((scan: any) => (
          <div key={scan.id} className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-3">
                <ScanStatusIcon status={scan.status} />
                <div>
                  <p className="text-sm font-medium">{scan.name}</p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs text-muted-foreground capitalize">{scan.type} scan</span>
                    <span className="text-muted-foreground/30">•</span>
                    <span className="text-xs text-muted-foreground">{scan.assetIds?.length ?? 0} assets</span>
                    <span className="text-muted-foreground/30">•</span>
                    <span className="text-xs text-muted-foreground">{scan.findingsCount} findings</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(scan.status))}>
                  {scan.status}
                </span>
                {(scan.status === "pending" || scan.status === "running") && (
                  <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => handleCancel(scan.id)}>
                    <X className="w-3 h-3 mr-1" /> Cancel
                  </Button>
                )}
              </div>
            </div>
            <div className="flex gap-4 mt-3 text-xs text-muted-foreground flex-wrap">
              <span>Started: {formatDateTime(scan.startedAt)}</span>
              {scan.completedAt && <span>Completed: {formatDateTime(scan.completedAt)}</span>}
              {scan.completedAt && scan.startedAt && (() => {
                const ms = new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime();
                const totalSec = Math.max(0, Math.round(ms / 1000));
                const dur = totalSec < 60 ? `${totalSec}s` : `${Math.floor(totalSec/60)}m ${totalSec%60}s`;
                return <span className="text-foreground font-medium">Duration: {dur}</span>;
              })()}
            </div>
          </div>
        ))}
        {!isLoading && allScans.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
            No scans yet. Create your first scan to start identifying vulnerabilities.
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <p className="text-xs text-muted-foreground">
            Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, allScans.length)} of {allScans.length} scans
          </p>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" className="h-7 w-7 p-0" disabled={page === 1} onClick={() => setPage(p => p - 1)}>‹</Button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
              <Button key={p} size="sm" variant={p === page ? "default" : "outline"} className="h-7 w-7 p-0 text-xs" onClick={() => setPage(p)}>{p}</Button>
            ))}
            <Button size="sm" variant="outline" className="h-7 w-7 p-0" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>›</Button>
          </div>
        </div>
      )}

      <Dialog open={showCreate} onOpenChange={v => { setShowCreate(v); if (!v) { setForm({ type: "full", assetIds: [] }); setCustomName(""); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>Create Scan</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Scan Name</Label>
              <Input
                value={customName}
                onChange={e => setCustomName(e.target.value)}
                placeholder={autoName}
                className="h-9"
              />
              {!customName && form.assetIds.length > 0 && (
                <p className="text-[10px] text-muted-foreground">Auto-generated: {autoName}</p>
              )}
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Scan Type</Label>
              <Select value={form.type} onValueChange={v => setForm(p => ({ ...p, type: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SCAN_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)} Scan</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Assets ({form.assetIds.length} selected)</Label>
              <div className="border border-border rounded-lg max-h-40 overflow-y-auto">
                {assetsList.map((a: any) => (
                  <label key={a.id} className="flex items-center gap-2 px-3 py-2 hover:bg-accent/30 cursor-pointer">
                    <input type="checkbox" checked={form.assetIds.includes(a.id)} onChange={() => toggleAsset(a.id)} className="rounded" />
                    <span className="text-sm">{a.value ?? a.name}</span>
                    <span className="text-xs text-muted-foreground ml-auto">{a.type}</span>
                  </label>
                ))}
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createScan.isPending}>{createScan.isPending ? "Creating..." : "Start Scan"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
