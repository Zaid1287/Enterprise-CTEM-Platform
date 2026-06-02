import { useState } from "react";
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
import { cn, statusBadgeClass, capitalize, formatDateTime, formatDate } from "@/lib/utils";

const SCAN_TYPES = ["passive", "active", "vulnerability", "full"];

function ScanStatusIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (status === "running") return <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />;
  if (status === "failed") return <AlertCircle className="w-4 h-4 text-red-400" />;
  return <Clock className="w-4 h-4 text-muted-foreground" />;
}

export default function ScansPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: "", type: "full", assetIds: [] as number[] });
  const queryClient = useQueryClient();

  const { data: scans, isLoading } = useListScans({} as any, {
    query: { queryKey: getListScansQueryKey({} as any) },
  });
  const { data: assets } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const createScan = useCreateScan();
  const cancelScan = useCancelScan();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.assetIds.length) {
      alert("Select at least one asset");
      return;
    }
    await createScan.mutateAsync({ data: form } as any);
    queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
    setShowCreate(false);
    setForm({ name: "", type: "full", assetIds: [] });
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
          <p className="text-sm text-muted-foreground">{Array.isArray(scans) ? scans.length : 0} total scans</p>
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
        {!isLoading && (scans as any[] ?? []).map((scan: any) => (
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
            <div className="flex gap-4 mt-3 text-xs text-muted-foreground">
              <span>Started: {formatDateTime(scan.startedAt)}</span>
              {scan.completedAt && <span>Completed: {formatDateTime(scan.completedAt)}</span>}
            </div>
          </div>
        ))}
        {!isLoading && (scans as any[] ?? []).length === 0 && (
          <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
            No scans yet. Create your first scan to start identifying vulnerabilities.
          </div>
        )}
      </div>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>Create Scan</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Scan Name</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} placeholder="Q1 Full Scan" required className="h-9" />
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
                {(assets as any[] ?? []).map((a: any) => (
                  <label key={a.id} className="flex items-center gap-2 px-3 py-2 hover:bg-accent/30 cursor-pointer">
                    <input type="checkbox" checked={form.assetIds.includes(a.id)} onChange={() => toggleAsset(a.id)} className="rounded" />
                    <span className="text-sm">{a.name}</span>
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
