import { useState, useMemo } from "react";
import {
  useListScans, useCreateScan, useCancelScan,
  useListAssets, useListScanJobs, getListScansQueryKey, getListAssetsQueryKey, getListScanJobsQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient } from "@tanstack/react-query";
import {
  Plus, X, RefreshCw, CheckCircle2, Loader2, AlertCircle, Clock,
  ShieldAlert, ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const SCAN_TYPES = ["passive", "active", "vulnerability", "full"];
const PAGE_SIZE = 10;

const PIPELINE_PHASES = ["Passive Recon", "Port & SSL", "Tech & Screenshots", "Nuclei & Secrets", "Scoring"];

function ScanJobsProgress({ scanId }: { scanId: number }) {
  const { data: jobs } = useListScanJobs(scanId, {
    query: { queryKey: getListScanJobsQueryKey(scanId), refetchInterval: 5000 },
  });
  const list = (jobs as any[]) ?? [];
  if (list.length === 0) return null;
  const done    = list.filter((j: any) => j.status === "completed" || j.status === "failed").length;
  const running = list.filter((j: any) => j.status === "running").length;
  const total   = list.length;
  const pct     = total > 0 ? Math.round((done / total) * 100) : 0;

  // Infer current phase (1-5) from overall completion percentage
  const currentPhase = running > 0
    ? Math.min(5, Math.max(1, Math.ceil((pct / 100) * 5) || 1))
    : pct === 100 ? 5 : 0;

  return (
    <div className="mt-2 space-y-1.5">
      {/* Phase dots */}
      <div className="flex items-center gap-1">
        {PIPELINE_PHASES.map((label, i) => {
          const phaseNum = i + 1;
          const isComplete = pct === 100 || phaseNum < currentPhase;
          const isActive   = phaseNum === currentPhase && running > 0;
          return (
            <div key={label} className="flex items-center gap-1" title={`Phase ${phaseNum}: ${label}`}>
              <div className={cn(
                "w-2 h-2 rounded-full transition-all",
                isComplete ? "bg-green-400" : isActive ? "bg-yellow-400 animate-pulse" : "bg-muted",
              )} />
              {i < 4 && <div className={cn("w-4 h-px", isComplete ? "bg-green-400/40" : "bg-muted")} />}
            </div>
          );
        })}
        <span className="text-[10px] text-muted-foreground ml-1">
          {pct === 100 ? "Complete" : running > 0 ? `Phase ${currentPhase}: ${PIPELINE_PHASES[currentPhase - 1]}` : "Pending"}
        </span>
      </div>
      {/* Asset progress bar */}
      <div className="flex items-center gap-2">
        <div className="flex-1 h-1 bg-muted rounded-full overflow-hidden">
          <div className="h-full bg-primary rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
        </div>
        <span className="text-[10px] text-muted-foreground shrink-0">
          {running > 0 && <span className="text-blue-400 mr-1">{running} running ·</span>}
          {done}/{total} assets
        </span>
      </div>
    </div>
  );
}

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
  const [createError, setCreateError] = useState<{ message: string; unverified?: { id: number; name: string }[] } | null>(null);
  const [page, setPage] = useState(1);
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";
  const scanParams = isPrivileged && tenantFilter ? { tenantId: tenantFilter } : {};

  const { data: scans, isLoading } = useListScans(scanParams as any, {
    query: {
      queryKey: getListScansQueryKey(scanParams as any),
      refetchInterval: (q) => {
        const data = q.state.data as any[];
        if (data?.some((s: any) => s.status === "running" || s.status === "pending")) return 3000;
        return 30_000;
      },
      staleTime: 0,
    },
  });
  const { data: assets } = useListAssets({} as any, {
    query: { queryKey: getListAssetsQueryKey({} as any) },
  });
  const createScan = useCreateScan();
  const cancelScan = useCancelScan();

  const assetsList = (assets as any[]) ?? [];
  const allScans = (scans as any[]) ?? [];

  const autoName = useMemo(
    () => buildScanName(form.assetIds, assetsList),
    [form.assetIds, assetsList],
  );
  const effectiveName = customName.trim() || autoName;

  const totalPages = Math.max(1, Math.ceil(allScans.length / PAGE_SIZE));
  const paginated = allScans.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    if (!form.assetIds.length) {
      setCreateError({ message: "Select at least one asset to scan." });
      return;
    }
    try {
      await createScan.mutateAsync({ data: { name: effectiveName, ...form } } as any);
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
      setShowCreate(false);
      setForm({ type: "full", assetIds: [] });
      setCustomName("");
      setCreateError(null);
      toast({ title: "Scan started", description: effectiveName });
    } catch (err: any) {
      // Try to extract structured error from API response
      let msg = "Failed to start scan. Please try again.";
      let unverified: { id: number; name: string }[] | undefined;
      try {
        const body = err?.response ? await err.response.json() : err;
        if (body?.error) msg = body.error;
        if (body?.unverifiedAssets) unverified = body.unverifiedAssets;
      } catch {}
      setCreateError({ message: msg, unverified });
    }
  };

  const handleCancel = async (id: number) => {
    try {
      await cancelScan.mutateAsync({ scanId: id });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
      toast({ title: "Scan cancelled" });
    } catch {
      toast({ title: "Could not cancel scan", variant: "destructive" });
    }
  };

  const toggleAsset = (id: number, verified: boolean) => {
    if (!verified) {
      toast({
        title: "Asset not verified",
        description: "You must verify ownership of this asset before scanning it. Go to Assets → Verify.",
        variant: "destructive",
      });
      return;
    }
    setForm(prev => ({
      ...prev,
      assetIds: prev.assetIds.includes(id) ? prev.assetIds.filter(a => a !== id) : [...prev.assetIds, id],
    }));
  };

  const verifiedAssets = assetsList.filter((a: any) => a.verificationStatus === "verified");
  const unverifiedAssets = assetsList.filter((a: any) => a.verificationStatus !== "verified");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Scan Management</h1>
          <p className="text-sm text-muted-foreground">{allScans.length} total scans</p>
        </div>
        <div className="flex gap-2 items-center">
          {isPrivileged && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); setPage(1); }} />}
          <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries({ queryKey: getListScansQueryKey() })}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          <Button size="sm" onClick={() => { setCreateError(null); setShowCreate(true); }}>
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
            {(scan.status === "running" || scan.status === "pending") && (
              <ScanJobsProgress scanId={scan.id} />
            )}
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

      <Dialog open={showCreate} onOpenChange={v => {
        setShowCreate(v);
        if (!v) { setForm({ type: "full", assetIds: [] }); setCustomName(""); setCreateError(null); }
      }}>
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
              <Label className="text-xs">
                Assets ({form.assetIds.length} selected)
                {verifiedAssets.length === 0 && assetsList.length > 0 && (
                  <span className="ml-2 text-red-400 font-normal">— no verified assets</span>
                )}
              </Label>
              <div className="border border-border rounded-lg max-h-52 overflow-y-auto divide-y divide-border/40">
                {assetsList.length === 0 && (
                  <p className="text-xs text-muted-foreground px-3 py-4 text-center">No assets found. Add assets first.</p>
                )}
                {/* Verified assets */}
                {verifiedAssets.map((a: any) => (
                  <label key={a.id} className="flex items-center gap-2.5 px-3 py-2.5 hover:bg-accent/30 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={form.assetIds.includes(a.id)}
                      onChange={() => toggleAsset(a.id, true)}
                      className="rounded shrink-0"
                    />
                    <ShieldCheck className="w-3.5 h-3.5 text-green-400 shrink-0" />
                    <span className="text-sm flex-1 truncate">{a.value ?? a.name}</span>
                    <span className="text-xs text-muted-foreground shrink-0">{a.type}</span>
                  </label>
                ))}
                {/* Unverified assets — greyed out with tooltip */}
                {unverifiedAssets.map((a: any) => (
                  <div
                    key={a.id}
                    className="flex items-center gap-2.5 px-3 py-2.5 opacity-50 cursor-not-allowed"
                    title="Verify ownership before scanning"
                    onClick={() => toggleAsset(a.id, false)}
                  >
                    <input type="checkbox" disabled className="rounded shrink-0" />
                    <ShieldAlert className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                    <span className="text-sm flex-1 truncate">{a.value ?? a.name}</span>
                    <span className="text-[10px] text-amber-400 shrink-0 border border-amber-500/30 rounded px-1 py-0.5">Unverified</span>
                  </div>
                ))}
              </div>
              {unverifiedAssets.length > 0 && (
                <p className="text-[10px] text-amber-400/80 flex items-start gap-1">
                  <ShieldAlert className="w-3 h-3 mt-0.5 shrink-0" />
                  {unverifiedAssets.length} asset{unverifiedAssets.length !== 1 ? "s" : ""} need ownership verification before scanning.
                  Go to <strong>Assets</strong> → select the asset → <strong>Verify</strong>.
                </p>
              )}
            </div>

            {/* Error banner */}
            {createError && (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2.5 space-y-1.5">
                <p className="text-xs text-red-400 font-medium">{createError.message}</p>
                {createError.unverified && createError.unverified.length > 0 && (
                  <ul className="text-[11px] text-red-300/80 space-y-0.5 list-disc list-inside">
                    {createError.unverified.map(u => (
                      <li key={u.id}>{u.name ?? `Asset #${u.id}`}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button
                type="submit"
                disabled={createScan.isPending || form.assetIds.length === 0}
              >
                {createScan.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Starting…</> : "Start Scan"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
