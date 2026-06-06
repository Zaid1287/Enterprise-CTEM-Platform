import { useState, useMemo, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import {
  useListAssets, useCreateAsset, useUpdateAsset, useDeleteAsset,
  useCheckAssetVerification, useVerifyAsset, useListUsers, useGetToolPipeline,
  useListScans, useStopScan, useRunPipelineScan, useCreateScanSchedule,
  getListAssetsQueryKey, getGetToolPipelineQueryKey, getListScansQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Plus, Search, Trash2, ExternalLink, RefreshCw, ShieldCheck,
  Zap, Square, Loader2, Pencil, Copy, CheckCircle2, XCircle, AlertTriangle, Globe,
  Shield, Server, Filter,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDate, riskLevelBg } from "@/lib/utils";
import { Link } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const ASSET_TYPES = ["domain", "subdomain", "url", "ip", "cidr", "api", "ssl_cert", "cloud_asset", "host", "mobile_app"];
const RISK_LEVELS = ["critical", "high", "medium", "low"];

const SCAN_FREQUENCIES = [
  { value: "manual",  label: "Manual only" },
  { value: "daily",   label: "Daily" },
  { value: "weekly",  label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];

const emptyForm = {
  name: "", type: "domain", value: "", description: "",
  scanFrequency: "manual",
  assignedClientId: undefined as number | undefined,
  assignedAccountManagerId: undefined as number | undefined,
};

type VerifyStep = "idle" | "token_shown" | "checking" | "verified" | "failed";

export default function AssetsPage() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const isClient = user?.role === "client";

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  // Create dialog
  const [showCreate, setShowCreate] = useState(false);
  const [newAsset, setNewAsset] = useState({ ...emptyForm });
  const [selectedToolIds, setSelectedToolIds] = useState<number[]>([]);
  const [runNow, setRunNow] = useState(false);

  // DNS verify state (client flow)
  const [verifyStep, setVerifyStep] = useState<VerifyStep>("idle");
  const [verifyToken, setVerifyToken] = useState("");
  const [verifyMsg, setVerifyMsg] = useState("");
  const [pendingAssetId, setPendingAssetId] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  // Edit dialog
  const [showEdit, setShowEdit] = useState(false);
  const [editingAsset, setEditingAsset] = useState<any>(null);
  const [editForm, setEditForm] = useState({ ...emptyForm });

  // Inline verify
  const [verifyingId, setVerifyingId] = useState<number | null>(null);
  const [stoppingId, setStoppingId] = useState<number | null>(null);
  const [showRunScan, setShowRunScan] = useState(false);
  const [preSelectedAssetIds, setPreSelectedAssetIds] = useState<number[]>([]);
  const [scanAssetId, setScanAssetId] = useState<number | null>(null);
  const [showScanConfirm, setShowScanConfirm] = useState(false);

  const queryClient = useQueryClient();

  const params = {
    search: search || undefined,
    type: typeFilter || undefined,
    verificationStatus: statusFilter || undefined,
  } as any;
  if (riskFilter) params.riskLevel = riskFilter;

  const { data: assets, isLoading } = useListAssets(params, {
    query: { queryKey: getListAssetsQueryKey(params) },
  });
  const { data: usersData } = useListUsers();
  const { data: pipelineData } = useGetToolPipeline({
    query: { queryKey: getGetToolPipelineQueryKey() },
  });
  const { data: scansData } = useListScans(
    { status: "running" } as any,
    { query: { queryKey: getListScansQueryKey({ status: "running" } as any), refetchInterval: 4000 } },
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
      for (const assetId of (scan.assetIds ?? [])) map[assetId] = scan.id;
    }
    return map;
  }, [runningScans]);

  // Auto-refresh asset list when all running scans finish (updates lastScannedAt + risk)
  const prevRunningCount = useRef(runningScans.length);
  useEffect(() => {
    if (prevRunningCount.current > 0 && runningScans.length === 0) {
      queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    }
    prevRunningCount.current = runningScans.length;
  }, [runningScans.length, queryClient]);

  const createAsset = useCreateAsset();
  const updateAsset = useUpdateAsset();
  const deleteAsset = useDeleteAsset();
  const verifyAsset = useVerifyAsset();
  const checkVerify = useCheckAssetVerification();
  const stopScan = useStopScan();
  const runPipeline = useRunPipelineScan();
  const createSchedule = useCreateScanSchedule();

  function resetCreateForm() {
    setNewAsset({ ...emptyForm });
    setSelectedToolIds([]);
    setRunNow(false);
    setVerifyStep("idle");
    setVerifyToken("");
    setVerifyMsg("");
    setPendingAssetId(null);
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload: any = {
      name: newAsset.name, type: newAsset.type, value: newAsset.value,
      scanFrequency: newAsset.scanFrequency,
      description: newAsset.description || undefined,
    };
    if (!isClient) {
      if (newAsset.assignedClientId) payload.assignedClientId = newAsset.assignedClientId;
      if (newAsset.assignedAccountManagerId) payload.assignedAccountManagerId = newAsset.assignedAccountManagerId;
    }
    const created = await createAsset.mutateAsync({ data: payload } as any);
    await queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    const newId = (created as any)?.id;

    // For domain/subdomain assets (client), show DNS TXT verify step
    if (isClient && newId && (newAsset.type === "domain" || newAsset.type === "subdomain" || newAsset.type === "url")) {
      setPendingAssetId(newId);
      await initiateDnsVerify(newId);
      return;
    }

    // Non-client: optionally run scan
    if (newId && runNow && selectedToolIds.length > 0) {
      const result = await runPipeline.mutateAsync({
        data: {
          name: `${newAsset.value} Scan Report – ${new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" })}`,
          assetToolConfig: [{ assetId: newId, toolIds: selectedToolIds }],
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
    toast({ title: "Asset added successfully" });
  };

  async function initiateDnsVerify(assetId: number) {
    setVerifyStep("token_shown");
    try {
      const res = await verifyAsset.mutateAsync({
        assetId,
        data: { method: "dns_txt" } as any,
      });
      setVerifyToken((res as any).challenge ?? "");
    } catch {
      setVerifyStep("idle");
      toast({ title: "Could not generate verification token", variant: "destructive" });
    }
  }

  async function checkDnsVerify() {
    if (!pendingAssetId) return;
    setVerifyStep("checking");
    try {
      const res = await checkVerify.mutateAsync({ assetId: pendingAssetId });
      if ((res as any).verified) {
        setVerifyStep("verified");
        setVerifyMsg((res as any).message ?? "Asset verified!");
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
      } else {
        setVerifyStep("failed");
        setVerifyMsg((res as any).message ?? "TXT record not found yet.");
      }
    } catch {
      setVerifyStep("failed");
      setVerifyMsg("Verification check failed. Please try again.");
    }
  }

  function copyToken() {
    navigator.clipboard.writeText(verifyToken).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingAsset) return;
    const payload: any = {
      name: editForm.name, type: editForm.type, value: editForm.value,
      description: editForm.description || undefined,
      scanFrequency: editForm.scanFrequency,
    };
    if (!isClient) {
      if (editForm.assignedClientId) payload.assignedClientId = editForm.assignedClientId;
      if (editForm.assignedAccountManagerId) payload.assignedAccountManagerId = editForm.assignedAccountManagerId;
    }
    await updateAsset.mutateAsync({ assetId: editingAsset.id, data: payload } as any);
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    setShowEdit(false);
    setEditingAsset(null);
    toast({ title: "Asset updated" });
  };

  function openEdit(asset: any) {
    setEditingAsset(asset);
    setEditForm({
      name: asset.name ?? "",
      type: asset.type ?? "domain",
      value: asset.value ?? "",
      description: asset.description ?? "",
      scanFrequency: asset.scanFrequency ?? "manual",
      assignedClientId: asset.assignedClientId,
      assignedAccountManagerId: asset.assignedAccountManagerId,
    });
    setShowEdit(true);
  }

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this asset? This will also remove associated findings and scan data.")) return;
    await deleteAsset.mutateAsync({ assetId: id });
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    toast({ title: "Asset deleted" });
  };

  const handleInlineVerify = async (asset: any) => {
    if (asset.type === "domain" || asset.type === "subdomain" || asset.type === "url") {
      setVerifyingId(asset.id);
      setPendingAssetId(asset.id);
      try {
        const res = await verifyAsset.mutateAsync({ assetId: asset.id, data: { method: "dns_txt" } as any });
        setVerifyToken((res as any).challenge ?? "");
        setVerifyStep("token_shown");
        setShowCreate(true);
        setNewAsset(prev => ({ ...prev, name: asset.name, type: asset.type, value: asset.value }));
      } finally {
        setVerifyingId(null);
      }
    } else {
      setVerifyingId(asset.id);
      try {
        await checkVerify.mutateAsync({ assetId: asset.id });
        queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
        toast({ title: "Asset verified" });
      } finally {
        setVerifyingId(null);
      }
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

  async function triggerScan(assetId: number) {
    const asset = allAssets.find((a: any) => a.id === assetId);
    if (!asset) return;
    try {
      const result = await runPipeline.mutateAsync({
        data: {
          name: `${asset.value} Scan Report – ${new Date().toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" })}`,
          assetToolConfig: [{ assetId, toolIds: enabledTools.map((t: any) => t.toolId) }],
        } as any,
      });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
      setShowScanConfirm(false);
      setScanAssetId(null);
      toast({ title: "Scan started", description: `Scanning ${asset.name}` });
      navigate(`/scan-reports/${(result as any).scanId}`);
    } catch {
      toast({ title: "Failed to start scan", variant: "destructive" });
    }
  }

  const activeFilters = [typeFilter, riskFilter, statusFilter].filter(Boolean).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Asset Inventory</h1>
          <p className="text-sm text-muted-foreground">{allAssets.length} asset{allAssets.length !== 1 ? "s" : ""} tracked</p>
        </div>
        <div className="flex items-center gap-2">
          {!isClient && (
            <Button
              size="sm" variant="outline"
              onClick={() => { setPreSelectedAssetIds(allAssets.map((a: any) => a.id)); setShowRunScan(true); }}
              disabled={allAssets.length === 0}
              className="border-primary/40 text-primary hover:bg-primary/10"
            >
              <Zap className="w-3.5 h-3.5 mr-1.5" /> Scan All
            </Button>
          )}
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> Add Asset
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by name…" className="pl-8 h-8 text-sm" />
        </div>
        <Select value={typeFilter || "_all_"} onValueChange={v => setTypeFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-34 h-8 text-sm"><SelectValue placeholder="All types" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All types</SelectItem>
            {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t.replace(/_/g, " "))}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={riskFilter || "_all_"} onValueChange={v => setRiskFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-32 h-8 text-sm"><SelectValue placeholder="Risk level" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All risks</SelectItem>
            {RISK_LEVELS.map(r => <SelectItem key={r} value={r}>{capitalize(r)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={statusFilter || "_all_"} onValueChange={v => setStatusFilter(v === "_all_" ? "" : v)}>
          <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="Verify status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All statuses</SelectItem>
            <SelectItem value="verified">Verified</SelectItem>
            <SelectItem value="pending">Pending</SelectItem>
            <SelectItem value="unverified">Unverified</SelectItem>
          </SelectContent>
        </Select>
        {(search || activeFilters > 0) && (
          <Button variant="outline" size="sm" className="h-8 gap-1.5" onClick={() => { setSearch(""); setTypeFilter(""); setRiskFilter(""); setStatusFilter(""); }}>
            <RefreshCw className="w-3.5 h-3.5" /> Clear
            {activeFilters > 0 && <span className="bg-primary text-primary-foreground text-[10px] rounded-full w-4 h-4 flex items-center justify-center">{activeFilters}</span>}
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-x-auto">
        <table className="w-full text-sm min-w-[900px]">
          <thead>
            <tr className="border-b border-border bg-accent/20">
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Risk Level</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Risk Score</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">IP / Port</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Vulnerabilities</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Last Scan</th>
              <th className="text-left px-3 py-2.5 text-xs font-medium text-muted-foreground">Scan</th>
              <th className="px-3 py-2.5 text-xs font-medium text-muted-foreground text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(5)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(11)].map((_, j) => <td key={j} className="px-3 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && allAssets.map((asset: any) => {
              const runningScanId = runningByAsset[asset.id];
              const isRunning = Boolean(runningScanId);
              const vulns = asset.vulnerabilities ?? {};
              const hasVulns = (vulns.total ?? 0) > 0;

              return (
                <tr key={asset.id} className="border-b border-border/50 hover:bg-accent/20 transition-colors">
                  {/* Asset name */}
                  <td className="px-3 py-3 max-w-[140px]">
                    <Link href={`/assets/${asset.id}`}>
                      <span className="font-medium text-primary hover:underline cursor-pointer block truncate">{asset.name}</span>
                    </Link>
                  </td>

                  {/* Type */}
                  <td className="px-3 py-3">
                    <TypeBadge type={asset.type} />
                  </td>

                  {/* Value */}
                  <td className="px-3 py-3 max-w-[160px]">
                    <span className="text-xs text-muted-foreground font-mono block truncate">{asset.value}</span>
                  </td>

                  {/* Risk Level */}
                  <td className="px-3 py-3">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium capitalize", riskLevelBg(asset.riskLevel))}>
                      {asset.riskLevel ?? "—"}
                    </span>
                  </td>

                  {/* Risk Score */}
                  <td className="px-3 py-3">
                    {asset.riskScore != null ? (
                      <div className="flex items-center gap-1.5">
                        <span className={cn(
                          "text-sm font-bold tabular-nums",
                          asset.riskScore >= 80 ? "text-red-400" :
                          asset.riskScore >= 60 ? "text-orange-400" :
                          asset.riskScore >= 40 ? "text-yellow-400" : "text-green-400",
                        )}>
                          {asset.riskScore}
                        </span>
                        <span className="text-[10px] text-muted-foreground">/100</span>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground/40">—</span>
                    )}
                  </td>

                  {/* Verification status */}
                  <td className="px-3 py-3">
                    <VerifyBadge status={asset.verificationStatus} />
                  </td>

                  {/* IP / Port */}
                  <td className="px-3 py-3">
                    {asset.ipAddress || asset.port ? (
                      <div className="text-xs text-muted-foreground font-mono">
                        {asset.ipAddress && <span className="block">{asset.ipAddress}</span>}
                        {asset.port && <span className="block text-[10px] opacity-70">:{asset.port}</span>}
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground/40">—</span>
                    )}
                  </td>

                  {/* Vulnerabilities */}
                  <td className="px-3 py-3">
                    {hasVulns ? (
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <Link href={`/findings?assetId=${asset.id}`}>
                          <span className="text-xs font-semibold text-foreground hover:underline cursor-pointer tabular-nums">
                            {vulns.total}
                          </span>
                        </Link>
                        {vulns.critical > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-medium tabular-nums">
                            {vulns.critical}C
                          </span>
                        )}
                        {vulns.high > 0 && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 font-medium tabular-nums">
                            {vulns.high}H
                          </span>
                        )}
                        {vulns.open > 0 && vulns.open < vulns.total && (
                          <span className="text-[10px] text-muted-foreground">{vulns.open} open</span>
                        )}
                      </div>
                    ) : (
                      <span className="text-xs text-green-500/80">Clean</span>
                    )}
                  </td>

                  {/* Last scan */}
                  <td className="px-3 py-3 text-xs text-muted-foreground whitespace-nowrap">
                    {asset.lastScannedAt ? formatDate(asset.lastScannedAt) : <span className="text-muted-foreground/40">Never</span>}
                  </td>

                  {/* Scan column */}
                  <td className="px-3 py-3">
                    {isRunning ? (
                      <div className="flex items-center gap-1.5">
                        <span className="flex items-center gap-1 text-xs text-blue-400 font-medium">
                          <Loader2 className="w-3 h-3 animate-spin" /> Scanning
                        </span>
                        <Button
                          size="sm" variant="destructive" className="h-6 px-2 text-xs"
                          disabled={stoppingId === runningScanId}
                          onClick={() => handleStop(runningScanId)}
                        >
                          <Square className="w-2.5 h-2.5 fill-current" />
                        </Button>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        className="h-7 px-2.5 text-xs bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20"
                        variant="ghost"
                        onClick={() => {
                          if (isClient) {
                            triggerScan(asset.id);
                          } else {
                            setScanAssetId(asset.id);
                            setShowScanConfirm(true);
                          }
                        }}
                        disabled={enabledTools.length === 0}
                      >
                        <Zap className="w-3 h-3 mr-1" /> Run Scan
                      </Button>
                    )}
                  </td>

                  {/* Actions */}
                  <td className="px-3 py-3">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-foreground"
                        onClick={() => openEdit(asset)} title="Edit"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </Button>
                      {asset.verificationStatus !== "verified" && (
                        <Button
                          variant="ghost" size="icon" className="h-7 w-7 text-amber-500 hover:text-amber-400"
                          disabled={verifyingId === asset.id}
                          onClick={() => handleInlineVerify(asset)}
                          title="Verify ownership"
                        >
                          {verifyingId === asset.id
                            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                            : <ShieldCheck className="w-3.5 h-3.5" />}
                        </Button>
                      )}
                      <Link href={`/assets/${asset.id}`}>
                        <Button variant="ghost" size="icon" className="h-7 w-7" title="View details">
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                      </Link>
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive/80"
                        onClick={() => handleDelete(asset.id)} title="Delete"
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
                <td colSpan={10} className="px-4 py-16 text-center">
                  <Globe className="w-10 h-10 text-muted-foreground/20 mx-auto mb-3" />
                  <p className="text-sm font-medium text-muted-foreground">No assets found</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    {search || activeFilters > 0 ? "Try adjusting your filters" : "Add your first asset to get started"}
                  </p>
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Add Asset Dialog ── */}
      <Dialog open={showCreate} onOpenChange={v => { if (!v) { setShowCreate(false); resetCreateForm(); } }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Asset</DialogTitle>
            <DialogDescription>
              {isClient ? "Add a domain or IP you own. Domain assets require DNS verification." : "Add an asset to monitor for vulnerabilities."}
            </DialogDescription>
          </DialogHeader>

          {/* DNS Verify flow (shown after client creates domain asset) */}
          {isClient && verifyStep !== "idle" ? (
            <DnsTxtVerifyPanel
              step={verifyStep}
              token={verifyToken}
              message={verifyMsg}
              assetValue={newAsset.value}
              copied={copied}
              onCopy={copyToken}
              onCheck={checkDnsVerify}
              onRetry={() => setVerifyStep("token_shown")}
              onDone={() => { setShowCreate(false); resetCreateForm(); }}
            />
          ) : (
            <form onSubmit={handleCreate} className="space-y-4 mt-1">
              <div className="space-y-1.5">
                <Label className="text-xs">Asset Name *</Label>
                <Input
                  value={newAsset.name}
                  onChange={e => setNewAsset(p => ({ ...p, name: e.target.value }))}
                  placeholder="My Website"
                  required className="h-9"
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Type *</Label>
                  <Select value={newAsset.type} onValueChange={v => setNewAsset(p => ({ ...p, type: v }))}>
                    <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t.replace(/_/g, " "))}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">
                    {newAsset.type === "ip" ? "IP Address" : newAsset.type === "url" ? "URL" : "Domain / Value"} *
                  </Label>
                  <Input
                    value={newAsset.value}
                    onChange={e => setNewAsset(p => ({ ...p, value: e.target.value }))}
                    placeholder={newAsset.type === "ip" ? "1.2.3.4" : newAsset.type === "url" ? "https://…" : "example.com"}
                    required className="h-9 font-mono text-sm"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Description (optional)</Label>
                <Input
                  value={newAsset.description}
                  onChange={e => setNewAsset(p => ({ ...p, description: e.target.value }))}
                  placeholder="e.g. Main production website"
                  className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={newAsset.scanFrequency} onValueChange={v => setNewAsset(p => ({ ...p, scanFrequency: v }))}>
                  <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_FREQUENCIES.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                  </SelectContent>
                </Select>
                {newAsset.scanFrequency !== "manual" && (
                  <p className="text-xs text-muted-foreground">
                    This asset will be scanned automatically on a <strong>{newAsset.scanFrequency}</strong> schedule.
                  </p>
                )}
              </div>

              {/* Admin/AM only fields */}
              {!isClient && (
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
                        {clients.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
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
                        {accountManagers.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              )}

              {/* Tools — admin only */}
              {!isClient && enabledTools.length > 0 && (
                <div className="space-y-2 border-t border-border pt-3">
                  <Label className="text-xs font-semibold flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-primary" /> Tools to run on this asset
                  </Label>
                  <div className="grid grid-cols-2 gap-1.5 max-h-32 overflow-y-auto pr-1">
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
                        <input
                          type="checkbox"
                          className="h-3.5 w-3.5 accent-current"
                          checked={selectedToolIds.includes(tool.toolId)}
                          onChange={() => setSelectedToolIds(prev =>
                            prev.includes(tool.toolId) ? prev.filter(id => id !== tool.toolId) : [...prev, tool.toolId],
                          )}
                        />
                        {tool.toolName}
                      </label>
                    ))}
                  </div>
                  {selectedToolIds.length > 0 && (
                    <label className="flex items-center gap-2 text-xs cursor-pointer text-muted-foreground hover:text-foreground pt-1">
                      <input type="checkbox" checked={runNow} onChange={e => setRunNow(e.target.checked)} className="h-3.5 w-3.5" />
                      Run scan immediately after adding
                    </label>
                  )}
                </div>
              )}

              {/* Client info box */}
              {isClient && (newAsset.type === "domain" || newAsset.type === "subdomain" || newAsset.type === "url") && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2.5 text-xs text-amber-400 flex items-start gap-2">
                  <Shield className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>After adding, you'll need to verify ownership by adding a DNS TXT record to your domain.</span>
                </div>
              )}

              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => { setShowCreate(false); resetCreateForm(); }}>Cancel</Button>
                <Button type="submit" disabled={createAsset.isPending}>
                  {createAsset.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
                  Add Asset
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      {/* ── Edit Dialog ── */}
      <Dialog open={showEdit} onOpenChange={v => { setShowEdit(v); if (!v) setEditingAsset(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Edit Asset</DialogTitle></DialogHeader>
          <form onSubmit={handleEdit} className="space-y-4 mt-1">
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name *</Label>
              <Input value={editForm.name} onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))} required className="h-9" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Type</Label>
                <Select value={editForm.type} onValueChange={v => setEditForm(p => ({ ...p, type: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t.replace(/_/g, " "))}</SelectItem>)}
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
            <div className="space-y-1.5">
              <Label className="text-xs">Scan Frequency</Label>
              <Select value={editForm.scanFrequency} onValueChange={v => setEditForm(p => ({ ...p, scanFrequency: v }))}>
                <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SCAN_FREQUENCIES.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                </SelectContent>
              </Select>
              {editForm.scanFrequency !== "manual" && (
                <p className="text-xs text-muted-foreground">
                  Auto-scans run <strong>{editForm.scanFrequency}</strong>. Next scan triggers automatically.
                </p>
              )}
            </div>
            {!isClient && (
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Assign Client</Label>
                  <Select
                    value={editForm.assignedClientId?.toString() ?? "_none_"}
                    onValueChange={v => setEditForm(p => ({ ...p, assignedClientId: v === "_none_" ? undefined : parseInt(v) }))}
                  >
                    <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="_none_">None</SelectItem>
                      {clients.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Account Manager</Label>
                  <Select
                    value={editForm.assignedAccountManagerId?.toString() ?? "_none_"}
                    onValueChange={v => setEditForm(p => ({ ...p, assignedAccountManagerId: v === "_none_" ? undefined : parseInt(v) }))}
                  >
                    <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="_none_">None</SelectItem>
                      {accountManagers.map((u: any) => <SelectItem key={u.id} value={u.id.toString()}>{u.firstName} {u.lastName}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowEdit(false)}>Cancel</Button>
              <Button type="submit" disabled={updateAsset.isPending}>
                {updateAsset.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
                Save Changes
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Scan Confirm Dialog ── */}
      <Dialog open={showScanConfirm} onOpenChange={v => { setShowScanConfirm(v); if (!v) setScanAssetId(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Run Scan</DialogTitle>
            <DialogDescription>
              This will trigger the enabled pipeline tools against{" "}
              <strong>{allAssets.find((a: any) => a.id === scanAssetId)?.name ?? "this asset"}</strong>.
              The scan may take several minutes.
            </DialogDescription>
          </DialogHeader>
          <div className="rounded-lg border border-border bg-accent/20 px-3 py-2.5 text-xs text-muted-foreground">
            <p className="font-medium text-foreground mb-1">Tools that will run:</p>
            {enabledTools.length > 0
              ? enabledTools.map((t: any) => <span key={t.toolId} className="inline-block bg-accent rounded px-1.5 py-0.5 mr-1 mb-1">{t.toolName}</span>)
              : <span>No tools enabled in pipeline. Enable tools in Security Tools settings.</span>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScanConfirm(false)}>Cancel</Button>
            <Button onClick={() => scanAssetId && triggerScan(scanAssetId)} disabled={enabledTools.length === 0}>
              <Zap className="w-4 h-4 mr-1.5" /> Start Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

// ── Sub-components ──

function TypeBadge({ type }: { type: string }) {
  const icons: Record<string, React.ElementType> = {
    domain: Globe, subdomain: Globe, url: Globe, ip: Server,
    host: Server, cidr: Server, cloud_asset: Shield, api: Zap,
  };
  const Icon = icons[type] ?? Globe;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground bg-accent/50 px-2 py-0.5 rounded">
      <Icon className="w-3 h-3" />
      {type.replace(/_/g, " ")}
    </span>
  );
}

function VerifyBadge({ status }: { status: string }) {
  const cfg = {
    verified:   { label: "Verified",   cls: "bg-green-500/15 text-green-400 border-green-500/30",  icon: CheckCircle2 },
    pending:    { label: "Pending",     cls: "bg-amber-500/15 text-amber-400 border-amber-500/30",  icon: Loader2 },
    unverified: { label: "Unverified",  cls: "bg-muted text-muted-foreground border-border",         icon: XCircle },
  }[status] ?? { label: status, cls: "bg-muted text-muted-foreground border-border", icon: AlertTriangle };
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md font-medium border", cfg.cls)}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function DnsTxtVerifyPanel({
  step, token, message, assetValue, copied, onCopy, onCheck, onRetry, onDone,
}: {
  step: VerifyStep;
  token: string;
  message: string;
  assetValue: string;
  copied: boolean;
  onCopy: () => void;
  onCheck: () => void;
  onRetry: () => void;
  onDone: () => void;
}) {
  const domain = assetValue.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];

  if (step === "verified") {
    return (
      <div className="py-6 text-center space-y-3">
        <CheckCircle2 className="w-12 h-12 text-green-400 mx-auto" />
        <p className="font-semibold">Domain Verified!</p>
        <p className="text-sm text-muted-foreground">{message}</p>
        <Button onClick={onDone} className="mt-2">Done</Button>
      </div>
    );
  }

  if (step === "failed") {
    return (
      <div className="py-4 space-y-4">
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-400">
          <XCircle className="w-4 h-4 inline mr-2" />
          {message}
        </div>
        <p className="text-xs text-muted-foreground">DNS changes can take up to 24 hours to propagate. Make sure the TXT record is saved correctly.</p>
        <div className="flex gap-2">
          <Button variant="outline" onClick={onRetry}>Show Instructions Again</Button>
          <Button onClick={onCheck} variant="outline">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Try Again
          </Button>
        </div>
        <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onDone}>
          Skip for now (verify later)
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4 py-2">
      <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
        <p className="font-semibold text-foreground">Verify domain ownership</p>
        <p className="text-xs text-muted-foreground">Your asset has been created. To enable scanning, verify you own <strong>{domain}</strong> by adding a DNS TXT record.</p>
      </div>

      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Step 1 — Add this TXT record to your DNS</p>
        <div className="rounded-lg border border-border bg-accent/20 p-3 space-y-2 text-xs font-mono">
          <div className="grid grid-cols-3 gap-2">
            <div>
              <p className="text-muted-foreground mb-0.5 font-sans">Type</p>
              <span className="text-foreground">TXT</span>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5 font-sans">Host / Name</p>
              <span className="text-foreground">{domain}</span>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5 font-sans">TTL</p>
              <span className="text-foreground">300</span>
            </div>
          </div>
          <div>
            <p className="text-muted-foreground mb-1 font-sans">Value</p>
            <div className="flex items-center gap-2 bg-background rounded px-2 py-1.5 border border-border">
              <span className="flex-1 truncate text-primary">{token || "Generating…"}</span>
              <Button size="sm" variant="ghost" className="h-6 px-2 shrink-0" onClick={onCopy}>
                {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
              </Button>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Step 2 — Verify the record</p>
        <p className="text-xs text-muted-foreground">After adding the TXT record, click verify. DNS propagation can take a few minutes.</p>
        <div className="flex gap-2">
          <Button onClick={onCheck} disabled={step === "checking" || !token}>
            {step === "checking"
              ? <><Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> Checking DNS…</>
              : <><ShieldCheck className="w-4 h-4 mr-1.5" /> Verify Domain</>}
          </Button>
          <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onDone}>
            Skip for now
          </Button>
        </div>
      </div>
    </div>
  );
}
