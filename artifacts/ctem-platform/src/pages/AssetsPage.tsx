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
  Shield, Server, Filter, Cloud, Lock, Smartphone, Network, Code2, Cpu,
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
const ASSET_TYPES = ["domain", "subdomain", "url", "ip", "cidr", "api", "ssl_cert", "cloud_asset", "host", "mobile_app", "sentinelware"];
const RISK_LEVELS = ["critical", "high", "medium", "low"];

const SCAN_FREQUENCIES = [
  { value: "manual",  label: "Manual only" },
  { value: "daily",   label: "Daily" },
  { value: "weekly",  label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];

const TYPE_CONFIG: Record<string, { label: string; valueLabel: string; valuePlaceholder: string; needsVerify: boolean }> = {
  domain:       { label: "Domain",           valueLabel: "Domain",             valuePlaceholder: "example.com",                needsVerify: true  },
  subdomain:    { label: "Subdomain",         valueLabel: "Subdomain",          valuePlaceholder: "app.example.com",            needsVerify: true  },
  url:          { label: "URL",               valueLabel: "URL",                valuePlaceholder: "https://example.com",         needsVerify: true  },
  ip:           { label: "IP Address",        valueLabel: "IP Address",         valuePlaceholder: "203.0.113.10",               needsVerify: false },
  cidr:         { label: "CIDR / IP Range",   valueLabel: "CIDR Range",         valuePlaceholder: "10.0.0.0/8",                 needsVerify: false },
  api:          { label: "API Endpoint",      valueLabel: "Base URL",           valuePlaceholder: "https://api.example.com/v1", needsVerify: true  },
  ssl_cert:     { label: "SSL Certificate",   valueLabel: "Hostname",           valuePlaceholder: "example.com",                needsVerify: false },
  cloud_asset:  { label: "Cloud Asset",       valueLabel: "Resource ID / ARN",  valuePlaceholder: "arn:aws:ec2:us-east-1:…",    needsVerify: true  },
  host:         { label: "Host",              valueLabel: "Hostname / IP",      valuePlaceholder: "server01.internal",          needsVerify: false },
  mobile_app:   { label: "Mobile App",        valueLabel: "Bundle ID / App ID", valuePlaceholder: "com.example.app",            needsVerify: false },
  sentinelware: { label: "Sentinelware",      valueLabel: "Value",              valuePlaceholder: "",                           needsVerify: false },
};

function typeLabel(t: string) { return TYPE_CONFIG[t]?.label ?? t.replace(/_/g, " "); }
function typeValueLabel(t: string) { return TYPE_CONFIG[t]?.valueLabel ?? "Value"; }
function typeValuePlaceholder(t: string) { return TYPE_CONFIG[t]?.valuePlaceholder ?? ""; }
function typeNeedsVerify(t: string) { return TYPE_CONFIG[t]?.needsVerify ?? false; }

const emptyForm = {
  name: "", type: "domain", value: "", description: "",
  scanFrequency: "manual",
  assignedClientId: undefined as number | undefined,
  assignedAccountManagerId: undefined as number | undefined,
};

type VerifyStep = "idle" | "method_select" | "token_shown" | "email_sent" | "checking" | "verified" | "failed";
type VerifyMethod = "dns_txt" | "email" | "http_file" | "cloud";

const VERIFY_METHODS: { value: VerifyMethod; label: string; desc: string }[] = [
  { value: "dns_txt",   label: "DNS TXT Record",   desc: "Add a TXT record to your domain's DNS — fastest and most reliable." },
  { value: "http_file", label: "HTTP File",         desc: "Place a verification file on your web server." },
  { value: "email",     label: "Admin Email",       desc: "Receive a confirmation link at admin@yourdomain.com." },
  { value: "cloud",     label: "Cloud Resource Tag", desc: "Add a tag to your cloud resource (AWS / GCP / Azure)." },
];

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

  // Verify state (client flow — all methods)
  const [verifyStep, setVerifyStep] = useState<VerifyStep>("idle");
  const [verifyMethod, setVerifyMethod] = useState<VerifyMethod>("dns_txt");
  const [verifyToken, setVerifyToken] = useState("");
  const [verifyMsg, setVerifyMsg] = useState("");
  const [verifyExtra, setVerifyExtra] = useState<Record<string, any>>({});
  const [pendingAssetId, setPendingAssetId] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);

  // Edit dialog
  const [showEdit, setShowEdit] = useState(false);
  const [editingAsset, setEditingAsset] = useState<any>(null);
  const [editForm, setEditForm] = useState({ ...emptyForm });

  // Type-specific metadata for create/edit forms
  const [newMetadata, setNewMetadata] = useState<Record<string, string>>({});
  const [editMetadata, setEditMetadata] = useState<Record<string, string>>({});

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
    setNewMetadata({});
    setSelectedToolIds([]);
    setRunNow(false);
    setVerifyStep("idle");
    setVerifyMethod("dns_txt");
    setVerifyToken("");
    setVerifyMsg("");
    setVerifyExtra({});
    setPendingAssetId(null);
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanMeta = Object.fromEntries(Object.entries(newMetadata).filter(([, v]) => v !== ""));
    const payload: any = {
      name: newAsset.name, type: newAsset.type, value: newAsset.value,
      scanFrequency: newAsset.scanFrequency,
      description: newAsset.description || undefined,
      metadata: Object.keys(cleanMeta).length > 0 ? cleanMeta : undefined,
    };
    if (!isClient) {
      if (newAsset.assignedClientId) payload.assignedClientId = newAsset.assignedClientId;
      if (newAsset.assignedAccountManagerId) payload.assignedAccountManagerId = newAsset.assignedAccountManagerId;
    }
    const created = await createAsset.mutateAsync({ data: payload } as any);
    await queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    const newId = (created as any)?.id;

    // For verifiable types (client role), show verification method selection
    if (isClient && newId && typeNeedsVerify(newAsset.type)) {
      setPendingAssetId(newId);
      setVerifyStep("method_select");
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

  async function initiateVerify(assetId: number, method: VerifyMethod) {
    setVerifyMethod(method);
    setVerifyStep(method === "email" ? "email_sent" : "token_shown");
    try {
      const res = await verifyAsset.mutateAsync({ assetId, data: { method } as any });
      const data = res as any;
      setVerifyToken(data.challenge ?? "");
      setVerifyExtra(data);
      if (method === "email") {
        toast({ title: "Verification email sent", description: `Check inbox at ${data.emailSentTo}` });
      }
    } catch {
      setVerifyStep("method_select");
      toast({ title: "Could not start verification", variant: "destructive" });
    }
  }

  async function checkVerification() {
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
        setVerifyMsg((res as any).message ?? "Verification not confirmed yet.");
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
    const cleanMeta = Object.fromEntries(Object.entries(editMetadata).filter(([, v]) => v !== ""));
    const payload: any = {
      name: editForm.name, type: editForm.type, value: editForm.value,
      description: editForm.description || undefined,
      scanFrequency: editForm.scanFrequency,
      metadata: Object.keys(cleanMeta).length > 0 ? cleanMeta : editingAsset.metadata ?? null,
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
    setEditMetadata(asset.metadata ?? {});
    setShowEdit(true);
  }

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this asset? This will also remove associated findings and scan data.")) return;
    await deleteAsset.mutateAsync({ assetId: id });
    queryClient.invalidateQueries({ queryKey: getListAssetsQueryKey() });
    toast({ title: "Asset deleted" });
  };

  const handleInlineVerify = (asset: any) => {
    setPendingAssetId(asset.id);
    setNewAsset(prev => ({ ...prev, name: asset.name, type: asset.type, value: asset.value }));
    setVerifyStep("method_select");
    setVerifyMethod("dns_txt");
    setVerifyToken("");
    setVerifyExtra({});
    setVerifyMsg("");
    setShowCreate(true);
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
    } catch (err: any) {
      const body = err?.body ?? err?.data ?? null;
      if (body?.unverifiedAssets?.length) {
        const names = body.unverifiedAssets.map((a: any) => a.name).join(", ");
        toast({ title: "Ownership not verified", description: `Verify these assets first: ${names}`, variant: "destructive" });
      } else {
        toast({ title: "Failed to start scan", variant: "destructive" });
      }
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
            {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{typeLabel(t)}</SelectItem>)}
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
                    ) : asset.verificationStatus !== "verified" ? (
                      <span className="flex items-center gap-1 text-[11px] text-amber-500/80 font-medium">
                        <ShieldCheck className="w-3 h-3 shrink-0" />
                        Verify first
                      </span>
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

          {/* Verify ownership flow (shown after client creates asset) */}
          {isClient && verifyStep !== "idle" ? (
            <VerifyOwnershipPanel
              step={verifyStep}
              method={verifyMethod}
              token={verifyToken}
              extra={verifyExtra}
              message={verifyMsg}
              assetValue={newAsset.value}
              assetType={newAsset.type}
              copied={copied}
              onCopy={copyToken}
              onMethodSelect={(m) => pendingAssetId && initiateVerify(pendingAssetId, m)}
              onCheck={checkVerification}
              onRetry={() => setVerifyStep("method_select")}
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
                  <Select value={newAsset.type} onValueChange={v => { setNewAsset(p => ({ ...p, type: v, value: "" })); setNewMetadata({}); }}>
                    <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{typeLabel(t)}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">{typeValueLabel(newAsset.type)} *</Label>
                  <Input
                    value={newAsset.value}
                    onChange={e => setNewAsset(p => ({ ...p, value: e.target.value }))}
                    placeholder={typeValuePlaceholder(newAsset.type)}
                    required className="h-9 font-mono text-sm"
                  />
                </div>
              </div>

              {/* Type-specific metadata fields */}
              <AssetMetadataFields type={newAsset.type} metadata={newMetadata} onChange={setNewMetadata} />

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
              {isClient && typeNeedsVerify(newAsset.type) && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2.5 text-xs text-amber-400 flex items-start gap-2">
                  <Shield className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                  <span>After adding, you'll need to verify ownership of this {typeLabel(newAsset.type).toLowerCase()}. Choose from DNS TXT, HTTP file, email, or cloud tag.</span>
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
                    {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{typeLabel(t)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{typeValueLabel(editForm.type)}</Label>
                <Input value={editForm.value} onChange={e => setEditForm(p => ({ ...p, value: e.target.value }))} required className="h-9 font-mono text-sm" placeholder={typeValuePlaceholder(editForm.type)} />
              </div>
            </div>

            {/* Type-specific metadata fields */}
            <AssetMetadataFields type={editForm.type} metadata={editMetadata} onChange={setEditMetadata} />

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

function AssetMetadataFields({
  type, metadata, onChange,
}: {
  type: string;
  metadata: Record<string, string>;
  onChange: (m: Record<string, string>) => void;
}) {
  const set = (key: string, value: string) => onChange({ ...metadata, [key]: value });

  if (type === "api") {
    return (
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className="text-xs">HTTP Method</Label>
          <Select value={metadata.method ?? "any"} onValueChange={v => set("method", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {["any", "GET", "POST", "PUT", "PATCH", "DELETE"].map(m => (
                <SelectItem key={m} value={m}>{m === "any" ? "All methods" : m}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Auth Type</Label>
          <Select value={metadata.authType ?? "none"} onValueChange={v => set("authType", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {[
                { value: "none",    label: "None / Public" },
                { value: "api_key", label: "API Key" },
                { value: "oauth2",  label: "OAuth 2.0" },
                { value: "jwt",     label: "JWT Bearer" },
                { value: "basic",   label: "Basic Auth" },
              ].map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5 col-span-2">
          <Label className="text-xs">API Version (optional)</Label>
          <Input
            value={metadata.apiVersion ?? ""}
            onChange={e => set("apiVersion", e.target.value)}
            placeholder="v1, v2, 2024-01-01…"
            className="h-9 text-xs"
          />
        </div>
      </div>
    );
  }

  if (type === "ssl_cert") {
    return (
      <div className="space-y-1.5">
        <Label className="text-xs">Port (default 443)</Label>
        <Input
          type="number"
          value={metadata.port ?? "443"}
          onChange={e => set("port", e.target.value)}
          placeholder="443"
          className="h-9 text-xs w-32"
        />
        <p className="text-xs text-muted-foreground">The scanner will connect on this port to inspect the SSL/TLS certificate.</p>
      </div>
    );
  }

  if (type === "cloud_asset") {
    return (
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className="text-xs">Cloud Provider</Label>
          <Select value={metadata.cloudProvider ?? ""} onValueChange={v => set("cloudProvider", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="Select provider" /></SelectTrigger>
            <SelectContent>
              {[
                { value: "aws",   label: "Amazon Web Services" },
                { value: "gcp",   label: "Google Cloud Platform" },
                { value: "azure", label: "Microsoft Azure" },
                { value: "other", label: "Other / On-prem" },
              ].map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Resource Type</Label>
          <Input
            value={metadata.cloudResourceType ?? ""}
            onChange={e => set("cloudResourceType", e.target.value)}
            placeholder="ec2, s3, gke, vm…"
            className="h-9 text-xs"
          />
        </div>
        <div className="space-y-1.5 col-span-2">
          <Label className="text-xs">Region (optional)</Label>
          <Input
            value={metadata.cloudRegion ?? ""}
            onChange={e => set("cloudRegion", e.target.value)}
            placeholder="us-east-1, europe-west1, eastus…"
            className="h-9 text-xs"
          />
        </div>
      </div>
    );
  }

  if (type === "host") {
    return (
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className="text-xs">Host Type</Label>
          <Select value={metadata.hostType ?? ""} onValueChange={v => set("hostType", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="Select type" /></SelectTrigger>
            <SelectContent>
              {[
                { value: "physical",  label: "Physical Server" },
                { value: "virtual",   label: "Virtual Machine" },
                { value: "container", label: "Container" },
                { value: "cloud",     label: "Cloud Instance" },
              ].map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Operating System</Label>
          <Select value={metadata.os ?? ""} onValueChange={v => set("os", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="Select OS" /></SelectTrigger>
            <SelectContent>
              {[
                { value: "linux",   label: "Linux" },
                { value: "windows", label: "Windows" },
                { value: "macos",   label: "macOS" },
                { value: "unknown", label: "Unknown" },
              ].map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>
    );
  }

  if (type === "mobile_app") {
    return (
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label className="text-xs">Platform</Label>
          <Select value={metadata.platform ?? ""} onValueChange={v => set("platform", v)}>
            <SelectTrigger className="h-9 text-xs"><SelectValue placeholder="Select platform" /></SelectTrigger>
            <SelectContent>
              {[
                { value: "ios",     label: "iOS (Apple App Store)" },
                { value: "android", label: "Android (Google Play)" },
                { value: "both",    label: "Cross-platform" },
              ].map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Bundle ID</Label>
          <Input
            value={metadata.bundleId ?? ""}
            onChange={e => set("bundleId", e.target.value)}
            placeholder="com.example.myapp"
            className="h-9 text-xs font-mono"
          />
        </div>
        <div className="space-y-1.5 col-span-2">
          <Label className="text-xs">App Store URL (optional)</Label>
          <Input
            value={metadata.appStoreUrl ?? ""}
            onChange={e => set("appStoreUrl", e.target.value)}
            placeholder="https://apps.apple.com/app/…"
            className="h-9 text-xs"
          />
        </div>
      </div>
    );
  }

  if (type === "cidr") {
    return (
      <div className="rounded-lg border border-border bg-accent/20 px-3 py-2.5 text-xs text-muted-foreground">
        <p className="font-medium text-foreground mb-1">CIDR Range</p>
        <p>Use standard notation like <code className="font-mono bg-background px-1 rounded">10.0.0.0/8</code> (Class A) or <code className="font-mono bg-background px-1 rounded">192.168.1.0/24</code> (subnet). The scanner will enumerate live hosts within this range.</p>
      </div>
    );
  }

  return null;
}

function TypeBadge({ type }: { type: string }) {
  const icons: Record<string, React.ElementType> = {
    domain: Globe, subdomain: Globe, url: Globe, ip: Server,
    cidr: Network, api: Code2, ssl_cert: Lock,
    cloud_asset: Cloud, host: Cpu, mobile_app: Smartphone, sentinelware: Shield,
  };
  const Icon = icons[type] ?? Globe;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-muted-foreground bg-accent/50 px-2 py-0.5 rounded">
      <Icon className="w-3 h-3" />
      {typeLabel(type)}
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

function VerifyOwnershipPanel({
  step, method, token, extra, message, assetValue, assetType, copied,
  onCopy, onMethodSelect, onCheck, onRetry, onDone,
}: {
  step: VerifyStep;
  method: VerifyMethod;
  token: string;
  extra: Record<string, any>;
  message: string;
  assetValue: string;
  assetType: string;
  copied: boolean;
  onCopy: () => void;
  onMethodSelect: (m: VerifyMethod) => void;
  onCheck: () => void;
  onRetry: () => void;
  onDone: () => void;
}) {
  const domain = assetValue.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const isCloud = assetType === "cloud_asset";

  // ── Verified ────────────────────────────────────────────────────────────────
  if (step === "verified") {
    return (
      <div className="py-8 text-center space-y-3">
        <CheckCircle2 className="w-14 h-14 text-green-400 mx-auto" />
        <p className="font-semibold text-lg">Ownership Verified!</p>
        <p className="text-sm text-muted-foreground">{message}</p>
        <Button onClick={onDone} className="mt-2">Continue</Button>
      </div>
    );
  }

  // ── Failed ──────────────────────────────────────────────────────────────────
  if (step === "failed") {
    return (
      <div className="py-4 space-y-4">
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-400 flex items-start gap-2">
          <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{message}</span>
        </div>
        {method === "dns_txt" && <p className="text-xs text-muted-foreground">DNS propagation can take up to 24 hours.</p>}
        {method === "http_file" && <p className="text-xs text-muted-foreground">Make sure the file is publicly accessible and has the exact content (no trailing spaces or newlines).</p>}
        {method === "email" && <p className="text-xs text-muted-foreground">The link in your email is valid for 1 hour. Request a new one if it expired.</p>}
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={onRetry}>Choose Different Method</Button>
          {method !== "cloud" && (
            <Button variant="outline" size="sm" onClick={onCheck}>
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Try Again
            </Button>
          )}
        </div>
        <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onDone}>
          Skip for now (verify later)
        </Button>
      </div>
    );
  }

  // ── Checking ────────────────────────────────────────────────────────────────
  if (step === "checking") {
    return (
      <div className="py-10 text-center space-y-3">
        <Loader2 className="w-10 h-10 text-primary mx-auto animate-spin" />
        <p className="text-sm text-muted-foreground">Checking verification…</p>
      </div>
    );
  }

  // ── Method selection ────────────────────────────────────────────────────────
  if (step === "method_select") {
    const available = isCloud
      ? VERIFY_METHODS
      : VERIFY_METHODS.filter(m => m.value !== "cloud");
    return (
      <div className="space-y-4 py-2">
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
          <p className="font-semibold text-foreground">Verify asset ownership</p>
          <p className="text-xs text-muted-foreground">
            Choose a method to prove you own <strong>{domain || assetValue}</strong>. Verified assets can be scanned.
          </p>
        </div>
        <div className="grid gap-2">
          {available.map(m => (
            <button
              key={m.value}
              type="button"
              onClick={() => onMethodSelect(m.value)}
              className="flex items-start gap-3 text-left rounded-lg border border-border hover:border-primary/50 hover:bg-primary/5 p-3 transition-colors"
            >
              <div className="w-8 h-8 rounded-md bg-primary/10 flex items-center justify-center shrink-0 mt-0.5">
                {m.value === "dns_txt"   && <Globe className="w-4 h-4 text-primary" />}
                {m.value === "http_file" && <Server className="w-4 h-4 text-primary" />}
                {m.value === "email"     && <Shield className="w-4 h-4 text-primary" />}
                {m.value === "cloud"     && <Zap className="w-4 h-4 text-primary" />}
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">{m.label}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{m.desc}</p>
              </div>
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" className="text-muted-foreground w-full" onClick={onDone}>
          Skip for now (verify later)
        </Button>
      </div>
    );
  }

  // ── Email sent ──────────────────────────────────────────────────────────────
  if (step === "email_sent") {
    const emailSentTo = extra.emailSentTo ?? `admin@${domain}`;
    return (
      <div className="space-y-4 py-2">
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
          <p className="font-semibold text-foreground flex items-center gap-2">
            <Shield className="w-4 h-4 text-primary" /> Email verification sent
          </p>
          <p className="text-xs text-muted-foreground">
            A verification email has been sent to <strong>{emailSentTo}</strong>. Click the link in the email to confirm ownership.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-accent/20 p-3 space-y-2">
          <p className="text-xs font-medium text-muted-foreground">What to do:</p>
          <ol className="text-xs text-muted-foreground space-y-1 list-decimal list-inside">
            <li>Check the inbox at <strong className="text-foreground">{emailSentTo}</strong></li>
            <li>Open the email from Sentinelware</li>
            <li>Click <strong className="text-foreground">"Confirm Ownership"</strong></li>
            <li>Then click the button below to check status</li>
          </ol>
        </div>
        <p className="text-xs text-muted-foreground">The link expires in 1 hour. No Resend API key configured? Contact your platform admin.</p>
        <div className="flex gap-2">
          <Button onClick={onCheck} className="flex-1">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> I clicked the link — Check Status
          </Button>
        </div>
        <Button variant="ghost" size="sm" className="text-muted-foreground w-full" onClick={onRetry}>
          Choose a different method
        </Button>
      </div>
    );
  }

  // ── Cloud instructions ──────────────────────────────────────────────────────
  if (step === "token_shown" && method === "cloud") {
    const cmds = extra.cloudInstructions ?? {};
    return (
      <div className="space-y-4 py-2">
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
          <p className="font-semibold text-foreground">Add verification tag to your cloud resource</p>
          <p className="text-xs text-muted-foreground">Add the tag below to prove you control this resource. Then click "I've added the tag".</p>
        </div>
        <div className="space-y-2">
          <div className="rounded-lg border border-border bg-accent/20 p-3 space-y-2 text-xs font-mono">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <p className="text-muted-foreground mb-0.5 font-sans">Tag Key</p>
                <span className="text-foreground">sentinelware-verify</span>
              </div>
              <div>
                <p className="text-muted-foreground mb-1 font-sans">Tag Value</p>
                <div className="flex items-center gap-1 bg-background rounded px-2 py-1 border border-border">
                  <span className="flex-1 truncate text-primary">{token || "Generating…"}</span>
                  <button type="button" onClick={onCopy} className="text-muted-foreground hover:text-foreground ml-1">
                    {copied ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              </div>
            </div>
          </div>
          {cmds.aws && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground hover:text-foreground mb-1">AWS CLI command</summary>
              <pre className="bg-accent/20 rounded p-2 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap">{cmds.aws}</pre>
            </details>
          )}
          {cmds.gcp && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground hover:text-foreground mb-1">GCP CLI command</summary>
              <pre className="bg-accent/20 rounded p-2 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap">{cmds.gcp}</pre>
            </details>
          )}
          {cmds.azure && (
            <details className="text-xs">
              <summary className="cursor-pointer text-muted-foreground hover:text-foreground mb-1">Azure CLI command</summary>
              <pre className="bg-accent/20 rounded p-2 text-[10px] font-mono overflow-x-auto whitespace-pre-wrap">{cmds.azure}</pre>
            </details>
          )}
        </div>
        <Button onClick={onCheck} className="w-full">
          <ShieldCheck className="w-3.5 h-3.5 mr-1.5" /> I've added the tag — Verify
        </Button>
        <Button variant="ghost" size="sm" className="text-muted-foreground w-full" onClick={onRetry}>
          Choose a different method
        </Button>
      </div>
    );
  }

  // ── HTTP File instructions ──────────────────────────────────────────────────
  if (step === "token_shown" && method === "http_file") {
    const fileUrl = extra.checkUrl ?? `https://${domain}/.well-known/sentinelware-verification.txt`;
    return (
      <div className="space-y-4 py-2">
        <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
          <p className="font-semibold text-foreground">Place a verification file on your server</p>
          <p className="text-xs text-muted-foreground">Create the file below at your web server root. Then click "Check Verification".</p>
        </div>
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Step 1 — File path</p>
          <div className="rounded border border-border bg-accent/20 px-3 py-2 font-mono text-xs text-foreground">
            /.well-known/sentinelware-verification.txt
          </div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Step 2 — File content (exact)</p>
          <div className="flex items-center gap-2 bg-accent/20 rounded px-3 py-2 border border-border font-mono text-xs">
            <span className="flex-1 truncate text-primary">{token || "Generating…"}</span>
            <button type="button" onClick={onCopy} className="text-muted-foreground hover:text-foreground shrink-0">
              {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
          <p className="text-xs text-muted-foreground">The file must be accessible at: <strong className="font-mono">{fileUrl}</strong></p>
        </div>
        <Button onClick={onCheck} className="w-full">
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Check Verification
        </Button>
        <Button variant="ghost" size="sm" className="text-muted-foreground w-full" onClick={onRetry}>
          Choose a different method
        </Button>
      </div>
    );
  }

  // ── DNS TXT instructions (default) ─────────────────────────────────────────
  return (
    <div className="space-y-4 py-2">
      <div className="rounded-lg border border-primary/30 bg-primary/5 p-3 text-sm space-y-1">
        <p className="font-semibold text-foreground">Add a DNS TXT record</p>
        <p className="text-xs text-muted-foreground">Verify you own <strong>{domain}</strong> by adding a TXT record to your DNS. This usually takes a few minutes.</p>
      </div>

      <div className="space-y-2">
        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">DNS Record to add</p>
        <div className="rounded-lg border border-border bg-accent/20 p-3 space-y-2 text-xs font-mono">
          <div className="grid grid-cols-3 gap-2">
            <div>
              <p className="text-muted-foreground mb-0.5 font-sans">Type</p>
              <span className="text-foreground">TXT</span>
            </div>
            <div>
              <p className="text-muted-foreground mb-0.5 font-sans">Host / Name</p>
              <span className="text-foreground">sentinelwares</span>
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
        <p className="text-xs text-muted-foreground">After adding the TXT record, click verify. DNS propagation can take a few minutes.</p>
        <div className="flex gap-2">
          <Button onClick={onCheck} disabled={!token}>
            <ShieldCheck className="w-4 h-4 mr-1.5" /> Verify Domain
          </Button>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onRetry}>
            Choose different method
          </Button>
          <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onDone}>
            Skip for now
          </Button>
        </div>
      </div>
    </div>
  );
}
