import { useState, useMemo, useRef } from "react";
import { useParams, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ArrowLeft, ShieldCheck, CheckCircle2, XCircle, Clock, MinusCircle,
  Globe, ChevronDown, ChevronUp, Loader2, RefreshCw, BookOpen, Server,
  AlertTriangle, Upload, Download, Trash2, Paperclip, Plus,
} from "lucide-react";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const STATUS_CONFIG = {
  compliant:      { label: "Compliant",     color: "text-green-400",  bg: "bg-green-500/15 border-green-500/30",   icon: CheckCircle2 },
  in_progress:    { label: "In Progress",   color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30", icon: Clock        },
  non_compliant:  { label: "Non-Compliant", color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30",       icon: XCircle      },
  not_applicable: { label: "N/A",           color: "text-slate-400",  bg: "bg-slate-500/15 border-slate-500/30",   icon: MinusCircle  },
} as const;
type StatusKey = keyof typeof STATUS_CONFIG;

const FRAMEWORK_COLORS: Record<string, string> = {
  "ISO27001": "text-blue-400 bg-blue-500/10 border-blue-500/30",
  "SOC2":     "text-purple-400 bg-purple-500/10 border-purple-500/30",
  "PCI-DSS":  "text-orange-400 bg-orange-500/10 border-orange-500/30",
  "HIPAA":    "text-pink-400 bg-pink-500/10 border-pink-500/30",
  "CIS":      "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
  "NIST-CSF": "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  "CUSTOM":   "text-slate-400 bg-slate-500/10 border-slate-500/30",
};
function fwColor(sn: string | null | undefined) {
  return FRAMEWORK_COLORS[sn ?? ""] ?? "text-slate-400 bg-slate-500/10 border-slate-500/30";
}

function ScoreRing({ score, size = 56 }: { score: number; size?: number }) {
  const r = size / 2 - 6;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 70 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444";
  return (
    <svg width={size} height={size} style={{ flexShrink: 0 }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={5} className="text-muted/20" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={5}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transform: "rotate(-90deg)", transformOrigin: "center", transition: "stroke-dashoffset 0.5s ease" }} />
      <text x="50%" y="50%" dominantBaseline="middle" textAnchor="middle"
        style={{ fill: color, fontSize: size < 48 ? 9 : 13, fontWeight: 700 }}>
        {score}%
      </text>
    </svg>
  );
}

interface AssetControl {
  globalControlId: number;
  controlId: string;
  title: string;
  description: string | null;
  category: string | null;
  isEnabled: boolean;
  frameworkId: number;
  frameworkName: string | null;
  frameworkShortName: string | null;
  assetControlId: number | null;
  assetStatus: string | null;
  assetNotes: string | null;
  assetAssignedTo: string | null;
  assetEvidence: string | null;
  tenantStatus: string;
  status: string;
}

interface EvidenceFile {
  name: string;
  path: string;
  size: number;
  uploadedAt: string;
}

interface Framework {
  id: number;
  name: string;
  shortName: string;
}

interface FrameworkSummary {
  frameworkId: number;
  frameworkName: string;
  shortName: string;
  total: number;
  compliant: number;
  inProgress: number;
  nonCompliant: number;
  notApplicable: number;
  score: number;
}

interface AssetDetail {
  id: number;
  name: string;
  type: string;
  domain?: string;
  ip?: string;
  riskLevel?: string;
  verificationStatus?: string;
  businessImpact?: number;
  tags?: string[];
  lastScannedAt?: string;
}

export default function ComplianceAssetDetailPage() {
  const { assetId } = useParams<{ assetId: string }>();
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const assetIdNum = parseInt(assetId!);

  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);
  const [expandedFrameworks, setExpandedFrameworks] = useState<Set<number>>(new Set());
  const [editingControl, setEditingControl] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<{ status: string; notes: string; assignedTo: string }>({
    status: "non_compliant", notes: "", assignedTo: "",
  });
  const [scopeFrameworkId, setScopeFrameworkId] = useState<string>("");
  const [uploadingControlId, setUploadingControlId] = useState<number | null>(null);
  const evidenceInputRef = useRef<HTMLInputElement>(null);

  const { data: asset, isError: assetError } = useQuery<AssetDetail>({
    queryKey: ["asset-detail", assetIdNum],
    queryFn: () => apiFetch(`${BASE}/api/assets/${assetIdNum}`),
    retry: false,
  });

  const { data: frameworks = [] } = useQuery<Framework[]>({
    queryKey: ["compliance-frameworks"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/frameworks`),
  });

  const { data: summary = [], isLoading: loadingSummary, refetch: refetchSummary } = useQuery<FrameworkSummary[]>({
    queryKey: ["asset-compliance-summary", assetIdNum],
    queryFn: () => apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}/summary`),
  });

  const { data: controls = [], isLoading: loadingControls, refetch: refetchControls } = useQuery<AssetControl[]>({
    queryKey: ["asset-compliance-controls", assetIdNum, selectedFramework],
    queryFn: () =>
      apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}${selectedFramework ? `?frameworkId=${selectedFramework}` : ""}`),
  });

  const updateControl = useMutation({
    mutationFn: ({ globalControlId, status, notes, assignedTo }: {
      globalControlId: number; status: string; notes: string; assignedTo: string;
    }) =>
      apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}/${globalControlId}`, {
        method: "PUT",
        body: JSON.stringify({ status, notes, assignedTo }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset-compliance-controls", assetIdNum] });
      qc.invalidateQueries({ queryKey: ["asset-compliance-summary", assetIdNum] });
      qc.invalidateQueries({ queryKey: ["compliance-clients-overview"] });
      setEditingControl(null);
      toast({ title: "Control updated" });
    },
    onError: (e: any) => toast({ title: "Error updating control", description: e.message, variant: "destructive" }),
  });

  const scopeFramework = useMutation({
    mutationFn: (frameworkId: number) =>
      apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}/scope`, {
        method: "POST",
        body: JSON.stringify({ frameworkId }),
      }),
    onSuccess: (data: any) => {
      qc.invalidateQueries({ queryKey: ["asset-compliance-controls", assetIdNum] });
      qc.invalidateQueries({ queryKey: ["asset-compliance-summary", assetIdNum] });
      setScopeFrameworkId("");
      toast({ title: "Framework scoped", description: `${data.count} controls added to this asset.` });
    },
    onError: (e: any) => toast({ title: "Failed to scope framework", description: e.message, variant: "destructive" }),
  });

  const deleteEvidence = useMutation({
    mutationFn: ({ globalControlId, filename }: { globalControlId: number; filename: string }) =>
      apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}/${globalControlId}/evidence/${encodeURIComponent(filename)}`, {
        method: "DELETE",
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset-compliance-controls", assetIdNum] });
      toast({ title: "Evidence file removed" });
    },
    onError: (e: any) => toast({ title: "Failed to delete evidence", description: e.message, variant: "destructive" }),
  });

  async function handleEvidenceUpload(globalControlId: number, files: FileList | null) {
    if (!files?.length) return;
    setUploadingControlId(globalControlId);
    const fd = new FormData();
    for (const f of Array.from(files)) fd.append("files", f);
    try {
      await apiFetch(`${BASE}/api/compliance/assets/${assetIdNum}/${globalControlId}/evidence`, {
        method: "POST",
        body: fd,
      });
      qc.invalidateQueries({ queryKey: ["asset-compliance-controls", assetIdNum] });
      toast({ title: "Evidence uploaded", description: `${files.length} file${files.length !== 1 ? "s" : ""} uploaded.` });
    } catch (e: any) {
      toast({ title: "Upload failed", description: e.message, variant: "destructive" });
    } finally {
      setUploadingControlId(null);
    }
  }

  const { data: accountManagers = [] } = useQuery<{ id: number; email: string; name: string }[]>({
    queryKey: ["compliance-account-managers"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/account-managers`),
  });

  const enabledControls = useMemo(() => controls.filter(c => c.isEnabled), [controls]);

  const grouped = useMemo(() => {
    const byFramework: Record<number, {
      frameworkId: number; frameworkName: string; shortName: string; controls: AssetControl[];
    }> = {};
    for (const c of enabledControls) {
      if (!byFramework[c.frameworkId]) {
        byFramework[c.frameworkId] = {
          frameworkId: c.frameworkId,
          frameworkName: c.frameworkName ?? "Unknown Framework",
          shortName: c.frameworkShortName ?? "FW",
          controls: [],
        };
      }
      byFramework[c.frameworkId].controls.push(c);
    }
    return Object.values(byFramework).sort((a, b) => a.frameworkId - b.frameworkId);
  }, [enabledControls]);

  const totalEnabled = enabledControls.length; // used for controls-section header count

  // Overall metrics computed from summary — uses ALL framework controls as denominator
  // (identical methodology to Overview tab so scores match)
  const compliantCount    = summary.reduce((a, s) => a + s.compliant,      0);
  const inProgressCount   = summary.reduce((a, s) => a + s.inProgress,     0);
  const nonCompliantCount = summary.reduce((a, s) => a + s.nonCompliant,   0);
  const notApplicableCount = summary.reduce((a, s) => a + s.notApplicable, 0);
  const totalControls     = summary.reduce((a, s) => a + s.total,          0);
  const overallScore = totalControls > 0
    ? Math.round((compliantCount / Math.max(1, totalControls - notApplicableCount)) * 100)
    : 0;
  const scoreColor = overallScore >= 70 ? "text-green-400" : overallScore >= 40 ? "text-yellow-400" : "text-red-400";

  const handleRefresh = () => {
    refetchSummary();
    refetchControls();
  };

  const toggleFramework = (fwId: number) => {
    setExpandedFrameworks(prev => {
      const next = new Set(prev);
      if (next.has(fwId)) next.delete(fwId);
      else next.add(fwId);
      return next;
    });
  };

  const expandAll = () => setExpandedFrameworks(new Set(grouped.map(g => g.frameworkId)));
  const collapseAll = () => setExpandedFrameworks(new Set());

  const startEdit = (ctrl: AssetControl) => {
    setEditingControl(ctrl.globalControlId);
    setEditForm({
      status: ctrl.status ?? "non_compliant",
      notes: ctrl.assetNotes ?? "",
      assignedTo: ctrl.assetAssignedTo ?? "",
    });
  };

  const activeFrameworkSummary = selectedFramework
    ? summary.find(s => s.frameworkId === selectedFramework)
    : null;

  return (
    <div className="flex flex-col w-full min-h-full bg-background">

      {/* ── Hero Header ──────────────────────────────────────────────────────── */}
      <div className="border-b border-border bg-gradient-to-b from-card/60 to-background/80 px-6 pt-5 pb-6">

        {/* Nav row */}
        <div className="flex items-center gap-2 mb-5">
          <Button variant="ghost" size="sm" onClick={() => navigate("/compliance")}
            className="gap-1.5 text-muted-foreground hover:text-foreground h-8 px-2">
            <ArrowLeft className="w-4 h-4" />
            Compliance Management
          </Button>
          <span className="text-muted-foreground/50 text-sm">/</span>
          <span className="text-sm font-medium truncate">
            {asset?.name ?? `Asset #${assetIdNum}`}
          </span>
        </div>

        {/* Asset identity */}
        <div className="flex items-start gap-5">
          <div className="w-16 h-16 rounded-xl bg-primary/10 border border-primary/25 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-8 h-8 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-start gap-3 flex-wrap mb-2">
              <h1 className="text-2xl font-bold tracking-tight leading-tight">
                {asset?.name ?? (assetError ? `Asset #${assetIdNum}` : "Loading…")}
              </h1>
              <div className="flex items-center gap-2 flex-wrap mt-0.5">
                <Badge className="text-[10px] bg-green-500/20 text-green-400 border-green-500/30">
                  <ShieldCheck className="w-2.5 h-2.5 mr-1" />Compliance Enabled
                </Badge>
                {asset?.type && (
                  <Badge variant="outline" className="text-[10px] capitalize">{asset.type}</Badge>
                )}
                {asset?.verificationStatus === "verified" && (
                  <Badge className="text-[10px] bg-blue-500/15 text-blue-400 border-blue-500/30">Verified</Badge>
                )}
                {asset?.riskLevel && (
                  <Badge className={cn("text-[10px] capitalize border",
                    asset.riskLevel === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                    asset.riskLevel === "high" ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                    asset.riskLevel === "medium" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                    "bg-slate-500/15 text-slate-400 border-slate-500/30"
                  )}>
                    {asset.riskLevel} risk
                  </Badge>
                )}
              </div>
            </div>
            <div className="flex items-center gap-5 text-sm text-muted-foreground flex-wrap">
              {(asset?.domain || asset?.ip) && (
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5" />
                  {asset.domain ?? asset.ip}
                </span>
              )}
              {!asset?.domain && !asset?.ip && (
                <span className="flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5" />
                  Asset ID #{assetIdNum}
                </span>
              )}
              {asset?.businessImpact !== undefined && (
                <span>Business Impact: <span className="font-medium text-foreground">{asset.businessImpact}/10</span></span>
              )}
            </div>
          </div>
          <Button size="sm" variant="outline" onClick={handleRefresh} className="shrink-0 gap-1.5 h-8">
            <RefreshCw className="w-3.5 h-3.5" />Refresh
          </Button>
        </div>

        {/* Metrics strip */}
        <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mt-6">
          {[
            {
              label: "Overall Score",
              value: <span className={cn("text-3xl font-bold", scoreColor)}>{overallScore}%</span>,
              accent: "border-l-4 " + (overallScore >= 70 ? "border-l-green-500" : overallScore >= 40 ? "border-l-yellow-500" : "border-l-red-500"),
              sub: `all framework controls`,
            },
            { label: "Total Controls", value: <span className="text-2xl font-bold">{totalControls}</span>, sub: `across all frameworks` },
            { label: "Compliant", value: <span className="text-2xl font-bold text-green-400">{compliantCount}</span>, sub: "passing" },
            { label: "In Progress", value: <span className="text-2xl font-bold text-yellow-400">{inProgressCount}</span>, sub: "being addressed" },
            { label: "Non-Compliant", value: <span className="text-2xl font-bold text-red-400">{nonCompliantCount}</span>, sub: "requires action" },
            { label: "Not Applicable", value: <span className="text-2xl font-bold text-slate-400">{notApplicableCount}</span>, sub: "excluded" },
          ].map((m, i) => (
            <div key={i} className={cn("bg-card/50 border border-border/50 rounded-lg px-3 py-3", m.accent ?? "")}>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1.5">{m.label}</p>
              {m.value}
              <p className="text-[10px] text-muted-foreground mt-0.5">{m.sub}</p>
            </div>
          ))}
        </div>
      </div>

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="flex-1 px-6 py-6 space-y-6">

        {/* Framework Summary Cards */}
        <div>
          <div className="flex items-start justify-between mb-3 gap-4">
            <p className="text-sm font-semibold flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-primary" />
              Framework Compliance Scores
              <span className="text-xs font-normal text-muted-foreground">
                — click a framework to filter controls below
              </span>
            </p>
            {totalControls > 0 && (
              <p className="text-[10px] text-muted-foreground shrink-0 mt-0.5">
                Across all <span className="text-foreground font-medium">{totalControls}</span> framework controls
                {" "}· overall: <span className="text-foreground font-medium">{overallScore}%</span>
              </p>
            )}
          </div>

          {loadingSummary ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-28 rounded-xl" />)}
            </div>
          ) : summary.length === 0 ? (
            <div className="bg-card border border-border rounded-xl p-8 text-center">
              <AlertTriangle className="w-6 h-6 text-muted-foreground/40 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No framework data available for this asset.</p>
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {summary.map(fw => (
                <button
                  key={fw.frameworkId}
                  onClick={() => {
                    const next = selectedFramework === fw.frameworkId ? null : fw.frameworkId;
                    setSelectedFramework(next);
                    if (next) {
                      setExpandedFrameworks(new Set([next]));
                    } else {
                      setExpandedFrameworks(new Set());
                    }
                  }}
                  className={cn(
                    "text-left rounded-xl border p-3 transition-all hover:border-primary/40 bg-card/60",
                    selectedFramework === fw.frameworkId
                      ? "border-primary/60 bg-primary/5 shadow-sm"
                      : "border-border/50 hover:bg-muted/20"
                  )}
                >
                  <div className="flex items-start justify-between gap-1 mb-2">
                    <Badge className={cn("text-[10px] border font-mono leading-tight", fwColor(fw.shortName))}>
                      {fw.shortName}
                    </Badge>
                    <ScoreRing score={fw.score} size={38} />
                  </div>
                  <p className="text-xs font-medium text-foreground leading-tight mb-2 line-clamp-2">{fw.frameworkName}</p>
                  <div className="grid grid-cols-2 gap-1">
                    <div className="bg-green-500/10 rounded px-1 py-1 text-center">
                      <p className="text-xs font-bold text-green-400">{fw.compliant}</p>
                      <p className="text-[9px] text-muted-foreground">Compliant</p>
                    </div>
                    <div className="bg-red-500/10 rounded px-1 py-1 text-center">
                      <p className="text-xs font-bold text-red-400">{fw.nonCompliant}</p>
                      <p className="text-[9px] text-muted-foreground">Non-Compliant</p>
                    </div>
                  </div>
                  {fw.total > 0 && (
                    <div className="mt-2 w-full bg-muted/30 rounded-full h-1">
                      <div
                        className={cn("h-1 rounded-full transition-all",
                          fw.score >= 70 ? "bg-green-500" : fw.score >= 40 ? "bg-yellow-500" : "bg-red-500")}
                        style={{ width: `${fw.score}%` }}
                      />
                    </div>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Controls Section */}
        <div>
          <div className="flex items-center justify-between mb-3 gap-3">
            <div className="flex items-center gap-2 min-w-0">
              <ShieldCheck className="w-4 h-4 text-primary shrink-0" />
              <p className="text-sm font-semibold">
                {selectedFramework && activeFrameworkSummary
                  ? `${activeFrameworkSummary.frameworkName} Controls`
                  : "All Controls"}
              </p>
              <span className="text-xs text-muted-foreground font-normal">
                ({loadingControls ? "…" : totalEnabled} controls)
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {selectedFramework && (
                <Button size="sm" variant="ghost" className="h-7 text-xs gap-1"
                  onClick={() => { setSelectedFramework(null); setExpandedFrameworks(new Set()); }}>
                  <XCircle className="w-3 h-3" />Clear filter
                </Button>
              )}
              {expandedFrameworks.size < grouped.length ? (
                <Button size="sm" variant="outline" className="h-7 text-xs" onClick={expandAll}>Expand All</Button>
              ) : (
                <Button size="sm" variant="outline" className="h-7 text-xs" onClick={collapseAll}>Collapse All</Button>
              )}
            </div>
          </div>

          {/* Scope Framework Panel */}
          <div className="bg-card border border-border/60 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <Plus className="w-4 h-4 text-primary shrink-0" />
              <h4 className="text-sm font-semibold">Scope a Framework</h4>
              <span className="text-xs text-muted-foreground">
                Add all controls from a compliance framework to this asset.
              </span>
            </div>
            <div className="flex items-center gap-2">
              <Select value={scopeFrameworkId} onValueChange={setScopeFrameworkId}>
                <SelectTrigger className="h-8 text-xs flex-1 max-w-xs">
                  <SelectValue placeholder="Select framework…" />
                </SelectTrigger>
                <SelectContent>
                  {frameworks.map(fw => (
                    <SelectItem key={fw.id} value={String(fw.id)}>
                      {fw.name} ({fw.shortName})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                className="h-8 text-xs px-4 shrink-0"
                disabled={!scopeFrameworkId || scopeFramework.isPending}
                onClick={() => scopeFramework.mutate(parseInt(scopeFrameworkId))}
              >
                {scopeFramework.isPending
                  ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  : <><Plus className="w-3.5 h-3.5 mr-1" />Scope Controls</>}
              </Button>
            </div>
          </div>

          {loadingControls ? (
            <div className="space-y-3">
              {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-xl" />)}
            </div>
          ) : grouped.length === 0 ? (
            <div className="bg-card border border-border rounded-xl p-12 text-center">
              <ShieldCheck className="w-8 h-8 text-muted-foreground/30 mx-auto mb-3" />
              <p className="text-sm text-muted-foreground font-medium">No controls in scope for this asset</p>
              <p className="text-xs text-muted-foreground mt-1">
                Select a framework above and click "Scope Controls" to begin tracking.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {grouped.map(fw => {
                const isExpanded = expandedFrameworks.has(fw.frameworkId);
                const fwSummary = summary.find(s => s.frameworkId === fw.frameworkId);

                const byCategory: Record<string, AssetControl[]> = {};
                for (const c of fw.controls) {
                  const cat = c.category ?? "General";
                  if (!byCategory[cat]) byCategory[cat] = [];
                  byCategory[cat].push(c);
                }
                const categories = Object.keys(byCategory).sort();

                return (
                  <div key={fw.frameworkId} className="border border-border/60 rounded-xl overflow-hidden bg-card/40">

                    {/* Framework accordion header */}
                    <button
                      className="w-full flex items-center gap-3 px-5 py-4 hover:bg-muted/20 transition-colors text-left"
                      onClick={() => toggleFramework(fw.frameworkId)}
                    >
                      <Badge className={cn("text-xs border font-mono shrink-0", fwColor(fw.shortName))}>
                        {fw.shortName}
                      </Badge>
                      <span className="text-sm font-semibold flex-1 text-left">{fw.frameworkName}</span>

                      {fwSummary && (
                        <div className="hidden sm:flex items-center gap-4 shrink-0 mr-2">
                          <span className="text-xs text-green-400">{fwSummary.compliant} compliant</span>
                          <span className="text-xs text-yellow-400">{fwSummary.inProgress} in progress</span>
                          <span className="text-xs text-red-400">{fwSummary.nonCompliant} non-compliant</span>
                          <span className="text-xs text-muted-foreground">{fw.controls.length} total</span>
                        </div>
                      )}

                      <div className="flex items-center gap-3 shrink-0">
                        {fwSummary && <ScoreRing score={fwSummary.score} size={38} />}
                        {isExpanded
                          ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
                          : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                      </div>
                    </button>

                    {/* Framework body — categories → controls */}
                    {isExpanded && (
                      <div className="border-t border-border/40">
                        {categories.map(cat => (
                          <div key={cat}>
                            <div className="px-5 py-2 bg-muted/30 border-b border-border/30 flex items-center gap-2">
                              <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{cat}</p>
                              <span className="text-[10px] text-muted-foreground/60">
                                ({byCategory[cat].length} control{byCategory[cat].length !== 1 ? "s" : ""})
                              </span>
                            </div>
                            <div className="divide-y divide-border/25">
                              {byCategory[cat].map(ctrl => {
                                const status = (ctrl.status ?? "non_compliant") as StatusKey;
                                const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.non_compliant;
                                const Icon = cfg.icon;
                                const isEditing = editingControl === ctrl.globalControlId;

                                return (
                                  <div key={ctrl.globalControlId}
                                    className={cn("px-5 py-3.5 transition-colors", isEditing ? "bg-muted/10" : "hover:bg-muted/10")}>

                                    <div className="flex items-start gap-3">
                                      <Icon className={cn("w-4 h-4 mt-0.5 shrink-0", cfg.color)} />

                                      <div className="flex-1 min-w-0">
                                        <div className="flex items-start gap-2 flex-wrap">
                                          <span className="text-[10px] font-mono text-muted-foreground shrink-0 mt-0.5 bg-muted/40 px-1.5 py-0.5 rounded">
                                            {ctrl.controlId}
                                          </span>
                                          <span className="text-sm font-medium leading-snug">{ctrl.title}</span>
                                        </div>
                                        {ctrl.description && (
                                          <p className="text-xs text-muted-foreground mt-1 leading-relaxed line-clamp-2">
                                            {ctrl.description}
                                          </p>
                                        )}
                                        {(ctrl.assetNotes || ctrl.assetAssignedTo) && (
                                          <div className="flex items-center gap-4 mt-1.5 text-xs text-muted-foreground">
                                            {ctrl.assetAssignedTo && (
                                              <span>Assigned: <span className="font-medium text-foreground">{ctrl.assetAssignedTo}</span></span>
                                            )}
                                            {ctrl.assetNotes && (
                                              <span className="italic truncate max-w-xs">{ctrl.assetNotes}</span>
                                            )}
                                          </div>
                                        )}
                                      </div>

                                      <div className="flex items-center gap-2 shrink-0">
                                        <Badge className={cn("text-xs border gap-1 px-2 py-0.5 whitespace-nowrap", cfg.bg, cfg.color)}>
                                          <Icon className="w-3 h-3" />
                                          {cfg.label}
                                        </Badge>
                                        <Button
                                          size="sm"
                                          variant={isEditing ? "secondary" : "ghost"}
                                          className="h-7 text-xs"
                                          onClick={() => isEditing ? setEditingControl(null) : startEdit(ctrl)}
                                        >
                                          {isEditing ? "Cancel" : "Edit"}
                                        </Button>
                                      </div>
                                    </div>

                                    {/* Inline edit form */}
                                    {isEditing && (() => {
                                      let evidenceFiles: EvidenceFile[] = [];
                                      try { if (ctrl.assetEvidence) evidenceFiles = JSON.parse(ctrl.assetEvidence); } catch {}
                                      return (
                                        <div className="mt-3 ml-7 space-y-3 p-4 rounded-lg bg-muted/20 border border-border/50">
                                          {/* Status / Assigned / Notes row */}
                                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                                            <div>
                                              <Label className="text-xs mb-1.5 block">Status</Label>
                                              <Select
                                                value={editForm.status}
                                                onValueChange={v => setEditForm(f => ({ ...f, status: v }))}
                                              >
                                                <SelectTrigger className="h-8 text-xs">
                                                  <SelectValue />
                                                </SelectTrigger>
                                                <SelectContent>
                                                  <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                                                  <SelectItem value="in_progress">In Progress</SelectItem>
                                                  <SelectItem value="compliant">Compliant</SelectItem>
                                                  <SelectItem value="not_applicable">Not Applicable</SelectItem>
                                                </SelectContent>
                                              </Select>
                                            </div>
                                            <div>
                                              <Label className="text-xs mb-1.5 block">Assigned To</Label>
                                              <Select
                                                value={editForm.assignedTo || "__none__"}
                                                onValueChange={v => setEditForm(f => ({ ...f, assignedTo: v === "__none__" ? "" : v }))}
                                              >
                                                <SelectTrigger className="h-8 text-xs">
                                                  <SelectValue placeholder="Select account manager…" />
                                                </SelectTrigger>
                                                <SelectContent>
                                                  <SelectItem value="__none__">— Unassigned —</SelectItem>
                                                  {accountManagers.map(am => (
                                                    <SelectItem key={am.id} value={am.email}>{am.name} ({am.email})</SelectItem>
                                                  ))}
                                                </SelectContent>
                                              </Select>
                                            </div>
                                            <div>
                                              <Label className="text-xs mb-1.5 block">Notes</Label>
                                              <div className="flex gap-2">
                                                <Input
                                                  className="h-8 text-xs flex-1"
                                                  placeholder="Notes…"
                                                  value={editForm.notes}
                                                  onChange={e => setEditForm(f => ({ ...f, notes: e.target.value }))}
                                                />
                                                <Button
                                                  size="sm"
                                                  className="h-8 text-xs shrink-0 px-3"
                                                  disabled={updateControl.isPending}
                                                  onClick={() => updateControl.mutate({
                                                    globalControlId: ctrl.globalControlId,
                                                    status: editForm.status,
                                                    notes: editForm.notes,
                                                    assignedTo: editForm.assignedTo,
                                                  })}
                                                >
                                                  {updateControl.isPending
                                                    ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                                    : "Save"}
                                                </Button>
                                              </div>
                                            </div>
                                          </div>

                                          {/* Evidence section */}
                                          <div className="border-t border-border/40 pt-3">
                                            <div className="flex items-center justify-between mb-2">
                                              <Label className="text-xs flex items-center gap-1.5">
                                                <Paperclip className="w-3 h-3" />
                                                Evidence Files
                                                {evidenceFiles.length > 0 && (
                                                  <span className="text-muted-foreground">({evidenceFiles.length})</span>
                                                )}
                                              </Label>
                                              <div>
                                                <input
                                                  ref={evidenceInputRef}
                                                  type="file"
                                                  multiple
                                                  className="hidden"
                                                  onChange={e => handleEvidenceUpload(ctrl.globalControlId, e.target.files)}
                                                />
                                                <Button
                                                  size="sm"
                                                  variant="outline"
                                                  className="h-7 text-xs gap-1.5"
                                                  disabled={uploadingControlId === ctrl.globalControlId}
                                                  onClick={() => {
                                                    if (evidenceInputRef.current) {
                                                      evidenceInputRef.current.value = "";
                                                      evidenceInputRef.current.click();
                                                    }
                                                  }}
                                                >
                                                  {uploadingControlId === ctrl.globalControlId
                                                    ? <Loader2 className="w-3 h-3 animate-spin" />
                                                    : <><Upload className="w-3 h-3" />Upload</>}
                                                </Button>
                                              </div>
                                            </div>

                                            {evidenceFiles.length === 0 ? (
                                              <p className="text-[11px] text-muted-foreground italic">
                                                No evidence files yet. Upload documents, screenshots, or reports.
                                              </p>
                                            ) : (
                                              <div className="space-y-1.5">
                                                {evidenceFiles.map(ef => (
                                                  <div key={ef.path} className="flex items-center gap-2 bg-background/60 border border-border/40 rounded-lg px-2.5 py-1.5 group">
                                                    <Paperclip className="w-3 h-3 text-muted-foreground shrink-0" />
                                                    <span className="flex-1 text-xs truncate min-w-0">{ef.name}</span>
                                                    <span className="text-[10px] text-muted-foreground shrink-0">
                                                      {(ef.size / 1024).toFixed(0)} KB
                                                    </span>
                                                    <a
                                                      href={`${BASE}/api/compliance/assets/${assetIdNum}/${ctrl.globalControlId}/evidence/${encodeURIComponent(ef.path)}`}
                                                      target="_blank"
                                                      rel="noopener noreferrer"
                                                      className="p-1 rounded hover:bg-muted transition-colors shrink-0"
                                                      title="Download"
                                                    >
                                                      <Download className="w-3 h-3 text-muted-foreground" />
                                                    </a>
                                                    <button
                                                      className="p-1 rounded hover:bg-red-500/10 transition-colors shrink-0"
                                                      title="Delete"
                                                      onClick={() => deleteEvidence.mutate({ globalControlId: ctrl.globalControlId, filename: ef.path })}
                                                    >
                                                      <Trash2 className="w-3 h-3 text-muted-foreground hover:text-red-400" />
                                                    </button>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      );
                                    })()}
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
