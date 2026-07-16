import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Eye, EyeOff, Cloud, AlertTriangle, Globe, Terminal, Cpu, Server,
  RefreshCw, Search, CheckCircle, XCircle, Clock, ShieldAlert,
  Play, Layers, Mail, Activity, Lock, Wifi, Package,
  ChevronDown, ChevronRight, MoreHorizontal, ExternalLink,
  FileText, Loader2, Filter, TrendingUp,
} from "lucide-react";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ShadowItSummary {
  totalAssets: number;
  totalSaasApps: number;
  pendingReview: number;
  approved: number;
  remediated: number;
  byRisk: Record<string, number>;
  byType: Record<string, number>;
  saasByStatus: Record<string, number>;
}

interface ShadowAsset {
  id: number;
  tenantId: number;
  name: string;
  type: string;
  classification: string;
  source: string;
  parentAssetId: number | null;
  relatedScanId: number | null;
  evidence: Record<string, unknown> | null;
  riskScore: number | null;
  riskLevel: string;
  hasOpenPorts: boolean;
  hasAdminPanel: boolean;
  hasAuthBypass: boolean;
  isPubliclyAccessible: boolean;
  certFirstSeen: string | null;
  status: string;
  reviewedBy: number | null;
  reviewedAt: string | null;
  reviewNote: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
}

interface ShadowSaasApp {
  id: number;
  tenantId: number;
  appName: string;
  appCategory: string | null;
  idpSource: string;
  appId: string | null;
  userCount: number;
  isSanctioned: boolean;
  riskRating: string;
  evidence: Record<string, unknown> | null;
  status: string;
  discoveredViaAssetId: number | null;
  createdAt: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const RISK_LEVEL_META: Record<string, { label: string; dot: string; badge: string; bar: string }> = {
  critical: { label: "Critical", dot: "bg-red-500",    badge: "bg-red-500/15 text-red-400 border-red-500/25",    bar: "bg-red-500" },
  high:     { label: "High",     dot: "bg-orange-500", badge: "bg-orange-500/15 text-orange-400 border-orange-500/25", bar: "bg-orange-500" },
  medium:   { label: "Medium",   dot: "bg-yellow-500", badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25", bar: "bg-yellow-500" },
  low:      { label: "Low",      dot: "bg-blue-500",   badge: "bg-blue-500/15 text-blue-400 border-blue-500/25",   bar: "bg-blue-500" },
  info:     { label: "Info",     dot: "bg-slate-400",  badge: "bg-slate-500/15 text-slate-400 border-slate-500/25", bar: "bg-slate-400" },
};

const STATUS_META: Record<string, { label: string; icon: React.ReactNode; cls: string }> = {
  new:            { label: "New",            icon: <AlertTriangle className="w-3 h-3" />, cls: "bg-blue-500/15 text-blue-400 border-blue-500/25" },
  under_review:   { label: "Reviewing",      icon: <Clock className="w-3 h-3" />,         cls: "bg-yellow-500/15 text-yellow-400 border-yellow-500/25" },
  approved:       { label: "Approved",       icon: <CheckCircle className="w-3 h-3" />,   cls: "bg-green-500/15 text-green-400 border-green-500/25" },
  remediated:     { label: "Remediated",     icon: <CheckCircle className="w-3 h-3" />,   cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/25" },
  false_positive: { label: "False Positive", icon: <XCircle className="w-3 h-3" />,       cls: "bg-slate-500/15 text-slate-400 border-slate-500/25" },
};

const CLASS_META: Record<string, { label: string; cls: string }> = {
  forgotten:          { label: "Forgotten",     cls: "bg-orange-500/10 text-orange-400 border-orange-500/20" },
  rogue:              { label: "Rogue",          cls: "bg-red-500/10 text-red-400 border-red-500/20" },
  development:        { label: "Development",    cls: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  saas:               { label: "SaaS",           cls: "bg-purple-500/10 text-purple-400 border-purple-500/20" },
  cloud:              { label: "Cloud",          cls: "bg-sky-500/10 text-sky-400 border-sky-500/20" },
  unauthorized_stack: { label: "Unauth Stack",   cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" },
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  subdomain:          <Globe className="w-4 h-4 text-blue-400" />,
  cloud_bucket:       <Cloud className="w-4 h-4 text-sky-400" />,
  email_service:      <Mail className="w-4 h-4 text-purple-400" />,
  admin_panel:        <Terminal className="w-4 h-4 text-red-400" />,
  shadow_service:     <Server className="w-4 h-4 text-orange-400" />,
  unauthorized_tech:  <Cpu className="w-4 h-4 text-yellow-400" />,
  ip_asset:           <Activity className="w-4 h-4 text-slate-400" />,
};

function RiskBadge({ level }: { level: string }) {
  const m = RISK_LEVEL_META[level] ?? RISK_LEVEL_META.info;
  return (
    <span className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border", m.badge)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", m.dot)} />
      {m.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const m = STATUS_META[status] ?? { label: status, icon: null, cls: "bg-slate-500/15 text-slate-400 border-slate-500/25" };
  return (
    <span className={cn("inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border", m.cls)}>
      {m.icon}{m.label}
    </span>
  );
}

function ClassBadge({ cls }: { cls: string }) {
  const m = CLASS_META[cls] ?? { label: cls, cls: "bg-slate-500/10 text-slate-400 border-slate-500/20" };
  return (
    <span className={cn("inline-flex text-[10px] font-medium px-1.5 py-0.5 rounded border", m.cls)}>
      {m.label}
    </span>
  );
}

function fmtDate(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function fmtRelative(d: string | null) {
  if (!d) return "—";
  const ms = Date.now() - new Date(d).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ── Asset Card ─────────────────────────────────────────────────────────────────

function AssetCard({
  asset, canTriage,
  onTriage, onEvidence,
}: {
  asset: ShadowAsset;
  canTriage: boolean;
  onTriage: (a: ShadowAsset) => void;
  onEvidence: (a: ShadowAsset) => void;
}) {
  const riskMeta = RISK_LEVEL_META[asset.riskLevel] ?? RISK_LEVEL_META.info;
  const score = asset.riskScore != null ? Math.round(asset.riskScore) : null;

  return (
    <div className={cn(
      "group relative bg-card border border-border rounded-xl overflow-hidden hover:border-primary/30 hover:shadow-md transition-all duration-200",
      asset.status === "new" && asset.riskLevel === "critical" && "border-red-500/30",
      asset.status === "new" && asset.riskLevel === "high" && "border-orange-500/30",
    )}>
      {/* Risk accent strip */}
      <div className={cn("h-0.5 w-full", riskMeta.bar)} />

      <div className="p-4">
        {/* Top row */}
        <div className="flex items-start gap-3 mb-3">
          <div className="p-1.5 rounded-lg bg-accent/60 shrink-0 mt-0.5">
            {TYPE_ICONS[asset.type] ?? <Layers className="w-4 h-4 text-slate-400" />}
          </div>
          <div className="flex-1 min-w-0">
            <p className="font-mono text-xs font-medium truncate leading-tight" title={asset.name}>
              {asset.name}
            </p>
            <p className="text-[10px] text-muted-foreground capitalize mt-0.5">
              {asset.type.replace(/_/g, " ")} · {asset.source.replace(/_/g, " ")}
            </p>
          </div>
          <div className="shrink-0">
            <RiskBadge level={asset.riskLevel} />
          </div>
        </div>

        {/* Risk score bar */}
        {score != null && (
          <div className="mb-3 space-y-1">
            <div className="flex justify-between items-center text-[10px]">
              <span className="text-muted-foreground">Risk Score</span>
              <span className={cn("font-semibold tabular-nums", riskMeta.badge.includes("red") ? "text-red-400" : riskMeta.badge.includes("orange") ? "text-orange-400" : "text-muted-foreground")}>
                {score}/100
              </span>
            </div>
            <div className="h-1 rounded-full bg-accent overflow-hidden">
              <div className={cn("h-full rounded-full", riskMeta.bar)} style={{ width: `${score}%` }} />
            </div>
          </div>
        )}

        {/* Badges row */}
        <div className="flex flex-wrap gap-1 mb-3">
          <ClassBadge cls={asset.classification} />
          <StatusBadge status={asset.status} />
        </div>

        {/* Flags */}
        {(asset.hasOpenPorts || asset.hasAdminPanel || asset.hasAuthBypass || asset.isPubliclyAccessible) && (
          <div className="flex flex-wrap gap-1 mb-3">
            {asset.hasOpenPorts      && <span className="text-[9px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded">Open Port</span>}
            {asset.hasAdminPanel     && <span className="text-[9px] bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded">Admin Panel</span>}
            {asset.hasAuthBypass     && <span className="text-[9px] bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded">No Auth</span>}
            {asset.isPubliclyAccessible && <span className="text-[9px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded">Public</span>}
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between pt-2 border-t border-border/50">
          <span className="text-[10px] text-muted-foreground">
            Seen {fmtRelative(asset.firstSeenAt)}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost" size="sm"
              className="h-6 px-2 text-[10px] gap-1 text-muted-foreground hover:text-foreground"
              onClick={() => onEvidence(asset)}
            >
              <FileText className="h-3 w-3" /> Evidence
            </Button>
            {canTriage && (
              <Button
                size="sm"
                className={cn(
                  "h-6 px-2 text-[10px] gap-1",
                  asset.status === "new"
                    ? "bg-primary text-primary-foreground hover:bg-primary/90"
                    : "variant-outline border-border text-muted-foreground hover:text-foreground bg-transparent border"
                )}
                onClick={() => onTriage(asset)}
              >
                <ChevronRight className="h-3 w-3" />
                {asset.status === "new" ? "Triage" : "Update"}
              </Button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function ShadowItPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const canTriage = ["admin", "super_admin", "manager"].includes(user?.role ?? "");

  // Filters
  const [assetStatus, setAssetStatus] = useState("new");
  const [assetRisk, setAssetRisk]     = useState<string>("");
  const [assetType, setAssetType]     = useState<string>("");
  const [assetSearch, setAssetSearch] = useState("");
  const [assetPage, setAssetPage]     = useState(0);
  const PAGE = 48;

  const [saasStatus, setSaasStatus]   = useState<string>("");

  // Triage dialog
  const [triageItem, setTriageItem]       = useState<ShadowAsset | null>(null);
  const [triageStatus, setTriageStatus]   = useState("approved");
  const [triageRisk, setTriageRisk]       = useState("");
  const [triageNote, setTriageNote]       = useState("");

  // Evidence dialog
  const [evidenceItem, setEvidenceItem]   = useState<ShadowAsset | null>(null);

  // Scan
  const [scanRunning, setScanRunning]     = useState(false);

  // ── Queries ────────────────────────────────────────────────────────────────

  const { data: summary, isLoading: summaryLoading } = useQuery<ShadowItSummary>({
    queryKey: ["shadow-it-summary"],
    queryFn: () => apiFetch<ShadowItSummary>("/api/shadow-it/summary"),
    refetchInterval: 30_000,
    staleTime: 20_000,
  });

  const assetParams = new URLSearchParams({
    limit: String(PAGE),
    offset: String(assetPage * PAGE),
    ...(assetStatus ? { status: assetStatus } : {}),
    ...(assetRisk   ? { riskLevel: assetRisk } : {}),
    ...(assetType   ? { type: assetType } : {}),
  });

  const { data: assetsData, isLoading: assetsLoading, refetch: refetchAssets, isFetching: assetsFetching } = useQuery<{ items: ShadowAsset[]; total: number }>({
    queryKey: ["shadow-it-assets", assetStatus, assetRisk, assetType, assetPage],
    queryFn: () => apiFetch<{ items: ShadowAsset[]; total: number }>(`/api/shadow-it/assets?${assetParams}`),
    staleTime: 20_000,
  });

  const saasParams = new URLSearchParams({
    limit: "100",
    ...(saasStatus ? { status: saasStatus } : {}),
  });

  const { data: saasData, isLoading: saasLoading } = useQuery<{ items: ShadowSaasApp[]; total: number }>({
    queryKey: ["shadow-it-saas", saasStatus],
    queryFn: () => apiFetch<{ items: ShadowSaasApp[]; total: number }>(`/api/shadow-it/saas?${saasParams}`),
    staleTime: 20_000,
  });

  // ── Mutations ──────────────────────────────────────────────────────────────

  const triageMutation = useMutation({
    mutationFn: ({ id, status, reviewNote, riskLevel }: { id: number; status: string; reviewNote: string; riskLevel?: string }) =>
      apiFetch(`/api/shadow-it/assets/${id}/triage`, {
        method: "PATCH",
        body: JSON.stringify({ status, reviewNote, ...(riskLevel ? { riskLevel } : {}) }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadow-it-assets"] });
      queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
      setTriageItem(null);
      toast({ title: "Asset updated", description: "Shadow IT asset triaged successfully." });
    },
    onError: () => toast({ title: "Update failed", variant: "destructive" }),
  });

  const saasMutation = useMutation({
    mutationFn: ({ id, isSanctioned }: { id: number; isSanctioned: boolean }) =>
      apiFetch(`/api/shadow-it/saas/${id}`, { method: "PATCH", body: JSON.stringify({ isSanctioned }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadow-it-saas"] });
      queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
    },
    onError: () => toast({ title: "Update failed", variant: "destructive" }),
  });

  const runScan = useCallback(async () => {
    setScanRunning(true);
    try {
      await apiFetch("/api/shadow-it/scan", { method: "POST", body: JSON.stringify({}) });
      toast({ title: "Shadow IT scan started", description: "Discovery running in background — results will appear shortly." });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["shadow-it-assets"] });
        queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
        setScanRunning(false);
      }, 8_000);
    } catch {
      toast({ title: "Scan failed", variant: "destructive" });
      setScanRunning(false);
    }
  }, [queryClient, toast]);

  const openTriage = (asset: ShadowAsset) => {
    setTriageItem(asset);
    setTriageStatus(asset.status === "new" ? "approved" : asset.status);
    setTriageRisk(asset.riskLevel);
    setTriageNote(asset.reviewNote ?? "");
  };

  // Client-side name filter
  const assets = (assetsData?.items ?? []).filter(a =>
    !assetSearch || a.name.toLowerCase().includes(assetSearch.toLowerCase())
  );

  const totalPages = Math.ceil((assetsData?.total ?? 0) / PAGE);

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full min-h-0 overflow-y-auto bg-background">

      {/* ── Hero Header ─────────────────────────────────────────────────────── */}
      <div className="relative overflow-hidden border-b border-border bg-gradient-to-br from-orange-950/30 via-background to-background px-6 py-5 shrink-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_var(--tw-gradient-stops))] from-orange-500/5 via-transparent to-transparent pointer-events-none" />
        <div className="relative flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="p-1.5 rounded-lg bg-orange-500/15 border border-orange-500/20">
                <EyeOff className="h-5 w-5 text-orange-400" />
              </div>
              <h1 className="text-xl font-bold tracking-tight">Shadow IT Discovery</h1>
              {(assetsFetching || summaryLoading) && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
            </div>
            <p className="text-sm text-muted-foreground">
              Assets, services, and SaaS apps discovered outside your registered inventory
            </p>
          </div>
          {canTriage && (
            <Button onClick={runScan} disabled={scanRunning} size="sm" className="h-8 gap-1.5 shrink-0">
              {scanRunning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {scanRunning ? "Scanning…" : "Run Discovery"}
            </Button>
          )}
        </div>

        {/* KPI strip */}
        <div className="relative mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            {
              label: "Total Discovered",
              value: (summary?.totalAssets ?? 0) + (summary?.totalSaasApps ?? 0),
              sub: "Assets + SaaS apps",
              accent: "border-border",
              valueColor: "text-foreground",
            },
            {
              label: "Pending Review",
              value: summary?.pendingReview ?? 0,
              sub: "Need triage",
              accent: (summary?.pendingReview ?? 0) > 0 ? "border-orange-500/30 bg-orange-500/5" : "border-border",
              valueColor: (summary?.pendingReview ?? 0) > 0 ? "text-orange-400" : "text-foreground",
            },
            {
              label: "Critical Risk",
              value: summary?.byRisk?.critical ?? 0,
              sub: "Immediate action",
              accent: (summary?.byRisk?.critical ?? 0) > 0 ? "border-red-500/30 bg-red-500/5" : "border-border",
              valueColor: (summary?.byRisk?.critical ?? 0) > 0 ? "text-red-400" : "text-foreground",
            },
            {
              label: "Approved",
              value: (summary?.approved ?? 0) + (summary?.remediated ?? 0),
              sub: "Reviewed & closed",
              accent: "border-border",
              valueColor: "text-green-400",
            },
          ].map((k) => (
            <div key={k.label} className={cn("rounded-xl border bg-card/60 backdrop-blur-sm px-4 py-3", k.accent)}>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">{k.label}</p>
              <p className={cn("text-2xl font-bold tabular-nums", k.valueColor)}>
                {summaryLoading ? <span className="text-muted-foreground/30">—</span> : k.value}
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{k.sub}</p>
            </div>
          ))}
        </div>

        {/* Risk distribution bar */}
        {summary && summary.totalAssets > 0 && (
          <div className="relative mt-3 space-y-1.5">
            <div className="flex items-center justify-between">
              <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide">Risk Distribution ({summary.totalAssets} assets)</p>
              <div className="flex items-center gap-3">
                {["critical","high","medium","low","info"].map(level => {
                  const n = summary.byRisk[level] ?? 0;
                  if (!n) return null;
                  const m = RISK_LEVEL_META[level];
                  return (
                    <span key={level} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                      <span className={cn("h-2 w-2 rounded-full", m.dot)} />
                      {m.label}: <strong className="text-foreground">{n}</strong>
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="flex h-1.5 rounded-full overflow-hidden gap-px bg-accent">
              {["critical","high","medium","low","info"].map(level => {
                const n = summary.byRisk[level] ?? 0;
                const pct = summary.totalAssets > 0 ? (n / summary.totalAssets) * 100 : 0;
                if (pct === 0) return null;
                return <div key={level} className={cn("h-full", RISK_LEVEL_META[level].bar)} style={{ width: `${pct}%` }} title={`${level}: ${n}`} />;
              })}
            </div>
          </div>
        )}
      </div>

      {/* ── Pending Review Alert ─────────────────────────────────────────────── */}
      {(summary?.pendingReview ?? 0) > 0 && (
        <div className="mx-6 mt-4 rounded-xl border border-orange-500/25 bg-orange-500/8 px-4 py-3 flex items-center justify-between gap-4 shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="p-2 rounded-lg bg-orange-500/15 shrink-0">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-orange-400">
                {summary!.pendingReview} asset{summary!.pendingReview !== 1 ? "s" : ""} pending review
              </p>
              <p className="text-xs text-muted-foreground mt-0.5">
                New shadow assets were discovered and require triage — approve, remediate, or mark as false positive.
              </p>
            </div>
          </div>
          <Button
            size="sm"
            className="h-8 gap-1.5 bg-orange-500 hover:bg-orange-600 text-white shrink-0"
            onClick={() => setAssetStatus("new")}
          >
            <ShieldAlert className="h-3.5 w-3.5" /> Review Now
          </Button>
        </div>
      )}

      {/* ── Tabs ────────────────────────────────────────────────────────────── */}
      <div className="flex-1 px-6 pb-6 pt-4">
        <Tabs defaultValue="assets" className="h-full flex flex-col">
          <TabsList className="h-9 shrink-0 mb-4">
            <TabsTrigger value="assets" className="gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              Unknown Assets
              {(summary?.pendingReview ?? 0) > 0 && (
                <span className="ml-1 h-4 min-w-4 px-1 rounded-full bg-orange-500 text-white text-[9px] font-bold flex items-center justify-center">
                  {summary!.pendingReview}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="saas" className="gap-1.5">
              <Cloud className="h-3.5 w-3.5" />
              Shadow SaaS
              {(summary?.totalSaasApps ?? 0) > 0 && (
                <span className="ml-1 h-4 min-w-4 px-1 rounded-full bg-purple-500 text-white text-[9px] font-bold flex items-center justify-center">
                  {summary!.totalSaasApps}
                </span>
              )}
            </TabsTrigger>
          </TabsList>

          {/* ── Assets Tab ─────────────────────────────────────────────────── */}
          <TabsContent value="assets" className="flex-1 mt-0 space-y-4">
            {/* Filter bar */}
            <div className="flex flex-wrap gap-2 items-center bg-card border border-border rounded-xl px-3 py-2.5">
              <Filter className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <div className="relative flex-1 min-w-[160px]">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search by name…"
                  value={assetSearch}
                  onChange={e => setAssetSearch(e.target.value)}
                  className="pl-7 h-7 text-xs bg-transparent border-0 shadow-none focus-visible:ring-0 focus-visible:ring-offset-0 p-0 pl-6"
                />
              </div>
              <div className="h-4 w-px bg-border" />
              <Select value={assetStatus || "_all"} onValueChange={v => { setAssetStatus(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="w-36 h-7 text-xs gap-1">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All Statuses</SelectItem>
                  <SelectItem value="new">New</SelectItem>
                  <SelectItem value="under_review">Under Review</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="remediated">Remediated</SelectItem>
                  <SelectItem value="false_positive">False Positive</SelectItem>
                </SelectContent>
              </Select>
              <Select value={assetRisk || "_all"} onValueChange={v => { setAssetRisk(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="w-32 h-7 text-xs gap-1">
                  <SelectValue placeholder="Risk" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All Risks</SelectItem>
                  <SelectItem value="critical">🔴 Critical</SelectItem>
                  <SelectItem value="high">🟠 High</SelectItem>
                  <SelectItem value="medium">🟡 Medium</SelectItem>
                  <SelectItem value="low">🔵 Low</SelectItem>
                  <SelectItem value="info">⚪ Info</SelectItem>
                </SelectContent>
              </Select>
              <Select value={assetType || "_all"} onValueChange={v => { setAssetType(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="w-40 h-7 text-xs gap-1">
                  <SelectValue placeholder="Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All Types</SelectItem>
                  <SelectItem value="subdomain">Subdomain</SelectItem>
                  <SelectItem value="cloud_bucket">Cloud Bucket</SelectItem>
                  <SelectItem value="admin_panel">Admin Panel</SelectItem>
                  <SelectItem value="shadow_service">Shadow Service</SelectItem>
                  <SelectItem value="unauthorized_tech">Unauth Tech</SelectItem>
                  <SelectItem value="ip_asset">IP Asset</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => refetchAssets()} title="Refresh">
                <RefreshCw className={cn("h-3.5 w-3.5", assetsFetching && "animate-spin")} />
              </Button>
              <span className="text-[10px] text-muted-foreground ml-auto tabular-nums">
                {assetsData?.total ?? 0} total
              </span>
            </div>

            {/* Asset grid */}
            {assetsLoading ? (
              <div className="flex flex-col items-center justify-center py-20 gap-3">
                <Loader2 className="h-7 w-7 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">Loading assets…</p>
              </div>
            ) : assets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-center gap-3 border border-dashed border-border rounded-xl">
                <div className="p-3 rounded-full bg-muted">
                  <Eye className="h-7 w-7 text-muted-foreground" />
                </div>
                <div>
                  <p className="font-medium">No shadow assets found</p>
                  <p className="text-sm text-muted-foreground mt-1 max-w-sm">
                    Shadow IT assets are discovered automatically during pipeline scans.
                    {canTriage && " Run a manual scan to check now."}
                  </p>
                </div>
                {canTriage && (
                  <Button variant="outline" size="sm" className="gap-1.5 mt-1" onClick={runScan} disabled={scanRunning}>
                    <Play className="h-3.5 w-3.5" /> Run Discovery Now
                  </Button>
                )}
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {assets.map(asset => (
                  <AssetCard
                    key={asset.id}
                    asset={asset}
                    canTriage={canTriage}
                    onTriage={openTriage}
                    onEvidence={setEvidenceItem}
                  />
                ))}
              </div>
            )}

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between text-xs pt-2">
                <span className="text-muted-foreground tabular-nums">
                  Page {assetPage + 1} of {totalPages} · {assetsData!.total} total
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" className="h-7 text-xs" disabled={assetPage === 0} onClick={() => setAssetPage(p => p - 1)}>
                    ← Previous
                  </Button>
                  <Button variant="outline" size="sm" className="h-7 text-xs" disabled={assetPage + 1 >= totalPages} onClick={() => setAssetPage(p => p + 1)}>
                    Next →
                  </Button>
                </div>
              </div>
            )}
          </TabsContent>

          {/* ── SaaS Tab ───────────────────────────────────────────────────── */}
          <TabsContent value="saas" className="flex-1 mt-0 space-y-4">
            {/* Info banner */}
            <div className="flex items-center gap-3 bg-purple-500/8 border border-purple-500/20 rounded-xl px-4 py-3">
              <div className="p-1.5 rounded-lg bg-purple-500/15 shrink-0">
                <Mail className="h-4 w-4 text-purple-400" />
              </div>
              <p className="text-xs text-muted-foreground">
                SaaS apps are discovered via <strong className="text-foreground">SPF records</strong>, <strong className="text-foreground">DKIM selectors</strong>, and JavaScript API analysis during pipeline scans.
              </p>
              <div className="ml-auto shrink-0">
                <Select value={saasStatus || "_all"} onValueChange={v => setSaasStatus(v === "_all" ? "" : v)}>
                  <SelectTrigger className="w-36 h-7 text-xs">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_all">All Statuses</SelectItem>
                    <SelectItem value="new">New</SelectItem>
                    <SelectItem value="sanctioned">Sanctioned</SelectItem>
                    <SelectItem value="revoked">Revoked</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {saasLoading ? (
              <div className="flex flex-col items-center justify-center py-20 gap-3">
                <Loader2 className="h-7 w-7 animate-spin text-muted-foreground" />
                <p className="text-sm text-muted-foreground">Loading SaaS apps…</p>
              </div>
            ) : (saasData?.items ?? []).length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 text-center gap-3 border border-dashed border-border rounded-xl">
                <div className="p-3 rounded-full bg-muted">
                  <Cloud className="h-7 w-7 text-muted-foreground" />
                </div>
                <div>
                  <p className="font-medium">No shadow SaaS apps found</p>
                  <p className="text-sm text-muted-foreground mt-1 max-w-sm">
                    SaaS apps are discovered from SPF includes and DKIM selectors in your domain's DNS records during pipeline scans.
                  </p>
                </div>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {(saasData?.items ?? []).map(app => (
                  <div
                    key={app.id}
                    className={cn(
                      "bg-card border border-border rounded-xl p-4 hover:shadow-md transition-all",
                      app.isSanctioned && "border-green-500/25",
                    )}
                  >
                    <div className="flex items-start justify-between mb-3">
                      <div className="min-w-0 flex-1">
                        <p className="font-semibold text-sm truncate">{app.appName}</p>
                        <p className="text-[10px] text-muted-foreground capitalize mt-0.5">{app.appCategory ?? "Other"}</p>
                      </div>
                      <div className="shrink-0 ml-2">
                        <RiskBadge level={app.riskRating} />
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-1 mb-3">
                      <span className="text-[10px] border border-border rounded px-1.5 py-0.5 text-muted-foreground">
                        {app.idpSource.replace(/_/g, " ")}
                      </span>
                      <StatusBadge status={app.status} />
                      {app.isSanctioned && (
                        <span className="text-[10px] bg-green-500/10 text-green-400 border border-green-500/20 px-1.5 py-0.5 rounded">
                          Sanctioned
                        </span>
                      )}
                    </div>
                    <p className="text-[10px] text-muted-foreground mb-3">
                      Discovered {fmtDate(app.createdAt)}
                    </p>
                    {canTriage && (
                      <div className="flex items-center justify-between border-t border-border/50 pt-2.5 mt-1">
                        <Label htmlFor={`sanction-${app.id}`} className="text-xs text-muted-foreground">Mark sanctioned</Label>
                        <Switch
                          id={`sanction-${app.id}`}
                          checked={app.isSanctioned}
                          onCheckedChange={checked => saasMutation.mutate({ id: app.id, isSanctioned: checked })}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>

      {/* ── Triage Dialog ─────────────────────────────────────────────────────── */}
      <Dialog open={!!triageItem} onOpenChange={() => setTriageItem(null)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-orange-400" />
              Triage Shadow IT Asset
            </DialogTitle>
          </DialogHeader>
          {triageItem && (
            <div className="space-y-4 mt-1">
              {/* Asset info */}
              <div className="p-3 rounded-lg bg-accent/50 border border-border">
                <div className="flex items-center gap-2 mb-2">
                  {TYPE_ICONS[triageItem.type] ?? <Layers className="w-4 h-4" />}
                  <span className="font-mono text-xs font-medium break-all">{triageItem.name}</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  <ClassBadge cls={triageItem.classification} />
                  <RiskBadge level={triageItem.riskLevel} />
                  <StatusBadge status={triageItem.status} />
                </div>
              </div>

              {/* Severity override */}
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">
                  Severity Override
                  <span className="ml-1 text-[10px] text-muted-foreground font-normal">(current: {triageItem.riskLevel})</span>
                </Label>
                <Select value={triageRisk} onValueChange={setTriageRisk}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-red-500" />
                        Critical
                      </span>
                    </SelectItem>
                    <SelectItem value="high">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-orange-500" />
                        High
                      </span>
                    </SelectItem>
                    <SelectItem value="medium">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-yellow-500" />
                        Medium
                      </span>
                    </SelectItem>
                    <SelectItem value="low">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-blue-500" />
                        Low
                      </span>
                    </SelectItem>
                    <SelectItem value="info">
                      <span className="flex items-center gap-2">
                        <span className="h-2 w-2 rounded-full bg-slate-400" />
                        Info
                      </span>
                    </SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-[10px] text-muted-foreground">
                  Override the system-assigned severity if you've assessed the risk differently.
                </p>
              </div>

              {/* Action */}
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">Action</Label>
                <Select value={triageStatus} onValueChange={setTriageStatus}>
                  <SelectTrigger className="h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="approved">✅ Approve — add to known inventory</SelectItem>
                    <SelectItem value="remediated">🛠 Remediated — issue resolved</SelectItem>
                    <SelectItem value="under_review">🔍 Under Review — needs investigation</SelectItem>
                    <SelectItem value="false_positive">❌ False Positive — not a concern</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Note */}
              <div className="space-y-1.5">
                <Label className="text-xs font-medium">Review Note <span className="text-muted-foreground font-normal">(optional)</span></Label>
                <Textarea
                  className="text-sm resize-none"
                  placeholder="Add context about this decision…"
                  value={triageNote}
                  onChange={e => setTriageNote(e.target.value)}
                  rows={3}
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setTriageItem(null)}>Cancel</Button>
            <Button
              onClick={() => triageItem && triageMutation.mutate({
                id: triageItem.id,
                status: triageStatus,
                reviewNote: triageNote,
                riskLevel: triageRisk !== triageItem.riskLevel ? triageRisk : undefined,
              })}
              disabled={triageMutation.isPending}
            >
              {triageMutation.isPending && <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />}
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Evidence Dialog ─────────────────────────────────────────────────── */}
      <Dialog open={!!evidenceItem} onOpenChange={() => setEvidenceItem(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <FileText className="h-4 w-4 text-blue-400" />
              Evidence — {evidenceItem?.name}
            </DialogTitle>
          </DialogHeader>
          {evidenceItem && (
            <div className="space-y-4 text-sm mt-1">
              {/* Details grid */}
              <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-accent/40 border border-border">
                {[
                  { label: "Type",           value: <span className="capitalize">{evidenceItem.type.replace(/_/g, " ")}</span> },
                  { label: "Source",         value: <span className="capitalize">{evidenceItem.source.replace(/_/g, " ")}</span> },
                  { label: "Classification", value: <ClassBadge cls={evidenceItem.classification} /> },
                  { label: "Risk",           value: <><RiskBadge level={evidenceItem.riskLevel} />{evidenceItem.riskScore != null && <span className="text-xs ml-1 text-muted-foreground">({Math.round(evidenceItem.riskScore)}/100)</span>}</> },
                  { label: "First Seen",     value: fmtDate(evidenceItem.firstSeenAt) },
                  { label: "Last Seen",      value: fmtDate(evidenceItem.lastSeenAt) },
                  ...(evidenceItem.certFirstSeen ? [{ label: "Cert First Seen", value: fmtDate(evidenceItem.certFirstSeen) }] : []),
                ].map(row => (
                  <div key={row.label}>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">{row.label}</p>
                    <div className="flex items-center gap-1">{row.value}</div>
                  </div>
                ))}
              </div>

              {/* Flags */}
              {(evidenceItem.hasOpenPorts || evidenceItem.hasAdminPanel || evidenceItem.hasAuthBypass || evidenceItem.isPubliclyAccessible) && (
                <div className="flex flex-wrap gap-1.5">
                  {evidenceItem.hasOpenPorts      && <span className="text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2 py-0.5 rounded">Open Dangerous Port</span>}
                  {evidenceItem.hasAdminPanel     && <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded">Admin Panel Exposed</span>}
                  {evidenceItem.hasAuthBypass     && <span className="text-xs bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded">No Authentication</span>}
                  {evidenceItem.isPubliclyAccessible && <span className="text-xs bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded">Publicly Accessible</span>}
                </div>
              )}

              {/* Review note */}
              {evidenceItem.reviewNote && (
                <div className="p-3 rounded-lg bg-accent/50 border border-border text-xs">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Review Note</p>
                  <p>{evidenceItem.reviewNote}</p>
                </div>
              )}

              {/* Raw evidence */}
              <div>
                <p className="text-[10px] font-medium text-muted-foreground mb-1.5 uppercase tracking-wide">Raw Evidence</p>
                <pre className="bg-accent/50 border border-border rounded-lg p-3 text-xs overflow-x-auto max-h-56 leading-relaxed whitespace-pre-wrap break-all">
                  {evidenceItem.evidence ? JSON.stringify(evidenceItem.evidence, null, 2) : "No evidence stored"}
                </pre>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEvidenceItem(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
