import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  Play, ChevronRight, Layers, Mail, Activity,
} from "lucide-react";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";

// ── Types ─────────────────────────────────────────────────────────────────────

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

// ── Risk / type helpers ───────────────────────────────────────────────────────

function riskBadge(level: string) {
  const map: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high:     "bg-orange-500 text-white",
    medium:   "bg-yellow-500 text-black",
    low:      "bg-blue-500 text-white",
    info:     "bg-gray-500 text-white",
  };
  return <Badge className={`text-xs font-semibold ${map[level] ?? "bg-gray-500 text-white"}`}>{level.toUpperCase()}</Badge>;
}

function classificationBadge(cls: string) {
  const map: Record<string, { label: string; className: string }> = {
    forgotten:         { label: "Forgotten",         className: "bg-orange-100 text-orange-800 border border-orange-300" },
    rogue:             { label: "Rogue",              className: "bg-red-100 text-red-800 border border-red-300" },
    development:       { label: "Development",        className: "bg-blue-100 text-blue-800 border border-blue-300" },
    saas:              { label: "SaaS",               className: "bg-purple-100 text-purple-800 border border-purple-300" },
    cloud:             { label: "Cloud",              className: "bg-sky-100 text-sky-800 border border-sky-300" },
    unauthorized_stack:{ label: "Unauth Stack",       className: "bg-yellow-100 text-yellow-800 border border-yellow-300" },
  };
  const cfg = map[cls] ?? { label: cls, className: "bg-gray-100 text-gray-800" };
  return <Badge variant="outline" className={`text-xs ${cfg.className}`}>{cfg.label}</Badge>;
}

function typeIcon(type: string) {
  const iconMap: Record<string, React.ReactNode> = {
    subdomain:          <Globe className="w-4 h-4 text-blue-400" />,
    cloud_bucket:       <Cloud className="w-4 h-4 text-sky-400" />,
    email_service:      <Mail className="w-4 h-4 text-purple-400" />,
    admin_panel:        <Terminal className="w-4 h-4 text-red-400" />,
    shadow_service:     <Server className="w-4 h-4 text-orange-400" />,
    unauthorized_tech:  <Cpu className="w-4 h-4 text-yellow-400" />,
    ip_asset:           <Activity className="w-4 h-4 text-gray-400" />,
  };
  return iconMap[type] ?? <Layers className="w-4 h-4 text-gray-400" />;
}

function statusBadge(status: string) {
  const map: Record<string, { label: string; className: string; icon: React.ReactNode }> = {
    new:            { label: "New",           className: "bg-blue-100 text-blue-800",    icon: <AlertTriangle className="w-3 h-3" /> },
    under_review:   { label: "Reviewing",     className: "bg-yellow-100 text-yellow-800", icon: <Clock className="w-3 h-3" /> },
    approved:       { label: "Approved",      className: "bg-green-100 text-green-800",  icon: <CheckCircle className="w-3 h-3" /> },
    remediated:     { label: "Remediated",    className: "bg-emerald-100 text-emerald-800", icon: <CheckCircle className="w-3 h-3" /> },
    false_positive: { label: "False Positive", className: "bg-gray-100 text-gray-600",   icon: <XCircle className="w-3 h-3" /> },
  };
  const cfg = map[status] ?? { label: status, className: "bg-gray-100 text-gray-600", icon: null };
  return (
    <Badge className={`flex items-center gap-1 text-xs ${cfg.className}`}>
      {cfg.icon}{cfg.label}
    </Badge>
  );
}

function fmtDate(d: string | null) {
  if (!d) return "—";
  return new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function ShadowItPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const canTriage = ["admin", "super_admin", "manager"].includes(user?.role ?? "");

  // Filters (assets tab)
  const [assetStatus, setAssetStatus]   = useState("new");
  const [assetRisk, setAssetRisk]       = useState<string>("");
  const [assetType, setAssetType]       = useState<string>("");
  const [assetSearch, setAssetSearch]   = useState("");
  const [assetPage, setAssetPage]       = useState(0);
  const PAGE = 50;

  // Filters (saas tab)
  const [saasStatus, setSaasStatus]     = useState<string>("");

  // Triage drawer
  const [triageItem, setTriageItem]     = useState<ShadowAsset | null>(null);
  const [triageStatus, setTriageStatus] = useState("approved");
  const [triageNote, setTriageNote]     = useState("");

  // Evidence drawer
  const [evidenceItem, setEvidenceItem] = useState<ShadowAsset | null>(null);

  // Scan running flag
  const [scanRunning, setScanRunning]   = useState(false);

  // ── Queries ──────────────────────────────────────────────────────────────────

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

  const { data: assetsData, isLoading: assetsLoading, refetch: refetchAssets } = useQuery<{ items: ShadowAsset[]; total: number }>({
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

  // ── Mutations ─────────────────────────────────────────────────────────────────

  const triageMutation = useMutation({
    mutationFn: ({ id, status, reviewNote }: { id: number; status: string; reviewNote: string }) =>
      apiFetch(`/api/shadow-it/assets/${id}/triage`, { method: "PATCH", body: JSON.stringify({ status, reviewNote }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["shadow-it-assets"] });
      queryClient.invalidateQueries({ queryKey: ["shadow-it-summary"] });
      setTriageItem(null);
      toast({ title: "Asset triaged", description: "Shadow IT asset status updated." });
    },
    onError: () => toast({ title: "Triage failed", variant: "destructive" }),
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
      toast({ title: "Shadow IT scan started", description: "Discovery is running in the background. Results will appear automatically." });
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

  // Filtered assets (client-side search on name)
  const assets = (assetsData?.items ?? []).filter(a =>
    !assetSearch || a.name.toLowerCase().includes(assetSearch.toLowerCase())
  );

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <EyeOff className="w-6 h-6 text-orange-500" />
              Shadow IT Discovery
            </h1>
            <p className="text-muted-foreground text-sm mt-1">
              Assets, services, and SaaS apps discovered outside your registered inventory
            </p>
          </div>
          {canTriage && (
            <Button onClick={runScan} disabled={scanRunning} className="gap-2">
              {scanRunning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              {scanRunning ? "Scanning…" : "Run Shadow IT Scan"}
            </Button>
          )}
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Total Discovered</p>
              <p className="text-3xl font-bold mt-1">{summaryLoading ? "—" : (summary?.totalAssets ?? 0) + (summary?.totalSaasApps ?? 0)}</p>
              <p className="text-xs text-muted-foreground mt-1">Assets + SaaS apps</p>
            </CardContent>
          </Card>
          <Card className="border-red-200 bg-red-50 dark:bg-red-950/20">
            <CardContent className="pt-4">
              <p className="text-xs text-red-600 uppercase tracking-wide font-medium">Pending Review</p>
              <p className="text-3xl font-bold text-red-600 mt-1">{summaryLoading ? "—" : summary?.pendingReview ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Need triage</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wide">Critical Risk</p>
              <p className="text-3xl font-bold text-red-600 mt-1">{summaryLoading ? "—" : summary?.byRisk?.critical ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Critical assets</p>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="pt-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wide">SaaS Discovered</p>
              <p className="text-3xl font-bold text-purple-600 mt-1">{summaryLoading ? "—" : summary?.totalSaasApps ?? 0}</p>
              <p className="text-xs text-muted-foreground mt-1">Via SPF / DKIM analysis</p>
            </CardContent>
          </Card>
        </div>

        {/* Risk breakdown bar */}
        {summary && (summary.totalAssets > 0) && (
          <div className="space-y-1">
            <p className="text-xs text-muted-foreground font-medium">Risk Distribution (Shadow Assets)</p>
            <div className="flex h-2 rounded-full overflow-hidden gap-0.5">
              {["critical", "high", "medium", "low", "info"].map(level => {
                const n = summary.byRisk[level] ?? 0;
                const pct = summary.totalAssets > 0 ? (n / summary.totalAssets) * 100 : 0;
                if (pct === 0) return null;
                const colorMap: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-blue-500", info: "bg-gray-400" };
                return <div key={level} className={`${colorMap[level]} h-full`} style={{ width: `${pct}%` }} title={`${level}: ${n}`} />;
              })}
            </div>
            <div className="flex gap-3 flex-wrap">
              {["critical", "high", "medium", "low", "info"].map(level => {
                const n = summary.byRisk[level] ?? 0;
                if (!n) return null;
                const colorMap: Record<string, string> = { critical: "text-red-600", high: "text-orange-500", medium: "text-yellow-600", low: "text-blue-600", info: "text-gray-500" };
                return <span key={level} className={`text-xs ${colorMap[level]}`}>{level}: <strong>{n}</strong></span>;
              })}
            </div>
          </div>
        )}

        {/* Main Tabs */}
        <Tabs defaultValue="assets" className="w-full">
          <TabsList>
            <TabsTrigger value="assets">
              <ShieldAlert className="w-4 h-4 mr-2" />
              Unknown Assets
              {(summary?.pendingReview ?? 0) > 0 && (
                <Badge className="ml-2 bg-red-500 text-white text-xs">{summary?.pendingReview}</Badge>
              )}
            </TabsTrigger>
            <TabsTrigger value="saas">
              <Cloud className="w-4 h-4 mr-2" />
              Shadow SaaS
              {(summary?.totalSaasApps ?? 0) > 0 && (
                <Badge className="ml-2 bg-purple-500 text-white text-xs">{summary?.totalSaasApps}</Badge>
              )}
            </TabsTrigger>
          </TabsList>

          {/* ── Assets Tab ─────────────────────────────────────────────────── */}
          <TabsContent value="assets" className="space-y-4 mt-4">
            <div className="flex flex-wrap gap-2 items-center">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search by name…"
                  value={assetSearch}
                  onChange={e => setAssetSearch(e.target.value)}
                  className="pl-8"
                />
              </div>
              <Select value={assetStatus} onValueChange={v => { setAssetStatus(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="w-36"><SelectValue placeholder="Status" /></SelectTrigger>
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
                <SelectTrigger className="w-32"><SelectValue placeholder="Risk" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="_all">All Risks</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={assetType || "_all"} onValueChange={v => { setAssetType(v === "_all" ? "" : v); setAssetPage(0); }}>
                <SelectTrigger className="w-40"><SelectValue placeholder="Type" /></SelectTrigger>
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
              <Button variant="ghost" size="icon" onClick={() => refetchAssets()} title="Refresh">
                <RefreshCw className="w-4 h-4" />
              </Button>
              <span className="text-xs text-muted-foreground ml-auto">
                {assetsData?.total ?? 0} total
              </span>
            </div>

            {assetsLoading ? (
              <div className="flex items-center justify-center h-32 text-muted-foreground">
                <RefreshCw className="w-4 h-4 animate-spin mr-2" />Loading…
              </div>
            ) : assets.length === 0 ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <Eye className="w-10 h-10 text-muted-foreground mb-3" />
                  <p className="font-medium">No shadow assets found</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    Shadow IT assets are discovered automatically during pipeline scans and daily discovery runs.
                    {canTriage && " Run a manual scan to check now."}
                  </p>
                  {canTriage && (
                    <Button variant="outline" className="mt-4 gap-2" onClick={runScan} disabled={scanRunning}>
                      <Play className="w-4 h-4" />Run Discovery Now
                    </Button>
                  )}
                </CardContent>
              </Card>
            ) : (
              <div className="rounded-md border overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr className="text-left">
                      <th className="px-3 py-2 font-medium text-muted-foreground">Asset</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Type</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Classification</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Risk</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Source</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">First Seen</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Status</th>
                      <th className="px-3 py-2 font-medium text-muted-foreground">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {assets.map(asset => (
                      <tr key={asset.id} className="hover:bg-muted/30 transition-colors">
                        <td className="px-3 py-2.5 max-w-[240px]">
                          <div className="flex items-center gap-2">
                            {typeIcon(asset.type)}
                            <span className="truncate font-mono text-xs">{asset.name}</span>
                          </div>
                          <div className="flex gap-1 mt-0.5 ml-6">
                            {asset.hasOpenPorts && <span className="text-[10px] text-orange-500">⬤ open port</span>}
                            {asset.hasAdminPanel && <span className="text-[10px] text-red-500">⬤ admin panel</span>}
                            {asset.hasAuthBypass && <span className="text-[10px] text-red-600">⬤ no auth</span>}
                            {asset.isPubliclyAccessible && <span className="text-[10px] text-blue-500">⬤ public</span>}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="text-xs capitalize text-muted-foreground">{asset.type.replace(/_/g, " ")}</span>
                        </td>
                        <td className="px-3 py-2.5">{classificationBadge(asset.classification)}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            {riskBadge(asset.riskLevel)}
                            {asset.riskScore != null && (
                              <span className="text-xs text-muted-foreground">{Math.round(asset.riskScore)}</span>
                            )}
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className="text-xs text-muted-foreground capitalize">{asset.source.replace(/_/g, " ")}</span>
                        </td>
                        <td className="px-3 py-2.5 text-xs text-muted-foreground whitespace-nowrap">{fmtDate(asset.firstSeenAt)}</td>
                        <td className="px-3 py-2.5">{statusBadge(asset.status)}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex gap-1">
                            <Button variant="ghost" size="icon" className="h-7 w-7" title="View evidence" onClick={() => setEvidenceItem(asset)}>
                              <Search className="w-3.5 h-3.5" />
                            </Button>
                            {canTriage && (
                              <Button variant="ghost" size="icon" className="h-7 w-7" title="Triage" onClick={() => { setTriageItem(asset); setTriageStatus("approved"); setTriageNote(""); }}>
                                <ChevronRight className="w-3.5 h-3.5" />
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination */}
            {(assetsData?.total ?? 0) > PAGE && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">
                  Showing {assetPage * PAGE + 1}–{Math.min((assetPage + 1) * PAGE, assetsData!.total)} of {assetsData!.total}
                </span>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" disabled={assetPage === 0} onClick={() => setAssetPage(p => p - 1)}>Previous</Button>
                  <Button variant="outline" size="sm" disabled={(assetPage + 1) * PAGE >= (assetsData?.total ?? 0)} onClick={() => setAssetPage(p => p + 1)}>Next</Button>
                </div>
              </div>
            )}
          </TabsContent>

          {/* ── SaaS Tab ───────────────────────────────────────────────────── */}
          <TabsContent value="saas" className="space-y-4 mt-4">
            <div className="flex flex-wrap gap-2 items-center">
              <div className="flex items-center gap-2 bg-purple-50 dark:bg-purple-950/20 rounded-md p-2 border border-purple-200 text-xs text-purple-700 dark:text-purple-300">
                <Mail className="w-4 h-4" />
                SaaS apps are discovered via SPF records, DKIM selectors, and JavaScript API analysis during pipeline scans.
              </div>
              <div className="ml-auto flex gap-2 items-center">
                <Select value={saasStatus || "_all"} onValueChange={v => setSaasStatus(v === "_all" ? "" : v)}>
                  <SelectTrigger className="w-36"><SelectValue placeholder="Status" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_all">All Statuses</SelectItem>
                    <SelectItem value="new">New</SelectItem>
                    <SelectItem value="sanctioned">Sanctioned</SelectItem>
                    <SelectItem value="revoked">Revoked</SelectItem>
                  </SelectContent>
                </Select>
                <span className="text-xs text-muted-foreground">{saasData?.total ?? 0} total</span>
              </div>
            </div>

            {saasLoading ? (
              <div className="flex items-center justify-center h-32 text-muted-foreground">
                <RefreshCw className="w-4 h-4 animate-spin mr-2" />Loading…
              </div>
            ) : (saasData?.items ?? []).length === 0 ? (
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <Cloud className="w-10 h-10 text-muted-foreground mb-3" />
                  <p className="font-medium">No shadow SaaS apps found</p>
                  <p className="text-sm text-muted-foreground mt-1">
                    SaaS apps are discovered from SPF includes and DKIM selectors in your domain's DNS records during scans.
                    Run a pipeline scan on a domain asset to discover email SaaS services.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                {(saasData?.items ?? []).map(app => (
                  <Card key={app.id} className={`transition-colors ${app.isSanctioned ? "border-green-200" : ""}`}>
                    <CardContent className="pt-4 pb-3">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <p className="font-semibold text-sm">{app.appName}</p>
                          <p className="text-xs text-muted-foreground capitalize">{app.appCategory ?? "Other"}</p>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          {riskBadge(app.riskRating)}
                          {app.isSanctioned && (
                            <Badge className="text-[10px] bg-green-100 text-green-700">Sanctioned</Badge>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1 mb-2">
                        <Badge variant="outline" className="text-[10px]">
                          {app.idpSource.replace(/_/g, " ")}
                        </Badge>
                        {statusBadge(app.status)}
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">
                        Discovered {fmtDate(app.createdAt)}
                      </p>
                      {canTriage && (
                        <div className="flex items-center justify-between border-t pt-2 mt-1">
                          <Label htmlFor={`sanction-${app.id}`} className="text-xs">Sanctioned</Label>
                          <Switch
                            id={`sanction-${app.id}`}
                            checked={app.isSanctioned}
                            onCheckedChange={checked => saasMutation.mutate({ id: app.id, isSanctioned: checked })}
                          />
                        </div>
                      )}
                    </CardContent>
                  </Card>
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
            <DialogTitle>Triage Shadow IT Asset</DialogTitle>
          </DialogHeader>
          {triageItem && (
            <div className="space-y-4">
              <div className="p-3 rounded-md bg-muted/50 font-mono text-sm break-all">
                {triageItem.name}
              </div>
              <div className="flex gap-2">
                {classificationBadge(triageItem.classification)}
                {riskBadge(triageItem.riskLevel)}
              </div>
              <div>
                <Label className="text-xs font-medium">Action</Label>
                <Select value={triageStatus} onValueChange={setTriageStatus}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="approved">Approve — add to known inventory</SelectItem>
                    <SelectItem value="remediated">Remediated — issue resolved</SelectItem>
                    <SelectItem value="under_review">Under Review — needs investigation</SelectItem>
                    <SelectItem value="false_positive">False Positive — not a concern</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs font-medium">Note (optional)</Label>
                <Textarea
                  className="mt-1 text-sm"
                  placeholder="Add a review note…"
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
              onClick={() => triageItem && triageMutation.mutate({ id: triageItem.id, status: triageStatus, reviewNote: triageNote })}
              disabled={triageMutation.isPending}
            >
              {triageMutation.isPending ? "Saving…" : "Save Triage"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Evidence Drawer ───────────────────────────────────────────────────── */}
      <Dialog open={!!evidenceItem} onOpenChange={() => setEvidenceItem(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Search className="w-4 h-4" />
              Evidence — {evidenceItem?.name}
            </DialogTitle>
          </DialogHeader>
          {evidenceItem && (
            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div><span className="text-muted-foreground">Type:</span> <span className="capitalize">{evidenceItem.type.replace(/_/g, " ")}</span></div>
                <div><span className="text-muted-foreground">Source:</span> <span className="capitalize">{evidenceItem.source.replace(/_/g, " ")}</span></div>
                <div><span className="text-muted-foreground">Classification:</span> {classificationBadge(evidenceItem.classification)}</div>
                <div><span className="text-muted-foreground">Risk:</span> {riskBadge(evidenceItem.riskLevel)} {evidenceItem.riskScore != null && <span className="text-xs ml-1">({Math.round(evidenceItem.riskScore)}/100)</span>}</div>
                <div><span className="text-muted-foreground">First Seen:</span> {fmtDate(evidenceItem.firstSeenAt)}</div>
                <div><span className="text-muted-foreground">Last Seen:</span> {fmtDate(evidenceItem.lastSeenAt)}</div>
                {evidenceItem.certFirstSeen && (
                  <div className="col-span-2"><span className="text-muted-foreground">Cert First Seen:</span> {fmtDate(evidenceItem.certFirstSeen)}</div>
                )}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {evidenceItem.hasOpenPorts && <Badge variant="destructive" className="text-xs">Open Dangerous Port</Badge>}
                {evidenceItem.hasAdminPanel && <Badge className="text-xs bg-orange-500">Admin Panel Exposed</Badge>}
                {evidenceItem.hasAuthBypass && <Badge variant="destructive" className="text-xs">No Authentication</Badge>}
                {evidenceItem.isPubliclyAccessible && <Badge className="text-xs bg-blue-500">Publicly Accessible</Badge>}
              </div>
              {evidenceItem.reviewNote && (
                <div className="p-2 rounded bg-muted text-xs">
                  <span className="font-medium">Review note:</span> {evidenceItem.reviewNote}
                </div>
              )}
              <div>
                <p className="text-xs font-medium text-muted-foreground mb-1 uppercase tracking-wide">Raw Evidence</p>
                <pre className="bg-muted rounded-md p-3 text-xs overflow-x-auto max-h-64 leading-relaxed whitespace-pre-wrap break-all">
                  {JSON.stringify(evidenceItem.evidence, null, 2) ?? "No evidence stored"}
                </pre>
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEvidenceItem(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
