import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useLocation } from "wouter";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useGetAsset, useListFindings, useGetAssetRiskScore, useCheckAssetVerification,
  useListAssetTechnologies, useRunTechScan, useListAssetScreenshots, useRunScreenshotScan,
  useUpdateAsset, useListBrandThreats, useListUsers, useListScans, useCancelScan,
  useListAssetPorts,
  getGetAssetQueryKey, getListFindingsQueryKey, getGetAssetRiskScoreQueryKey,
  getListAssetTechnologiesQueryKey, getListAssetScreenshotsQueryKey, getListBrandThreatsQueryKey,
  getListScansQueryKey, getListAssetPortsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient, useQuery, useMutation } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import {
  ArrowLeft, ExternalLink, ShieldCheck, Cpu, Loader2, RefreshCw, Camera, AlertTriangle, X,
  ChevronLeft, ChevronRight, Download, ShieldAlert, Fish, DatabaseZap, Siren, UserCheck,
  Brain, Sparkles, ChevronDown, ChevronUp, Network, BookmarkCheck, AtSign, Smartphone,
  Mail, Search, Image, Server, ClipboardCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Link } from "wouter";
import { cn, severityBgColor, statusBadgeClass, riskLevelBg, capitalize, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { downloadAssetPdf } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";

const CATEGORY_COLOR: Record<string, string> = {
  "Web Server":           "bg-blue-500/10 text-blue-400 border-blue-500/20",
  "CMS":                  "bg-purple-500/10 text-purple-400 border-purple-500/20",
  "E-commerce":           "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  "JavaScript Framework": "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  "JavaScript Library":   "bg-sky-500/10 text-sky-400 border-sky-500/20",
  "UI Framework":         "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  "CSS Framework":        "bg-violet-500/10 text-violet-400 border-violet-500/20",
  "Programming Language": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "Web Framework":        "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "CDN":                  "bg-slate-500/10 text-slate-400 border-slate-500/20",
  "Analytics":            "bg-rose-500/10 text-rose-400 border-rose-500/20",
  "Tag Manager":          "bg-pink-500/10 text-pink-400 border-pink-500/20",
  "Security":             "bg-red-500/10 text-red-400 border-red-500/20",
  "Payment":              "bg-green-500/10 text-green-400 border-green-500/20",
  "PaaS":                 "bg-teal-500/10 text-teal-400 border-teal-500/20",
  "Caching":              "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
};

const PAGE_TYPE_BADGE: Record<string, string> = {
  index:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  login:     "bg-amber-500/15 text-amber-400 border-amber-500/30",
  signup:    "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  admin:     "bg-red-500/15 text-red-400 border-red-500/30",
  api:       "bg-purple-500/15 text-purple-400 border-purple-500/30",
  sensitive: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  error:     "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

const FINDING_SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

function categoryColor(cat: string) {
  return CATEGORY_COLOR[cat] ?? "bg-muted text-muted-foreground border-border";
}

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { user } = useAuth();
  const [verifying, setVerifying]             = useState(false);
  const [scanning, setScanning]               = useState(false);
  const [screenshotting, setScreenshotting]   = useState(false);
  const [downloading, setDownloading]         = useState(false);
  const [expandedShot, setExpandedShot]       = useState<any | null>(null);
  const [findingsPage, setFindingsPage]       = useState(0);
  const [businessImpact, setBusinessImpact]   = useState<number>(5);
  const [savingImpact, setSavingImpact]       = useState(false);
  const [assignedClientId, setAssignedClientId]       = useState<string>("_none_");
  const [assignedAmId, setAssignedAmId]               = useState<string>("_none_");
  const [savingAssignment, setSavingAssignment]       = useState(false);
  const [cancellingId, setCancellingId]               = useState<number | null>(null);

  const BASE_URL = import.meta.env.BASE_URL.replace(/\/$/, "");

  // ── Compliance tracking toggle (verified assets only) ──────────────────────
  const { data: complianceSettings, refetch: refetchCompliance } = useQuery({
    queryKey: ["asset-compliance-settings", id],
    queryFn: () => apiFetch(`${BASE_URL}/api/compliance/assets/${id}/settings`),
    enabled: !!id,
    retry: false,
  });
  const complianceEnabled = (complianceSettings as any)?.isEnabled ?? false;
  const complianceIsVerified = (complianceSettings as any)?.verificationStatus === "verified";

  const toggleCompliance = useMutation({
    mutationFn: (isEnabled: boolean) =>
      apiFetch(`${BASE_URL}/api/compliance/assets/${id}/settings`, {
        method: "PATCH",
        body: JSON.stringify({ isEnabled }),
      }),
    onSuccess: () => {
      refetchCompliance();
      toast({ title: complianceEnabled ? "Compliance tracking disabled" : "Compliance tracking enabled" });
    },
    onError: (e: any) => toast({ title: e?.message ?? "Failed", variant: "destructive" }),
  });

  // ── AI risk explanation state ─────────────────────────────────────────────
  const [showAiRisk, setShowAiRisk]     = useState(false);
  const [aiRiskText, setAiRiskText]     = useState("");
  const [aiRiskLoading, setAiRiskLoading] = useState(false);
  const [aiRiskNoKey, setAiRiskNoKey]   = useState(false);
  const [aiRiskModel, setAiRiskModel]   = useState<string | null>(null);
  const aiRiskAbort                     = useRef(false);
  const BASE_AI = import.meta.env.BASE_URL.replace(/\/$/, "");

  const triggerRiskExplain = useCallback(async () => {
    if (aiRiskLoading) return;
    aiRiskAbort.current = false;
    setAiRiskText(""); setAiRiskLoading(true); setAiRiskNoKey(false); setAiRiskModel(null);
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    try {
      const resp = await fetch(`${BASE_AI}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: "explain-risk-score", assetId: id }),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        if (aiRiskAbort.current) { reader.cancel(); break; }
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.noKey) setAiRiskNoKey(true);
            if (d.provider) setAiRiskModel(d.provider);
            if (d.text) { accumulated += d.text; setAiRiskText(accumulated); }
          } catch { /* ignore */ }
        }
      }
    } catch { setAiRiskText(accumulated || "Failed to generate AI explanation. Please try again."); }
    setAiRiskLoading(false);
  }, [id, BASE_AI]);

  const canEditAssignment = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";

  const updateAsset = useUpdateAsset();
  const { data: usersData } = useListUsers();

  const { data: asset, isLoading } = useGetAsset(id, {
    query: { enabled: !!id, queryKey: getGetAssetQueryKey(id) },
  });
  const { data: findings } = useListFindings({ assetId: id } as any, {
    query: { enabled: !!id, queryKey: getListFindingsQueryKey({ assetId: id }) },
  });
  const { data: riskScore } = useGetAssetRiskScore(id, {
    query: { enabled: !!id, queryKey: getGetAssetRiskScoreQueryKey(id) },
  });
  const { data: technologies, refetch: refetchTechs } = useListAssetTechnologies(id, {
    query: { enabled: !!id, queryKey: getListAssetTechnologiesQueryKey(id) },
  });
  const { data: screenshots, refetch: refetchScreenshots } = useListAssetScreenshots(id, {
    query: { enabled: !!id, queryKey: getListAssetScreenshotsQueryKey(id) },
  });
  const { data: brandThreats } = useListBrandThreats({
    query: { enabled: !!id, queryKey: getListBrandThreatsQueryKey(), staleTime: 30_000 },
  });

  const { data: portsData } = useListAssetPorts(id, {
    query: { enabled: !!id, queryKey: getListAssetPortsQueryKey(id) },
  });

  const { data: scansData } = useListScans(
    { assetId: id } as any,
    {
      query: {
        enabled: !!id,
        queryKey: getListScansQueryKey({ assetId: id } as any),
        refetchInterval: (query) => {
          const scans: any[] = (query as any).state?.data ?? [];
          return scans.some((s: any) => s.status === "running" || s.status === "pending") ? 4000 : false;
        },
      },
    },
  );
  const runningScan = ((scansData as any[]) ?? []).find(s => s.status === "running" || s.status === "pending") ?? null;

  const cancelScan = useCancelScan();

  const handleCancelScan = async (scanId: number) => {
    setCancellingId(scanId);
    try {
      await cancelScan.mutateAsync({ scanId });
      queryClient.invalidateQueries({ queryKey: getListScansQueryKey({ assetId: id } as any) });
      toast({ title: "Scan cancelled" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to cancel scan", variant: "destructive" });
    } finally {
      setCancellingId(null);
    }
  };

  const verifyAsset  = useCheckAssetVerification();
  const runTechScan  = useRunTechScan();
  const runShotScan  = useRunScreenshotScan();

  const handleVerify = async () => {
    setVerifying(true);
    try {
      await verifyAsset.mutateAsync({ assetId: id });
      queryClient.invalidateQueries({ queryKey: getGetAssetQueryKey(id) });
    } finally {
      setVerifying(false);
    }
  };

  const handleTechScan = async () => {
    setScanning(true);
    try {
      const res = await runTechScan.mutateAsync({ assetId: id });
      await refetchTechs();
      const count = (res as any)?.technologies?.length ?? 0;
      toast({ title: `Technology scan complete`, description: `${count} technolog${count === 1 ? "y" : "ies"} detected.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Tech scan failed", variant: "destructive" });
    } finally {
      setScanning(false);
    }
  };

  const handleScreenshotScan = async () => {
    setScreenshotting(true);
    try {
      const res = await runShotScan.mutateAsync({ assetId: id });
      await refetchScreenshots();
      const count = (res as any)?.screenshots?.length ?? 0;
      toast({ title: `Screenshot scan complete`, description: `${count} page${count === 1 ? "" : "s"} captured.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Screenshot scan failed", variant: "destructive" });
    } finally {
      setScreenshotting(false);
    }
  };

  const a     = asset as any;
  const rs    = riskScore as any;

  function normalizeDomain(val: string): string {
    return val.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
  }

  const assetDomain = a?.value ? normalizeDomain(String(a.value)) : null;
  const matchingBrandScan = assetDomain
    ? ((brandThreats as any[]) ?? []).find(
        (s: any) =>
          normalizeDomain(s.domain) === assetDomain &&
          ((s.phishingCount ?? 0) > 0 || (s.dataLeakCount ?? 0) > 0)
      )
    : null;

  const users = (usersData as any[]) ?? [];
  const clientUsers = users.filter((u: any) => u.role === "client");
  const amUsers = users.filter((u: any) => u.role === "account_manager");

  // Sync assignment state when asset loads
  useEffect(() => {
    setAssignedClientId(a?.assignedClientId != null ? String(a.assignedClientId) : "_none_");
    setAssignedAmId(a?.assignedAccountManagerId != null ? String(a.assignedAccountManagerId) : "_none_");
  }, [a?.assignedClientId, a?.assignedAccountManagerId]);

  // Sync local businessImpact state when asset loads
  useEffect(() => {
    if (a?.businessImpact != null) setBusinessImpact(a.businessImpact);
  }, [a?.businessImpact]);

  const handleSaveAssignment = async () => {
    setSavingAssignment(true);
    try {
      await updateAsset.mutateAsync({
        assetId: id,
        data: {
          assignedClientId: assignedClientId === "_none_" ? null : parseInt(assignedClientId),
          assignedAccountManagerId: assignedAmId === "_none_" ? null : parseInt(assignedAmId),
        } as any,
      });
      queryClient.invalidateQueries({ queryKey: getGetAssetQueryKey(id) });
      toast({ title: "Assignment saved", description: "Asset assignment has been updated." });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to save assignment", variant: "destructive" });
    } finally {
      setSavingAssignment(false);
    }
  };

  const handleSaveBusinessImpact = async (val: number) => {
    setSavingImpact(true);
    try {
      await updateAsset.mutateAsync({ assetId: id, data: { businessImpact: val } });
      queryClient.invalidateQueries({ queryKey: getGetAssetQueryKey(id) });
      queryClient.invalidateQueries({ queryKey: getGetAssetRiskScoreQueryKey(id) });
      toast({ title: "Business impact updated", description: `Set to ${val}/10 — risk score will reflect this on next calculation.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to save", variant: "destructive" });
    } finally {
      setSavingImpact(false);
    }
  };
  const techs = (technologies as any[]) ?? [];
  const shots = (screenshots as any[]) ?? [];

  const grouped: Record<string, any[]> = {};
  for (const t of techs) {
    if (!grouped[t.category]) grouped[t.category] = [];
    grouped[t.category].push(t);
  }

  const webTypes = ["domain", "subdomain", "url", "ip"];
  const canScan  = a && webTypes.includes(a.type);

  const totalFindings = shots.reduce((n: number, s: any) => n + ((s.findings as any[])?.length ?? 0), 0);

  if (isLoading) return <div className="space-y-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}</div>;
  if (!a) return <div className="text-muted-foreground">Asset not found</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/assets")}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Assets
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5"
          disabled={downloading || isLoading || !a}
          onClick={async () => {
            setDownloading(true);
            try { await downloadAssetPdf(id, getToken()); }
            catch { /* ignore */ }
            finally { setDownloading(false); }
          }}
        >
          {downloading
            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
            : <Download className="w-3.5 h-3.5" />}
          {downloading ? "Generating…" : "Download PDF"}
        </Button>
      </div>

      {/* Running scan banner */}
      {runningScan && (
        <div className="bg-primary/5 border border-primary/20 rounded-xl px-4 py-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Loader2 className="w-4 h-4 animate-spin text-primary" />
            <span className="text-sm font-medium">Scan in progress</span>
            <span className="text-[11px] text-muted-foreground capitalize">
              · {runningScan.type} scan · status: {runningScan.status}
            </span>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/10 shrink-0"
            disabled={cancellingId === runningScan.id}
            onClick={() => handleCancelScan(runningScan.id)}
          >
            {cancellingId === runningScan.id
              ? <Loader2 className="w-3 h-3 animate-spin mr-1" />
              : <X className="w-3 h-3 mr-1" />}
            Cancel Scan
          </Button>
        </div>
      )}

      {/* Header */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <span className="text-xs bg-accent/50 px-2 py-0.5 rounded">{a.type}</span>
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(a.verificationStatus))}>{a.verificationStatus}</span>
              {a.verificationStatus !== "verified" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-6 px-2 text-xs border-green-500/40 text-green-500 hover:bg-green-500/10 hover:text-green-400"
                  disabled={verifying}
                  onClick={handleVerify}
                >
                  <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                  {verifying ? "Verifying…" : "Mark Verified"}
                </Button>
              )}
              {/* Compliance tracking toggle — only shown for verified assets */}
              {a.verificationStatus === "verified" && (
                <button
                  disabled={toggleCompliance.isPending}
                  onClick={() => toggleCompliance.mutate(!complianceEnabled)}
                  className={cn(
                    "inline-flex items-center gap-1.5 h-6 px-2 rounded text-xs font-medium border transition-colors",
                    complianceEnabled
                      ? "bg-primary/10 text-primary border-primary/30 hover:bg-primary/20"
                      : "bg-muted/40 text-muted-foreground border-border hover:bg-muted/60",
                  )}
                  title={complianceEnabled ? "Disable compliance tracking for this asset" : "Enable compliance tracking for this asset"}
                >
                  {toggleCompliance.isPending
                    ? <Loader2 className="w-3 h-3 animate-spin" />
                    : <ClipboardCheck className="w-3 h-3" />}
                  {complianceEnabled ? "Compliance On" : "Compliance Off"}
                </button>
              )}
            </div>
            <h1 className="text-base font-semibold">{a.name}</h1>
            <p className="text-sm font-mono text-muted-foreground mt-0.5">{a.value}</p>
          </div>
          {rs && (
            <div className="text-right">
              <p className="text-3xl font-bold tabular-nums" style={{ color: rs.level === "critical" ? "#ef4444" : rs.level === "high" ? "#f97316" : rs.level === "medium" ? "#eab308" : rs.level ? "#22c55e" : "#64748b" }}>
                {rs.score != null ? Math.round(rs.score) : "—"}
              </p>
              <p className="text-xs text-muted-foreground">risk score</p>
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(rs.level))}>{rs.level ?? "Not Scanned"}</span>
              <button
                className="mt-1.5 flex items-center gap-1 text-[10px] text-primary/70 hover:text-primary transition-colors ml-auto"
                onClick={() => {
                  setShowAiRisk(v => {
                    if (!v && !aiRiskText) triggerRiskExplain();
                    return !v;
                  });
                }}
              >
                <Brain className="w-3 h-3" />
                {showAiRisk ? "Hide AI" : "Explain this risk"}
                {showAiRisk ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            </div>
          )}
        </div>

        {/* ── AI Risk Explanation Panel ── */}
        {showAiRisk && (
          <div className="mt-3 bg-muted/20 border border-primary/20 rounded-xl p-3 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <Brain className="w-3.5 h-3.5 text-primary" />
                <span className="text-xs font-semibold">AI Risk Analysis</span>
                {aiRiskModel && !aiRiskLoading && (
                  <span className="text-[9px] text-green-400/70 font-mono">⚡ {aiRiskModel}</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                  onClick={() => { setAiRiskText(""); triggerRiskExplain(); }}
                  disabled={aiRiskLoading}
                  title="Regenerate"
                >
                  <RefreshCw className={cn("w-3 h-3", aiRiskLoading && "animate-spin")} />
                </button>
                <a href={`/ai-copilot?assetId=${id}&action=risk`} className="text-[9px] text-primary/70 hover:text-primary underline">Full view →</a>
              </div>
            </div>
            {aiRiskNoKey && (
              <div className="flex items-center gap-1.5 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1">
                <AlertTriangle className="w-3 h-3 shrink-0" />
                Template response — <a href="/settings/account" className="underline ml-0.5">add an API key</a> for real AI analysis.
              </div>
            )}
            <div className="text-xs text-muted-foreground">
              {aiRiskLoading && !aiRiskText ? (
                <div className="space-y-1.5">
                  <Skeleton className="h-2.5 w-3/4" />
                  <Skeleton className="h-2.5 w-full" />
                  <Skeleton className="h-2.5 w-5/6" />
                  <div className="flex items-center gap-1 text-[10px] text-muted-foreground/50 mt-2">
                    <Sparkles className="w-3 h-3 animate-pulse text-primary" />
                    Analysing risk score…
                  </div>
                </div>
              ) : (
                <>
                  <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
                    h2: ({ children }) => <h2 className="text-xs font-bold mt-2 mb-1 text-foreground">{children}</h2>,
                    h3: ({ children }) => <h3 className="text-[11px] font-semibold mt-1.5 mb-0.5 text-foreground/90">{children}</h3>,
                    p: ({ children }) => <p className="text-[11px] text-muted-foreground mb-1.5 leading-relaxed">{children}</p>,
                    ul: ({ children }) => <ul className="list-disc pl-4 space-y-0.5 mb-1.5">{children}</ul>,
                    li: ({ children }) => <li className="text-[11px] text-muted-foreground">{children}</li>,
                    strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                    table: ({ children }) => <div className="overflow-x-auto my-1"><table className="text-[10px] w-full border-collapse">{children}</table></div>,
                    th: ({ children }) => <th className="px-2 py-0.5 text-left font-semibold text-foreground border border-border/40 bg-muted/40">{children}</th>,
                    td: ({ children }) => <td className="px-2 py-0.5 text-muted-foreground border border-border/40">{children}</td>,
                  }}>{aiRiskText}</ReactMarkdown>
                  {aiRiskLoading && <span className="inline-block w-1.5 h-3 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
                </>
              )}
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          <div className="bg-accent/40 rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">IP Address</p>
            <p className="text-xs font-medium font-mono mt-0.5">{a.ipAddress ?? "—"}</p>
          </div>
          {/* Port card — shows scanned open ports count, or configured port, or "—" */}
          <div className="bg-accent/40 rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Open Ports</p>
            {(() => {
              const pd = portsData as any;
              const scannedPorts: any[] = pd?.ports ?? [];
              if (scannedPorts.length > 0) {
                const portNums = scannedPorts.map((p: any) => p.port).join(", ");
                return (
                  <p className="text-xs font-medium font-mono mt-0.5 text-emerald-400">
                    {scannedPorts.length} open
                    <span className="text-[10px] text-muted-foreground ml-1">({portNums})</span>
                  </p>
                );
              }
              if (a.port != null) {
                return <p className="text-xs font-medium font-mono mt-0.5">{a.port}</p>;
              }
              return <p className="text-xs font-medium font-mono mt-0.5 text-muted-foreground/50">—</p>;
            })()}
          </div>
          <div className="bg-accent/40 rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Last Scanned</p>
            <p className="text-xs font-medium font-mono mt-0.5">{formatDate(a.lastScannedAt)}</p>
          </div>
          <div className="bg-accent/40 rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Added</p>
            <p className="text-xs font-medium font-mono mt-0.5">{formatDate(a.createdAt)}</p>
          </div>
        </div>

        {/* Business Impact */}
        <div className="bg-accent/40 rounded-lg p-3 mt-3">
          <div className="flex items-center justify-between mb-2">
            <div>
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Business Impact</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">How critical is this asset to business operations? (1 = low, 10 = critical)</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-lg font-bold tabular-nums text-primary">{businessImpact}<span className="text-xs text-muted-foreground font-normal">/10</span></span>
              <Button
                size="sm"
                variant="outline"
                className="h-6 text-[11px] px-2"
                disabled={savingImpact || businessImpact === (a.businessImpact ?? 5)}
                onClick={() => handleSaveBusinessImpact(businessImpact)}
              >
                {savingImpact ? <Loader2 className="w-3 h-3 animate-spin" /> : "Save"}
              </Button>
            </div>
          </div>
          <input
            type="range"
            min={1}
            max={10}
            step={1}
            value={businessImpact}
            onChange={e => setBusinessImpact(Number(e.target.value))}
            className="w-full accent-primary h-1.5"
          />
          <div className="flex justify-between mt-1">
            {[1,2,3,4,5,6,7,8,9,10].map(n => (
              <span key={n} className={cn("text-[10px] tabular-nums", n === businessImpact ? "text-primary font-bold" : "text-muted-foreground")}>{n}</span>
            ))}
          </div>
        </div>

        {/* Assignment — editable for admin/SA/AM, read-only for others */}
        {canEditAssignment ? (
          <div className="bg-accent/40 rounded-lg p-3 mt-3 space-y-3">
            <div className="flex items-center gap-2 mb-1">
              <UserCheck className="w-3.5 h-3.5 text-muted-foreground" />
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Assignment</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Client</Label>
                <Select value={assignedClientId} onValueChange={setAssignedClientId}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {clientUsers.map((u: any) => (
                      <SelectItem key={u.id} value={String(u.id)}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-[10px] text-muted-foreground uppercase tracking-wider">Account Manager</Label>
                <Select value={assignedAmId} onValueChange={setAssignedAmId}>
                  <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="None" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="_none_">None</SelectItem>
                    {amUsers.map((u: any) => (
                      <SelectItem key={u.id} value={String(u.id)}>{u.firstName} {u.lastName}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-[11px] px-3 w-full"
              disabled={savingAssignment || (
                assignedClientId === (a.assignedClientId != null ? String(a.assignedClientId) : "_none_") &&
                assignedAmId === (a.assignedAccountManagerId != null ? String(a.assignedAccountManagerId) : "_none_")
              )}
              onClick={handleSaveAssignment}
            >
              {savingAssignment ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : null}
              Save Assignment
            </Button>
          </div>
        ) : (a.assignedClientName || a.assignedAccountManagerName) ? (
          <div className="grid grid-cols-2 gap-3 mt-3">
            {a.assignedClientName && (
              <div className="bg-accent/40 rounded-lg p-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Client</p>
                <p className="text-xs font-medium mt-0.5">{a.assignedClientName}</p>
              </div>
            )}
            {a.assignedAccountManagerName && (
              <div className="bg-accent/40 rounded-lg p-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Account Manager</p>
                <p className="text-xs font-medium mt-0.5">{a.assignedAccountManagerName}</p>
              </div>
            )}
          </div>
        ) : null}

        {a.tags?.length > 0 && (
          <div className="flex gap-1.5 flex-wrap mt-3">
            {a.tags.map((tag: string) => (
              <span key={tag} className="text-xs bg-primary/10 text-primary border border-primary/20 px-2 py-0.5 rounded-full">{tag}</span>
            ))}
          </div>
        )}
      </div>

      {/* Watchlist Scans */}
      {(() => {
        const allScans = (brandThreats as any[]) ?? [];
        const assetVal = a?.value ? normalizeDomain(String(a.value)) : "";
        const watchlistScans = assetVal
          ? allScans.filter((s: any) => {
              const d = (s.domain ?? "").toLowerCase().replace(/^www\./, "");
              const v = (s.watchlistItemValue ?? "").toLowerCase();
              return d === assetVal || v === assetVal || (s.watchlistItemId && v && assetVal.includes(v.replace(/^@/, "")));
            })
          : [];
        const nonDomainWatchlist = watchlistScans.filter((s: any) => s.watchlistItemType && s.watchlistItemType !== "domain");
        if (!nonDomainWatchlist.length) return null;
        const TYPE_ICON: Record<string, React.ReactNode> = {
          social_handle: <AtSign className="w-3.5 h-3.5 text-pink-400" />,
          mobile_app:    <Smartphone className="w-3.5 h-3.5 text-orange-400" />,
          email:         <Mail className="w-3.5 h-3.5 text-blue-400" />,
          keyword:       <Search className="w-3.5 h-3.5 text-cyan-400" />,
          logo_url:      <Image className="w-3.5 h-3.5 text-violet-400" />,
          ip:            <Server className="w-3.5 h-3.5 text-slate-400" />,
        };
        const STATUS_COLOR: Record<string, string> = {
          done:    "bg-green-500/15 text-green-400 border-green-500/30",
          running: "bg-blue-500/15 text-blue-400 border-blue-500/30",
          pending: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
          error:   "bg-red-500/15 text-red-400 border-red-500/30",
        };
        return (
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center gap-2 mb-3">
              <BookmarkCheck className="w-4 h-4 text-primary" />
              <h3 className="text-sm font-medium">Brand Watchlist Scans</h3>
              <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{nonDomainWatchlist.length}</span>
            </div>
            <div className="space-y-2">
              {nonDomainWatchlist.map((s: any) => (
                <div key={s.id} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
                  <span className="shrink-0">{TYPE_ICON[s.watchlistItemType ?? ""] ?? <ShieldAlert className="w-3.5 h-3.5 text-muted-foreground" />}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-xs font-medium font-mono truncate">{s.watchlistItemValue ?? s.domain}</span>
                      <span className="text-[10px] text-muted-foreground capitalize shrink-0">{(s.watchlistItemType ?? "domain").replace(/_/g, " ")}</span>
                    </div>
                    <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                      {(s.brandAbuseCount ?? 0) > 0 && (
                        <span className="text-[10px] text-orange-400">{s.brandAbuseCount} abuse</span>
                      )}
                      {(s.dataLeakCount ?? 0) > 0 && (
                        <span className="text-[10px] text-red-400">{s.dataLeakCount} leaks</span>
                      )}
                      {(s.brandAbuseCount ?? 0) === 0 && (s.dataLeakCount ?? 0) === 0 && (
                        <span className="text-[10px] text-muted-foreground/60">No threats found</span>
                      )}
                    </div>
                  </div>
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium shrink-0 capitalize", STATUS_COLOR[s.status] ?? "bg-muted text-muted-foreground border-border")}>{s.status}</span>
                  <Link href={`/brand-threats/${s.id}`}>
                    <Button variant="ghost" size="sm" className="h-6 px-2 text-[10px] shrink-0">
                      <ExternalLink className="w-3 h-3 mr-1" /> View
                    </Button>
                  </Link>
                </div>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Brand Threat Summary */}
      {matchingBrandScan && (
        <div className="bg-card border border-orange-500/30 rounded-xl p-4">
          <div className="flex items-center justify-between gap-2 mb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-orange-400" />
              <h3 className="text-sm font-medium">Brand Threat Intelligence</h3>
              <span className={cn(
                "text-[10px] px-1.5 py-0.5 rounded font-bold",
                matchingBrandScan.phishingRisk === "critical" ? "bg-red-500/20 text-red-400 border border-red-500/30" :
                matchingBrandScan.phishingRisk === "high"     ? "bg-orange-500/20 text-orange-400 border border-orange-500/30" :
                matchingBrandScan.phishingRisk === "medium"   ? "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" :
                                                                "bg-green-500/20 text-green-400 border border-green-500/30"
              )}>
                {(matchingBrandScan.phishingRisk ?? "low").toUpperCase()} RISK
              </span>
            </div>
            <Link href={`/brand-threats/${matchingBrandScan.id}`}>
              <Button variant="outline" size="sm" className="h-6 px-2 text-xs gap-1 border-orange-500/30 text-orange-400 hover:bg-orange-500/10">
                <ExternalLink className="w-3 h-3" /> View Details
              </Button>
            </Link>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className={cn(
              "rounded-lg p-3 flex flex-col items-center gap-1 border",
              (matchingBrandScan.phishingCount ?? 0) > 0
                ? "bg-red-500/10 border-red-500/30"
                : "bg-accent/40 border-border"
            )}>
              <Fish className={cn("w-4 h-4", (matchingBrandScan.phishingCount ?? 0) > 0 ? "text-red-400" : "text-muted-foreground")} />
              <span className={cn("text-xl font-bold tabular-nums", (matchingBrandScan.phishingCount ?? 0) > 0 ? "text-red-400" : "text-foreground")}>
                {matchingBrandScan.phishingCount ?? 0}
              </span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">Phishing</span>
            </div>
            <div className={cn(
              "rounded-lg p-3 flex flex-col items-center gap-1 border",
              (matchingBrandScan.dataLeakCount ?? 0) > 0
                ? "bg-orange-500/10 border-orange-500/30"
                : "bg-accent/40 border-border"
            )}>
              <DatabaseZap className={cn("w-4 h-4", (matchingBrandScan.dataLeakCount ?? 0) > 0 ? "text-orange-400" : "text-muted-foreground")} />
              <span className={cn("text-xl font-bold tabular-nums", (matchingBrandScan.dataLeakCount ?? 0) > 0 ? "text-orange-400" : "text-foreground")}>
                {matchingBrandScan.dataLeakCount ?? 0}
              </span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">Data Leaks</span>
            </div>
            <div className={cn(
              "rounded-lg p-3 flex flex-col items-center gap-1 border",
              (matchingBrandScan.brandAbuseCount ?? 0) > 0
                ? "bg-yellow-500/10 border-yellow-500/30"
                : "bg-accent/40 border-border"
            )}>
              <Siren className={cn("w-4 h-4", (matchingBrandScan.brandAbuseCount ?? 0) > 0 ? "text-yellow-400" : "text-muted-foreground")} />
              <span className={cn("text-xl font-bold tabular-nums", (matchingBrandScan.brandAbuseCount ?? 0) > 0 ? "text-yellow-400" : "text-foreground")}>
                {matchingBrandScan.brandAbuseCount ?? 0}
              </span>
              <span className="text-[10px] text-muted-foreground uppercase tracking-wide">Brand Abuse</span>
            </div>
          </div>
          {matchingBrandScan.liveCount > 0 && (
            <p className="text-[11px] text-muted-foreground mt-2">
              {matchingBrandScan.liveCount} live lookalike domain{matchingBrandScan.liveCount !== 1 ? "s" : ""} detected across {matchingBrandScan.totalPermutations} permutations.
            </p>
          )}
        </div>
      )}

      {/* Findings */}
      {(() => {
        const FINDINGS_PER_PAGE = 10;
        const allF = (findings as any[]) ?? [];
        const totalPages = Math.max(1, Math.ceil(allF.length / FINDINGS_PER_PAGE));
        const paged = allF.slice(findingsPage * FINDINGS_PER_PAGE, (findingsPage + 1) * FINDINGS_PER_PAGE);
        return (
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium">
                Findings
                {allF.length > 0 && <span className="ml-1.5 text-xs text-muted-foreground font-normal">({allF.length})</span>}
              </h3>
              {totalPages > 1 && (
                <div className="flex items-center gap-0.5">
                  <button
                    onClick={() => setFindingsPage(p => Math.max(0, p - 1))}
                    disabled={findingsPage === 0}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30 transition-colors"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-xs text-muted-foreground px-1.5 tabular-nums">
                    {findingsPage + 1} / {totalPages}
                  </span>
                  <button
                    onClick={() => setFindingsPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={findingsPage >= totalPages - 1}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30 transition-colors"
                  >
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
            <div className="space-y-2">
              {paged.map((f: any) => {
                const isBrandIntel = typeof f.evidence === "string" && f.evidence.startsWith("btw:");
                return (
                  <div key={f.id} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", severityBgColor(f.severity))}>{f.severity}</span>
                    <Link href={`/findings/${f.id}`}>
                      <span className="text-sm text-primary hover:underline cursor-pointer flex-1 line-clamp-1">{f.title}</span>
                    </Link>
                    {isBrandIntel && (
                      <span className="text-[9px] font-bold bg-violet-500/15 text-violet-400 border border-violet-500/30 px-1.5 py-0.5 rounded uppercase tracking-wide shrink-0">
                        Brand Intel
                      </span>
                    )}
                    {f.isKev && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold shrink-0">KEV</span>}
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", statusBadgeClass(f.status))}>{capitalize(f.status)}</span>
                  </div>
                );
              })}
              {allF.length === 0 && (
                <p className="text-sm text-muted-foreground">No findings for this asset.</p>
              )}
            </div>
          </div>
        );
      })()}

      {/* Technology Detection */}
      <div className="bg-card border border-border rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-sm font-medium">Detected Technologies</h3>
            {techs.length > 0 && (
              <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{techs.length}</span>
            )}
          </div>
          {canScan && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-3 text-xs gap-1.5"
              disabled={scanning}
              onClick={handleTechScan}
            >
              {scanning
                ? <><Loader2 className="w-3 h-3 animate-spin" /> Scanning…</>
                : <><RefreshCw className="w-3 h-3" /> {techs.length > 0 ? "Re-scan" : "Detect Technologies"}</>}
            </Button>
          )}
        </div>

        {scanning && (
          <div className="py-6 flex flex-col items-center gap-2 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
            <p className="text-xs">Fingerprinting {a.value}…</p>
            <p className="text-[10px] text-muted-foreground/60">Fetching HTTP headers, HTML patterns, and scripts</p>
          </div>
        )}

        {!scanning && techs.length === 0 && (
          <div className="py-6 text-center text-sm text-muted-foreground">
            {canScan
              ? "No technologies detected yet. Click \"Detect Technologies\" to run a real-time fingerprint scan."
              : "Technology detection is only available for domain, subdomain, URL, and IP assets."}
          </div>
        )}

        {!scanning && techs.length > 0 && (
          <div className="space-y-4">
            {Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, items]) => (
              <div key={category}>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">{category}</p>
                <div className="flex flex-wrap gap-2">
                  {items.map((t: any) => (
                    <div key={t.id} className={cn("flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium", categoryColor(t.category))}>
                      {t.icon && <span>{t.icon}</span>}
                      <span>{t.technology}</span>
                      {t.version && (
                        <span className="text-[10px] opacity-70 font-mono bg-black/10 px-1 rounded">{t.version}</span>
                      )}
                      {t.confidence < 100 && (
                        <span className="text-[10px] opacity-50">{t.confidence}%</span>
                      )}
                      {t.website && (
                        <a href={t.website} target="_blank" rel="noopener noreferrer" className="opacity-50 hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
            <p className="text-[10px] text-muted-foreground/50 mt-2">
              Last scanned: {formatDate(techs[0]?.detectedAt)}
              {techs[0]?.cpe && <span className="ml-2 font-mono">{techs[0].cpe}</span>}
            </p>
          </div>
        )}
      </div>

      {/* ── Open Ports (Network Exposure) ───────────────────────────────────── */}
      {(() => {
        const pd = portsData as any;
        const ports: any[] = pd?.ports ?? [];
        const portSource: string = pd?.source ?? "";
        const portScannedAt: string | null = pd?.scannedAt ?? null;
        const dangerousPorts = new Set([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]);
        return (
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-muted-foreground" />
                <h3 className="text-sm font-medium">Open Ports</h3>
                {ports.length > 0 && (
                  <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">
                    {ports.length} discovered
                  </span>
                )}
                {portSource && portSource !== "none" && (
                  <span className="text-[10px] text-muted-foreground font-mono bg-muted/40 px-1.5 py-0.5 rounded">
                    via {portSource}
                  </span>
                )}
              </div>
              {portScannedAt && (
                <span className="text-[10px] text-muted-foreground">{formatDate(portScannedAt)}</span>
              )}
            </div>

            {ports.length === 0 ? (
              <div className="py-6 text-center">
                <Network className="w-7 h-7 text-muted-foreground/25 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No port scan data yet.</p>
                <p className="text-xs text-muted-foreground/60 mt-1">
                  Run a full pipeline scan to discover open ports via nmap and Shodan.
                </p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border">
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2 pr-4">Port</th>
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2 pr-4">Protocol</th>
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2 pr-4">State</th>
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2 pr-4">Service</th>
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2 pr-4">Version</th>
                      <th className="text-left text-[10px] font-semibold text-muted-foreground uppercase tracking-wider pb-2">Source</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/50">
                    {ports.map((p: any) => {
                      const isDangerous = dangerousPorts.has(p.port) && ![80, 443].includes(p.port);
                      return (
                        <tr key={p.port} className="hover:bg-muted/20 transition-colors">
                          <td className="py-2 pr-4 font-mono font-semibold">
                            <span className={cn(
                              "inline-flex items-center gap-1",
                              isDangerous ? "text-orange-400" : p.port === 443 ? "text-emerald-400" : "text-foreground"
                            )}>
                              {p.port}
                              {isDangerous && (
                                <span className="text-[9px] bg-orange-500/15 text-orange-400 border border-orange-500/25 px-1 py-0.5 rounded font-semibold">RISK</span>
                              )}
                            </span>
                          </td>
                          <td className="py-2 pr-4 text-muted-foreground font-mono uppercase text-[11px]">{p.protocol ?? "tcp"}</td>
                          <td className="py-2 pr-4">
                            <span className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded font-medium",
                              p.state === "open" ? "bg-emerald-500/15 text-emerald-400" :
                              p.state === "filtered" ? "bg-yellow-500/15 text-yellow-400" :
                              "bg-muted text-muted-foreground"
                            )}>
                              {p.state ?? "open"}
                            </span>
                          </td>
                          <td className="py-2 pr-4 text-muted-foreground">{p.service ?? "—"}</td>
                          <td className="py-2 pr-4 text-muted-foreground font-mono text-[10px]">{p.version || "—"}</td>
                          <td className="py-2">
                            <span className="text-[10px] bg-muted/40 text-muted-foreground px-1.5 py-0.5 rounded font-mono">
                              {p.source ?? "—"}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })()}

      {/* ── Screenshot Gallery ──────────────────────────────────────────────── */}
      {canScan && (
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Camera className="w-4 h-4 text-muted-foreground" />
              <h3 className="text-sm font-medium">Visual Screenshot Gallery</h3>
              {shots.length > 0 && (
                <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{shots.length}</span>
              )}
              {totalFindings > 0 && (
                <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-medium flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />{totalFindings} sensitive
                </span>
              )}
            </div>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-3 text-xs gap-1.5"
              disabled={screenshotting}
              onClick={handleScreenshotScan}
            >
              {screenshotting
                ? <><Loader2 className="w-3 h-3 animate-spin" /> Capturing…</>
                : <><Camera className="w-3 h-3" /> {shots.length > 0 ? "Re-capture" : "Capture Screenshots"}</>}
            </Button>
          </div>

          {screenshotting && (
            <div className="py-10 flex flex-col items-center gap-3 text-muted-foreground">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
              <p className="text-sm font-medium">Capturing pages on {a.value}…</p>
              <p className="text-xs text-muted-foreground/60">Visiting index, login, signup, admin, and API paths via headless Chromium</p>
            </div>
          )}

          {!screenshotting && shots.length === 0 && (
            <div className="py-8 text-center">
              <Camera className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No screenshots captured yet.</p>
              <p className="text-xs text-muted-foreground/60 mt-1">Click "Capture Screenshots" to visit and photograph pages via headless Chromium.</p>
            </div>
          )}

          {!screenshotting && shots.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {shots.map((shot: any) => {
                const shotFindings: any[] = shot.findings ?? [];
                const criticalOrHigh = shotFindings.filter((f: any) => f.severity === "critical" || f.severity === "high");
                return (
                  <div
                    key={shot.id}
                    className="group border border-border rounded-lg overflow-hidden cursor-pointer hover:border-primary/50 transition-colors bg-accent/20"
                    onClick={() => setExpandedShot(shot)}
                  >
                    {/* Screenshot image */}
                    <div className="relative w-full aspect-video bg-background overflow-hidden">
                      {shot.screenshotData && shot.screenshotData.startsWith("data:image") ? (
                        <img
                          src={shot.screenshotData}
                          alt={`${shot.pageType} screenshot`}
                          className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-300"
                        />
                      ) : shot.screenshotData && shot.screenshotData.length > 100 ? (
                        <img
                          src={`data:image/png;base64,${shot.screenshotData}`}
                          alt={`${shot.pageType} screenshot`}
                          className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-300"
                        />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center text-muted-foreground/30">
                          <Camera className="w-8 h-8" />
                        </div>
                      )}
                      {/* Page type badge overlay */}
                      <span className={cn(
                        "absolute top-2 left-2 text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase tracking-wider",
                        PAGE_TYPE_BADGE[shot.pageType] ?? "bg-muted text-muted-foreground border-border"
                      )}>
                        {shot.pageType}
                      </span>
                      {/* Status code */}
                      {shot.statusCode && (
                        <span className={cn(
                          "absolute top-2 right-2 text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold",
                          shot.statusCode < 300 ? "bg-green-500/20 text-green-400" :
                          shot.statusCode < 400 ? "bg-blue-500/20 text-blue-400" :
                          shot.statusCode < 500 ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-red-500/20 text-red-400"
                        )}>
                          {shot.statusCode}
                        </span>
                      )}
                      {/* Sensitive findings badge */}
                      {criticalOrHigh.length > 0 && (
                        <div className="absolute bottom-2 right-2 flex items-center gap-1 bg-red-500/90 text-white text-[10px] px-1.5 py-0.5 rounded font-semibold">
                          <AlertTriangle className="w-2.5 h-2.5" />
                          {criticalOrHigh.length} critical
                        </div>
                      )}
                    </div>

                    {/* Card footer */}
                    <div className="p-2.5">
                      <p className="text-xs font-medium line-clamp-1 mb-0.5">{shot.title || shot.url}</p>
                      <p className="text-[10px] text-muted-foreground font-mono line-clamp-1">{shot.url}</p>
                      {shotFindings.length > 0 && (
                        <div className="flex gap-1 flex-wrap mt-1.5">
                          {shotFindings.slice(0, 3).map((f: any, i: number) => (
                            <span key={i} className={cn("text-[9px] px-1.5 py-0.5 rounded border font-medium", FINDING_SEVERITY_COLOR[f.severity])}>
                              {f.type}
                            </span>
                          ))}
                          {shotFindings.length > 3 && (
                            <span className="text-[9px] text-muted-foreground px-1 py-0.5">+{shotFindings.length - 3} more</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {!screenshotting && shots.length > 0 && (
            <p className="text-[10px] text-muted-foreground/50 mt-3">
              Last captured: {formatDate(shots[0]?.capturedAt)} · {shots.length} page{shots.length === 1 ? "" : "s"} · Chromium headless
            </p>
          )}
        </div>
      )}

      {/* ── Expanded Screenshot Lightbox ───────────────────────────────────── */}
      {expandedShot && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setExpandedShot(null)}
        >
          <div
            className="bg-card border border-border rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-2">
                <span className={cn(
                  "text-xs px-2 py-0.5 rounded border font-semibold uppercase tracking-wider",
                  PAGE_TYPE_BADGE[expandedShot.pageType] ?? "bg-muted text-muted-foreground border-border"
                )}>
                  {expandedShot.pageType}
                </span>
                <span className="text-sm font-medium line-clamp-1">{expandedShot.title || expandedShot.url}</span>
                {expandedShot.statusCode && (
                  <span className={cn(
                    "text-xs px-1.5 py-0.5 rounded font-mono",
                    expandedShot.statusCode < 300 ? "text-green-400" :
                    expandedShot.statusCode < 400 ? "text-blue-400" :
                    expandedShot.statusCode < 500 ? "text-yellow-400" : "text-red-400"
                  )}>
                    {expandedShot.statusCode}
                  </span>
                )}
              </div>
              <Button size="sm" variant="ghost" onClick={() => setExpandedShot(null)}><X className="w-4 h-4" /></Button>
            </div>

            <div className="p-4 space-y-4">
              {/* Full screenshot */}
              <div className="rounded-lg overflow-hidden border border-border bg-background">
                {expandedShot.screenshotData && (
                  <img
                    src={expandedShot.screenshotData.startsWith("data:") ? expandedShot.screenshotData : `data:image/png;base64,${expandedShot.screenshotData}`}
                    alt="Full page screenshot"
                    className="w-full object-contain"
                  />
                )}
              </div>

              {/* URL */}
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">URL</p>
                <a href={expandedShot.url} target="_blank" rel="noopener noreferrer"
                   className="text-sm font-mono text-primary hover:underline flex items-center gap-1">
                  {expandedShot.url} <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Sensitive findings */}
              {(expandedShot.findings?.length ?? 0) > 0 && (
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
                    Sensitive Disclosures ({expandedShot.findings.length})
                  </p>
                  <div className="space-y-2">
                    {expandedShot.findings.map((f: any, i: number) => (
                      <div key={i} className={cn("rounded-lg border p-3", FINDING_SEVERITY_COLOR[f.severity])}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-semibold uppercase tracking-wider">{f.severity}</span>
                          <span className="text-xs font-medium">{f.type}</span>
                        </div>
                        <p className="text-xs font-mono break-all opacity-80">{f.value}</p>
                        {f.context && (
                          <p className="text-[10px] opacity-60 mt-1 break-all">{f.context}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(expandedShot.findings?.length ?? 0) === 0 && (
                <div className="flex items-center gap-2 text-emerald-400 text-sm">
                  <ShieldCheck className="w-4 h-4" />
                  No sensitive disclosures detected on this page.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
