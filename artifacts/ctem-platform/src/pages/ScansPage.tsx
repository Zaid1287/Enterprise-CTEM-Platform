import { useState, useMemo, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useListScans, useCreateScan, useCancelScan,
  useListAssets, useListScanJobs, useListAssetGroups, useGetAssetGroupMembers,
  getListScansQueryKey, getListAssetsQueryKey, getListScanJobsQueryKey, getListAssetGroupsQueryKey,
  getGetAssetGroupMembersQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient } from "@tanstack/react-query";
import {
  Plus, X, RefreshCw, CheckCircle2, Loader2, AlertCircle, Clock,
  ShieldAlert, ShieldCheck, Calendar, History, Layers, Link2,
  Brain, Sparkles, AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import ScheduledScansList from "@/components/scan/ScheduledScansList";

const SCAN_TYPES = ["passive", "active", "vulnerability", "full"];

const SCAN_INTENSITIES: { value: string; label: string; description: string }[] = [
  { value: "passive",             label: "Passive (Stealthiest)",   description: "300–900 ms delays — minimal footprint, slowest" },
  { value: "endpoint-discovery",  label: "Endpoint Discovery",      description: "700–1800 ms delays — balanced default" },
  { value: "dir-fuzzing",         label: "Directory Fuzzing",       description: "1–3 s delays — moderate aggression" },
  { value: "heavy-enumeration",   label: "Heavy Enumeration",       description: "1.5–4 s delays — comprehensive but loud" },
  { value: "vuln-scan",           label: "Vulnerability Scan",      description: "800–2000 ms delays — CVE / Nuclei focused" },
];
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

type TabId = "history" | "schedules";

export default function ScansPage() {
  const [activeTab, setActiveTab] = useState<TabId>("history");
  const [showCreate, setShowCreate] = useState(false);
  const [customName, setCustomName] = useState("");
  const [form, setForm] = useState({ type: "full", assetIds: [] as number[], intensity: "endpoint-discovery" });
  const [createError, setCreateError] = useState<{ message: string; unverified?: { id: number; name: string }[] } | null>(null);
  const [page, setPage] = useState(1);
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const [groupFilter, setGroupFilter] = useState<number | null>(null);
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // ── AI triage state (per scan) ────────────────────────────────────────────
  const [aiScanOpen, setAiScanOpen] = useState<Record<number, boolean>>({});
  const [aiScanText, setAiScanText] = useState<Record<number, string>>({});
  const [aiScanLoading, setAiScanLoading] = useState<Record<number, boolean>>({});
  const [aiScanNoKey, setAiScanNoKey] = useState<Record<number, boolean>>({});
  const BASE_SCAN = import.meta.env.BASE_URL.replace(/\/$/, "");

  const triggerScanTriage = useCallback(async (scanId: number) => {
    if (aiScanLoading[scanId]) return;
    setAiScanText(p => ({ ...p, [scanId]: "" }));
    setAiScanLoading(p => ({ ...p, [scanId]: true }));
    setAiScanNoKey(p => ({ ...p, [scanId]: false }));
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    try {
      const resp = await fetch(`${BASE_SCAN}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: "summarize-scan", scanId }),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.noKey) setAiScanNoKey(p => ({ ...p, [scanId]: true }));
            if (d.text) { accumulated += d.text; setAiScanText(p => ({ ...p, [scanId]: accumulated })); }
          } catch { /* ignore */ }
        }
      }
    } catch { setAiScanText(p => ({ ...p, [scanId]: accumulated || "Failed to generate triage summary. Please try again." })); }
    setAiScanLoading(p => ({ ...p, [scanId]: false }));
  }, [aiScanLoading, BASE_SCAN]);

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

  const { data: groups } = useListAssetGroups({
    query: { queryKey: getListAssetGroupsQueryKey() },
  });
  const groupList = (groups as any[]) ?? [];

  const selectedGroup = groupFilter ? groupList.find((g: any) => g.id === groupFilter) : null;

  // Fetch members for the selected group (disabled when no group selected)
  const { data: groupMembersRaw } = useGetAssetGroupMembers(groupFilter ?? 0, {
    query: {
      queryKey: getGetAssetGroupMembersQueryKey(groupFilter ?? 0),
      enabled: !!groupFilter,
    },
  });
  const groupMemberIds = useMemo(() => {
    if (!groupFilter) return null;
    const members = (groupMembersRaw as any[]) ?? [];
    return new Set(members.map((m: any) => m.id));
  }, [groupFilter, groupMembersRaw]);

  const allScans = useMemo(() => {
    const raw = (scans as any[]) ?? [];
    if (!groupFilter || !groupMemberIds) return raw;
    // Show scans that include at least one asset from the selected group
    return raw.filter((scan: any) =>
      Array.isArray(scan.assetIds) && scan.assetIds.some((id: number) => groupMemberIds.has(id))
    );
  }, [scans, groupFilter, groupMemberIds]);

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
      setForm({ type: "full", assetIds: [], intensity: "endpoint-discovery" });
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
        <div className="flex gap-2 items-center flex-wrap">
          {/* Group filter */}
          {activeTab === "history" && groupList.length > 0 && (
            <div className="relative">
              <select
                value={groupFilter ?? ""}
                onChange={e => { setGroupFilter(e.target.value ? Number(e.target.value) : null); setPage(1); }}
                className="h-8 pl-7 pr-3 text-xs border border-border rounded-md bg-background text-foreground appearance-none cursor-pointer hover:border-primary/40 transition-colors"
              >
                <option value="">All Groups</option>
                {groupList.map((g: any) => (
                  <option key={g.id} value={g.id}>{g.name}</option>
                ))}
              </select>
              <Layers className="absolute left-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
            </div>
          )}
          {isPrivileged && activeTab === "history" && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); setPage(1); }} />}
          <Button variant="outline" size="sm" onClick={() => queryClient.invalidateQueries({ queryKey: getListScansQueryKey() })}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          <Button size="sm" onClick={() => { setCreateError(null); setShowCreate(true); }}>
            <Plus className="w-4 h-4 mr-1.5" /> New Scan
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border pb-0">
        {([
          { id: "history", label: "Scan History", icon: <History className="w-3.5 h-3.5" /> },
          { id: "schedules", label: "Scheduled Scans", icon: <Calendar className="w-3.5 h-3.5" /> },
        ] as { id: TabId; label: string; icon: React.ReactNode }[]).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 transition-colors -mb-px",
              activeTab === tab.id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground hover:border-border",
            )}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Scheduled Scans tab */}
      {activeTab === "schedules" && (
        <div className="space-y-4">
          <ScheduledScansList />
          <div className="bg-muted/20 border border-border rounded-xl p-4 text-sm text-muted-foreground">
            <p className="font-medium text-foreground mb-1">How scheduled scans work</p>
            <ul className="space-y-1 text-xs list-disc list-inside">
              <li>Schedules run at the exact time and day you configure — not based on last scan completion.</li>
              <li>Only <span className="text-green-400 font-medium">verified</span> assets in each schedule will be scanned. Unverified assets are skipped automatically.</li>
              <li>To create a schedule, click <strong>New Scan</strong>, select assets and choose "Save as Schedule".</li>
              <li>The beat scheduler checks every 60 seconds for overdue schedules — maximum 60s delay from configured time.</li>
            </ul>
          </div>
        </div>
      )}

      {/* Scan History tab */}
      {activeTab === "history" && (<>
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
                {scan.status === "pending" && (scan as any).queuePosition > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                    #{(scan as any).queuePosition} in queue
                  </span>
                )}
                {(scan as any).bullmqJobId && (
                  <a
                    href={`${import.meta.env.BASE_URL}queue-monitor`.replace(/\/\//g, "/")}
                    title={`BullMQ job: ${(scan as any).bullmqJobId}`}
                    className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors"
                    onClick={e => { e.preventDefault(); window.location.href = `${import.meta.env.BASE_URL}queue-monitor`.replace(/\/\//g, "/"); }}
                  >
                    <Link2 className="w-2.5 h-2.5" /> Queue
                  </a>
                )}
                {(scan.status === "pending" || scan.status === "running") && (
                  <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => handleCancel(scan.id)}>
                    <X className="w-3 h-3 mr-1" /> Cancel
                  </Button>
                )}
                {scan.status === "completed" && (
                  <Button
                    variant="outline" size="sm"
                    className={cn("h-7 text-xs", aiScanOpen[scan.id] && "border-primary/50 text-primary")}
                    onClick={() => {
                      const isOpen = !aiScanOpen[scan.id];
                      setAiScanOpen(p => ({ ...p, [scan.id]: isOpen }));
                      if (isOpen && !aiScanText[scan.id]) triggerScanTriage(scan.id);
                    }}
                  >
                    {aiScanLoading[scan.id] ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Brain className="w-3 h-3 mr-1" />}
                    AI Triage
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
            {/* AI Triage Panel */}
            {aiScanOpen[scan.id] && (
              <div className="mt-3 bg-muted/20 border border-primary/20 rounded-lg p-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5">
                    <Brain className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-semibold">AI Triage Summary</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      className="text-muted-foreground hover:text-foreground"
                      onClick={() => { setAiScanText(p => ({ ...p, [scan.id]: "" })); triggerScanTriage(scan.id); }}
                      disabled={aiScanLoading[scan.id]}
                    >
                      <RefreshCw className={cn("w-3 h-3", aiScanLoading[scan.id] && "animate-spin")} />
                    </button>
                    <button className="text-muted-foreground hover:text-foreground" onClick={() => setAiScanOpen(p => ({ ...p, [scan.id]: false }))}>
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                </div>
                {aiScanNoKey[scan.id] && (
                  <div className="flex items-center gap-1.5 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1">
                    <AlertTriangle className="w-3 h-3 shrink-0" />
                    Template response — <a href="/settings/account" className="underline ml-0.5">add an API key</a> for real AI triage.
                  </div>
                )}
                <div className="text-xs text-muted-foreground">
                  {aiScanLoading[scan.id] && !aiScanText[scan.id] ? (
                    <div className="space-y-1.5">
                      <Skeleton className="h-2.5 w-3/4" /><Skeleton className="h-2.5 w-full" /><Skeleton className="h-2.5 w-5/6" />
                      <div className="flex items-center gap-1 text-[10px] text-muted-foreground/50 mt-2">
                        <Sparkles className="w-3 h-3 animate-pulse text-primary" /> Triaging scan results…
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
                      }}>{aiScanText[scan.id]}</ReactMarkdown>
                      {aiScanLoading[scan.id] && <span className="inline-block w-1.5 h-3 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
                    </>
                  )}
                </div>
              </div>
            )}
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
      </>)}

      <Dialog open={showCreate} onOpenChange={v => {
        setShowCreate(v);
        if (!v) { setForm({ type: "full", assetIds: [], intensity: "endpoint-discovery" }); setCustomName(""); setCreateError(null); }
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
              <Label className="text-xs">Scan Intensity</Label>
              <Select value={form.intensity} onValueChange={v => setForm(p => ({ ...p, intensity: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SCAN_INTENSITIES.map(s => (
                    <SelectItem key={s.value} value={s.value}>
                      <div className="flex flex-col">
                        <span>{s.label}</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-[10px] text-muted-foreground">
                {SCAN_INTENSITIES.find(s => s.value === form.intensity)?.description}
              </p>
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
