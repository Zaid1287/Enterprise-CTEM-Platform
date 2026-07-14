import { useState, useMemo } from "react";
import { useLocation, useParams } from "wouter";
import {
  useGetAssetGroup, useUpdateAssetGroup, useGetAssetGroupMembers, useSetAssetGroupMembers,
  useListAssets, useListFindings, useGetToolPipeline, useCreateScanSchedule,
  getGetAssetGroupQueryKey, getGetAssetGroupMembersQueryKey, getListAssetGroupsQueryKey,
  getGetToolPipelineQueryKey, getListFindingsQueryKey, getListScanSchedulesQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import RunScanDialog from "@/components/scan/RunScanDialog";
import {
  ArrowLeft, Layers, Save, Users, Plus, X, Globe, Server, Database, Code2, Wifi, Shield, FileText,
  Play, Loader2, RefreshCw, Search, ShieldAlert, Smartphone, Network, AlertCircle, CheckCircle2,
  Clock, Info, Minus, ExternalLink, Calendar,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  domain: Globe, subdomain: Network, ip: Wifi, cidr: Network, url: Globe,
  api: Code2, ssl_cert: ShieldAlert, cloud_asset: Shield, host: Server,
  database: Database, service: Server, mobile_app: Smartphone, other: FileText,
};

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  info: "bg-muted text-muted-foreground border border-border",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  open: AlertCircle, in_progress: Clock, accepted_risk: Info,
  false_positive: Minus, mitigated: CheckCircle2, auto_mitigated: RefreshCw,
};

const STATUS_COLOR: Record<string, string> = {
  open: "bg-red-500/10 text-red-400",
  in_progress: "bg-blue-500/10 text-blue-400",
  accepted_risk: "bg-amber-500/10 text-amber-400",
  false_positive: "bg-muted text-muted-foreground",
  mitigated: "bg-green-500/10 text-green-400",
  auto_mitigated: "bg-teal-500/10 text-teal-400",
};

export default function AssetGroupDetailPage() {
  const [, navigate] = useLocation();
  const params = useParams<{ groupId: string }>();
  const groupId = Number(params.groupId);
  const qc = useQueryClient();
  const { toast } = useToast();

  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", color: "slate" });
  const [saving, setSaving] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);
  const [modalSearch, setModalSearch] = useState("");
  const [selected, setSelected] = useState<number[]>([]);
  const [showScanDialog, setShowScanDialog] = useState(false);
  const [showScheduleDialog, setShowScheduleDialog] = useState(false);
  const [schedForm, setSchedForm] = useState({ name: "", frequency: "daily", runTime: "09:00", dayOfWeek: 1, dayOfMonth: 1, timezone: "+00:00" });
  const [refreshingRisk, setRefreshingRisk] = useState(false);
  const [activeTab, setActiveTab] = useState<"members" | "findings">("members");

  const { data: group, isLoading } = useGetAssetGroup(groupId, {
    query: { queryKey: getGetAssetGroupQueryKey(groupId) },
  });
  const { data: members, isLoading: loadingMembers } = useGetAssetGroupMembers(groupId, {
    query: { queryKey: getGetAssetGroupMembersQueryKey(groupId) },
  });
  const { data: allAssets } = useListAssets({} as any);
  const { data: pipelineRaw } = useGetToolPipeline({
    query: { queryKey: getGetToolPipelineQueryKey() },
  });
  const { data: allFindings, isLoading: loadingFindings } = useListFindings({} as any, {
    query: {
      queryKey: getListFindingsQueryKey({} as any),
      staleTime: 30_000,
      refetchInterval: 60_000,
    },
  });

  const updateGroup = useUpdateAssetGroup();
  const setMembersApi = useSetAssetGroupMembers();

  const g = group as any;
  const memberList = (members as any[]) ?? [];
  const allAssetList = (allAssets as any[]) ?? [];

  const memberIdSet = useMemo(() => new Set(memberList.map((m: any) => m.id)), [memberList]);

  const groupFindings = useMemo(() => {
    const list = (allFindings as any[]) ?? [];
    return list.filter((f: any) => memberIdSet.has(f.assetId));
  }, [allFindings, memberIdSet]);

  const pipelineTools = useMemo(() => {
    const steps = (pipelineRaw as any[]) ?? [];
    return steps.map((s: any) => ({
      id: s.toolId ?? s.id ?? 0,
      name: s.toolName ?? s.name ?? "",
      category: s.toolCategory ?? s.category ?? "",
      isActive: s.isEnabled ?? true,
    }));
  }, [pipelineRaw]);

  const verifiedMemberIds = useMemo(() =>
    memberList.filter((a: any) => a.verificationStatus === "verified").map((a: any) => a.id),
    [memberList]
  );

  const filteredModalAssets = useMemo(() => {
    const q = modalSearch.toLowerCase();
    if (!q) return allAssetList;
    return allAssetList.filter((a: any) =>
      (a.name ?? "").toLowerCase().includes(q) ||
      (a.value ?? "").toLowerCase().includes(q) ||
      (a.type ?? "").toLowerCase().includes(q)
    );
  }, [allAssetList, modalSearch]);

  const findingCounts = useMemo(() => ({
    critical: groupFindings.filter((f: any) => f.severity === "critical").length,
    high: groupFindings.filter((f: any) => f.severity === "high").length,
    open: groupFindings.filter((f: any) => f.status === "open").length,
    total: groupFindings.length,
  }), [groupFindings]);

  function startEdit() {
    setForm({ name: g?.name ?? "", description: g?.description ?? "", color: g?.color ?? "slate" });
    setEditing(true);
  }

  async function saveEdit() {
    setSaving(true);
    await updateGroup.mutateAsync({ groupId, data: form } as any);
    qc.invalidateQueries({ queryKey: getGetAssetGroupQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    setSaving(false);
    setEditing(false);
  }

  function openAssign() {
    setSelected(memberList.map((m: any) => m.id));
    setModalSearch("");
    setAssignOpen(true);
  }

  async function saveMembers() {
    await setMembersApi.mutateAsync({ groupId, data: { assetIds: selected } });
    qc.invalidateQueries({ queryKey: getGetAssetGroupMembersQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getGetAssetGroupQueryKey(groupId) });
    qc.invalidateQueries({ queryKey: getListAssetGroupsQueryKey() });
    setAssignOpen(false);
  }

  function toggleAsset(id: number) {
    setSelected(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);
  }

  async function handleRefreshRisk() {
    setRefreshingRisk(true);
    try {
      const result = await apiFetch<{ recalculated: number }>("/api/risk/recalculate", { method: "POST" });
      await qc.invalidateQueries({ queryKey: getGetAssetGroupMembersQueryKey(groupId) });
      toast({ title: "Risk scores refreshed", description: `Recalculated ${result.recalculated} asset(s) in your tenant.` });
    } catch {
      toast({ title: "Failed to refresh risk scores", variant: "destructive" });
    } finally {
      setRefreshingRisk(false);
    }
  }

  function handleScanGroup() {
    if (verifiedMemberIds.length === 0) {
      toast({
        title: "No verified assets",
        description: "Verify ownership of at least one asset before scanning.",
        variant: "destructive",
      });
      return;
    }
    setShowScanDialog(true);
  }

  const createScheduleMutation = useCreateScanSchedule();

  function openScheduleDialog() {
    setSchedForm({ name: `${g?.name ?? "Group"} Schedule`, frequency: "daily", runTime: "09:00", dayOfWeek: 1, dayOfMonth: 1, timezone: "+00:00" });
    setShowScheduleDialog(true);
  }

  async function handleCreateSchedule() {
    const payload: Record<string, unknown> = {
      name: schedForm.name,
      frequency: schedForm.frequency,
      runTime: schedForm.runTime,
      timezone: schedForm.timezone,
      groupId,
    };
    if (schedForm.frequency === "weekly") payload.dayOfWeek = schedForm.dayOfWeek;
    if (schedForm.frequency === "monthly") payload.dayOfMonth = schedForm.dayOfMonth;
    try {
      await createScheduleMutation.mutateAsync({ data: payload as any });
      qc.invalidateQueries({ queryKey: getListScanSchedulesQueryKey() });
      toast({ title: "Schedule created", description: "All verified assets in this group will be scanned on schedule." });
      setShowScheduleDialog(false);
    } catch {
      toast({ title: "Failed to create schedule", variant: "destructive" });
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-28 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    );
  }

  const COLOR_MAP: Record<string, string> = { slate:"#64748b",rose:"#f43f5e",orange:"#f97316",amber:"#f59e0b",lime:"#84cc16",teal:"#14b8a6",sky:"#0ea5e9",violet:"#8b5cf6" };
  const groupColor = COLOR_MAP[g?.color ?? "slate"] ?? "#64748b";

  return (
    <div className="space-y-5">
      {/* Back */}
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2 text-muted-foreground" onClick={() => navigate("/asset-groups")}>
        <ArrowLeft className="w-4 h-4" /> Asset Groups
      </Button>

      {/* Hero header */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {/* Color bar accent */}
        <div className="h-1.5 w-full" style={{ background: `linear-gradient(90deg, ${groupColor}aa, ${groupColor}22)` }} />
        <div className="p-5">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border" style={{ background: `${groupColor}20`, borderColor: `${groupColor}40` }}>
                <Layers className="w-5 h-5" style={{ color: groupColor }} />
              </div>
              {editing ? (
                <div className="space-y-1 flex-1 min-w-0">
                  <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} className="h-8 text-sm font-medium" />
                  <Input value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} placeholder="Description (optional)" className="h-7 text-xs" />
                  <div className="flex items-center gap-1.5 pt-0.5">
                    <span className="text-[10px] text-muted-foreground mr-1">Color:</span>
                    {["slate","rose","orange","amber","lime","teal","sky","violet"].map(c => (
                      <button
                        key={c}
                        onClick={() => setForm(p => ({ ...p, color: c }))}
                        className={`w-4 h-4 rounded-full border-2 transition-all ${form.color === c ? "border-foreground scale-110" : "border-transparent hover:border-muted-foreground"}`}
                        style={{ backgroundColor: COLOR_MAP[c] }}
                        title={c}
                      />
                    ))}
                  </div>
                </div>
              ) : (
                <div className="min-w-0">
                  <h1 className="text-lg font-semibold truncate">{g?.name}</h1>
                  {g?.description && <p className="text-xs text-muted-foreground mt-0.5">{g.description}</p>}
                  {g?.createdAt && <p className="text-[10px] text-muted-foreground/60 mt-1">Created {formatDate(g.createdAt)}</p>}
                </div>
              )}
            </div>
            {editing ? (
              <div className="flex gap-1.5 shrink-0">
                <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setEditing(false)}>Cancel</Button>
                <Button size="sm" className="h-7 text-xs gap-1" onClick={saveEdit} disabled={saving}>
                  <Save className="w-3 h-3" />{saving ? "Saving…" : "Save"}
                </Button>
              </div>
            ) : (
              <div className="flex gap-1.5 shrink-0">
              <Button
                variant="outline" size="sm" className="h-7 text-xs gap-1"
                disabled={memberList.length === 0}
                onClick={openScheduleDialog}
                title="Schedule recurring scans for this group"
              >
                <Calendar className="w-3 h-3" />
                Schedule
              </Button>
              <Button
                variant="outline" size="sm" className="h-7 text-xs gap-1"
                disabled={memberList.length === 0}
                onClick={handleScanGroup}
              >
                <Play className="w-3 h-3" />
                Scan Now
              </Button>
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={startEdit}>Edit</Button>
              </div>
            )}
          </div>
        </div>

        {/* Stat cards row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 px-5 pb-5 -mt-1">
          <div className="bg-background/60 border border-border rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Assets</p>
            <p className="text-2xl font-bold tabular-nums">{memberList.length}</p>
            {verifiedMemberIds.length < memberList.length && memberList.length > 0 && (
              <p className="text-[10px] text-amber-400 mt-0.5">{memberList.length - verifiedMemberIds.length} unverified</p>
            )}
          </div>
          <div className="bg-background/60 border border-border rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Findings</p>
            <p className="text-2xl font-bold tabular-nums">{findingCounts.total}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{findingCounts.open} open</p>
          </div>
          <div className="bg-background/60 border border-red-500/20 rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Critical</p>
            <p className={cn("text-2xl font-bold tabular-nums", findingCounts.critical > 0 ? "text-red-400" : "text-muted-foreground/40")}>{findingCounts.critical}</p>
            <p className="text-[10px] text-orange-400 mt-0.5">{findingCounts.high} high</p>
          </div>
          <div className="bg-background/60 border border-border rounded-lg p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Verified</p>
            <p className="text-2xl font-bold tabular-nums text-green-400">{verifiedMemberIds.length}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">of {memberList.length} assets</p>
          </div>
        </div>
      </div>

      {/* Tab switcher */}
      <div className="flex gap-1 border-b border-border">
        <button
          onClick={() => setActiveTab("members")}
          className={cn(
            "pb-2.5 px-3 text-sm font-medium border-b-2 transition-colors",
            activeTab === "members"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          <span className="flex items-center gap-1.5">
            <Users className="w-3.5 h-3.5" />
            Members
            <span className="ml-0.5 text-xs bg-muted text-muted-foreground rounded px-1.5 py-0.5">{memberList.length}</span>
          </span>
        </button>
        <button
          onClick={() => setActiveTab("findings")}
          className={cn(
            "pb-2.5 px-3 text-sm font-medium border-b-2 transition-colors",
            activeTab === "findings"
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground"
          )}
        >
          <span className="flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5" />
            Findings
            {findingCounts.total > 0 && (
              <span className={cn(
                "ml-0.5 text-xs rounded px-1.5 py-0.5 font-semibold",
                findingCounts.critical > 0 ? "bg-red-500/15 text-red-400" :
                findingCounts.high > 0 ? "bg-orange-500/15 text-orange-400" :
                "bg-muted text-muted-foreground"
              )}>{findingCounts.total}</span>
            )}
          </span>
        </button>
      </div>

      {/* ── Members tab ── */}
      {activeTab === "members" && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-muted-foreground">
              {memberList.length} asset{memberList.length !== 1 ? "s" : ""} in this group
            </h2>
            <div className="flex gap-1.5">
              <Button
                size="sm" variant="outline" className="h-7 text-xs gap-1"
                onClick={handleRefreshRisk}
                disabled={refreshingRisk || memberList.length === 0}
              >
                {refreshingRisk
                  ? <Loader2 className="w-3 h-3 animate-spin" />
                  : <RefreshCw className="w-3 h-3" />}
                {refreshingRisk ? "Refreshing…" : "Refresh Risk"}
              </Button>
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1" onClick={openAssign}>
                <Plus className="w-3 h-3" /> Assign Assets
              </Button>
            </div>
          </div>

          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {loadingMembers && (
              <div className="p-4 space-y-2">
                {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-10 rounded-lg" />)}
              </div>
            )}
            {!loadingMembers && memberList.length === 0 && (
              <div className="p-8 text-center text-sm text-muted-foreground">
                No assets assigned to this group yet.
                <br />
                <button className="mt-2 text-primary hover:underline text-xs" onClick={openAssign}>Assign assets →</button>
              </div>
            )}
            {!loadingMembers && memberList.length > 0 && (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/20">
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Value</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Risk</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Scanned</th>
                  </tr>
                </thead>
                <tbody>
                  {memberList.map((a: any) => {
                    const Icon = ASSET_TYPE_ICON[a.type] ?? FileText;
                    const isVerified = a.verificationStatus === "verified";
                    return (
                      <tr
                        key={a.id}
                        className="border-b border-border/50 hover:bg-accent/30 cursor-pointer transition-colors group"
                        onClick={() => navigate(`/assets/${a.id}`)}
                      >
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                            <span className="font-medium text-xs group-hover:text-primary transition-colors">{a.name}</span>
                            <ExternalLink className="w-2.5 h-2.5 text-muted-foreground/40 group-hover:text-primary/60 transition-colors shrink-0" />
                          </div>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-muted-foreground capitalize">{a.type?.replace(/_/g, " ")}</td>
                        <td className="px-4 py-2.5 text-xs font-mono text-primary/80 truncate max-w-[160px]">{a.value}</td>
                        <td className="px-4 py-2.5">
                          <span className={cn(
                            "text-[10px] px-1.5 py-0.5 rounded font-medium",
                            isVerified ? "bg-green-500/15 text-green-400" : "bg-amber-500/15 text-amber-400"
                          )}>
                            {isVerified ? "Verified" : "Unverified"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5">
                          {a.riskScore != null ? (
                            <span className={cn(
                              "text-[10px] px-1.5 py-0.5 rounded font-bold",
                              a.riskScore >= 80 ? "bg-red-500/15 text-red-400" :
                              a.riskScore >= 60 ? "bg-orange-500/15 text-orange-400" :
                              a.riskScore >= 40 ? "bg-yellow-500/15 text-yellow-400" :
                              "bg-green-500/15 text-green-400"
                            )}>{a.riskScore}</span>
                          ) : (
                            <span className="text-[10px] text-muted-foreground/50">—</span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-muted-foreground">
                          {a.lastScannedAt ? formatDate(a.lastScannedAt) : <span className="text-muted-foreground/50">Never</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* ── Findings tab ── */}
      {activeTab === "findings" && (
        <div>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-sm font-medium text-muted-foreground">
                {groupFindings.length} finding{groupFindings.length !== 1 ? "s" : ""} across {memberList.length} asset{memberList.length !== 1 ? "s" : ""}
              </h2>
              {findingCounts.critical > 0 && (
                <span className="text-xs px-2 py-0.5 rounded bg-red-500/15 text-red-400 font-semibold">{findingCounts.critical} Critical</span>
              )}
              {findingCounts.high > 0 && (
                <span className="text-xs px-2 py-0.5 rounded bg-orange-500/15 text-orange-400 font-semibold">{findingCounts.high} High</span>
              )}
              {findingCounts.open > 0 && (
                <span className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground">{findingCounts.open} Open</span>
              )}
            </div>
            <Button
              size="sm" variant="outline" className="h-7 text-xs gap-1"
              onClick={() => navigate(`/findings`)}
            >
              <ExternalLink className="w-3 h-3" /> View in Findings
            </Button>
          </div>

          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {loadingFindings && (
              <div className="p-4 space-y-2">
                {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10 rounded-lg" />)}
              </div>
            )}
            {!loadingFindings && groupFindings.length === 0 && (
              <div className="p-8 text-center">
                <ShieldAlert className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  {memberList.length === 0
                    ? "No assets in this group. Assign assets first."
                    : "No findings for assets in this group. Run a scan to discover vulnerabilities."}
                </p>
                {memberList.length > 0 && (
                  <Button size="sm" variant="outline" className="mt-3 h-7 text-xs gap-1" onClick={handleScanGroup}>
                    <Play className="w-3 h-3" /> Scan Group
                  </Button>
                )}
              </div>
            )}
            {!loadingFindings && groupFindings.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm min-w-[700px]">
                  <thead>
                    <tr className="border-b border-border bg-muted/20">
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground w-[280px]">Title</th>
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Asset</th>
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Severity</th>
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">CVE</th>
                      <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">First Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {groupFindings.map((f: any) => {
                      const StatusIcon = STATUS_ICON[f.status] ?? Minus;
                      return (
                        <tr
                          key={f.id}
                          className="border-b border-border/40 hover:bg-accent/20 cursor-pointer transition-colors"
                          onClick={() => navigate(`/findings?search=${encodeURIComponent(f.title)}`)}
                        >
                          <td className="px-4 py-2.5 max-w-[280px]">
                            <div className="flex items-start gap-1.5">
                              {f.isKev && (
                                <span className="text-[9px] bg-red-500/20 text-red-400 border border-red-500/30 px-1 py-0.5 rounded font-bold shrink-0 mt-0.5">KEV</span>
                              )}
                              <span className="font-medium text-xs line-clamp-2 leading-snug">{f.title}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[120px] truncate">
                            {f.assetName ?? f.assetValue ?? `Asset #${f.assetId}`}
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-bold uppercase", SEV_COLOR[f.severity] ?? SEV_COLOR.info)}>
                              {f.severity}
                            </span>
                          </td>
                          <td className="px-4 py-2.5">
                            <span className={cn("inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded font-medium", STATUS_COLOR[f.status] ?? "bg-muted text-muted-foreground")}>
                              <StatusIcon className="w-2.5 h-2.5" />
                              {f.status?.replace(/_/g, " ")}
                            </span>
                          </td>
                          <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground">
                            {f.cve && /^CVE-\d{4}-\d+$/i.test(f.cve) ? (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${f.cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-primary hover:underline"
                                onClick={e => e.stopPropagation()}
                              >
                                {f.cve}
                              </a>
                            ) : f.cve && !f.cve.startsWith("EXPOSED-") && !f.cve.startsWith("EXP-") && !f.cve.startsWith("CLOUD-") && !f.cve.startsWith("VT-") ? (
                              <span className="text-muted-foreground/80">{f.cve}</span>
                            ) : "—"}
                          </td>
                          <td className="px-4 py-2.5 text-xs text-muted-foreground">
                            {f.createdAt ? formatDate(f.createdAt) : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Assign Assets modal ── */}
      {assignOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-md shadow-2xl flex flex-col max-h-[80vh]">
            <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
              <div>
                <h3 className="text-sm font-semibold">Assign Assets to Group</h3>
                <p className="text-xs text-muted-foreground mt-0.5">{selected.length} of {allAssetList.length} selected</p>
              </div>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setAssignOpen(false)}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            {/* Search box */}
            <div className="px-4 py-3 border-b border-border shrink-0">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input
                  value={modalSearch}
                  onChange={e => setModalSearch(e.target.value)}
                  placeholder="Search assets by name, value, or type…"
                  className="pl-8 h-8 text-xs"
                  autoFocus
                />
              </div>
              {modalSearch && (
                <p className="text-xs text-muted-foreground mt-1.5">
                  Showing {filteredModalAssets.length} of {allAssetList.length} assets
                </p>
              )}
            </div>

            {/* Asset list */}
            <div className="overflow-y-auto flex-1">
              <div className="border border-border rounded-lg m-4 overflow-hidden">
                {filteredModalAssets.length === 0 && (
                  <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                    No assets match your search.
                  </div>
                )}
                {filteredModalAssets.map((a: any) => {
                  const Icon = ASSET_TYPE_ICON[a.type] ?? FileText;
                  const isVerified = a.verificationStatus === "verified";
                  return (
                    <label key={a.id} className="flex items-center gap-2 px-3 py-2.5 hover:bg-accent/30 cursor-pointer border-b border-border/50 last:border-0">
                      <input
                        type="checkbox"
                        checked={selected.includes(a.id)}
                        onChange={() => toggleAsset(a.id)}
                        className="accent-primary shrink-0"
                      />
                      <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="text-sm flex-1 truncate">{a.name}</span>
                      <span className="text-xs text-muted-foreground shrink-0">{a.type?.replace(/_/g, " ")}</span>
                      {!isVerified && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-amber-500/15 text-amber-400 font-medium shrink-0">Unverified</span>
                      )}
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="flex justify-between items-center gap-2 px-5 py-3 border-t border-border shrink-0">
              <button
                className="text-xs text-muted-foreground hover:text-foreground"
                onClick={() => setSelected([])}
              >
                Deselect all
              </button>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setAssignOpen(false)}>Cancel</Button>
                <Button size="sm" onClick={saveMembers} disabled={setMembersApi.isPending}>
                  {setMembersApi.isPending ? "Saving…" : "Save Members"}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Pipeline Scan Dialog ── */}
      <RunScanDialog
        open={showScanDialog}
        onOpenChange={setShowScanDialog}
        pipelineTools={pipelineTools}
        assets={allAssetList}
        preSelectedAssetIds={verifiedMemberIds}
        onRunComplete={(scanId) => {
          setShowScanDialog(false);
          toast({ title: "Pipeline scan started", description: `Scan #${scanId} is running for this group's verified assets.` });
          navigate("/scans");
        }}
      />

      {/* ── Schedule Group Dialog ── */}
      <Dialog open={showScheduleDialog} onOpenChange={v => { if (!v) setShowScheduleDialog(false); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Calendar className="w-4 h-4 text-primary" /> Schedule Group Scans
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-1">
            <div>
              <Label className="text-xs mb-1.5 block">Schedule Name</Label>
              <Input value={schedForm.name} onChange={e => setSchedForm(p => ({ ...p, name: e.target.value }))} className="text-sm" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs mb-1.5 block">Frequency</Label>
                <Select value={schedForm.frequency} onValueChange={v => setSchedForm(p => ({ ...p, frequency: v }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="daily">Daily</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs mb-1.5 block flex items-center gap-1"><Clock className="w-3 h-3" /> Time (UTC)</Label>
                <Input type="time" value={schedForm.runTime} onChange={e => setSchedForm(p => ({ ...p, runTime: e.target.value }))} className="text-sm h-9" />
              </div>
            </div>
            {schedForm.frequency === "weekly" && (
              <div>
                <Label className="text-xs mb-1.5 block">Day of Week</Label>
                <Select value={String(schedForm.dayOfWeek)} onValueChange={v => setSchedForm(p => ({ ...p, dayOfWeek: Number(v) }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"].map((d, i) => (
                      <SelectItem key={i} value={String(i)}>{d}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            {schedForm.frequency === "monthly" && (
              <div>
                <Label className="text-xs mb-1.5 block">Day of Month</Label>
                <Select value={String(schedForm.dayOfMonth)} onValueChange={v => setSchedForm(p => ({ ...p, dayOfMonth: Number(v) }))}>
                  <SelectTrigger className="text-sm h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                      <SelectItem key={d} value={String(d)}>{d}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="bg-primary/5 border border-primary/20 rounded-lg px-3 py-2 text-xs text-muted-foreground">
              <span className="font-medium text-foreground">{memberList.length} assets</span> in this group will be scanned on schedule. Only verified assets will run.
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScheduleDialog(false)}>Cancel</Button>
            <Button onClick={handleCreateSchedule} disabled={createScheduleMutation.isPending || !schedForm.name.trim()}>
              {createScheduleMutation.isPending ? "Creating…" : "Create Schedule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
