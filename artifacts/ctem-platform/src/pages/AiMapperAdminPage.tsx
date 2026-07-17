import { useState } from "react";
import { SmartPagination } from "@/components/ui/SmartPagination";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
} from "recharts";
import {
  Globe2, Search, ChevronRight, Loader2, ShieldCheck, ShieldOff, Server,
  AlertTriangle, Activity, Play, CheckCircle2, XCircle, Clock, Wifi,
  TrendingUp, Users, Scan, ArrowUpDown, ArrowUp, ArrowDown, Key,
  RefreshCw,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";

const BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

interface TenantAiRow {
  id: number; name: string; slug: string; plan: string; isActive: boolean;
  isEnabled: boolean; endpoints: number; critical: number; high: number;
  noAuth: number; scans: number; activeScans: number; lastScanAt: string | null;
}
interface ProtocolDist { protocol: string; count: number; }
interface ActivityScan {
  id: number; title: string; status: string; progress: number;
  endpointCount: number | null; tenantId: number; tenantName: string;
  createdAt: string; completedAt: string | null;
}
interface ShodanPreset { id: string; label: string; protocol: string; query: string; }

const PROTO_COLORS: Record<string, string> = {
  mcp: "#3b82f6", ollama: "#22c55e", vllm: "#a855f7", langserve: "#f97316",
  gradio: "#ec4899", comfyui: "#eab308", litellm: "#8b5cf6", localai: "#06b6d4",
  openwebui: "#0ea5e9", stablediff: "#f43f5e", generic: "#64748b", tgi: "#d946ef",
  librechat: "#10b981", streamlit: "#ff4b4b",
};

const ST_ICON: Record<string, React.ElementType> = {
  pending: Clock, running: Loader2, completed: CheckCircle2,
  failed: XCircle, cancelled: XCircle,
};
const ST_COLOR: Record<string, string> = {
  pending: "text-slate-400", running: "text-blue-400 animate-spin",
  completed: "text-green-400", failed: "text-red-400", cancelled: "text-slate-400",
};

type SortCol = "name" | "endpoints" | "critical" | "noAuth" | "scans" | "lastScanAt";
type FilterTab = "all" | "enabled" | "disabled" | "active";

function SortBtn({ col, current, dir, onClick }: { col: SortCol; current: SortCol; dir: "asc" | "desc"; onClick: () => void }) {
  return (
    <button className="inline-flex items-center gap-0.5" onClick={onClick}>
      {col === current
        ? dir === "asc" ? <ArrowUp className="w-3 h-3 text-violet-400" /> : <ArrowDown className="w-3 h-3 text-violet-400" />
        : <ArrowUpDown className="w-3 h-3 text-muted-foreground/40" />}
    </button>
  );
}

export default function AiMapperAdminPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [search, setSearch]       = useState("");
  const [tab, setTab]             = useState<FilterTab>("all");
  const [adminPage, setAdminPage] = useState(1);
  const ADMIN_PAGE_SIZE = 15;
  const [sortCol, setSortCol]     = useState<SortCol>("endpoints");
  const [popoverTenantId, setPopoverTenantId] = useState<number | null>(null);
  const [pendingEnabled, setPendingEnabled]   = useState(false);
  const [sortDir, setSortDir]     = useState<"asc" | "desc">("desc");
  const [launchTenant, setLaunchTenant] = useState<TenantAiRow | null>(null);
  const [scanTitle, setScanTitle] = useState("AI Surface Scan");
  const [selPresets, setSelPresets] = useState<string[]>([]);
  const [cidrScope, setCidrScope] = useState("");

  const { data: rows = [], isLoading, refetch } = useQuery<TenantAiRow[]>({
    queryKey: ["ai-mapper-admin-overview"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/admin/overview`),
    refetchInterval: 30_000,
  });
  const { data: protocols = [] } = useQuery<ProtocolDist[]>({
    queryKey: ["ai-mapper-admin-protocols"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/admin/protocols`),
    refetchInterval: 60_000,
  });
  const { data: activity = [], isLoading: actLoading } = useQuery<ActivityScan[]>({
    queryKey: ["ai-mapper-admin-activity"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/admin/activity`),
    refetchInterval: (q) => {
      const d = q.state.data as ActivityScan[] | undefined;
      if (!d || d.some(s => s.status === "running" || s.status === "pending")) return 5000;
      return 30_000;
    },
  });
  const { data: presets = [] } = useQuery<ShodanPreset[]>({
    queryKey: ["ai-mapper-presets"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/query-presets`),
  });

  const toggleMut = useMutation({
    mutationFn: ({ tenantId, isEnabled }: { tenantId: number; isEnabled: boolean }) =>
      apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/module`, { method: "PATCH", body: JSON.stringify({ isEnabled }) }),
    onSuccess: (_d, { isEnabled }) => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-admin-overview"] });
      toast({ title: isEnabled ? "AI Mapper enabled" : "AI Mapper disabled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const launchMut = useMutation({
    mutationFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${launchTenant!.id}/scans`, {
      method: "POST",
      body: JSON.stringify({ title: scanTitle, queryPresets: selPresets, cidrScope: cidrScope.trim() || undefined }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-admin-overview"] });
      qc.invalidateQueries({ queryKey: ["ai-mapper-admin-activity"] });
      toast({ title: "Scan launched", description: `Started for ${launchTenant!.name}` });
      setLaunchTenant(null); setScanTitle("AI Surface Scan"); setSelPresets([]); setCidrScope("");
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function closeDialog() { setLaunchTenant(null); setScanTitle("AI Surface Scan"); setSelPresets([]); setCidrScope(""); }

  const totalEnabled   = rows.filter(r => r.isEnabled).length;
  const totalEndpoints = rows.reduce((s, r) => s + r.endpoints, 0);
  const totalCritical  = rows.reduce((s, r) => s + r.critical, 0);
  const totalNoAuth    = rows.reduce((s, r) => s + r.noAuth, 0);
  const totalActive    = rows.reduce((s, r) => s + r.activeScans, 0);

  const filtered = rows
    .filter(r => {
      if (search) {
        const q = search.toLowerCase();
        if (!r.name.toLowerCase().includes(q) && !r.slug.toLowerCase().includes(q)) return false;
      }
      if (tab === "enabled")  return r.isEnabled;
      if (tab === "disabled") return !r.isEnabled;
      if (tab === "active")   return r.activeScans > 0;
      return true;
    })
    .sort((a, b) => {
      let av: any = a[sortCol]; let bv: any = b[sortCol];
      if (sortCol === "lastScanAt") { av = av ? new Date(av).getTime() : 0; bv = bv ? new Date(bv).getTime() : 0; }
      if (typeof av === "string") return sortDir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
      return sortDir === "asc" ? (av ?? 0) - (bv ?? 0) : (bv ?? 0) - (av ?? 0);
    });

  const adminTotalPages = Math.max(1, Math.ceil(filtered.length / ADMIN_PAGE_SIZE));
  const adminPaged = filtered.slice((adminPage - 1) * ADMIN_PAGE_SIZE, adminPage * ADMIN_PAGE_SIZE);

  function toggleSort(col: SortCol) {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("desc"); setAdminPage(1); }
  }

  const pieData = protocols.map(p => ({ name: p.protocol, value: p.count, color: PROTO_COLORS[p.protocol] ?? "#64748b" }));

  const KPI = [
    { label: "Total Tenants",   value: rows.length,                   icon: Users,         tw: "text-slate-300", bg: "border-slate-700/60 bg-slate-800/30" },
    { label: "Module Enabled",  value: `${totalEnabled} / ${rows.length}`, icon: ShieldCheck,  tw: "text-violet-400", bg: "border-violet-500/25 bg-violet-500/8" },
    { label: "AI Endpoints",    value: totalEndpoints.toLocaleString(), icon: Server,        tw: "text-blue-400",   bg: "border-blue-500/25 bg-blue-500/8" },
    { label: "Critical Exposed",value: totalCritical.toLocaleString(),  icon: AlertTriangle, tw: "text-red-400",    bg: "border-red-500/25 bg-red-500/8" },
    { label: "No-Auth Servers", value: totalNoAuth.toLocaleString(),    icon: Wifi,          tw: "text-yellow-400", bg: "border-yellow-500/25 bg-yellow-500/8" },
    { label: "Active Scans",    value: totalActive.toLocaleString(),    icon: Activity,      tw: "text-green-400",  bg: "border-green-500/25 bg-green-500/8" },
  ];

  return (
    <div className="h-[calc(100vh-56px)] flex flex-col overflow-hidden">
      {/* ── Header ─────────────────────────────────────────────────────────────── */}
      <div className="px-6 py-3.5 border-b border-border flex items-center justify-between gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-violet-500/10 border border-violet-500/25 flex items-center justify-center shrink-0">
            <Globe2 className="w-4.5 h-4.5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-lg font-bold leading-tight">AI Mapper — Admin Console</h1>
            <p className="text-xs text-muted-foreground">
              {isLoading ? "Loading…" : `${rows.length} tenants · ${totalEndpoints.toLocaleString()} endpoints discovered globally`}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" size="sm" className="h-8 text-xs" onClick={() => { refetch(); qc.invalidateQueries({ queryKey: ["ai-mapper-admin-protocols"] }); qc.invalidateQueries({ queryKey: ["ai-mapper-admin-activity"] }); }}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
          <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => navigate("/settings/platform")}>
            <Key className="w-3.5 h-3.5 mr-1.5" /> Shodan API Key
          </Button>
          <Button variant="outline" size="sm" className="h-8 text-xs" onClick={() => navigate("/ai-mapper")}>
            <TrendingUp className="w-3.5 h-3.5 mr-1.5" /> My Overview
          </Button>
        </div>
      </div>

      {/* ── Scrollable Body ─────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        <div className="px-6 py-4 space-y-4">

          {/* KPI Strip */}
          <div className="grid grid-cols-6 gap-3">
            {KPI.map(k => (
              <div key={k.label} className={cn("rounded-xl border p-3.5 flex items-center gap-3", k.bg)}>
                <k.icon className={cn("w-4.5 h-4.5 shrink-0", k.tw)} />
                <div className="min-w-0">
                  {isLoading
                    ? <Skeleton className="h-5 w-12 mb-1" />
                    : <p className="text-xl font-bold leading-none">{k.value}</p>}
                  <p className="text-xs text-muted-foreground mt-0.5 truncate">{k.label}</p>
                </div>
              </div>
            ))}
          </div>

          {/* Middle Row: chart + activity */}
          <div className="grid grid-cols-[1fr_360px] gap-4">
            {/* Protocol Pie */}
            <div className="bg-card border border-border rounded-xl p-4">
              <p className="text-sm font-semibold mb-1">Protocol Distribution</p>
              <p className="text-xs text-muted-foreground mb-4">All discovered AI endpoints across every tenant</p>
              {protocols.length === 0 ? (
                <div className="h-44 flex items-center justify-center">
                  <div className="text-center">
                    <Server className="w-8 h-8 mx-auto mb-2 text-muted-foreground opacity-30" />
                    <p className="text-sm text-muted-foreground">No endpoint data yet — run scans to populate</p>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-8">
                  <div className="h-52 w-52 shrink-0">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={52} outerRadius={80} dataKey="value" paddingAngle={2}>
                          {pieData.map((entry, i) => (
                            <Cell key={i} fill={entry.color} stroke="transparent" />
                          ))}
                        </Pie>
                        <ReTooltip
                          contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: "12px" }}
                          formatter={(val: any, name: any) => [`${Number(val).toLocaleString()} endpoints`, name]}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex-1 grid grid-cols-2 gap-x-6 gap-y-2">
                    {pieData.map(p => (
                      <div key={p.name} className="flex items-center gap-2">
                        <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: p.color }} />
                        <span className="text-sm capitalize text-muted-foreground truncate">{p.name}</span>
                        <span className="text-sm font-semibold ml-auto pl-1 tabular-nums">{p.value.toLocaleString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Activity Feed */}
            <div className="bg-card border border-border rounded-xl p-4 flex flex-col overflow-hidden">
              <p className="text-sm font-semibold mb-1 shrink-0">Recent Scan Activity</p>
              <p className="text-xs text-muted-foreground mb-3 shrink-0">Latest scans across all tenants</p>
              {actLoading ? (
                <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
              ) : activity.length === 0 ? (
                <div className="flex-1 flex items-center justify-center">
                  <p className="text-sm text-muted-foreground">No scans yet</p>
                </div>
              ) : (
                <div className="space-y-0 overflow-y-auto flex-1 -mx-1 px-1">
                  {activity.map(s => {
                    const Icon = ST_ICON[s.status] ?? Clock;
                    return (
                      <div key={s.id} className="flex items-start gap-2.5 py-2 border-b border-border/40 last:border-0">
                        <Icon className={cn("w-3.5 h-3.5 mt-0.5 shrink-0", ST_COLOR[s.status])} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium truncate">{s.title}</p>
                          <p className="text-xs text-muted-foreground truncate">{s.tenantName}</p>
                          {(s.status === "running" || s.status === "pending") && (
                            <Progress value={s.progress ?? 0} className="h-0.5 mt-1" />
                          )}
                        </div>
                        <div className="text-right shrink-0 ml-2">
                          {s.endpointCount != null && s.endpointCount > 0 && (
                            <p className="text-xs font-semibold">{s.endpointCount} ep</p>
                          )}
                          <p className="text-xs text-muted-foreground">{formatDistanceToNow(new Date(s.createdAt), { addSuffix: true })}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Table controls */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                value={search}
                onChange={e => { setSearch(e.target.value); setAdminPage(1); }}
                placeholder="Search tenants…"
                className="pl-8 h-8 text-sm w-56"
              />
            </div>
            <Tabs value={tab} onValueChange={v => { setTab(v as FilterTab); setAdminPage(1); }}>
              <TabsList className="h-8">
                <TabsTrigger value="all"      className="text-xs h-6 px-3">All ({rows.length})</TabsTrigger>
                <TabsTrigger value="enabled"  className="text-xs h-6 px-3">Enabled ({totalEnabled})</TabsTrigger>
                <TabsTrigger value="disabled" className="text-xs h-6 px-3">Disabled ({rows.length - totalEnabled})</TabsTrigger>
                {totalActive > 0 && (
                  <TabsTrigger value="active" className="text-xs h-6 px-3 data-[state=active]:text-green-400">
                    <Activity className="w-3 h-3 mr-1 text-green-400" />Active ({totalActive})
                  </TabsTrigger>
                )}
              </TabsList>
            </Tabs>
            <span className="text-xs text-muted-foreground ml-auto">{filtered.length} of {rows.length} tenants</span>
          </div>

          {/* Full-width table */}
          {isLoading ? (
            <div className="space-y-2">{[...Array(6)].map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}</div>
          ) : (
            <>
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/20 text-xs text-muted-foreground">
                    <th className="text-left px-4 py-2.5 font-medium">
                      <button className="flex items-center gap-1" onClick={() => toggleSort("name")}>
                        Tenant <SortBtn col="name" current={sortCol} dir={sortDir} onClick={() => toggleSort("name")} />
                      </button>
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium w-24">Plan</th>
                    <th className="text-left px-4 py-2.5 font-medium w-32">AI Mapper</th>
                    <th className="text-right px-4 py-2.5 font-medium w-28">
                      <button className="flex items-center gap-1 ml-auto" onClick={() => toggleSort("endpoints")}>
                        Endpoints <SortBtn col="endpoints" current={sortCol} dir={sortDir} onClick={() => toggleSort("endpoints")} />
                      </button>
                    </th>
                    <th className="text-right px-4 py-2.5 font-medium w-24">
                      <button className="flex items-center gap-1 ml-auto" onClick={() => toggleSort("critical")}>
                        Critical <SortBtn col="critical" current={sortCol} dir={sortDir} onClick={() => toggleSort("critical")} />
                      </button>
                    </th>
                    <th className="text-right px-4 py-2.5 font-medium w-24">
                      <button className="flex items-center gap-1 ml-auto" onClick={() => toggleSort("noAuth")}>
                        No-Auth <SortBtn col="noAuth" current={sortCol} dir={sortDir} onClick={() => toggleSort("noAuth")} />
                      </button>
                    </th>
                    <th className="text-right px-4 py-2.5 font-medium w-20">
                      <button className="flex items-center gap-1 ml-auto" onClick={() => toggleSort("scans")}>
                        Scans <SortBtn col="scans" current={sortCol} dir={sortDir} onClick={() => toggleSort("scans")} />
                      </button>
                    </th>
                    <th className="text-left px-4 py-2.5 font-medium w-36">
                      <button className="flex items-center gap-1" onClick={() => toggleSort("lastScanAt")}>
                        Last Scan <SortBtn col="lastScanAt" current={sortCol} dir={sortDir} onClick={() => toggleSort("lastScanAt")} />
                      </button>
                    </th>
                    <th className="text-right px-4 py-2.5 font-medium w-40">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={9} className="px-4 py-12 text-center text-muted-foreground text-sm">
                        No tenants match your filters
                      </td>
                    </tr>
                  )}
                  {adminPaged.map(t => (
                    <tr key={t.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
                          <span className={cn("w-2 h-2 rounded-full shrink-0",
                            t.activeScans > 0 ? "bg-green-500 animate-pulse" :
                            t.isActive ? "bg-slate-600" : "bg-red-800"
                          )} />
                          <div>
                            <p className="font-medium">{t.name}</p>
                            <p className="text-xs text-muted-foreground font-mono">{t.slug}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Popover
                          open={popoverTenantId === t.id}
                          onOpenChange={open => {
                            if (open) { setPopoverTenantId(t.id); setPendingEnabled(t.isEnabled); }
                            else setPopoverTenantId(null);
                          }}
                        >
                          <PopoverTrigger asChild>
                            <button className={cn(
                              "text-xs px-2.5 py-1 rounded-full font-medium border transition-colors cursor-pointer inline-flex items-center gap-1.5",
                              t.isEnabled
                                ? "bg-violet-500/10 text-violet-400 border-violet-500/25 hover:bg-violet-500/20"
                                : "bg-muted/50 text-muted-foreground border-border hover:bg-muted"
                            )}>
                              {t.isEnabled
                                ? <><ShieldCheck className="w-3 h-3" />Enabled</>
                                : <><ShieldOff className="w-3 h-3" />Disabled</>}
                            </button>
                          </PopoverTrigger>
                          <PopoverContent className="w-56 p-3 space-y-3" align="start">
                            <p className="text-sm font-medium">{t.name}</p>
                            <div className="flex items-center justify-between">
                              <Label className="text-sm">AI Mapper</Label>
                              <Switch
                                checked={pendingEnabled}
                                onCheckedChange={setPendingEnabled}
                              />
                            </div>
                            <p className="text-xs text-muted-foreground">
                              {pendingEnabled ? "Module will be enabled for this tenant." : "Module will be disabled for this tenant."}
                            </p>
                            <Button
                              size="sm"
                              className="w-full"
                              disabled={toggleMut.isPending || pendingEnabled === t.isEnabled}
                              onClick={() => {
                                toggleMut.mutate({ tenantId: t.id, isEnabled: pendingEnabled });
                                setPopoverTenantId(null);
                              }}
                            >
                              {toggleMut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : null}
                              Save
                            </Button>
                          </PopoverContent>
                        </Popover>
                      </td>
                      <td className="px-4 py-3 tabular-nums text-right">
                        {t.endpoints > 0
                          ? <span className="font-semibold">{t.endpoints.toLocaleString()}</span>
                          : <span className="text-muted-foreground/30">—</span>}
                      </td>
                      <td className="px-4 py-3 tabular-nums text-right">
                        {t.critical > 0
                          ? <span className="text-red-400 font-semibold">{t.critical}</span>
                          : <span className="text-muted-foreground/30">—</span>}
                      </td>
                      <td className="px-4 py-3 tabular-nums text-right">
                        {t.noAuth > 0
                          ? <span className="text-yellow-400 font-semibold">{t.noAuth}</span>
                          : <span className="text-muted-foreground/30">—</span>}
                      </td>
                      <td className="px-4 py-3 tabular-nums text-right">
                        <span className="inline-flex items-center gap-1 justify-end">
                          {t.activeScans > 0 && <Activity className="w-3 h-3 text-green-400 animate-pulse" />}
                          {t.scans}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {t.lastScanAt ? formatDistanceToNow(new Date(t.lastScanAt), { addSuffix: true }) : "—"}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          {t.isEnabled && (
                            <Button
                              variant="ghost" size="sm"
                              className="h-7 px-2 text-xs text-violet-400 hover:text-violet-300 hover:bg-violet-500/10"
                              onClick={() => { setLaunchTenant(t); setScanTitle(`${t.name} — AI Scan`); }}
                            >
                              <Scan className="w-3 h-3 mr-1" /> Scan
                            </Button>
                          )}
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 px-2 text-xs"
                            onClick={() => navigate(`/ai-mapper/clients/${t.id}`)}
                          >
                            View <ChevronRight className="w-3.5 h-3.5 ml-0.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <SmartPagination
              page={adminPage}
              totalPages={adminTotalPages}
              totalItems={filtered.length}
              pageSize={ADMIN_PAGE_SIZE}
              itemLabel="tenants"
              onPageChange={setAdminPage}
              className="px-4 py-3 border-t border-border/40"
            />
            </>
          )}
        </div>
      </div>

      {/* ── Launch Scan Dialog ─────────────────────────────────────────────────── */}
      <Dialog open={!!launchTenant} onOpenChange={open => { if (!open) closeDialog(); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Scan className="w-4 h-4 text-violet-400" />
              Launch Scan — {launchTenant?.name}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label>Scan Title</Label>
              <Input value={scanTitle} onChange={e => setScanTitle(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>
                CIDR / IP Scope
                <span className="text-muted-foreground font-normal ml-1.5 text-xs">(optional — one entry per line)</span>
              </Label>
              <Textarea
                value={cidrScope}
                onChange={e => setCidrScope(e.target.value)}
                placeholder={"192.168.1.0/24\n10.0.0.15\n203.0.113.0/28"}
                rows={3}
                className="font-mono text-xs resize-none"
              />
              <p className="text-xs text-muted-foreground">Leave blank to run Shodan queries globally. Provide ranges to scope to specific IPs.</p>
            </div>
            <div className="space-y-2">
              <Label>
                Shodan Query Presets
                <span className="text-muted-foreground font-normal ml-1.5 text-xs">(all protocols if none selected)</span>
              </Label>
              <div className="grid grid-cols-1 gap-1 max-h-48 overflow-y-auto pr-1">
                {presets.map(p => (
                  <button
                    key={p.id}
                    onClick={() => setSelPresets(prev => prev.includes(p.id) ? prev.filter(x => x !== p.id) : [...prev, p.id])}
                    className={cn(
                      "text-left px-3 py-2 rounded-md border text-sm transition-colors",
                      selPresets.includes(p.id)
                        ? "border-violet-500/50 bg-violet-500/10 text-violet-300"
                        : "border-border hover:border-violet-500/30 hover:bg-muted/40"
                    )}
                  >
                    <div className="font-medium text-xs">{p.label}</div>
                    <div className="text-xs text-muted-foreground font-mono truncate">{p.query}</div>
                  </button>
                ))}
              </div>
              {selPresets.length > 0 && (
                <button className="text-xs text-muted-foreground hover:text-foreground" onClick={() => setSelPresets([])}>
                  Clear {selPresets.length} selected
                </button>
              )}
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={closeDialog}>Cancel</Button>
            <Button onClick={() => launchMut.mutate()} disabled={launchMut.isPending || !scanTitle.trim()}>
              {launchMut.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
              Launch Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
