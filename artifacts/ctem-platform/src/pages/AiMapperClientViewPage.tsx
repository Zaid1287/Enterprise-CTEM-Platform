import { useState } from "react";
import { useRoute, useLocation } from "wouter";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  ArrowLeft, Server, ShieldCheck, ShieldOff, Radar, Search,
  Loader2, Globe2, AlertTriangle, StopCircle, Plus, ChevronRight,
  Activity, XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";

const BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/20 text-green-400 border-green-500/30",
};
const PIE_COLORS = ["#8b5cf6","#3b82f6","#10b981","#f59e0b","#ef4444","#06b6d4","#ec4899"];

interface ClientSummary { id: number; name: string; slug: string; plan: string; isEnabled: boolean; }
interface ShodanPreset { id: string; label: string; protocol: string; query: string; }
interface AiScan { id: number; title: string; status: string; progress: number; createdAt: string; endpointCount?: number; }
interface AiEndpoint { id: number; ip: string; port: number; hostname?: string; protocol: string; riskScore: number; riskLevel: string; authStatus: string; country?: string; framework?: string; }
interface BomItem { id: number; framework: string; endpointCount: number; highestRiskLevel: string; }
interface ModuleStatus { isEnabled: boolean; updatedAt: string | null; }
interface TenantStats { endpoints: number; critical: number; high: number; noAuth: number; scans: number; activeScans: number; lastScanAt: string | null; isEnabled: boolean; }

type Tab = "overview" | "scans" | "endpoints" | "bom";

export default function AiMapperClientViewPage() {
  const [, params] = useRoute("/ai-mapper/clients/:tenantId");
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const tenantId = Number(params?.tenantId);

  const [tab, setTab] = useState<Tab>("overview");
  const [endpointQ, setEndpointQ] = useState("");
  const [showNewScan, setShowNewScan] = useState(false);
  const [scanTitle, setScanTitle] = useState("AI Surface Scan");
  const [selectedPresets, setSelectedPresets] = useState<string[]>([]);

  const isAdminOrSA = user?.role === "admin" || user?.role === "super_admin";

  // ── Queries ────────────────────────────────────────────────────────────────
  const { data: presets = [] } = useQuery<ShodanPreset[]>({
    queryKey: ["ai-mapper-presets"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/query-presets`),
  });

  const { data: clients = [] } = useQuery<ClientSummary[]>({
    queryKey: isAdminOrSA ? ["ai-mapper-admin-overview"] : ["ai-mapper-am-clients"],
    queryFn: () => apiFetch(`${BASE}/api/${isAdminOrSA ? "ai-mapper/admin/overview" : "ai-mapper/am-clients"}`),
  });

  const { data: module } = useQuery<ModuleStatus>({
    queryKey: ["ai-mapper-client-module", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/module`),
    enabled: !!tenantId,
  });

  const { data: stats } = useQuery<TenantStats>({
    queryKey: ["ai-mapper-client-stats", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/stats`),
    enabled: !!tenantId,
    refetchInterval: 15000,
  });

  const { data: scans = [], isLoading: scansLoading } = useQuery<AiScan[]>({
    queryKey: ["ai-mapper-client-scans", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/scans`),
    enabled: !!tenantId && tab === "scans",
    refetchInterval: (q) => {
      const d = q.state.data as AiScan[] | undefined;
      if (!d) return 5000;
      return d.some(s => s.status === "running" || s.status === "pending") ? 3000 : false;
    },
  });

  const { data: endpointData } = useQuery<{ data: AiEndpoint[]; total: number }>({
    queryKey: ["ai-mapper-client-endpoints", tenantId, endpointQ],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/endpoints?limit=50&q=${encodeURIComponent(endpointQ)}`),
    enabled: !!tenantId && tab === "endpoints",
  });

  const { data: bom } = useQuery<{ bom: BomItem[]; protocolDistribution: { protocol: string; count: number }[] }>({
    queryKey: ["ai-mapper-client-bom", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/bom`),
    enabled: !!tenantId && tab === "bom",
  });

  // ── Mutations ──────────────────────────────────────────────────────────────
  const toggleMutation = useMutation({
    mutationFn: (isEnabled: boolean) =>
      apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/module`, { method: "PATCH", body: JSON.stringify({ isEnabled }) }),
    onSuccess: (_d, isEnabled) => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-client-module", tenantId] });
      qc.invalidateQueries({ queryKey: ["ai-mapper-client-stats", tenantId] });
      qc.invalidateQueries({ queryKey: isAdminOrSA ? ["ai-mapper-admin-overview"] : ["ai-mapper-am-clients"] });
      toast({ title: isEnabled ? "AI Mapper enabled for client" : "AI Mapper disabled for client" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const createScanMutation = useMutation({
    mutationFn: () =>
      apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/scans`, {
        method: "POST",
        body: JSON.stringify({ title: scanTitle, queryPresets: selectedPresets }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-client-scans", tenantId] });
      qc.invalidateQueries({ queryKey: ["ai-mapper-client-stats", tenantId] });
      setShowNewScan(false);
      setScanTitle("AI Surface Scan");
      setSelectedPresets([]);
      toast({ title: "Scan started" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const cancelScanMutation = useMutation({
    mutationFn: (scanId: number) =>
      apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/scans/${scanId}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-client-scans", tenantId] });
      toast({ title: "Scan cancelled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const currentClient = clients.find((c: any) => c.id === tenantId);
  const isEnabled = module?.isEnabled ?? false;

  // ── Switcher ───────────────────────────────────────────────────────────────
  const backPath = isAdminOrSA ? "/ai-mapper/admin" : "/ai-mapper/clients";

  const statusBadge = isEnabled
    ? <span className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-full bg-violet-500/10 text-violet-400 border border-violet-500/25 font-medium"><ShieldCheck className="w-3 h-3" />Module Active</span>
    : <span className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded-full bg-muted/50 text-muted-foreground border border-border font-medium"><ShieldOff className="w-3 h-3" />Module Inactive</span>;

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="ghost" size="icon" onClick={() => navigate(backPath)}>
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-xl font-bold truncate">{currentClient?.name ?? `Tenant #${tenantId}`}</h1>
            {statusBadge}
          </div>
          <p className="text-sm text-muted-foreground">{currentClient?.slug ?? ""} · AI Mapper client view</p>
        </div>

        {/* Client switcher */}
        {clients.length > 1 && (
          <Select
            value={String(tenantId)}
            onValueChange={v => navigate(`/ai-mapper/clients/${v}`)}
          >
            <SelectTrigger className="w-48">
              <SelectValue placeholder="Switch client" />
            </SelectTrigger>
            <SelectContent>
              {(clients as ClientSummary[]).map(c => (
                <SelectItem key={c.id} value={String(c.id)}>
                  <span className="flex items-center gap-2">
                    {c.isEnabled ? <ShieldCheck className="w-3 h-3 text-violet-400" /> : <ShieldOff className="w-3 h-3 text-muted-foreground" />}
                    {c.name}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* Toggle (admin only) */}
        {isAdminOrSA && (
          <Button
            variant={isEnabled ? "outline" : "default"}
            size="sm"
            onClick={() => toggleMutation.mutate(!isEnabled)}
            disabled={toggleMutation.isPending}
          >
            {toggleMutation.isPending && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
            {isEnabled ? "Disable Module" : "Enable Module"}
          </Button>
        )}
      </div>

      {/* Module inactive banner */}
      {!isEnabled && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-yellow-500/5 border border-yellow-500/20 text-yellow-400 text-sm">
          <ShieldOff className="w-4 h-4 shrink-0" />
          <span>AI Mapper is not active for this client. {isAdminOrSA ? "Enable the module to start scanning." : "Contact an administrator to enable it."}</span>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "AI Endpoints", value: stats?.endpoints ?? 0, icon: Server,        color: "text-blue-400"   },
          { label: "Critical",     value: stats?.critical  ?? 0, icon: AlertTriangle, color: "text-red-400"    },
          { label: "No Auth",      value: stats?.noAuth    ?? 0, icon: XCircle,       color: "text-orange-400" },
          { label: "Scans",        value: stats?.scans     ?? 0, icon: Radar,         color: "text-violet-400" },
        ].map(s => (
          <Card key={s.label}>
            <CardContent className="py-4">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={cn("w-4 h-4", s.color)} />
                <span className="text-xs text-muted-foreground">{s.label}</span>
              </div>
              <p className="text-2xl font-bold">{s.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border pb-0">
        {(["overview", "scans", "endpoints", "bom"] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={cn(
              "px-4 py-2 text-sm font-medium capitalize rounded-t transition-colors border-b-2 -mb-px",
              tab === t
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground"
            )}
          >
            {t === "bom" ? "AI BOM" : t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {/* ── Overview tab ─────────────────────────────────────────────────────── */}
      {tab === "overview" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader><CardTitle className="text-sm">Module Status</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Status</span>
                  {statusBadge}
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Last enabled</span>
                  <span>{module?.updatedAt ? formatDistanceToNow(new Date(module.updatedAt), { addSuffix: true }) : "—"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Last scan</span>
                  <span>{stats?.lastScanAt ? formatDistanceToNow(new Date(stats.lastScanAt), { addSuffix: true }) : "—"}</span>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-sm">Risk Summary</CardTitle></CardHeader>
              <CardContent className="space-y-2 text-sm">
                {[
                  { label: "Critical endpoints", value: stats?.critical ?? 0, color: "text-red-400" },
                  { label: "High risk endpoints", value: stats?.high ?? 0,    color: "text-orange-400" },
                  { label: "No auth exposed",     value: stats?.noAuth ?? 0,  color: "text-yellow-400" },
                  { label: "Active scans",         value: stats?.activeScans ?? 0, color: "text-green-400" },
                ].map(r => (
                  <div key={r.label} className="flex justify-between">
                    <span className="text-muted-foreground">{r.label}</span>
                    <span className={cn("font-semibold tabular-nums", r.value > 0 ? r.color : "")}>{r.value}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
          <div className="flex gap-3 flex-wrap">
            <Button size="sm" variant="outline" onClick={() => setTab("scans")}>
              <Radar className="w-3.5 h-3.5 mr-1.5" /> View Scans
            </Button>
            <Button size="sm" variant="outline" onClick={() => setTab("endpoints")}>
              <Server className="w-3.5 h-3.5 mr-1.5" /> View Endpoints
            </Button>
            {isEnabled && (
              <Button size="sm" onClick={() => { setTab("scans"); setShowNewScan(true); }}>
                <Plus className="w-3.5 h-3.5 mr-1.5" /> New Scan
              </Button>
            )}
          </div>
        </div>
      )}

      {/* ── Scans tab ─────────────────────────────────────────────────────────── */}
      {tab === "scans" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">{scans.length} scan{scans.length !== 1 ? "s" : ""}</p>
            {isEnabled && (
              <Button size="sm" onClick={() => setShowNewScan(true)}>
                <Plus className="w-3.5 h-3.5 mr-1.5" /> New Scan
              </Button>
            )}
          </div>

          {/* New scan dialog inline */}
          {showNewScan && (
            <Card className="border-primary/40">
              <CardHeader><CardTitle className="text-sm">New AI Surface Scan</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1 block">Scan title</label>
                  <Input value={scanTitle} onChange={e => setScanTitle(e.target.value)} placeholder="AI Surface Scan" />
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-2 block">Shodan query presets</label>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-48 overflow-y-auto pr-1">
                    {presets.map(p => (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => setSelectedPresets(prev => prev.includes(p.id) ? prev.filter(x => x !== p.id) : [...prev, p.id])}
                        className={cn(
                          "text-left p-2.5 rounded-lg border text-xs transition-colors",
                          selectedPresets.includes(p.id)
                            ? "border-primary bg-primary/10 text-primary"
                            : "border-border hover:border-primary/50 hover:bg-muted/40"
                        )}
                      >
                        <div className="font-medium">{p.label}</div>
                        <div className="text-muted-foreground font-mono mt-0.5 truncate">{p.query}</div>
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex gap-2 justify-end">
                  <Button variant="ghost" size="sm" onClick={() => setShowNewScan(false)}>Cancel</Button>
                  <Button size="sm" onClick={() => createScanMutation.mutate()} disabled={createScanMutation.isPending}>
                    {createScanMutation.isPending && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
                    Start Scan
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {scansLoading ? (
            <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>
          ) : scans.length === 0 ? (
            <div className="py-16 text-center text-muted-foreground text-sm">
              <Radar className="w-8 h-8 mx-auto mb-3 opacity-30" />
              No scans yet.
            </div>
          ) : (
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/20">
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                    <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Endpoints</th>
                    <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Started</th>
                    <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map(s => (
                    <tr key={s.id} className="border-b border-border/50 hover:bg-accent/30">
                      <td className="px-4 py-3 font-medium">{s.title}</td>
                      <td className="px-4 py-3">
                        {(s.status === "running" || s.status === "pending") ? (
                          <div className="flex items-center gap-2">
                            <Activity className="w-3.5 h-3.5 text-green-400 animate-pulse" />
                            <div className="flex-1 max-w-32">
                              <Progress value={s.progress ?? 0} className="h-1.5" />
                            </div>
                            <span className="text-xs text-muted-foreground">{s.progress ?? 0}%</span>
                          </div>
                        ) : (
                          <Badge variant="outline" className="text-xs capitalize">{s.status}</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 tabular-nums text-right">{s.endpointCount ?? 0}</td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {formatDistanceToNow(new Date(s.createdAt), { addSuffix: true })}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          {(s.status === "running" || s.status === "pending") && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="w-7 h-7 text-destructive"
                              onClick={() => cancelScanMutation.mutate(s.id)}
                              disabled={cancelScanMutation.isPending}
                              title="Cancel scan"
                            >
                              <StopCircle className="w-3.5 h-3.5" />
                            </Button>
                          )}
                          <Button
                            variant="ghost"
                            size="icon"
                            className="w-7 h-7"
                            onClick={() => navigate(`/ai-mapper/clients/${tenantId}/scans/${s.id}`)}
                          >
                            <ChevronRight className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Endpoints tab ─────────────────────────────────────────────────────── */}
      {tab === "endpoints" && (
        <div className="space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              value={endpointQ}
              onChange={e => setEndpointQ(e.target.value)}
              placeholder="Filter: protocol:ollama auth:none…"
              className="pl-9"
            />
          </div>

          {!endpointData ? (
            <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-14 rounded-lg" />)}</div>
          ) : endpointData.data.length === 0 ? (
            <div className="py-16 text-center text-muted-foreground text-sm">
              <Server className="w-8 h-8 mx-auto mb-3 opacity-30" />
              No endpoints found.
            </div>
          ) : (
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="px-4 py-2 border-b border-border text-xs text-muted-foreground">
                {endpointData.total} endpoint{endpointData.total !== 1 ? "s" : ""}
              </div>
              <div className="divide-y divide-border">
                {endpointData.data.map(ep => (
                  <div
                    key={ep.id}
                    className="flex items-center gap-4 px-4 py-3 hover:bg-muted/30 cursor-pointer"
                    onClick={() => navigate(`/ai-mapper/clients/${tenantId}/endpoints/${ep.id}`)}
                  >
                    <RiskScoreGauge score={ep.riskScore} size="sm" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">{ep.ip}:{ep.port}</span>
                        {ep.hostname && <span className="text-xs text-muted-foreground truncate">{ep.hostname}</span>}
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge variant="outline" className="text-xs">{ep.protocol}</Badge>
                        {ep.framework && <span className="text-xs text-muted-foreground">{ep.framework}</span>}
                        <Badge className={cn("text-xs border", RISK_BADGE[ep.riskLevel] ?? "")}>{ep.riskLevel}</Badge>
                        {ep.authStatus === "none" && <Badge variant="destructive" className="text-xs">No Auth</Badge>}
                      </div>
                    </div>
                    <div className="text-right text-xs text-muted-foreground shrink-0">
                      {ep.country && <p>{ep.country}</p>}
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── BOM tab ─────────────────────────────────────────────────────────── */}
      {tab === "bom" && (
        <div className="space-y-4">
          {!bom ? (
            <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}</div>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Protocol distribution pie */}
                <Card>
                  <CardHeader><CardTitle className="text-sm">Protocol Distribution</CardTitle></CardHeader>
                  <CardContent>
                    {bom.protocolDistribution.length === 0 ? (
                      <div className="py-8 text-center text-sm text-muted-foreground">No data</div>
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <PieChart>
                          <Pie data={bom.protocolDistribution.map(d => ({ name: d.protocol, value: Number(d.count) }))} cx="50%" cy="50%" outerRadius={70} dataKey="value" label={({ name }) => name}>
                            {bom.protocolDistribution.map((_, i) => <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />)}
                          </Pie>
                          <Tooltip />
                        </PieChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>

                {/* Risk by framework bar */}
                <Card>
                  <CardHeader><CardTitle className="text-sm">Endpoint Count by Framework</CardTitle></CardHeader>
                  <CardContent>
                    {bom.bom.length === 0 ? (
                      <div className="py-8 text-center text-sm text-muted-foreground">No BOM data</div>
                    ) : (
                      <ResponsiveContainer width="100%" height={200}>
                        <BarChart data={bom.bom.map(b => ({ name: b.framework, count: b.endpointCount }))}>
                          <XAxis dataKey="name" tick={{ fontSize: 10 }} />
                          <YAxis tick={{ fontSize: 10 }} />
                          <Tooltip />
                          <Bar dataKey="count" fill="#8b5cf6" radius={[3, 3, 0, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* BOM table */}
              {bom.bom.length > 0 && (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-muted/20">
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Framework</th>
                        <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Endpoints</th>
                        <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Highest Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bom.bom.map(b => (
                        <tr key={b.id} className="border-b border-border/50">
                          <td className="px-4 py-2.5 font-medium">{b.framework}</td>
                          <td className="px-4 py-2.5 tabular-nums text-right">{b.endpointCount}</td>
                          <td className="px-4 py-2.5">
                            <Badge className={cn("text-xs border", RISK_BADGE[b.highestRiskLevel] ?? "")}>{b.highestRiskLevel}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
