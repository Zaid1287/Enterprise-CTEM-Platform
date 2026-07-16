import { useEffect, useState, useMemo, useCallback } from "react";
import { useSearch, Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  RefreshCw, Package, AlertTriangle, Globe, Eye,
  ChevronFirst, ChevronLast, ChevronLeft, ChevronRight, Loader2,
} from "lucide-react";
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip as ReTooltip,
  ResponsiveContainer, ReferenceLine, Label, PieChart, Pie, Cell, Legend,
} from "recharts";
import { useToast } from "@/hooks/use-toast";

const PAGE_SIZE_SUPPLIERS   = 20;
const PAGE_SIZE_COMPONENTS  = 20;

// ── Helpers ──────────────────────────────────────────────────────────────────

function riskBadge(level: string) {
  const m: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
    none:     "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold border ${m[level] ?? m.low}`}>{level}</span>;
}

function gradeBadgeSm(grade: string) {
  const c = grade === "A+" || grade === "A"
    ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-1.5 py-0.5 rounded border text-xs font-bold ${c}`}>{grade}</span>;
}

function cyberPostureColor(score: number) {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

function vendorDotColor(riskScore: number): string {
  if (riskScore >= 70) return "#ef4444";
  if (riskScore >= 50) return "#f97316";
  if (riskScore >= 30) return "#fbbf24";
  return "#22c55e";
}

// Deterministic jitter — spreads overlapping dots without randomness
function jitterX(id: number): number { return ((id * 2654435761) >>> 0) % 100 / 100 * 0.5 - 0.25; }
function jitterY(id: number): number { return ((id * 1234567891) >>> 0) % 100 / 100 * 6 - 3; }

// Smart pagination — first page, last 3, current ±2, "…" between gaps
function getPageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 9) return Array.from({ length: total }, (_, i) => i + 1);
  const always = new Set([1, total - 2, total - 1, total].filter(p => p >= 1));
  const near   = new Set(
    [current - 2, current - 1, current, current + 1, current + 2].filter(p => p >= 1 && p <= total),
  );
  const all = [...new Set([...always, ...near])].sort((a, b) => a - b);
  const result: (number | "...")[] = [];
  for (let i = 0; i < all.length; i++) {
    result.push(all[i]);
    if (i + 1 < all.length && (all[i + 1] as number) - (all[i] as number) > 1) result.push("...");
  }
  return result;
}

function SmartPagination({
  page, totalPages, total, pageSize, onPage,
}: { page: number; totalPages: number; total: number; pageSize: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return null;
  const safe = Math.min(page, totalPages);
  const nums = getPageNumbers(safe, totalPages);
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border/40">
      <p className="text-xs text-muted-foreground">
        Showing {(safe - 1) * pageSize + 1}–{Math.min(safe * pageSize, total)} of {total}
      </p>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(1)} title="First page">
          <ChevronFirst className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(safe - 1)}>
          <ChevronLeft className="w-3.5 h-3.5" />
        </Button>
        {nums.map((p, i) =>
          p === "..." ? (
            <span key={`e-${i}`} className="text-xs text-muted-foreground px-1 select-none">…</span>
          ) : (
            <Button
              key={p}
              variant={p === safe ? "default" : "ghost"}
              size="icon"
              className="h-7 w-7 text-xs"
              onClick={() => onPage(p as number)}
            >
              {p}
            </Button>
          )
        )}
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(safe + 1)}>
          <ChevronRight className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(totalPages)} title="Last page">
          <ChevronLast className="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  );
}

interface MatrixPoint { x: number; y: number; name: string; id: number; fill: string }

// Custom scatter tooltip — solid hex colours, always readable in dark mode
function MatrixTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload as MatrixPoint;
  return (
    <div style={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, padding: "8px 12px", boxShadow: "0 4px 16px rgba(0,0,0,0.5)" }}>
      <p style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 13, margin: 0 }}>{d.name}</p>
      <p style={{ color: "#94a3b8", fontSize: 11, margin: "4px 0 0" }}>Risk Score: <strong style={{ color: d.fill }}>{d.y}</strong></p>
      <p style={{ color: "#94a3b8", fontSize: 11, margin: "2px 0 0" }}>Business Impact: <strong style={{ color: "#e2e8f0" }}>{d.x}/10</strong></p>
    </div>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function TprmSupplyChainPage() {
  const { toast } = useToast();
  const search = useSearch();
  const params = new URLSearchParams(search);
  const vendorIdFilter = params.get("vendorId") ?? "";

  const [nodes, setNodes]         = useState<any[]>([]);
  const [stats, setStats]         = useState<any>(null);
  const [vendors, setVendors]     = useState<any[]>([]);
  const [total, setTotal]         = useState(0);
  const [loading, setLoading]     = useState(true);
  const [compPage, setCompPage]   = useState(1);
  const [suppPage, setSuppPage]   = useState(1);
  const [nodeType, setNodeType]   = useState("all");
  const [riskFilter, setRiskFilter] = useState("all");
  const [matrixData, setMatrixData] = useState<MatrixPoint[]>([]);
  const [activeTab, setActiveTab] = useState("overview");

  // Inline risk-level save state
  const [savingNode, setSavingNode] = useState<Record<number, boolean>>({});
  const [riskOverrides, setRiskOverrides] = useState<Record<number, string>>({});

  const loadComponents = useCallback((pg: number, nt: string, rl: string) => {
    const p = new URLSearchParams({ page: String(pg), limit: String(PAGE_SIZE_COMPONENTS) });
    if (nt !== "all") p.set("nodeType", nt);
    if (rl !== "all") p.set("riskLevel", rl);
    if (vendorIdFilter) p.set("vendorId", vendorIdFilter);
    return apiFetch<any>(`/api/tprm/supply-chain?${p}`);
  }, [vendorIdFilter]);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      loadComponents(compPage, nodeType, riskFilter),
      apiFetch<any>("/api/tprm/supply-chain/stats"),
      apiFetch<any>("/api/tprm/vendors?limit=500"),
    ]).then(([r, s, vr]) => {
      setNodes(r.nodes);
      setTotal(r.total);
      setStats(s);
      const vList = vr.vendors ?? [];
      setVendors(vList);
      const pts: MatrixPoint[] = vList.map((v: any) => ({
        x: Math.max(1, Math.min(10, (v.businessImpact ?? 5) + jitterX(v.id))),
        y: Math.max(0, Math.min(100, (v.riskScore ?? 0) + jitterY(v.id))),
        name: v.companyName,
        id:   v.id,
        fill: vendorDotColor(v.riskScore ?? 0),
      }));
      setMatrixData(pts);
    })
    .catch(() => {})
    .finally(() => setLoading(false));
  }, [compPage, nodeType, riskFilter, loadComponents]);

  useEffect(() => { load(); }, [compPage, nodeType, riskFilter]);

  // Reload only components when comp-page changes
  const reloadComponents = useCallback((pg: number, nt: string, rl: string) => {
    setLoading(true);
    loadComponents(pg, nt, rl)
      .then(r => { setNodes(r.nodes); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [loadComponents]);

  async function handleNodeRiskChange(node: any, newRisk: string) {
    setSavingNode(s => ({ ...s, [node.id]: true }));
    setRiskOverrides(o => ({ ...o, [node.id]: newRisk }));
    try {
      await apiFetch(`/api/tprm/supply-chain/${node.id}`, {
        method: "PATCH",
        body: JSON.stringify({ riskLevel: newRisk }),
      });
      toast({ title: "Risk level updated", description: `${node.name} → ${newRisk}` });
    } catch {
      setRiskOverrides(o => { const n = { ...o }; delete n[node.id]; return n; });
      toast({ title: "Update failed", description: "Could not update risk level", variant: "destructive" });
    } finally {
      setSavingNode(s => { const n = { ...s }; delete n[node.id]; return n; });
    }
  }

  // Suppliers KPI
  const avgCyberPosture = vendors.length > 0
    ? Math.round(vendors.reduce((s, v) => s + (v.riskScore ?? 0), 0) / vendors.length)
    : 0;

  // Pie data
  const riskDistData = [
    { name: "Critical (≥70)", value: vendors.filter(v => v.riskScore >= 70).length,                            fill: "#ef4444" },
    { name: "High (50–69)",   value: vendors.filter(v => v.riskScore >= 50 && v.riskScore < 70).length,        fill: "#f97316" },
    { name: "Medium (30–49)", value: vendors.filter(v => v.riskScore >= 30 && v.riskScore < 50).length,        fill: "#fbbf24" },
    { name: "Low (<30)",      value: vendors.filter(v => v.riskScore < 30).length,                             fill: "#22c55e" },
  ].filter(d => d.value > 0);

  // Suppliers pagination (client-side)
  const suppTotalPages = Math.max(1, Math.ceil(vendors.length / PAGE_SIZE_SUPPLIERS));
  const pagedVendors   = vendors.slice((suppPage - 1) * PAGE_SIZE_SUPPLIERS, suppPage * PAGE_SIZE_SUPPLIERS);

  // Components pagination (server-side)
  const compTotalPages = Math.max(1, Math.ceil(total / PAGE_SIZE_COMPONENTS));

  // Reset pages on filter change
  const changeNodeType = (v: string) => { setNodeType(v); setCompPage(1); reloadComponents(1, v, riskFilter); };
  const changeRisk     = (v: string) => { setRiskFilter(v); setCompPage(1); reloadComponents(1, nodeType, v); };
  const changeCompPage = (p: number) => { setCompPage(p); reloadComponents(p, nodeType, riskFilter); };

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Supply Chain</h1>
          <p className="text-muted-foreground text-sm">
            {vendors.length} supplier{vendors.length !== 1 ? "s" : ""} · {total} component{total !== 1 ? "s" : ""} tracked
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load}><RefreshCw className="w-4 h-4" /></Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="h-8 text-xs">
          <TabsTrigger value="overview"    className="text-xs">Overview</TabsTrigger>
          <TabsTrigger value="suppliers"   className="text-xs">Suppliers ({vendors.length})</TabsTrigger>
          <TabsTrigger value="components"  className="text-xs">Components ({total})</TabsTrigger>
        </TabsList>

        {/* ════════════ OVERVIEW TAB ════════════ */}
        <TabsContent value="overview" className="mt-4 space-y-5">

          {/* KPI cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card className="bg-card/60">
              <CardContent className="pt-3 pb-3">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">Cyber Posture</p>
                <p className={`text-2xl font-bold mt-0.5 ${cyberPostureColor(avgCyberPosture)}`}>{avgCyberPosture}/100</p>
                <p className="text-[10px] text-muted-foreground">Avg. rating across all suppliers</p>
              </CardContent>
            </Card>
            {[
              { label: "Total Components",               value: stats?.totalNodes ?? 0,                  color: "text-blue-400" },
              { label: "Critical Risk",                  value: stats?.criticalNodes ?? 0,               color: "text-red-400" },
              { label: "Suppliers w/ Critical Findings", value: stats?.vendorsWithCriticalFindings ?? 0, color: "text-yellow-400" },
            ].map(k => (
              <Card key={k.label} className="bg-card/60">
                <CardContent className="pt-3 pb-3">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">{k.label}</p>
                  <p className={`text-2xl font-bold mt-0.5 ${k.color}`}>{k.value}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Charts row */}
          <div className="grid md:grid-cols-2 gap-5">
            {/* Risk Rating Breakdown */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Risk Rating Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                {loading ? <Skeleton className="h-44" /> : riskDistData.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-8 text-center">No supplier data yet</p>
                ) : (
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie
                        data={riskDistData}
                        dataKey="value"
                        nameKey="name"
                        cx="50%"
                        cy="50%"
                        outerRadius={65}
                        label={({ percent }) => `${(percent * 100).toFixed(0)}%`}
                        labelLine={false}
                      >
                        {riskDistData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                      </Pie>
                      <Legend iconSize={9} wrapperStyle={{ fontSize: 10 }} />
                      <ReTooltip
                        contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8, fontSize: 12 }}
                        itemStyle={{ color: "#e2e8f0" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            {/* Risk × Business Impact Matrix — fixed: bigger, better margins, jitter */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Risk × Business Impact Matrix</CardTitle>
                <p className="text-xs text-muted-foreground">Upper-right = highest priority to remediate</p>
              </CardHeader>
              <CardContent className="pb-2">
                {loading ? <Skeleton className="h-[220px]" /> : matrixData.length === 0 ? (
                  <p className="text-sm text-muted-foreground py-8 text-center">
                    No vendor data — add vendors to populate
                  </p>
                ) : (
                  <div className="relative">
                    {/* Quadrant labels */}
                    <div className="absolute inset-0 pointer-events-none z-10">
                      <div className="absolute top-2 right-10 text-[9px] text-red-400/50 font-semibold tracking-wider uppercase">High Priority</div>
                      <div className="absolute bottom-8 left-10 text-[9px] text-green-400/50 font-semibold tracking-wider uppercase">Low Priority</div>
                    </div>
                    <ResponsiveContainer width="100%" height={240}>
                      <ScatterChart margin={{ top: 16, right: 20, bottom: 36, left: 40 }}>
                        {/* Shaded quadrant backgrounds */}
                        <defs>
                          <linearGradient id="highPriority" x1="0" y1="0" x2="1" y2="1">
                            <stop offset="0%" stopColor="#ef4444" stopOpacity={0.06} />
                            <stop offset="100%" stopColor="#ef4444" stopOpacity={0.01} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" opacity={0.08} />
                        <XAxis
                          dataKey="x"
                          type="number"
                          domain={[0, 11]}
                          tickCount={6}
                          tick={{ fontSize: 10, fill: "#94a3b8" }}
                          axisLine={{ stroke: "#334155" }}
                          tickLine={false}
                        >
                          <Label
                            value="Business Impact (1–10)"
                            offset={-18}
                            position="insideBottom"
                            style={{ fontSize: 10, fill: "#64748b" }}
                          />
                        </XAxis>
                        <YAxis
                          dataKey="y"
                          type="number"
                          domain={[0, 100]}
                          tick={{ fontSize: 10, fill: "#94a3b8" }}
                          axisLine={{ stroke: "#334155" }}
                          tickLine={false}
                          width={36}
                        >
                          <Label
                            value="Risk Score"
                            angle={-90}
                            position="insideLeft"
                            offset={10}
                            style={{ fontSize: 10, fill: "#64748b" }}
                          />
                        </YAxis>
                        {/* Mid-point reference lines */}
                        <ReferenceLine x={5.5} stroke="#475569" strokeDasharray="4 4" opacity={0.5} />
                        <ReferenceLine y={50}  stroke="#475569" strokeDasharray="4 4" opacity={0.5} />
                        <ReTooltip content={<MatrixTooltip />} cursor={false} />
                        <Scatter
                          data={matrixData}
                          shape={(props: any) => {
                            const { cx, cy, payload } = props;
                            return (
                              <g>
                                <circle
                                  cx={cx} cy={cy} r={6}
                                  fill={payload.fill}
                                  fillOpacity={0.85}
                                  stroke={payload.fill}
                                  strokeWidth={1.5}
                                  strokeOpacity={0.4}
                                />
                              </g>
                            );
                          }}
                        />
                      </ScatterChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Suppliers with Critical Findings */}
          {(stats?.criticalVendors?.length ?? 0) > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-red-400" />Suppliers with Critical Findings
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {(stats.criticalVendors ?? []).map((v: any) => (
                    <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
                      <Badge variant="outline" className="text-[10px] border-red-500/40 text-red-400 cursor-pointer hover:bg-red-500/10">
                        {v.companyName}
                      </Badge>
                    </Link>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ════════════ SUPPLIERS TAB ════════════ */}
        <TabsContent value="suppliers" className="mt-4">
          {loading ? (
            <div className="space-y-2">{Array(6).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
          ) : vendors.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-14 text-center">
                <Package className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm font-medium">No suppliers yet</p>
                <p className="text-xs text-muted-foreground mt-1">Add vendors to see them here as supply chain suppliers</p>
                <Button size="sm" className="mt-4" asChild><Link href="/tprm/vendors/new">Add Supplier</Link></Button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm min-w-[860px]">
                    <thead>
                      <tr className="border-b border-border/50">
                        {["Company Name", "Status", "Business Impact", "Evaluation Type", "Cyber Posture", "Risk Rating", "Date Added", ""].map(h => (
                          <th key={h} className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {pagedVendors.map((v: any) => (
                        <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              {v.logoUrl
                                ? <img src={v.logoUrl} alt="" className="w-6 h-6 rounded bg-white/10 object-contain p-0.5 shrink-0" />
                                : <div className="w-6 h-6 rounded bg-muted flex items-center justify-center text-[10px] font-bold shrink-0">{v.companyName[0]}</div>
                              }
                              <div>
                                <p className="text-sm font-medium truncate max-w-[160px]">{v.companyName}</p>
                                <p className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                                  <Globe className="w-2.5 h-2.5" />{v.domain}
                                </p>
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge variant={v.status === "active" ? "default" : "secondary"} className="text-[10px]">{v.status}</Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              <Progress value={(v.businessImpact ?? 5) * 10} className="h-1 w-16" />
                              <span className="text-xs font-medium">{v.businessImpact ?? 5}/10</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge variant="outline" className="text-[10px]">
                              {v.assessmentType === "continuous" ? "Continuous" : "One-Time"}
                            </Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              <Progress value={v.riskScore} className="h-1.5 w-20" />
                              <span className={`text-xs font-semibold ${cyberPostureColor(v.riskScore)}`}>{v.riskScore}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">{gradeBadgeSm(v.riskGrade)}</td>
                          <td className="px-4 py-2.5 text-xs text-muted-foreground whitespace-nowrap">
                            {v.createdAt ? new Date(v.createdAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) : "—"}
                          </td>
                          <td className="px-4 py-2.5">
                            <Button size="sm" variant="ghost" className="h-6 text-xs" asChild>
                              <Link href={`/tprm/vendors/${v.id}`}><Eye className="w-3 h-3 mr-1" />View</Link>
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <SmartPagination
                  page={suppPage}
                  totalPages={suppTotalPages}
                  total={vendors.length}
                  pageSize={PAGE_SIZE_SUPPLIERS}
                  onPage={p => setSuppPage(p)}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ════════════ COMPONENTS TAB ════════════ */}
        <TabsContent value="components" className="mt-4 space-y-4">

          {/* Filters */}
          <div className="flex flex-wrap gap-2">
            <Select value={nodeType} onValueChange={changeNodeType}>
              <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="Node Type" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="software">Software</SelectItem>
                <SelectItem value="saas">SaaS</SelectItem>
                <SelectItem value="api">API</SelectItem>
                <SelectItem value="cdn">CDN</SelectItem>
                <SelectItem value="infra">Infrastructure</SelectItem>
              </SelectContent>
            </Select>
            <Select value={riskFilter} onValueChange={changeRisk}>
              <SelectTrigger className="w-32 h-8 text-sm"><SelectValue placeholder="Risk" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Risk</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {loading ? (
            <div className="space-y-2">{Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
          ) : nodes.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-14 text-center">
                <Package className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                <p className="text-sm font-medium">No supply chain components</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Upload an SBOM file in a vendor's detail page, or run a vendor scan to auto-discover components.
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm min-w-[860px]">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Component</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Version</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Type</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">License</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Supplier</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Risk Level</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">CVEs</th>
                      </tr>
                    </thead>
                    <tbody>
                      {nodes.map((n: any) => {
                        const currentRisk = riskOverrides[n.id] ?? n.riskLevel;
                        const isSaving    = savingNode[n.id] ?? false;
                        // Supplier: use component supplier → vendor name fallback
                        const supplierDisplay = n.supplier || n.vendorName || "—";
                        // Version: only available for SBOM-uploaded nodes
                        const versionDisplay  = n.version || (n.sbomUploadId ? "—" : <span className="text-muted-foreground/40 text-[10px]">scan-based</span>);
                        const licenseDisplay  = n.license || (n.sbomUploadId ? "—" : <span className="text-muted-foreground/40 text-[10px]">scan-based</span>);
                        return (
                          <tr key={n.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                            <td className="px-4 py-2">
                              <p className="font-medium truncate max-w-[200px]">{n.name}</p>
                              {n.purl && <p className="text-[10px] text-muted-foreground font-mono truncate max-w-[200px]">{n.purl}</p>}
                            </td>
                            <td className="px-4 py-2 text-muted-foreground font-mono text-xs">{versionDisplay}</td>
                            <td className="px-4 py-2">
                              <Badge variant="outline" className="text-[10px]">{n.nodeType}</Badge>
                            </td>
                            <td className="px-4 py-2 text-xs text-muted-foreground">{licenseDisplay}</td>
                            <td className="px-4 py-2 text-xs text-muted-foreground">{supplierDisplay}</td>

                            {/* ── Inline Risk Level Editor ── */}
                            <td className="px-4 py-2" onClick={e => e.stopPropagation()}>
                              {isSaving ? (
                                <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                  <Loader2 className="w-3 h-3 animate-spin" />Saving…
                                </span>
                              ) : (
                                <select
                                  value={currentRisk}
                                  onChange={e => handleNodeRiskChange(n, e.target.value)}
                                  className={`h-6 text-[11px] font-semibold px-1.5 rounded border cursor-pointer
                                    ${currentRisk === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                                      currentRisk === "high"     ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                                      currentRisk === "medium"   ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                                      "bg-blue-500/15 text-blue-400 border-blue-500/30"}`}
                                >
                                  <option value="critical">Critical</option>
                                  <option value="high">High</option>
                                  <option value="medium">Medium</option>
                                  <option value="low">Low</option>
                                </select>
                              )}
                            </td>

                            <td className="px-4 py-2">
                              {Array.isArray(n.vulnerabilities) && n.vulnerabilities.length > 0 ? (
                                <span className="flex items-center gap-1 text-xs text-red-400 font-medium">
                                  <AlertTriangle className="w-3 h-3" />{n.vulnerabilities.length}
                                </span>
                              ) : (
                                <span className="text-xs text-muted-foreground">0</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <SmartPagination
                  page={compPage}
                  totalPages={compTotalPages}
                  total={total}
                  pageSize={PAGE_SIZE_COMPONENTS}
                  onPage={changeCompPage}
                />
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
