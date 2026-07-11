import { useEffect, useState } from "react";
import { useSearch, Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RefreshCw, Package, AlertTriangle } from "lucide-react";
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Label,
} from "recharts";

function riskBadge(level: string) {
  const m: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border-red-500/30", high: "bg-orange-500/20 text-orange-400 border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border-blue-500/30", none: "bg-slate-500/20 text-slate-400 border-slate-500/30" };
  return <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold border ${m[level] ?? m.low}`}>{level}</span>;
}

function vendorDotColor(riskScore: number): string {
  if (riskScore >= 70) return "#ef4444";
  if (riskScore >= 50) return "#f97316";
  if (riskScore >= 30) return "#fbbf24";
  return "#22c55e";
}

interface MatrixPoint { x: number; y: number; name: string; id: number; fill: string }

export default function TprmSupplyChainPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const vendorIdFilter = params.get("vendorId") ?? "";

  const [nodes, setNodes]         = useState<any[]>([]);
  const [stats, setStats]         = useState<any>(null);
  const [total, setTotal]         = useState(0);
  const [loading, setLoading]     = useState(true);
  const [page, setPage]           = useState(1);
  const [nodeType, setNodeType]   = useState("all");
  const [riskLevel, setRiskLevel] = useState("all");
  const [matrixData, setMatrixData] = useState<MatrixPoint[]>([]);

  const load = () => {
    setLoading(true);
    const p = new URLSearchParams({ page: String(page), limit: "100" });
    if (nodeType !== "all") p.set("nodeType", nodeType);
    if (riskLevel !== "all") p.set("riskLevel", riskLevel);
    if (vendorIdFilter) p.set("vendorId", vendorIdFilter);
    Promise.all([
      apiFetch<any>(`/api/tprm/supply-chain?${p}`),
      apiFetch<any>("/api/tprm/supply-chain/stats"),
      apiFetch<any>("/api/tprm/vendors?limit=200"),
    ]).then(([r, s, vr]) => {
      setNodes(r.nodes);
      setTotal(r.total);
      setStats(s);
      const pts: MatrixPoint[] = (vr.vendors ?? []).map((v: any) => ({
        x: v.businessImpact ?? 5,
        y: v.riskScore ?? 0,
        name: v.companyName,
        id: v.id,
        fill: vendorDotColor(v.riskScore ?? 0),
      }));
      setMatrixData(pts);
    })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [page, nodeType, riskLevel]);

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Supply Chain</h1>
          <p className="text-muted-foreground text-sm">{total} component{total !== 1 ? "s" : ""} tracked</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => { setPage(1); load(); }}><RefreshCw className="w-4 h-4" /></Button>
      </div>

      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: "Total Components",              value: stats.totalNodes,                   color: "text-blue-400" },
            { label: "Critical Risk",                 value: stats.criticalNodes,                color: "text-red-400" },
            { label: "High Risk",                     value: stats.highNodes,                    color: "text-orange-400" },
            { label: "Vendors w/ Critical Findings",  value: stats.vendorsWithCriticalFindings,  color: "text-yellow-400" },
          ].map(k => (
            <Card key={k.label} className="bg-card/60">
              <CardContent className="pt-3 pb-3">
                <p className="text-xs text-muted-foreground">{k.label}</p>
                <p className={`text-xl font-bold mt-0.5 ${k.color}`}>{k.value}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Risk-by-Business-Impact Matrix */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Risk × Business Impact Matrix</CardTitle>
          <p className="text-xs text-muted-foreground">Each point = one vendor. Upper-right quadrant = highest priority to remediate.</p>
        </CardHeader>
        <CardContent>
          {loading ? <Skeleton className="h-52" /> : matrixData.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No vendor data — add vendors to populate this matrix</p>
          ) : (
            <div className="relative">
              {/* Quadrant labels */}
              <div className="absolute inset-0 pointer-events-none z-10">
                <div className="absolute top-1 right-12 text-[10px] text-red-400/60 font-medium">HIGH PRIORITY</div>
                <div className="absolute bottom-6 left-10 text-[10px] text-green-400/60 font-medium">LOW PRIORITY</div>
              </div>
              <ResponsiveContainer width="100%" height={220}>
                <ScatterChart margin={{ top: 10, right: 20, bottom: 30, left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                  <XAxis dataKey="x" type="number" domain={[0, 11]} tickCount={6} tick={{ fontSize: 10 }}>
                    <Label value="Business Impact (1–10)" offset={-5} position="insideBottom" style={{ fontSize: 10, fill: "#6b7280" }} />
                  </XAxis>
                  <YAxis dataKey="y" type="number" domain={[0, 100]} tick={{ fontSize: 10 }} width={28}>
                    <Label value="Risk Score" angle={-90} position="insideLeft" style={{ fontSize: 10, fill: "#6b7280" }} />
                  </YAxis>
                  <ReferenceLine x={5.5} stroke="#6b7280" strokeDasharray="4 4" opacity={0.4} />
                  <ReferenceLine y={50} stroke="#6b7280" strokeDasharray="4 4" opacity={0.4} />
                  <Tooltip
                    cursor={{ strokeDasharray: "3 3" }}
                    content={({ payload }) => {
                      if (!payload?.length) return null;
                      const d = payload[0].payload as MatrixPoint;
                      return (
                        <div className="bg-card border border-border rounded p-2 text-xs">
                          <p className="font-semibold">{d.name}</p>
                          <p className="text-muted-foreground">Risk: {d.y} · Impact: {d.x}</p>
                        </div>
                      );
                    }}
                  />
                  <Scatter
                    data={matrixData}
                    shape={(props: any) => {
                      const { cx, cy, payload } = props;
                      return <circle cx={cx} cy={cy} r={6} fill={payload.fill} fillOpacity={0.8} stroke={payload.fill} strokeWidth={1} />;
                    }}
                  />
                </ScatterChart>
              </ResponsiveContainer>
              <div className="flex items-center gap-4 mt-1 justify-end text-[10px] text-muted-foreground">
                {[["#22c55e","Low (<30)"],["#fbbf24","Medium (30–49)"],["#f97316","High (50–69)"],["#ef4444","Critical (≥70)"]].map(([c,l]) => (
                  <span key={l} className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: c }} />{l}</span>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Suppliers with Critical Findings */}
      {stats?.criticalVendors?.length > 0 && (
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
                  <Badge variant="outline" className="text-[10px] border-red-500/40 text-red-400 cursor-pointer hover:bg-red-500/10">{v.companyName}</Badge>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <Select value={nodeType} onValueChange={v => { setNodeType(v); setPage(1); }}>
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
        <Select value={riskLevel} onValueChange={v => { setRiskLevel(v); setPage(1); }}>
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

      {/* Component Table */}
      {loading ? (
        <div className="space-y-2">{Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : nodes.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-14 text-center">
            <Package className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm font-medium">No supply chain components</p>
            <p className="text-xs text-muted-foreground mt-1">Upload an SBOM file in a vendor's detail page to populate this view</p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Component</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Version</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Type</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">License</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Supplier</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Risk</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">CVEs</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map(n => (
                  <tr key={n.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                    <td className="px-4 py-2">
                      <p className="font-medium truncate max-w-[200px]">{n.name}</p>
                      {n.purl && <p className="text-[10px] text-muted-foreground font-mono truncate max-w-[200px]">{n.purl}</p>}
                    </td>
                    <td className="px-4 py-2 text-muted-foreground font-mono text-xs">{n.version ?? "—"}</td>
                    <td className="px-4 py-2"><Badge variant="outline" className="text-[10px]">{n.nodeType}</Badge></td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{n.license ?? "—"}</td>
                    <td className="px-4 py-2 text-xs text-muted-foreground">{n.supplier ?? "—"}</td>
                    <td className="px-4 py-2">{riskBadge(n.riskLevel)}</td>
                    <td className="px-4 py-2">
                      {Array.isArray(n.vulnerabilities) && n.vulnerabilities.length > 0 ? (
                        <span className="flex items-center gap-1 text-xs text-red-400 font-medium">
                          <AlertTriangle className="w-3 h-3" />{n.vulnerabilities.length}
                        </span>
                      ) : <span className="text-xs text-muted-foreground">0</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      )}

      {total > 100 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Showing {Math.min((page-1)*100+1, total)}–{Math.min(page*100, total)} of {total}</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p-1)}>Previous</Button>
            <Button variant="outline" size="sm" disabled={page*100 >= total} onClick={() => setPage(p => p+1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
