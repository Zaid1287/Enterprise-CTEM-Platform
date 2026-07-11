import { useEffect, useState } from "react";
import { useSearch, Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RefreshCw, Search, Package, AlertTriangle } from "lucide-react";

function riskBadge(level: string) {
  const m: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border-red-500/30", high: "bg-orange-500/20 text-orange-400 border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border-blue-500/30", none: "bg-slate-500/20 text-slate-400 border-slate-500/30" };
  return <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-semibold border ${m[level] ?? m.low}`}>{level}</span>;
}

export default function TprmSupplyChainPage() {
  const search = useSearch();
  const params = new URLSearchParams(search);
  const vendorIdFilter = params.get("vendorId") ?? "";

  const [nodes, setNodes]     = useState<any[]>([]);
  const [stats, setStats]     = useState<any>(null);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(true);
  const [page, setPage]       = useState(1);
  const [nodeType, setNodeType] = useState("all");
  const [riskLevel, setRiskLevel] = useState("all");

  const load = () => {
    setLoading(true);
    const p = new URLSearchParams({ page: String(page), limit: "100" });
    if (nodeType !== "all") p.set("nodeType", nodeType);
    if (riskLevel !== "all") p.set("riskLevel", riskLevel);
    if (vendorIdFilter) p.set("vendorId", vendorIdFilter);
    Promise.all([
      apiFetch<any>(`/api/tprm/supply-chain?${p}`),
      apiFetch<any>("/api/tprm/supply-chain/stats"),
    ]).then(([r, s]) => { setNodes(r.nodes); setTotal(r.total); setStats(s); })
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
            { label: "Total Components", value: stats.totalNodes, color: "text-blue-400" },
            { label: "Critical Risk", value: stats.criticalNodes, color: "text-red-400" },
            { label: "High Risk", value: stats.highNodes, color: "text-orange-400" },
            { label: "Vendors w/ Critical Findings", value: stats.vendorsWithCriticalFindings, color: "text-yellow-400" },
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

      {/* Table */}
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
