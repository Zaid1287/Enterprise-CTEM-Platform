import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ClipboardList, Loader2, Download, ArrowUp, ArrowDown, ArrowUpDown } from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
  PieChart, Pie,
} from "recharts";

const RISK_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};
const RISK_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const PROTOCOL_COLOR: Record<string, string> = {
  mcp:       "#a855f7",
  ollama:    "#3b82f6",
  vllm:      "#06b6d4",
  gradio:    "#ec4899",
  comfyui:   "#f59e0b",
  langserve: "#10b981",
  litellm:   "#6366f1",
  generic:   "#64748b",
};

interface BomItem {
  framework: string;
  endpointCount: number;
  highestRiskLevel: string;
  uniqueModels?: string[];
  uniqueTools?: string[];
  firstSeenAt?: string;
  lastSeenAt?: string;
}
interface ProtocolDist { protocol: string; count: number; }

type SortCol = "framework" | "endpointCount" | "highestRiskLevel" | "models" | "tools" | "lastSeenAt";
type SortDir = "asc" | "desc";

function SortBtn({ col, cur, dir, onClick }: { col: SortCol; cur: SortCol; dir: SortDir; onClick: () => void }) {
  return (
    <button className="ml-1 inline-flex items-center" onClick={onClick}>
      {col === cur
        ? dir === "asc" ? <ArrowUp className="w-3 h-3 text-violet-400" /> : <ArrowDown className="w-3 h-3 text-violet-400" />
        : <ArrowUpDown className="w-3 h-3 text-muted-foreground/40" />}
    </button>
  );
}

function exportCsv(bom: BomItem[]) {
  const header = ["Framework", "Endpoints", "Highest Risk", "Unique Models", "Unique Tools", "First Seen", "Last Seen"];
  const rows = bom.map(b => [
    b.framework,
    b.endpointCount,
    b.highestRiskLevel,
    (b.uniqueModels ?? []).length,
    (b.uniqueTools ?? []).length,
    b.firstSeenAt ? new Date(b.firstSeenAt).toLocaleDateString() : "",
    b.lastSeenAt  ? new Date(b.lastSeenAt).toLocaleDateString()  : "",
  ]);
  const csv = [header, ...rows].map(r => r.map(c => `"${c}"`).join(",")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "ai-bom.csv";
  a.click();
}

export default function AiMapperBomPage() {
  const [sortCol, setSortCol] = useState<SortCol>("highestRiskLevel");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const { data, isLoading } = useQuery<{ bom: BomItem[]; protocolDistribution: ProtocolDist[] }>({
    queryKey: ["ai-mapper-bom"],
    queryFn: () => apiFetch("/api/ai-mapper/bom"),
  });

  const bom = data?.bom ?? [];

  const dist = (data?.protocolDistribution ?? []).map(d => ({
    name:  d.protocol ?? "unknown",
    value: Number(d.count),
    fill:  PROTOCOL_COLOR[d.protocol ?? ""] ?? "#64748b",
  }));

  const top10 = [...bom]
    .sort((a, b) => (RISK_ORDER[b.highestRiskLevel] ?? 0) - (RISK_ORDER[a.highestRiskLevel] ?? 0) || b.endpointCount - a.endpointCount)
    .slice(0, 10)
    .map(b => ({ name: b.framework, count: b.endpointCount, fill: RISK_COLOR[b.highestRiskLevel] ?? "#64748b" }));

  function toggleSort(col: SortCol) {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("desc"); }
  }

  const sorted = [...bom].sort((a, b) => {
    let va: number | string = 0;
    let vb: number | string = 0;
    if (sortCol === "framework")       { va = a.framework; vb = b.framework; }
    if (sortCol === "endpointCount")   { va = a.endpointCount; vb = b.endpointCount; }
    if (sortCol === "highestRiskLevel"){ va = RISK_ORDER[a.highestRiskLevel] ?? 0; vb = RISK_ORDER[b.highestRiskLevel] ?? 0; }
    if (sortCol === "models")          { va = (a.uniqueModels ?? []).length; vb = (b.uniqueModels ?? []).length; }
    if (sortCol === "tools")           { va = (a.uniqueTools ?? []).length; vb = (b.uniqueTools ?? []).length; }
    if (sortCol === "lastSeenAt")      { va = a.lastSeenAt ?? ""; vb = b.lastSeenAt ?? ""; }
    if (typeof va === "string" && typeof vb === "string") {
      return sortDir === "asc" ? va.localeCompare(vb) : vb.localeCompare(va);
    }
    return sortDir === "asc" ? (va as number) - (vb as number) : (vb as number) - (va as number);
  });

  return (
    <div className="p-6 space-y-6 w-full">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold">AI Bill of Materials</h1>
          <p className="text-sm text-muted-foreground">Inventory of all AI frameworks and protocols discovered in your attack surface</p>
        </div>
        {bom.length > 0 && (
          <Button variant="outline" size="sm" onClick={() => exportCsv(sorted)}>
            <Download className="w-4 h-4 mr-2" /> Export CSV
          </Button>
        )}
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : bom.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <ClipboardList className="w-10 h-10 mx-auto mb-3 text-muted-foreground opacity-40" />
            <p className="font-medium">No frameworks discovered yet</p>
            <p className="text-sm text-muted-foreground mt-1">Run an AI surface scan to build your AI BOM</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6">
            {/* Protocol distribution pie */}
            {dist.length > 0 && (
              <Card>
                <CardHeader><CardTitle className="text-sm">Protocol Distribution</CardTitle></CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie data={dist} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                        {dist.map((d, i) => <Cell key={i} fill={d.fill} />)}
                      </Pie>
                      <Tooltip formatter={(v: number) => [`${v} endpoints`, "Count"]} />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}

            {/* Top 10 riskiest frameworks — horizontal bar */}
            {top10.length > 0 && (
              <Card>
                <CardHeader><CardTitle className="text-sm">Top 10 Riskiest Frameworks</CardTitle></CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={top10} layout="vertical" margin={{ left: 8, right: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} allowDecimals={false} />
                      <YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} width={72} />
                      <Tooltip formatter={(v: number) => [`${v} endpoints`, "Endpoints"]} />
                      <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                        {top10.map((d, i) => <Cell key={i} fill={d.fill} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}
          </div>

          {/* BOM table */}
          <Card>
            <CardHeader><CardTitle className="text-sm">Framework Inventory ({bom.length})</CardTitle></CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-muted/40 text-muted-foreground text-xs uppercase tracking-wide">
                      <th className="text-left px-5 py-2.5">
                        Framework
                        <SortBtn col="framework" cur={sortCol} dir={sortDir} onClick={() => toggleSort("framework")} />
                      </th>
                      <th className="text-right px-5 py-2.5">
                        Endpoints
                        <SortBtn col="endpointCount" cur={sortCol} dir={sortDir} onClick={() => toggleSort("endpointCount")} />
                      </th>
                      <th className="text-left px-5 py-2.5">
                        Highest Risk
                        <SortBtn col="highestRiskLevel" cur={sortCol} dir={sortDir} onClick={() => toggleSort("highestRiskLevel")} />
                      </th>
                      <th className="text-right px-5 py-2.5">
                        Models
                        <SortBtn col="models" cur={sortCol} dir={sortDir} onClick={() => toggleSort("models")} />
                      </th>
                      <th className="text-right px-5 py-2.5">
                        Tools
                        <SortBtn col="tools" cur={sortCol} dir={sortDir} onClick={() => toggleSort("tools")} />
                      </th>
                      <th className="text-left px-5 py-2.5">
                        First Seen
                        <SortBtn col="lastSeenAt" cur={sortCol} dir={sortDir} onClick={() => toggleSort("lastSeenAt")} />
                      </th>
                      <th className="text-left px-5 py-2.5">Last Seen</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {sorted.map(b => (
                      <tr key={b.framework} className="hover:bg-muted/20">
                        <td className="px-5 py-3 font-medium">{b.framework}</td>
                        <td className="px-5 py-3 font-mono text-right">{b.endpointCount}</td>
                        <td className="px-5 py-3">
                          <Badge className={`text-xs border ${
                            b.highestRiskLevel === "critical" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                            b.highestRiskLevel === "high"     ? "bg-orange-500/20 text-orange-400 border-orange-500/30" :
                            b.highestRiskLevel === "medium"   ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" :
                            "bg-green-500/20 text-green-400 border-green-500/30"
                          }`}>
                            {b.highestRiskLevel}
                          </Badge>
                        </td>
                        <td className="px-5 py-3 font-mono text-right text-muted-foreground">
                          {(b.uniqueModels ?? []).length > 0
                            ? <span title={(b.uniqueModels ?? []).join(", ")}>{b.uniqueModels!.length}</span>
                            : <span className="opacity-30">—</span>}
                        </td>
                        <td className="px-5 py-3 font-mono text-right text-muted-foreground">
                          {(b.uniqueTools ?? []).length > 0
                            ? <span title={(b.uniqueTools ?? []).join(", ")}>{b.uniqueTools!.length}</span>
                            : <span className="opacity-30">—</span>}
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground">
                          {b.firstSeenAt ? new Date(b.firstSeenAt).toLocaleDateString() : "—"}
                        </td>
                        <td className="px-5 py-3 text-xs text-muted-foreground">
                          {b.lastSeenAt ? new Date(b.lastSeenAt).toLocaleDateString() : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
