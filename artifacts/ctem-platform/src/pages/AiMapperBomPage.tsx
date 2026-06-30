import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ClipboardList, Loader2, TrendingUp } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";

const RISK_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

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

interface ProtocolDist {
  protocol: string;
  count: number;
}

export default function AiMapperBomPage() {
  const { data, isLoading } = useQuery<{ bom: BomItem[]; protocolDistribution: ProtocolDist[] }>({
    queryKey: ["ai-mapper-bom"],
    queryFn: () => apiFetch("/api/ai-mapper/bom"),
  });

  const bom  = data?.bom  ?? [];
  const dist = (data?.protocolDistribution ?? []).map(d => ({
    name:  d.protocol ?? "unknown",
    value: Number(d.count),
    fill:  PROTOCOL_COLOR[d.protocol ?? ""] ?? "#64748b",
  }));

  const riskDist = ["critical", "high", "medium", "low"].map(lvl => ({
    name:  lvl.charAt(0).toUpperCase() + lvl.slice(1),
    count: bom.filter(b => b.highestRiskLevel === lvl).length,
    fill:  RISK_COLOR[lvl],
  })).filter(d => d.count > 0);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">AI Bill of Materials</h1>
        <p className="text-sm text-muted-foreground">Inventory of all AI frameworks and protocols discovered in your attack surface</p>
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
            <Card>
              <CardHeader><CardTitle className="text-sm">Protocol Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={dist} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                      {dist.map((d, i) => <Cell key={i} fill={d.fill} />)}
                    </Pie>
                    <Tooltip formatter={(v: number) => [`${v} endpoints`, "Count"]} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Risk distribution bar */}
            <Card>
              <CardHeader><CardTitle className="text-sm">Risk by Framework</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={riskDist} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" tick={{ fill: "#94a3b8", fontSize: 11 }} />
                    <YAxis type="category" dataKey="name" tick={{ fill: "#94a3b8", fontSize: 11 }} width={60} />
                    <Tooltip />
                    <Bar dataKey="count">
                      {riskDist.map((d, i) => <Cell key={i} fill={d.fill} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* BOM table */}
          <Card>
            <CardHeader><CardTitle className="text-sm">Framework Inventory</CardTitle></CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-muted/40 text-muted-foreground text-xs uppercase tracking-wide">
                    <th className="text-left px-5 py-2.5">Framework</th>
                    <th className="text-left px-5 py-2.5">Endpoints</th>
                    <th className="text-left px-5 py-2.5">Highest Risk</th>
                    <th className="text-left px-5 py-2.5">Last Seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {bom.map(b => (
                    <tr key={b.framework} className="hover:bg-muted/20">
                      <td className="px-5 py-3 font-medium">{b.framework}</td>
                      <td className="px-5 py-3 font-mono">{b.endpointCount}</td>
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
                      <td className="px-5 py-3 text-xs text-muted-foreground">
                        {b.lastSeenAt ? new Date(b.lastSeenAt).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
