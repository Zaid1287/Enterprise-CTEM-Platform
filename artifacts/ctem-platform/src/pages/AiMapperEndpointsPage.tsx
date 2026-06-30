import { useState, useCallback } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import { Search, Filter, ChevronLeft, ChevronRight, Loader2, Crosshair } from "lucide-react";

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/20 text-green-400 border-green-500/30",
};

const PROTOCOL_COLORS: Record<string, string> = {
  mcp:       "bg-purple-500/20 text-purple-400",
  ollama:    "bg-blue-500/20 text-blue-400",
  vllm:      "bg-cyan-500/20 text-cyan-400",
  gradio:    "bg-pink-500/20 text-pink-400",
  comfyui:   "bg-amber-500/20 text-amber-400",
  langserve: "bg-emerald-500/20 text-emerald-400",
  litellm:   "bg-indigo-500/20 text-indigo-400",
  generic:   "bg-slate-500/20 text-slate-400",
};

interface AiEndpoint {
  id: number; ip: string; port: number; hostname?: string; url: string;
  protocol: string; framework?: string; authStatus: string;
  riskScore: number; riskLevel: string; country?: string; org?: string; city?: string;
  models?: string[]; tools?: { name: string }[];
  systemPromptLeaked: boolean; corsPolicy?: string; hasTls: boolean; firstSeenAt: string;
}

export default function AiMapperEndpointsPage() {
  const [, navigate] = useLocation();
  const [q, setQ]   = useState("");
  const [sort, setSort]   = useState("riskScore");
  const [order, setOrder] = useState("desc");
  const [page, setPage]   = useState(1);
  const LIMIT = 25;

  const { data, isLoading } = useQuery<{ data: AiEndpoint[]; total: number; page: number; limit: number }>({
    queryKey: ["ai-mapper-endpoints", q, sort, order, page],
    queryFn: () => apiFetch(`/api/ai-mapper/endpoints?q=${encodeURIComponent(q)}&sort=${sort}&order=${order}&page=${page}&limit=${LIMIT}`),
    placeholderData: prev => prev,
  });

  const endpoints = data?.data ?? [];
  const total     = data?.total ?? 0;
  const pages     = Math.ceil(total / LIMIT);

  return (
    <div className="p-6 space-y-5 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">AI Endpoints</h1>
        <p className="text-sm text-muted-foreground">{total.toLocaleString()} exposed AI endpoints discovered</p>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={q}
            onChange={e => { setQ(e.target.value); setPage(1); }}
            placeholder='Search or filter… e.g. protocol:ollama auth:none risk:critical'
            className="pl-9 text-sm font-mono"
          />
        </div>
        <Select value={sort} onValueChange={v => setSort(v)}>
          <SelectTrigger className="w-36">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="riskScore">Risk Score</SelectItem>
            <SelectItem value="firstSeenAt">First Seen</SelectItem>
          </SelectContent>
        </Select>
        <Select value={order} onValueChange={v => setOrder(v)}>
          <SelectTrigger className="w-24">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="desc">Desc</SelectItem>
            <SelectItem value="asc">Asc</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Quick-filter chips */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: "No Auth",   query: "auth:none" },
          { label: "Critical",  query: "risk:critical" },
          { label: "Prompt Leaked", query: "has:system_prompt" },
          { label: "Ollama",    query: "protocol:ollama" },
          { label: "MCP",       query: "protocol:mcp" },
          { label: "Open CORS", query: "auth:none risk:high" },
        ].map(chip => (
          <button
            key={chip.query}
            onClick={() => { setQ(chip.query); setPage(1); }}
            className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${
              q === chip.query ? "border-primary bg-primary/10 text-primary" : "border-border hover:border-primary/50 text-muted-foreground hover:text-foreground"
            }`}
          >
            {chip.label}
          </button>
        ))}
        {q && <button onClick={() => { setQ(""); setPage(1); }} className="px-2.5 py-1 text-xs rounded-full border border-border text-muted-foreground hover:text-foreground">✕ Clear</button>}
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
        </div>
      ) : endpoints.length === 0 ? (
        <Card>
          <CardContent className="py-16 text-center">
            <Crosshair className="w-10 h-10 mx-auto mb-3 text-muted-foreground opacity-40" />
            <p className="font-medium">No endpoints found</p>
            <p className="text-sm text-muted-foreground mt-1">Run an AI surface scan to discover exposed AI endpoints</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="rounded-lg border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-muted/40 text-muted-foreground text-xs uppercase tracking-wide">
                  <th className="text-left px-4 py-2.5">Risk</th>
                  <th className="text-left px-4 py-2.5">Endpoint</th>
                  <th className="text-left px-4 py-2.5">Protocol</th>
                  <th className="text-left px-4 py-2.5">Auth</th>
                  <th className="text-left px-4 py-2.5">Location</th>
                  <th className="text-left px-4 py-2.5">Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {endpoints.map(ep => (
                  <tr
                    key={ep.id}
                    className="hover:bg-muted/30 cursor-pointer transition-colors"
                    onClick={() => navigate(`/ai-mapper/endpoints/${ep.id}`)}
                  >
                    <td className="px-4 py-3">
                      <RiskScoreGauge score={ep.riskScore} size="sm" />
                    </td>
                    <td className="px-4 py-3">
                      <p className="font-mono font-medium">{ep.ip}:{ep.port}</p>
                      {ep.hostname && <p className="text-xs text-muted-foreground truncate max-w-48">{ep.hostname}</p>}
                      {ep.framework && <p className="text-xs text-muted-foreground">{ep.framework}</p>}
                    </td>
                    <td className="px-4 py-3">
                      <Badge className={`text-xs ${PROTOCOL_COLORS[ep.protocol] ?? PROTOCOL_COLORS.generic}`}>
                        {ep.protocol}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      {ep.authStatus === "none"
                        ? <Badge variant="destructive" className="text-xs">None</Badge>
                        : ep.authStatus === "required"
                          ? <Badge variant="outline" className="text-xs text-green-400">Required</Badge>
                          : <Badge variant="outline" className="text-xs">Unknown</Badge>
                      }
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {ep.country && <p>{ep.city ? `${ep.city}, ` : ""}{ep.country}</p>}
                      {ep.org && <p className="truncate max-w-32">{ep.org}</p>}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {ep.systemPromptLeaked && <Badge variant="destructive" className="text-xs">Prompt Leaked</Badge>}
                        {ep.corsPolicy === "open" && <Badge className="text-xs bg-orange-500/20 text-orange-400 border-orange-500/30">Open CORS</Badge>}
                        {!ep.hasTls && <Badge variant="outline" className="text-xs text-yellow-400">No TLS</Badge>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Showing {((page - 1) * LIMIT) + 1}–{Math.min(page * LIMIT, total)} of {total}
              </p>
              <div className="flex items-center gap-2">
                <Button variant="outline" size="icon" disabled={page === 1} onClick={() => setPage(p => p - 1)}>
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <span className="text-sm">{page} / {pages}</span>
                <Button variant="outline" size="icon" disabled={page >= pages} onClick={() => setPage(p => p + 1)}>
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
