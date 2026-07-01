import { useState, useRef, useEffect, useCallback } from "react";
import { useLocation, useSearch } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { RiskScoreGauge } from "@/components/aiMapper/RiskScoreGauge";
import {
  Search, ChevronLeft, ChevronRight, Loader2, Crosshair,
  Download, ArrowUp, ArrowDown, ArrowUpDown, HelpCircle,
  ShieldOff, Lock, AlertTriangle, Wrench, BrainCircuit, ShieldCheck,
} from "lucide-react";

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/20 text-green-400 border-green-500/30",
};
const PROTOCOL_COLORS: Record<string, string> = {
  mcp:        "bg-blue-500/20 text-blue-400",
  ollama:     "bg-green-500/20 text-green-400",
  vllm:       "bg-purple-500/20 text-purple-400",
  langserve:  "bg-orange-500/20 text-orange-400",
  gradio:     "bg-pink-500/20 text-pink-400",
  litellm:    "bg-purple-500/20 text-purple-400",
  comfyui:    "bg-amber-500/20 text-amber-400",
  openwebui:  "bg-sky-500/20 text-sky-400",
  librechat:  "bg-teal-500/20 text-teal-400",
  localai:    "bg-violet-500/20 text-violet-400",
  openclaw:   "bg-rose-500/20 text-rose-400",
  generic:    "bg-red-500/20 text-red-400",
};

const SORT_COLS = ["riskScore", "firstSeenAt", "protocol", "authStatus"] as const;
type SortCol = typeof SORT_COLS[number];

interface AiEndpoint {
  id: number; ip: string; port: number; hostname?: string; url: string;
  protocol: string; framework?: string; authStatus: string;
  riskScore: number; riskLevel: string; country?: string; org?: string; city?: string;
  models?: string[]; tools?: { name: string }[];
  systemPromptLeaked: boolean; corsPolicy?: string; hasTls: boolean; firstSeenAt: string;
}

function SortTh({ label, col, cur, dir, onClick }: { label: string; col: SortCol; cur: SortCol; dir: string; onClick: () => void }) {
  return (
    <th className="text-left px-4 py-2.5 cursor-pointer select-none hover:text-foreground" onClick={onClick}>
      <span className="inline-flex items-center gap-1">
        {label}
        {col === cur
          ? dir === "asc" ? <ArrowUp className="w-3 h-3 text-violet-400" /> : <ArrowDown className="w-3 h-3 text-violet-400" />
          : <ArrowUpDown className="w-3 h-3 opacity-40" />}
      </span>
    </th>
  );
}

function buildCsvBlob(endpoints: AiEndpoint[]): Blob {
  const header = ["IP", "Port", "Hostname", "Protocol", "Framework", "Auth", "Risk Score", "Risk Level", "Country", "Org", "TLS", "Prompt Leaked", "First Seen"];
  const rows = endpoints.map(ep => [
    ep.ip, ep.port, ep.hostname ?? "", ep.protocol, ep.framework ?? "",
    ep.authStatus, ep.riskScore.toFixed(1), ep.riskLevel,
    ep.country ?? "", ep.org ?? "", ep.hasTls ? "Yes" : "No",
    ep.systemPromptLeaked ? "Yes" : "No",
    ep.firstSeenAt ? new Date(ep.firstSeenAt).toLocaleDateString() : "",
  ]);
  const csv = [header, ...rows].map(r => r.map(c => `"${c}"`).join(",")).join("\n");
  return new Blob([csv], { type: "text/csv" });
}

function triggerDownload(blob: Blob, filename: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

export default function AiMapperEndpointsPage() {
  const [, navigate] = useLocation();
  const rawSearch = useSearch();
  const [exporting, setExporting] = useState(false);

  function getParam(key: string, fallback: string) {
    const p = new URLSearchParams(rawSearch);
    return p.get(key) ?? fallback;
  }

  const [q, setQ]         = useState(() => getParam("q", ""));
  const [sort, setSort]   = useState<SortCol>(() => (getParam("sort", "riskScore") as SortCol));
  const [order, setOrder] = useState(() => getParam("order", "desc"));
  const [page, setPage]   = useState(() => Number(getParam("page", "1")));
  const [debouncedQ, setDebouncedQ] = useState(q);
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const LIMIT = 25;

  useEffect(() => {
    if (debounceTimer.current) clearTimeout(debounceTimer.current);
    debounceTimer.current = setTimeout(() => setDebouncedQ(q), 350);
    return () => { if (debounceTimer.current) clearTimeout(debounceTimer.current); };
  }, [q]);

  useEffect(() => {
    const p = new URLSearchParams();
    if (debouncedQ) p.set("q", debouncedQ);
    if (sort !== "riskScore") p.set("sort", sort);
    if (order !== "desc") p.set("order", order);
    if (page !== 1) p.set("page", String(page));
    const qs = p.toString();
    navigate(qs ? `?${qs}` : "?", { replace: true });
  }, [debouncedQ, sort, order, page]);

  const { data, isLoading } = useQuery<{ data: AiEndpoint[]; total: number; page: number; limit: number }>({
    queryKey: ["ai-mapper-endpoints", debouncedQ, sort, order, page],
    queryFn: () => apiFetch(`/api/ai-mapper/endpoints?q=${encodeURIComponent(debouncedQ)}&sort=${sort}&order=${order}&page=${page}&limit=${LIMIT}`),
    placeholderData: prev => prev,
  });

  const endpoints = data?.data ?? [];
  const total     = data?.total ?? 0;
  const pages     = Math.ceil(total / LIMIT);

  function handleSort(col: SortCol) {
    if (sort === col) setOrder(o => o === "asc" ? "desc" : "asc");
    else { setSort(col); setOrder("desc"); setPage(1); }
  }

  const handleExportAll = useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    try {
      const PAGE_SIZE = 500;
      let fetched = 0;
      let all: AiEndpoint[] = [];
      do {
        const pageNum = Math.floor(fetched / PAGE_SIZE) + 1;
        const resp: { data: AiEndpoint[]; total: number } = await apiFetch(
          `/api/ai-mapper/endpoints?q=${encodeURIComponent(debouncedQ)}&sort=${sort}&order=${order}&page=${pageNum}&limit=${PAGE_SIZE}`
        );
        all = all.concat(resp.data ?? []);
        fetched = all.length;
        if (fetched >= resp.total) break;
      } while (fetched < 10000);
      triggerDownload(buildCsvBlob(all), `ai-endpoints-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch {
      /* silently skip */
    } finally {
      setExporting(false);
    }
  }, [exporting, debouncedQ, sort, order]);

  return (
    <div className="p-6 space-y-5 max-w-6xl mx-auto">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">AI Endpoints</h1>
          <p className="text-sm text-muted-foreground">{total.toLocaleString()} exposed AI endpoints discovered</p>
        </div>
        {total > 0 && (
          <Button variant="outline" size="sm" onClick={handleExportAll} disabled={exporting}>
            {exporting
              ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Exporting…</>
              : <><Download className="w-4 h-4 mr-2" /> Export All ({total.toLocaleString()})</>}
          </Button>
        )}
      </div>

      {/* Search + sort */}
      <div className="flex gap-2 flex-wrap">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="relative flex-1 min-w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  value={q}
                  onChange={e => { setQ(e.target.value); setPage(1); }}
                  placeholder='Search… e.g. protocol:ollama auth:none risk:critical ip:10.'
                  className="pl-9 pr-9 text-sm font-mono"
                />
                <HelpCircle className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground opacity-50" />
              </div>
            </TooltipTrigger>
            <TooltipContent side="bottom" className="max-w-xs text-xs space-y-1 p-3">
              <p className="font-semibold mb-1">Query syntax</p>
              <p><span className="text-violet-300">protocol:</span>ollama · mcp · vllm · gradio · litellm</p>
              <p><span className="text-violet-300">auth:</span>none · required · unknown</p>
              <p><span className="text-violet-300">risk:</span>critical · high · medium · low</p>
              <p><span className="text-violet-300">has:</span>system_prompt · open_cors · no_tls</p>
              <p><span className="text-violet-300">ip:</span>10.0. · country:US · org:Amazon</p>
              <p className="text-muted-foreground mt-1">Combine multiple filters with spaces</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>

      {/* Quick-filter chips */}
      <div className="flex flex-wrap gap-2">
        {[
          { label: "All",      query: "" },
          { label: "Critical", query: "risk:critical" },
          { label: "High",     query: "risk:high" },
          { label: "No Auth",  query: "auth:none" },
          { label: "MCP",      query: "protocol:mcp" },
          { label: "Ollama",   query: "protocol:ollama" },
          { label: "vLLM",     query: "protocol:vllm" },
        ].map(chip => (
          <button
            key={chip.label}
            onClick={() => { setQ(chip.query); setPage(1); }}
            className={`px-2.5 py-1 text-xs rounded-full border transition-colors ${
              q === chip.query ? "border-primary bg-primary/10 text-primary" : "border-border hover:border-primary/50 text-muted-foreground hover:text-foreground"
            }`}
          >
            {chip.label}
          </button>
        ))}
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
                  <SortTh label="Risk"     col="riskScore"   cur={sort} dir={order} onClick={() => handleSort("riskScore")} />
                  <th className="text-left px-4 py-2.5">Endpoint</th>
                  <SortTh label="Protocol" col="protocol"    cur={sort} dir={order} onClick={() => handleSort("protocol")} />
                  <SortTh label="Auth"     col="authStatus"  cur={sort} dir={order} onClick={() => handleSort("authStatus")} />
                  <th className="text-center px-3 py-2.5" title="TLS">TLS</th>
                  <th className="text-center px-3 py-2.5" title="System Prompt Leaked">Prompt</th>
                  <th className="text-center px-3 py-2.5">Models</th>
                  <th className="text-center px-3 py-2.5">Tools</th>
                  <th className="text-left px-4 py-2.5">Location</th>
                  <SortTh label="First Seen" col="firstSeenAt" cur={sort} dir={order} onClick={() => handleSort("firstSeenAt")} />
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
                      {ep.hostname && <p className="text-xs text-muted-foreground truncate max-w-40">{ep.hostname}</p>}
                      {ep.framework && <p className="text-xs text-muted-foreground">{ep.framework}</p>}
                    </td>
                    <td className="px-4 py-3">
                      <Badge className={`text-xs border ${PROTOCOL_COLORS[ep.protocol] ?? PROTOCOL_COLORS.generic}`}>
                        {ep.protocol}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      {ep.authStatus === "none"
                        ? <span className="inline-flex items-center gap-1 text-xs text-red-400"><ShieldOff className="w-3.5 h-3.5" />None</span>
                        : ep.authStatus === "required"
                          ? <span className="inline-flex items-center gap-1 text-xs text-green-400"><Lock className="w-3.5 h-3.5" />Required</span>
                          : <span className="text-xs text-muted-foreground">Unknown</span>
                      }
                    </td>
                    <td className="px-3 py-3 text-center">
                      {ep.hasTls
                        ? <ShieldCheck className="w-4 h-4 text-green-400 mx-auto" />
                        : <AlertTriangle className="w-4 h-4 text-yellow-400 mx-auto" />
                      }
                    </td>
                    <td className="px-3 py-3 text-center">
                      {ep.systemPromptLeaked
                        ? <span title="System prompt leaked"><AlertTriangle className="w-4 h-4 text-red-400 mx-auto" /></span>
                        : <span className="text-xs text-muted-foreground">—</span>
                      }
                    </td>
                    <td className="px-3 py-3 text-center">
                      {ep.models && ep.models.length > 0
                        ? <span className="inline-flex items-center gap-1 text-xs font-medium text-violet-400"><BrainCircuit className="w-3.5 h-3.5" />{ep.models.length}</span>
                        : <span className="text-xs text-muted-foreground">—</span>
                      }
                    </td>
                    <td className="px-3 py-3 text-center">
                      {ep.tools && ep.tools.length > 0
                        ? <span className="inline-flex items-center gap-1 text-xs font-medium text-blue-400"><Wrench className="w-3.5 h-3.5" />{ep.tools.length}</span>
                        : <span className="text-xs text-muted-foreground">—</span>
                      }
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">
                      {ep.country && <p>{ep.city ? `${ep.city}, ` : ""}{ep.country}</p>}
                      {ep.org && <p className="truncate max-w-28">{ep.org}</p>}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                      {ep.firstSeenAt ? new Date(ep.firstSeenAt).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

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
