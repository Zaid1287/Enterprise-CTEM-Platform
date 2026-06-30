import { useState, useEffect, useRef, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import * as d3 from "d3";
import {
  Brain, Play, RefreshCw, AlertTriangle, ShieldX, Server,
  Globe, Loader2, ChevronRight, Eye, Clock, CheckCircle2,
  AlertCircle, Lock, LockOpen, Filter, X, Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn, formatDateTime } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

// ── Types ─────────────────────────────────────────────────────────────────────

interface AiMapperSummary {
  totalEndpoints: number;
  unauthEndpoints: number;
  highRiskEndpoints: number;
  serviceBreakdown: Record<string, number>;
  lastScanAt: string | null;
}

interface AiMapperScan {
  id: number;
  status: string;
  resultCount: number;
  unauthCount: number;
  highRiskCount: number;
  error: string | null;
  startedAt: string;
  completedAt: string | null;
}

interface AiMapperResult {
  id: number;
  scanId: number;
  assetId: number | null;
  url: string;
  host: string | null;
  port: number | null;
  serviceType: string;
  framework: string | null;
  isAuthenticated: boolean;
  corsPolicy: string | null;
  riskScore: number;
  riskLevel: string;
  modelsExposed: string[] | null;
  toolsExposed: string[] | null;
  ip: string | null;
  country: string | null;
  countryCode: string | null;
  city: string | null;
  org: string | null;
  discoveredAt: string;
}

interface GlobePoint {
  country: string;
  countryCode: string;
  count: number;
  highRisk: number;
  services: string[];
}

interface GlobeData {
  points: GlobePoint[];
  totalEndpoints: number;
}

interface AiAnalysis {
  analysis: string;
  suggestions: string[];
  riskLevel: string;
  model: string;
}

// ── Country centroid lookup (lat, lon) ────────────────────────────────────────

const COUNTRY_CENTROIDS: Record<string, [number, number]> = {
  US: [38, -97], CN: [35, 105], RU: [61, 105], DE: [51, 10], GB: [54, -2],
  FR: [46, 2],   JP: [36, 138], IN: [20, 77],  BR: [-15, -47], CA: [60, -95],
  AU: [-27, 133], IT: [43, 12], ES: [40, -4],  NL: [52, 5],  SG: [1.3, 103.8],
  KR: [37, 128], SE: [62, 15], NO: [64, 26],   CH: [47, 8],  PL: [52, 20],
  UA: [49, 32],  TR: [39, 35], IL: [31.5, 35], HK: [22, 114], TW: [23, 121],
  MX: [24, -102], AR: [-34, -64], ZA: [-29, 25], NG: [10, 8], EG: [27, 30],
  ID: [-5, 120], PH: [13, 122], VN: [16, 108], TH: [15, 101], MY: [2.5, 112],
  PK: [30, 70],  BD: [24, 90],  IR: [32, 53],  SA: [24, 45],  AE: [24, 54],
  AT: [47, 14],  BE: [50.8, 4], CZ: [50, 15],  PT: [39.5, -8], RO: [46, 25],
  FI: [64, 26],  DK: [56, 10], GR: [39, 22],   HU: [47, 19], BG: [43, 25],
  CL: [-30, -71], CO: [4, -72], PE: [-10, -76], NZ: [-42, 174], ZW: [-20, 30],
};

// ── Risk color helpers ────────────────────────────────────────────────────────

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info:     "bg-muted/40 text-muted-foreground border-border",
};

const RISK_DOT: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308", low: "#3b82f6", info: "#6b7280",
};

const SERVICE_COLORS: Record<string, string> = {
  ollama: "#6366f1", gradio: "#f59e0b", vllm: "#10b981", langserve: "#3b82f6",
  qdrant: "#8b5cf6", lmstudio: "#ec4899", comfyui: "#14b8a6", flowise: "#f97316",
  langflow: "#06b6d4", litellm: "#84cc16", "openai-compat": "#0ea5e9",
};

// ── Globe Component ───────────────────────────────────────────────────────────

function GlobeViz({ data, loading }: { data: GlobeData | undefined; loading: boolean }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; point: GlobePoint } | null>(null);

  const draw = useCallback(() => {
    if (!svgRef.current || !data) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const W = svgRef.current.clientWidth || 400;
    const H = svgRef.current.clientHeight || 300;
    const R = Math.min(W, H) / 2 - 8;
    const cx = W / 2, cy = H / 2;

    const projection = d3.geoOrthographic()
      .scale(R)
      .translate([cx, cy])
      .clipAngle(90);

    const path = d3.geoPath(projection);
    const graticule = d3.geoGraticule()();

    // Ocean
    svg.append("circle")
      .attr("cx", cx).attr("cy", cy).attr("r", R)
      .attr("fill", "#0f172a")
      .attr("stroke", "#1e293b")
      .attr("stroke-width", 1);

    // Graticule
    svg.append("path")
      .datum(graticule)
      .attr("d", path)
      .attr("fill", "none")
      .attr("stroke", "#1e293b")
      .attr("stroke-width", 0.5);

    // Dots for each country with services
    const pts = data.points.filter(p => COUNTRY_CENTROIDS[p.countryCode]);

    pts.forEach(p => {
      const [lat, lon] = COUNTRY_CENTROIDS[p.countryCode];
      const coords = projection([lon, lat]);
      if (!coords) return;
      const [x, y] = coords;
      const r = Math.max(4, Math.min(14, 4 + p.count * 2));
      const color = p.highRisk > 0 ? RISK_DOT.critical : RISK_DOT.high;

      // Glow
      svg.append("circle")
        .attr("cx", x).attr("cy", y).attr("r", r + 4)
        .attr("fill", color)
        .attr("opacity", 0.15);

      const dot = svg.append("circle")
        .attr("cx", x).attr("cy", y).attr("r", r)
        .attr("fill", color)
        .attr("opacity", 0.85)
        .attr("stroke", color)
        .attr("stroke-width", 1)
        .style("cursor", "pointer");

      svg.append("text")
        .attr("x", x).attr("y", y + 1)
        .attr("text-anchor", "middle")
        .attr("dominant-baseline", "middle")
        .attr("fill", "white")
        .attr("font-size", Math.max(7, r - 3))
        .attr("font-weight", "600")
        .attr("pointer-events", "none")
        .text(p.count.toString());

      dot.on("mouseenter", (event: MouseEvent) => {
        setTooltip({ x: event.clientX, y: event.clientY, point: p });
      }).on("mouseleave", () => setTooltip(null));
    });

    // Drag to rotate
    let lastX = 0, lastY = 0;
    svg.call(
      d3.drag<SVGSVGElement, unknown>()
        .on("start", (event) => { lastX = event.x; lastY = event.y; })
        .on("drag", (event) => {
          const dx = event.x - lastX;
          const dy = event.y - lastY;
          const rotate = projection.rotate();
          projection.rotate([rotate[0] + dx * 0.4, rotate[1] - dy * 0.4]);
          svg.select<SVGPathElement>(".graticule").attr("d", path(graticule) ?? "");
          svg.selectAll("path").attr("d", (d) => path(d as d3.GeoPermissibleObjects) ?? "");
          // Redraw — simple approach: redraw all
          draw();
          lastX = event.x; lastY = event.y;
        }) as any
    );
  }, [data]);

  useEffect(() => { draw(); }, [draw]);

  return (
    <div className="relative w-full h-full">
      {loading ? (
        <div className="flex items-center justify-center h-full">
          <Loader2 className="w-8 h-8 text-muted-foreground animate-spin" />
        </div>
      ) : !data || data.totalEndpoints === 0 ? (
        <div className="flex flex-col items-center justify-center h-full gap-2 text-muted-foreground">
          <Globe className="w-12 h-12 opacity-20" />
          <p className="text-sm">No AI endpoints discovered yet</p>
          <p className="text-xs opacity-60">Run a scan to populate the globe</p>
        </div>
      ) : (
        <>
          <svg ref={svgRef} className="w-full h-full" style={{ cursor: "grab" }} />
          {tooltip && (
            <div
              className="fixed z-50 bg-popover border border-border rounded-lg p-2.5 text-xs shadow-xl pointer-events-none"
              style={{ left: tooltip.x + 12, top: tooltip.y - 8 }}
            >
              <p className="font-semibold">{tooltip.point.country}</p>
              <p className="text-muted-foreground">{tooltip.point.count} AI endpoints</p>
              {tooltip.point.highRisk > 0 && (
                <p className="text-red-400">{tooltip.point.highRisk} high/critical risk</p>
              )}
              <p className="text-muted-foreground/70 mt-1">{tooltip.point.services.join(", ")}</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Scan status icon ──────────────────────────────────────────────────────────

function ScanStatusIcon({ status }: { status: string }) {
  if (status === "completed") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (status === "running")   return <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />;
  if (status === "failed")    return <AlertCircle className="w-4 h-4 text-red-400" />;
  return <Clock className="w-4 h-4 text-muted-foreground" />;
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type TabId = "results" | "history" | "analysis";

export default function AiMapperPage() {
  const [activeTab, setActiveTab] = useState<TabId>("results");
  const [serviceFilter, setServiceFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [expandedResult, setExpandedResult] = useState<number | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: summary, isLoading: summaryLoading } = useQuery<AiMapperSummary>({
    queryKey: ["ai-mapper-summary"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/summary`),
    refetchInterval: 15_000,
  });

  const { data: scans, isLoading: scansLoading } = useQuery<AiMapperScan[]>({
    queryKey: ["ai-mapper-scans"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/scans`),
    refetchInterval: (q) => {
      const d = q.state.data as AiMapperScan[] | undefined;
      return d?.some(s => s.status === "running" || s.status === "pending") ? 3000 : 30_000;
    },
  });

  const { data: resultsData, isLoading: resultsLoading } = useQuery<{ results: AiMapperResult[]; total: number }>({
    queryKey: ["ai-mapper-results", serviceFilter, riskFilter],
    queryFn: () => {
      const params = new URLSearchParams();
      if (serviceFilter) params.set("serviceType", serviceFilter);
      if (riskFilter)    params.set("riskLevel", riskFilter);
      params.set("limit", "100");
      return apiFetch(`${BASE}/api/ai-mapper/results?${params}`);
    },
  });

  const { data: globeData, isLoading: globeLoading } = useQuery<GlobeData>({
    queryKey: ["ai-mapper-globe"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/globe-data`),
    staleTime: 60_000,
  });

  const [analysis, setAnalysis] = useState<AiAnalysis | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const handleAnalyze = async () => {
    setAnalyzing(true);
    try {
      const data = await apiFetch(`${BASE}/api/ai-mapper/analyze`, { method: "POST" });
      setAnalysis(data as AiAnalysis);
    } catch (e: any) {
      toast({ title: "Analysis failed", description: e.message, variant: "destructive" });
    } finally {
      setAnalyzing(false);
    }
  };

  const startScanMutation = useMutation({
    mutationFn: () => apiFetch(`${BASE}/api/ai-mapper/scans`, { method: "POST", body: JSON.stringify({}) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["ai-mapper-scans"] });
      queryClient.invalidateQueries({ queryKey: ["ai-mapper-summary"] });
      toast({ title: "AI Mapper scan started", description: "Probing assets for exposed AI services…" });
    },
    onError: (e: any) => toast({ title: "Scan failed", description: e.message, variant: "destructive" }),
  });

  const results = resultsData?.results ?? [];
  const allServices = summary ? Object.keys(summary.serviceBreakdown) : [];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center">
            <Brain className="w-4.5 h-4.5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">AI Mapper</h1>
            <p className="text-xs text-muted-foreground">
              Discover exposed AI infrastructure — Ollama, Gradio, vLLM, Qdrant, LangServe, and more
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => {
              queryClient.invalidateQueries({ queryKey: ["ai-mapper-summary"] });
              queryClient.invalidateQueries({ queryKey: ["ai-mapper-results"] });
              queryClient.invalidateQueries({ queryKey: ["ai-mapper-globe"] });
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          <Button
            size="sm"
            onClick={() => startScanMutation.mutate()}
            disabled={startScanMutation.isPending}
            className="gap-1.5"
          >
            {startScanMutation.isPending
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
              : <Play className="w-3.5 h-3.5" />}
            Run Scan
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {summaryLoading ? (
          [...Array(4)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)
        ) : (
          <>
            <StatCard
              icon={<Server className="w-4 h-4 text-violet-400" />}
              label="AI Endpoints Found"
              value={summary?.totalEndpoints ?? 0}
              sub={summary?.lastScanAt ? `Last scan ${formatDateTime(summary.lastScanAt)}` : "No scans yet"}
              color="bg-violet-500/10"
            />
            <StatCard
              icon={<LockOpen className="w-4 h-4 text-red-400" />}
              label="Unauthenticated"
              value={summary?.unauthEndpoints ?? 0}
              sub="Accessible without credentials"
              color="bg-red-500/10"
              danger={!!summary?.unauthEndpoints}
            />
            <StatCard
              icon={<ShieldX className="w-4 h-4 text-orange-400" />}
              label="High / Critical Risk"
              value={summary?.highRiskEndpoints ?? 0}
              sub="Immediate attention needed"
              color="bg-orange-500/10"
              danger={!!summary?.highRiskEndpoints}
            />
            <StatCard
              icon={<Globe className="w-4 h-4 text-blue-400" />}
              label="Services Detected"
              value={allServices.length}
              sub={allServices.slice(0, 3).map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(", ") || "—"}
              color="bg-blue-500/10"
            />
          </>
        )}
      </div>

      {/* Globe + Service breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden" style={{ height: 340 }}>
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
            <span className="text-sm font-medium flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-muted-foreground" />
              Global Distribution
            </span>
            {globeData && globeData.points.length > 0 && (
              <span className="text-xs text-muted-foreground">
                {globeData.points.length} countries · drag to rotate
              </span>
            )}
          </div>
          <div style={{ height: 295 }}>
            <GlobeViz data={globeData} loading={globeLoading} />
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-4">
          <h3 className="text-sm font-medium mb-3">Services Breakdown</h3>
          {summaryLoading ? (
            <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 rounded" />)}</div>
          ) : allServices.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-40 text-muted-foreground text-xs gap-2">
              <Zap className="w-8 h-8 opacity-20" />
              <span>Run a scan to discover services</span>
            </div>
          ) : (
            <div className="space-y-2">
              {allServices.sort((a, b) => (summary!.serviceBreakdown[b] ?? 0) - (summary!.serviceBreakdown[a] ?? 0))
                .map(svc => {
                  const count = summary!.serviceBreakdown[svc] ?? 0;
                  const total = summary!.totalEndpoints;
                  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                  const color = SERVICE_COLORS[svc] ?? "#6b7280";
                  return (
                    <div key={svc} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-medium capitalize">{svc}</span>
                        <span className="text-muted-foreground">{count}</span>
                      </div>
                      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all"
                          style={{ width: `${pct}%`, backgroundColor: color }}
                        />
                      </div>
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {([
          { id: "results",  label: "Endpoints",    count: resultsData?.total },
          { id: "history",  label: "Scan History", count: scans?.length },
          { id: "analysis", label: "AI Analysis" },
        ] as { id: TabId; label: string; count?: number }[]).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 transition-colors -mb-px",
              activeTab === tab.id
                ? "border-primary text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground hover:border-border",
            )}
          >
            {tab.label}
            {tab.count !== undefined && (
              <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-muted text-muted-foreground font-medium">
                {tab.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Endpoints Tab */}
      {activeTab === "results" && (
        <div className="space-y-3">
          {/* Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-3.5 h-3.5 text-muted-foreground" />
            <div className="flex gap-1.5 flex-wrap">
              {allServices.map(svc => (
                <button
                  key={svc}
                  onClick={() => setServiceFilter(prev => prev === svc ? "" : svc)}
                  className={cn(
                    "px-2 py-0.5 rounded text-xs border transition-colors capitalize",
                    serviceFilter === svc
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:border-primary/50",
                  )}
                >
                  {svc}
                </button>
              ))}
              {(["critical", "high", "medium", "low"] as const).map(risk => (
                <button
                  key={risk}
                  onClick={() => setRiskFilter(prev => prev === risk ? "" : risk)}
                  className={cn(
                    "px-2 py-0.5 rounded text-xs border transition-colors",
                    riskFilter === risk
                      ? "border-primary bg-primary/10 text-primary"
                      : "border-border text-muted-foreground hover:border-primary/50",
                  )}
                >
                  {risk}
                </button>
              ))}
              {(serviceFilter || riskFilter) && (
                <button
                  onClick={() => { setServiceFilter(""); setRiskFilter(""); }}
                  className="flex items-center gap-1 px-2 py-0.5 rounded text-xs border border-border text-muted-foreground hover:text-foreground"
                >
                  <X className="w-3 h-3" /> Clear
                </button>
              )}
            </div>
          </div>

          {/* Results table */}
          {resultsLoading ? (
            <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}</div>
          ) : results.length === 0 ? (
            <div className="bg-card border border-border rounded-xl p-12 text-center text-muted-foreground">
              <Brain className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="text-sm font-medium">No AI endpoints discovered</p>
              <p className="text-xs mt-1 opacity-70">Click "Run Scan" to probe your assets for exposed AI services</p>
            </div>
          ) : (
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-muted/30 border-b border-border">
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Endpoint</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Service</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Auth</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">CORS</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Risk</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Location</th>
                    <th className="text-left px-3 py-2.5 text-muted-foreground font-medium">Models</th>
                    <th className="px-3 py-2.5"></th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(r => (
                    <>
                      <tr
                        key={r.id}
                        className="border-b border-border/40 hover:bg-accent/20 cursor-pointer transition-colors"
                        onClick={() => setExpandedResult(prev => prev === r.id ? null : r.id)}
                      >
                        <td className="px-3 py-2.5">
                          <span className="font-mono text-primary truncate block max-w-[200px]">{r.url}</span>
                          {r.host && r.host !== r.url.replace("http://", "").split(":")[0] && (
                            <span className="text-muted-foreground/60 text-[10px]">{r.host}</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          <span
                            className="px-1.5 py-0.5 rounded text-[10px] font-medium text-white"
                            style={{ backgroundColor: SERVICE_COLORS[r.serviceType] ?? "#6b7280" }}
                          >
                            {r.framework ?? r.serviceType}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          {r.isAuthenticated
                            ? <Lock className="w-3.5 h-3.5 text-green-400" />
                            : <LockOpen className="w-3.5 h-3.5 text-red-400" />}
                        </td>
                        <td className="px-3 py-2.5">
                          <span className={cn("text-[10px]",
                            r.corsPolicy === "open" ? "text-red-400" :
                            r.corsPolicy === "restricted" ? "text-yellow-400" : "text-muted-foreground/50"
                          )}>
                            {r.corsPolicy ?? "none"}
                          </span>
                        </td>
                        <td className="px-3 py-2.5">
                          <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-medium border capitalize", RISK_BADGE[r.riskLevel] ?? RISK_BADGE.info)}>
                            {r.riskLevel}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-muted-foreground">
                          {r.country ? `${r.city ? r.city + ", " : ""}${r.country}` : r.ip ?? "—"}
                        </td>
                        <td className="px-3 py-2.5 text-muted-foreground">
                          {r.modelsExposed?.length ? (
                            <span title={r.modelsExposed.join(", ")}>
                              {r.modelsExposed.length} model{r.modelsExposed.length !== 1 ? "s" : ""}
                            </span>
                          ) : "—"}
                        </td>
                        <td className="px-3 py-2.5">
                          <ChevronRight className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform", expandedResult === r.id && "rotate-90")} />
                        </td>
                      </tr>
                      {expandedResult === r.id && (
                        <tr key={`${r.id}-expand`} className="border-b border-border/40 bg-muted/10">
                          <td colSpan={8} className="px-4 py-3">
                            <div className="grid grid-cols-2 gap-4 text-xs">
                              <div className="space-y-1.5">
                                <p className="font-medium text-foreground">Connection Details</p>
                                <p><span className="text-muted-foreground">URL:</span> <span className="font-mono">{r.url}</span></p>
                                <p><span className="text-muted-foreground">Port:</span> {r.port ?? "—"}</p>
                                <p><span className="text-muted-foreground">IP:</span> {r.ip ?? "—"}</p>
                                <p><span className="text-muted-foreground">Org:</span> {r.org ?? "—"}</p>
                                <p><span className="text-muted-foreground">Risk Score:</span> {r.riskScore}/10</p>
                              </div>
                              <div className="space-y-1.5">
                                <p className="font-medium text-foreground">Exposed Resources</p>
                                {r.modelsExposed?.length ? (
                                  <>
                                    <p className="text-muted-foreground">Models:</p>
                                    <div className="flex flex-wrap gap-1">
                                      {r.modelsExposed.map(m => (
                                        <span key={m} className="bg-violet-500/10 text-violet-400 border border-violet-500/20 px-1.5 py-0.5 rounded text-[10px]">
                                          {m}
                                        </span>
                                      ))}
                                    </div>
                                  </>
                                ) : <p className="text-muted-foreground/60">No models enumerated</p>}
                                {r.toolsExposed?.length ? (
                                  <>
                                    <p className="text-muted-foreground mt-1">Tools:</p>
                                    <div className="flex flex-wrap gap-1">
                                      {r.toolsExposed.map(t => (
                                        <span key={t} className="bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded text-[10px]">
                                          {t}
                                        </span>
                                      ))}
                                    </div>
                                  </>
                                ) : null}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Scan History Tab */}
      {activeTab === "history" && (
        <div className="space-y-3">
          {scansLoading ? (
            <div className="space-y-2">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>
          ) : !scans?.length ? (
            <div className="bg-card border border-border rounded-xl p-12 text-center text-muted-foreground">
              <Clock className="w-10 h-10 mx-auto mb-3 opacity-20" />
              <p className="text-sm">No scans run yet</p>
            </div>
          ) : (
            <div className="grid gap-2">
              {scans.map(scan => (
                <div key={scan.id} className="bg-card border border-border rounded-xl px-4 py-3 flex items-center gap-3">
                  <ScanStatusIcon status={scan.status} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">Scan #{scan.id}</span>
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium border capitalize", {
                        "bg-green-500/10 text-green-400 border-green-500/20": scan.status === "completed",
                        "bg-yellow-500/10 text-yellow-400 border-yellow-500/20": scan.status === "running",
                        "bg-red-500/10 text-red-400 border-red-500/20": scan.status === "failed",
                        "bg-muted/40 text-muted-foreground border-border": scan.status === "pending",
                      })}>
                        {scan.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Started {formatDateTime(scan.startedAt)}
                      {scan.completedAt && ` · Completed ${formatDateTime(scan.completedAt)}`}
                    </p>
                  </div>
                  {scan.status === "completed" && (
                    <div className="flex items-center gap-4 text-xs text-muted-foreground shrink-0">
                      <span><span className="text-foreground font-medium">{scan.resultCount}</span> endpoints</span>
                      {scan.unauthCount > 0 && (
                        <span className="text-red-400">
                          <span className="font-medium">{scan.unauthCount}</span> unauth
                        </span>
                      )}
                      {scan.highRiskCount > 0 && (
                        <span className="text-orange-400">
                          <span className="font-medium">{scan.highRiskCount}</span> high risk
                        </span>
                      )}
                    </div>
                  )}
                  {scan.status === "failed" && scan.error && (
                    <span className="text-xs text-red-400 max-w-[200px] truncate" title={scan.error}>{scan.error}</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* AI Analysis Tab */}
      {activeTab === "analysis" && (
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-3">
              <div>
                <h3 className="text-sm font-semibold">AI Attack Surface Analysis</h3>
                <p className="text-xs text-muted-foreground mt-0.5">
                  GPT-4o-mini analyzes your discovered AI endpoints and generates prioritized recommendations
                </p>
              </div>
              <Button
                size="sm"
                onClick={handleAnalyze}
                disabled={analyzing}
                className="gap-1.5"
              >
                {analyzing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Brain className="w-3.5 h-3.5" />}
                {analyzing ? "Analyzing…" : analysis ? "Re-analyze" : "Analyze Surface"}
              </Button>
            </div>

            {analysis ? (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <span className={cn("px-2 py-0.5 rounded text-xs font-medium border capitalize", RISK_BADGE[analysis.riskLevel] ?? RISK_BADGE.info)}>
                    {analysis.riskLevel} risk
                  </span>
                  <span className="text-xs text-muted-foreground">· model: {analysis.model}</span>
                </div>

                <div className="prose prose-sm max-w-none text-foreground">
                  <div className="bg-accent/20 border border-border rounded-lg p-4 text-sm whitespace-pre-wrap leading-relaxed">
                    {analysis.analysis}
                  </div>
                </div>

                {analysis.suggestions?.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Recommendations</p>
                    {analysis.suggestions.map((s, i) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <span className="w-5 h-5 rounded-full bg-primary/15 text-primary text-[10px] font-bold flex items-center justify-center shrink-0 mt-0.5">
                          {i + 1}
                        </span>
                        <span>{s}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-10 text-muted-foreground gap-3">
                <Brain className="w-10 h-10 opacity-20" />
                <p className="text-sm">Click "Analyze Surface" to get AI-powered security recommendations</p>
                <p className="text-xs opacity-60">Works even without OpenAI — uses built-in templates as fallback</p>
              </div>
            )}
          </div>

          {/* Unauthenticated warning */}
          {summary && summary.unauthEndpoints > 0 && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
              <div className="text-sm">
                <p className="font-semibold text-red-400">
                  {summary.unauthEndpoints} unauthenticated AI endpoint{summary.unauthEndpoints !== 1 ? "s" : ""} detected
                </p>
                <p className="text-muted-foreground text-xs mt-1">
                  These services are accessible without credentials. Anyone on the internet can query your models,
                  extract data, and potentially exploit tool execution capabilities.
                </p>
              </div>
            </div>
          )}

          {/* Service info cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {[
              { name: "Ollama", port: 11434, desc: "Local LLM serving framework. Exposes model list and inference API.", risk: "high" },
              { name: "Gradio", port: 7860, desc: "ML demo framework. May expose model weights and inference endpoints.", risk: "medium" },
              { name: "vLLM", port: 8000, desc: "High-throughput LLM serving. OpenAI-compatible API for model inference.", risk: "high" },
              { name: "Qdrant", port: 6333, desc: "Vector database. Exposure allows data extraction from embeddings.", risk: "critical" },
              { name: "LangServe", port: 8080, desc: "LangChain serving. Exposes chain endpoints and agent capabilities.", risk: "high" },
              { name: "Flowise", port: 3001, desc: "No-code LLM orchestration. May expose chatflow configs and tools.", risk: "critical" },
            ].map(svc => (
              <div key={svc.name} className="bg-card border border-border rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium flex items-center gap-1.5">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: SERVICE_COLORS[svc.name.toLowerCase()] ?? "#6b7280" }}
                    />
                    {svc.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">:{svc.port}</span>
                    <span className={cn("px-1.5 py-0.5 rounded text-[10px] border capitalize", RISK_BADGE[svc.risk] ?? RISK_BADGE.info)}>
                      {svc.risk}
                    </span>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{svc.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Stat Card ─────────────────────────────────────────────────────────────────

function StatCard({ icon, label, value, sub, color, danger }: {
  icon: React.ReactNode; label: string; value: number; sub: string;
  color: string; danger?: boolean;
}) {
  return (
    <div className={cn("bg-card border border-border rounded-xl p-4", danger && "border-red-500/30")}>
      <div className="flex items-center gap-2 mb-2">
        <div className={cn("w-7 h-7 rounded-lg flex items-center justify-center", color)}>{icon}</div>
        <span className="text-xs text-muted-foreground">{label}</span>
      </div>
      <p className={cn("text-2xl font-bold", danger && value > 0 ? "text-red-400" : "")}>{value}</p>
      <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{sub}</p>
    </div>
  );
}
