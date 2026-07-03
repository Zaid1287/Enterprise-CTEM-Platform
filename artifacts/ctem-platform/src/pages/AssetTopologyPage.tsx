import { useEffect, useRef, useState, useCallback } from "react";
import { useLocation } from "wouter";
import * as d3 from "d3";
import { getToken } from "@/lib/auth";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { RefreshCw, Wifi, WifiOff, ExternalLink, Scan } from "lucide-react";
import { apiFetch } from "@/lib/apiFetch";

// ── Types ──────────────────────────────────────────────────────────────────────

interface GraphNode extends d3.SimulationNodeDatum {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

interface RawRelationship {
  id: string;
  type: string;
  startNodeId: string;
  endNodeId: string;
}

interface GraphLink extends d3.SimulationLinkDatum<GraphNode> {
  id: string;
  type: string;
}

interface GraphMeta {
  nodeCount: number;
  relationshipCount: number;
  assetCount: number;
  findingCount: number;
  cveCount: number;
}

interface GraphData {
  nodes: GraphNode[];
  relationships: RawRelationship[];
  meta: GraphMeta;
}

// ── Visual constants ───────────────────────────────────────────────────────────

const NODE_COLOR: Record<string, string> = {
  organization: "#6366f1",
  domain:       "#3b82f6",
  subdomain:    "#0ea5e9",
  ip:           "#14b8a6",
  port:         "#10b981",
  url:          "#8b5cf6",
  host:         "#f59e0b",
  cloud:        "#60a5fa",
  cloud_asset:  "#60a5fa",
  api:          "#a855f7",
  vulnerability:"#ef4444",
  finding:      "#ef4444",
  cve:          "#f97316",
  other:        "#6b7280",
};

const NODE_RADIUS: Record<string, number> = {
  organization: 28,
  domain:       22,
  subdomain:    17,
  ip:           20,
  port:         13,
  url:          17,
  host:         18,
  cloud:        18,
  api:          16,
  vulnerability:16,
  finding:      16,
  cve:          13,
};

const EDGE_STYLE: Record<string, { stroke: string; dash?: string }> = {
  OWNS:              { stroke: "#6366f1" },
  SUBDOMAIN_OF:      { stroke: "#3b82f6", dash: "4 2" },
  RESOLVES_TO:       { stroke: "#14b8a6", dash: "3 3" },
  EXPOSES:           { stroke: "#10b981" },
  HAS_VULNERABILITY: { stroke: "#ef4444" },
  REFERENCES_CVE:    { stroke: "#f97316", dash: "2 4" },
};

const RISK_LABELS = ["All", "Low+", "Medium+", "High+", "Critical only"] as const;
const RISK_ORDER  = ["info", "low", "medium", "high", "critical"] as const;

// ── Pure helpers ───────────────────────────────────────────────────────────────

function nodeColor(n: GraphNode): string {
  const lbl = n.labels[0]?.toLowerCase() ?? "other";
  if (lbl === "vulnerability" || lbl === "finding") {
    const s = n.properties.severity;
    if (s === "critical") return "#dc2626";
    if (s === "high")     return "#ea580c";
    if (s === "medium")   return "#d97706";
    return "#2563eb";
  }
  return NODE_COLOR[lbl] ?? NODE_COLOR.other;
}

function nodeRadius(n: GraphNode): number {
  return NODE_RADIUS[n.labels[0]?.toLowerCase() ?? "other"] ?? 16;
}

function nodeLabel(n: GraphNode): string {
  const p   = n.properties;
  const raw = p.name ?? p.value ?? (p.port ? `:${p.port}` : null) ?? p.id ?? n.id.split("-")[0];
  const s   = String(raw);
  return s.length > 15 ? s.slice(0, 14) + "…" : s;
}

/** Risk severity → numeric index (for filter comparison). */
function riskIndex(severity: string | undefined): number {
  const idx = RISK_ORDER.indexOf((severity ?? "low") as any);
  return idx < 0 ? 1 : idx;
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function AssetTopologyPage() {
  const svgRef  = useRef<SVGSVGElement>(null);
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const simRef  = useRef<d3.Simulation<GraphNode, GraphLink> | null>(null);
  const [, navigate] = useLocation();

  const [data, setData]               = useState<GraphData | null>(null);
  const [loading, setLoading]         = useState(true);
  const [error, setError]             = useState<string | null>(null);
  const [tooltip, setTooltip]         = useState<{ x: number; y: number; node: GraphNode } | null>(null);
  const [selected, setSelected]       = useState<GraphNode | null>(null);
  const [highlightType, setHighlight] = useState<string | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; node: GraphNode } | null>(null);
  const [riskFilter, setRiskFilter]   = useState<number>(0);
  const [sseConnected, setSseConnected] = useState(false);
  const [scanningId, setScanningId]   = useState<number | null>(null);

  // ── Data fetch ───────────────────────────────────────────────────────────────
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const token = getToken();
      const res = await fetch("/api/graph/attack-surface", {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setData(await res.json());
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  // ── SSE auto-refresh on scan_complete ────────────────────────────────────────
  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const ctrl   = new AbortController();
    let   active = true;

    const connect = async () => {
      try {
        const res = await fetch("/api/alerts/stream", {
          headers: { Authorization: `Bearer ${token}` },
          signal: ctrl.signal,
        });
        if (!res.ok || !res.body) return;
        setSseConnected(true);
        const reader = res.body.getReader();
        const dec    = new TextDecoder();
        let   buf    = "";
        let   lastEvent = "";
        while (active) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split("\n");
          buf = lines.pop() ?? "";
          for (const line of lines) {
            if (line.startsWith("event:")) {
              lastEvent = line.slice(6).trim();
            } else if (line.startsWith("data:") && lastEvent === "scan_complete") {
              fetchData();
              lastEvent = "";
            } else if (line === "") {
              lastEvent = "";
            }
          }
        }
      } catch {
        // network error or abort — silently ignore
      } finally {
        setSseConnected(false);
      }
    };

    connect();
    return () => { active = false; ctrl.abort(); setSseConnected(false); };
  }, [fetchData]);

  // ── D3 render ─────────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svgEl = svgRef.current;
    const W     = svgEl.clientWidth || 960;
    const H     = 640;

    const nodes: GraphNode[] = data.nodes.map(n => ({ ...n }));
    const byId = new Map<string, GraphNode>(nodes.map(n => [n.id, n]));

    const links: GraphLink[] = data.relationships
      .map(r => {
        const s = byId.get(r.startNodeId);
        const t = byId.get(r.endNodeId);
        if (!s || !t) return null;
        return { id: r.id, type: r.type, source: s, target: t } as GraphLink;
      })
      .filter((l): l is GraphLink => l !== null);

    // ── SVG scaffold ──────────────────────────────────────────────────────────
    const svg = d3.select(svgEl);
    svg.selectAll("*").remove();

    const defs = svg.append("defs");
    Object.entries(EDGE_STYLE).forEach(([type, style]) => {
      defs.append("marker")
        .attr("id", `arr-${type}`)
        .attr("markerWidth", 7).attr("markerHeight", 7)
        .attr("refX", 14).attr("refY", 3)
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,0 L0,6 L7,3 z")
        .attr("fill", style.stroke)
        .attr("opacity", 0.55);
    });

    const root = svg.append("g").attr("class", "root");

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.08, 6])
      .on("zoom", ev => root.attr("transform", ev.transform.toString()));
    svg.call(zoom).on("dblclick.zoom", null);
    zoomRef.current = zoom;

    // ── Simulation ────────────────────────────────────────────────────────────
    const sim = d3.forceSimulation<GraphNode>(nodes)
      .force("link", d3.forceLink<GraphNode, GraphLink>(links)
        .id(d => d.id)
        .distance(d => {
          const t = (d as GraphLink).type;
          if (t === "OWNS") return 150;
          if (t === "HAS_VULNERABILITY") return 90;
          return 110;
        })
        .strength(0.55))
      .force("charge", d3.forceManyBody<GraphNode>()
        .strength(n => {
          const lbl = n.labels[0]?.toLowerCase();
          if (lbl === "organization") return -900;
          if (lbl === "cve" || lbl === "port") return -80;
          return -260;
        }))
      .force("center", d3.forceCenter(W / 2, H / 2).strength(0.07))
      .force("collision", d3.forceCollide<GraphNode>().radius(n => nodeRadius(n) + 14));
    simRef.current = sim;

    // ── Links ─────────────────────────────────────────────────────────────────
    const linkG   = root.append("g");
    const linkEls = linkG.selectAll<SVGLineElement, GraphLink>("line")
      .data(links).join("line")
      .attr("stroke", d => EDGE_STYLE[d.type]?.stroke ?? "#6b7280")
      .attr("stroke-opacity", 0.4)
      .attr("stroke-width", 1.5)
      .attr("stroke-dasharray", d => EDGE_STYLE[d.type]?.dash ?? null)
      .attr("marker-end", d => `url(#arr-${d.type})`);

    const labelG   = root.append("g");
    const labelEls = labelG.selectAll<SVGTextElement, GraphLink>("text")
      .data(links).join("text")
      .attr("font-size", "7.5px")
      .attr("fill", "#9ca3af")
      .attr("text-anchor", "middle")
      .attr("paint-order", "stroke")
      .attr("stroke", "hsl(var(--background))")
      .attr("stroke-width", "4px")
      .text(d => d.type.replace(/_/g, " "));

    // ── Nodes ─────────────────────────────────────────────────────────────────
    const drag = d3.drag<SVGGElement, GraphNode>()
      .on("start", (ev, d) => {
        if (!ev.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on("drag", (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev, d) => {
        if (!ev.active) sim.alphaTarget(0);
        d.fx = null; d.fy = null;
      });

    const nodeG   = root.append("g");
    const nodeEls = nodeG.selectAll<SVGGElement, GraphNode>("g")
      .data(nodes).join("g")
      .attr("data-label", d => d.labels[0]?.toLowerCase() ?? "other")
      .attr("data-risk", d => {
        const lbl = d.labels[0]?.toLowerCase();
        if (lbl === "vulnerability" || lbl === "finding") return d.properties.severity ?? "low";
        if (lbl === "asset" || ["domain", "subdomain", "ip", "url", "host", "api", "cloud", "cloud_asset"].includes(lbl ?? "")) {
          return d.properties.riskLevel ?? "low";
        }
        return "";
      })
      .style("cursor", "grab")
      .call(drag as any)
      .on("mouseover", (ev, d) => {
        const rect = svgEl.getBoundingClientRect();
        setTooltip({ x: ev.clientX - rect.left, y: ev.clientY - rect.top, node: d });
        d3.select(ev.currentTarget).select("circle").attr("stroke-width", 3.5);
      })
      .on("mouseout", ev => {
        setTooltip(null);
        d3.select(ev.currentTarget).select("circle").attr("stroke-width", 1.5);
      })
      .on("click", (ev, d) => {
        ev.stopPropagation();
        setContextMenu(null);
        setSelected(prev => prev?.id === d.id ? null : d);
      })
      .on("contextmenu", (ev, d) => {
        ev.preventDefault();
        ev.stopPropagation();
        const rect = svgEl.getBoundingClientRect();
        setContextMenu({ x: ev.clientX - rect.left, y: ev.clientY - rect.top, node: d });
      });

    nodeEls.append("circle")
      .attr("r", d => nodeRadius(d))
      .attr("fill", d => nodeColor(d))
      .attr("fill-opacity", 0.14)
      .attr("stroke", d => nodeColor(d))
      .attr("stroke-width", 1.5);

    nodeEls.append("text")
      .attr("text-anchor", "middle").attr("dy", "0.38em")
      .attr("font-size", "8px").attr("font-weight", "700")
      .attr("fill", d => nodeColor(d))
      .attr("paint-order", "stroke")
      .attr("stroke", "hsl(var(--background))").attr("stroke-width", "4px")
      .text(d => d.labels[0]?.slice(0, 2).toUpperCase() ?? "??");

    nodeEls.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", d => nodeRadius(d) + 11)
      .attr("font-size", "8px")
      .attr("fill", "hsl(var(--foreground))")
      .attr("fill-opacity", 0.75)
      .attr("paint-order", "stroke")
      .attr("stroke", "hsl(var(--background))").attr("stroke-width", "4px")
      .text(d => nodeLabel(d));

    // Dismiss context menu and selection on blank SVG click
    svg.on("click", () => { setSelected(null); setContextMenu(null); });

    // ── Tick ──────────────────────────────────────────────────────────────────
    sim.on("tick", () => {
      linkEls
        .attr("x1", d => (d.source as GraphNode).x ?? 0)
        .attr("y1", d => (d.source as GraphNode).y ?? 0)
        .attr("x2", d => (d.target as GraphNode).x ?? 0)
        .attr("y2", d => (d.target as GraphNode).y ?? 0);
      labelEls
        .attr("x", d => (((d.source as GraphNode).x ?? 0) + ((d.target as GraphNode).x ?? 0)) / 2)
        .attr("y", d => (((d.source as GraphNode).y ?? 0) + ((d.target as GraphNode).y ?? 0)) / 2 - 4);
      nodeEls.attr("transform", d => `translate(${d.x ?? 0},${d.y ?? 0})`);
    });

    return () => { sim.stop(); };
  }, [data]);

  // ── Combined filter: highlightType + riskFilter ───────────────────────────
  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);

    svg.selectAll<SVGGElement, unknown>("g[data-label]").attr("opacity", function() {
      const el      = this as Element;
      const lbl     = el.getAttribute("data-label") ?? "";
      const riskAttr = el.getAttribute("data-risk") ?? "";

      // Type-highlight filter
      const typeOk = !highlightType || lbl === highlightType;

      // Risk-level filter (only applies to nodes that have a risk attribute)
      const riskOk = !riskFilter || !riskAttr || riskIndex(riskAttr) >= riskFilter;

      return typeOk && riskOk ? 1 : 0.06;
    });

    svg.selectAll<SVGLineElement, unknown>("line").attr("opacity",
      highlightType || riskFilter ? 0.08 : 0.4
    );
  }, [highlightType, riskFilter]);

  // ── Run scan on an asset node ─────────────────────────────────────────────
  const runScan = useCallback(async (node: GraphNode) => {
    const assetId = parseInt(node.id.replace("asset-", ""), 10);
    if (isNaN(assetId)) return;
    setContextMenu(null);
    setScanningId(assetId);
    try {
      await apiFetch("/api/pipeline-run", { method: "POST", body: JSON.stringify({ assetId }) });
    } catch {}
    setScanningId(null);
  }, []);

  // ── Zoom helpers ─────────────────────────────────────────────────────────
  const zoomBy = (factor: number) => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(280).call(zoomRef.current.scaleBy, factor);
  };
  const fitView = () => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current).transition().duration(380).call(
      zoomRef.current.transform,
      d3.zoomIdentity.translate(60, 50).scale(0.82),
    );
  };

  // ── Legend entries ────────────────────────────────────────────────────────
  const legend = data
    ? Array.from(
        new Map(
          data.nodes.map(n => [
            n.labels[0]?.toLowerCase() ?? "other",
            { type: n.labels[0]?.toLowerCase() ?? "other", color: nodeColor(n) },
          ])
        ).values()
      ).map(e => ({
        ...e,
        count: data.nodes.filter(n => n.labels[0]?.toLowerCase() === e.type).length,
      }))
    : [];

  // ── Context menu actions ──────────────────────────────────────────────────
  function contextActions(node: GraphNode): { label: string; icon: React.ReactNode; action: () => void }[] {
    const lbl = node.labels[0]?.toLowerCase();
    const actions: { label: string; icon: React.ReactNode; action: () => void }[] = [];

    if (lbl !== "port" && lbl !== "cve" && lbl !== "vulnerability" && lbl !== "finding" && lbl !== "organization") {
      const assetId = node.id.replace("asset-", "");
      if (!isNaN(parseInt(assetId, 10))) {
        actions.push({
          label: "View Asset",
          icon: <ExternalLink className="w-3 h-3" />,
          action: () => { setContextMenu(null); navigate(`/assets/${assetId}`); },
        });
        actions.push({
          label: scanningId === parseInt(assetId, 10) ? "Scanning…" : "Run Scan",
          icon: <Scan className="w-3 h-3" />,
          action: () => runScan(node),
        });
      }
    }

    if (lbl === "vulnerability" || lbl === "finding") {
      const findingId = node.id.replace("finding-", "");
      actions.push({
        label: "View Finding",
        icon: <ExternalLink className="w-3 h-3" />,
        action: () => { setContextMenu(null); navigate(`/findings/${findingId}`); },
      });
    }

    if (lbl === "cve" && node.properties.nvdUrl) {
      actions.push({
        label: "Open in NVD",
        icon: <ExternalLink className="w-3 h-3" />,
        action: () => { setContextMenu(null); window.open(node.properties.nvdUrl, "_blank", "noopener"); },
      });
    }

    return actions;
  }

  // ── Render ────────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-60" />
        <div className="flex gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-5 w-24" />)}
        </div>
        <Skeleton className="h-[640px] w-full rounded-xl" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-3 text-sm">
        <p className="text-destructive">Failed to load graph: {error}</p>
        <Button size="sm" variant="outline" onClick={fetchData}><RefreshCw className="w-3.5 h-3.5 mr-1.5" />Retry</Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Attack Surface Graph</h1>
          <p className="text-sm text-muted-foreground">
            Interactive graph — drag to rearrange, scroll to zoom, right-click nodes for actions
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {/* Live SSE indicator */}
          <span
            className={`flex items-center gap-1 text-xs px-2 py-1 rounded-md border ${
              sseConnected
                ? "bg-green-500/10 border-green-500/30 text-green-600 dark:text-green-400"
                : "bg-muted/30 border-border text-muted-foreground"
            }`}
            title={sseConnected ? "Live auto-refresh active — graph updates when scans complete" : "Not connected to live stream"}
          >
            {sseConnected
              ? <><Wifi className="w-3 h-3" /><span className="hidden sm:inline">Live</span></>
              : <><WifiOff className="w-3 h-3" /><span className="hidden sm:inline">Offline</span></>}
          </span>
          <Button size="sm" variant="outline" onClick={fetchData}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />Refresh
          </Button>
        </div>
      </div>

      {/* Stats */}
      {data && (
        <div className="flex flex-wrap gap-5 text-sm">
          {([
            { label: "Assets",        value: data.meta.assetCount,        color: "#3b82f6" },
            { label: "Findings",      value: data.meta.findingCount,      color: "#ef4444" },
            { label: "CVEs",          value: data.meta.cveCount,          color: "#f97316" },
            { label: "Relationships", value: data.meta.relationshipCount, color: "#6b7280" },
          ] as const).map(s => (
            <div key={s.label} className="flex items-center gap-1.5">
              <span className="inline-block w-2 h-2 rounded-full" style={{ background: s.color }} />
              <span className="font-semibold tabular-nums">{s.value}</span>
              <span className="text-muted-foreground">{s.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Controls row: Legend + Risk filter */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Node type legend / filter */}
        <div className="flex flex-wrap gap-2">
          {legend.map(({ type, color, count }) => (
            <button
              key={type}
              onClick={() => setHighlight(hl => hl === type ? null : type)}
              className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-md border transition-colors ${
                highlightType === type
                  ? "bg-primary/10 border-primary/40"
                  : "bg-muted/30 border-border hover:bg-muted/60"
              }`}
            >
              <div className="w-2.5 h-2.5 rounded-full border" style={{ background: `${color}30`, borderColor: color }} />
              <span className="capitalize">{type}</span>
              <span className="font-semibold">({count})</span>
            </button>
          ))}
        </div>

        {/* Risk-level filter slider */}
        <div className="flex items-center gap-2 ml-auto shrink-0">
          <span className="text-xs text-muted-foreground whitespace-nowrap">Risk:</span>
          <input
            type="range"
            min={0}
            max={4}
            step={1}
            value={riskFilter}
            onChange={e => setRiskFilter(Number(e.target.value))}
            className="w-28 accent-primary cursor-pointer"
            title="Filter nodes by minimum risk level"
          />
          <span
            className={`text-xs font-medium min-w-[70px] ${
              riskFilter === 4 ? "text-red-500"    :
              riskFilter === 3 ? "text-orange-500" :
              riskFilter === 2 ? "text-yellow-600" :
              riskFilter === 1 ? "text-blue-500"   : "text-muted-foreground"
            }`}
          >
            {RISK_LABELS[riskFilter]}
          </span>
        </div>
      </div>

      {/* Graph canvas */}
      <div
        className="relative bg-card border border-border rounded-xl overflow-hidden select-none"
        onClick={() => setContextMenu(null)}
      >
        {/* Zoom controls */}
        <div className="absolute top-3 right-3 z-10 flex flex-col gap-1">
          {([
            { label: "+", title: "Zoom in",  fn: () => zoomBy(1.45) },
            { label: "−", title: "Zoom out", fn: () => zoomBy(0.69) },
            { label: "⊡", title: "Fit view", fn: fitView },
          ] as const).map(b => (
            <button
              key={b.title}
              onClick={b.fn}
              title={b.title}
              className="w-7 h-7 rounded border border-border bg-card/80 backdrop-blur-sm text-sm font-bold text-muted-foreground hover:text-foreground hover:bg-accent flex items-center justify-center transition-colors"
            >
              {b.label}
            </button>
          ))}
        </div>

        <svg
          ref={svgRef}
          width="100%"
          height={640}
          style={{ display: "block" }}
        />

        {/* Hover tooltip */}
        {tooltip && (
          <div
            className="absolute z-20 pointer-events-none bg-popover border border-border/70 rounded-lg shadow-xl p-3 text-xs max-w-[230px] space-y-0.5"
            style={{ left: tooltip.x + 14, top: Math.max(8, tooltip.y - 20) }}
          >
            <p className="font-semibold text-[11px] mb-1.5 text-foreground">
              {tooltip.node.labels.join(" · ")}
            </p>
            {Object.entries(tooltip.node.properties)
              .filter(([k, v]) => v != null && v !== "" && !["tenantId", "assetId", "virtual", "nvdUrl"].includes(k))
              .slice(0, 8)
              .map(([k, v]) => (
                <div key={k} className="flex gap-1 min-w-0">
                  <span className="text-muted-foreground capitalize shrink-0">
                    {k.replace(/([A-Z])/g, " $1").trim()}:
                  </span>
                  <span className="font-mono truncate">{String(v)}</span>
                </div>
              ))}
          </div>
        )}

        {/* Right-click context menu */}
        {contextMenu && (() => {
          const actions = contextActions(contextMenu.node);
          if (actions.length === 0) return null;
          return (
            <div
              className="absolute z-30 bg-popover border border-border rounded-lg shadow-2xl p-1 text-xs min-w-[160px]"
              style={{ left: contextMenu.x, top: contextMenu.y }}
              onClick={e => e.stopPropagation()}
            >
              <div className="px-2 py-1 text-[10px] text-muted-foreground font-medium uppercase tracking-wide border-b border-border mb-1">
                {contextMenu.node.labels[0]}
              </div>
              {actions.map(a => (
                <button
                  key={a.label}
                  onClick={a.action}
                  className="w-full flex items-center gap-2 px-2 py-1.5 rounded hover:bg-accent text-left transition-colors"
                >
                  {a.icon}
                  {a.label}
                </button>
              ))}
            </div>
          );
        })()}

        {data?.nodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-muted-foreground text-sm">
            No assets yet — add assets to visualize your attack surface
          </div>
        )}
      </div>

      {/* Selected node detail panel */}
      {selected && (
        <div className="bg-card border border-border rounded-xl p-4 animate-in slide-in-from-bottom-2 duration-200">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full border"
                style={{ background: `${nodeColor(selected)}25`, borderColor: nodeColor(selected) }}
              />
              <h3 className="text-sm font-semibold">{selected.labels.join(" / ")}</h3>
            </div>
            <div className="flex items-center gap-2">
              {/* Asset actions in detail panel */}
              {selected.labels[0]?.toLowerCase() !== "port" &&
               selected.labels[0]?.toLowerCase() !== "organization" &&
               !isNaN(parseInt(selected.id.replace("asset-", ""), 10)) &&
               selected.id.startsWith("asset-") && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7 text-xs"
                  onClick={() => navigate(`/assets/${selected.id.replace("asset-", "")}`)}
                >
                  <ExternalLink className="w-3 h-3 mr-1" />View Asset
                </Button>
              )}
              {selected.labels[0]?.toLowerCase() === "cve" && selected.properties.nvdUrl && (
                <a
                  href={selected.properties.nvdUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-orange-500 hover:text-orange-400 border border-orange-500/30 rounded px-2 py-1 hover:bg-orange-500/5 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />NVD
                </a>
              )}
              <button
                onClick={() => setSelected(null)}
                className="text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                ✕ close
              </button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
            {Object.entries(selected.properties)
              .filter(([k, v]) => v != null && v !== "" && !["tenantId", "assetId", "virtual"].includes(k))
              .map(([k, v]) => {
                const isUrl = k === "nvdUrl" && typeof v === "string" && v.startsWith("http");
                return (
                  <div key={k} className="bg-accent/40 rounded-lg p-2.5">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">
                      {k.replace(/([A-Z])/g, " $1").trim()}
                    </p>
                    {isUrl ? (
                      <a
                        href={v as string}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs font-mono text-orange-500 hover:underline break-all leading-relaxed flex items-center gap-1"
                      >
                        <ExternalLink className="w-3 h-3 shrink-0" />NVD Link
                      </a>
                    ) : (
                      <p className="text-xs font-mono break-all leading-relaxed">{String(v)}</p>
                    )}
                  </div>
                );
              })}
          </div>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Neo4j-compatible schema · {data?.meta.nodeCount ?? 0} nodes · {data?.meta.relationshipCount ?? 0} relationships ·
        Right-click nodes for actions · Risk slider dims nodes below threshold
      </p>
    </div>
  );
}
