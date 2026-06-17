import { useEffect, useRef, useMemo } from "react";
import { useListAssets } from "@workspace/api-client-react";
import { Skeleton } from "@/components/ui/skeleton";

interface Node {
  id: number;
  label: string;
  type: string;
  value: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

interface Edge {
  source: number;
  target: number;
  label: string;
}

const TYPE_COLOR: Record<string, string> = {
  domain:   "#6366f1",
  ip:       "#14b8a6",
  host:     "#f59e0b",
  cloud:    "#3b82f6",
  api:      "#a855f7",
  database: "#ec4899",
  service:  "#10b981",
  other:    "#6b7280",
};

const TYPE_RADIUS: Record<string, number> = {
  domain: 22, ip: 18, host: 18, cloud: 20,
  api: 16, database: 18, service: 16, other: 14,
};

function inferEdges(nodes: Node[]): Edge[] {
  const edges: Edge[] = [];
  const domains = nodes.filter(n => n.type === "domain");
  const ips     = nodes.filter(n => n.type === "ip");
  const others  = nodes.filter(n => n.type !== "domain" && n.type !== "ip");

  // subdomain → parent domain
  for (const sub of nodes) {
    for (const dom of domains) {
      if (sub.id !== dom.id && sub.value.endsWith(`.${dom.value}`)) {
        edges.push({ source: dom.id, target: sub.id, label: "subdomain" });
      }
    }
  }

  // service/host hosted at ip (naive: pair by creation order)
  for (let i = 0; i < Math.min(ips.length, others.length); i++) {
    edges.push({ source: ips[i].id, target: others[i].id, label: "hosted-at" });
  }

  // api → domain (if domain count > 0)
  const apis = nodes.filter(n => n.type === "api");
  for (let i = 0; i < apis.length && i < domains.length; i++) {
    if (!edges.find(e => (e.source === apis[i].id || e.target === apis[i].id))) {
      edges.push({ source: domains[i % domains.length].id, target: apis[i].id, label: "exposes" });
    }
  }

  return edges;
}

function forceLayout(nodes: Node[], edges: Edge[], width: number, height: number, iterations = 200) {
  const cx = width / 2, cy = height / 2;
  const k = Math.sqrt((width * height) / (nodes.length || 1));

  for (let iter = 0; iter < iterations; iter++) {
    // repulsion
    for (let i = 0; i < nodes.length; i++) {
      nodes[i].vx = 0; nodes[i].vy = 0;
      for (let j = 0; j < nodes.length; j++) {
        if (i === j) continue;
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
        const f = (k * k) / d;
        nodes[i].vx += (dx / d) * f;
        nodes[i].vy += (dy / d) * f;
      }
    }
    // attraction
    for (const e of edges) {
      const s = nodes.find(n => n.id === e.source);
      const t = nodes.find(n => n.id === e.target);
      if (!s || !t) continue;
      const dx = t.x - s.x, dy = t.y - s.y;
      const d = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const f = (d * d) / k;
      const fx = (dx / d) * f * 0.5;
      const fy = (dy / d) * f * 0.5;
      s.vx += fx; s.vy += fy;
      t.vx -= fx; t.vy -= fy;
    }
    // gravity
    for (const n of nodes) {
      n.vx += (cx - n.x) * 0.01;
      n.vy += (cy - n.y) * 0.01;
    }
    // integrate
    const cool = 1 - iter / iterations;
    for (const n of nodes) {
      const speed = Math.sqrt(n.vx * n.vx + n.vy * n.vy);
      const limit = k * cool * 0.5;
      if (speed > limit) { n.vx = (n.vx / speed) * limit; n.vy = (n.vy / speed) * limit; }
      n.x = Math.max(40, Math.min(width - 40, n.x + n.vx));
      n.y = Math.max(40, Math.min(height - 40, n.y + n.vy));
    }
  }
}

export default function AssetTopologyPage() {
  const svgRef = useRef<SVGSVGElement>(null);
  const W = 900, H = 600;

  const { data: assets, isLoading } = useListAssets({} as any);
  const assetList = (assets as any[]) ?? [];

  const { nodes, edges } = useMemo(() => {
    if (!assetList.length) return { nodes: [], edges: [] };
    const nodes: Node[] = assetList.map((a: any, i: number) => ({
      id: a.id,
      label: a.name ?? a.value ?? `Asset ${a.id}`,
      type: a.type ?? "other",
      value: a.value ?? "",
      x: W / 2 + (Math.cos((i / assetList.length) * Math.PI * 2) * W * 0.3),
      y: H / 2 + (Math.sin((i / assetList.length) * Math.PI * 2) * H * 0.3),
      vx: 0, vy: 0,
    }));
    const edges = inferEdges(nodes);
    forceLayout(nodes, edges, W, H);
    return { nodes, edges };
  }, [assetList.length]);

  const typeGroups = useMemo(() => {
    const groups: Record<string, number> = {};
    for (const n of nodes) groups[n.type] = (groups[n.type] ?? 0) + 1;
    return groups;
  }, [nodes]);

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[600px] w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold">Asset Topology</h1>
        <p className="text-sm text-muted-foreground">Visual map of your assets and their relationships</p>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-3">
        {Object.entries(typeGroups).map(([type, count]) => (
          <div key={type} className="flex items-center gap-1.5 text-xs">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: TYPE_COLOR[type] ?? "#6b7280" }} />
            <span className="capitalize text-muted-foreground">{type}</span>
            <span className="text-foreground font-medium">({count})</span>
          </div>
        ))}
      </div>

      {/* Graph */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 600 }}>
          <defs>
            <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
              <path d="M0,0 L0,6 L6,3 z" fill="#6b7280" opacity="0.4" />
            </marker>
          </defs>

          {/* Edges */}
          {edges.map((e, i) => {
            const s = nodes.find(n => n.id === e.source);
            const t = nodes.find(n => n.id === e.target);
            if (!s || !t) return null;
            const mx = (s.x + t.x) / 2, my = (s.y + t.y) / 2;
            return (
              <g key={i}>
                <line
                  x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke="#6b7280" strokeOpacity="0.25" strokeWidth="1.5"
                  markerEnd="url(#arrow)"
                />
                <text x={mx} y={my - 4} textAnchor="middle" fontSize="9" fill="#6b7280" opacity="0.6">{e.label}</text>
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map(n => {
            const color = TYPE_COLOR[n.type] ?? "#6b7280";
            const r = TYPE_RADIUS[n.type] ?? 14;
            const shortLabel = n.label.length > 14 ? n.label.slice(0, 13) + "…" : n.label;
            return (
              <g key={n.id}>
                <circle
                  cx={n.x} cy={n.y} r={r}
                  fill={color} fillOpacity="0.18"
                  stroke={color} strokeWidth="1.5" strokeOpacity="0.8"
                />
                <text x={n.x} y={n.y + 3} textAnchor="middle" fontSize="9" fontWeight="600"
                  fill={color} paintOrder="stroke" stroke="hsl(var(--background))" strokeWidth="3">
                  {n.type.slice(0, 2).toUpperCase()}
                </text>
                <text x={n.x} y={n.y + r + 12} textAnchor="middle" fontSize="9" fill="hsl(var(--foreground))"
                  opacity="0.75" paintOrder="stroke" stroke="hsl(var(--background))" strokeWidth="3">
                  {shortLabel}
                </text>
              </g>
            );
          })}

          {nodes.length === 0 && (
            <text x={W / 2} y={H / 2} textAnchor="middle" fontSize="14" fill="#6b7280">
              No assets found
            </text>
          )}
        </svg>
      </div>

      <p className="text-xs text-muted-foreground">
        {nodes.length} assets · {edges.length} inferred relationships · Edges auto-detected from domain/subdomain patterns and asset types
      </p>
    </div>
  );
}
