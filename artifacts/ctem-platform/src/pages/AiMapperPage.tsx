import { useEffect, useRef, useState } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { getToken } from "@/lib/auth";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { Server, ShieldOff, AlertTriangle, Activity, Scan, Globe2, Loader2, Download } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";

interface GlobePoint {
  id: number; ip: string; port: number; lat: number; lng: number;
  protocol: string; riskScore: number; riskLevel: string;
  authStatus: string; country?: string; color: string; altitude: number;
}

interface Stats {
  total: number; critical: number; high: number; noAuth: number; activeScans: number;
}

const PROTOCOL_LEGEND = [
  { label: "MCP Server",  color: "#3b82f6" },
  { label: "Ollama",      color: "#22c55e" },
  { label: "vLLM",        color: "#a855f7" },
  { label: "LangServe",   color: "#f97316" },
  { label: "Gradio",      color: "#ec4899" },
  { label: "LiteLLM",     color: "#a855f7" },
  { label: "ComfyUI",     color: "#f59e0b" },
  { label: "Generic",     color: "#ef4444" },
];

function AiMapperGlobe({ points }: { points: GlobePoint[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const globeRef     = useRef<any>(null);
  const [, navigate] = useLocation();

  useEffect(() => {
    if (!containerRef.current || !points.length) return;
    let cancelled = false;
    (async () => {
      try {
        const GlobeLib = (await import("globe.gl")).default;
        if (cancelled || !containerRef.current) return;
        const el = containerRef.current;
        const globe = (GlobeLib as any)()(el);
        globeRef.current = globe;
        globe
          .globeImageUrl("//unpkg.com/three-globe/example/img/earth-night.jpg")
          .backgroundColor("rgba(0,0,0,0)")
          .width(el.clientWidth)
          .height(el.clientHeight)
          .pointsData(points)
          .pointLat("lat").pointLng("lng").pointColor("color")
          .pointAltitude("altitude").pointRadius(0.5)
          .pointLabel((d: GlobePoint) => `
            <div style="background:rgba(15,23,42,0.95);padding:10px 12px;border-radius:6px;border:1px solid rgba(99,102,241,0.4);min-width:180px">
              <div style="font-family:monospace;font-weight:700;color:#e2e8f0;margin-bottom:6px">${d.ip}:${d.port}</div>
              <div style="color:${d.color};font-size:11px;margin-bottom:2px">Protocol: ${d.protocol}</div>
              <div style="font-size:11px;color:#94a3b8">Risk: <span style="color:${d.riskLevel==="critical"?"#ef4444":d.riskLevel==="high"?"#f97316":"#eab308"}">${d.riskLevel.toUpperCase()} (${d.riskScore}/10)</span></div>
              <div style="font-size:11px;color:#94a3b8">Auth: ${d.authStatus==="none"?'<span style="color:#ef4444">NONE</span>':d.authStatus}</div>
              ${d.country?`<div style="font-size:11px;color:#94a3b8">Country: ${d.country}</div>`:""}
              <div style="font-size:10px;color:#4b5563;margin-top:4px">Click to inspect →</div>
            </div>
          `)
          .onPointClick((d: GlobePoint) => navigate(`/ai-mapper/endpoints/${d.id}`));
        globe.controls().autoRotate = true;
        globe.controls().autoRotateSpeed = 0.3;
        globe.controls().enableDamping = true;
      } catch { /* globe.gl unavailable */ }
    })();
    return () => { cancelled = true; globeRef.current = null; };
  }, [points.length]);

  useEffect(() => {
    if (globeRef.current && points.length) globeRef.current.pointsData(points);
  }, [points]);

  return <div ref={containerRef} className="w-full h-full" />;
}

async function downloadReport(format: "csv" | "pdf", toast: ReturnType<typeof useToast>["toast"]) {
  const token = getToken();
  try {
    const res = await fetch(`/api/ai-mapper/reports/${format}`, {
      headers: { Authorization: `Bearer ${token ?? ""}` },
    });
    if (!res.ok) {
      toast({ title: `Export failed (${res.status})`, description: "Could not generate report. Check your permissions.", variant: "destructive" });
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ai-mapper-report-${new Date().toISOString().slice(0, 10)}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    toast({ title: "Export failed", description: "Network error during export.", variant: "destructive" });
  }
}

export default function AiMapperPage() {
  const [, navigate] = useLocation();
  const { aiMapperEnabled, user } = useAuth();
  const { toast } = useToast();
  const [csvLoading, setCsvLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const role = user?.role ?? "";
  const isAdmin = role === "admin" || role === "super_admin";

  const { data: stats } = useQuery<Stats>({
    queryKey: ["ai-mapper-stats"],
    queryFn: () => apiFetch("/api/ai-mapper/stats"),
    refetchInterval: 30_000,
    enabled: aiMapperEnabled,
  });

  const { data: globePoints = [], isLoading: globeLoading } = useQuery<GlobePoint[]>({
    queryKey: ["ai-mapper-globe"],
    queryFn: () => apiFetch("/api/ai-mapper/globe"),
    refetchInterval: 30_000,
    enabled: aiMapperEnabled,
  });

  const STAT_CARDS = [
    { label: "Total Endpoints",    value: stats?.total           ?? 0, icon: Server,        color: "text-blue-400" },
    { label: "Critical",           value: stats?.critical         ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "High Risk",          value: stats?.high             ?? 0, icon: ShieldOff,     color: "text-orange-400" },
    { label: "No Auth",            value: stats?.noAuth           ?? 0, icon: ShieldOff,     color: "text-yellow-400" },
    { label: "Prompt Leaks",       value: (stats as any)?.systemPromptLeaks ?? 0, icon: AlertTriangle, color: "text-purple-400" },
    { label: "Active Scans",       value: stats?.activeScans      ?? 0, icon: Activity,      color: "text-green-400" },
  ];

  return (
    <div className="flex flex-col h-[calc(100vh-56px)] p-6 gap-5 w-full">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold">AI Mapper — Overview</h1>
            {isAdmin && (
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-400 border border-purple-500/30">
                All Tenants
              </span>
            )}
          </div>
          <p className="text-sm text-muted-foreground">Exposed AI infrastructure discovered across the internet</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => navigate("/ai-mapper/scan-schedules")}>
            <Activity className="w-4 h-4 mr-2" /> Schedules
          </Button>
          <Button variant="outline" size="sm" disabled={csvLoading} onClick={async () => { setCsvLoading(true); await downloadReport("csv", toast); setCsvLoading(false); }}>
            {csvLoading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Download className="w-4 h-4 mr-2" />}
            Export CSV
          </Button>
          <Button variant="outline" size="sm" disabled={pdfLoading} onClick={async () => { setPdfLoading(true); await downloadReport("pdf", toast); setPdfLoading(false); }}>
            {pdfLoading ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Download className="w-4 h-4 mr-2" />}
            Export PDF
          </Button>
          <Button variant="outline" size="sm" onClick={() => navigate("/ai-mapper/endpoints")}>
            <Server className="w-4 h-4 mr-2" /> Endpoints
          </Button>
          <Button size="sm" onClick={() => navigate("/ai-mapper/scans")}>
            <Scan className="w-4 h-4 mr-2" /> Run Scan
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-6 gap-3">
        {STAT_CARDS.map(s => (
          <Card key={s.label}>
            <CardContent className="py-4 px-4">
              <div className="flex items-center gap-2 mb-1">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-muted-foreground">{s.label}</span>
              </div>
              <p className="text-2xl font-bold">{s.value.toLocaleString()}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="relative flex-1 rounded-xl border border-border overflow-hidden bg-[#020b18] min-h-64">
        {globeLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <Loader2 className="w-8 h-8 animate-spin text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">Loading globe…</p>
            </div>
          </div>
        ) : globePoints.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <Globe2 className="w-12 h-12 mx-auto mb-3 text-muted-foreground opacity-30" />
              <p className="text-sm font-medium text-muted-foreground">No geo-located endpoints yet</p>
              <p className="text-xs text-muted-foreground mt-1">Run a scan with Shodan to see endpoints on the globe</p>
              <Button className="mt-4" size="sm" onClick={() => navigate("/ai-mapper/scans")}>
                Start Scan
              </Button>
            </div>
          </div>
        ) : (
          <AiMapperGlobe points={globePoints} />
        )}

        <div className="absolute bottom-4 left-4 bg-black/60 backdrop-blur-sm rounded-lg p-2.5 border border-white/10">
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Protocol</p>
          <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
            {PROTOCOL_LEGEND.map(p => (
              <div key={p.label} className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full shrink-0" style={{ background: p.color }} />
                <span className="text-xs text-slate-300">{p.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="absolute bottom-4 right-4 bg-black/60 backdrop-blur-sm rounded-lg p-2.5 border border-white/10">
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Risk (altitude)</p>
          {[
            { label: "Critical 9–10", color: "#ef4444" },
            { label: "High 7–9",      color: "#f97316" },
            { label: "Medium 4–7",    color: "#eab308" },
            { label: "Low 0–4",       color: "#22c55e" },
          ].map(r => (
            <div key={r.label} className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full shrink-0" style={{ background: r.color }} />
              <span className="text-xs text-slate-300">{r.label}</span>
            </div>
          ))}
        </div>

        {globePoints.length > 0 && (
          <div className="absolute top-4 left-1/2 -translate-x-1/2 bg-black/60 backdrop-blur-sm rounded-full px-3 py-1 border border-white/10">
            <p className="text-xs text-slate-300">{globePoints.length} endpoints · click a pin to inspect</p>
          </div>
        )}
      </div>
    </div>
  );
}
