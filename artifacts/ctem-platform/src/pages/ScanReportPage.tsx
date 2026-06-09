import { useState, useEffect, useRef } from "react";
import { useParams, Link } from "wouter";
import {
  useGetScanAssetReport, useGetScan, useStopScan,
  getGetScanQueryKey, getGetScanAssetReportQueryKey,
  useListAssetScreenshots, getListAssetScreenshotsQueryKey,
  useListAssetTechnologies, getListAssetTechnologiesQueryKey,
} from "@workspace/api-client-react";
import {
  ChevronLeft, ChevronDown, ChevronRight, Shield, Globe, Network, AlertTriangle, Server,
  Database, Search, Cpu, Eye, CheckCircle2, XCircle, AlertCircle,
  Info, ExternalLink, Terminal, Wifi, Square, Loader2, Clock, Key,
  Lock, Fingerprint, Download, Camera, X, Tag,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import { downloadAsPdf } from "@/lib/generatePdf";

type AssetTab = "ports" | "vulns" | "subdomains" | "http" | "dns" | "endpoints" | "intel" | "secrets" | "raw" | "screenshots" | "technologies";

function downloadScanReportPdf(scan: any, assetReports: any[]) {
  const ts = scan?.completedAt ? new Date(scan.completedAt).toLocaleString() : new Date().toLocaleString();
  const totalFindings = assetReports.reduce((a: number, r: any) => a + (r.summary?.vulnerabilities ?? 0), 0);

  const sections: { title?: string; lines: string[] }[] = [
    {
      lines: [
        `Report Name: ${scan?.name ?? `Scan #${scan?.id}`}`,
        `Completed: ${ts}`,
        `Assets Scanned: ${assetReports.length}`,
        `Total Findings: ${totalFindings}`,
        "---",
      ],
    },
  ];

  for (const asset of assetReports) {
    const s = asset.summary ?? {};
    const assetLines: string[] = [
      `Asset: ${asset.assetName} (${asset.assetValue})`,
      `Open Ports: ${s.openPorts ?? 0}`,
      `Vulnerabilities: ${s.vulnerabilities ?? 0}  (Critical: ${s.criticalVulns ?? 0}, High: ${s.highVulns ?? 0})`,
      `Subdomains: ${s.subdomains ?? 0}`,
      `DNS Records: ${s.dnsRecords ?? 0}`,
      `Endpoints: ${s.endpoints ?? 0}`,
    ];

    const cves: any[] = asset.cves ?? [];
    if (cves.length > 0) {
      assetLines.push("---", "CVEs Found (top 10):");
      cves.slice(0, 10).forEach((c: any) => {
        assetLines.push(`  • ${c.cveId ?? "—"}  [${c.severity?.toUpperCase() ?? "?"}]  CVSS: ${c.cvss ?? "—"}  ${c.title ?? ""}`);
      });
    }

    sections.push({ title: `Asset: ${asset.assetName}`, lines: assetLines });
  }

  const safeName = (scan?.name ?? `scan-${scan?.id}`).replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  downloadAsPdf(`${safeName}.pdf`, scan?.name ?? `Scan #${scan?.id}`, sections);
}

const severityConfig = {
  critical: { cls: "bg-red-500/15 text-red-400 border-red-500/40", icon: XCircle },
  high: { cls: "bg-orange-500/15 text-orange-400 border-orange-500/40", icon: AlertTriangle },
  medium: { cls: "bg-yellow-500/15 text-yellow-400 border-yellow-500/40", icon: AlertCircle },
  low: { cls: "bg-blue-500/15 text-blue-400 border-blue-500/40", icon: Info },
  info: { cls: "bg-muted text-muted-foreground border-border", icon: Info },
};

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = severityConfig[severity as keyof typeof severityConfig] ?? severityConfig.info;
  return (
    <span className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase tracking-wide", cfg.cls)}>
      {severity}
    </span>
  );
}

function formatDuration(startMs: number, endMs: number): string {
  const totalSec = Math.max(0, Math.round((endMs - startMs) / 1000));
  if (totalSec < 60) return `${totalSec}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

function formatMs(ms: number | null): string {
  if (ms === null) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`;
}

function StatCard({ icon: Icon, label, value, className }: { icon: React.ElementType; label: string; value: number | string; className?: string }) {
  return (
    <div className={cn("bg-card border border-border rounded-xl p-4 flex items-center gap-3", className)}>
      <div className="w-9 h-9 rounded-lg bg-accent/60 flex items-center justify-center shrink-0">
        <Icon className="w-4.5 h-4.5 text-primary" />
      </div>
      <div>
        <p className="text-lg font-bold leading-tight">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </div>
  );
}

interface ToolProgress {
  toolName: string;
  toolCategory: string;
  phase: number;
  status: "queued" | "running" | "done" | "failed";
  startedAt: string | null;
  completedAt: string | null;
  durationMs: number | null;
  findingsCount: number;
  detail: string;
}
interface AssetProgress {
  assetId: number;
  assetName: string;
  assetValue: string;
  tools: ToolProgress[];
}

const PHASE_NAMES: Record<number, string> = {
  1: "Recon & OSINT",
  2: "Port Scanning",
  3: "Web Recon",
  4: "Vuln & Secrets",
  5: "SSL/TLS Analysis",
};

const PHASE_COLORS: Record<number, string> = {
  1: "text-violet-400 bg-violet-500/10 border-violet-500/30",
  2: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  3: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
  4: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  5: "text-green-400 bg-green-500/10 border-green-500/30",
};

function ToolStatusIcon({ status }: { status: ToolProgress["status"] }) {
  if (status === "running") return <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin shrink-0" />;
  if (status === "done") return <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />;
  if (status === "failed") return <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />;
  return <div className="w-3.5 h-3.5 rounded-full border border-border bg-muted/40 shrink-0" />;
}

function LiveProgressView({
  scanId,
  scanStatus,
  scan,
  stopping,
  onStop,
}: {
  scanId: number;
  scanStatus: string;
  scan: any;
  stopping: boolean;
  onStop: () => void;
}) {
  const [progress, setProgress] = useState<AssetProgress[]>([]);
  const [selectedAssetIdx, setSelectedAssetIdx] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const token = sessionStorage.getItem("access_token");

    async function fetchProgress() {
      try {
        const res = await fetch(`/api/scans/${scanId}/progress`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data)) setProgress(data);
        }
      } catch {}
    }

    fetchProgress();
    intervalRef.current = setInterval(fetchProgress, 2000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [scanId]);

  const selectedAsset = progress[selectedAssetIdx] ?? progress[0];
  const tools = selectedAsset?.tools ?? [];

  const phaseGroups = [1, 2, 3, 4, 5].map(phase => ({
    phase,
    name: PHASE_NAMES[phase],
    tools: tools.filter(t => t.phase === phase),
  })).filter(g => g.tools.length > 0);

  const totalTools = tools.length;
  const doneTools = tools.filter(t => t.status === "done" || t.status === "failed").length;
  const runningTools = tools.filter(t => t.status === "running").length;
  const pct = totalTools > 0 ? Math.round((doneTools / totalTools) * 100) : 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link href="/scan-reports">
          <button className="w-8 h-8 rounded-lg bg-accent/60 hover:bg-accent flex items-center justify-center transition-colors">
            <ChevronLeft className="w-4 h-4" />
          </button>
        </Link>
        <div>
          <h1 className="text-lg font-semibold">Pipeline Scan Report #{scanId}</h1>
          <p className="text-xs text-muted-foreground">Scan in progress — live tool execution</p>
        </div>
        <div className="ml-auto flex items-center gap-2">
          <Button
            size="sm" variant="outline"
            className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/10"
            onClick={onStop} disabled={stopping}
          >
            {stopping ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Square className="w-3 h-3 mr-1 fill-current" />}
            Stop Scan
          </Button>
          <div className="flex items-center gap-1.5 bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs px-2.5 py-1 rounded-full">
            <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
          </div>
        </div>
      </div>

      <div className="flex gap-4 items-start">
        {/* Asset list */}
        {progress.length > 0 && (
          <div className="w-52 shrink-0 space-y-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide px-1 mb-2">Assets</p>
            {progress.map((a, idx) => {
              const aDone = a.tools.filter(t => t.status === "done" || t.status === "failed").length;
              const aTotal = a.tools.length;
              const aPct = aTotal > 0 ? Math.round((aDone / aTotal) * 100) : 0;
              const aRunning = a.tools.some(t => t.status === "running");
              return (
                <button
                  key={a.assetId}
                  onClick={() => setSelectedAssetIdx(idx)}
                  className={cn(
                    "w-full text-left rounded-lg px-3 py-2.5 transition-colors border",
                    idx === selectedAssetIdx
                      ? "bg-primary/10 border-primary/30 text-foreground"
                      : "bg-card border-border text-muted-foreground hover:text-foreground hover:bg-accent/50"
                  )}
                >
                  <div className="flex items-center gap-1.5">
                    {aRunning && <Loader2 className="w-2.5 h-2.5 text-blue-400 animate-spin shrink-0" />}
                    <p className="text-sm font-medium truncate">{a.assetName}</p>
                  </div>
                  <p className="text-[10px] text-muted-foreground truncate mt-0.5">{a.assetValue}</p>
                  <div className="mt-1.5 w-full bg-muted/40 rounded-full h-1">
                    <div className="bg-primary h-1 rounded-full transition-all duration-500" style={{ width: `${aPct}%` }} />
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{aDone}/{aTotal} tools · {aPct}%</p>
                </button>
              );
            })}
          </div>
        )}

        {/* Progress content */}
        <div className="flex-1 min-w-0 space-y-3">
          {/* Overall progress bar */}
          {totalTools > 0 && (
            <div className="bg-card border border-border rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <p className="text-sm font-semibold">{selectedAsset?.assetName ?? "Loading…"}</p>
                  <p className="text-xs text-muted-foreground">{selectedAsset?.assetValue}</p>
                </div>
                <div className="text-right">
                  <p className="text-lg font-bold text-primary">{pct}%</p>
                  <p className="text-[10px] text-muted-foreground">{doneTools}/{totalTools} tools</p>
                </div>
              </div>
              <div className="w-full bg-muted/40 rounded-full h-2">
                <div className="bg-primary h-2 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
              </div>
              {runningTools > 0 && (
                <p className="text-[10px] text-blue-400 mt-1.5 flex items-center gap-1">
                  <Loader2 className="w-2.5 h-2.5 animate-spin" />
                  {runningTools} tool{runningTools > 1 ? "s" : ""} actively running
                </p>
              )}
            </div>
          )}

          {/* Phase groups */}
          {phaseGroups.length > 0 ? (
            <div className="space-y-3">
              {phaseGroups.map(group => (
                <div key={group.phase} className="bg-card border border-border rounded-xl overflow-hidden">
                  <div className={cn("flex items-center gap-2 px-4 py-2 border-b border-border/50 text-xs font-semibold", PHASE_COLORS[group.phase])}>
                    <span className="opacity-60">Phase {group.phase}</span>
                    <span>—</span>
                    <span>{group.name}</span>
                    <span className="ml-auto opacity-60">
                      {group.tools.filter(t => t.status === "done" || t.status === "failed").length}/{group.tools.length}
                    </span>
                  </div>
                  <div className="divide-y divide-border/40">
                    {group.tools.map(tool => (
                      <div key={tool.toolName} className={cn(
                        "flex items-center gap-3 px-4 py-2.5 transition-colors",
                        tool.status === "running" ? "bg-blue-500/5" : ""
                      )}>
                        <ToolStatusIcon status={tool.status} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className={cn(
                              "text-sm font-medium",
                              tool.status === "running" ? "text-blue-300" :
                              tool.status === "done" ? "text-foreground" :
                              tool.status === "failed" ? "text-red-400" :
                              "text-muted-foreground"
                            )}>
                              {tool.toolName}
                            </span>
                            {tool.status === "running" && (
                              <span className="text-[10px] bg-blue-500/15 border border-blue-500/30 text-blue-400 px-1.5 py-0.5 rounded animate-pulse">
                                RUNNING
                              </span>
                            )}
                            {tool.findingsCount > 0 && (
                              <span className="text-[10px] bg-orange-500/15 border border-orange-500/30 text-orange-400 px-1.5 py-0.5 rounded">
                                {tool.findingsCount} finding{tool.findingsCount !== 1 ? "s" : ""}
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-muted-foreground truncate mt-0.5">{tool.detail}</p>
                        </div>
                        {tool.durationMs !== null && (
                          <span className="text-[10px] text-muted-foreground shrink-0">{formatMs(tool.durationMs)}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-card border border-border rounded-xl p-14 text-center">
              <div className="w-14 h-14 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center mx-auto mb-4">
                <Loader2 className="w-7 h-7 text-primary animate-spin" />
              </div>
              <p className="text-base font-semibold">Initializing scan pipeline…</p>
              <p className="text-sm text-muted-foreground mt-1.5">Setting up tools and queuing phases</p>
              {scan?.startedAt && (
                <p className="text-xs text-muted-foreground mt-3 flex items-center justify-center gap-1">
                  <Clock className="w-3 h-3" /> Started {new Date(scan.startedAt).toLocaleTimeString()}
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function ScanReportPage() {
  const params = useParams<{ id: string }>();
  const scanId = Number(params.id);
  const [selectedAssetIdx, setSelectedAssetIdx] = useState(0);
  const [assetTab, setAssetTab] = useState<AssetTab>("ports");
  const [subdomainFilter, setSubdomainFilter] = useState<"all" | "200" | "auth" | "redirect" | "dead">("all");
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const { user } = useAuth();
  const isClient = user?.role === "client";

  const { data: scanData, refetch: refetchScan } = useGetScan(scanId, {
    query: { queryKey: getGetScanQueryKey(scanId), refetchInterval: (q) => {
      const s = (q.state.data as any)?.status;
      return s === "running" || s === "pending" ? 4000 : false;
    }},
  });
  const scan = scanData as any;
  const scanStatus: string = scan?.status ?? "unknown";

  const { data: reports, isLoading, error } = useGetScanAssetReport(scanId, {
    query: {
      queryKey: getGetScanAssetReportQueryKey(scanId),
      refetchInterval: (q) => {
        const data = q.state.data as any[];
        if (data && data.length > 0) return false;
        if (scanStatus === "running" || scanStatus === "pending") return 3000;
        return false;
      },
    },
  });
  const stopMutation = useStopScan();

  async function handleStop() {
    setStopping(true);
    try {
      await stopMutation.mutateAsync({ scanId });
      refetchScan();
    } finally {
      setStopping(false);
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-4 gap-3">{[...Array(4)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>
        <Skeleton className="h-96 rounded-xl" />
      </div>
    );
  }

  if (error || !reports) {
    return (
      <div className="bg-card border border-destructive/30 rounded-xl p-8 text-center">
        <XCircle className="w-8 h-8 text-destructive mx-auto mb-2" />
        <p className="text-sm text-muted-foreground">Failed to load scan report.</p>
        <Link href="/scan-reports" className="text-xs text-primary mt-2 inline-block">← Back to Scan Reports</Link>
      </div>
    );
  }

  if ((reports as unknown[]).length === 0) {
    if (scanStatus === "running" || scanStatus === "pending" || scanStatus === "unknown") {
      return (
        <LiveProgressView
          scanId={scanId}
          scanStatus={scanStatus}
          scan={scan}
          stopping={stopping}
          onStop={handleStop}
        />
      );
    }
    return (
      <div className="bg-card border border-border rounded-xl p-8 text-center">
        <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
        <p className="text-sm text-muted-foreground">No scan results found for this scan.</p>
        <Link href="/scan-reports" className="text-xs text-primary mt-2 inline-block">← Back to Scan Reports</Link>
      </div>
    );
  }

  const assetReports = reports as any[];
  const selectedAsset = assetReports[selectedAssetIdx] ?? assetReports[0];
  const summary = selectedAsset?.summary ?? {};

  const secretsCount = (selectedAsset?.secrets ?? []).length;
  const assetTabs: { key: AssetTab; label: string; icon: React.ElementType; count?: number }[] = [
    { key: "ports",        label: "Open Ports",    icon: Network,       count: summary.openPorts },
    { key: "vulns",        label: "CVEs",           icon: AlertTriangle, count: (selectedAsset?.cves ?? []).length },
    { key: "secrets",      label: "Secrets",        icon: Key,           count: secretsCount },
    { key: "screenshots",  label: "Screenshots",    icon: Camera },
    { key: "technologies", label: "Technologies",   icon: Cpu },
    { key: "subdomains",   label: "Subdomains",     icon: Globe,         count: summary.subdomains },
    { key: "http",         label: "HTTP Info",      icon: Wifi },
    { key: "dns",          label: "DNS Records",    icon: Database,      count: summary.dnsRecords },
    { key: "endpoints",    label: "Endpoints",      icon: Search,        count: summary.endpoints },
    { key: "intel",        label: "Intelligence",   icon: Eye,           count: summary.intelItems },
    ...(!isClient ? [{ key: "raw" as AssetTab, label: "Raw Output", icon: Terminal }] : []),
  ];

  const toolResults: any[] = selectedAsset?.toolResults ?? [];
  const configuredTools: any[] = selectedAsset?.configuredTools ?? [];
  // All tool names to show = union of configured + any extra results
  const allToolNames = Array.from(new Set([
    ...configuredTools.map((t: any) => t.name),
    ...toolResults.map((t: any) => t.toolName),
  ]));
  const displayedTool = selectedTool ?? allToolNames[0] ?? null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link href="/scan-reports">
          <button className="w-8 h-8 rounded-lg bg-accent/60 hover:bg-accent flex items-center justify-center transition-colors">
            <ChevronLeft className="w-4 h-4" />
          </button>
        </Link>
        <div>
          <h1 className="text-lg font-semibold">{scan?.name ?? `Pipeline Scan Report #${scanId}`}</h1>
          <div className="flex items-center flex-wrap gap-x-3 gap-y-0.5 mt-0.5">
            <p className="text-xs text-muted-foreground">{assetReports.length} assets · {assetReports.reduce((acc: number, a: any) => acc + (a.summary?.vulnerabilities ?? 0), 0)} total findings</p>
            {scan?.startedAt && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                Started {new Date(scan.startedAt).toLocaleString()}
              </span>
            )}
            {scan?.completedAt && scan?.startedAt && (
              <span className="text-xs text-muted-foreground">
                · Duration: <span className="text-foreground font-medium">{formatDuration(new Date(scan.startedAt).getTime(), new Date(scan.completedAt).getTime())}</span>
              </span>
            )}
            {scan?.completedAt && (
              <span className="text-xs text-muted-foreground">
                · Completed {new Date(scan.completedAt).toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {(scanStatus === "running" || scanStatus === "pending") && (
            <Button
              size="sm" variant="outline"
              className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/10"
              onClick={handleStop}
              disabled={stopping}
            >
              {stopping ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Square className="w-3 h-3 mr-1 fill-current" />}
              Stop Scan
            </Button>
          )}
          {scanStatus === "running" && (
            <div className="flex items-center gap-1.5 bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs px-2.5 py-1 rounded-full">
              <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
            </div>
          )}
          {scanStatus === "completed" && (
            <>
              <Button
                size="sm" variant="outline" className="h-7 text-xs gap-1.5"
                onClick={() => downloadScanReportPdf(scan, assetReports)}
              >
                <Download className="w-3.5 h-3.5" /> Download Report
              </Button>
              <div className="flex items-center gap-1.5 bg-green-500/10 border border-green-500/30 text-green-400 text-xs px-2.5 py-1 rounded-full">
                <CheckCircle2 className="w-3 h-3" /> Completed
              </div>
            </>
          )}
          {scanStatus === "cancelled" && (
            <div className="flex items-center gap-1.5 bg-muted border border-border text-muted-foreground text-xs px-2.5 py-1 rounded-full">
              <XCircle className="w-3 h-3" /> Cancelled
            </div>
          )}
          {(scanStatus === "pending") && (
            <div className="flex items-center gap-1.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs px-2.5 py-1 rounded-full">
              <Loader2 className="w-3 h-3 animate-spin" /> Pending…
            </div>
          )}
        </div>
      </div>

      {/* Asset tabs (left) + content (right) */}
      <div className="flex gap-4 items-start">

        {/* Asset list */}
        <div className="w-56 shrink-0 space-y-1">
          <div className="flex items-center justify-between px-1 mb-2">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Assets Scanned</p>
            {scanStatus === "running" && (
              <span className="flex items-center gap-1 text-[10px] text-blue-400">
                <Loader2 className="w-2.5 h-2.5 animate-spin" /> Live
              </span>
            )}
          </div>
          {assetReports.map((asset: any, idx: number) => {
            const critVulns = asset.summary?.criticalVulns ?? 0;
            const highVulns = asset.summary?.highVulns ?? 0;
            const secretsNum = (asset.secrets ?? []).length;
            return (
              <button
                key={asset.assetId}
                onClick={() => { setSelectedAssetIdx(idx); setAssetTab("ports"); setSelectedTool(null); }}
                className={cn(
                  "w-full text-left rounded-lg px-3 py-2.5 transition-colors border",
                  idx === selectedAssetIdx
                    ? "bg-primary/10 border-primary/30 text-foreground"
                    : "bg-card border-border text-muted-foreground hover:text-foreground hover:bg-accent/50"
                )}
              >
                <p className="text-sm font-medium truncate">{asset.assetName}</p>
                <p className="text-[10px] text-muted-foreground truncate mt-0.5">{asset.assetValue}</p>
                <div className="flex gap-1.5 mt-1.5 flex-wrap">
                  <span className="text-[10px] bg-muted/60 text-muted-foreground rounded px-1">{asset.summary?.openPorts ?? 0} ports</span>
                  {critVulns > 0 && <span className="text-[10px] bg-red-500/15 text-red-400 rounded px-1">{critVulns} crit</span>}
                  {highVulns > 0 && !critVulns && <span className="text-[10px] bg-orange-500/15 text-orange-400 rounded px-1">{highVulns} high</span>}
                  {secretsNum > 0 && <span className="text-[10px] bg-yellow-500/15 text-yellow-400 rounded px-1"><Key className="w-2 h-2 inline mr-0.5" />{secretsNum}</span>}
                </div>
              </button>
            );
          })}
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0 space-y-3">

          {/* Summary stats */}
          <div className="grid grid-cols-4 gap-3">
            <StatCard icon={Network} label="Open Ports" value={summary.openPorts ?? 0} />
            <StatCard icon={AlertTriangle} label="CVEs Found" value={(selectedAsset?.cves ?? []).length}
              className={(summary.criticalVulns ?? 0) > 0 ? "border-red-500/30" : ""} />
            <StatCard icon={Key} label="Secrets Found" value={secretsCount}
              className={secretsCount > 0 ? "border-yellow-500/30" : ""} />
            <StatCard icon={Globe} label="Subdomains" value={summary.subdomains ?? 0} />
          </div>

          {/* WAF / CDN info bar */}
          {(summary.waf || summary.cdn) && (
            <div className="bg-card border border-border rounded-xl px-4 py-2.5 flex items-center gap-4 text-xs text-muted-foreground">
              {summary.waf && summary.waf !== "none" && (
                <span className="flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-green-400" />
                  WAF: <span className="text-foreground font-medium">{summary.waf}</span>
                </span>
              )}
              {summary.cdn && (
                <span className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-blue-400" />
                  CDN: <span className="text-foreground font-medium">{summary.cdn}</span>
                </span>
              )}
              <span className="flex items-center gap-1.5 ml-auto">
                <Server className="w-3.5 h-3.5" />
                {summary.toolsRun ?? 0} tools run
              </span>
            </div>
          )}

          {/* Tabs */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="flex border-b border-border overflow-x-auto">
              {assetTabs.map(t => (
                <button
                  key={t.key}
                  onClick={() => setAssetTab(t.key)}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-2.5 text-xs whitespace-nowrap border-b-2 transition-colors shrink-0",
                    assetTab === t.key
                      ? "border-primary text-foreground font-medium"
                      : "border-transparent text-muted-foreground hover:text-foreground"
                  )}
                >
                  <t.icon className="w-3.5 h-3.5" />
                  {t.label}
                  {t.count !== undefined && t.count > 0 && (
                    <span className={cn(
                      "ml-0.5 text-[10px] rounded-full px-1.5",
                      t.key === "secrets" ? "bg-yellow-500/20 text-yellow-400" : "bg-primary/20 text-primary"
                    )}>{t.count}</span>
                  )}
                </button>
              ))}
            </div>

            <div className="p-4">
              {/* Ports tab */}
              {assetTab === "ports" && (() => {
                const ports = selectedAsset.ports ?? [];
                const intel: any[] = selectedAsset.intelligence ?? [];
                const shodanItems = intel.filter((i: any) => i.type === "Shodan");
                const shodanTags   = shodanItems.find((i: any) => i.key === "Tags")?.value;
                const shodanVulns  = shodanItems.find((i: any) => i.key === "Known CVEs")?.value;
                const shodanCpes   = shodanItems.find((i: any) => i.key === "CPEs")?.value;
                const scanMethod   = shodanItems.find((i: any) => i.key === "Scan Method")?.value;
                const resolvedIp   = shodanItems.find((i: any) => i.key === "Resolved IP")?.value;
                const hasShodan    = shodanItems.length > 0;
                const vulnList     = shodanVulns ? shodanVulns.split(", ").filter(Boolean) : [];

                return (
                  <div className="space-y-4">
                    {/* Shodan InternetDB panel */}
                    {hasShodan && (
                      <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 space-y-3">
                        <div className="flex items-center gap-2">
                          <Database className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                          <p className="text-xs font-semibold text-blue-300">Shodan InternetDB</p>
                          {resolvedIp && (
                            <span className="font-mono text-[10px] bg-muted/60 px-1.5 py-0.5 rounded text-muted-foreground">{resolvedIp}</span>
                          )}
                          {scanMethod && (
                            <span className="ml-auto text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium uppercase tracking-wide">
                              {scanMethod}
                            </span>
                          )}
                        </div>
                        <div className="grid grid-cols-2 gap-3 text-xs">
                          {shodanTags && (
                            <div>
                              <p className="text-[10px] text-muted-foreground mb-1.5 flex items-center gap-1">
                                <Tag className="w-2.5 h-2.5" /> Tags
                              </p>
                              <div className="flex flex-wrap gap-1">
                                {shodanTags.split(", ").filter(Boolean).map((t: string) => (
                                  <span key={t} className="bg-blue-500/10 border border-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded text-[10px] font-medium">{t}</span>
                                ))}
                              </div>
                            </div>
                          )}
                          {vulnList.length > 0 && (
                            <div>
                              <p className="text-[10px] text-muted-foreground mb-1.5 flex items-center gap-1">
                                <AlertTriangle className="w-2.5 h-2.5 text-red-400" />
                                <span className="text-red-400">Known CVEs ({vulnList.length})</span>
                              </p>
                              <div className="flex flex-wrap gap-1">
                                {vulnList.slice(0, 10).map((v: string) => (
                                  <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noopener noreferrer"
                                     className="text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded hover:bg-red-500/20 transition-colors">
                                    {v}
                                  </a>
                                ))}
                                {vulnList.length > 10 && (
                                  <span className="text-[10px] text-muted-foreground self-center">+{vulnList.length - 10} more</span>
                                )}
                              </div>
                            </div>
                          )}
                          {shodanCpes && (
                            <div className="col-span-2">
                              <p className="text-[10px] text-muted-foreground mb-1">CPEs</p>
                              <p className="text-[10px] font-mono text-muted-foreground/70 break-all leading-relaxed">{shodanCpes}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Header row */}
                    {ports.length > 0 && (
                      <div className="flex items-center gap-2 px-3 pb-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
                        <span className="w-3 shrink-0" />
                        <span className="w-14 shrink-0">Port</span>
                        <span className="w-8 shrink-0">Proto</span>
                        <span className="w-24 shrink-0">Service</span>
                        <span className="flex-1">Version / Banner</span>
                        <span>State</span>
                      </div>
                    )}

                    {ports.length === 0 ? (
                      <EmptyState message="No open ports found" />
                    ) : (
                      <div className="space-y-0.5">
                        {ports.map((p: any, i: number) => <PortRow key={i} port={p} />)}
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* CVEs tab */}
              {assetTab === "vulns" && (
                <div className="space-y-2">
                  {(selectedAsset.cves ?? selectedAsset.vulnerabilities ?? []).length === 0 ? (
                    <EmptyState message="No CVEs detected" icon={CheckCircle2} />
                  ) : (
                    (selectedAsset.cves ?? selectedAsset.vulnerabilities ?? []).map((v: any, i: number) => (
                      <div key={i} className={cn("rounded-lg border p-3.5", v.severity === "critical" ? "border-red-500/30 bg-red-500/5" : v.severity === "high" ? "border-orange-500/30 bg-orange-500/5" : "border-border bg-card")}>
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={v.severity} />
                            <span className="text-xs font-mono text-muted-foreground">{v.cve}</span>
                            <span className="text-[10px] bg-muted text-muted-foreground rounded px-1.5 py-0.5">{v.cwe}</span>
                          </div>
                          <span className="text-xs font-bold text-foreground shrink-0">CVSS {v.cvss}</span>
                        </div>
                        <p className="text-sm font-semibold mt-1.5">{v.title}</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          <span className="text-foreground font-medium">Remediation: </span>{v.remediation}
                        </p>
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cve}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 text-[10px] text-primary mt-1.5 hover:underline"
                        >
                          View in NVD <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Secrets tab */}
              {assetTab === "secrets" && (
                <div className="space-y-2">
                  {(selectedAsset.secrets ?? []).length === 0 ? (
                    <EmptyState message="No secrets or credentials detected" icon={Lock} />
                  ) : (
                    <>
                      <div className="flex items-center gap-2 mb-3 p-3 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
                        <Fingerprint className="w-4 h-4 text-yellow-400 shrink-0" />
                        <p className="text-xs text-yellow-300">
                          <span className="font-semibold">{(selectedAsset.secrets ?? []).length} credential{(selectedAsset.secrets ?? []).length !== 1 ? "s" : ""} detected</span>
                          {" "}— exposed secrets can enable full account takeover. Rotate immediately.
                        </p>
                      </div>
                      {(selectedAsset.secrets ?? []).map((s: any, i: number) => (
                        <div key={i} className={cn(
                          "rounded-lg border p-3.5",
                          s.severity === "critical" ? "border-red-500/30 bg-red-500/5" :
                          s.severity === "high" ? "border-orange-500/30 bg-orange-500/5" :
                          "border-yellow-500/20 bg-yellow-500/5"
                        )}>
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-center gap-2">
                              <SeverityBadge severity={s.severity} />
                              <span className="text-xs font-mono text-muted-foreground">{s.cve}</span>
                              {s.cwe && <span className="text-[10px] bg-muted text-muted-foreground rounded px-1.5 py-0.5">{s.cwe}</span>}
                            </div>
                            <Key className="w-3.5 h-3.5 text-yellow-400 shrink-0 mt-0.5" />
                          </div>
                          <p className="text-sm font-semibold mt-1.5">{s.title}</p>
                          {s.source && (
                            <p className="text-xs font-mono text-muted-foreground mt-1 bg-muted/30 rounded px-2 py-1 break-all">
                              {s.source}
                            </p>
                          )}
                          <p className="text-xs text-muted-foreground mt-1.5">
                            <span className="text-foreground font-medium">Remediation: </span>{s.remediation}
                          </p>
                        </div>
                      ))}
                    </>
                  )}
                </div>
              )}

              {/* Subdomains tab */}
              {assetTab === "subdomains" && (() => {
                const allSubs: any[] = selectedAsset.subdomains ?? [];
                const live200     = allSubs.filter((s: any) => s.httpStatus === 200);
                const liveAuth    = allSubs.filter((s: any) => s.httpStatus === 401 || s.httpStatus === 403);
                const liveRedir   = allSubs.filter((s: any) => s.httpStatus && [301,302,307,308].includes(s.httpStatus));
                const deadSubs    = allSubs.filter((s: any) => !s.ip);
                const filtered    =
                  subdomainFilter === "200"      ? live200 :
                  subdomainFilter === "auth"     ? liveAuth :
                  subdomainFilter === "redirect" ? liveRedir :
                  subdomainFilter === "dead"     ? deadSubs :
                  allSubs;

                const httpStatusBadge = (s: any) => {
                  const code = s.httpStatus;
                  if (!code) return null;
                  let cls = "bg-muted text-muted-foreground border-border";
                  if (code === 200) cls = "bg-green-500/15 text-green-400 border-green-500/30";
                  else if (code === 401 || code === 403) cls = "bg-yellow-500/15 text-yellow-400 border-yellow-500/30";
                  else if ([301,302,307,308].includes(code)) cls = "bg-blue-500/15 text-blue-400 border-blue-500/30";
                  else if (code >= 400) cls = "bg-red-500/15 text-red-400 border-red-500/30";
                  return <span className={cn("text-[10px] font-mono px-1.5 py-0.5 rounded border font-semibold", cls)}>{code}</span>;
                };

                if (allSubs.length === 0) return <EmptyState message="No subdomains discovered" />;

                return (
                  <div className="space-y-4">
                    {/* Summary cards */}
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                      {[
                        { label: "Total",       count: allSubs.length,   cls: "border-border",            active: subdomainFilter === "all" },
                        { label: "200 OK",      count: live200.length,   cls: "border-green-500/30",      active: subdomainFilter === "200", f: "200" },
                        { label: "401 / 403",   count: liveAuth.length,  cls: "border-yellow-500/30",     active: subdomainFilter === "auth", f: "auth" },
                        { label: "Redirects",   count: liveRedir.length, cls: "border-blue-500/30",       active: subdomainFilter === "redirect", f: "redirect" },
                        { label: "Dead / Unresolved", count: deadSubs.length, cls: "border-red-500/30",  active: subdomainFilter === "dead", f: "dead" },
                      ].map(({ label, count, cls, active, f }) => (
                        <button
                          key={label}
                          onClick={() => setSubdomainFilter((f ?? "all") as any)}
                          className={cn(
                            "bg-card border rounded-xl p-3 text-left transition-all hover:bg-accent/30",
                            cls, active && "ring-1 ring-primary bg-primary/5",
                          )}
                        >
                          <p className="text-lg font-bold leading-tight">{count}</p>
                          <p className="text-[10px] text-muted-foreground">{label}</p>
                        </button>
                      ))}
                    </div>

                    {/* Source legend (compact) */}
                    {(() => {
                      const srcMap: Record<string, number> = {};
                      for (const s of allSubs) for (const src of (s.sources ?? [])) srcMap[src] = (srcMap[src] ?? 0) + 1;
                      const entries = Object.entries(srcMap).sort((a, b) => b[1] - a[1]);
                      if (entries.length === 0) return null;
                      return (
                        <div className="flex flex-wrap gap-1.5">
                          {entries.map(([src, cnt]) => (
                            <span key={src} className="text-[10px] px-2 py-0.5 rounded-full bg-accent/50 border border-border text-muted-foreground">
                              {src} <span className="font-semibold text-foreground/70">{cnt}</span>
                            </span>
                          ))}
                        </div>
                      );
                    })()}

                    {/* Table */}
                    {filtered.length === 0 ? (
                      <EmptyState message={`No subdomains match filter "${subdomainFilter}"`} />
                    ) : (
                      <div className="overflow-x-auto">
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="text-left border-b border-border">
                              <th className="pb-2 text-xs font-medium text-muted-foreground pr-4">Subdomain</th>
                              <th className="pb-2 text-xs font-medium text-muted-foreground pr-4">IP</th>
                              <th className="pb-2 text-xs font-medium text-muted-foreground pr-3">HTTP</th>
                              <th className="pb-2 text-xs font-medium text-muted-foreground pr-4">Title</th>
                              <th className="pb-2 text-xs font-medium text-muted-foreground pr-4">CDN / Server</th>
                              <th className="pb-2 text-xs font-medium text-muted-foreground">Sources</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filtered.map((s: any, i: number) => (
                              <tr key={i} className="border-b border-border/40 hover:bg-accent/20 transition-colors">
                                <td className="py-2 pr-4">
                                  <a
                                    href={`https://${s.name}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="font-mono text-xs text-primary hover:underline flex items-center gap-1 group"
                                  >
                                    {s.name}
                                    <ExternalLink className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 shrink-0" />
                                  </a>
                                  {s.redirectTo && (
                                    <p className="text-[10px] text-blue-400 font-mono truncate max-w-[200px]" title={s.redirectTo}>
                                      → {s.redirectTo}
                                    </p>
                                  )}
                                </td>
                                <td className="py-2 pr-4 font-mono text-xs text-muted-foreground whitespace-nowrap">
                                  {s.ip || "—"}
                                </td>
                                <td className="py-2 pr-3 whitespace-nowrap">
                                  {httpStatusBadge(s) ?? <span className="text-muted-foreground text-xs">—</span>}
                                </td>
                                <td className="py-2 pr-4 text-xs text-muted-foreground max-w-[180px] truncate" title={s.httpTitle ?? ""}>
                                  {s.httpTitle || "—"}
                                </td>
                                <td className="py-2 pr-4">
                                  <div className="flex flex-col gap-0.5">
                                    {s.cdnProvider && (
                                      <span className="text-[10px] bg-blue-500/15 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded w-fit">
                                        {s.cdnProvider}
                                      </span>
                                    )}
                                    {s.webServer && (
                                      <span className="text-[10px] text-muted-foreground font-mono">{s.webServer}</span>
                                    )}
                                    {!s.cdnProvider && !s.webServer && <span className="text-muted-foreground text-xs">—</span>}
                                  </div>
                                </td>
                                <td className="py-2">
                                  <div className="flex flex-wrap gap-1">
                                    {(s.sources ?? []).slice(0, 3).map((src: string) => (
                                      <span key={src} className="text-[9px] px-1.5 py-0.5 rounded bg-accent/60 border border-border text-muted-foreground whitespace-nowrap">
                                        {src}
                                      </span>
                                    ))}
                                    {(s.sources ?? []).length > 3 && (
                                      <span className="text-[9px] px-1 py-0.5 text-muted-foreground">+{s.sources.length - 3}</span>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* HTTP Info tab */}
              {assetTab === "http" && (
                <div>
                  {!selectedAsset.httpInfo ? (
                    <EmptyState message="No HTTP information collected" />
                  ) : (
                    <div className="space-y-4">
                      <div className="grid grid-cols-2 gap-3">
                        <InfoRow label="URL" value={selectedAsset.httpInfo.url} mono />
                        <InfoRow label="Status Code" value={String(selectedAsset.httpInfo.status)} />
                        <InfoRow label="Title" value={selectedAsset.httpInfo.title} />
                        <InfoRow label="Server" value={selectedAsset.httpInfo.server} mono />
                        <InfoRow label="Content Length" value={`${(selectedAsset.httpInfo.contentLength / 1024).toFixed(1)} KB`} />
                        <InfoRow label="WAF" value={selectedAsset.httpInfo.waf} />
                        <InfoRow label="Technologies" value={(selectedAsset.httpInfo.tech ?? []).join(", ")} />
                      </div>
                      {Object.keys(selectedAsset.httpInfo.headers ?? {}).length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-muted-foreground mb-2">Response Headers</p>
                          {/* Highlight security-relevant headers first */}
                          {(() => {
                            const h = selectedAsset.httpInfo.headers ?? {};
                            const secHeaders = ["server","x-powered-by","strict-transport-security","content-security-policy","x-frame-options","x-content-type-options","referrer-policy","permissions-policy"];
                            const highlighted = secHeaders.filter(k => h[k]);
                            if (!highlighted.length) return null;
                            return (
                              <div className="mb-2 space-y-1">
                                {highlighted.map(k => {
                                  const isVuln = ["server","x-powered-by"].includes(k);
                                  const isMissingSec = ["strict-transport-security","content-security-policy","x-frame-options","x-content-type-options","referrer-policy","permissions-policy"].includes(k) && h[k];
                                  return (
                                    <div key={k} className={cn("flex gap-2 rounded px-2 py-1.5 font-mono text-xs border", isVuln ? "bg-orange-500/5 border-orange-500/20" : "bg-green-500/5 border-green-500/20")}>
                                      <span className={cn("shrink-0 font-semibold", isVuln ? "text-orange-400" : "text-green-400")}>{k}:</span>
                                      <span className="text-muted-foreground break-all">{String(h[k])}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            );
                          })()}
                          <div className="bg-muted/30 rounded-lg p-3 space-y-1 font-mono text-xs">
                            {Object.entries(selectedAsset.httpInfo.headers ?? {}).map(([k, v]) => (
                              <div key={k} className="flex gap-2">
                                <span className="text-primary shrink-0">{k}:</span>
                                <span className="text-muted-foreground break-all">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* WAF Intelligence */}
                      <div>
                        <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
                          <Shield className="w-3 h-3" /> WAF Intelligence
                        </p>
                        {(selectedAsset.httpInfo as any)?.wafDetails ? (
                          <div className="bg-accent/10 border border-border/50 rounded-lg px-4 py-3 flex items-start justify-between gap-4">
                            <div>
                              <p className="text-sm font-semibold">{(selectedAsset.httpInfo as any).wafDetails.name}</p>
                              <p className="text-xs text-muted-foreground mt-0.5">{(selectedAsset.httpInfo as any).wafDetails.method}</p>
                            </div>
                            <span className={cn("text-[10px] border rounded px-2 py-1 font-bold uppercase tracking-wide shrink-0",
                              (selectedAsset.httpInfo as any).wafDetails.confidence === "high"   ? "bg-green-500/15 text-green-400 border-green-500/30" :
                              (selectedAsset.httpInfo as any).wafDetails.confidence === "medium" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                              "bg-muted/60 text-muted-foreground border-border"
                            )}>{(selectedAsset.httpInfo as any).wafDetails.confidence} confidence</span>
                          </div>
                        ) : (
                          <div className="bg-accent/10 border border-border/50 rounded-lg px-4 py-2.5 flex items-center gap-2 text-sm text-muted-foreground">
                            <XCircle className="w-4 h-4 text-muted-foreground/40 shrink-0" /> No WAF detected on primary host (header inspection + active probe)
                          </div>
                        )}
                        {/* Per-host WAF from subdomain fingerprinting */}
                        {(selectedAsset.httpInfo?.hostFingerprints ?? []).some((fp: any) => fp.waf) && (
                          <div className="mt-2 space-y-1">
                            <p className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1">
                              <Globe className="w-3 h-3" /> Detected on subdomains:
                            </p>
                            {(selectedAsset.httpInfo!.hostFingerprints as any[])
                              .filter((fp: any) => fp.waf)
                              .map((fp: any, i: number) => (
                                <div key={i} className="flex items-center justify-between gap-2 bg-accent/10 border border-border/50 rounded px-3 py-1">
                                  <span className="font-mono text-xs text-primary">{fp.host}</span>
                                  <span className="text-xs bg-accent/60 border border-border rounded px-2 py-0.5 font-medium">{fp.waf}</span>
                                </div>
                              ))}
                          </div>
                        )}
                      </div>

                      {/* Origin IP Discovery */}
                      {((selectedAsset.httpInfo as any)?.originIps ?? []).length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
                            <Network className="w-3 h-3" /> Origin IP Discovery
                            <span className="ml-1 text-[10px] bg-accent/60 border border-border rounded px-1.5 py-0.5">{(selectedAsset.httpInfo as any).originIps.length} candidate{(selectedAsset.httpInfo as any).originIps.length !== 1 ? "s" : ""}</span>
                          </p>
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left border-b border-border">
                                <th className="pb-2 text-xs font-medium text-muted-foreground">IP Address</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground">Discovery Method</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground text-center w-24">Confidence</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground">Org / rDNS</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground">Open Ports</th>
                              </tr>
                            </thead>
                            <tbody>
                              {((selectedAsset.httpInfo as any).originIps as any[]).map((c: any, i: number) => (
                                <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                                  <td className="py-1.5 font-mono text-xs text-foreground">{c.ip}</td>
                                  <td className="py-1.5 text-xs text-muted-foreground max-w-[180px] truncate">{c.method}</td>
                                  <td className="py-1.5 text-center">
                                    <span className={cn("text-[10px] border rounded px-1.5 py-0.5 font-bold",
                                      c.confidence === "high"   ? "bg-green-500/15 text-green-400 border-green-500/30" :
                                      c.confidence === "medium" ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                                      "bg-muted/50 text-muted-foreground border-border"
                                    )}>{c.confidence}</span>
                                  </td>
                                  <td className="py-1.5 text-xs text-muted-foreground font-mono max-w-[160px] truncate">{c.org || c.reverseDns || "—"}</td>
                                  <td className="py-1.5 text-xs text-muted-foreground font-mono">{(c.openPorts ?? []).slice(0, 6).join(", ") || "—"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}

                      {/* Cookie Security Analysis */}
                      {(selectedAsset.httpInfo?.cookieFlags ?? []).length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
                            <Lock className="w-3 h-3" /> Cookie Security Analysis
                            <span className="ml-1 text-[10px] bg-accent/60 border border-border rounded px-1.5 py-0.5">{selectedAsset.httpInfo.cookieFlags.length} cookies</span>
                          </p>
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="text-left border-b border-border">
                                <th className="pb-2 text-xs font-medium text-muted-foreground">Cookie Name</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground text-center w-20">Secure</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground text-center w-24">HttpOnly</th>
                                <th className="pb-2 text-xs font-medium text-muted-foreground text-center w-28">SameSite</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(selectedAsset.httpInfo.cookieFlags as any[]).map((c: any, i: number) => (
                                <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                                  <td className="py-2 font-mono text-xs text-foreground">{c.name || "(unnamed)"}</td>
                                  <td className="py-2 text-center">
                                    {c.secure
                                      ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mx-auto" />
                                      : <AlertCircle className="w-3.5 h-3.5 text-red-400 mx-auto" />}
                                  </td>
                                  <td className="py-2 text-center">
                                    {c.httpOnly
                                      ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 mx-auto" />
                                      : <AlertCircle className="w-3.5 h-3.5 text-red-400 mx-auto" />}
                                  </td>
                                  <td className="py-2 text-center">
                                    {c.sameSite ? (
                                      <span className={cn("text-[10px] border rounded px-1.5 py-0.5 font-mono font-bold",
                                        c.sameSite.toLowerCase() === "strict" ? "bg-green-500/15 text-green-400 border-green-500/30" :
                                        c.sameSite.toLowerCase() === "lax"    ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                                        "bg-red-500/15 text-red-400 border-red-500/30"
                                      )}>{c.sameSite}</span>
                                    ) : <AlertCircle className="w-3.5 h-3.5 text-red-400 mx-auto" />}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* DNS Records tab */}
              {assetTab === "dns" && (
                <DnsTab records={selectedAsset.dnsRecords ?? []} />
              )}

              {/* Endpoints tab */}
              {assetTab === "endpoints" && (
                <div>
                  {(selectedAsset.endpoints ?? []).length === 0 ? (
                    <EmptyState message="No endpoints discovered" />
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-border">
                          <th className="pb-2 text-xs font-medium text-muted-foreground">URL / Path</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Method</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedAsset.endpoints ?? []).map((e: any, i: number) => {
                          const statusCls =
                            e.status < 300 ? "bg-green-500/15 text-green-400 border-green-500/30" :
                            e.status < 400 ? "bg-blue-500/15 text-blue-400 border-blue-500/30" :
                            e.status < 500 ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                            "bg-red-500/15 text-red-400 border-red-500/30";
                          return (
                            <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                              <td className="py-2 font-mono text-xs">{e.url}</td>
                              <td className="py-2">
                                <span className="text-[10px] bg-accent/60 text-foreground rounded px-1.5 py-0.5 font-mono font-bold">{e.method}</span>
                              </td>
                              <td className="py-2">
                                <span className={cn("text-[10px] rounded border px-1.5 py-0.5 font-mono", statusCls)}>{e.status}</span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* Screenshots tab */}
              {assetTab === "screenshots" && (
                <ScreenshotsTab assetId={selectedAsset.assetId} />
              )}

              {/* Technologies tab */}
              {assetTab === "technologies" && (
                <div className="space-y-4">
                  {/* Per-host fingerprint breakdown from multi-host scan */}
                  {(selectedAsset.httpInfo?.hostFingerprints ?? []).length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
                        <Globe className="w-3 h-3" /> Per-Host Fingerprints
                        <span className="ml-1 text-[10px] bg-accent/60 border border-border rounded px-1.5 py-0.5">{selectedAsset.httpInfo.hostFingerprints.length} subdomains</span>
                      </p>
                      <div className="space-y-1.5">
                        {(selectedAsset.httpInfo.hostFingerprints as any[]).map((fp: any, i: number) => (
                          <div key={i} className="flex items-start gap-2 bg-accent/10 border border-border/50 rounded-lg px-3 py-2">
                            <span className="font-mono text-xs text-primary shrink-0 mt-0.5">{fp.host}</span>
                            <div className="flex flex-wrap gap-1">
                              {(fp.techs as string[]).map((t: string) => (
                                <span key={t} className="text-[10px] bg-accent/50 border border-border rounded px-1.5 py-0.5 text-muted-foreground">{t}</span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  <TechnologiesTab assetId={selectedAsset.assetId} />
                </div>
              )}

              {/* Intelligence tab */}
              {assetTab === "intel" && (
                <div>
                  {(selectedAsset.intelligence ?? []).length === 0 ? (
                    <EmptyState message="No intelligence data collected" />
                  ) : (
                    <div className="grid grid-cols-2 gap-2">
                      {(selectedAsset.intelligence ?? []).map((item: any, i: number) => (
                        <div key={i} className="bg-accent/20 border border-border rounded-lg px-3 py-2.5">
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span className="text-[10px] bg-primary/15 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{item.type}</span>
                            <span className="text-xs text-muted-foreground">{item.key}</span>
                          </div>
                          <p className="text-sm font-medium">{item.value}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Raw Output tab */}
              {assetTab === "raw" && (() => {
                // Build per-phase groups from all configured tools
                const phaseGroups: Record<number, { phaseName: string; tools: string[] }> = {};
                for (const t of configuredTools) {
                  if (!phaseGroups[t.phase]) phaseGroups[t.phase] = { phaseName: t.phaseName, tools: [] };
                  phaseGroups[t.phase].tools.push(t.name);
                }
                // Also include any tools that ran but weren't in configuredTools
                for (const tr of toolResults) {
                  const ph = tr.phase ?? 1;
                  if (!phaseGroups[ph]) phaseGroups[ph] = { phaseName: tr.phaseName ?? "Recon", tools: [] };
                  if (!phaseGroups[ph].tools.includes(tr.toolName)) phaseGroups[ph].tools.push(tr.toolName);
                }
                const sortedPhases = Object.entries(phaseGroups).sort(([a], [b]) => Number(a) - Number(b));

                const selectedResult = toolResults.find((t: any) => t.toolName === displayedTool);
                const toolRan = !!selectedResult;
                // "No Results" = tool ran but rawOutput has no data sections (no === markers after header)
                const hasData = selectedResult?.rawOutput
                  ? selectedResult.rawOutput.includes("===")
                  : false;

                return (
                  <div className="flex gap-4 min-h-[400px]">
                    {/* Tool sidebar */}
                    <div className="w-44 shrink-0 space-y-3">
                      {sortedPhases.map(([phaseNum, group]) => (
                        <div key={phaseNum}>
                          <p className={cn(
                            "text-[9px] font-bold uppercase tracking-widest px-2 py-1 rounded-md border mb-1.5 inline-block",
                            PHASE_COLORS[Number(phaseNum)] ?? "text-muted-foreground bg-muted border-border"
                          )}>
                            {group.phaseName}
                          </p>
                          <div className="space-y-0.5">
                            {group.tools.map(toolName => {
                              const ran = toolResults.some((t: any) => t.toolName === toolName);
                              const result = toolResults.find((t: any) => t.toolName === toolName);
                              const hasOutput = result?.rawOutput?.includes("===");
                              return (
                                <button
                                  key={toolName}
                                  onClick={() => setSelectedTool(toolName)}
                                  className={cn(
                                    "w-full text-left text-xs px-2.5 py-1.5 rounded-lg border transition-colors flex items-center gap-2",
                                    displayedTool === toolName
                                      ? "bg-primary/20 border-primary/40 text-foreground"
                                      : "bg-accent/20 border-border/50 text-muted-foreground hover:text-foreground hover:bg-accent/40"
                                  )}
                                >
                                  <span className={cn(
                                    "w-1.5 h-1.5 rounded-full shrink-0",
                                    !ran ? "bg-muted-foreground/30" :
                                    !hasOutput ? "bg-yellow-500/60" :
                                    "bg-green-500"
                                  )} />
                                  <span className="font-mono truncate">{toolName}</span>
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      ))}
                      {sortedPhases.length === 0 && (
                        <p className="text-[10px] text-muted-foreground/50 px-2">No tools configured</p>
                      )}
                    </div>

                    {/* Output area */}
                    <div className="flex-1 min-w-0">
                      {!displayedTool && (
                        <div className="h-full flex items-center justify-center text-muted-foreground/40">
                          <p className="text-sm">Select a tool to view output</p>
                        </div>
                      )}
                      {displayedTool && (
                        <div className="space-y-2">
                          {/* Tool header */}
                          <div className="flex items-center gap-2 pb-2 border-b border-border/50">
                            <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
                            <span className="text-xs font-mono font-semibold">{displayedTool}</span>
                            {!toolRan && (
                              <span className="text-[10px] bg-muted border border-border px-1.5 py-0.5 rounded text-muted-foreground">did not run</span>
                            )}
                            {toolRan && !hasData && (
                              <span className="text-[10px] bg-yellow-500/10 border border-yellow-500/30 text-yellow-500 px-1.5 py-0.5 rounded">no results</span>
                            )}
                            {toolRan && hasData && (
                              <span className="text-[10px] bg-green-500/10 border border-green-500/30 text-green-400 px-1.5 py-0.5 rounded">results available</span>
                            )}
                            {selectedResult?.phaseName && (
                              <span className="ml-auto text-[10px] text-muted-foreground/50">{selectedResult.phaseName}</span>
                            )}
                          </div>

                          {/* Content */}
                          {!toolRan && (
                            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground/40 gap-2">
                              <XCircle className="w-8 h-8" />
                              <p className="text-sm font-medium">Tool did not run</p>
                              <p className="text-xs">This tool was configured but was not executed during the scan.</p>
                            </div>
                          )}
                          {toolRan && !hasData && (
                            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground/40 gap-2">
                              <AlertCircle className="w-8 h-8 text-yellow-500/40" />
                              <p className="text-sm font-medium">No Results</p>
                              <p className="text-xs">Tool ran successfully but found no data for this target.</p>
                              {selectedResult?.rawOutput && (
                                <details className="mt-3 w-full max-w-lg">
                                  <summary className="text-[10px] text-muted-foreground/50 cursor-pointer hover:text-muted-foreground">Show execution log</summary>
                                  <pre className="mt-2 bg-muted/20 border border-border/40 rounded-lg p-3 text-[10px] font-mono text-muted-foreground/50 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                                    {selectedResult.rawOutput}
                                  </pre>
                                </details>
                              )}
                            </div>
                          )}
                          {toolRan && hasData && (
                            <pre className="bg-muted/20 border border-border/40 rounded-lg p-4 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[600px] overflow-y-auto">
                              {selectedResult!.rawOutput}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

// ── Page type badge colours ────────────────────────────────────────────────────
const PAGE_TYPE_STYLES: Record<string, string> = {
  index:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  login:     "bg-violet-500/15 text-violet-400 border-violet-500/30",
  signup:    "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  admin:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  api:       "bg-green-500/15 text-green-400 border-green-500/30",
  sensitive: "bg-red-500/15 text-red-400 border-red-500/30",
  error:     "bg-muted text-muted-foreground border-border",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-400",
};

function PortRow({ port }: { port: any }) {
  const [open, setOpen] = useState(false);
  const hasScripts = port.scripts && Object.keys(port.scripts).length > 0;
  const hasBanner  = !!port.banner;
  const hasCpes    = (port.cpes ?? []).length > 0;
  const expandable = hasScripts || hasBanner || hasCpes;

  return (
    <>
      <div
        className={cn(
          "flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors text-sm",
          expandable ? "cursor-pointer hover:bg-accent/20" : "",
          open ? "bg-accent/20 border-border" : "border-border/50 bg-card/50"
        )}
        onClick={() => expandable && setOpen(o => !o)}
      >
        {expandable
          ? (open ? <ChevronDown className="w-3 h-3 text-muted-foreground shrink-0" /> : <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" />)
          : <span className="w-3 shrink-0" />}
        <span className="font-mono font-bold text-primary w-14 shrink-0">{port.port}</span>
        <span className="text-[10px] text-muted-foreground uppercase w-8 shrink-0">{port.protocol ?? "tcp"}</span>
        <span className="font-medium text-xs w-24 shrink-0">{port.service ?? "unknown"}</span>
        <span className="text-xs text-muted-foreground font-mono flex-1 truncate">{port.version || (hasBanner ? port.banner : "—")}</span>
        <span className="text-[10px] bg-green-500/15 text-green-400 border border-green-500/30 px-1.5 py-0.5 rounded shrink-0">
          {port.state ?? "open"}
        </span>
      </div>
      {open && (
        <div className="ml-5 mb-1 rounded-lg border border-border/50 bg-muted/20 text-xs overflow-hidden">
          {hasBanner && (
            <div className="px-3 py-2 border-b border-border/30">
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mr-2">Banner</span>
              <span className="font-mono text-foreground/80">{port.banner}</span>
            </div>
          )}
          {hasScripts && Object.entries(port.scripts as Record<string, string>).map(([k, v]) => (
            <div key={k} className="px-3 py-2 border-b border-border/30 last:border-0">
              <span className="text-[10px] font-semibold text-primary/70 mr-2">{k}</span>
              <span className="font-mono text-muted-foreground whitespace-pre-wrap break-all">{String(v).trim()}</span>
            </div>
          ))}
          {hasCpes && (
            <div className="px-3 py-2 flex flex-wrap gap-1 items-center">
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mr-1">CPEs</span>
              {(port.cpes as string[]).map((c, i) => (
                <span key={i} className="font-mono text-[10px] bg-accent/50 px-1.5 py-0.5 rounded text-muted-foreground">{c}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </>
  );
}

function ScreenshotsTab({ assetId }: { assetId: number }) {
  const { data, isLoading } = useListAssetScreenshots(assetId, {
    query: { queryKey: getListAssetScreenshotsQueryKey(assetId), enabled: !!assetId },
  });
  const [lightbox, setLightbox] = useState<any | null>(null);

  const screens = (data as any[]) ?? [];

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 gap-3">
        {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-44 rounded-xl" />)}
      </div>
    );
  }

  if (screens.length === 0) {
    return (
      <div className="text-center py-10 text-muted-foreground">
        <Camera className="w-8 h-8 mx-auto mb-2 opacity-40" />
        <p className="text-sm font-medium">No screenshots captured yet</p>
        <p className="text-xs mt-1 opacity-70">Screenshots are captured automatically when a scan runs on this asset. Run a new scan to capture them.</p>
      </div>
    );
  }

  const hasCritical = screens.some((s: any) =>
    (s.findings ?? []).some((f: any) => f.severity === "critical" || f.severity === "high")
  );

  return (
    <div className="space-y-3">
      {hasCritical && (
        <div className="flex items-center gap-2 p-3 bg-red-500/5 border border-red-500/20 rounded-lg">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <p className="text-xs text-red-300">
            <span className="font-semibold">Sensitive data detected</span>
            {" "}— credentials or secrets were found in page source. See findings below.
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        {screens.map((s: any, i: number) => {
          const findings: any[] = s.findings ?? [];
          const critFindings = findings.filter((f: any) => f.severity === "critical" || f.severity === "high");
          return (
            <div
              key={i}
              className={cn(
                "bg-accent/20 border rounded-xl overflow-hidden cursor-pointer hover:bg-accent/30 transition-colors group",
                critFindings.length > 0 ? "border-red-500/40" : "border-border"
              )}
              onClick={() => setLightbox(s)}
            >
              {/* Thumbnail */}
              <div className="relative w-full h-36 bg-muted/40 overflow-hidden">
                {s.screenshotData ? (
                  <img
                    src={`data:image/png;base64,${s.screenshotData}`}
                    alt={s.title || s.url}
                    className="w-full h-full object-cover object-top group-hover:scale-105 transition-transform duration-300"
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center text-muted-foreground/40">
                    <Camera className="w-8 h-8" />
                  </div>
                )}
                {/* Status code pill */}
                <span className={cn(
                  "absolute top-2 right-2 text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border",
                  s.statusCode >= 200 && s.statusCode < 300 ? "bg-green-500/80 text-white border-green-500" :
                  s.statusCode >= 300 && s.statusCode < 400 ? "bg-blue-500/80 text-white border-blue-500" :
                  s.statusCode >= 400 ? "bg-red-500/80 text-white border-red-500" :
                  "bg-muted text-muted-foreground border-border"
                )}>{s.statusCode}</span>
                {/* Page type badge */}
                <span className={cn(
                  "absolute top-2 left-2 text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase tracking-wide",
                  PAGE_TYPE_STYLES[s.pageType] ?? PAGE_TYPE_STYLES.error
                )}>{s.pageType}</span>
              </div>
              {/* Card footer */}
              <div className="px-3 py-2">
                <p className="text-xs font-medium truncate">{s.title || "Untitled"}</p>
                <p className="text-[10px] text-muted-foreground truncate font-mono mt-0.5">{s.url}</p>
                {findings.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {findings.slice(0, 3).map((f: any, fi: number) => (
                      <span key={fi} className="flex items-center gap-0.5 text-[10px] bg-muted/60 border border-border rounded px-1.5 py-0.5">
                        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", SEVERITY_DOT[f.severity] ?? "bg-muted-foreground")} />
                        {f.type}
                      </span>
                    ))}
                    {findings.length > 3 && (
                      <span className="text-[10px] text-muted-foreground">+{findings.length - 3} more</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Lightbox */}
      {lightbox && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setLightbox(null)}
        >
          <div
            className="bg-card border border-border rounded-2xl overflow-hidden max-w-4xl w-full max-h-[90vh] flex flex-col"
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
              <div className="flex items-center gap-2">
                <span className={cn(
                  "text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase tracking-wide",
                  PAGE_TYPE_STYLES[lightbox.pageType] ?? PAGE_TYPE_STYLES.error
                )}>{lightbox.pageType}</span>
                <span className="text-xs font-mono text-muted-foreground truncate max-w-[400px]">{lightbox.url}</span>
              </div>
              <button onClick={() => setLightbox(null)} className="w-7 h-7 rounded-lg bg-accent/60 hover:bg-accent flex items-center justify-center">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
            {/* Screenshot */}
            <div className="overflow-y-auto flex-1">
              {lightbox.screenshotData ? (
                <img src={`data:image/png;base64,${lightbox.screenshotData}`} alt={lightbox.title} className="w-full" />
              ) : (
                <div className="h-64 flex items-center justify-center text-muted-foreground/40">
                  <Camera className="w-10 h-10" />
                </div>
              )}
            </div>
            {/* Findings */}
            {(lightbox.findings ?? []).length > 0 && (
              <div className="border-t border-border px-4 py-3 shrink-0">
                <p className="text-xs font-semibold text-muted-foreground mb-2">
                  Sensitive Data Found ({lightbox.findings.length})
                </p>
                <div className="flex flex-wrap gap-2">
                  {lightbox.findings.map((f: any, i: number) => (
                    <div key={i} className={cn(
                      "flex items-center gap-1.5 text-xs rounded-lg border px-2.5 py-1.5",
                      f.severity === "critical" ? "border-red-500/40 bg-red-500/5 text-red-300" :
                      f.severity === "high" ? "border-orange-500/40 bg-orange-500/5 text-orange-300" :
                      "border-yellow-500/30 bg-yellow-500/5 text-yellow-300"
                    )}>
                      <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", SEVERITY_DOT[f.severity] ?? "bg-muted-foreground")} />
                      <span className="font-semibold">{f.type}:</span>
                      <span className="font-mono text-[10px] opacity-80">{f.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const TECH_CATEGORY_STYLES: Record<string, string> = {
  "CMS":               "bg-violet-500/15 text-violet-400 border-violet-500/30",
  "JavaScript frameworks": "bg-blue-500/15 text-blue-400 border-blue-500/30",
  "Web servers":       "bg-green-500/15 text-green-400 border-green-500/30",
  "Databases":         "bg-orange-500/15 text-orange-400 border-orange-500/30",
  "Analytics":         "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  "Security":          "bg-red-500/15 text-red-400 border-red-500/30",
  "CDN":               "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  "Programming languages": "bg-pink-500/15 text-pink-400 border-pink-500/30",
};

function TechnologiesTab({ assetId }: { assetId: number }) {
  const { data, isLoading } = useListAssetTechnologies(assetId, {
    query: { queryKey: getListAssetTechnologiesQueryKey(assetId), enabled: !!assetId },
  });

  const techs = (data as any[]) ?? [];

  if (isLoading) {
    return (
      <div className="grid grid-cols-3 gap-3">
        {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}
      </div>
    );
  }

  if (techs.length === 0) {
    return (
      <div className="text-center py-10 text-muted-foreground">
        <Cpu className="w-8 h-8 mx-auto mb-2 opacity-40" />
        <p className="text-sm font-medium">No technologies detected</p>
        <p className="text-xs mt-1 opacity-70">Technology fingerprinting runs automatically on web assets. Run a scan to detect technologies.</p>
      </div>
    );
  }

  // Group by category
  const byCategory = techs.reduce<Record<string, any[]>>((acc, t) => {
    const cat = t.category || "Other";
    (acc[cat] = acc[cat] ?? []).push(t);
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Cpu className="w-3.5 h-3.5" />
        <span>{techs.length} technologies detected</span>
      </div>
      {Object.entries(byCategory).map(([cat, items]) => (
        <div key={cat}>
          <p className={cn(
            "text-[10px] font-bold uppercase tracking-widest px-2 py-0.5 rounded border inline-block mb-2",
            TECH_CATEGORY_STYLES[cat] ?? "text-muted-foreground bg-muted border-border"
          )}>{cat}</p>
          <div className="grid grid-cols-3 gap-2">
            {items.map((t: any, i: number) => (
              <div key={i} className="bg-accent/20 border border-border rounded-lg px-3 py-2.5 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-sm font-semibold truncate">{t.name}</p>
                  {t.version && (
                    <p className="text-[10px] font-mono text-muted-foreground mt-0.5">v{t.version}</p>
                  )}
                </div>
                {t.confidence !== undefined && (
                  <div className="shrink-0 text-right">
                    <p className="text-xs font-bold text-primary">{t.confidence}%</p>
                    <p className="text-[9px] text-muted-foreground">conf.</p>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="bg-accent/20 border border-border rounded-lg px-3 py-2.5">
      <p className="text-[10px] text-muted-foreground font-medium mb-0.5">{label}</p>
      <p className={cn("text-sm break-all", mono ? "font-mono text-xs" : "font-medium")}>{value || "—"}</p>
    </div>
  );
}

function DnsTypeStyle(type: string): string {
  const map: Record<string, string> = {
    A:       "bg-blue-500/15 text-blue-400 border-blue-500/30",
    AAAA:    "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
    MX:      "bg-orange-500/15 text-orange-400 border-orange-500/30",
    NS:      "bg-violet-500/15 text-violet-400 border-violet-500/30",
    TXT:     "bg-slate-500/15 text-slate-300 border-slate-500/30",
    SOA:     "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
    CNAME:   "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    SRV:     "bg-teal-500/15 text-teal-400 border-teal-500/30",
    PTR:     "bg-pink-500/15 text-pink-400 border-pink-500/30",
    DMARC:   "bg-green-500/15 text-green-400 border-green-500/30",
    "MTA-STS": "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    BIMI:    "bg-purple-500/15 text-purple-400 border-purple-500/30",
  };
  return map[type] ?? "bg-accent/60 text-primary border-border";
}

function DnsTab({ records }: { records: any[] }) {
  const [filter, setFilter] = useState<string>("ALL");
  if (records.length === 0) return <EmptyState message="No DNS records collected" icon={Database} />;

  // Separate by type group
  const dmarcRecs   = records.filter(r => r.type === "DMARC");
  const spfRecs     = records.filter(r => r.type === "TXT" && r.value?.startsWith("v=spf1"));
  const srvRecs     = records.filter(r => r.type === "SRV");
  const ptrRecs     = records.filter(r => r.type === "PTR");
  const types       = ["ALL", ...Array.from(new Set(records.map((r: any) => r.type))).sort()];
  const filtered    = filter === "ALL" ? records : records.filter(r => r.type === filter);

  return (
    <div className="space-y-4">

      {/* SPF + DMARC analysis cards */}
      {(spfRecs.length > 0 || dmarcRecs.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* SPF card */}
          {spfRecs.length > 0 ? (
            <div className="bg-card border border-border rounded-lg p-3 space-y-1.5">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn("text-[10px] border rounded px-1.5 py-0.5 font-mono font-bold", DnsTypeStyle("TXT"))}>SPF</span>
                <span className="text-xs font-semibold text-foreground">Email Sender Policy</span>
              </div>
              {spfRecs.map((r: any, i: number) => (
                <div key={i} className="space-y-1">
                  <p className="font-mono text-[10px] text-muted-foreground bg-muted/40 rounded px-2 py-1 break-all">{r.value}</p>
                  {r.notes && <p className="text-xs text-muted-foreground leading-relaxed">{r.notes}</p>}
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-xs font-semibold text-red-400">No SPF Record</p>
                <p className="text-xs text-muted-foreground mt-0.5">Anyone can send email claiming to be from this domain — high phishing risk.</p>
              </div>
            </div>
          )}

          {/* DMARC card */}
          {dmarcRecs.filter((r: any) => r.value !== "(not configured)").length > 0 ? (
            <div className="bg-card border border-border rounded-lg p-3 space-y-1.5">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn("text-[10px] border rounded px-1.5 py-0.5 font-mono font-bold", DnsTypeStyle("DMARC"))}>DMARC</span>
                <span className="text-xs font-semibold text-foreground">Email Authentication Policy</span>
              </div>
              {dmarcRecs.filter((r: any) => r.value !== "(not configured)").map((r: any, i: number) => (
                <div key={i} className="space-y-1">
                  <p className="font-mono text-[10px] text-muted-foreground bg-muted/40 rounded px-2 py-1 break-all">{r.value}</p>
                  {r.notes && <p className="text-xs text-muted-foreground leading-relaxed">{r.notes}</p>}
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-xs font-semibold text-red-400">No DMARC Record</p>
                <p className="text-xs text-muted-foreground mt-0.5">Domain is vulnerable to email spoofing attacks — implement DMARC with at least p=quarantine.</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SRV records */}
      {srvRecs.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
            <span className={cn("border rounded px-1.5 py-0.5 font-mono font-bold", DnsTypeStyle("SRV"))}>SRV</span>
            Service Records
          </p>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b border-border">
                <th className="pb-2 text-xs font-medium text-muted-foreground">Service</th>
                <th className="pb-2 text-xs font-medium text-muted-foreground">Target</th>
                <th className="pb-2 text-xs font-medium text-muted-foreground">Port</th>
                <th className="pb-2 text-xs font-medium text-muted-foreground">Priority</th>
                <th className="pb-2 text-xs font-medium text-muted-foreground">Weight</th>
              </tr>
            </thead>
            <tbody>
              {srvRecs.map((r: any, i: number) => (
                <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                  <td className="py-2 font-mono text-[10px] text-muted-foreground">{r.value}</td>
                  <td className="py-2 font-mono text-xs">{r.target ?? "—"}</td>
                  <td className="py-2 text-xs font-mono text-foreground">{r.port ?? "—"}</td>
                  <td className="py-2 text-xs">{r.priority ?? "—"}</td>
                  <td className="py-2 text-xs">{r.weight ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* PTR / Reverse DNS */}
      {ptrRecs.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1.5">
            <span className={cn("border rounded px-1.5 py-0.5 font-mono font-bold", DnsTypeStyle("PTR"))}>PTR</span>
            Reverse DNS Lookups
          </p>
          <div className="space-y-1">
            {ptrRecs.map((r: any, i: number) => (
              <div key={i} className="flex items-center gap-2 bg-accent/10 rounded-lg px-3 py-2 text-xs font-mono">
                <span className="text-muted-foreground">{r.value}</span>
                <ChevronRight className="w-3 h-3 text-muted-foreground/50" />
                <span className="text-foreground">{r.target}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* All records — filterable table */}
      <div>
        <div className="flex items-center gap-2 mb-3 flex-wrap">
          <span className="text-xs font-semibold text-muted-foreground">Filter by type:</span>
          {types.map(t => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={cn(
                "text-[10px] font-mono font-bold border rounded px-2 py-0.5 transition-colors",
                filter === t ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
              )}
            >{t}</button>
          ))}
          <span className="ml-auto text-xs text-muted-foreground">{filtered.length} records</span>
        </div>

        <table className="w-full text-sm">
          <thead>
            <tr className="text-left border-b border-border">
              <th className="pb-2 text-xs font-medium text-muted-foreground w-20">Type</th>
              <th className="pb-2 text-xs font-medium text-muted-foreground">Value</th>
              <th className="pb-2 text-xs font-medium text-muted-foreground w-16">TTL</th>
              <th className="pb-2 text-xs font-medium text-muted-foreground w-20">Priority</th>
              <th className="pb-2 text-xs font-medium text-muted-foreground">Analysis</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r: any, i: number) => (
              <tr key={i} className="border-b border-border/40 hover:bg-accent/20 align-top">
                <td className="py-2">
                  <span className={cn("font-mono text-[10px] font-bold border rounded px-1.5 py-0.5", DnsTypeStyle(r.type))}>{r.type}</span>
                </td>
                <td className="py-2 font-mono text-[10px] text-muted-foreground max-w-[260px] break-all pr-4">
                  {r.type === "PTR" ? r.value : r.value}
                  {r.type === "PTR" && r.target && <span className="text-foreground"> → {r.target}</span>}
                </td>
                <td className="py-2 text-xs text-muted-foreground">{r.ttl > 0 ? `${r.ttl}s` : "—"}</td>
                <td className="py-2 text-xs text-muted-foreground">{r.priority ?? "—"}</td>
                <td className="py-2 text-xs text-muted-foreground max-w-[220px]">{r.notes ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function EmptyState({ message, icon: Icon = Shield }: { message: string; icon?: React.ElementType }) {
  return (
    <div className="text-center py-8 text-muted-foreground">
      <Icon className="w-7 h-7 mx-auto mb-2 opacity-40" />
      <p className="text-sm">{message}</p>
    </div>
  );
}
