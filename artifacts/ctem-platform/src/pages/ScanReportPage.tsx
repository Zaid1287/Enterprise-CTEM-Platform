import { useState, useEffect, useRef } from "react";
import { useParams, Link } from "wouter";
import { useGetScanAssetReport, useGetScan, useStopScan, getGetScanQueryKey, getGetScanAssetReportQueryKey } from "@workspace/api-client-react";
import {
  ChevronLeft, Shield, Globe, Network, AlertTriangle, Server,
  Database, Search, Cpu, Eye, CheckCircle2, XCircle, AlertCircle,
  Info, ExternalLink, Terminal, Wifi, Square, Loader2, Clock, Key,
  Lock, Fingerprint, Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import { downloadAsPdf } from "@/lib/generatePdf";

type AssetTab = "ports" | "vulns" | "subdomains" | "http" | "dns" | "endpoints" | "intel" | "secrets" | "raw";

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
    { key: "ports",      label: "Open Ports",     icon: Network,      count: summary.openPorts },
    { key: "vulns",      label: "CVEs",            icon: AlertTriangle, count: (selectedAsset?.cves ?? []).length },
    { key: "secrets",    label: "Secrets",         icon: Key,           count: secretsCount },
    { key: "subdomains", label: "Subdomains",      icon: Globe,         count: summary.subdomains },
    { key: "http",       label: "HTTP Info",       icon: Wifi },
    { key: "dns",        label: "DNS Records",     icon: Database,      count: summary.dnsRecords },
    { key: "endpoints",  label: "Endpoints",       icon: Search,        count: summary.endpoints },
    { key: "intel",      label: "Intelligence",    icon: Eye,           count: summary.intelItems },
    ...(!isClient ? [{ key: "raw" as AssetTab, label: "Raw Output", icon: Terminal }] : []),
  ];

  const toolResults = selectedAsset?.toolResults ?? [];
  const displayedTool = selectedTool ?? toolResults[0]?.toolName ?? null;

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
              {assetTab === "ports" && (
                <div>
                  {(selectedAsset.ports ?? []).length === 0 ? (
                    <EmptyState message="No open ports found" />
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-border">
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Port</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Protocol</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Service</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Version / Banner</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">State</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedAsset.ports ?? []).map((p: any, i: number) => (
                          <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                            <td className="py-2 font-mono font-bold text-primary">{p.port}</td>
                            <td className="py-2 text-xs text-muted-foreground uppercase">{p.protocol}</td>
                            <td className="py-2 font-medium">{p.service}</td>
                            <td className="py-2 text-xs text-muted-foreground font-mono">{p.version}</td>
                            <td className="py-2">
                              <span className="text-[10px] bg-green-500/15 text-green-400 border border-green-500/30 px-1.5 py-0.5 rounded">{p.state}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

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
              {assetTab === "subdomains" && (
                <div>
                  {(selectedAsset.subdomains ?? []).length === 0 ? (
                    <EmptyState message="No subdomains discovered" />
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-border">
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Subdomain</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">IP Address</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">CNAME</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">CDN</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedAsset.subdomains ?? []).map((s: any, i: number) => (
                          <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                            <td className="py-2 font-mono text-xs text-primary">{s.name}</td>
                            <td className="py-2 font-mono text-xs">{s.ip}</td>
                            <td className="py-2 text-xs text-muted-foreground truncate max-w-[180px]">{s.cname ?? "—"}</td>
                            <td className="py-2 text-xs">{s.cdnProvider ? <span className="text-[10px] bg-blue-500/15 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded">{s.cdnProvider}</span> : <span className="text-muted-foreground">—</span>}</td>
                            <td className="py-2">
                              <span className={cn("text-[10px] px-1.5 py-0.5 rounded border", s.status === "active" ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border")}>
                                {s.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

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
                    </div>
                  )}
                </div>
              )}

              {/* DNS Records tab */}
              {assetTab === "dns" && (
                <div>
                  {(selectedAsset.dnsRecords ?? []).length === 0 ? (
                    <EmptyState message="No DNS records collected" />
                  ) : (
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-border">
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Type</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Value</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">TTL</th>
                          <th className="pb-2 text-xs font-medium text-muted-foreground">Priority</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(selectedAsset.dnsRecords ?? []).map((r: any, i: number) => (
                          <tr key={i} className="border-b border-border/40 hover:bg-accent/20">
                            <td className="py-2">
                              <span className="font-mono text-[10px] font-bold bg-accent/60 px-1.5 py-0.5 rounded text-primary">{r.type}</span>
                            </td>
                            <td className="py-2 font-mono text-xs text-muted-foreground max-w-[360px] truncate">{r.value}</td>
                            <td className="py-2 text-xs">{r.ttl}s</td>
                            <td className="py-2 text-xs text-muted-foreground">{r.priority ?? "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
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
              {assetTab === "raw" && (
                <div className="space-y-3">
                  <div className="flex gap-2 flex-wrap">
                    {toolResults.map((tr: any) => (
                      <button
                        key={tr.toolName}
                        onClick={() => setSelectedTool(tr.toolName)}
                        className={cn(
                          "text-xs px-2.5 py-1 rounded-lg border transition-colors",
                          (displayedTool === tr.toolName)
                            ? "bg-primary/20 border-primary/40 text-foreground"
                            : "bg-accent/30 border-border text-muted-foreground hover:text-foreground"
                        )}
                      >
                        {tr.toolName}
                      </button>
                    ))}
                  </div>
                  {displayedTool && (() => {
                    const tr = toolResults.find((t: any) => t.toolName === displayedTool);
                    return tr ? (
                      <pre className="bg-muted/30 border border-border rounded-lg p-4 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {tr.rawOutput ?? "No output captured."}
                      </pre>
                    ) : null;
                  })()}
                </div>
              )}
            </div>
          </div>

        </div>
      </div>
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

function EmptyState({ message, icon: Icon = Shield }: { message: string; icon?: React.ElementType }) {
  return (
    <div className="text-center py-8 text-muted-foreground">
      <Icon className="w-7 h-7 mx-auto mb-2 opacity-40" />
      <p className="text-sm">{message}</p>
    </div>
  );
}
