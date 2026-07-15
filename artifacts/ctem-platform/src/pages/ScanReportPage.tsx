import { useState, useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "wouter";
import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
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
  Lock, Fingerprint, Download, Camera, X, Tag, Code, FileCode, ShieldAlert, Cloud, GitBranch, Github, FolderOpen, Filter, Zap, Wrench,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";
import { downloadScanReportPdf } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";

type AssetTab = "ports" | "vulns" | "subdomains" | "http" | "dns" | "endpoints" | "intel" | "secrets" | "raw" | "screenshots" | "technologies" | "js" | "params" | "cloud" | "secretshunt" | "dirfuzz" | "nuclei";


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

const TOOL_CAT_LABELS: Record<string, string> = {
  recon:     "Reconnaissance",
  web_recon: "Web Reconnaissance",
  port_scan: "Port Scanning",
  vuln_scan: "Vulnerability Scanning",
  ssl:       "SSL/TLS Analysis",
  secrets:   "Secrets Detection",
};

function toolDisplayLabel(tool: ToolProgress): string {
  if (tool.detail) {
    const stripped = tool.detail.replace(/^\[.*?\]\s*/, "").split("—")[0].trim();
    if (stripped.length > 2) return stripped;
  }
  return TOOL_CAT_LABELS[tool.toolCategory] ??
    tool.toolCategory.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

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
    async function fetchProgress() {
      try {
        const token = getToken();
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
                              {toolDisplayLabel(tool)}
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

// ── ASM Score & Report Metric Helpers ─────────────────────────────────────
function computeAsmScore(asset: any): number {
  let score = 100;
  score -= Math.min((asset.summary?.criticalVulns ?? 0) * 15, 40);
  score -= Math.min((asset.summary?.highVulns ?? 0) * 6, 20);
  score -= Math.min((asset.secrets ?? []).length * 8, 20);
  score -= Math.min((asset.vulnScan?.stats?.critical ?? 0) * 12, 30);
  score -= Math.min((asset.vulnScan?.stats?.high ?? 0) * 4, 15);
  score -= Math.min((asset.secretsHunt?.stats?.secretsFound ?? 0) * 5, 15);
  if ((asset.secretsHunt?.stats?.gitDirsExposed ?? 0) > 0) score -= 10;
  const waf = asset.httpInfo?.waf;
  if (!waf || waf === "none" || waf === "None") score -= 5;
  if ((asset.summary?.openPorts ?? 0) > 20) score -= 5;
  return Math.max(0, Math.min(100, Math.round(score)));
}

function computeScanAsmScore(assetReports: any[]): number {
  if (assetReports.length === 0) return 100;
  return Math.round(assetReports.map(computeAsmScore).reduce((a, b) => a + b, 0) / assetReports.length);
}

function worstSeverity(assetReports: any[]): "critical" | "high" | "medium" | "low" {
  for (const a of assetReports) {
    if ((a.summary?.criticalVulns ?? 0) > 0 || (a.vulnScan?.stats?.critical ?? 0) > 0) return "critical";
  }
  for (const a of assetReports) {
    if ((a.summary?.highVulns ?? 0) > 0 || (a.vulnScan?.stats?.high ?? 0) > 0 || (a.secrets ?? []).length > 0) return "high";
  }
  for (const a of assetReports) {
    if ((a.cves ?? []).some((c: any) => c.severity === "medium")) return "medium";
  }
  return "low";
}

function worstImportance(assetReports: any[]): "critical" | "high" | "medium" | "low" {
  for (const a of assetReports) {
    if ((a.summary?.criticalVulns ?? 0) > 0 || (a.vulnScan?.stats?.critical ?? 0) > 0 || (a.secrets ?? []).length >= 3) return "critical";
  }
  for (const a of assetReports) {
    if ((a.summary?.highVulns ?? 0) > 0 || (a.secrets ?? []).length > 0) return "high";
  }
  for (const a of assetReports) {
    if ((a.summary?.subdomains ?? 0) > 5 || (a.summary?.openPorts ?? 0) > 10) return "medium";
  }
  return "low";
}

function SectionCard({
  title, icon: Icon, count, accent, fullWidth, children,
}: {
  title: string; icon: React.ElementType; count?: number; accent?: "red" | "orange" | "yellow";
  fullWidth?: boolean; children: React.ReactNode;
}) {
  const palette = {
    red:    { leftBar: "bg-red-500",    iconBg: "bg-red-500/15",    iconColor: "text-red-400",    badgeCls: "bg-red-500/20 text-red-400 border border-red-500/30" },
    orange: { leftBar: "bg-orange-500", iconBg: "bg-orange-500/15", iconColor: "text-orange-400", badgeCls: "bg-orange-500/20 text-orange-400 border border-orange-500/30" },
    yellow: { leftBar: "bg-yellow-500", iconBg: "bg-yellow-500/15", iconColor: "text-yellow-400", badgeCls: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" },
    none:   { leftBar: "bg-primary/60", iconBg: "bg-primary/10",    iconColor: "text-primary",    badgeCls: "bg-primary/15 text-primary border border-primary/30" },
  };
  const p = palette[accent ?? "none"];
  return (
    <div className={cn("bg-card border border-border rounded-2xl overflow-hidden flex flex-col", fullWidth && "xl:col-span-2")}>
      <div className="flex items-center justify-between px-4 py-3 border-b border-border/50 shrink-0 bg-gradient-to-r from-muted/30 to-transparent">
        <div className="flex items-center gap-2.5">
          <div className={cn("w-1 h-6 rounded-full shrink-0", p.leftBar)} />
          <div className={cn("w-6 h-6 rounded-md flex items-center justify-center shrink-0", p.iconBg)}>
            <Icon className={cn("w-3 h-3", p.iconColor)} />
          </div>
          <h3 className="text-[11px] font-bold uppercase tracking-widest text-foreground/60">{title}</h3>
        </div>
        {count !== undefined && (
          <span className={cn(
            "text-[11px] font-black px-2.5 py-0.5 rounded-full min-w-[28px] text-center tabular-nums",
            count > 0 ? p.badgeCls : "bg-muted/40 text-muted-foreground/30 border border-border"
          )}>{count}</span>
        )}
      </div>
      <div className="p-5 overflow-y-auto flex-1">
        {children}
      </div>
    </div>
  );
}

function PaginatedSection({ items, pageSize = 25, renderItem, emptyMessage, emptyIcon }: {
  items: any[]; pageSize?: number;
  renderItem: (item: any, idx: number) => React.ReactNode;
  emptyMessage?: string; emptyIcon?: React.ElementType;
}) {
  const [page, setPage] = useState(0);
  const totalPages = Math.ceil(items.length / pageSize);
  const visible = items.slice(page * pageSize, (page + 1) * pageSize);
  if (items.length === 0) {
    return emptyMessage ? <EmptyState message={emptyMessage} icon={emptyIcon} /> : null;
  }
  return (
    <div>
      <div className="space-y-0.5">
        {visible.map((item, i) => renderItem(item, page * pageSize + i))}
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-4 mt-2 border-t border-border/30">
          <span className="text-xs text-muted-foreground">
            {(page * pageSize + 1).toLocaleString()}–{Math.min((page + 1) * pageSize, items.length).toLocaleString()} of {items.length.toLocaleString()}
          </span>
          <div className="flex items-center gap-1.5">
            <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
              className="text-xs px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-accent/40 transition-colors">← Prev</button>
            <span className="text-xs text-muted-foreground px-2 tabular-nums">{page + 1} / {totalPages}</span>
            <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
              className="text-xs px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-accent/40 transition-colors">Next →</button>
          </div>
        </div>
      )}
    </div>
  );
}

function SubdomainsContent({ subdomains }: { subdomains: any[] }) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 48;
  const filtered = search
    ? subdomains.filter((s: any) => {
        const name = typeof s === "string" ? s : String(s.subdomain ?? s.name ?? "");
        return name.toLowerCase().includes(search.toLowerCase());
      })
    : subdomains;
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  if (subdomains.length === 0) return <EmptyState message="No subdomains discovered" icon={Globe} />;
  return (
    <div className="space-y-4">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          placeholder={`Filter ${subdomains.length} subdomains…`}
          className="w-full pl-9 pr-4 py-2 bg-muted/20 border border-border rounded-xl text-xs focus:outline-none focus:border-primary/50 placeholder:text-muted-foreground/50"
        />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {visible.map((s: any, i: number) => {
          const name = typeof s === "string" ? s : (s.subdomain ?? s.name ?? "");
          const ip   = typeof s === "object" ? (s.ip ?? "") : "";
          return (
            <div key={i} className="flex items-center gap-2.5 bg-muted/15 border border-border/50 rounded-xl px-3 py-2.5 hover:bg-accent/20 transition-colors">
              <Globe className="w-3 h-3 text-primary/50 shrink-0" />
              <span className="text-xs font-mono text-foreground/80 truncate flex-1">{name}</span>
              {ip && <span className="text-[10px] text-muted-foreground/50 font-mono shrink-0">{ip}</span>}
            </div>
          );
        })}
      </div>
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2 border-t border-border/30">
          <span className="text-xs text-muted-foreground">
            {(page * PAGE_SIZE + 1).toLocaleString()}–{Math.min((page + 1) * PAGE_SIZE, filtered.length).toLocaleString()} of {filtered.length.toLocaleString()}
          </span>
          <div className="flex items-center gap-1.5">
            <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
              className="text-xs px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-accent/40 transition-colors">← Prev</button>
            <span className="text-xs text-muted-foreground px-2 tabular-nums">{page + 1} / {totalPages}</span>
            <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
              className="text-xs px-3 py-1.5 rounded-lg border border-border disabled:opacity-30 hover:bg-accent/40 transition-colors">Next →</button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function ScanReportPage() {
  const params = useParams<{ id: string }>();
  const scanId = Number(params.id);
  const [selectedAssetIdx, setSelectedAssetIdx] = useState(0);
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const { user } = useAuth();
  const isClient = user?.role === "client";
  const queryClient = useQueryClient();
  const prevScanStatusRef = useRef<string | undefined>(undefined);

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
        if (["running", "pending", "unknown", "completed"].includes(scanStatus)) return 4000;
        return false;
      },
    },
  });

  useEffect(() => {
    const prev = prevScanStatusRef.current;
    prevScanStatusRef.current = scanStatus;
    if (prev === "running" && (scanStatus === "completed" || scanStatus === "failed")) {
      queryClient.invalidateQueries({ queryKey: getGetScanAssetReportQueryKey(scanId) });
    }
  }, [scanStatus, scanId, queryClient]);

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
        <>
          <LiveProgressView
            scanId={scanId}
            scanStatus={scanStatus}
            scan={scan}
            stopping={stopping}
            onStop={() => setConfirmStop(true)}
          />
          <Dialog open={confirmStop} onOpenChange={setConfirmStop}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <Square className="w-5 h-5 text-destructive fill-destructive" /> Stop Scan?
                </DialogTitle>
              </DialogHeader>
              <p className="text-sm text-muted-foreground">This will immediately cancel the running scan. Partial results will be preserved but the scan cannot be resumed.</p>
              <DialogFooter className="mt-2">
                <Button variant="outline" onClick={() => setConfirmStop(false)} disabled={stopping}>Keep Running</Button>
                <Button variant="destructive" onClick={async () => { setConfirmStop(false); await handleStop(); }} disabled={stopping}>
                  {stopping ? <><Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> Stopping…</> : "Stop Scan"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
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

  const toolResults: any[] = selectedAsset?.toolResults ?? [];
  const configuredTools: any[] = selectedAsset?.configuredTools ?? [];
  const allToolNames = Array.from(new Set([
    ...configuredTools.map((t: any) => t.name),
    ...toolResults.map((t: any) => t.toolName),
  ]));
  const displayedTool = selectedTool ?? allToolNames[0] ?? null;

  // ── Derived scan-level metrics ────────────────────────────────────────────
  const totalFindings      = assetReports.reduce((a: number, r: any) => a + (r.summary?.vulnerabilities ?? 0), 0);
  const totalCritHigh      = assetReports.reduce((a: number, r: any) => a + (r.summary?.criticalVulns ?? 0) + (r.summary?.highVulns ?? 0), 0);
  const totalCriticalCves  = (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "critical").length;
  const totalHighCves      = (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "high").length;
  const durationStr   = (scan?.startedAt && scan?.completedAt)
    ? formatDuration(new Date(scan.startedAt).getTime(), new Date(scan.completedAt).getTime())
    : scanStatus === "running" ? "In progress" : "—";

  const scanAsmScore = computeScanAsmScore(assetReports);
  const scanSeverity = worstSeverity(assetReports);

  const STATUS_META: Record<string, { bar: string; bg: string; border: string; text: string; label: string }> = {
    completed: { bar: "bg-green-500",  bg: "bg-green-500/10",  border: "border-green-500/30",  text: "text-green-400",        label: "Completed" },
    running:   { bar: "bg-blue-500",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   text: "text-blue-400",         label: "Running"   },
    pending:   { bar: "bg-amber-500",  bg: "bg-amber-500/10",  border: "border-amber-500/30",  text: "text-amber-400",        label: "Pending"   },
    cancelled: { bar: "bg-muted-foreground/40", bg: "bg-muted", border: "border-border", text: "text-muted-foreground", label: "Cancelled" },
  };
  const sm = STATUS_META[scanStatus] ?? STATUS_META.completed;

  const SEV_COLORS_MAP: Record<string, string> = {
    critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-green-400",
  };
  const SEV_BG_MAP: Record<string, string> = {
    critical: "bg-red-500/5 border-red-500/30",
    high:     "bg-orange-500/5 border-orange-500/30",
    medium:   "bg-yellow-500/5 border-yellow-500/30",
    low:      "bg-green-500/5 border-green-500/30",
  };
  const asmColor = scanAsmScore >= 80 ? "text-green-400" : scanAsmScore >= 60 ? "text-yellow-400" : scanAsmScore >= 40 ? "text-orange-400" : "text-red-400";

  return (
    <div className="space-y-5">

      {/* ── Breadcrumb + actions ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Link href="/scan-reports">
            <button className="flex items-center gap-1.5 hover:text-foreground transition-colors">
              <ChevronLeft className="w-3.5 h-3.5" /> Scan Reports
            </button>
          </Link>
          <span className="opacity-40">/</span>
          <span className="text-foreground/70 truncate max-w-sm">{scan?.name ?? `Scan #${scanId}`}</span>
        </div>
        <div className="flex items-center gap-2">
          {(scanStatus === "running" || scanStatus === "pending") && (
            <>
              <Button size="sm" variant="outline"
                className="h-7 text-xs border-red-500/40 text-red-400 hover:bg-red-500/10"
                onClick={() => setConfirmStop(true)} disabled={stopping}>
                {stopping ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Square className="w-3 h-3 mr-1 fill-current" />}
                Stop Scan
              </Button>
              <Dialog open={confirmStop} onOpenChange={setConfirmStop}>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                      <Square className="w-5 h-5 text-destructive fill-destructive" /> Stop Scan?
                    </DialogTitle>
                  </DialogHeader>
                  <p className="text-sm text-muted-foreground">This will immediately cancel the running scan. Partial results will be preserved but the scan cannot be resumed.</p>
                  <DialogFooter className="mt-2">
                    <Button variant="outline" onClick={() => setConfirmStop(false)} disabled={stopping}>Keep Running</Button>
                    <Button variant="destructive" onClick={async () => { setConfirmStop(false); await handleStop(); }} disabled={stopping}>
                      {stopping ? <><Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> Stopping…</> : "Stop Scan"}
                    </Button>
                  </DialogFooter>
                </DialogContent>
              </Dialog>
            </>
          )}
          {scanStatus === "completed" && (
            <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5"
              disabled={downloading}
              onClick={async () => {
                setDownloading(true);
                try { await downloadScanReportPdf(scan, assetReports, getToken()); }
                catch { /* ignore */ }
                finally { setDownloading(false); }
              }}>
              {downloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
              {downloading ? "Generating…" : "Download Report"}
            </Button>
          )}
        </div>
      </div>

      {/* ── Hero banner ─────────────────────────────────────────────────────── */}
      <div className="relative rounded-2xl border border-border overflow-hidden bg-card">
        {/* Subtle dot-grid pattern */}
        <div className="absolute inset-0 opacity-[0.025]"
          style={{ backgroundImage: "radial-gradient(circle, hsl(var(--foreground)) 1px, transparent 1px)", backgroundSize: "20px 20px" }} />
        {/* Threat-level gradient tint */}
        <div className={cn("absolute inset-0 opacity-30",
          scanSeverity === "critical" ? "bg-gradient-to-br from-red-950/60 via-transparent to-transparent" :
          scanSeverity === "high"     ? "bg-gradient-to-br from-orange-950/60 via-transparent to-transparent" :
          "bg-gradient-to-br from-yellow-950/40 via-transparent to-transparent"
        )} />
        {/* Top status bar */}
        <div className={cn("h-0.5 w-full", sm.bar)} />

        <div className="relative px-6 py-5">
          <div className="flex items-start gap-6">
            {/* ASM Score radial gauge */}
            <div className="relative shrink-0 w-[84px] h-[84px]">
              <svg width="84" height="84" className="-rotate-90">
                <circle cx="42" cy="42" r="34" fill="none" stroke="currentColor"
                  className="text-muted/20" strokeWidth="7" />
                <circle cx="42" cy="42" r="34" fill="none" stroke="currentColor"
                  className={asmColor}
                  strokeWidth="7"
                  strokeLinecap="round"
                  strokeDasharray={`${2 * Math.PI * 34}`}
                  strokeDashoffset={`${2 * Math.PI * 34 * (1 - scanAsmScore / 100)}`}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center rotate-0">
                <p className={cn("text-2xl font-black tabular-nums leading-none", asmColor)}>{scanAsmScore}</p>
                <p className="text-[8px] uppercase tracking-widest text-muted-foreground/60 mt-0.5">ASM</p>
              </div>
            </div>

            {/* Scan info */}
            <div className="flex-1 min-w-0 pt-0.5">
              <div className="flex flex-wrap items-center gap-1.5 mb-2.5">
                <span className={cn("text-[10px] flex items-center gap-1 px-2.5 py-1 rounded-full font-bold uppercase border", sm.bg, sm.text, sm.border)}>
                  {scanStatus === "running"   && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
                  {scanStatus === "completed" && <CheckCircle2 className="w-2.5 h-2.5" />}
                  {scanStatus === "cancelled" && <XCircle className="w-2.5 h-2.5" />}
                  {sm.label}
                </span>
                <span className={cn("text-[10px] px-2.5 py-1 rounded-full font-bold uppercase border",
                  scanSeverity === "critical" ? "bg-red-500/10 text-red-400 border-red-500/30" :
                  scanSeverity === "high"     ? "bg-orange-500/10 text-orange-400 border-orange-500/30" :
                  "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                )}>
                  {scanSeverity} threat
                </span>
                {totalCritHigh > 0 && (
                  <span className="text-[10px] bg-red-500/15 text-red-400 border border-red-500/30 px-2.5 py-1 rounded-full font-bold flex items-center gap-1">
                    <XCircle className="w-2.5 h-2.5" />{totalCritHigh} crit/high
                  </span>
                )}
              </div>

              <h1 className="text-lg font-bold leading-tight tracking-tight">{scan?.name ?? `Pipeline Scan Report #${scanId}`}</h1>
              <p className="text-xs text-muted-foreground mt-1">
                {scan?.startedAt && new Date(scan.startedAt).toLocaleDateString("en-US", { weekday: "short", month: "long", day: "numeric", year: "numeric" })}
                {scan?.startedAt && ` · ${new Date(scan.startedAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" })}`}
                {durationStr !== "—" && <span className="ml-2 opacity-60">· {durationStr}</span>}
              </p>

              {/* Quick stats row */}
              <div className="flex items-center gap-4 mt-3.5 flex-wrap text-xs">
                <span className="flex items-center gap-1.5 text-muted-foreground">
                  <Globe className="w-3.5 h-3.5" />
                  <span className="font-bold text-foreground">{assetReports.length}</span> asset{assetReports.length !== 1 ? "s" : ""}
                </span>
                <span className="flex items-center gap-1.5 text-muted-foreground">
                  <AlertTriangle className={cn("w-3.5 h-3.5", totalFindings > 0 ? "text-orange-400" : "")} />
                  <span className="font-bold text-foreground">{totalFindings}</span> finding{totalFindings !== 1 ? "s" : ""}
                </span>
                {(summary.waf && summary.waf !== "none") && (
                  <span className="flex items-center gap-1.5 bg-blue-500/10 border border-blue-500/25 rounded-full px-2.5 py-0.5 text-blue-400 font-medium">
                    <Shield className="w-3 h-3" /> WAF: {summary.waf}
                  </span>
                )}
                {summary.cdn && (
                  <span className="flex items-center gap-1.5 bg-purple-500/10 border border-purple-500/25 rounded-full px-2.5 py-0.5 text-purple-400 font-medium">
                    <Zap className="w-3 h-3" /> CDN: {summary.cdn}
                  </span>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ── 4 Summary Metric Cards ─────────────────────────────────────── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {/* CVEs Critical/High */}
        <div className="border border-red-500/25 bg-red-500/5 rounded-2xl p-5 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-red-500/10 to-transparent pointer-events-none" />
          <div className="flex items-center gap-2 mb-3">
            <div className="w-7 h-7 rounded-xl bg-red-500/20 border border-red-500/30 flex items-center justify-center">
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-widest text-red-400/80">Critical / High</span>
          </div>
          <div className="flex items-end gap-1.5">
            <p className="text-4xl font-black tabular-nums leading-none text-red-400">{totalCriticalCves}</p>
            <p className="text-xl font-black tabular-nums leading-none text-orange-400 pb-0.5">/{totalHighCves}</p>
          </div>
          <p className="text-[10px] text-muted-foreground/60 mt-2">CVEs by severity</p>
          <div className="mt-3 flex gap-0.5 h-1 rounded-full overflow-hidden">
            {totalCriticalCves > 0 && <div className="bg-red-500 h-full" style={{ flex: totalCriticalCves }} />}
            {totalHighCves > 0    && <div className="bg-orange-500 h-full" style={{ flex: totalHighCves }} />}
            {Math.max(0, (selectedAsset?.cves?.length ?? 0) - totalCriticalCves - totalHighCves) > 0 && <div className="bg-muted/40 h-full" style={{ flex: Math.max(1, (selectedAsset?.cves?.length ?? 0) - totalCriticalCves - totalHighCves) }} />}
          </div>
        </div>

        {/* Severity */}
        <div className={cn("border rounded-2xl p-5 relative overflow-hidden", SEV_BG_MAP[scanSeverity])}>
          <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent pointer-events-none" />
          <div className="flex items-center gap-2 mb-3">
            <div className={cn("w-7 h-7 rounded-xl flex items-center justify-center border", SEV_BG_MAP[scanSeverity])}>
              <AlertTriangle className={cn("w-3.5 h-3.5", SEV_COLORS_MAP[scanSeverity])} />
            </div>
            <span className={cn("text-[10px] font-bold uppercase tracking-widest", SEV_COLORS_MAP[scanSeverity], "opacity-80")}>Risk Level</span>
          </div>
          <p className={cn("text-3xl font-black capitalize leading-none", SEV_COLORS_MAP[scanSeverity])}>{scanSeverity}</p>
          <p className="text-[10px] text-muted-foreground/60 mt-2">Worst finding</p>
          <div className="mt-3 flex items-center gap-1">
            {(["low","medium","high","critical"] as const).map(s => (
              <div key={s} className={cn("h-1.5 flex-1 rounded-full transition-all",
                s === scanSeverity ? SEV_COLORS_MAP[s].replace("text-","bg-").replace("-400","-500") :
                "bg-muted/25"
              )} />
            ))}
          </div>
        </div>

        {/* Assets Scanned */}
        <div className="bg-card border border-border rounded-2xl p-5 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <div className="flex items-center gap-2 mb-3">
            <div className="w-7 h-7 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
              <Globe className="w-3.5 h-3.5 text-primary" />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70">Assets</span>
          </div>
          <p className="text-4xl font-black text-primary leading-none tabular-nums">{assetReports.length}</p>
          <p className="text-[10px] text-muted-foreground/60 mt-2">Scanned targets</p>
          <div className="mt-3 flex gap-1">
            {assetReports.slice(0, 8).map((_: any, i: number) => (
              <div key={i} className={cn("h-1.5 flex-1 rounded-full", i === selectedAssetIdx ? "bg-primary" : "bg-primary/20")} />
            ))}
          </div>
        </div>

        {/* Duration */}
        <div className="bg-card border border-border rounded-2xl p-5 relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-muted/30 to-transparent pointer-events-none" />
          <div className="flex items-center gap-2 mb-3">
            <div className="w-7 h-7 rounded-xl bg-muted border border-border flex items-center justify-center">
              <Clock className="w-3.5 h-3.5 text-muted-foreground" />
            </div>
            <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70">Duration</span>
          </div>
          <p className="text-3xl font-black text-foreground leading-none tabular-nums">{durationStr}</p>
          <p className="text-[10px] text-muted-foreground/60 mt-2">Scan time</p>
          <div className="mt-3 flex items-center gap-1.5 text-[10px] text-muted-foreground/50">
            <span>{summary.toolsRun ?? 0} tools run</span>
          </div>
        </div>
      </div>

      {/* ── Asset selector ─────────────────────────────────────────────────── */}
      <div className="flex gap-2.5 overflow-x-auto pb-1">
        {assetReports.map((asset: any, idx: number) => {
          const critVulns  = asset.summary?.criticalVulns ?? 0;
          const highVulns  = asset.summary?.highVulns ?? 0;
          const secretsNum = (asset.secrets ?? []).length;
          const assetScore = computeAsmScore(asset);
          const scoreColor = assetScore >= 80 ? "text-green-400" : assetScore >= 60 ? "text-yellow-400" : assetScore >= 40 ? "text-orange-400" : "text-red-400";
          const scoreBg    = assetScore >= 80 ? "bg-green-500" : assetScore >= 60 ? "bg-yellow-500" : assetScore >= 40 ? "bg-orange-500" : "bg-red-500";
          const isActive   = idx === selectedAssetIdx;
          return (
            <button
              key={asset.assetId}
              onClick={() => { setSelectedAssetIdx(idx); setSelectedTool(null); }}
              className={cn(
                "flex-shrink-0 text-left rounded-2xl border transition-all duration-150 overflow-hidden",
                isActive
                  ? "bg-card border-primary/50 shadow-lg shadow-primary/10 ring-1 ring-primary/20"
                  : "bg-card/60 border-border hover:border-muted-foreground/30 hover:bg-card"
              )}
            >
              {/* Score bar top */}
              <div className={cn("h-0.5 w-full", isActive ? scoreBg : "bg-transparent")} />
              <div className="px-4 py-3">
                <div className="flex items-center gap-2 mb-1.5">
                  <span className={cn("text-lg font-black tabular-nums leading-none", scoreColor)}>{assetScore}</span>
                  <span className="text-[9px] text-muted-foreground/50 font-medium">/ 100</span>
                  <div className="flex gap-1 ml-1">
                    {critVulns > 0 && <span className="text-[8px] font-bold bg-red-500/15 text-red-400 border border-red-500/20 rounded px-1 py-0.5">CRIT</span>}
                    {highVulns > 0 && !critVulns && <span className="text-[8px] font-bold bg-orange-500/15 text-orange-400 border border-orange-500/20 rounded px-1 py-0.5">HIGH</span>}
                    {secretsNum > 0 && <span className="text-[8px] font-bold bg-yellow-500/15 text-yellow-400 border border-yellow-500/20 rounded px-1 py-0.5">KEY</span>}
                  </div>
                  {scanStatus === "running" && isActive && <Loader2 className="w-2.5 h-2.5 text-blue-400 animate-spin ml-auto" />}
                </div>
                <p className="text-sm font-semibold truncate leading-tight max-w-[180px]">{asset.assetName}</p>
                <p className="text-[10px] text-muted-foreground truncate mt-0.5 max-w-[180px] font-mono">{asset.assetValue}</p>
                <div className="flex gap-1.5 mt-2">
                  {(asset.summary?.openPorts ?? 0) > 0 && <span className="text-[9px] bg-muted/30 text-muted-foreground rounded px-1.5 py-0.5">{asset.summary.openPorts} ports</span>}
                  {(asset.summary?.subdomains ?? 0) > 0 && <span className="text-[9px] bg-muted/30 text-muted-foreground rounded px-1.5 py-0.5">{asset.summary.subdomains} subs</span>}
                  {(asset.summary?.cves ?? 0) > 0 && <span className="text-[9px] bg-red-500/10 text-red-400 rounded px-1.5 py-0.5">{asset.summary.cves} CVEs</span>}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* ── Asset summary stats strip ──────────────────────────────────────── */}
      <div className="grid grid-cols-4 sm:grid-cols-7 xl:grid-cols-9 gap-2.5">
        {([
          { label: "Open Ports",  value: summary.openPorts ?? 0,                   icon: Network,    highlight: false,                              color: "text-foreground" },
          { label: "CVEs",        value: (selectedAsset?.cves ?? []).length,        icon: AlertTriangle, highlight: (selectedAsset?.cves ?? []).length > 0, color: (selectedAsset?.cves ?? []).length > 0 ? "text-red-400" : "text-foreground" },
          { label: "Subdomains",  value: summary.subdomains ?? 0,                   icon: Globe,      highlight: false,                              color: "text-foreground" },
          { label: "DNS Records", value: summary.dnsRecords ?? 0,                   icon: Database,   highlight: false,                              color: "text-foreground" },
          { label: "Endpoints",   value: summary.endpoints ?? 0,                    icon: Search,     highlight: false,                              color: "text-foreground" },
          { label: "Secrets",     value: secretsCount,                              icon: Key,        highlight: secretsCount > 0,                   color: secretsCount > 0 ? "text-yellow-400" : "text-foreground" },
          { label: "Tools Run",   value: summary.toolsRun ?? 0,                     icon: Wrench,     highlight: false,                              color: "text-primary" },
        ] as { label: string; value: number | string; icon: React.ElementType; highlight: boolean; color: string }[]).map(({ label, value, icon: StatIcon, highlight, color }) => (
          <div key={label} className={cn(
            "bg-card border rounded-xl p-3 text-center transition-colors",
            highlight ? "border-red-500/20 bg-red-500/5" : "border-border"
          )}>
            <StatIcon className={cn("w-3.5 h-3.5 mx-auto mb-1.5 opacity-50", color)} />
            <p className={cn("text-lg font-black tabular-nums leading-none", color)}>{value}</p>
            <p className="text-[9px] text-muted-foreground/60 mt-1 uppercase tracking-wide font-medium">{label}</p>
          </div>
        ))}
        {summary.waf && summary.waf !== "none" && (
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3 text-center">
            <Shield className="w-3.5 h-3.5 mx-auto mb-1.5 opacity-50 text-blue-400" />
            <p className="text-xs font-bold text-blue-400 leading-snug">{summary.waf}</p>
            <p className="text-[9px] text-muted-foreground/60 mt-1 uppercase tracking-wide font-medium">WAF</p>
          </div>
        )}
        {summary.cdn && (
          <div className="bg-purple-500/5 border border-purple-500/20 rounded-xl p-3 text-center">
            <Zap className="w-3.5 h-3.5 mx-auto mb-1.5 opacity-50 text-purple-400" />
            <p className="text-xs font-bold text-purple-400 leading-snug">{summary.cdn}</p>
            <p className="text-[9px] text-muted-foreground/60 mt-1 uppercase tracking-wide font-medium">CDN</p>
          </div>
        )}
      </div>

      {/* ── Data cards: full-width ─────────────────────────────────────────── */}
      <div>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">

            {/* ── 1. Open Ports (full-width) ─────────────────────────── */}
            <SectionCard icon={Network} title="Open Ports" count={(selectedAsset?.ports ?? []).length} fullWidth>
              <PaginatedSection
                items={selectedAsset?.ports ?? []}
                pageSize={25}
                emptyMessage="No open ports detected"
                emptyIcon={Network}
                renderItem={(port, i) => <PortRow key={i} port={port} />}
              />
            </SectionCard>

            {/* ── 2. CVEs ──────────────────────────────────────────────── */}
            <SectionCard icon={AlertTriangle} title="CVEs" count={(selectedAsset?.cves ?? []).length} fullWidth accent="red">
              {(selectedAsset?.cves ?? []).length > 0 && (
                <div className="flex items-center gap-2 mb-4 pb-4 border-b border-border/30">
                  {[
                    { label: "Critical", count: (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "critical").length, color: "bg-red-500", text: "text-red-400" },
                    { label: "High",     count: (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "high").length,     color: "bg-orange-500", text: "text-orange-400" },
                    { label: "Medium",   count: (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "medium").length,   color: "bg-yellow-500", text: "text-yellow-400" },
                    { label: "Low",      count: (selectedAsset?.cves ?? []).filter((c: any) => c.severity === "low").length,      color: "bg-blue-500",  text: "text-blue-400" },
                  ].map(({ label, count, color, text }) => count > 0 && (
                    <div key={label} className="flex items-center gap-1.5">
                      <div className={cn("w-2 h-2 rounded-full shrink-0", color)} />
                      <span className={cn("text-sm font-black tabular-nums", text)}>{count}</span>
                      <span className="text-[10px] text-muted-foreground">{label}</span>
                    </div>
                  ))}
                  <div className="ml-auto flex-1 max-w-[140px]">
                    <div className="flex h-1.5 rounded-full overflow-hidden gap-px">
                      {[
                        { sev: "critical", color: "bg-red-500" },
                        { sev: "high",     color: "bg-orange-500" },
                        { sev: "medium",   color: "bg-yellow-500" },
                        { sev: "low",      color: "bg-blue-400" },
                      ].map(({ sev, color }) => {
                        const n = (selectedAsset?.cves ?? []).filter((c: any) => c.severity === sev).length;
                        return n > 0 ? <div key={sev} className={cn("h-full", color)} style={{ flex: n }} /> : null;
                      })}
                    </div>
                  </div>
                </div>
              )}
              <PaginatedSection
                items={selectedAsset?.cves ?? []}
                pageSize={12}
                emptyMessage="No CVEs found"
                emptyIcon={AlertTriangle}
                renderItem={(cve) => {
                  const sev = (cve.severity ?? "unknown").toLowerCase();
                  const leftBar  = sev === "critical" ? "bg-red-500"    : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-yellow-500" : "bg-blue-400";
                  const sevBadge = sev === "critical" ? "text-red-400 bg-red-500/10 border-red-500/30"
                    : sev === "high"   ? "text-orange-400 bg-orange-500/10 border-orange-500/30"
                    : sev === "medium" ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/30"
                    : "text-blue-400 bg-blue-500/10 border-blue-500/30";
                  const cvssNum   = cve.cvss !== undefined ? Number(cve.cvss) : null;
                  const cvssColor = cvssNum === null ? "" : cvssNum >= 9 ? "text-red-400" : cvssNum >= 7 ? "text-orange-400" : cvssNum >= 4 ? "text-yellow-400" : "text-blue-400";
                  const cvssBarW  = cvssNum !== null ? `${Math.min(cvssNum / 10, 1) * 100}%` : "0%";
                  return (
                    <div key={cve.id} className="group mb-2 last:mb-0 rounded-xl border border-border/50 bg-card/50 hover:border-border hover:bg-card transition-all overflow-hidden flex">
                      {/* Left severity stripe */}
                      <div className={cn("w-1 shrink-0", leftBar)} />
                      <div className="flex-1 px-3.5 py-3 min-w-0">
                        <div className="flex items-start gap-2">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-0.5">
                              <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve ?? cve.id}`} target="_blank" rel="noopener noreferrer"
                                className="text-xs font-mono font-bold text-primary hover:underline shrink-0">
                                {cve.cve ?? cve.id}
                              </a>
                              {cve.cwe && <span className="text-[9px] font-mono text-muted-foreground/60 border border-border/50 rounded px-1">{cve.cwe}</span>}
                            </div>
                            <p className="text-xs font-medium text-foreground/90 leading-snug">
                              {cve.title ?? cve.description ?? ""}
                            </p>
                            {cve.remediation && (
                              <p className="text-[10px] text-green-400/80 mt-1 leading-snug line-clamp-1">
                                Fix: {cve.remediation}
                              </p>
                            )}
                          </div>
                          <div className="shrink-0 flex flex-col items-end gap-1">
                            <span className={cn("text-[9px] font-black uppercase border rounded-md px-1.5 py-0.5", sevBadge)}>{sev}</span>
                            {cvssNum !== null && (
                              <div className="text-right">
                                <p className={cn("text-sm font-black tabular-nums leading-none", cvssColor)}>{cvssNum.toFixed(1)}</p>
                                <p className="text-[8px] text-muted-foreground/50 uppercase">CVSS</p>
                              </div>
                            )}
                          </div>
                        </div>
                        {cvssNum !== null && (
                          <div className="mt-2 h-0.5 bg-muted/20 rounded-full overflow-hidden">
                            <div className={cn("h-full rounded-full", leftBar)} style={{ width: cvssBarW }} />
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }}
              />
            </SectionCard>

            {/* ── 3. Secrets & Credentials ─────────────────────────────── */}
            <SectionCard icon={Key} title="Secrets & Credentials" count={secretsCount} fullWidth accent="yellow">
              <PaginatedSection
                items={selectedAsset?.secrets ?? []}
                pageSize={15}
                emptyMessage="No secrets found"
                emptyIcon={Key}
                renderItem={(s, i) => (
                  <div key={i} className="flex items-start gap-3 py-3 border-b border-border/30 last:border-0">
                    <div className="w-8 h-8 rounded-xl bg-yellow-500/10 border border-yellow-500/20 flex items-center justify-center shrink-0">
                      <Key className="w-3.5 h-3.5 text-yellow-400" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-yellow-300 truncate">{s.type ?? "Secret"}</p>
                      {s.value && <p className="text-xs font-mono text-muted-foreground mt-0.5 truncate">{s.value}</p>}
                      {s.file && <p className="text-[10px] text-muted-foreground/60 truncate mt-0.5">{s.file}</p>}
                    </div>
                    {s.port && <span className="text-xs bg-muted/60 text-muted-foreground rounded-lg px-2 py-0.5 shrink-0 font-mono">:{s.port}</span>}
                  </div>
                )}
              />
            </SectionCard>

            {/* ── 4. Screenshots ───────────────────────────────────────── */}
            <SectionCard icon={Camera} title="Screenshots" fullWidth>
              <ScreenshotsTab assetId={selectedAsset?.assetId} />
            </SectionCard>

            {/* ── 5. Technologies ──────────────────────────────────────── */}
            <SectionCard icon={Cpu} title="Technologies" fullWidth>
              <TechnologiesTab assetId={selectedAsset?.assetId} />
            </SectionCard>

            {/* ── 6. DNS Records ───────────────────────────────────────── */}
            <SectionCard icon={Database} title="DNS Records" count={(selectedAsset?.dnsRecords ?? []).length} fullWidth>
              {(selectedAsset?.dnsRecords ?? []).length === 0
                ? <EmptyState message="No DNS records found" icon={Database} />
                : <DnsTab records={selectedAsset?.dnsRecords ?? []} />
              }
            </SectionCard>

            {/* ── 7. Subdomains (full-width) ────────────────────────────── */}
            <SectionCard icon={Globe} title="Subdomains" count={(selectedAsset?.subdomains ?? []).length} fullWidth>
              <SubdomainsContent subdomains={selectedAsset?.subdomains ?? []} />
            </SectionCard>

            {/* ── 8. HTTP Info (full-width) ─────────────────────────────── */}
            <SectionCard icon={Wifi} title="HTTP Info" fullWidth>
              {(() => {
                const httpInfo = selectedAsset?.httpInfo ?? {};
                const headers  = selectedAsset?.httpHeaders ?? {};
                const hasInfo  = Object.keys(httpInfo).length > 0 || Object.keys(headers).length > 0;
                if (!hasInfo) return <EmptyState message="No HTTP info collected" icon={Wifi} />;
                return (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                    {httpInfo.statusCode   && <InfoRow label="Status Code"    value={String(httpInfo.statusCode)} />}
                    {httpInfo.title        && <InfoRow label="Page Title"      value={httpInfo.title} />}
                    {httpInfo.server       && <InfoRow label="Server"          value={httpInfo.server} mono />}
                    {httpInfo.contentType  && <InfoRow label="Content-Type"    value={httpInfo.contentType} mono />}
                    {httpInfo.waf          && <InfoRow label="WAF / Firewall"  value={httpInfo.waf} />}
                    {httpInfo.cdn          && <InfoRow label="CDN"             value={httpInfo.cdn} />}
                    {httpInfo.ip           && <InfoRow label="Resolved IP"     value={httpInfo.ip} mono />}
                    {Object.entries(headers).slice(0, 12).map(([k, v]) => (
                      <InfoRow key={k} label={k} value={String(v)} mono />
                    ))}
                  </div>
                );
              })()}
            </SectionCard>

            {/* ── 9. Endpoints ─────────────────────────────────────────── */}
            <SectionCard icon={Search} title="Endpoints" count={(selectedAsset?.endpoints ?? []).length} fullWidth>
              {(selectedAsset?.endpoints ?? []).length === 0
                ? <EmptyState message="No endpoints discovered" icon={Search} />
                : <EndpointsTab endpoints={selectedAsset?.endpoints ?? []} isClient={isClient} />
              }
            </SectionCard>

            {/* ── 10. Intelligence ─────────────────────────────────────── */}
            <SectionCard icon={Eye} title="Intelligence" count={(selectedAsset?.intelligence ?? []).length} fullWidth>
              {(() => {
                const intelItems: any[] = selectedAsset?.intelligence ?? [];
                if (intelItems.length === 0) return <EmptyState message="No intelligence data" icon={Eye} />;
                const grouped = intelItems.reduce<Record<string, any[]>>((acc, item) => {
                  const t = item.type ?? "Other";
                  (acc[t] = acc[t] ?? []).push(item);
                  return acc;
                }, {});
                return (
                  <div className="space-y-6">
                    {Object.entries(grouped).map(([type, typeItems]) => {
                      const meta = INTEL_TYPE_META[type] ?? INTEL_TYPE_META["Other"];
                      const Icon = meta.icon;
                      return (
                        <div key={type}>
                          <div className={cn("flex items-center gap-3 px-4 py-2.5 rounded-2xl border mb-4", meta.bg, meta.border)}>
                            <Icon className={cn("w-3.5 h-3.5", meta.color)} />
                            <span className={cn("text-xs font-bold uppercase tracking-wider", meta.color)}>{type}</span>
                            <span className={cn("ml-auto text-[11px] font-bold px-2.5 py-0.5 rounded-full border", meta.bg, meta.color, meta.border)}>{typeItems.length}</span>
                          </div>
                          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
                            {typeItems.map((item: any, i: number) => (
                              <div key={i} className="bg-card border border-border rounded-2xl p-4 hover:shadow-sm hover:border-muted-foreground/30 transition-all">
                                <p className="text-[10px] font-bold text-muted-foreground/60 uppercase tracking-wider mb-2">{item.key}</p>
                                <p className="text-sm font-semibold text-foreground break-words leading-snug">{item.value}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                );
              })()}
            </SectionCard>

            {/* ── 11. JavaScript Analysis (full-width) ──────────────────── */}
            <SectionCard icon={Code} title="JavaScript Analysis"
              count={selectedAsset?.jsAnalysis?.stats?.totalSecrets ?? undefined} fullWidth>
              {!(selectedAsset?.jsAnalysis)
                ? <EmptyState message="No JavaScript analysis performed" icon={Code} />
                : <JsAnalysisTab jsAnalysis={selectedAsset?.jsAnalysis} />
              }
            </SectionCard>

            {/* ── 12. Parameter Discovery ──────────────────────────────── */}
            <SectionCard icon={FileCode} title="Parameter Discovery" fullWidth
              count={selectedAsset?.paramDiscovery?.stats?.unique ?? undefined}>
              {!(selectedAsset?.paramDiscovery)
                ? <EmptyState message="No parameter discovery performed" icon={FileCode} />
                : <ParamDiscoveryTab paramDiscovery={selectedAsset?.paramDiscovery} />
              }
            </SectionCard>

            {/* ── 13. Cloud Assets ─────────────────────────────────────── */}
            <SectionCard icon={Cloud} title="Cloud Assets"
              count={selectedAsset?.cloudRecon?.stats?.existingBuckets ?? undefined}>
              {!(selectedAsset?.cloudRecon)
                ? <EmptyState message="No cloud recon performed" icon={Cloud} />
                : <CloudReconTab cloudRecon={selectedAsset?.cloudRecon} />
              }
            </SectionCard>

            {/* ── 14. Secrets Hunt ─────────────────────────────────────── */}
            <SectionCard icon={Github} title="Secrets Hunt"
              count={(selectedAsset?.secretsHunt?.stats?.secretsFound ?? 0) + (selectedAsset?.secretsHunt?.stats?.gitDirsExposed ?? 0) || undefined}>
              {!(selectedAsset?.secretsHunt)
                ? <EmptyState message="No secrets hunt performed" icon={Github} />
                : <SecretsHuntTab secretsHunt={selectedAsset?.secretsHunt} />
              }
            </SectionCard>

            {/* ── 15. Directory Fuzzing ─────────────────────────────────── */}
            <SectionCard icon={FolderOpen} title="Directory Fuzzing" fullWidth
              count={selectedAsset?.dirFuzz?.stats?.totalUnique ?? undefined}>
              {!(selectedAsset?.dirFuzz)
                ? <EmptyState message="No directory fuzzing performed" icon={FolderOpen} />
                : <DirFuzzTab dirFuzz={selectedAsset?.dirFuzz} />
              }
            </SectionCard>

            {/* ── 16. Vuln Template Scan ───────────────────────────────── */}
            <SectionCard icon={ShieldAlert} title="Vulnerability Template Scan" fullWidth
              count={((selectedAsset?.vulnScan?.stats?.critical ?? 0) + (selectedAsset?.vulnScan?.stats?.high ?? 0)) || undefined}
              accent={((selectedAsset?.vulnScan?.stats?.critical ?? 0) > 0) ? "red" : "orange"}>
              {!(selectedAsset?.vulnScan)
                ? <EmptyState message="No vulnerability template scan performed" icon={ShieldAlert} />
                : <NucleiTab vulnScan={selectedAsset?.vulnScan} />
              }
            </SectionCard>

          </div>

          {/* ── Raw Output (admin only, full-width) ────────────────────── */}
          {!isClient && allToolNames.length > 0 && (
            <div className="mt-4 bg-card border border-border rounded-xl overflow-hidden">
              <div className="flex items-center gap-2 px-5 py-3 border-b border-border/60 bg-muted/20">
                <Terminal className="w-3.5 h-3.5 text-muted-foreground" />
                <h2 className="text-xs font-semibold uppercase tracking-wide">Raw Tool Output</h2>
                <span className="ml-auto text-[10px] bg-muted/40 text-muted-foreground border border-border px-1.5 py-0.5 rounded">Admin</span>
              </div>
              <div className="flex">
                {/* Tool list sidebar */}
                <div className="w-44 shrink-0 border-r border-border/60 overflow-y-auto max-h-[500px]">
                  {allToolNames.map((name: string) => {
                    const result = toolResults.find((r: any) => r.toolName === name);
                    const ran    = !!result;
                    const ok     = ran && !result.error;
                    return (
                      <button
                        key={name}
                        onClick={() => setSelectedTool(name)}
                        className={cn(
                          "w-full text-left flex items-center gap-2 px-3 py-2.5 text-xs border-b border-border/40 transition-colors",
                          displayedTool === name
                            ? "bg-primary/10 text-foreground"
                            : "text-muted-foreground hover:text-foreground hover:bg-accent/40"
                        )}
                      >
                        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0",
                          !ran ? "bg-muted-foreground/30" : ok ? "bg-green-400" : "bg-red-400")} />
                        <span className="truncate">{name}</span>
                      </button>
                    );
                  })}
                </div>
                {/* Output panel */}
                <div className="flex-1 p-4 overflow-auto max-h-[500px]">
                  {(() => {
                    if (!displayedTool) return <EmptyState icon={Terminal} message="Select a tool" />;
                    const selectedResult = toolResults.find((r: any) => r.toolName === displayedTool);
                    const toolRan  = !!selectedResult;
                    const hasData  = toolRan && selectedResult.rawOutput && selectedResult.rawOutput.length > 0;
                    return (
                      <div>
                        {!toolRan && (
                          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground/40 gap-2">
                            <Clock className="w-8 h-8" />
                            <p className="text-sm font-medium">Not yet run</p>
                            <p className="text-xs">This tool hasn't executed for this asset.</p>
                          </div>
                        )}
                        {toolRan && selectedResult.error && (
                          <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4">
                            <p className="text-xs font-semibold text-red-400 mb-1">Tool Error</p>
                            <pre className="text-[10px] font-mono text-red-300/80 whitespace-pre-wrap">{selectedResult.error}</pre>
                          </div>
                        )}
                        {toolRan && !hasData && !selectedResult.error && (
                          <div className="flex flex-col items-center justify-center py-16 text-muted-foreground/40 gap-2">
                            <AlertCircle className="w-8 h-8 text-yellow-500/40" />
                            <p className="text-sm font-medium">No Results</p>
                            <p className="text-xs">Tool ran but found no data for this target.</p>
                          </div>
                        )}
                        {toolRan && hasData && (
                          <pre className="bg-muted/20 border border-border/40 rounded-lg p-4 text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[400px] overflow-y-auto">
                            {selectedResult!.rawOutput}
                          </pre>
                        )}
                      </div>
                    );
                  })()}
                </div>
              </div>
            </div>
          )}

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

const INTEL_TYPE_META: Record<string, { color: string; bg: string; border: string; icon: any }> = {
  "GeoIP":       { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   icon: Globe },
  "ASN":         { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  icon: Network },
  "Hosting":     { color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30",   icon: Server },
  "Network":     { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/30", icon: Wifi },
  "Certificate": { color: "text-primary",    bg: "bg-primary/10",    border: "border-primary/30",    icon: Shield },
  "Risk":        { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    icon: AlertTriangle },
  "WHOIS":       { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: Eye },
  "Other":       { color: "text-muted-foreground", bg: "bg-muted/20", border: "border-border",       icon: Eye },
};

const TECH_CAT_META: Record<string, { color: string; bg: string; border: string; bar: string; label: string }> = {
  "CMS":                    { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/30", bar: "bg-violet-400", label: "CMS" },
  "JavaScript frameworks":  { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/30",   bar: "bg-blue-400",   label: "JS Framework" },
  "Web servers":            { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  bar: "bg-green-400",  label: "Web Server" },
  "Databases":              { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "bg-orange-400", label: "Database" },
  "Analytics":              { color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/30",   bar: "bg-cyan-400",   label: "Analytics" },
  "Security":               { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "bg-red-400",    label: "Security" },
  "CDN":                    { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "bg-yellow-400", label: "CDN" },
  "Programming languages":  { color: "text-pink-400",   bg: "bg-pink-500/10",   border: "border-pink-500/30",   bar: "bg-pink-400",   label: "Language" },
  "Other":                  { color: "text-muted-foreground", bg: "bg-muted/20", border: "border-border", bar: "bg-muted-foreground", label: "Other" },
};

function TechnologiesTab({ assetId }: { assetId: number }) {
  const { data, isLoading } = useListAssetTechnologies(assetId, {
    query: { queryKey: getListAssetTechnologiesQueryKey(assetId), enabled: !!assetId },
  });

  const techs = (data as any[]) ?? [];

  if (isLoading) {
    return (
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
        {[...Array(8)].map((_, i) => <Skeleton key={i} className="h-24 rounded-2xl" />)}
      </div>
    );
  }

  if (techs.length === 0) {
    return (
      <div className="text-center py-14 text-muted-foreground">
        <div className="w-14 h-14 rounded-2xl bg-muted/30 flex items-center justify-center mx-auto mb-4">
          <Cpu className="w-7 h-7 opacity-30" />
        </div>
        <p className="text-sm font-semibold">No technologies detected</p>
        <p className="text-xs mt-1.5 opacity-60 max-w-xs mx-auto">Technology fingerprinting runs automatically on web assets during the scan.</p>
      </div>
    );
  }

  const byCategory = techs.reduce<Record<string, any[]>>((acc, t) => {
    const cat = t.category || "Other";
    (acc[cat] = acc[cat] ?? []).push(t);
    return acc;
  }, {});

  return (
    <div className="space-y-8">
      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-xl">
          <Cpu className="w-3.5 h-3.5 text-primary" />
          <span className="text-sm font-bold text-primary">{techs.length}</span>
          <span className="text-xs text-muted-foreground">technologies</span>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-muted/20 border border-border rounded-xl">
          <Tag className="w-3 h-3 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">{Object.keys(byCategory).length} categories</span>
        </div>
        {Object.entries(byCategory).map(([cat]) => {
          const meta = TECH_CAT_META[cat] ?? TECH_CAT_META["Other"];
          return (
            <span key={cat} className={cn("text-[10px] font-bold px-2 py-1 rounded-lg border uppercase tracking-wide", meta.bg, meta.color, meta.border)}>
              {meta.label}
            </span>
          );
        })}
      </div>

      {Object.entries(byCategory).map(([cat, items]) => {
        const meta = TECH_CAT_META[cat] ?? TECH_CAT_META["Other"];
        return (
          <div key={cat}>
            {/* Category header */}
            <div className={cn("flex items-center gap-3 px-4 py-2.5 rounded-2xl border mb-4", meta.bg, meta.border)}>
              <div className={cn("w-6 h-6 rounded-lg flex items-center justify-center shrink-0", meta.bg)}>
                <Cpu className={cn("w-3.5 h-3.5", meta.color)} />
              </div>
              <span className={cn("text-xs font-bold uppercase tracking-wider", meta.color)}>{cat}</span>
              <span className={cn("ml-auto text-[11px] font-bold px-2 py-0.5 rounded-full", meta.bg, meta.color)}>{items.length}</span>
            </div>
            {/* Tech card grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-3">
              {items.map((t: any, i: number) => {
                const label = t.technology || t.name || "?";
                const initial = label[0].toUpperCase();
                const conf = t.confidence ?? 100;
                return (
                  <div key={i} className="bg-card border border-border rounded-2xl p-4 hover:shadow-md hover:border-border/80 transition-all group flex flex-col gap-3">
                    <div className="flex items-center gap-3">
                      <div className={cn("w-9 h-9 rounded-xl flex items-center justify-center shrink-0 font-black text-base border", meta.bg, meta.color, meta.border)}>
                        {t.icon ? <span className="text-lg">{t.icon}</span> : initial}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-bold leading-tight truncate">{label}</p>
                        {t.version && (
                          <p className="text-[10px] font-mono text-muted-foreground leading-tight mt-0.5">v{t.version}</p>
                        )}
                      </div>
                    </div>
                    {t.confidence !== undefined && (
                      <div className="space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="text-[9px] text-muted-foreground/60 uppercase tracking-wider font-semibold">Confidence</span>
                          <span className={cn("text-[11px] font-black tabular-nums", conf >= 80 ? meta.color : "text-muted-foreground")}>{conf}%</span>
                        </div>
                        <div className="h-1.5 bg-muted/40 rounded-full overflow-hidden">
                          <div className={cn("h-full rounded-full transition-all", meta.bar)} style={{ width: `${conf}%` }} />
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
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

// ── Endpoints Tab ─────────────────────────────────────────────────────────────

const ENDPOINT_CATEGORIES = ["all", "sensitive", "admin", "graphql", "api", "auth", "parameterized", "page", "other"] as const;
type EpCat = (typeof ENDPOINT_CATEGORIES)[number];

const CAT_STYLE: Record<string, string> = {
  sensitive:    "bg-red-500/15 text-red-400 border-red-500/30",
  admin:        "bg-orange-500/15 text-orange-400 border-orange-500/30",
  graphql:      "bg-purple-500/15 text-purple-400 border-purple-500/30",
  api:          "bg-blue-500/15 text-blue-400 border-blue-500/30",
  auth:         "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  parameterized:"bg-pink-500/15 text-pink-400 border-pink-500/30",
  page:         "bg-accent/60 text-muted-foreground border-border",
  asset:        "bg-accent/40 text-muted-foreground/60 border-border/40",
  other:        "bg-accent/40 text-muted-foreground/60 border-border/40",
};

const SRC_STYLE: Record<string, string> = {
  wayback:      "bg-violet-500/15 text-violet-400 border-violet-500/30",
  commoncrawl:  "bg-sky-500/15 text-sky-400 border-sky-500/30",
  urlscan:      "bg-amber-500/15 text-amber-400 border-amber-500/30",
  otx:          "bg-red-500/15 text-red-300 border-red-500/30",
  crawl:        "bg-green-500/15 text-green-400 border-green-500/30",
  "js-crawl":   "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  probe:        "bg-accent/60 text-muted-foreground border-border",
};

const SRC_LABEL: Record<string, string> = {
  wayback:      "Archive",
  commoncrawl:  "Web Archive",
  urlscan:      "Passive Intel",
  otx:          "Threat Intel",
  crawl:        "Crawler",
  "js-crawl":   "JS Crawler",
  probe:        "Active Scan",
};

function EndpointsTab({ endpoints, isClient }: { endpoints: any[]; isClient?: boolean }) {
  const [activeCat, setActiveCat] = useState<EpCat>("all");
  const [search, setSearch] = useState("");
  const PAGE_SIZE = 100;
  const [page, setPage] = useState(0);

  if (endpoints.length === 0) return <EmptyState message="No endpoints discovered" icon={Search} />;

  const counts: Record<string, number> = { all: endpoints.length };
  for (const e of endpoints) {
    const c = (e.category as string) ?? "other";
    counts[c] = (counts[c] ?? 0) + 1;
  }

  const sourceCounts: Record<string, number> = {};
  for (const e of endpoints) {
    const s = (e.source as string) ?? "probe";
    sourceCounts[s] = (sourceCounts[s] ?? 0) + 1;
  }

  const filtered = endpoints.filter(e => {
    const cat = (e.category as string) ?? "other";
    const matchCat = activeCat === "all" || cat === activeCat;
    const matchSearch = !search || e.url.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSearch;
  });

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const visible = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="space-y-4">
      {/* Source stats bar — hidden for clients */}
      {!isClient && (
        <div className="flex flex-wrap gap-2 items-center">
          {Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).map(([src, cnt]) => (
            <span key={src} className={cn("text-[10px] border rounded-lg px-2.5 py-1 font-semibold", SRC_STYLE[src] ?? "bg-accent/60 text-muted-foreground border-border")}>
              {SRC_LABEL[src] ?? src}: {cnt}
            </span>
          ))}
          <span className="text-[10px] text-muted-foreground ml-auto font-medium">{endpoints.length.toLocaleString()} total (deduped)</span>
        </div>
      )}

      {/* Category filter tabs */}
      <div className="flex flex-wrap gap-1.5">
        {ENDPOINT_CATEGORIES.filter(c => c === "all" || (counts[c] ?? 0) > 0).map(cat => (
          <button
            key={cat}
            onClick={() => { setActiveCat(cat); setPage(0); }}
            className={cn(
              "text-[11px] px-2.5 py-1 rounded border font-medium transition-colors",
              activeCat === cat
                ? cat === "all" ? "bg-primary text-primary-foreground border-primary" : CAT_STYLE[cat]
                : "bg-accent/20 text-muted-foreground border-border hover:bg-accent/40"
            )}
          >
            {cat.charAt(0).toUpperCase() + cat.slice(1)}
            {cat !== "all" && <span className="ml-1 opacity-70">{counts[cat]}</span>}
            {cat === "all" && <span className="ml-1 opacity-70">{counts.all}</span>}
          </button>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
        <input
          type="text"
          placeholder="Filter by URL…"
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          className="w-full pl-8 pr-3 py-1.5 text-xs bg-accent/20 border border-border rounded focus:outline-none focus:ring-1 focus:ring-primary/50 font-mono"
        />
      </div>

      {filtered.length === 0 ? (
        <p className="text-xs text-muted-foreground text-center py-6">No endpoints match this filter.</p>
      ) : (
        <>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left border-b border-border">
                <th className="pb-2 font-medium text-muted-foreground">URL</th>
                <th className="pb-2 font-medium text-muted-foreground w-16">Status</th>
                <th className="pb-2 font-medium text-muted-foreground w-28">Category</th>
                {!isClient && <th className="pb-2 font-medium text-muted-foreground w-24">Source</th>}
              </tr>
            </thead>
            <tbody>
              {visible.map((e: any, i: number) => (
                <tr key={i} className="border-b border-border/30 hover:bg-accent/20 group">
                  <td className="py-1.5 pr-4">
                    <div className="flex items-center gap-1.5">
                      <span className="font-mono text-[11px] break-all leading-tight">{e.url}</span>
                      <a href={e.url} target="_blank" rel="noopener noreferrer"
                        className="shrink-0 opacity-0 group-hover:opacity-60 hover:!opacity-100 transition-opacity">
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </div>
                  </td>
                  <td className="py-1.5 pr-2">
                    {e.statusCode ? (
                      <span className={cn(
                        "text-[10px] border rounded px-1.5 py-0.5 font-mono font-bold tabular-nums",
                        e.statusCode >= 200 && e.statusCode < 300 ? "bg-green-500/15 text-green-400 border-green-500/30" :
                        e.statusCode >= 300 && e.statusCode < 400 ? "bg-blue-500/15 text-blue-400 border-blue-500/30" :
                        e.statusCode === 401 || e.statusCode === 403 ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                        e.statusCode >= 400 && e.statusCode < 500 ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                        e.statusCode >= 500 ? "bg-red-500/15 text-red-400 border-red-500/30" :
                        "bg-accent/30 text-muted-foreground border-border"
                      )}>{e.statusCode}</span>
                    ) : (
                      <span className="text-[10px] text-muted-foreground/40">—</span>
                    )}
                  </td>
                  <td className="py-1.5 pr-2">
                    <span className={cn("text-[10px] border rounded-lg px-2 py-0.5 font-semibold capitalize", CAT_STYLE[(e.category as string) ?? "other"] ?? CAT_STYLE.other)}>
                      {e.category ?? "other"}
                    </span>
                  </td>
                  {!isClient && (
                    <td className="py-1.5">
                      <span className={cn("text-[10px] border rounded-lg px-2 py-0.5 font-semibold", SRC_STYLE[(e.source as string)] ?? SRC_STYLE.probe)}>
                        {SRC_LABEL[(e.source as string)] ?? e.source ?? "probe"}
                      </span>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-muted-foreground">
                Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length.toLocaleString()}
              </span>
              <div className="flex gap-1.5">
                <button disabled={page === 0} onClick={() => setPage(p => p - 1)}
                  className="text-xs px-2.5 py-1 rounded border border-border disabled:opacity-30 hover:bg-accent/40">← Prev</button>
                <button disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}
                  className="text-xs px-2.5 py-1 rounded border border-border disabled:opacity-30 hover:bg-accent/40">Next →</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
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

      {/* All records — spacious card list */}
      <div>
        <div className="flex items-center gap-2 mb-4 flex-wrap">
          <span className="text-xs font-semibold text-muted-foreground">Filter:</span>
          {types.map(t => (
            <button
              key={t}
              onClick={() => setFilter(t)}
              className={cn(
                "text-[10px] font-mono font-bold border rounded-lg px-2.5 py-1 transition-colors",
                filter === t ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
              )}
            >{t}</button>
          ))}
          <span className="ml-auto text-xs text-muted-foreground font-medium">{filtered.length} records</span>
        </div>

        <div className="space-y-2.5">
          {filtered.map((r: any, i: number) => (
            <div key={i} className="bg-card border border-border rounded-2xl px-5 py-4 hover:border-muted-foreground/30 transition-colors">
              <div className="flex items-start gap-4">
                <span className={cn("font-mono text-xs font-black border rounded-xl px-3 py-1.5 shrink-0 mt-0.5 min-w-[56px] text-center", DnsTypeStyle(r.type))}>{r.type}</span>
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-sm text-foreground/90 break-all leading-relaxed">
                    {r.value}
                    {r.type === "PTR" && r.target && <span className="text-primary"> → {r.target}</span>}
                  </p>
                  {r.notes && (
                    <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{r.notes}</p>
                  )}
                  {(r.priority !== undefined || (r.target && r.type !== "PTR") || r.port) && (
                    <div className="flex gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
                      {r.priority !== undefined && <span>Priority: <span className="font-semibold text-foreground">{r.priority}</span></span>}
                      {r.target && r.type !== "PTR" && <span>Target: <span className="font-mono text-foreground">{r.target}</span></span>}
                      {r.port && <span>Port: <span className="font-semibold text-foreground">{r.port}</span></span>}
                      {r.weight !== undefined && <span>Weight: <span className="font-semibold text-foreground">{r.weight}</span></span>}
                    </div>
                  )}
                </div>
                {r.ttl > 0 && (
                  <span className="text-[10px] bg-muted/30 text-muted-foreground border border-border rounded-lg px-2.5 py-1 font-mono shrink-0">{r.ttl}s</span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Nuclei Vulnerability Scanner Tab ─────────────────────────────────────────

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-accent/30 text-muted-foreground border-border",
};

const CATEGORY_STYLE: Record<string, string> = {
  "exposed-panel":    "bg-purple-500/10 text-purple-400 border-purple-500/25",
  "sensitive-file":   "bg-red-500/10 text-red-400 border-red-500/25",
  "misconfiguration": "bg-orange-500/10 text-orange-400 border-orange-500/25",
  "cve":              "bg-pink-500/10 text-pink-400 border-pink-500/25",
  "cors":             "bg-teal-500/10 text-teal-400 border-teal-500/25",
  "header":           "bg-blue-500/10 text-blue-400 border-blue-500/25",
};

const GRADE_STYLE: Record<string, string> = {
  "A+": "text-green-400 bg-green-500/15 border-green-500/30",
  "A":  "text-green-400 bg-green-500/15 border-green-500/30",
  "B":  "text-lime-400 bg-lime-500/15 border-lime-500/30",
  "C":  "text-yellow-400 bg-yellow-500/15 border-yellow-500/30",
  "D":  "text-orange-400 bg-orange-500/15 border-orange-500/30",
  "F":  "text-red-400 bg-red-500/15 border-red-500/30",
};

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={cn("text-[10px] font-bold uppercase border rounded px-1.5 py-0.5 shrink-0 w-16 text-center", SEVERITY_STYLE[sev] ?? SEVERITY_STYLE.info)}>
      {sev}
    </span>
  );
}

function CatBadge({ cat }: { cat: string }) {
  const label = cat.replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  return (
    <span className={cn("text-[10px] font-medium border rounded px-1.5 py-0.5 shrink-0", CATEGORY_STYLE[cat] ?? "bg-accent/30 text-muted-foreground border-border")}>
      {label}
    </span>
  );
}

function NucleiTab({ vulnScan }: { vulnScan: any }) {
  const [section, setSection] = useState<"findings" | "cors" | "headers">("findings");
  const [sevFilter, setSevFilter] = useState("all");
  const [catFilter, setCatFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  if (!vulnScan) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <ShieldAlert className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No vulnerability scan data available</p>
        <p className="text-xs opacity-70">Vulnerability template scanning runs automatically on all web assets during scan.</p>
      </div>
    );
  }

  const stats: any = vulnScan.stats ?? {};
  const findings: any[] = vulnScan.findings ?? [];
  const cors: any[] = vulnScan.cors ?? [];
  const headers: any[] = vulnScan.headers ?? [];

  const filteredFindings = findings.filter((f: any) => {
    if (sevFilter !== "all" && f.severity !== sevFilter) return false;
    if (catFilter !== "all" && f.category !== catFilter) return false;
    if (search && !f.name?.toLowerCase().includes(search.toLowerCase()) &&
        !f.url?.toLowerCase().includes(search.toLowerCase()) &&
        !f.templateId?.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const categories = [...new Set(findings.map((f: any) => f.category))];

  const toggleExpand = (i: number) => {
    setExpanded(prev => {
      const n = new Set(prev);
      if (n.has(i)) n.delete(i); else n.add(i);
      return n;
    });
  };

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
        {[
          { label: "Critical", value: stats.critical ?? 0, style: stats.critical > 0 ? "text-red-400" : "text-muted-foreground" },
          { label: "High",     value: stats.high ?? 0,     style: stats.high > 0 ? "text-orange-400" : "text-muted-foreground" },
          { label: "Medium",   value: stats.medium ?? 0,   style: stats.medium > 0 ? "text-yellow-400" : "text-muted-foreground" },
          { label: "Low",      value: stats.low ?? 0,      style: "text-blue-400" },
          { label: "CORS",     value: stats.corsVulnerable ?? 0, style: stats.corsVulnerable > 0 ? "text-teal-400" : "text-muted-foreground" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide block mb-1">{s.label}</span>
            <p className={cn("text-xl font-bold", s.style)}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Header score band */}
      {headers.length > 0 && (
        <div className="flex items-center gap-3 bg-accent/10 border border-border rounded-lg px-4 py-2.5">
          <Shield className="w-4 h-4 text-muted-foreground shrink-0" />
          <span className="text-xs text-muted-foreground">Security header score:</span>
          <div className="flex items-center gap-2 flex-wrap">
            {headers.map((h: any) => (
              <span key={h.host} className="flex items-center gap-1">
                <span className="text-xs text-foreground/80 font-mono">{h.host}</span>
                <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", GRADE_STYLE[h.grade] ?? GRADE_STYLE["F"])}>
                  {h.grade} {h.score}/100
                </span>
              </span>
            ))}
          </div>
          <span className="text-[10px] text-muted-foreground ml-auto">{stats.headerIssues ?? 0} issues detected</span>
        </div>
      )}

      {/* Section tabs */}
      <div className="flex items-center gap-2 flex-wrap">
        {([
          { key: "findings", label: `Template Findings (${findings.length})` },
          { key: "cors",     label: `CORS (${cors.length})` },
          { key: "headers",  label: `Security Headers (${headers.length} hosts)` },
        ] as const).map(s => (
          <button key={s.key} onClick={() => setSection(s.key)}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              section === s.key ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
            )}>{s.label}</button>
        ))}
      </div>

      {/* ── Findings section ── */}
      {section === "findings" && (
        <>
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-2">
            <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
              className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none">
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
              className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none">
              <option value="all">All categories</option>
              {categories.map((c: any) => (
                <option key={c} value={c}>{c.replace(/-/g, " ").replace(/\b\w/g, (x: string) => x.toUpperCase())}</option>
              ))}
            </select>
            <div className="flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 ml-auto">
              <Search className="w-3 h-3 text-muted-foreground" />
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search findings…"
                className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-40" />
              {search && <button onClick={() => setSearch("")}><X className="w-3 h-3 text-muted-foreground" /></button>}
            </div>
          </div>

          {filteredFindings.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground space-y-1">
              <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
              <p className="text-sm">{findings.length === 0 ? "No vulnerabilities detected" : "No results match filter"}</p>
              {findings.length === 0 && <p className="text-xs opacity-60">All vulnerability template checks ran clean against this target</p>}
            </div>
          ) : (
            <div className="space-y-1.5">
              {filteredFindings.map((f: any, i: number) => {
                const open = expanded.has(i);
                return (
                  <div key={i} className={cn("border rounded-lg overflow-hidden",
                    f.severity === "critical" ? "border-red-500/30 bg-red-500/5" :
                    f.severity === "high" ? "border-orange-500/25 bg-orange-500/5" :
                    "border-border bg-accent/10"
                  )}>
                    {/* Summary row */}
                    <button onClick={() => toggleExpand(i)} className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-white/5 transition-colors">
                      <SevBadge sev={f.severity} />
                      <CatBadge cat={f.category} />
                      <span className="text-sm font-medium text-foreground flex-1 text-left">{f.name}</span>
                      {f.cve && !f.cve.includes("-") === false && f.cve.match(/CVE-\d{4}-\d+/) && (
                        <span className="text-[10px] font-mono text-pink-400 shrink-0">{f.cve}</span>
                      )}
                      <span className="font-mono text-[10px] text-muted-foreground truncate max-w-48 hidden sm:block">{f.url}</span>
                      <ChevronRight className={cn("w-3.5 h-3.5 text-muted-foreground shrink-0 transition-transform", open && "rotate-90")} />
                    </button>
                    {/* Expanded detail */}
                    {open && (
                      <div className="border-t border-border/50 px-3 py-3 space-y-3 bg-accent/5">
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                          <div>
                            <span className="text-muted-foreground block mb-1 font-medium uppercase tracking-wide text-[10px]">URL</span>
                            <a href={f.url} target="_blank" rel="noreferrer" className="font-mono text-primary hover:underline break-all">{f.url}</a>
                          </div>
                          <div>
                            <span className="text-muted-foreground block mb-1 font-medium uppercase tracking-wide text-[10px]">Evidence</span>
                            <code className="text-foreground/80 bg-accent/30 rounded px-2 py-1 block font-mono text-[10px] break-all">{f.evidence}</code>
                          </div>
                          {f.cve && (
                            <div>
                              <span className="text-muted-foreground block mb-1 font-medium uppercase tracking-wide text-[10px]">CVE / Template</span>
                              <span className="font-mono text-pink-400">{f.cve}</span>
                              {f.cvss && <span className="ml-2 text-muted-foreground">CVSS {f.cvss}</span>}
                              {f.cwe && <span className="ml-2 text-blue-400">{f.cwe}</span>}
                            </div>
                          )}
                          {f.tags?.length > 0 && (
                            <div>
                              <span className="text-muted-foreground block mb-1 font-medium uppercase tracking-wide text-[10px]">Tags</span>
                              <div className="flex flex-wrap gap-1">
                                {f.tags.map((t: string) => <span key={t} className="text-[10px] bg-accent/40 border border-border rounded px-1.5 py-0.5 text-muted-foreground">{t}</span>)}
                              </div>
                            </div>
                          )}
                        </div>
                        <div>
                          <span className="text-muted-foreground block mb-1 font-medium uppercase tracking-wide text-[10px]">Description</span>
                          <p className="text-xs text-foreground/80 leading-relaxed">{f.description}</p>
                        </div>
                        <div className="border border-green-500/20 bg-green-500/5 rounded-lg px-3 py-2">
                          <span className="text-[10px] font-medium uppercase tracking-wide text-green-400 block mb-1">Remediation</span>
                          <p className="text-xs text-foreground/80 leading-relaxed">{f.remediation}</p>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* ── CORS section ── */}
      {section === "cors" && (
        cors.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground space-y-1">
            <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
            <p className="text-sm">No CORS misconfigurations detected</p>
            <p className="text-xs opacity-60">Tested: reflected-origin, null-origin, subdomain-confusion</p>
          </div>
        ) : (
          <div className="space-y-3">
            {cors.map((c: any, i: number) => (
              <div key={i} className="border rounded-lg overflow-hidden border-orange-500/25 bg-orange-500/5">
                <div className="flex items-center gap-3 px-4 py-3">
                  <SevBadge sev={c.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-foreground">
                      {c.variant.replace(/-/g, " ").replace(/\b\w/g, (x: string) => x.toUpperCase())}
                    </p>
                    <p className="text-[11px] font-mono text-muted-foreground">{c.host}</p>
                  </div>
                  <div className="text-right text-xs space-y-0.5 shrink-0">
                    <div className="font-mono text-foreground/80">ACAO: <span className="text-yellow-400">{c.allowOrigin}</span></div>
                    <div className={cn("text-[10px]", c.allowCredentials ? "text-red-400 font-semibold" : "text-muted-foreground")}>
                      Credentials: {c.allowCredentials ? "✓ true (DANGEROUS)" : "false"}
                    </div>
                  </div>
                </div>
                <div className="border-t border-border/40 px-4 py-3 space-y-2 bg-accent/5">
                  <p className="text-xs text-foreground/80">{c.description}</p>
                  <div className="border border-green-500/20 bg-green-500/5 rounded px-3 py-2">
                    <span className="text-[10px] font-medium text-green-400 uppercase tracking-wide block mb-0.5">Remediation</span>
                    <p className="text-xs text-foreground/80">{c.remediation}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      )}

      {/* ── Headers section ── */}
      {section === "headers" && (
        headers.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground space-y-1">
            <Info className="w-7 h-7 mx-auto opacity-30" />
            <p className="text-sm">No header analysis data available</p>
          </div>
        ) : (
          <div className="space-y-4">
            {headers.map((h: any, hi: number) => {
              const checks: any[] = h.checks ?? [];
              const issueChecks = checks.filter((c: any) => c.issue);
              return (
                <div key={hi} className="border border-border rounded-lg overflow-hidden">
                  {/* Host header */}
                  <div className="flex items-center gap-3 px-4 py-3 bg-accent/20">
                    <span className={cn("text-base font-bold border rounded-lg px-3 py-1", GRADE_STYLE[h.grade] ?? GRADE_STYLE["F"])}>{h.grade}</span>
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-sm font-semibold text-foreground">{h.host}</p>
                      <p className="text-[10px] text-muted-foreground">{h.score}/100 — {issueChecks.length} issue{issueChecks.length !== 1 ? "s" : ""}</p>
                    </div>
                    {h.serverBanner && (
                      <span className="text-[10px] text-muted-foreground font-mono truncate max-w-36 hidden sm:block">Server: {h.serverBanner}</span>
                    )}
                    {h.poweredBy && (
                      <span className="text-[10px] text-orange-400 font-mono truncate max-w-36 hidden sm:block">X-Powered-By: {h.poweredBy}</span>
                    )}
                  </div>
                  {/* Score bar */}
                  <div className="h-1.5 w-full bg-accent/30">
                    <div className={cn("h-full transition-all", h.score >= 80 ? "bg-green-500" : h.score >= 60 ? "bg-yellow-500" : h.score >= 40 ? "bg-orange-500" : "bg-red-500")}
                      style={{ width: `${h.score}%` }} />
                  </div>
                  {/* Per-header rows */}
                  <div className="divide-y divide-border/40">
                    {checks.map((c: any, ci: number) => (
                      <div key={ci} className={cn("flex items-start gap-3 px-4 py-2.5 text-xs",
                        c.issue ? "bg-accent/5" : "opacity-60")}>
                        <div className={cn("w-3 h-3 rounded-full mt-0.5 shrink-0",
                          !c.present || c.issue ? (
                            c.severity === "high" ? "bg-orange-400" :
                            c.severity === "medium" ? "bg-yellow-400" :
                            c.severity === "low" ? "bg-blue-400" : "bg-muted-foreground/40"
                          ) : "bg-green-400"
                        )} />
                        <div className="flex-1 min-w-0">
                          <span className="font-mono font-medium text-foreground/90">{c.name}</span>
                          {c.value && <span className="ml-2 text-[10px] text-muted-foreground font-mono truncate max-w-64 inline-block align-middle">{c.value}</span>}
                          {c.issue && <p className="text-[11px] text-orange-400/90 mt-0.5">{c.issue}</p>}
                          {c.issue && c.recommendation && <p className="text-[10px] text-muted-foreground mt-0.5">Fix: {c.recommendation}</p>}
                        </div>
                        <SevBadge sev={c.severity} />
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )
      )}
    </div>
  );
}

// ── Directory Fuzz Tab ────────────────────────────────────────────────────────

const DIR_SOURCE_META: Record<string, { label: string; badge: string; tool: string }> = {
  fuzz:      { label: "Active Scan",  badge: "bg-purple-500/15 text-purple-400 border-purple-500/30",   tool: "Dir Fuzz" },
  recursive: { label: "Recursive",    badge: "bg-violet-500/15 text-violet-400 border-violet-500/30",   tool: "Recursive" },
  wayback:   { label: "Archive",      badge: "bg-blue-500/15 text-blue-400 border-blue-500/30",         tool: "Archive" },
  otx:       { label: "Threat Intel", badge: "bg-teal-500/15 text-teal-400 border-teal-500/30",         tool: "OTX" },
  crawl:     { label: "Crawler",      badge: "bg-green-500/15 text-green-400 border-green-500/30",      tool: "Crawler" },
};

const STATUS_BADGE: Record<number, string> = {
  200: "bg-green-500/15 text-green-400 border-green-500/30",
  201: "bg-green-500/15 text-green-400 border-green-500/30",
  204: "bg-green-500/15 text-green-400 border-green-500/30",
  301: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  302: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  401: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  403: "bg-orange-500/15 text-orange-400 border-orange-500/30",
};

const INTERESTING_KEYWORDS_UI = ["admin","login","swagger","graphql","actuator","config","secret","backup","database","debug","git","phpinfo","phpmyadmin"];

function DirFuzzTab({ dirFuzz }: { dirFuzz: any }) {
  const [section, setSection] = useState<"interesting" | "master" | "hosts">("interesting");
  const [search, setSearch] = useState("");
  const [hostFilter, setHostFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [depthFilter, setDepthFilter] = useState("all");
  const [showAll, setShowAll] = useState(false);

  if (!dirFuzz) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <FolderOpen className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No directory fuzz data available</p>
        <p className="text-xs text-muted-foreground/70">Run a new scan — Dir Fuzz runs automatically on web assets.</p>
      </div>
    );
  }

  const stats: any      = dirFuzz.stats ?? {};
  const hosts: any[]    = dirFuzz.hosts ?? [];
  const masterList: string[] = dirFuzz.masterList ?? [];

  const allEndpoints: any[] = hosts.flatMap((h: any) => h.endpoints ?? []);

  const hostNames = ["all", ...hosts.map((h: any) => h.host)];

  const interestingEndpoints = allEndpoints.filter((e: any) =>
    e.isInteresting ||
    (e.source === "fuzz" && [200, 401, 403].includes(e.statusCode) &&
      INTERESTING_KEYWORDS_UI.some(kw => e.path?.toLowerCase().includes(kw)))
  );

  function applyFilters(list: any[]) {
    return list.filter((e: any) => {
      if (hostFilter !== "all" && e.host !== hostFilter) return false;
      if (sourceFilter !== "all" && e.source !== sourceFilter) return false;
      if (statusFilter === "2xx" && !(e.statusCode >= 200 && e.statusCode < 300)) return false;
      if (statusFilter === "3xx" && !(e.statusCode >= 300 && e.statusCode < 400)) return false;
      if (statusFilter === "auth" && ![401, 403].includes(e.statusCode)) return false;
      if (depthFilter !== "all" && String(e.depth ?? 0) !== depthFilter) return false;
      if (search && !e.url?.toLowerCase().includes(search.toLowerCase()) && !e.path?.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }

  const filtered = section === "interesting"
    ? applyFilters(interestingEndpoints)
    : section === "master"
      ? applyFilters(allEndpoints)
      : [];

  const PAGE = 100;
  const displayed = showAll ? filtered : filtered.slice(0, PAGE);

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Hosts Scanned",  value: `${stats.hostsLive ?? 0}/${stats.hostsScanned ?? 0}`, sub: "live / total",                                         color: "text-primary" },
          { label: "Total Unique",   value: stats.totalUnique ?? 0,       sub: `${stats.liveEndpoints ?? 0} live (2xx/3xx)`,                                   color: "text-primary" },
          { label: "Active + Recursive", value: (stats.fuzzHits ?? 0) + (stats.recursiveHits ?? 0), sub: `${stats.fuzzHits ?? 0} root · ${stats.recursiveHits ?? 0} recursive (depth ${stats.maxDepthReached ?? 0})`, color: (stats.fuzzHits ?? 0) + (stats.recursiveHits ?? 0) > 0 ? "text-purple-400" : "text-muted-foreground" },
          { label: "Interesting",    value: interestingEndpoints.length,  sub: "admin/api/config/backup",                                                        color: interestingEndpoints.length > 0 ? "text-orange-400" : "text-green-400" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide block mb-1">{s.label}</span>
            <p className={cn("text-xl font-bold", s.color)}>{s.value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Source breakdown */}
      <div className="grid grid-cols-4 gap-2">
        {[
          { key: "fuzz",      count: stats.fuzzHits      ?? 0 },
          { key: "recursive", count: stats.recursiveHits ?? 0 },
          { key: "wayback",   count: stats.waybackFound  ?? 0 },
          { key: "crawl",     count: stats.crawledFound  ?? 0 },
        ].map(({ key, count }) => {
          const meta = DIR_SOURCE_META[key];
          return (
            <div key={key} className={cn("border rounded-lg p-3 flex items-center gap-2", count > 0 ? meta.badge : "bg-accent/10 border-border")}>
              <FolderOpen className={cn("w-4 h-4 shrink-0", count > 0 ? meta.badge.split(" ")[1] : "text-muted-foreground/40")} />
              <div>
                <p className={cn("text-sm font-bold", count > 0 ? meta.badge.split(" ")[1] : "text-muted-foreground")}>{count.toLocaleString()}</p>
                <p className="text-[10px] text-muted-foreground">{meta.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Section tabs */}
      <div className="flex items-center gap-2 flex-wrap">
        {([
          { key: "interesting", label: `Interesting (${interestingEndpoints.length})` },
          { key: "master",      label: `Master List (${allEndpoints.length.toLocaleString()})` },
          { key: "hosts",       label: `By Host (${hosts.length})` },
        ] as const).map(s => (
          <button key={s.key} onClick={() => { setSection(s.key); setSearch(""); setShowAll(false); }}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              section === s.key ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
            )}>{s.label}</button>
        ))}
      </div>

      {/* Filters (for interesting + master tabs) */}
      {section !== "hosts" && (
        <div className="flex flex-wrap items-center gap-2">
          {/* Host filter */}
          {hosts.length > 1 && (
            <select value={hostFilter} onChange={e => setHostFilter(e.target.value)}
              className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none max-w-44 truncate">
              {hostNames.map(h => <option key={h} value={h}>{h === "all" ? "All hosts" : h}</option>)}
            </select>
          )}
          {/* Source filter */}
          <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
            className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none">
            <option value="all">All sources</option>
            <option value="fuzz">Active Scan</option>
            <option value="recursive">Recursive</option>
            <option value="wayback">Archive</option>
            <option value="crawl">Crawler</option>
          </select>
          {/* Status filter */}
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
            className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none">
            <option value="all">All statuses</option>
            <option value="2xx">2xx (OK)</option>
            <option value="3xx">3xx (Redirect)</option>
            <option value="auth">401/403 (Auth)</option>
          </select>
          {/* Depth filter */}
          <select value={depthFilter} onChange={e => setDepthFilter(e.target.value)}
            className="bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground outline-none">
            <option value="all">All depths</option>
            <option value="0">Depth 0 (root)</option>
            <option value="1">Depth 1</option>
            <option value="2">Depth 2</option>
            <option value="3">Depth 3</option>
          </select>
          {/* Search */}
          <div className="flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5 ml-auto">
            <Search className="w-3 h-3 text-muted-foreground" />
            <input value={search} onChange={e => { setSearch(e.target.value); setShowAll(false); }}
              placeholder="Search URL or path…"
              className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-44" />
            {search && <button onClick={() => setSearch("")}><X className="w-3 h-3 text-muted-foreground hover:text-foreground" /></button>}
          </div>
        </div>
      )}

      {/* ── Interesting / Master list ── */}
      {section !== "hosts" && (
        displayed.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground space-y-1">
            <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
            <p className="text-sm">{section === "interesting" ? "No interesting endpoints discovered" : "No results match filter"}</p>
            {section === "interesting" && <p className="text-xs opacity-60">No admin panels, debug tools, or sensitive files found accessible</p>}
          </div>
        ) : (
          <div className="space-y-1">
            {displayed.map((e: any, i: number) => {
              const srcMeta = DIR_SOURCE_META[e.source] ?? DIR_SOURCE_META.wayback;
              const statusBadge = STATUS_BADGE[e.statusCode] ?? "bg-accent/40 text-muted-foreground border-border";
              const depth = e.depth ?? 0;
              const depthColors = ["", "text-violet-400", "text-indigo-400", "text-cyan-400"];
              return (
                <div key={i} className={cn("flex items-center gap-2 rounded-lg px-3 py-2 border text-xs group",
                  e.isInteresting && e.statusCode === 200
                    ? "border-orange-500/20 bg-orange-500/5 hover:bg-orange-500/10"
                    : "border-border bg-accent/10 hover:bg-accent/20"
                )}>
                  {/* Status badge */}
                  <span className={cn("shrink-0 text-[10px] font-bold border rounded px-1.5 py-0.5 font-mono w-10 text-center", statusBadge)}>
                    {e.statusCode}
                  </span>
                  {/* Source badge */}
                  <span className={cn("shrink-0 text-[10px] font-bold border rounded px-1.5 py-0.5", srcMeta.badge)}>
                    {srcMeta.label}
                  </span>
                  {/* Depth badge (only for depth > 0) */}
                  {depth > 0 && (
                    <span className={cn("shrink-0 text-[10px] font-mono border rounded px-1 py-0.5 bg-accent/30 border-border", depthColors[depth] ?? "text-muted-foreground")}>
                      d{depth}
                    </span>
                  )}
                  {/* URL (indent recursive paths) */}
                  <span className="font-mono text-xs text-foreground flex-1 truncate" style={{ paddingLeft: depth > 0 ? `${depth * 6}px` : undefined }}>
                    {e.url}
                  </span>
                  {/* Redirect info */}
                  {e.redirectTo && (
                    <span className="text-[10px] text-muted-foreground truncate max-w-32 hidden sm:block">→ {e.redirectTo}</span>
                  )}
                  {/* Content type */}
                  {e.contentType && (
                    <span className="text-[10px] text-muted-foreground hidden lg:block">{e.contentType.split(";")[0]}</span>
                  )}
                  {/* External link */}
                  <a href={e.url} target="_blank" rel="noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                    <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                  </a>
                </div>
              );
            })}
            {/* Show more / less */}
            {filtered.length > PAGE && (
              <div className="flex items-center justify-center gap-3 pt-2">
                <span className="text-xs text-muted-foreground">
                  Showing {displayed.length} of {filtered.length.toLocaleString()}
                </span>
                <button onClick={() => setShowAll(!showAll)}
                  className="text-xs text-primary hover:underline">
                  {showAll ? "Show less" : `Show all ${filtered.length.toLocaleString()}`}
                </button>
              </div>
            )}
          </div>
        )
      )}

      {/* ── By Host view ── */}
      {section === "hosts" && (
        <div className="space-y-3">
          {hosts.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <p className="text-sm">No hosts scanned</p>
            </div>
          ) : hosts.map((h: any, i: number) => (
            <div key={i} className={cn("border rounded-lg overflow-hidden", h.isLive ? "border-border" : "border-border/40")}>
              {/* Host header */}
              <div className={cn("flex items-center gap-3 px-3 py-2.5", h.isLive ? "bg-accent/20" : "bg-accent/10")}>
                <div className={cn("w-2 h-2 rounded-full shrink-0", h.isLive ? "bg-green-400" : "bg-muted-foreground/40")} />
                <span className="font-mono text-sm font-semibold text-foreground flex-1">{h.host}</span>
                {h.isLive && (
                  <>
                    <span className="text-[10px] text-muted-foreground">{(h.endpoints?.length ?? 0).toLocaleString()} endpoints</span>
                    <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", STATUS_BADGE[h.liveStatusCode] ?? "bg-accent/40 text-muted-foreground border-border")}>HTTP {h.liveStatusCode}</span>
                  </>
                )}
                {!h.isLive && <span className="text-[10px] text-muted-foreground">Unreachable</span>}
              </div>
              {/* Host stats */}
              {h.isLive && (
                <div className="px-3 py-2 flex flex-wrap gap-3 text-[10px] text-muted-foreground border-t border-border bg-accent/5">
                  {[
                    { label: "Fuzz",       value: h.stats?.fuzzHits      ?? 0, color: "text-purple-400" },
                    { label: "Recursive",  value: h.stats?.recursiveHits ?? 0, color: "text-violet-400" },
                    { label: "Archive",    value: h.stats?.waybackFound  ?? 0, color: "text-blue-400" },
                    { label: "Crawled",    value: h.stats?.crawled       ?? 0, color: "text-green-400" },
                    { label: "Live 2xx",   value: h.stats?.live200       ?? 0, color: "text-green-400" },
                    { label: "3xx",        value: h.stats?.live301       ?? 0, color: "text-yellow-400" },
                    { label: "401/403",    value: h.stats?.live401403    ?? 0, color: "text-orange-400" },
                    { label: "Interesting",value: h.stats?.interesting   ?? 0, color: "text-red-400" },
                    { label: `Depth`,      value: `≤${h.stats?.maxDepthReached ?? 0}`, color: "text-cyan-400" },
                  ].map(s => (
                    <span key={s.label}><span className={cn("font-bold", s.color)}>{s.value}</span> {s.label}</span>
                  ))}
                </div>
              )}
              {/* Sample endpoints for this host */}
              {h.isLive && (h.endpoints ?? []).filter((e: any) => e.isInteresting || ((e.source === "fuzz" || e.source === "recursive") && e.statusCode === 200)).slice(0, 5).map((e: any, j: number) => {
                const srcMeta = DIR_SOURCE_META[e.source] ?? DIR_SOURCE_META.wayback;
                const statusBadge = STATUS_BADGE[e.statusCode] ?? "bg-accent/40 text-muted-foreground border-border";
                return (
                  <div key={j} className="flex items-center gap-2 px-3 py-1.5 text-xs border-t border-border/40 bg-accent/5">
                    <span className={cn("shrink-0 text-[10px] font-bold border rounded px-1 py-0.5 font-mono w-10 text-center", statusBadge)}>{e.statusCode}</span>
                    <span className={cn("shrink-0 text-[10px] font-bold border rounded px-1 py-0.5", srcMeta.badge)}>{srcMeta.label}</span>
                    <span className="font-mono text-foreground flex-1 truncate">{e.path}</span>
                    <a href={e.url} target="_blank" rel="noreferrer"><ExternalLink className="w-3 h-3 text-muted-foreground hover:text-foreground" /></a>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      )}

      {/* Master list download hint */}
      {section === "master" && masterList.length > 0 && (
        <div className="flex items-center gap-2 text-[10px] text-muted-foreground bg-accent/10 border border-border rounded-lg px-3 py-2">
          <Info className="w-3 h-3 shrink-0" />
          <span>all_endpoints_master.txt — {masterList.length.toLocaleString()} unique endpoints merged from active scanning, archive sources, and web crawling. View Raw Output tab for the full text dump.</span>
        </div>
      )}
    </div>
  );
}

// ── Secrets Hunt Tab ──────────────────────────────────────────────────────────

const SEV_META: Record<string, { label: string; badge: string }> = {
  critical: { label: "CRITICAL", badge: "bg-red-500/15 text-red-400 border-red-500/40" },
  high:     { label: "HIGH",     badge: "bg-orange-500/15 text-orange-400 border-orange-500/40" },
  medium:   { label: "MEDIUM",   badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/40" },
};

function SecretsHuntTab({ secretsHunt }: { secretsHunt: any }) {
  const [section, setSection] = useState<"github" | "gitdirs">("github");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  if (!secretsHunt) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <Github className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No secrets hunt data available</p>
        <p className="text-xs text-muted-foreground/70">Run a new scan — Secrets Hunt runs automatically on web assets.</p>
      </div>
    );
  }

  const stats: any = secretsHunt.stats ?? {};
  const org: any = secretsHunt.githubOrg;
  const secrets: any[] = secretsHunt.githubSecrets ?? [];
  const gitDirs: any[] = secretsHunt.gitDirectories ?? [];
  const exposed = gitDirs.filter((d: any) => d.isExposed);

  const filteredSecrets = secrets.filter((s: any) => {
    if (severityFilter !== "all" && s.severity !== severityFilter) return false;
    if (!search) return true;
    return (s.type + s.repo + s.file + s.lineContext).toLowerCase().includes(search.toLowerCase());
  });

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Repos Scanned",    value: stats.reposScanned ?? 0,    sub: `${stats.filesScanned ?? 0} files · ${stats.commitsScanned ?? 0} commits`, color: "text-primary" },
          { label: "Secrets Found",    value: stats.secretsFound ?? 0,    sub: `${stats.verifiedSecrets ?? 0} verified`,                                   color: stats.secretsFound > 0 ? "text-red-400" : "text-green-400" },
          { label: "Critical / High",  value: `${stats.criticalCount ?? 0} / ${stats.highCount ?? 0}`, sub: `${stats.mediumCount ?? 0} medium`,            color: stats.criticalCount > 0 ? "text-red-400" : stats.highCount > 0 ? "text-orange-400" : "text-foreground" },
          { label: ".git Exposure",    value: stats.gitDirsExposed ?? 0,  sub: `of ${stats.gitDirsChecked ?? 0} hosts checked`,                            color: stats.gitDirsExposed > 0 ? "text-red-400" : "text-green-400" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide block mb-1">{s.label}</span>
            <p className={cn("text-xl font-bold", s.color)}>{s.value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* GitHub org card */}
      {org && (
        <div className="bg-accent/10 border border-border rounded-lg p-3 flex items-center gap-3">
          <Github className="w-5 h-5 text-foreground shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-sm text-foreground">{org.name ?? org.login}</span>
              <span className="text-[10px] bg-accent/40 border border-border rounded px-1.5 py-0.5 text-muted-foreground uppercase">{org.type}</span>
              <span className="text-[10px] text-muted-foreground">{org.publicRepoCount} public repos</span>
            </div>
            <p className="font-mono text-[10px] text-primary/80 mt-0.5">{org.url}</p>
          </div>
          <a href={org.url} target="_blank" rel="noreferrer">
            <ExternalLink className="w-4 h-4 text-muted-foreground hover:text-foreground" />
          </a>
        </div>
      )}
      {!org && (
        <div className="bg-accent/10 border border-border rounded-lg p-3 flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-muted-foreground shrink-0" />
          <p className="text-xs text-muted-foreground">No GitHub organization found for this target. Secrets scan limited to .git directory exposure checks.</p>
        </div>
      )}

      {/* Section tabs */}
      <div className="flex items-center gap-2 flex-wrap">
        {([
          { key: "github",  label: `GitHub Secrets (${secrets.length})` },
          { key: "gitdirs", label: `.git Exposure (${exposed.length} / ${gitDirs.length})` },
        ] as const).map(s => (
          <button key={s.key} onClick={() => { setSection(s.key); setSearch(""); setSeverityFilter("all"); }}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              section === s.key ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
            )}>{s.label}</button>
        ))}
      </div>

      {/* ── GitHub secrets section ── */}
      {section === "github" && (
        <>
          {/* Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            {(["all", "critical", "high", "medium"] as const).map(sev => (
              <button key={sev} onClick={() => setSeverityFilter(sev)}
                className={cn("px-2.5 py-1 rounded text-[10px] font-bold border transition-colors",
                  severityFilter === sev ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/20 text-muted-foreground border-border hover:text-foreground"
                )}>{sev === "all" ? `All (${secrets.length})` : `${sev.toUpperCase()} (${secrets.filter((x: any) => x.severity === sev).length})`}</button>
            ))}
            <div className="ml-auto flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5">
              <Search className="w-3 h-3 text-muted-foreground" />
              <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search type, repo, file…"
                className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-40" />
              {search && <button onClick={() => setSearch("")}><X className="w-3 h-3 text-muted-foreground hover:text-foreground" /></button>}
            </div>
          </div>

          {filteredSecrets.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground space-y-1">
              <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
              <p className="text-sm">{secrets.length === 0 ? "No secrets found in public repositories" : "No secrets match filter"}</p>
              {secrets.length === 0 && org && (
                <p className="text-xs opacity-60">Scanned {stats.reposScanned} repos · {stats.filesScanned} sensitive files · {stats.commitsScanned} recent commits</p>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredSecrets.map((s: any, i: number) => {
                const sevMeta = SEV_META[s.severity] ?? SEV_META.medium;
                return (
                  <div key={i} className={cn("border rounded-lg p-3 space-y-2",
                    s.severity === "critical" ? "border-red-500/20 bg-red-500/5" :
                    s.severity === "high"     ? "border-orange-500/15 bg-orange-500/5" :
                    "border-border bg-accent/10"
                  )}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", sevMeta.badge)}>{sevMeta.label}</span>
                      {s.verified && (
                        <span className="text-[10px] font-bold border rounded px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 border-emerald-500/30">VERIFIED</span>
                      )}
                      <span className="text-[10px] font-bold border rounded px-1.5 py-0.5 bg-accent/40 text-muted-foreground border-border">{s.source === "commit" ? "COMMIT HISTORY" : "FILE"}</span>
                      <span className="text-sm font-semibold text-foreground">{s.type}</span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs">
                      <div className="flex items-center gap-1.5">
                        <Github className="w-3 h-3 text-muted-foreground shrink-0" />
                        <span className="text-muted-foreground">Repo:</span>
                        <span className="font-mono text-foreground">{s.repo}</span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Code className="w-3 h-3 text-muted-foreground shrink-0" />
                        <span className="text-muted-foreground">File:</span>
                        <span className="font-mono text-foreground truncate">{s.file}</span>
                      </div>
                      {s.commitSha && (
                        <div className="flex items-center gap-1.5">
                          <GitBranch className="w-3 h-3 text-muted-foreground shrink-0" />
                          <span className="text-muted-foreground">Commit:</span>
                          <span className="font-mono text-foreground">{s.commitSha}</span>
                        </div>
                      )}
                    </div>

                    <div className="bg-black/20 border border-border/50 rounded p-2 space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-muted-foreground font-semibold uppercase">Value (masked)</span>
                        <span className="font-mono text-xs text-red-300 break-all">{s.value}</span>
                      </div>
                      {s.lineContext && (
                        <div>
                          <span className="text-[10px] text-muted-foreground font-semibold uppercase">Context</span>
                          <p className="font-mono text-[10px] text-muted-foreground mt-0.5 leading-relaxed break-all">{s.lineContext}</p>
                        </div>
                      )}
                    </div>

                    <div className="flex items-center gap-3">
                      <a href={s.url} target="_blank" rel="noreferrer"
                        className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80 transition-colors">
                        <ExternalLink className="w-3 h-3" />View on GitHub
                      </a>
                      {s.severity === "critical" && (
                        <div className="flex items-start gap-1 text-[10px] text-red-400">
                          <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                          <span>Rotate this credential immediately — it may be actively exploited.</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {/* ── .git directory exposure section ── */}
      {section === "gitdirs" && (
        <div className="space-y-3">
          {exposed.length > 0 && (
            <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-3 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-red-400">Critical: Exposed .git Directories</p>
                <p className="text-xs text-muted-foreground mt-0.5">An exposed .git directory allows attackers to reconstruct the full source code, credentials, and commit history using tools like GitTools or git-dumper. This is a critical finding.</p>
              </div>
            </div>
          )}

          <div className="space-y-2">
            {gitDirs.map((d: any, i: number) => (
              <div key={i} className={cn("border rounded-lg p-3 space-y-2",
                d.isExposed ? "border-red-500/20 bg-red-500/5" : "border-border bg-accent/10"
              )}>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5",
                    d.isExposed ? "bg-red-500/15 text-red-400 border-red-500/40" : "bg-accent/60 text-muted-foreground border-border"
                  )}>{d.isExposed ? "EXPOSED" : `SAFE · HTTP ${d.httpStatus}`}</span>
                  <span className="font-mono text-sm font-semibold text-foreground">{d.host}</span>
                </div>

                {d.isExposed && (
                  <>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-primary/80 flex-1 truncate">{d.url}</span>
                      <a href={d.url} target="_blank" rel="noreferrer">
                        <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                      </a>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 text-xs">
                      {d.branch && (
                        <div className="flex items-center gap-1.5">
                          <GitBranch className="w-3 h-3 text-muted-foreground" />
                          <span className="text-muted-foreground">Branch:</span>
                          <span className="font-mono text-foreground">{d.branch}</span>
                        </div>
                      )}
                      {d.remoteUrl && (
                        <div className="flex items-center gap-1.5 col-span-2">
                          <Github className="w-3 h-3 text-muted-foreground" />
                          <span className="text-muted-foreground">Remote:</span>
                          <span className="font-mono text-foreground text-[10px] break-all">{d.remoteUrl}</span>
                        </div>
                      )}
                      {d.commitMsg && (
                        <div className="flex items-center gap-1.5 col-span-2">
                          <Tag className="w-3 h-3 text-muted-foreground" />
                          <span className="text-muted-foreground">Last commit:</span>
                          <span className="text-foreground italic">{d.commitMsg}</span>
                        </div>
                      )}
                    </div>
                    {d.configContent && (
                      <details>
                        <summary className="cursor-pointer text-[10px] text-muted-foreground hover:text-foreground select-none">.git/config preview</summary>
                        <pre className="font-mono text-[10px] text-muted-foreground bg-black/20 border border-border rounded p-2 mt-1 whitespace-pre-wrap break-all max-h-36 overflow-y-auto">{d.configContent}</pre>
                      </details>
                    )}
                    <div className="bg-red-500/5 border border-red-500/20 rounded p-2 text-[10px] text-red-400">
                      <p className="font-semibold mb-0.5">Exploitation</p>
                      <p className="text-muted-foreground">Run: <code className="font-mono bg-black/30 rounded px-1">git-dumper https://{d.host}/.git/ ./repo</code> to recover full source code and history.</p>
                    </div>
                  </>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Cloud Asset Recon Tab ─────────────────────────────────────────────────────

const PROVIDER_META: Record<string, { label: string; color: string; bg: string }> = {
  aws_s3: { label: "AWS S3",    color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30" },
  gcs:    { label: "GCS",       color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/30" },
  azure:  { label: "Azure",     color: "text-cyan-400",   bg: "bg-cyan-500/10 border-cyan-500/30" },
};

const BUCKET_STATUS_META: Record<string, { label: string; color: string }> = {
  public_listable: { label: "PUBLIC · LISTABLE", color: "bg-red-500/15 text-red-400 border-red-500/40" },
  public_exists:   { label: "PUBLIC",            color: "bg-orange-500/15 text-orange-400 border-orange-500/40" },
  private:         { label: "PRIVATE",           color: "bg-accent/60 text-muted-foreground border-border" },
  error:           { label: "ERROR",             color: "bg-accent/30 text-muted-foreground/60 border-border" },
};

function CloudReconTab({ cloudRecon }: { cloudRecon: any }) {
  const [section, setSection] = useState<"buckets" | "firebase" | "ssrf">("buckets");
  const [search, setSearch] = useState("");

  if (!cloudRecon) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <Cloud className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No cloud recon data available</p>
        <p className="text-xs text-muted-foreground/70">Run a new scan — Cloud Asset Recon runs automatically on web assets.</p>
      </div>
    );
  }

  const stats       = cloudRecon.stats ?? {};
  const buckets: any[]  = cloudRecon.buckets ?? [];
  const firebase: any[] = cloudRecon.firebase ?? [];
  const ssrf: any[]     = cloudRecon.ssrfEndpoints ?? [];
  const testedNames: string[] = cloudRecon.testedNames ?? [];

  const filteredBuckets = buckets.filter(b =>
    !search || b.name?.toLowerCase().includes(search.toLowerCase()) || b.url?.includes(search)
  );
  const filteredFb = firebase.filter(f =>
    !search || f.name?.toLowerCase().includes(search.toLowerCase()) || f.url?.includes(search)
  );

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Names Tested",    value: stats.totalTested ?? testedNames.length, sub: "bucket variations",              color: "text-primary" },
          { label: "Buckets Found",   value: stats.existingBuckets ?? 0,              sub: `${stats.publicBuckets ?? 0} public`, color: stats.publicBuckets > 0 ? "text-red-400" : "text-green-400" },
          { label: "Firebase",        value: (stats.publicFirebase ?? 0) + (stats.restrictedFirebase ?? 0), sub: `${stats.publicFirebase ?? 0} public`, color: stats.publicFirebase > 0 ? "text-red-400" : "text-foreground" },
          { label: "SSRF Targets",    value: stats.ssrfEndpoints ?? ssrf.length,      sub: "metadata endpoints",              color: "text-orange-400" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide block mb-1">{s.label}</span>
            <p className={cn("text-xl font-bold", s.color)}>{s.value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Provider breakdown */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { key: "aws_s3", count: stats.awsFound ?? 0 },
          { key: "gcs",    count: stats.gcsFound ?? 0 },
          { key: "azure",  count: stats.azureFound ?? 0 },
        ].map(({ key, count }) => {
          const meta = PROVIDER_META[key];
          return (
            <div key={key} className={cn("border rounded-lg p-3 flex items-center gap-3", count > 0 ? meta.bg : "bg-accent/10 border-border")}>
              <Cloud className={cn("w-5 h-5 shrink-0", count > 0 ? meta.color : "text-muted-foreground/40")} />
              <div>
                <p className={cn("text-sm font-bold", count > 0 ? meta.color : "text-muted-foreground")}>{count}</p>
                <p className="text-[10px] text-muted-foreground">{meta.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Section tabs + search */}
      <div className="flex items-center gap-2 flex-wrap">
        {([
          { key: "buckets", label: `Buckets (${buckets.length})` },
          { key: "firebase", label: `Firebase (${firebase.length})` },
          { key: "ssrf", label: `SSRF Metadata (${ssrf.length})` },
        ] as const).map(s => (
          <button key={s.key} onClick={() => { setSection(s.key); setSearch(""); }}
            className={cn("px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              section === s.key ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
            )}>{s.label}</button>
        ))}
        {section !== "ssrf" && (
          <div className="ml-auto flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5">
            <Search className="w-3 h-3 text-muted-foreground" />
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter…"
              className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-36" />
            {search && <button onClick={() => setSearch("")} className="text-muted-foreground hover:text-foreground"><X className="w-3 h-3" /></button>}
          </div>
        )}
      </div>

      {/* ── Buckets section ── */}
      {section === "buckets" && (
        filteredBuckets.length === 0
          ? (
            <div className="text-center py-8 text-muted-foreground space-y-1">
              <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
              <p className="text-sm">{search ? "No buckets match filter" : "No exposed cloud storage found"}</p>
              <p className="text-xs opacity-60">Tested {testedNames.length} naming patterns across S3, GCS, and Azure</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredBuckets.map((b: any, i: number) => {
                const provMeta = PROVIDER_META[b.provider] ?? { label: b.provider, color: "text-foreground", bg: "" };
                const statMeta = BUCKET_STATUS_META[b.status] ?? BUCKET_STATUS_META.error;
                return (
                  <div key={i} className={cn("border rounded-lg p-3 space-y-2", b.isPublic ? "border-red-500/20 bg-red-500/5" : "border-border bg-accent/10")}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", statMeta.color)}>{statMeta.label}</span>
                      <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", provMeta.bg, provMeta.color)}>{provMeta.label}</span>
                      <span className="font-mono text-sm font-semibold text-foreground">{b.name}</span>
                      <span className="ml-auto text-[10px] text-muted-foreground">HTTP {b.httpStatus}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-primary/80 flex-1 truncate">{b.url}</span>
                      <a href={b.url} target="_blank" rel="noreferrer" className="shrink-0">
                        <ExternalLink className="w-3 h-3 text-muted-foreground hover:text-foreground" />
                      </a>
                    </div>
                    {b.region && <p className="text-xs text-muted-foreground">Region: <span className="text-foreground">{b.region}</span></p>}
                    {b.fileCount != null && (
                      <p className="text-xs text-muted-foreground">Files listed: <span className="text-red-400 font-semibold">{b.fileCount}</span></p>
                    )}
                    {b.sampleFiles && b.sampleFiles.length > 0 && (
                      <div className="space-y-0.5">
                        <p className="text-[10px] text-muted-foreground font-medium">Sample files:</p>
                        <div className="flex flex-wrap gap-1">
                          {b.sampleFiles.slice(0, 10).map((f: string, j: number) => (
                            <span key={j} className="font-mono text-[10px] bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5 text-red-300">{f}</span>
                          ))}
                          {b.sampleFiles.length > 10 && <span className="text-[10px] text-muted-foreground">+{b.sampleFiles.length - 10} more</span>}
                        </div>
                      </div>
                    )}
                    {b.isPublic && (
                      <div className="flex items-start gap-1.5 text-[10px] text-orange-400 bg-orange-500/5 border border-orange-500/20 rounded px-2 py-1.5">
                        <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                        <span>{b.isListable ? "Bucket is publicly listable — all contents are exposed to the internet. This is a critical finding." : "Bucket is publicly accessible — direct access possible. Review ACL settings immediately."}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )
      )}

      {/* ── Firebase section ── */}
      {section === "firebase" && (
        filteredFb.length === 0
          ? (
            <div className="text-center py-8 text-muted-foreground space-y-1">
              <CheckCircle2 className="w-7 h-7 mx-auto text-green-400 opacity-60" />
              <p className="text-sm">No Firebase databases found</p>
            </div>
          ) : (
            <div className="space-y-2">
              {filteredFb.map((f: any, i: number) => (
                <div key={i} className={cn("border rounded-lg p-3 space-y-2", f.isPublic ? "border-red-500/20 bg-red-500/5" : "border-border bg-accent/10")}>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5",
                      f.status === "public" ? "bg-red-500/15 text-red-400 border-red-500/40" :
                      f.status === "restricted" ? "bg-accent/60 text-muted-foreground border-border" :
                      "bg-accent/30 text-muted-foreground/60 border-border"
                    )}>{f.status.toUpperCase()}</span>
                    <span className="text-[10px] font-bold border rounded px-1.5 py-0.5 text-yellow-400 border-yellow-500/30 bg-yellow-500/10">Firebase RTDB</span>
                    <span className="font-mono text-sm font-semibold text-foreground">{f.name}</span>
                    <span className="ml-auto text-[10px] text-muted-foreground">HTTP {f.httpStatus}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-primary/80 flex-1 truncate">{f.url}</span>
                    <a href={f.url} target="_blank" rel="noreferrer"><ExternalLink className="w-3 h-3 text-muted-foreground hover:text-foreground" /></a>
                  </div>
                  {f.dataKeys && f.dataKeys.length > 0 && (
                    <div>
                      <p className="text-[10px] text-muted-foreground font-medium mb-1">Exposed data keys:</p>
                      <div className="flex flex-wrap gap-1">
                        {f.dataKeys.map((k: string, j: number) => (
                          <span key={j} className="font-mono text-[10px] bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5 text-red-300">{k}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {f.dataPreview && (
                    <p className="font-mono text-[10px] bg-red-500/5 border border-red-500/15 rounded px-2 py-1.5 text-muted-foreground break-all">{f.dataPreview.slice(0, 300)}</p>
                  )}
                  {f.isPublic && (
                    <div className="flex items-start gap-1.5 text-[10px] text-red-400 bg-red-500/5 border border-red-500/20 rounded px-2 py-1.5">
                      <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                      <span>Firebase database allows unauthenticated reads. Update Security Rules: set .read to <code className="font-mono bg-black/20 rounded px-1">auth != null</code></span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )
      )}

      {/* ── SSRF Metadata Endpoints section ── */}
      {section === "ssrf" && (
        <div className="space-y-3">
          <div className="bg-orange-500/5 border border-orange-500/20 rounded-lg p-3 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-orange-400">For Manual Testing Only</p>
              <p className="text-xs text-muted-foreground mt-0.5">These endpoints are only reachable from within cloud VM instances. If you discover an SSRF vulnerability in the target application, probe these URLs to escalate to credential theft and lateral movement.</p>
            </div>
          </div>
          {ssrf.map((e: any, i: number) => (
            <div key={i} className="bg-accent/10 border border-border rounded-lg p-3 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5",
                  e.risk === "critical" ? "bg-red-500/15 text-red-400 border-red-500/40" : "bg-orange-500/15 text-orange-400 border-orange-500/40"
                )}>{e.risk?.toUpperCase()}</span>
                <span className="text-sm font-semibold text-foreground">{e.provider}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-[10px] text-primary/80 bg-primary/5 border border-primary/20 rounded px-2 py-1">{e.url}</span>
              </div>
              <p className="text-xs text-muted-foreground leading-relaxed">{e.description}</p>
              {e.payloadVariants && e.payloadVariants.length > 0 && (
                <div className="space-y-1">
                  <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Payload Variants</p>
                  <div className="space-y-0.5 max-h-36 overflow-y-auto">
                    {e.payloadVariants.map((v: string, j: number) => (
                      <div key={j} className="font-mono text-[10px] text-muted-foreground bg-muted/30 rounded px-2 py-1 break-all">{v}</div>
                    ))}
                  </div>
                </div>
              )}
              {e.notes && (
                <p className="text-[10px] text-muted-foreground/80 border-t border-border pt-2 leading-relaxed">{e.notes}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Tested names (collapsed) */}
      {testedNames.length > 0 && section === "buckets" && (
        <details className="group">
          <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground flex items-center gap-1.5 select-none">
            <ChevronRight className="w-3 h-3 transition-transform group-open:rotate-90" />
            {testedNames.length} naming patterns tested
          </summary>
          <div className="mt-2 flex flex-wrap gap-1 max-h-28 overflow-y-auto">
            {testedNames.map((n: string, i: number) => (
              <span key={i} className="font-mono text-[10px] bg-accent/30 border border-border rounded px-1.5 py-0.5 text-muted-foreground">{n}</span>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// ── Parameter Discovery Tab ───────────────────────────────────────────────────

const PARAM_CAT_META: Record<string, { label: string; color: string; desc: string }> = {
  ssrf_redirect: { label: "SSRF / Redirect",  color: "bg-red-500/15 text-red-400 border-red-500/30",     desc: "Open redirect & SSRF vectors — can be used to forge server-side requests or redirect users to attacker-controlled pages" },
  idor:          { label: "IDOR",              color: "bg-orange-500/15 text-orange-400 border-orange-500/30", desc: "Insecure Direct Object Reference — numeric/UUID identifiers that may expose other users' resources" },
  auth:          { label: "Auth / Token",      color: "bg-purple-500/15 text-purple-400 border-purple-500/30", desc: "Authentication & authorization parameters — leaked or predictable values can lead to account takeover" },
  file_path:     { label: "File / Path",       color: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", desc: "File inclusion & path traversal risk — values passed to file I/O operations without sanitization" },
  xss_sqli:      { label: "XSS / SQLi",        color: "bg-blue-500/15 text-blue-400 border-blue-500/30",   desc: "Reflected XSS & SQL injection vectors — user input reflected in HTML or passed into database queries" },
  other:         { label: "Other",             color: "bg-accent/60 text-muted-foreground border-border",   desc: "General parameters — worth testing but not classified into a high-risk category" },
};

const SOURCE_META: Record<string, { label: string; color: string }> = {
  archive: { label: "Archive",      color: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10" },
  crawl:   { label: "Crawled",      color: "text-green-400 border-green-500/30 bg-green-500/10" },
  form:    { label: "Form",         color: "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" },
  brute:   { label: "Brute-force",  color: "text-orange-400 border-orange-500/30 bg-orange-500/10" },
};

const CONF_COLORS: Record<string, string> = {
  high:   "text-red-400",
  medium: "text-yellow-400",
  low:    "text-muted-foreground",
};

function ParamDiscoveryTab({ paramDiscovery }: { paramDiscovery: any }) {
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [search, setSearch] = useState("");

  if (!paramDiscovery || paramDiscovery.stats?.total === 0) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <FileCode className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No parameters discovered</p>
        <p className="text-xs text-muted-foreground/70">Run a new scan — Parameter Discovery runs automatically on web assets.</p>
      </div>
    );
  }

  const stats = paramDiscovery.stats ?? {};
  const params: any[] = paramDiscovery.params ?? [];

  const categories = ["all", "ssrf_redirect", "idor", "auth", "file_path", "xss_sqli", "other"];
  const catCount = (cat: string) => cat === "all" ? stats.total : stats[cat === "ssrf_redirect" ? "ssrf" : cat === "xss_sqli" ? "xss_sqli" : cat] ?? 0;

  const filtered = params.filter(p => {
    if (activeCategory !== "all" && p.category !== activeCategory) return false;
    if (search && !p.name.toLowerCase().includes(search.toLowerCase()) && !p.url?.includes(search)) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "Total Params",    value: stats.total,       sub: `${stats.unique} unique names`,  color: "text-primary" },
          { label: "From Archive",    value: stats.fromArchive, sub: "historical archive URLs",        color: "text-cyan-400" },
          { label: "From Brute-force",value: stats.fromBrute,   sub: "active parameter discovery",    color: "text-orange-400" },
          { label: "High-risk",       value: (stats.ssrf ?? 0) + (stats.idor ?? 0) + (stats.auth ?? 0), sub: "SSRF + IDOR + Auth", color: "text-red-400" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide block mb-1">{s.label}</span>
            <p className={cn("text-xl font-bold", s.color)}>{s.value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Category breakdown */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
        {categories.filter(c => c !== "all").map(cat => {
          const meta = PARAM_CAT_META[cat];
          const count = cat === "ssrf_redirect" ? (stats.ssrf ?? 0) : stats[cat] ?? 0;
          return (
            <div key={cat} className={cn("border rounded-lg p-2 cursor-pointer transition-colors", activeCategory === cat ? meta.color : "bg-accent/10 border-border hover:border-muted-foreground/30")}
              onClick={() => setActiveCategory(activeCategory === cat ? "all" : cat)}>
              <p className="text-[10px] font-semibold leading-tight">{meta.label}</p>
              <p className="text-lg font-bold mt-0.5">{count}</p>
            </div>
          );
        })}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          onClick={() => setActiveCategory("all")}
          className={cn("px-3 py-1.5 text-xs font-medium rounded-lg border transition-colors", activeCategory === "all" ? "bg-primary/15 text-primary border-primary/30" : "bg-accent/30 text-muted-foreground border-border hover:text-foreground")}
        >All ({stats.total})</button>
        <div className="ml-auto flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5">
          <Search className="w-3 h-3 text-muted-foreground" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter by name or URL…"
            className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-44" />
          {search && <button onClick={() => setSearch("")} className="text-muted-foreground hover:text-foreground"><X className="w-3 h-3" /></button>}
        </div>
        <span className="text-xs text-muted-foreground">{filtered.length} results</span>
      </div>

      {/* Parameter list */}
      {filtered.length === 0
        ? <EmptyState message="No parameters match the current filter" icon={FileCode} />
        : (
          <div className="rounded-lg border border-border overflow-hidden">
            <div className="grid grid-cols-[1fr_auto_auto_auto_2fr] gap-0 border-b border-border bg-accent/20 px-3 py-2">
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Parameter</span>
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide px-2">Source</span>
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide px-2">Method</span>
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide px-2">Confidence</span>
              <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide px-2">URL / Context</span>
            </div>
            <div className="divide-y divide-border/40">
              {filtered.slice(0, 500).map((p: any, i: number) => {
                const catMeta = PARAM_CAT_META[p.category] ?? PARAM_CAT_META.other;
                const srcMeta = SOURCE_META[p.source] ?? { label: p.source, color: "text-muted-foreground border-border" };
                return (
                  <div key={i} className="grid grid-cols-[1fr_auto_auto_auto_2fr] gap-0 px-3 py-2 text-xs hover:bg-accent/20 transition-colors items-center">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={cn("text-[9px] font-bold border rounded px-1 py-0.5 uppercase tracking-wide whitespace-nowrap shrink-0", catMeta.color)}>
                        {catMeta.label}
                      </span>
                      <span className="font-mono font-semibold text-foreground truncate">{p.name}</span>
                    </div>
                    <div className="px-2">
                      <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5", srcMeta.color)}>{srcMeta.label}</span>
                    </div>
                    <div className="px-2">
                      <span className={cn("text-[10px] font-mono", p.method === "POST" ? "text-orange-400" : "text-muted-foreground")}>{p.method}</span>
                    </div>
                    <div className="px-2">
                      <span className={cn("text-[10px] font-semibold", CONF_COLORS[p.confidence])}>{p.confidence}</span>
                    </div>
                    <div className="px-2 flex items-center gap-2 min-w-0">
                      <span className="font-mono text-[10px] text-muted-foreground/70 truncate flex-1">{p.url}</span>
                      {p.example && (
                        <span className="font-mono text-[10px] bg-accent/60 border border-border rounded px-1.5 py-0.5 text-muted-foreground shrink-0 max-w-[120px] truncate" title={p.example}>
                          ex: {p.example}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
              {filtered.length > 1000 && (
                <div className="px-3 py-2 text-center text-xs text-muted-foreground">
                  … and {filtered.length - 1000} more parameters
                </div>
              )}
            </div>
          </div>
        )
      }

      {/* Category descriptions */}
      {activeCategory !== "all" && PARAM_CAT_META[activeCategory] && (
        <div className={cn("border rounded-lg p-3 flex items-start gap-2", PARAM_CAT_META[activeCategory].color)}>
          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          <div>
            <p className="text-xs font-semibold">{PARAM_CAT_META[activeCategory].label} Parameters</p>
            <p className="text-xs mt-0.5 opacity-80">{PARAM_CAT_META[activeCategory].desc}</p>
          </div>
        </div>
      )}
    </div>
  );
}

// ── JavaScript Analysis Tab ────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-accent/60 text-muted-foreground border-border",
};

function JsAnalysisTab({ jsAnalysis }: { jsAnalysis: any }) {
  const [section, setSection] = useState<"secrets" | "endpoints" | "files">("secrets");
  const [search, setSearch] = useState("");

  if (!jsAnalysis || jsAnalysis.stats?.analyzedFiles === 0) {
    return (
      <div className="text-center py-10 text-muted-foreground space-y-2">
        <Code className="w-8 h-8 mx-auto opacity-30" />
        <p className="text-sm">No JavaScript files were analyzed</p>
        <p className="text-xs text-muted-foreground/70">Run a new scan — JS Analysis runs automatically on web assets.</p>
      </div>
    );
  }

  const stats = jsAnalysis.stats ?? {};
  const jsFiles: any[]   = jsAnalysis.jsFiles ?? [];
  const endpoints: any[] = jsAnalysis.endpoints ?? [];
  const secrets: any[]   = jsAnalysis.secrets ?? [];

  const filteredSecrets   = secrets.filter(s => !search || s.type?.toLowerCase().includes(search.toLowerCase()) || s.file?.includes(search));
  const filteredEndpoints = endpoints.filter(e => !search || e.path?.toLowerCase().includes(search.toLowerCase()) || e.file?.includes(search));
  const filteredFiles     = jsFiles.filter(f => !search || f.url?.includes(search));

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { label: "JS Files",             value: stats.totalFiles ?? 0,      sub: `${stats.analyzedFiles ?? 0} analyzed`, icon: FileCode,    color: "text-primary" },
          { label: "Endpoints Extracted",  value: stats.totalEndpoints ?? 0,  sub: "via LinkFinder",                        icon: Search,      color: "text-blue-400" },
          { label: "Secrets Detected",     value: stats.totalSecrets ?? 0,    sub: `${stats.criticalSecrets ?? 0} critical`, icon: ShieldAlert, color: stats.criticalSecrets > 0 ? "text-red-400" : "text-orange-400" },
          { label: "High Severity",        value: stats.highSecrets ?? 0,     sub: "need immediate action",                 icon: AlertTriangle, color: "text-orange-400" },
        ].map(s => (
          <div key={s.label} className="bg-accent/20 border border-border rounded-lg p-3">
            <div className="flex items-center gap-1.5 mb-1">
              <s.icon className={cn("w-3.5 h-3.5", s.color)} />
              <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide">{s.label}</span>
            </div>
            <p className={cn("text-xl font-bold", s.color)}>{s.value}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
          </div>
        ))}
      </div>

      {/* Section tabs + search */}
      <div className="flex items-center gap-2 flex-wrap">
        {(["secrets", "endpoints", "files"] as const).map(s => (
          <button
            key={s}
            onClick={() => { setSection(s); setSearch(""); }}
            className={cn(
              "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border",
              section === s
                ? "bg-primary/15 text-primary border-primary/30"
                : "bg-accent/30 text-muted-foreground border-border hover:text-foreground"
            )}
          >
            {s === "secrets" ? `Secrets (${secrets.length})` : s === "endpoints" ? `Endpoints (${endpoints.length})` : `JS Files (${jsFiles.length})`}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-1.5 bg-accent/30 border border-border rounded-lg px-2.5 py-1.5">
          <Search className="w-3 h-3 text-muted-foreground" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter…"
            className="bg-transparent text-xs outline-none placeholder:text-muted-foreground/60 w-36"
          />
          {search && <button onClick={() => setSearch("")} className="text-muted-foreground hover:text-foreground"><X className="w-3 h-3" /></button>}
        </div>
      </div>

      {/* ── Secrets section ── */}
      {section === "secrets" && (
        filteredSecrets.length === 0
          ? <EmptyState message="No secrets detected in JavaScript files" icon={ShieldAlert} />
          : (
            <div className="space-y-2">
              {filteredSecrets.map((s: any, i: number) => (
                <div key={i} className="bg-accent/10 border border-border rounded-lg p-3 space-y-1.5">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={cn("text-[10px] font-bold border rounded px-1.5 py-0.5 uppercase tracking-wide", SEV_COLORS[s.severity ?? "info"])}>
                      {s.severity}
                    </span>
                    <span className="text-sm font-semibold text-foreground">{s.type}</span>
                    <span className="text-xs text-muted-foreground ml-auto">{s.cwe}</span>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap text-xs text-muted-foreground">
                    <FileCode className="w-3 h-3 shrink-0" />
                    <span className="font-mono text-[10px] text-primary/80 truncate max-w-[360px]">{s.file?.split("/").pop() ?? s.file}</span>
                    {s.line > 0 && <span className="text-muted-foreground/60">line {s.line}</span>}
                    <span className="font-mono text-[10px] bg-red-500/10 border border-red-500/20 rounded px-1.5 py-0.5 text-red-400">{s.value}</span>
                  </div>
                  {s.rawContext && (
                    <p className="font-mono text-[10px] bg-muted/40 rounded px-2 py-1.5 text-muted-foreground break-all leading-relaxed">{s.rawContext}</p>
                  )}
                  <p className="text-xs text-muted-foreground/80 leading-relaxed">
                    <span className="text-orange-400 font-medium">Remediation:</span> {s.remediation}
                  </p>
                </div>
              ))}
            </div>
          )
      )}

      {/* ── Endpoints section ── */}
      {section === "endpoints" && (
        filteredEndpoints.length === 0
          ? <EmptyState message="No endpoints extracted from JavaScript files" icon={Search} />
          : (
            <div className="space-y-1">
              {filteredEndpoints.slice(0, 500).map((e: any, i: number) => (
                <div key={i} className="flex items-center gap-2 px-3 py-1.5 bg-accent/10 border border-border/40 rounded-lg text-xs hover:bg-accent/20 transition-colors">
                  {e.method
                    ? <span className="text-[10px] font-bold text-cyan-400 border border-cyan-500/30 bg-cyan-500/10 rounded px-1.5 py-0.5 min-w-[36px] text-center">{e.method}</span>
                    : <span className="text-[10px] text-muted-foreground/40 min-w-[36px]">—</span>
                  }
                  <span className="font-mono text-[11px] text-foreground flex-1 truncate">{e.path}</span>
                  <span className="font-mono text-[10px] text-muted-foreground/60 shrink-0 hidden sm:block">{e.file?.split("/").pop()}</span>
                </div>
              ))}
              {filteredEndpoints.length > 500 && (
                <p className="text-xs text-muted-foreground text-center pt-1">… and {filteredEndpoints.length - 500} more</p>
              )}
            </div>
          )
      )}

      {/* ── JS Files section ── */}
      {section === "files" && (
        filteredFiles.length === 0
          ? <EmptyState message="No JavaScript files found" icon={FileCode} />
          : (
            <div className="space-y-1">
              {filteredFiles.map((f: any, i: number) => (
                <div key={i} className="flex items-center gap-2 px-3 py-2 bg-accent/10 border border-border/40 rounded-lg text-xs hover:bg-accent/20 transition-colors group">
                  <FileCode className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
                  <span className="font-mono text-[10px] text-foreground flex-1 truncate">{f.url}</span>
                  <div className="flex items-center gap-2 shrink-0 text-muted-foreground">
                    <span>{f.analyzed ? `${(f.size / 1024).toFixed(0)}KB` : "skipped"}</span>
                    {f.endpointCount > 0 && <span className="text-blue-400">{f.endpointCount} ep</span>}
                    {f.secretCount > 0 && <span className="text-red-400 font-medium">{f.secretCount} secrets</span>}
                    <span className={cn("text-[10px] border rounded px-1.5 py-0.5 font-bold", f.analyzed ? "text-green-400 border-green-500/30 bg-green-500/10" : "text-muted-foreground border-border")}>
                      {f.analyzed ? "OK" : "SKIP"}
                    </span>
                    <a href={f.url} target="_blank" rel="noreferrer" className="opacity-0 group-hover:opacity-100 transition-opacity">
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              ))}
            </div>
          )
      )}
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
