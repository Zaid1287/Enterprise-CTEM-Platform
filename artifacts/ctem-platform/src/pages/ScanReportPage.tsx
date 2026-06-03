import { useState } from "react";
import { useParams, Link } from "wouter";
import { useGetScanAssetReport, useGetScan, useStopScan, getGetScanQueryKey } from "@workspace/api-client-react";
import {
  ChevronLeft, Shield, Globe, Network, AlertTriangle, Server,
  Database, Search, Cpu, Eye, CheckCircle2, XCircle, AlertCircle,
  Info, ExternalLink, Terminal, Wifi, Square, Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

type AssetTab = "ports" | "vulns" | "subdomains" | "http" | "dns" | "endpoints" | "intel" | "raw";

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

export default function ScanReportPage() {
  const params = useParams<{ id: string }>();
  const scanId = Number(params.id);
  const [selectedAssetIdx, setSelectedAssetIdx] = useState(0);
  const [assetTab, setAssetTab] = useState<AssetTab>("ports");
  const [selectedTool, setSelectedTool] = useState<string | null>(null);
  const [stopping, setStopping] = useState(false);

  const { data: reports, isLoading, error } = useGetScanAssetReport(scanId);
  const { data: scanData, refetch: refetchScan } = useGetScan(scanId, {
    query: { queryKey: getGetScanQueryKey(scanId), refetchInterval: (q) => {
      const s = (q.state.data as any)?.status;
      return s === "running" || s === "pending" ? 4000 : false;
    }},
  });
  const stopMutation = useStopScan();

  const scan = scanData as any;
  const scanStatus: string = scan?.status ?? "completed";

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
        <Link href="/tools" className="text-xs text-primary mt-2 inline-block">← Back to Security Tools</Link>
      </div>
    );
  }

  if ((reports as unknown[]).length === 0) {
    return (
      <div className="bg-card border border-border rounded-xl p-8 text-center">
        <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
        <p className="text-sm text-muted-foreground">No scan results found for this scan.</p>
        <Link href="/tools" className="text-xs text-primary mt-2 inline-block">← Back to Security Tools</Link>
      </div>
    );
  }

  const assetReports = reports as any[];
  const selectedAsset = assetReports[selectedAssetIdx] ?? assetReports[0];
  const summary = selectedAsset?.summary ?? {};

  const assetTabs: { key: AssetTab; label: string; icon: React.ElementType; count?: number }[] = [
    { key: "ports", label: "Open Ports", icon: Network, count: summary.openPorts },
    { key: "vulns", label: "Vulnerabilities", icon: AlertTriangle, count: summary.vulnerabilities },
    { key: "subdomains", label: "Subdomains", icon: Globe, count: summary.subdomains },
    { key: "http", label: "HTTP Info", icon: Wifi },
    { key: "dns", label: "DNS Records", icon: Database, count: summary.dnsRecords },
    { key: "endpoints", label: "Endpoints", icon: Search, count: summary.endpoints },
    { key: "intel", label: "Intelligence", icon: Eye, count: summary.intelItems },
    { key: "raw", label: "Raw Output", icon: Terminal },
  ];

  const toolResults = selectedAsset?.toolResults ?? [];
  const displayedTool = selectedTool ?? toolResults[0]?.toolName ?? null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link href="/tools">
          <button className="w-8 h-8 rounded-lg bg-accent/60 hover:bg-accent flex items-center justify-center transition-colors">
            <ChevronLeft className="w-4 h-4" />
          </button>
        </Link>
        <div>
          <h1 className="text-lg font-semibold">Pipeline Scan Report #{scanId}</h1>
          <p className="text-xs text-muted-foreground">{assetReports.length} assets · {assetReports.reduce((acc: number, a: any) => acc + (a.summary?.vulnerabilities ?? 0), 0)} total vulnerabilities</p>
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
            <div className="flex items-center gap-1.5 bg-green-500/10 border border-green-500/30 text-green-400 text-xs px-2.5 py-1 rounded-full">
              <CheckCircle2 className="w-3 h-3" /> Completed
            </div>
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
            const isRunningAsset = scanStatus === "running";
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
                <div className="flex items-center gap-1.5">
                  {isRunningAsset && <Loader2 className="w-2.5 h-2.5 text-blue-400 animate-spin shrink-0" />}
                  <p className="text-sm font-medium truncate">{asset.assetName}</p>
                </div>
                <p className="text-[10px] text-muted-foreground truncate mt-0.5">{asset.assetValue}</p>
                <div className="flex gap-1.5 mt-1.5">
                  {isRunningAsset
                    ? <span className="text-[10px] text-blue-400">Scanning…</span>
                    : <>
                        <span className="text-[10px] bg-muted/60 text-muted-foreground rounded px-1">{asset.summary?.openPorts ?? 0} ports</span>
                        {critVulns > 0 && <span className="text-[10px] bg-red-500/15 text-red-400 rounded px-1">{critVulns} critical</span>}
                        {highVulns > 0 && !critVulns && <span className="text-[10px] bg-orange-500/15 text-orange-400 rounded px-1">{highVulns} high</span>}
                      </>
                  }
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
            <StatCard icon={AlertTriangle} label="Vulnerabilities" value={summary.vulnerabilities ?? 0}
              className={(summary.criticalVulns ?? 0) > 0 ? "border-red-500/30" : ""} />
            <StatCard icon={Globe} label="Subdomains" value={summary.subdomains ?? 0} />
            <StatCard icon={Search} label="Endpoints" value={summary.endpoints ?? 0} />
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
                    <span className="ml-0.5 text-[10px] bg-primary/20 text-primary rounded-full px-1.5">{t.count}</span>
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

              {/* Vulnerabilities tab */}
              {assetTab === "vulns" && (
                <div className="space-y-2">
                  {(selectedAsset.vulnerabilities ?? []).length === 0 ? (
                    <EmptyState message="No vulnerabilities detected" icon={CheckCircle2} />
                  ) : (
                    (selectedAsset.vulnerabilities ?? []).map((v: any, i: number) => (
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
