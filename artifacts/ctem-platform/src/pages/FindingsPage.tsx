import { useState, useMemo } from "react";
import { Link, useLocation } from "wouter";
import { useListFindings, useUpdateFinding, getListFindingsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Search, ExternalLink, ChevronLeft, ChevronRight, X,
  ShieldAlert, Globe, Network, Server, Cpu, Smartphone,
  FileText, Code2, Camera, AlignLeft, Tag, Info,
  CheckCircle2, Clock, AlertCircle, XCircle, Minus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, capitalize, formatDate } from "@/lib/utils";

const STATUSES = ["open", "in_progress", "accepted_risk", "false_positive", "mitigated"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const PAGE_SIZE = 25;

// ── Helpers ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-muted text-muted-foreground border-border",
};

const STATUS_COLOR: Record<string, string> = {
  open:            "bg-red-500/10 text-red-400 border-red-500/30",
  in_progress:     "bg-blue-500/10 text-blue-400 border-blue-500/30",
  accepted_risk:   "bg-amber-500/10 text-amber-400 border-amber-500/30",
  false_positive:  "bg-muted text-muted-foreground border-border",
  mitigated:       "bg-green-500/10 text-green-400 border-green-500/30",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  open: AlertCircle,
  in_progress: Clock,
  accepted_risk: Info,
  false_positive: Minus,
  mitigated: CheckCircle2,
};

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  domain:       Globe,
  subdomain:    Network,
  ip:           Server,
  cidr:         Network,
  url:          Globe,
  api:          Code2,
  ssl_cert:     ShieldAlert,
  cloud_asset:  Cpu,
  host:         Server,
  sentinelware: Server,
  mobile_app:   Smartphone,
};

function assetTypeLabel(t: string | null) {
  if (!t) return "—";
  if (t === "sentinelware") return "Sentinelware";
  return capitalize(t.replace(/_/g, " "));
}

/** Compute importance score 0-100 from CVE data */
function importanceScore(f: any): number | null {
  const cvss = f.cvss ?? 0;
  const epss = f.epss ?? 0;
  const kev  = f.isKev ? 30 : 0;
  if (!cvss && !epss && !kev) return null;
  return Math.min(100, Math.round(kev + (cvss / 10) * 40 + epss * 30));
}

function ScoreBadge({ score, label }: { score: number | null; label?: string }) {
  if (score === null) return <span className="text-xs text-muted-foreground/50">—</span>;
  const color =
    score >= 80 ? "text-red-400" :
    score >= 60 ? "text-orange-400" :
    score >= 40 ? "text-yellow-400" : "text-blue-400";
  return (
    <span className={cn("text-xs font-bold tabular-nums", color)} title={label}>
      {score}
    </span>
  );
}

// ── Metadata Drawer ────────────────────────────────────────────────────────

type DrawerMode = "metadata" | "headers" | "screenshots" | null;

function FindingDrawer({ finding, mode, onClose }: { finding: any; mode: DrawerMode; onClose: () => void }) {
  if (!mode || !finding) return null;

  let parsedEvidence: Record<string, any> | null = null;
  try {
    if (finding.evidence) parsedEvidence = JSON.parse(finding.evidence);
  } catch { /* not JSON */ }

  const headers: Record<string, string> | null = parsedEvidence?.headers ?? null;
  const screenshots: string[] = parsedEvidence?.screenshots ?? [];

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm" onClick={onClose} />

      {/* Drawer */}
      <div className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-md bg-sidebar border-l border-sidebar-border flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-sidebar-border">
          <div className="flex items-center gap-2">
            {mode === "metadata"    && <FileText className="w-4 h-4 text-primary" />}
            {mode === "headers"     && <AlignLeft className="w-4 h-4 text-primary" />}
            {mode === "screenshots" && <Camera className="w-4 h-4 text-primary" />}
            <h2 className="text-sm font-semibold">
              {mode === "metadata"    && "Finding Metadata"}
              {mode === "headers"     && "HTTP Headers"}
              {mode === "screenshots" && "Screenshots"}
            </h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 rounded transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4 text-sm">
          {mode === "metadata" && (
            <>
              {/* Title */}
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Title</p>
                <p className="font-medium">{finding.title}</p>
              </div>

              {/* Badges row */}
              <div className="flex flex-wrap gap-2">
                <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-bold uppercase border", SEV_COLOR[finding.severity] ?? SEV_COLOR.info)}>
                  {finding.severity}
                </span>
                {finding.isKev && (
                  <span className="text-[10px] px-2 py-0.5 rounded-md font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30">
                    KEV
                  </span>
                )}
                <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-semibold uppercase border", STATUS_COLOR[finding.status] ?? "")}>
                  {finding.status?.replace(/_/g, " ")}
                </span>
              </div>

              {/* Description */}
              {finding.description && (
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Description</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{finding.description}</p>
                </div>
              )}

              {/* Asset info */}
              <div className="bg-card border border-border rounded-lg p-3 space-y-2">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold">Asset Information</p>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <p className="text-muted-foreground mb-0.5">Name</p>
                    <p className="font-medium">{finding.assetName ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Value</p>
                    <p className="font-mono font-medium">{finding.assetValue ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Type</p>
                    <p className="font-medium">{assetTypeLabel(finding.assetType)}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Last Scanned</p>
                    <p className="font-medium">{finding.assetLastScannedAt ? formatDate(finding.assetLastScannedAt) : "—"}</p>
                  </div>
                </div>
              </div>

              {/* CVE / Scoring */}
              <div className="bg-card border border-border rounded-lg p-3 space-y-2">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold">Vulnerability Scoring</p>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <p className="text-muted-foreground mb-0.5">CVE</p>
                    <p className="font-mono font-medium">{finding.cve ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">CWE</p>
                    <p className="font-mono font-medium">{finding.cwe ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">CVSS</p>
                    <p className="font-bold text-orange-400">{finding.cvss ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">EPSS</p>
                    <p className="font-medium">{finding.epss != null ? `${(finding.epss * 100).toFixed(1)}%` : "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">ASM Score</p>
                    <p className="font-bold">{finding.riskScore ?? "—"}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground mb-0.5">Importance Score</p>
                    <p className="font-bold">{importanceScore(finding) ?? "—"}</p>
                  </div>
                </div>
              </div>

              {/* Remediation */}
              {finding.remediation && (
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Remediation</p>
                  <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-3">
                    <p className="text-xs text-muted-foreground leading-relaxed">{finding.remediation}</p>
                  </div>
                </div>
              )}

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <p className="text-muted-foreground mb-0.5">First Detected</p>
                  <p className="font-medium">{formatDate(finding.createdAt)}</p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-0.5">Last Updated</p>
                  <p className="font-medium">{formatDate(finding.updatedAt)}</p>
                </div>
              </div>

              <div className="pt-2">
                <Link href={`/findings/${finding.id}`}>
                  <Button size="sm" className="w-full gap-2">
                    <ExternalLink className="w-3.5 h-3.5" /> Open Full Detail
                  </Button>
                </Link>
              </div>
            </>
          )}

          {mode === "headers" && (
            headers ? (
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">HTTP response headers captured during scan.</p>
                <div className="bg-card border border-border rounded-lg divide-y divide-border">
                  {Object.entries(headers).map(([k, v]) => (
                    <div key={k} className="px-3 py-2 grid grid-cols-2 gap-2 text-xs">
                      <span className="font-mono text-primary/80 truncate">{k}</span>
                      <span className="font-mono text-muted-foreground truncate" title={String(v)}>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <AlignLeft className="w-10 h-10 text-muted-foreground/20 mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No header data available</p>
                <p className="text-xs text-muted-foreground/60 mt-1">HTTP headers are captured when an HTTP scan tool is run against this asset.</p>
              </div>
            )
          )}

          {mode === "screenshots" && (
            screenshots.length > 0 ? (
              <div className="space-y-3">
                {screenshots.map((src: string, i: number) => (
                  <img key={i} src={src} alt={`Screenshot ${i + 1}`} className="w-full rounded-lg border border-border" />
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <Camera className="w-10 h-10 text-muted-foreground/20 mb-3" />
                <p className="text-sm font-medium text-muted-foreground">No screenshots available</p>
                <p className="text-xs text-muted-foreground/60 mt-1">Screenshots are captured when a web screenshot tool is run against this asset.</p>
              </div>
            )
          )}
        </div>
      </div>
    </>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function FindingsPage() {
  const [, navigate] = useLocation();
  const [search, setSearch]   = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus]   = useState("");
  const [page, setPage]       = useState(1);

  const [drawerFinding, setDrawerFinding] = useState<any>(null);
  const [drawerMode, setDrawerMode]       = useState<DrawerMode>(null);

  const qc = useQueryClient();
  const updateFinding = useUpdateFinding();

  const handleStatusChange = async (findingId: number, newStatus: string, e: React.MouseEvent) => {
    e.stopPropagation();
    await updateFinding.mutateAsync({ findingId, data: { status: newStatus } as any });
    qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
  };

  function openDrawer(finding: any, mode: DrawerMode) {
    setDrawerFinding(finding);
    setDrawerMode(mode);
  }
  function closeDrawer() { setDrawerMode(null); setDrawerFinding(null); }

  const params = {
    search: search || undefined,
    severity: severity || undefined,
    status: status || undefined,
  };

  const { data: findings, isLoading } = useListFindings(params as any, {
    query: { queryKey: getListFindingsQueryKey(params as any) },
  });

  const list = (findings as any[]) ?? [];
  const totalPages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
  const paginated  = list.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Summary counts
  const counts = useMemo(() => ({
    critical: list.filter(f => f.severity === "critical").length,
    high:     list.filter(f => f.severity === "high").length,
    open:     list.filter(f => f.status === "open").length,
    kev:      list.filter(f => f.isKev).length,
  }), [list]);

  function resetPage() { setPage(1); }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Vulnerability Findings</h1>
          <p className="text-sm text-muted-foreground">{list.length} findings across all assets</p>
        </div>
      </div>

      {/* Summary chips */}
      <div className="flex gap-2 flex-wrap">
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs">
          <span className="font-bold text-red-400">{counts.critical}</span>
          <span className="text-red-400/80">Critical</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-orange-500/10 border border-orange-500/20 text-xs">
          <span className="font-bold text-orange-400">{counts.high}</span>
          <span className="text-orange-400/80">High</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-muted border border-border text-xs">
          <span className="font-bold text-foreground">{counts.open}</span>
          <span className="text-muted-foreground">Open</span>
        </div>
        {counts.kev > 0 && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/20 border border-red-500/30 text-xs">
            <span className="font-bold text-red-400">{counts.kev}</span>
            <span className="text-red-400/80">KEV</span>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={search}
            onChange={e => { setSearch(e.target.value); resetPage(); }}
            placeholder="Search findings..."
            className="pl-8 h-8 text-sm"
          />
        </div>
        <Select value={severity || "_all_"} onValueChange={v => { setSeverity(v === "_all_" ? "" : v); resetPage(); }}>
          <SelectTrigger className="w-34 h-8 text-sm"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All Severities</SelectItem>
            {SEVERITIES.map(s => <SelectItem key={s} value={s}>{capitalize(s)}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={status || "_all_"} onValueChange={v => { setStatus(v === "_all_" ? "" : v); resetPage(); }}>
          <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="_all_">All Statuses</SelectItem>
            {STATUSES.map(s => <SelectItem key={s} value={s}>{capitalize(s.replace(/_/g, " "))}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" onClick={() => { setSeverity(""); setStatus(""); setSearch(""); resetPage(); }}>
          Clear
        </Button>
      </div>

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[1200px]">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground w-[240px]">Title</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset Detail</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset Type</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Asset</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Severity</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">ASM Score</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">First Scan</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Last Scan</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Imp. Score</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Status</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">CVE</th>
                <th className="text-left px-3 py-2.5 text-xs font-semibold text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(8)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(12)].map((_, j) => (
                    <td key={j} className="px-3 py-3"><Skeleton className="h-4" /></td>
                  ))}
                </tr>
              ))}

              {!isLoading && paginated.map((f: any) => {
                const TypeIcon = ASSET_TYPE_ICON[f.assetType ?? ""] ?? Globe;
                const StatusIcon = STATUS_ICON[f.status] ?? Minus;
                const impScore = importanceScore(f);

                return (
                  <tr key={f.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors group cursor-pointer" onClick={() => navigate(`/findings/${f.id}`)}>
                    {/* Title */}
                    <td className="px-3 py-2.5 max-w-[240px]">
                      <div className="flex items-start gap-1.5">
                        {f.isKev && (
                          <span className="text-[9px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold shrink-0 mt-0.5">KEV</span>
                        )}
                        <span className="font-medium text-foreground line-clamp-2 text-xs leading-snug">{f.title}</span>
                      </div>
                    </td>

                    {/* Asset Detail (value) */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs font-mono text-primary/90">{f.assetValue ?? "—"}</span>
                    </td>

                    {/* Asset Type */}
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <TypeIcon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        <span className="text-xs text-muted-foreground">{assetTypeLabel(f.assetType)}</span>
                      </div>
                    </td>

                    {/* Asset Name */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground truncate max-w-[100px] block">{f.assetName ?? "—"}</span>
                    </td>

                    {/* Severity */}
                    <td className="px-3 py-2.5">
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-bold uppercase border", SEV_COLOR[f.severity] ?? SEV_COLOR.info)}>
                        {f.severity}
                      </span>
                    </td>

                    {/* ASM Score */}
                    <td className="px-3 py-2.5">
                      <ScoreBadge score={f.riskScore != null ? Math.round(f.riskScore) : null} label="Attack Surface Management Score" />
                    </td>

                    {/* First Scan (finding createdAt = first time found) */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">{formatDate(f.createdAt)}</span>
                    </td>

                    {/* Last Scan */}
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">
                        {f.assetLastScannedAt ? formatDate(f.assetLastScannedAt) : "—"}
                      </span>
                    </td>

                    {/* Importance Score */}
                    <td className="px-3 py-2.5">
                      <ScoreBadge score={impScore} label="Importance Score (derived from CVSS, EPSS, KEV)" />
                    </td>

                    {/* Status — inline dropdown */}
                    <td className="px-3 py-2.5" onClick={e => e.stopPropagation()}>
                      <select
                        value={f.status ?? "open"}
                        onChange={e => handleStatusChange(f.id, e.target.value, e as any)}
                        className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase cursor-pointer bg-transparent outline-none",
                          STATUS_COLOR[f.status] ?? "border-border text-muted-foreground"
                        )}
                      >
                        {STATUSES.map(s => (
                          <option key={s} value={s} className="bg-card text-foreground normal-case">
                            {s.replace(/_/g, " ")}
                          </option>
                        ))}
                      </select>
                    </td>

                    {/* CVE */}
                    <td className="px-3 py-2.5">
                      {f.cve ? (
                        <span className="text-xs font-mono text-amber-400/90">{f.cve}</span>
                      ) : (
                        <span className="text-xs text-muted-foreground/40">—</span>
                      )}
                    </td>

                    {/* Actions */}
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "metadata"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors font-medium"
                          title="View Metadata"
                        >
                          <FileText className="w-3 h-3" />
                          <span className="hidden xl:inline">Meta</span>
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "headers"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-accent/60 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors font-medium"
                          title="View HTTP Headers"
                        >
                          <AlignLeft className="w-3 h-3" />
                          <span className="hidden xl:inline">Headers</span>
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); openDrawer(f, "screenshots"); }}
                          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded bg-accent/60 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors font-medium"
                          title="View Screenshots"
                        >
                          <Camera className="w-3 h-3" />
                          <span className="hidden xl:inline">Shot</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}

              {!isLoading && list.length === 0 && (
                <tr>
                  <td colSpan={12} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No findings match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {!isLoading && totalPages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <p className="text-xs text-muted-foreground">
            Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, list.length)} of {list.length} findings
          </p>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" className="h-7 px-2" disabled={page === 1} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft className="w-3.5 h-3.5" />
            </Button>
            {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
              const p = totalPages <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= totalPages - 3 ? totalPages - 6 + i : page - 3 + i;
              if (p < 1 || p > totalPages) return null;
              return (
                <Button key={p} size="sm" variant={p === page ? "default" : "outline"} className="h-7 w-7 p-0 text-xs" onClick={() => setPage(p)}>{p}</Button>
              );
            })}
            <Button size="sm" variant="outline" className="h-7 px-2" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>
              <ChevronRight className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
      )}

      {/* Drawer */}
      <FindingDrawer finding={drawerFinding} mode={drawerMode} onClose={closeDrawer} />
    </div>
  );
}
