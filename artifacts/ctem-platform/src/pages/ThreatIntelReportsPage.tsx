import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FileBarChart2, Plus, Loader2, X, RefreshCw, Clock,
  CheckCircle2, AlertCircle, Download, Eye, Trash2,
  ChevronRight, BarChart3, Shield, Globe, Bug,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const STATUS_META: Record<string, { icon: React.ReactNode; cls: string; label: string }> = {
  ready:      { icon: <CheckCircle2 className="w-3.5 h-3.5" />, cls: "text-green-400", label: "Ready" },
  generating: { icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />, cls: "text-blue-400", label: "Generating…" },
  failed:     { icon: <AlertCircle className="w-3.5 h-3.5" />, cls: "text-red-400", label: "Failed" },
  pending:    { icon: <Clock className="w-3.5 h-3.5" />, cls: "text-muted-foreground", label: "Pending" },
};

const TYPE_LABEL: Record<string, string> = {
  summary:       "Executive Summary",
  ioc:           "IOC Report",
  actor:         "Threat Actor Report",
  vulnerability: "Vulnerability Intel",
  custom:        "Custom Report",
};

const TYPE_ICONS: Record<string, React.ReactNode> = {
  summary:       <BarChart3 className="w-4 h-4 text-blue-400" />,
  ioc:           <Bug className="w-4 h-4 text-red-400" />,
  actor:         <Shield className="w-4 h-4 text-purple-400" />,
  vulnerability: <AlertCircle className="w-4 h-4 text-orange-400" />,
  custom:        <Globe className="w-4 h-4 text-cyan-400" />,
};

/* ── New Report Modal ────────────────────────────────────────────────────── */
function NewReportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [reportType, setReportType] = useState("summary");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) { setErr("Please enter a report title"); return; }
    setLoading(true); setErr("");
    try {
      await apiFetch(`${BASE}/api/threat-intel/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: title.trim(), reportType }),
      });
      toast({ title: "Report generation started", description: "Your report is being generated from live TI data. It will be ready in seconds." });
      onDone(); onClose();
    } catch (e: any) {
      setErr(e.message ?? "Failed to start report generation");
    } finally { setLoading(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl p-5 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <FileBarChart2 className="w-4 h-4 text-blue-400" />Generate TI Report
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Report Title *</label>
            <Input value={title} onChange={e => setTitle(e.target.value)}
              placeholder="Q3 2026 Threat Intelligence Summary"
              className="h-8 text-xs" required />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Report Type</label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                {Object.entries(TYPE_LABEL).map(([v, l]) => (
                  <SelectItem key={v} value={v}>
                    <span className="flex items-center gap-2">{TYPE_ICONS[v]}{l}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="bg-muted/30 border border-border/50 rounded-lg p-2.5 text-[11px] text-muted-foreground">
            <p className="font-medium mb-1">Real data included:</p>
            <ul className="space-y-0.5 list-disc list-inside">
              <li>IOCs, Threat Actors, Campaigns, Malware</li>
              <li>CVE Intelligence with EPSS + KEV enrichment</li>
              <li>Dark Web Mentions & Data Breaches</li>
              <li>Vulnerability Findings from your assets</li>
              <li>Recent Threat News</li>
            </ul>
          </div>

          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : <Plus className="w-3.5 h-3.5 mr-1.5" />}
              Generate Report
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Report Viewer ───────────────────────────────────────────────────────── */
function ReportViewer({ reportId, onClose }: { reportId: number; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ["ti-report", reportId],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/reports/${reportId}`),
    staleTime: 60_000,
  });

  const report = data;
  let content: any = {};
  try { if (report?.content) content = JSON.parse(report.content); } catch {}
  const ov = content.overview ?? {};

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-t-2xl sm:rounded-2xl w-full sm:max-w-3xl max-h-[85vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            {report && TYPE_ICONS[report.reportType]}
            <div className="min-w-0">
              <h2 className="text-sm font-semibold truncate">{report?.title ?? "Loading…"}</h2>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {report?.completedAt ? `Generated ${new Date(report.completedAt).toLocaleString()}` : ""}
                {report && ` · ${TYPE_LABEL[report.reportType] ?? report.reportType}`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {report?.status === "ready" && (
              <a href={`${BASE}/api/threat-intel/reports/${reportId}/download?format=json`}
                download className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
                <Download className="w-3.5 h-3.5" />JSON
              </a>
            )}
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground ml-2">
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="overflow-y-auto flex-1 p-5 space-y-5">
          {isLoading ? (
            <div className="space-y-3">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}</div>
          ) : report?.status === "failed" ? (
            <div className="flex flex-col items-center py-10 gap-3 text-center">
              <AlertCircle className="w-8 h-8 text-red-400" />
              <p className="text-sm font-semibold">Report Generation Failed</p>
              <p className="text-xs text-muted-foreground">{(report.metadata as any)?.error ?? "An error occurred during report generation."}</p>
            </div>
          ) : (
            <>
              {/* Risk score */}
              {content.riskScore != null && (
                <div className="flex items-center gap-4 p-4 rounded-xl bg-gradient-to-r from-blue-500/10 to-purple-500/10 border border-blue-500/20">
                  <div className="text-center">
                    <p className="text-3xl font-bold">{content.riskScore}</p>
                    <p className="text-[10px] text-muted-foreground">Risk Score /100</p>
                  </div>
                  <div className="flex-1 grid grid-cols-2 gap-2">
                    {typeof ov.totalIocs === "number" && <StatItem label="IOCs" value={ov.totalIocs} />}
                    {typeof ov.totalActors === "number" && <StatItem label="Actors" value={ov.totalActors} />}
                    {typeof ov.totalCves === "number" && <StatItem label="CVEs" value={ov.totalCves} />}
                    {typeof ov.openFindings === "number" && <StatItem label="Open Findings" value={ov.openFindings} />}
                    {typeof ov.kevCount === "number" && <StatItem label="KEV CVEs" value={ov.kevCount} color="text-red-400" />}
                    {typeof ov.darkWebMentions === "number" && <StatItem label="Dark Web" value={ov.darkWebMentions} color="text-purple-400" />}
                  </div>
                </div>
              )}

              {/* Severity breakdown */}
              {ov.findingsBySeverity && (
                <SeveritySection label="Findings by Severity" data={ov.findingsBySeverity} />
              )}
              {ov.iocsBySeverity && (
                <SeveritySection label="IOCs by Severity" data={ov.iocsBySeverity} />
              )}
              {ov.bySeverity && (
                <SeveritySection label="Severity Breakdown" data={ov.bySeverity} />
              )}

              {/* Top threats */}
              {content.topThreats?.iocs?.length > 0 && (
                <Section title="Critical/High IOCs" count={content.topThreats.iocs.length}>
                  {content.topThreats.iocs.slice(0, 8).map((ioc: any) => (
                    <div key={ioc.id} className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0">
                      <span className="font-mono truncate flex-1">{ioc.value}</span>
                      <span className="text-[10px] text-muted-foreground ml-2">{ioc.type}</span>
                      <SevBadge sev={ioc.severity} />
                    </div>
                  ))}
                </Section>
              )}

              {content.topThreats?.cves?.length > 0 && (
                <Section title="Priority CVEs (KEV / High EPSS)" count={content.topThreats.cves.length}>
                  {content.topThreats.cves.slice(0, 8).map((c: any) => (
                    <div key={c.id} className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0">
                      <span className="font-mono">{c.cveId}</span>
                      {c.isKev && <span className="text-[9px] px-1 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 mx-1">KEV</span>}
                      {c.epss != null && <span className="text-[10px] text-muted-foreground">EPSS {(c.epss * 100).toFixed(1)}%</span>}
                      <SevBadge sev={c.severity} />
                    </div>
                  ))}
                </Section>
              )}

              {content.topThreats?.actors?.length > 0 && (
                <Section title="Active Threat Actors" count={content.topThreats.actors.length}>
                  {content.topThreats.actors.map((a: any) => (
                    <div key={a.id} className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0">
                      <span className="font-semibold">{a.name}</span>
                      <span className="text-[10px] text-muted-foreground">{a.country} · {a.motivation}</span>
                    </div>
                  ))}
                </Section>
              )}

              {content.topThreats?.darkWeb?.length > 0 && (
                <Section title="Critical Dark Web Mentions" count={content.topThreats.darkWeb.length}>
                  {content.topThreats.darkWeb.map((d: any) => (
                    <div key={d.id} className="flex items-center justify-between text-xs py-1 border-b border-border/30 last:border-0">
                      <span className="flex-1 truncate">{d.title}</span>
                      <span className="text-[10px] text-muted-foreground ml-2 font-mono">{d.assetDomain}</span>
                      <SevBadge sev={d.severity} />
                    </div>
                  ))}
                </Section>
              )}

              {content.recentNews?.length > 0 && (
                <Section title="Recent Threat News" count={content.recentNews.length}>
                  {content.recentNews.slice(0, 6).map((n: any) => (
                    <div key={n.id} className="text-xs py-1 border-b border-border/30 last:border-0">
                      <a href={n.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline line-clamp-1">{n.title}</a>
                      <p className="text-[10px] text-muted-foreground mt-0.5">{n.sourceName} · {n.publishedAt ? new Date(n.publishedAt).toLocaleDateString() : ""}</p>
                    </div>
                  ))}
                </Section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function StatItem({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="text-center">
      <p className={cn("text-lg font-bold", color ?? "")}>{value.toLocaleString()}</p>
      <p className="text-[9px] text-muted-foreground">{label}</p>
    </div>
  );
}

function SevBadge({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "text-red-400 border-red-500/20 bg-red-500/10"
    : sev === "high" ? "text-orange-400 border-orange-500/20 bg-orange-500/10"
    : sev === "medium" ? "text-yellow-400 border-yellow-500/20 bg-yellow-500/10"
    : "text-green-400 border-green-500/20 bg-green-500/10";
  return <span className={cn("text-[9px] px-1 py-0.5 rounded border ml-1 shrink-0 capitalize", cls)}>{sev}</span>;
}

function SeveritySection({ label, data }: { label: string; data: Record<string, number> }) {
  const order = ["critical", "high", "medium", "low", "info"];
  const total = Object.values(data).reduce((s, v) => s + v, 0);
  if (total === 0) return null;
  return (
    <div>
      <p className="text-[11px] font-semibold text-muted-foreground mb-2">{label}</p>
      <div className="flex gap-2 flex-wrap">
        {order.filter(s => (data[s] ?? 0) > 0).map(s => <SevBadge key={s} sev={s} />).map((b, i) => {
          const s = order.filter(s => (data[s] ?? 0) > 0)[i]!;
          return (
            <div key={s} className="flex items-center gap-1">
              <SevBadge sev={s} />
              <span className="text-xs font-semibold">{data[s]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Section({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-[11px] font-semibold text-muted-foreground">{title}</p>
        <span className="text-[10px] text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{count}</span>
      </div>
      <div className="bg-muted/20 border border-border/50 rounded-lg px-3 py-2 space-y-0">
        {children}
      </div>
    </div>
  );
}

/* ── Main page ───────────────────────────────────────────────────────────── */
export default function ThreatIntelReportsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [viewingId, setViewingId] = useState<number | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-reports"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/reports`),
    staleTime: 15_000,
    refetchInterval: (q) => {
      const d = q.state.data as any;
      if (!d) return 8_000;
      return d.reports?.some((r: any) => r.status === "generating" || r.status === "pending")
        ? 4_000 : false;
    },
  });

  async function deleteReport(id: number, title: string) {
    if (!confirm(`Delete report "${title}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`${BASE}/api/threat-intel/reports/${id}`, { method: "DELETE" });
      toast({ title: "Report deleted" });
      refetch();
    } catch (e: any) {
      toast({ title: "Delete failed", description: e.message, variant: "destructive" });
    }
  }

  const reports: any[] = data?.reports ?? [];
  const readyCount = reports.filter(r => r.status === "ready").length;
  const generatingCount = reports.filter(r => r.status === "generating").length;

  return (
    <div className="p-6 space-y-4">
      {showNew && <NewReportModal onClose={() => setShowNew(false)} onDone={() => refetch()} />}
      {viewingId && <ReportViewer reportId={viewingId} onClose={() => setViewingId(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileBarChart2 className="w-5 h-5 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Threat Intel Reports</h1>
            <p className="text-xs text-muted-foreground">
              {reports.length} report{reports.length !== 1 ? "s" : ""}
              {readyCount > 0 && ` · ${readyCount} ready`}
              {generatingCount > 0 && ` · ${generatingCount} generating`}
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          {isAdmin && (
            <Button size="sm" onClick={() => setShowNew(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5" />New Report
            </Button>
          )}
        </div>
      </div>

      {/* Info banner when generating */}
      {generatingCount > 0 && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
          <Loader2 className="w-4 h-4 animate-spin shrink-0" />
          <span>Generating report from live threat intelligence data — this takes a few seconds…</span>
        </div>
      )}

      {/* Report list */}
      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : reports.length === 0 ? (
        <div className="text-center py-16 text-sm text-muted-foreground">
          <FileBarChart2 className="w-10 h-10 mx-auto mb-3 opacity-20" />
          <p className="font-medium">No reports yet</p>
          <p className="text-xs mt-1 max-w-xs mx-auto">Generate your first threat intelligence report from real IOC, CVE, threat actor, and dark web data.</p>
          {isAdmin && (
            <Button size="sm" className="mt-4" onClick={() => setShowNew(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5" />Generate First Report
            </Button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {reports.map((r: any) => {
            const sm = STATUS_META[r.status] ?? STATUS_META.pending;
            const meta = r.metadata as any;
            return (
              <div key={r.id}
                className={cn("bg-card border rounded-xl p-4 flex items-center justify-between gap-4 transition-colors",
                  r.status === "ready" ? "hover:border-blue-500/30 cursor-pointer" : "border-border")}
                onClick={() => r.status === "ready" && setViewingId(r.id)}>
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex items-center gap-2">
                    {TYPE_ICONS[r.reportType]}
                    <p className="font-semibold text-sm truncate">{r.title}</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    <span className="bg-muted border border-border rounded px-1.5 py-0.5">{TYPE_LABEL[r.reportType] ?? r.reportType}</span>
                    {r.createdAt && <span className="flex items-center gap-1"><Clock className="w-2.5 h-2.5" />{new Date(r.createdAt).toLocaleString()}</span>}
                    {r.status === "ready" && meta?.stats && (
                      <>
                        {meta.stats.totalIocs != null && <span>{meta.stats.totalIocs} IOCs</span>}
                        {meta.stats.totalCves != null && <span>{meta.stats.totalCves} CVEs</span>}
                        {meta.stats.openFindings != null && <span>{meta.stats.openFindings} open findings</span>}
                        {meta.riskScore != null && <span className="font-semibold text-orange-400">Risk: {meta.riskScore}/100</span>}
                      </>
                    )}
                    {r.status === "failed" && meta?.error && (
                      <span className="text-red-400">{meta.error}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <div className={cn("flex items-center gap-1.5 text-xs font-medium", sm.cls)}>
                    {sm.icon}
                    <span>{sm.label}</span>
                  </div>
                  {r.status === "ready" && (
                    <div className="flex items-center gap-1">
                      <Button size="sm" variant="ghost" className="h-7 px-2 text-[11px]"
                        onClick={e => { e.stopPropagation(); setViewingId(r.id); }}>
                        <Eye className="w-3 h-3 mr-1" />View
                      </Button>
                      <a href={`${BASE}/api/threat-intel/reports/${r.id}/download?format=json`}
                        download onClick={e => e.stopPropagation()}
                        className="inline-flex items-center gap-1 h-7 px-2 text-[11px] rounded-md border border-input bg-background hover:bg-accent text-foreground transition-colors">
                        <Download className="w-3 h-3" />
                      </a>
                    </div>
                  )}
                  {isAdmin && r.status !== "generating" && (
                    <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                      onClick={e => { e.stopPropagation(); deleteReport(r.id, r.title); }}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  )}
                  {r.status === "ready" && <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/40" />}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
