import { useState } from "react";
import {
  useListReports, useCreateReport, useDeleteReport,
  getListReportsQueryKey,
} from "@workspace/api-client-react";
import { useListAssets } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Download, Trash2, FileText, Loader2, CheckCircle2, AlertCircle, ChevronRight, ChevronLeft, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";
import { downloadReportPdf, downloadSelectedAssetsPdf } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";

const REPORT_TYPES = ["executive", "technical", "compliance", "asset_inventory"];
const FORMATS = ["pdf", "csv", "json"];
const PAGE_SIZE = 10;

function StatusIcon({ status }: { status: string }) {
  if (status === "ready") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (status === "generating" || status === "pending") return <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />;
  if (status === "failed") return <AlertCircle className="w-4 h-4 text-red-400" />;
  return <FileText className="w-4 h-4 text-muted-foreground" />;
}

function riskBadgeClass(level: string) {
  switch ((level ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border border-orange-500/30";
    case "medium":   return "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30";
    case "low":      return "bg-green-500/15 text-green-400 border border-green-500/30";
    default:         return "bg-muted text-muted-foreground border border-border";
  }
}

async function downloadReportData(report: any) {
  const token = getToken();
  const res = await fetch(`/api/reports/${report.id}/download`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) return;
  const blob = await res.blob();
  const ext = report.format === "json" ? "json" : "csv";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const safeName = report.title.replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  a.download = `${safeName}_${report.type}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [step, setStep]             = useState<1 | 2>(1);
  const [form, setForm]             = useState({ title: "", type: "executive", format: "pdf" });
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [assetSearch, setAssetSearch] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [page, setPage] = useState(1);
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const { user } = useAuth();
  const queryClient = useQueryClient();

  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";
  const { data: reports, isLoading } = useListReports({
    query: {
      queryKey: [getListReportsQueryKey(), tenantFilter],
      queryFn: async () => {
        const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
        const { apiFetch } = await import("@/lib/apiFetch");
        const url = isPrivileged && tenantFilter
          ? `${BASE}/api/reports?tenantId=${tenantFilter}`
          : `${BASE}/api/reports`;
        return apiFetch<any[]>(url);
      },
    },
  });
  const { data: assetsData } = useListAssets();
  const assets: any[] = (assetsData as any[]) ?? [];

  const filteredAssets = assetSearch.trim()
    ? assets.filter(a =>
        a.name.toLowerCase().includes(assetSearch.toLowerCase()) ||
        a.value?.toLowerCase().includes(assetSearch.toLowerCase()) ||
        a.type?.toLowerCase().includes(assetSearch.toLowerCase()),
      )
    : assets;

  const createReport = useCreateReport();
  const deleteReport = useDeleteReport();

  const allReports = (reports as any[]) ?? [];
  const totalPages = Math.max(1, Math.ceil(allReports.length / PAGE_SIZE));
  const paginated  = allReports.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  function openCreate() {
    setStep(1);
    setForm({ title: "", type: "executive", format: "pdf" });
    setSelectedIds(new Set());
    setAssetSearch("");
    setShowCreate(true);
  }

  function closeCreate() {
    setShowCreate(false);
    setTimeout(() => { setStep(1); setSelectedIds(new Set()); setAssetSearch(""); }, 200);
  }

  const handleStep1 = (e: React.FormEvent) => {
    e.preventDefault();
    if (form.format === "pdf") {
      // For PDF: go to asset selection step
      setSelectedIds(new Set()); // clear previous
      setStep(2);
    } else {
      // For CSV/JSON: create DB record as before
      handleCreateNonPdf();
    }
  };

  const handleCreateNonPdf = async () => {
    const body: any = { ...form };
    if (isPrivileged && tenantFilter) body.targetTenantId = tenantFilter;
    await createReport.mutateAsync({ data: body } as any);
    queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
    closeCreate();
    setTimeout(() => queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() }), 4000);
  };

  const handleDownloadPdf = async () => {
    if (selectedIds.size === 0) return;
    setDownloading(true);
    try {
      await createReport.mutateAsync({
        data: { title: form.title || "Asset Security Report", type: form.type as any, format: "pdf" as any },
      } as any);
      queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
      await downloadSelectedAssetsPdf(
        form.title || "Asset Security Report",
        form.type,
        Array.from(selectedIds),
        getToken(),
      );
      closeCreate();
    } catch {
      // silently handle
    } finally {
      setDownloading(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this report?")) return;
    await deleteReport.mutateAsync({ reportId: id });
    queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
  };

  const handleDownload = async (r: any) => {
    if (r.format === "pdf") {
      await downloadReportPdf(r.id, getToken());
    } else {
      await downloadReportData(r);
    }
  };

  const toggleAsset = (id: number) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedIds.size === filteredAssets.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredAssets.map((a: any) => a.id)));
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Reports</h1>
          <p className="text-sm text-muted-foreground">Generate and download security reports</p>
        </div>
        <div className="flex items-center gap-2">
          {isPrivileged && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); setPage(1); }} />}
          <Button size="sm" onClick={openCreate}>
            <Plus className="w-4 h-4 mr-1.5" /> Generate Report
          </Button>
        </div>
      </div>

      <div className="grid gap-3">
        {isLoading && [...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        {!isLoading && paginated.map((r: any) => (
          <div key={r.id} className="bg-card border border-border rounded-xl p-4 flex items-center gap-4">
            <StatusIcon status={r.status} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium">{r.title}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <span className="text-xs text-muted-foreground capitalize">{r.type} report</span>
                <span className="text-muted-foreground/30">•</span>
                <span className="text-xs text-muted-foreground uppercase">{r.format}</span>
                {r.generatedAt && (
                  <>
                    <span className="text-muted-foreground/30">•</span>
                    <span className="text-xs text-muted-foreground">{formatDateTime(r.generatedAt)}</span>
                  </>
                )}
              </div>
            </div>
            <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(r.status))}>{r.status}</span>
            <div className="flex gap-1">
              {r.status === "ready" && (
                <Button variant="outline" size="sm" className="h-7 text-xs gap-1" onClick={() => handleDownload(r)}>
                  <Download className="w-3 h-3" />
                  {r.format === "pdf" ? "PDF" : r.format === "json" ? "JSON" : "CSV"}
                </Button>
              )}
              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(r.id)}>
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        ))}
        {!isLoading && allReports.length === 0 && (
          <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
            No reports generated yet.
          </div>
        )}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-1">
          <p className="text-xs text-muted-foreground">
            Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, allReports.length)} of {allReports.length} reports
          </p>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="outline" className="h-7 w-7 p-0" disabled={page === 1} onClick={() => setPage(p => p - 1)}>‹</Button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
              <Button key={p} size="sm" variant={p === page ? "default" : "outline"} className="h-7 w-7 p-0 text-xs" onClick={() => setPage(p)}>{p}</Button>
            ))}
            <Button size="sm" variant="outline" className="h-7 w-7 p-0" disabled={page === totalPages} onClick={() => setPage(p => p + 1)}>›</Button>
          </div>
        </div>
      )}

      {/* ── Create Report Dialog ── */}
      <Dialog open={showCreate} onOpenChange={v => { if (!v) closeCreate(); }}>
        <DialogContent className={step === 2 ? "max-w-2xl" : undefined}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              {step === 2 && (
                <button onClick={() => setStep(1)} className="text-muted-foreground hover:text-foreground transition-colors">
                  <ChevronLeft className="w-4 h-4" />
                </button>
              )}
              {step === 1 ? "Generate Report" : "Select Assets"}
              <span className="ml-auto text-xs font-normal text-muted-foreground">Step {step} of 2</span>
            </DialogTitle>
          </DialogHeader>

          {/* ── Step 1: Report details ── */}
          {step === 1 && (
            <form onSubmit={handleStep1} className="space-y-3 mt-2">
              <div className="space-y-1.5">
                <Label className="text-xs">Report Title</Label>
                <Input
                  value={form.title}
                  onChange={e => setForm(p => ({ ...p, title: e.target.value }))}
                  placeholder="e.g. Q2 2025 Executive Security Report"
                  required
                  className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Report Type</Label>
                <Select value={form.type} onValueChange={v => setForm(p => ({ ...p, type: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {REPORT_TYPES.map(t => <SelectItem key={t} value={t}>{capitalize(t)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Format</Label>
                <Select value={form.format} onValueChange={v => setForm(p => ({ ...p, format: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {FORMATS.map(f => <SelectItem key={f} value={f}>{f.toUpperCase()}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              {form.format === "pdf" && (
                <p className="text-xs text-muted-foreground bg-muted/40 rounded-lg px-3 py-2 border border-border">
                  You'll choose which assets to include in the next step. The PDF will contain all findings and brand threat data for the selected assets.
                </p>
              )}
              <DialogFooter className="mt-4">
                <Button variant="outline" type="button" onClick={closeCreate}>Cancel</Button>
                <Button type="submit" disabled={createReport.isPending}>
                  {form.format === "pdf"
                    ? <><span>Next</span><ChevronRight className="w-3.5 h-3.5 ml-1" /></>
                    : createReport.isPending ? "Creating…" : "Generate"
                  }
                </Button>
              </DialogFooter>
            </form>
          )}

          {/* ── Step 2: Asset selection ── */}
          {step === 2 && (
            <div className="space-y-3 mt-2">
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <Input
                    value={assetSearch}
                    onChange={e => setAssetSearch(e.target.value)}
                    placeholder="Search assets…"
                    className="h-8 pl-8 text-xs"
                  />
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  className="h-8 text-xs shrink-0"
                  onClick={toggleAll}
                >
                  {selectedIds.size === filteredAssets.length && filteredAssets.length > 0
                    ? "Deselect All"
                    : "Select All"}
                </Button>
              </div>

              <p className="text-xs text-muted-foreground">
                {selectedIds.size === 0
                  ? "Select at least one asset to generate the PDF."
                  : `${selectedIds.size} asset${selectedIds.size > 1 ? "s" : ""} selected`}
              </p>

              <div className="border border-border rounded-xl overflow-hidden divide-y divide-border max-h-[360px] overflow-y-auto">
                {filteredAssets.length === 0 && (
                  <div className="p-6 text-center text-sm text-muted-foreground">No assets found.</div>
                )}
                {filteredAssets.map((a: any) => {
                  const isSelected = selectedIds.has(a.id);
                  const risk = a.riskLevel ?? "unknown";
                  return (
                    <button
                      key={a.id}
                      type="button"
                      onClick={() => toggleAsset(a.id)}
                      className={cn(
                        "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors",
                        isSelected ? "bg-blue-500/8" : "hover:bg-muted/40",
                      )}
                    >
                      {/* Checkbox */}
                      <div className={cn(
                        "w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors",
                        isSelected ? "bg-blue-500 border-blue-500" : "border-border",
                      )}>
                        {isSelected && (
                          <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 10 8" fill="none">
                            <path d="M1 4L3.5 6.5L9 1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        )}
                      </div>
                      {/* Info */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{a.name}</p>
                        <p className="text-xs text-muted-foreground truncate">{a.value} · {a.type}</p>
                      </div>
                      {/* Risk badge */}
                      <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0 capitalize", riskBadgeClass(risk))}>
                        {risk}
                      </span>
                    </button>
                  );
                })}
              </div>

              <DialogFooter className="mt-2">
                <Button variant="outline" type="button" onClick={() => setStep(1)}>
                  <ChevronLeft className="w-3.5 h-3.5 mr-1" /> Back
                </Button>
                <Button
                  onClick={handleDownloadPdf}
                  disabled={selectedIds.size === 0 || downloading}
                  className="gap-1.5"
                >
                  {downloading
                    ? <><Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating PDF…</>
                    : <><Download className="w-3.5 h-3.5" /> Download PDF ({selectedIds.size})</>
                  }
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
