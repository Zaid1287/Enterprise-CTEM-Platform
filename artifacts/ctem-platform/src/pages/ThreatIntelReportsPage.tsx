import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FileBarChart2, Plus, Loader2, X, RefreshCw, Clock, CheckCircle2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const STATUS_META: Record<string, { icon: React.ReactNode; cls: string }> = {
  ready:       { icon: <CheckCircle2 className="w-3.5 h-3.5" />, cls: "text-green-400" },
  generating:  { icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />, cls: "text-blue-400" },
  failed:      { icon: <AlertCircle className="w-3.5 h-3.5" />, cls: "text-red-400" },
  pending:     { icon: <Clock className="w-3.5 h-3.5" />, cls: "text-muted-foreground" },
};

const TYPE_LABEL: Record<string, string> = {
  summary:       "Executive Summary",
  ioc:           "IOC Report",
  actor:         "Threat Actor Report",
  vulnerability: "Vulnerability Intel",
  custom:        "Custom Report",
};

function NewReportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [title, setTitle] = useState("");
  const [reportType, setReportType] = useState("summary");
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault(); setLoading(true); setErr("");
    try {
      await apiFetch(`${BASE}/api/threat-intel/reports`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title, reportType }) });
      toast({ title: "Report queued" }); onDone(); onClose();
    } catch (e: any) { setErr(e.message ?? "Error"); } finally { setLoading(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2"><FileBarChart2 className="w-4 h-4 text-blue-400" />Generate TI Report</h2>
          <button onClick={onClose}><X className="w-4 h-4 text-muted-foreground" /></button>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Report Title *</label>
            <Input value={title} onChange={e => setTitle(e.target.value)} placeholder="Q3 2026 Threat Intelligence Summary" className="h-8 text-xs" required />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Report Type</label>
            <Select value={reportType} onValueChange={setReportType}>
              <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>{Object.entries(TYPE_LABEL).map(([v, l]) => <SelectItem key={v} value={v}>{l}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">{loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Generate"}</Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ThreatIntelReportsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-reports"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/reports`),
    staleTime: 30_000,
    refetchInterval: (q) => {
      const d = q.state.data as any;
      if (!d) return 15_000;
      const hasGenerating = d.reports?.some((r: any) => r.status === "generating" || r.status === "pending");
      return hasGenerating ? 8_000 : false;
    },
  });

  const reports: any[] = data?.reports ?? [];

  return (
    <div className="p-6 space-y-4">
      {showNew && <NewReportModal onClose={() => setShowNew(false)} onDone={() => refetch()} />}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileBarChart2 className="w-5 h-5 text-blue-400" />
          <div><h1 className="text-xl font-bold">Threat Intel Reports</h1><p className="text-xs text-muted-foreground">{reports.length} reports generated</p></div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {isAdmin && <Button size="sm" onClick={() => setShowNew(true)}><Plus className="w-3.5 h-3.5 mr-1" />New Report</Button>}
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-3">{Array.from({length:4}).map((_,i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>
      ) : reports.length === 0 ? (
        <div className="text-center py-16 text-sm text-muted-foreground">
          <FileBarChart2 className="w-8 h-8 mx-auto mb-3 opacity-30" />
          <p>No reports yet. Generate your first threat intelligence report.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {reports.map((r: any) => {
            const sm = STATUS_META[r.status] ?? STATUS_META.pending;
            return (
              <div key={r.id} className="bg-card border border-border rounded-xl p-4 flex items-center justify-between gap-4 hover:border-blue-500/30 transition-colors">
                <div className="min-w-0 space-y-1">
                  <p className="font-semibold text-sm truncate">{r.title}</p>
                  <div className="flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                    <span className="bg-muted border border-border rounded px-1.5 py-0.5">{TYPE_LABEL[r.reportType] ?? r.reportType}</span>
                    {r.createdAt && <span>{new Date(r.createdAt).toLocaleDateString()}</span>}
                  </div>
                </div>
                <div className={cn("flex items-center gap-1.5 text-xs font-medium shrink-0", sm.cls)}>
                  {sm.icon}
                  <span className="capitalize">{r.status}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
