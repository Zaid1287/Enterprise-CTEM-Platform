import { useState } from "react";
import {
  useListReports, useCreateReport, useDeleteReport,
  getListReportsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Download, Trash2, FileText, Loader2, CheckCircle2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, statusBadgeClass, capitalize, formatDateTime } from "@/lib/utils";

const REPORT_TYPES = ["executive", "technical", "compliance", "asset_inventory"];
const FORMATS = ["pdf", "xlsx", "csv", "json"];

function StatusIcon({ status }: { status: string }) {
  if (status === "ready") return <CheckCircle2 className="w-4 h-4 text-green-400" />;
  if (status === "generating" || status === "pending") return <Loader2 className="w-4 h-4 text-yellow-400 animate-spin" />;
  if (status === "failed") return <AlertCircle className="w-4 h-4 text-red-400" />;
  return <FileText className="w-4 h-4 text-muted-foreground" />;
}

export default function ReportsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ title: "", type: "executive", format: "pdf" });
  const queryClient = useQueryClient();

  const { data: reports, isLoading } = useListReports({
    query: { queryKey: getListReportsQueryKey() },
  });
  const createReport = useCreateReport();
  const deleteReport = useDeleteReport();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await createReport.mutateAsync({ data: form } as any);
    queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
    setShowCreate(false);
    setForm({ title: "", type: "executive", format: "pdf" });
    // Refresh after a few seconds to pick up the ready status
    setTimeout(() => queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() }), 4000);
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this report?")) return;
    await deleteReport.mutateAsync({ reportId: id });
    queryClient.invalidateQueries({ queryKey: getListReportsQueryKey() });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Reports</h1>
          <p className="text-sm text-muted-foreground">Generate and download security reports</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> Generate Report
        </Button>
      </div>

      <div className="grid gap-3">
        {isLoading && [...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        {!isLoading && (reports as any[] ?? []).map((r: any) => (
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
              {r.status === "ready" && r.downloadUrl && (
                <Button variant="outline" size="sm" className="h-7 text-xs gap-1" onClick={() => alert("Download would begin here")}>
                  <Download className="w-3 h-3" /> Download
                </Button>
              )}
              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(r.id)}>
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>
        ))}
        {!isLoading && (reports as any[] ?? []).length === 0 && (
          <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
            No reports generated yet.
          </div>
        )}
      </div>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Generate Report</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Report Title</Label>
              <Input value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} placeholder="Q2 2025 Executive Security Report" required className="h-9" />
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
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createReport.isPending}>{createReport.isPending ? "Creating..." : "Generate"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
