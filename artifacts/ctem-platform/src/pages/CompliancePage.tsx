import { useState, useRef } from "react";
import {
  useListComplianceControls, useUpdateComplianceControl,
  getGetComplianceSummaryQueryKey, getListComplianceControlsQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient, useQuery } from "@tanstack/react-query";
import { Paperclip, Upload, FileText, X, Trash2, Bot, Loader2, Link2, ChevronLeft, ChevronRight, Pencil, Check } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { cn, statusBadgeClass } from "@/lib/utils";
import { getToken } from "@/lib/auth";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PAGE_SIZE = 25;

const FRAMEWORK_COLORS: Record<string, string> = {
  ISO27001: "border-blue-500/40 bg-blue-500/5",
  SOC2: "border-purple-500/40 bg-purple-500/5",
  "PCI-DSS": "border-orange-500/40 bg-orange-500/5",
  HIPAA: "border-green-500/40 bg-green-500/5",
  CIS: "border-yellow-500/40 bg-yellow-500/5",
};

async function uploadEvidence(controlId: number, files: FileList): Promise<void> {
  const form = new FormData();
  for (const f of Array.from(files)) form.append("files", f);
  const token = getToken();
  const res = await fetch(`/api/compliance/controls/${controlId}/evidence`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });
  if (!res.ok) throw new Error(await res.text());
}

async function deleteEvidence(controlId: number, filename: string): Promise<void> {
  const token = getToken();
  const res = await fetch(`/api/compliance/controls/${controlId}/evidence/${encodeURIComponent(filename)}`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(await res.text());
}

function EvidenceFiles({
  evidence,
  controlId,
  onDeleted,
}: {
  evidence: string | null;
  controlId: number;
  onDeleted: () => void;
}) {
  const [deletingIdx, setDeletingIdx] = useState<number | null>(null);
  if (!evidence) return null;
  let files: { name: string; path: string; size: number }[] = [];
  try { files = JSON.parse(evidence); } catch { return null; }
  if (!files.length) return null;

  const handleDelete = async (idx: number, path: string) => {
    setDeletingIdx(idx);
    try {
      await deleteEvidence(controlId, path);
      onDeleted();
    } catch {}
    setDeletingIdx(null);
  };

  return (
    <div className="flex flex-wrap gap-1 mt-1">
      {files.map((f, i) => (
        <span key={i} className="flex items-center gap-1 text-[10px] bg-primary/10 text-primary px-1.5 py-0.5 rounded border border-primary/20 group">
          <FileText className="w-2.5 h-2.5 shrink-0" />
          <a
            href={`/api/compliance/controls/${controlId}/evidence/${encodeURIComponent(f.path)}`}
            download={f.name}
            className="hover:underline truncate max-w-[120px]"
            title={f.name}
          >
            {f.name}
          </a>
          <button
            onClick={() => handleDelete(i, f.path)}
            disabled={deletingIdx === i}
            className="ml-0.5 opacity-0 group-hover:opacity-100 transition-opacity text-destructive hover:text-destructive/80"
            title="Delete evidence"
          >
            {deletingIdx === i ? <X className="w-2.5 h-2.5 animate-spin" /> : <Trash2 className="w-2.5 h-2.5" />}
          </button>
        </span>
      ))}
    </div>
  );
}

function InlineAssignedTo({
  value,
  onSave,
}: {
  value: string | null;
  onSave: (v: string) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value ?? "");
  const [saving, setSaving] = useState(false);

  const commit = async () => {
    setSaving(true);
    try { await onSave(draft.trim()); } finally { setSaving(false); }
    setEditing(false);
  };

  if (editing) {
    return (
      <div className="flex items-center gap-1">
        <input
          autoFocus
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter") commit();
            if (e.key === "Escape") setEditing(false);
          }}
          className="h-6 px-1.5 text-xs border border-primary/40 rounded bg-background text-foreground w-28 focus:outline-none focus:ring-1 focus:ring-primary/50"
          placeholder="Name or email"
        />
        <button onClick={commit} disabled={saving} className="text-green-400 hover:text-green-300 transition-colors">
          {saving ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
        </button>
        <button onClick={() => setEditing(false)} className="text-muted-foreground hover:text-foreground transition-colors">
          <X className="w-3 h-3" />
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => { setDraft(value ?? ""); setEditing(true); }}
      className="group flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
      title="Click to assign"
    >
      <span>{value || "—"}</span>
      <Pencil className="w-2.5 h-2.5 opacity-0 group-hover:opacity-60 transition-opacity" />
    </button>
  );
}

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const [page, setPage] = useState(1);
  const { user } = useAuth();
  const [uploadingId, setUploadingId] = useState<number | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [pendingControlId, setPendingControlId] = useState<number | null>(null);
  const [aiGuidanceControl, setAiGuidanceControl] = useState<any | null>(null);
  const [aiGuidanceText, setAiGuidanceText] = useState<string>("");
  const [aiLoading, setAiLoading] = useState(false);

  const handleAiGuidance = async (control: any) => {
    setAiGuidanceControl(control);
    setAiGuidanceText("");
    setAiLoading(true);
    try {
      const res = await apiFetch<{ guidance: string }>(`${BASE}/api/ai/compliance-guidance`, {
        method: "POST",
        body: JSON.stringify({ controlId: control.controlId, title: control.title, framework: control.frameworkName, status: control.status }),
      });
      setAiGuidanceText(res.guidance ?? "No guidance available.");
    } catch {
      setAiGuidanceText("Failed to fetch AI guidance. Ensure your OpenAI API key is configured.");
    } finally {
      setAiLoading(false);
    }
  };
  const queryClient = useQueryClient();

  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";

  const summaryUrl = `${BASE}/api/compliance/summary${isPrivileged && tenantFilter ? `?tenantId=${tenantFilter}` : ""}`;
  const { data: summary, isLoading: loadingSummary } = useQuery({
    queryKey: [...getGetComplianceSummaryQueryKey(), tenantFilter],
    queryFn: () => apiFetch(summaryUrl),
  });

  const controlParams = {
    frameworkId: selectedFramework ?? undefined,
    status: statusFilter || undefined,
    ...(isPrivileged && tenantFilter ? { tenantId: tenantFilter } : {}),
  };
  const { data: controls, isLoading: loadingControls } = useListComplianceControls(controlParams as any, {
    query: { queryKey: getListComplianceControlsQueryKey(controlParams as any) },
  });
  const updateControl = useUpdateComplianceControl();

  // Fetch ALL assets (not just verified) so assigned assets always appear in the dropdown.
  // Verified assets are marked with a ✓ suffix so users still know their status.
  const { data: allAssetsData } = useQuery({
    queryKey: ["compliance-all-assets"],
    queryFn: () => apiFetch<{ id: number; name: string; domain: string | null; type: string; verificationStatus: string }[]>(
      `${BASE}/api/assets`
    ),
  });
  const allAssets = (allAssetsData as any[]) ?? [];

  const handleStatusChange = async (controlId: number, status: string) => {
    await updateControl.mutateAsync({ controlId, data: { status } });
    queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() });
    queryClient.invalidateQueries({ queryKey: getGetComplianceSummaryQueryKey() });
  };

  const handleAssetAssign = async (controlId: number, assetId: number | null) => {
    await apiFetch(`${BASE}/api/compliance/controls/${controlId}`, {
      method: "PATCH",
      body: JSON.stringify({ targetAssetId: assetId }),
    });
    queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() });
  };

  const handleAssignedToSave = async (controlId: number, assignedTo: string) => {
    await apiFetch(`${BASE}/api/compliance/controls/${controlId}`, {
      method: "PATCH",
      body: JSON.stringify({ assignedTo: assignedTo || null }),
    });
    queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() });
  };

  const handleUploadClick = (controlId: number) => {
    setPendingControlId(controlId);
    fileInputRef.current?.click();
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || !files.length || !pendingControlId) return;
    setUploadingId(pendingControlId);
    try {
      await uploadEvidence(pendingControlId, files);
      queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() });
    } catch (err) {
      console.error("Evidence upload failed:", err);
    } finally {
      setUploadingId(null);
      setPendingControlId(null);
      e.target.value = "";
    }
  };

  const frameworks = summary as any[] ?? [];
  const allControls = (controls as any[] ?? []);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(allControls.length / PAGE_SIZE));
  const safePageIndex = Math.min(page, totalPages);
  const displayControls = allControls.slice((safePageIndex - 1) * PAGE_SIZE, safePageIndex * PAGE_SIZE);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold">Compliance Management</h1>
          <p className="text-sm text-muted-foreground">Track compliance across security frameworks</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {isPrivileged && <TenantFilter value={tenantFilter} onChange={setTenantFilter} />}
        </div>
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".pdf,.png,.jpg,.jpeg,.doc,.docx,.txt,.csv"
        className="hidden"
        onChange={handleFileChange}
      />

      {/* Framework Cards */}
      {loadingSummary ? (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {frameworks.map((fw: any) => (
            <button
              key={fw.frameworkId}
              onClick={() => {
                setSelectedFramework(selectedFramework === fw.frameworkId ? null : fw.frameworkId);
                setPage(1);
              }}
              className={cn(
                "text-left bg-card rounded-xl p-4 border transition-all",
                FRAMEWORK_COLORS[fw.shortName] ?? "border-border",
                selectedFramework === fw.frameworkId ? "ring-1 ring-primary" : "hover:border-border"
              )}
            >
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="text-sm font-semibold">{fw.shortName}</p>
                  <p className="text-xs text-muted-foreground">{fw.frameworkName}</p>
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold tabular-nums">{fw.score}%</p>
                  <p className="text-[10px] text-muted-foreground">compliance</p>
                </div>
              </div>
              <Progress value={fw.score} className="h-1.5 mb-2" />
              <div className="flex gap-3 text-xs">
                <span className="text-green-400">{fw.compliant} compliant</span>
                <span className="text-yellow-400">{fw.inProgress} in progress</span>
                <span className="text-red-400">{fw.nonCompliant} gaps</span>
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Controls Table */}
      <div>
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <h2 className="text-sm font-medium">
            {selectedFramework
              ? `Controls — ${frameworks.find((f: any) => f.frameworkId === selectedFramework)?.frameworkName ?? ""}`
              : "All Controls"}
            {allControls.length > 0 && (
              <span className="ml-2 text-xs text-muted-foreground font-normal">({allControls.length} total)</span>
            )}
          </h2>
          <div className="flex gap-2 items-center">
            <Select
              value={statusFilter || "_all_"}
              onValueChange={(v) => { setStatusFilter(v === "_all_" ? "" : v); setPage(1); }}
            >
              <SelectTrigger className="w-36 h-7 text-xs">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="_all_">All</SelectItem>
                <SelectItem value="compliant">Compliant</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                <SelectItem value="not_applicable">N/A</SelectItem>
              </SelectContent>
            </Select>
            {selectedFramework && (
              <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => { setSelectedFramework(null); setPage(1); }}>
                Clear
              </Button>
            )}
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Control ID</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Framework</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">
                  Asset Scope
                  <span className="ml-1 text-[10px] text-muted-foreground/60 font-normal">(✓ = verified)</span>
                </th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">
                  Assigned To
                  <span className="ml-1 text-[10px] text-muted-foreground/60 font-normal">(click to edit)</span>
                </th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {loadingControls && [...Array(8)].map((_, i) => (
                <tr key={i} className="border-b border-border/50">
                  {[...Array(7)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
                </tr>
              ))}
              {!loadingControls && displayControls.map((c: any) => (
                <tr key={c.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-2.5 text-xs font-mono font-medium text-primary">{c.controlId}</td>
                  <td className="px-4 py-2.5 text-xs max-w-xs">
                    <p className="font-medium">{c.title}</p>
                    <EvidenceFiles
                      evidence={c.evidence}
                      controlId={c.id}
                      onDeleted={() => queryClient.invalidateQueries({ queryKey: getListComplianceControlsQueryKey() })}
                    />
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{c.frameworkName}</td>

                  {/* Asset Scope — assign to any asset; verified ones marked with ✓ */}
                  <td className="px-4 py-2.5 text-xs">
                    <select
                      value={c.targetAssetId ?? ""}
                      onChange={e => handleAssetAssign(c.id, e.target.value ? Number(e.target.value) : null)}
                      className="h-6 px-2 text-xs border border-border rounded bg-background text-foreground appearance-none cursor-pointer hover:border-primary/40 transition-colors max-w-[160px]"
                      title="Assign to an asset"
                    >
                      <option value="">— unscoped —</option>
                      {allAssets.map((a: any) => (
                        <option key={a.id} value={a.id}>
                          {a.name || a.domain || `Asset #${a.id}`}
                          {a.verificationStatus === "verified" ? " ✓" : ""}
                        </option>
                      ))}
                    </select>
                    {c.targetAssetName && (
                      <p className="text-[10px] text-primary/70 mt-0.5 flex items-center gap-1">
                        <Link2 className="w-2.5 h-2.5" />{c.targetAssetName}
                      </p>
                    )}
                  </td>

                  {/* Assigned To — inline editable; click the name or "—" to edit */}
                  <td className="px-4 py-2.5 text-xs">
                    <InlineAssignedTo
                      value={c.assignedTo}
                      onSave={(v) => handleAssignedToSave(c.id, v)}
                    />
                  </td>

                  <td className="px-4 py-2.5">
                    <Select value={c.status} onValueChange={(v) => handleStatusChange(c.id, v)}>
                      <SelectTrigger className={cn("h-6 text-xs border-0 px-2 py-0 w-32", statusBadgeClass(c.status))}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="compliant">Compliant</SelectItem>
                        <SelectItem value="in_progress">In Progress</SelectItem>
                        <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                        <SelectItem value="not_applicable">N/A</SelectItem>
                      </SelectContent>
                    </Select>
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs gap-1 text-muted-foreground hover:text-foreground"
                        disabled={uploadingId === c.id}
                        onClick={() => handleUploadClick(c.id)}
                      >
                        {uploadingId === c.id
                          ? <><Upload className="w-3 h-3 animate-pulse" /> Uploading…</>
                          : <><Paperclip className="w-3 h-3" /> Attach</>
                        }
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 text-xs gap-1 text-primary/70 hover:text-primary"
                        onClick={() => handleAiGuidance(c)}
                      >
                        <Bot className="w-3 h-3" /> AI
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
              {!loadingControls && allControls.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-sm text-muted-foreground">No controls found.</td>
                </tr>
              )}
            </tbody>
          </table>

          {/* Pagination footer */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-card/50">
              <p className="text-xs text-muted-foreground">
                Showing {((safePageIndex - 1) * PAGE_SIZE) + 1}–{Math.min(safePageIndex * PAGE_SIZE, allControls.length)} of {allControls.length} controls
              </p>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 w-6 p-0"
                  disabled={safePageIndex <= 1}
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                >
                  <ChevronLeft className="w-3 h-3" />
                </Button>
                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .filter(p => p === 1 || p === totalPages || Math.abs(p - safePageIndex) <= 2)
                  .reduce<(number | "…")[]>((acc, p, i, arr) => {
                    if (i > 0 && p - (arr[i - 1] as number) > 1) acc.push("…");
                    acc.push(p);
                    return acc;
                  }, [])
                  .map((p, i) =>
                    p === "…"
                      ? <span key={`ellipsis-${i}`} className="w-6 text-center text-xs text-muted-foreground">…</span>
                      : (
                        <Button
                          key={p}
                          variant={p === safePageIndex ? "default" : "outline"}
                          size="sm"
                          className="h-6 w-6 p-0 text-xs"
                          onClick={() => setPage(p as number)}
                        >
                          {p}
                        </Button>
                      )
                  )}
                <Button
                  variant="outline"
                  size="sm"
                  className="h-6 w-6 p-0"
                  disabled={safePageIndex >= totalPages}
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                >
                  <ChevronRight className="w-3 h-3" />
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>

      <Dialog open={!!aiGuidanceControl} onOpenChange={open => { if (!open) { setAiGuidanceControl(null); setAiGuidanceText(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-primary" />
              AI Guidance — {aiGuidanceControl?.controlId}
            </DialogTitle>
          </DialogHeader>
          <p className="text-xs text-muted-foreground mb-3">
            <span className="font-semibold text-foreground">{aiGuidanceControl?.title}</span>
            {aiGuidanceControl?.frameworkName && ` · ${aiGuidanceControl.frameworkName}`}
          </p>
          {aiLoading
            ? <div className="flex items-center gap-2 text-sm text-muted-foreground py-4"><Loader2 className="w-4 h-4 animate-spin" /> Fetching guidance…</div>
            : <p className="text-sm leading-relaxed whitespace-pre-wrap">{aiGuidanceText}</p>
          }
        </DialogContent>
      </Dialog>
    </div>
  );
}
