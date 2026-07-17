import { useState, useMemo, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  ShieldCheck, CheckCircle2, XCircle, Clock, MinusCircle,
  ChevronRight, ChevronDown, Upload, Download, Trash2, Plus, Search,
  FileText, ToggleLeft, ToggleRight, Pencil, X,
  RefreshCw, Loader2, Info, BookOpen, Server, Building2,
} from "lucide-react";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

// ── Types ────────────────────────────────────────────────────────────────────
interface Framework {
  id: number;
  name: string;
  shortName: string;
  version: string;
  description: string | null;
  totalControls: number;
}

interface ControlAnswer {
  globalControlId: number;
  controlId: string;
  title: string;
  description: string | null;
  category: string | null;
  guidance: string | null;
  isEnabled: boolean;
  sortOrder: number;
  frameworkId: number;
  frameworkName: string | null;
  frameworkShortName: string | null;
  answerId: number | null;
  status: "non_compliant" | "in_progress" | "compliant" | "not_applicable";
  evidence: string | null;
  notes: string | null;
  assignedTo: string | null;
  dueDate: string | null;
  reviewedAt: string | null;
  updatedAt: string | null;
}

interface FrameworkSummary {
  frameworkId: number;
  frameworkName: string;
  shortName: string;
  version: string;
  description: string | null;
  total: number;
  compliant: number;
  inProgress: number;
  nonCompliant: number;
  notApplicable: number;
  score: number;
}

interface GlobalControl {
  id: number;
  frameworkId: number;
  controlId: string;
  title: string;
  description: string | null;
  category: string | null;
  guidance: string | null;
  isEnabled: boolean;
  sortOrder: number;
  frameworkName: string | null;
  frameworkShortName: string | null;
}

interface Asset {
  id: number;
  name: string;
  domain: string | null;
  type: string;
  riskLevel: string | null;
}

interface TenantAssignment {
  tenantId: number;
  tenantName: string;
  isEnabled: boolean;
  enabledAt: string | null;
}

// ── Helpers ──────────────────────────────────────────────────────────────────
const STATUS_CONFIG = {
  compliant:      { label: "Compliant",     color: "text-green-400",  bg: "bg-green-500/15 border-green-500/30",   icon: CheckCircle2 },
  in_progress:    { label: "In Progress",   color: "text-yellow-400", bg: "bg-yellow-500/15 border-yellow-500/30", icon: Clock        },
  non_compliant:  { label: "Non-Compliant", color: "text-red-400",    bg: "bg-red-500/15 border-red-500/30",       icon: XCircle      },
  not_applicable: { label: "N/A",           color: "text-slate-400",  bg: "bg-slate-500/15 border-slate-500/30",   icon: MinusCircle  },
} as const;
type StatusKey = keyof typeof STATUS_CONFIG;

const FRAMEWORK_COLORS: Record<string, string> = {
  "ISO27001": "text-blue-400 bg-blue-500/10 border-blue-500/30",
  "SOC2":     "text-purple-400 bg-purple-500/10 border-purple-500/30",
  "PCI-DSS":  "text-orange-400 bg-orange-500/10 border-orange-500/30",
  "HIPAA":    "text-pink-400 bg-pink-500/10 border-pink-500/30",
  "CIS":      "text-cyan-400 bg-cyan-500/10 border-cyan-500/30",
  "NIST-CSF": "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  "CUSTOM":   "text-slate-400 bg-slate-500/10 border-slate-500/30",
};
function fwColor(sn: string | null | undefined) {
  return FRAMEWORK_COLORS[sn ?? ""] ?? "text-slate-400 bg-slate-500/10 border-slate-500/30";
}

function parseEvidence(raw: string | null): { name: string; path: string; size: number; uploadedAt: string }[] {
  if (!raw) return [];
  try { return JSON.parse(raw); } catch { return []; }
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score, size = 56 }: { score: number; size?: number }) {
  const r = size / 2 - 6;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 70 ? "#22c55e" : score >= 40 ? "#eab308" : "#ef4444";
  return (
    <svg width={size} height={size}>
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="currentColor" strokeWidth={5} className="text-muted/20" />
      <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={color} strokeWidth={5}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transform: "rotate(-90deg)", transformOrigin: "center", transition: "stroke-dashoffset 0.5s ease" }} />
      <text x="50%" y="50%" dominantBaseline="middle" textAnchor="middle"
        style={{ fill: color, fontSize: size < 50 ? 10 : 13, fontWeight: 600 }}>
        {score}%
      </text>
    </svg>
  );
}

// ── Framework Card ────────────────────────────────────────────────────────────
function FrameworkCard({ fw, isSelected, onClick }: { fw: FrameworkSummary; isSelected: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className={cn(
      "w-full text-left bg-card border rounded-xl p-4 transition-all hover:border-primary/40",
      isSelected ? "border-primary/60 bg-primary/5" : "border-border",
    )}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex-1 min-w-0">
          <Badge className={cn("text-xs border font-mono mb-1", fwColor(fw.shortName))}>{fw.shortName}</Badge>
          <p className="text-sm font-semibold truncate">{fw.frameworkName}</p>
          <p className="text-xs text-muted-foreground">v{fw.version}</p>
        </div>
        <ScoreRing score={fw.score} size={52} />
      </div>
      <div className="grid grid-cols-4 gap-1">
        {([
          ["Compliant", fw.compliant, "text-green-400"],
          ["In Progress", fw.inProgress, "text-yellow-400"],
          ["Non-Compliant", fw.nonCompliant, "text-red-400"],
          ["N/A", fw.notApplicable, "text-slate-400"],
        ] as [string, number, string][]).map(([label, val, cls]) => (
          <div key={label} className="bg-muted/30 rounded px-1.5 py-1.5 text-center">
            <p className={cn("text-sm font-bold", cls)}>{val}</p>
            <p className="text-[9px] text-muted-foreground leading-tight">{label}</p>
          </div>
        ))}
      </div>
    </button>
  );
}

// ── Control Edit Drawer ───────────────────────────────────────────────────────
function ControlEditDrawer({ control, frameworkId, onClose }: { control: ControlAnswer; frameworkId: number; onClose: () => void }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [status, setStatus] = useState<StatusKey>(control.status);
  const [notes, setNotes] = useState(control.notes ?? "");
  const [assignedTo, setAssignedTo] = useState(control.assignedTo ?? "");
  const [dueDate, setDueDate] = useState(control.dueDate ?? "");
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const evidenceFiles = parseEvidence(control.evidence);

  const save = useMutation({
    mutationFn: () => apiFetch(`${BASE}/api/compliance/answers/${control.globalControlId}`, {
      method: "PUT",
      body: JSON.stringify({ status, notes, assignedTo, dueDate }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["compliance-answers", frameworkId] });
      qc.invalidateQueries({ queryKey: ["compliance-summary"] });
      toast({ title: "Control updated" });
      onClose();
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const delEvidence = useMutation({
    mutationFn: (filename: string) =>
      apiFetch(`${BASE}/api/compliance/answers/${control.globalControlId}/evidence/${filename}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-answers", frameworkId] }),
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  async function uploadFiles(files: FileList) {
    setUploading(true);
    const fd = new FormData();
    Array.from(files).forEach(f => fd.append("files", f));
    try {
      await apiFetch(`${BASE}/api/compliance/answers/${control.globalControlId}/evidence`, { method: "POST", body: fd });
      qc.invalidateQueries({ queryKey: ["compliance-answers", frameworkId] });
      toast({ title: "Evidence uploaded" });
    } catch (e: any) {
      toast({ title: "Upload failed", description: e.message, variant: "destructive" });
    } finally { setUploading(false); }
  }

  return (
    <div className="fixed inset-0 z-50 flex">
      <div className="flex-1 bg-black/50" onClick={onClose} />
      <div className="w-[520px] bg-background border-l border-border flex flex-col h-full overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <div className="flex items-center gap-2">
              <Badge className={cn("text-xs border font-mono", fwColor(control.frameworkShortName))}>
                {control.frameworkShortName}
              </Badge>
              <span className="text-xs text-muted-foreground font-mono">{control.controlId}</span>
            </div>
            <h2 className="text-sm font-semibold mt-1">{control.title}</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {control.description && (
            <div className="bg-muted/30 rounded-lg p-3 text-xs text-muted-foreground">
              <p className="font-medium text-foreground/80 mb-1">Description</p>
              <p className="leading-relaxed">{control.description}</p>
            </div>
          )}
          {control.guidance && (
            <div className="bg-primary/5 border border-primary/20 rounded-lg p-3 text-xs">
              <p className="font-medium text-primary/80 mb-1 flex items-center gap-1">
                <Info className="w-3 h-3" />Guidance
              </p>
              <p className="text-muted-foreground leading-relaxed">{control.guidance}</p>
            </div>
          )}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Status</label>
            <Select value={status} onValueChange={v => setStatus(v as StatusKey)}>
              <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="compliant">Compliant</SelectItem>
                <SelectItem value="not_applicable">Not Applicable</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Notes</label>
            <Textarea value={notes} onChange={e => setNotes(e.target.value)} rows={4}
              placeholder="Implementation notes, evidence references..." className="text-xs" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Assigned To</label>
              <Input value={assignedTo} onChange={e => setAssignedTo(e.target.value)}
                placeholder="owner@company.com" className="h-8 text-xs" />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Due Date</label>
              <Input type="date" value={dueDate} onChange={e => setDueDate(e.target.value)} className="h-8 text-xs" />
            </div>
          </div>
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-muted-foreground">Evidence Files</label>
              <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5"
                onClick={() => fileRef.current?.click()} disabled={uploading}>
                {uploading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Upload className="w-3 h-3" />}
                Upload
              </Button>
              <input ref={fileRef} type="file" multiple className="hidden"
                onChange={e => e.target.files && uploadFiles(e.target.files)} />
            </div>
            {evidenceFiles.length === 0
              ? <p className="text-xs text-muted-foreground italic">No evidence uploaded yet.</p>
              : (
                <div className="space-y-1.5">
                  {evidenceFiles.map(f => (
                    <div key={f.path} className="flex items-center gap-2 bg-muted/30 rounded px-3 py-1.5 text-xs">
                      <FileText className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="flex-1 truncate">{f.name}</span>
                      <span className="text-muted-foreground shrink-0">{(f.size / 1024).toFixed(1)}kb</span>
                      <a href={`${BASE}/api/compliance/answers/${control.globalControlId}/evidence/${f.path}`}
                        target="_blank" rel="noopener noreferrer" className="text-primary hover:text-primary/80">
                        <Download className="w-3.5 h-3.5" />
                      </a>
                      <button onClick={() => delEvidence.mutate(f.path)} className="text-red-400 hover:text-red-300">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
          </div>
        </div>

        <div className="px-5 py-4 border-t border-border flex gap-3">
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending} className="flex-1">
            {save.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}
            Save Changes
          </Button>
          <Button size="sm" variant="outline" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </div>
  );
}

// ── Global Control Dialog (admin edit/create) ─────────────────────────────────
function GlobalControlDialog({ control, frameworkId, onClose }: { control: GlobalControl | null; frameworkId: number; onClose: () => void }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [title, setTitle] = useState(control?.title ?? "");
  const [controlId, setControlId] = useState(control?.controlId ?? "");
  const [description, setDescription] = useState(control?.description ?? "");
  const [category, setCategory] = useState(control?.category ?? "");
  const [guidance, setGuidance] = useState(control?.guidance ?? "");
  const isEdit = !!control;

  const save = useMutation({
    mutationFn: () => isEdit
      ? apiFetch(`${BASE}/api/compliance/library/${control!.id}`, { method: "PATCH", body: JSON.stringify({ title, controlId, description, category, guidance }) })
      : apiFetch(`${BASE}/api/compliance/library`, { method: "POST", body: JSON.stringify({ frameworkId, controlId, title, description, category, guidance }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["compliance-library"] });
      qc.invalidateQueries({ queryKey: ["compliance-answers", frameworkId] });
      toast({ title: isEdit ? "Control updated" : "Control created" });
      onClose();
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  return (
    <Dialog open onOpenChange={() => onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Control" : "Add Control"}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Control ID *</label>
              <Input value={controlId} onChange={e => setControlId(e.target.value)} placeholder="e.g. A.5.1" className="h-8 text-xs" />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1 block">Category</label>
              <Input value={category} onChange={e => setCategory(e.target.value)} placeholder="e.g. Organizational Controls" className="h-8 text-xs" />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Title *</label>
            <Input value={title} onChange={e => setTitle(e.target.value)} placeholder="Control title" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Description</label>
            <Textarea value={description} onChange={e => setDescription(e.target.value)} rows={3}
              placeholder="Full control description..." className="text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1 block">Guidance</label>
            <Textarea value={guidance} onChange={e => setGuidance(e.target.value)} rows={3}
              placeholder="Implementation guidance..." className="text-xs" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending || !title || !controlId}>
            {save.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}
            {isEdit ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ── Controls Table ────────────────────────────────────────────────────────────
function ControlsTable({ controls, isAdmin, frameworkId, onEdit, onAdminEdit, onToggleEnabled, onDelete }: {
  controls: ControlAnswer[];
  isAdmin: boolean;
  frameworkId: number;
  onEdit: (c: ControlAnswer) => void;
  onAdminEdit?: (c: GlobalControl) => void;
  onToggleEnabled?: (id: number, enabled: boolean) => void;
  onDelete?: (id: number) => void;
}) {
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");

  const categories = useMemo(() => [...new Set(controls.map(c => c.category).filter(Boolean))] as string[], [controls]);

  const filtered = useMemo(() => controls.filter(c => {
    if (search && !c.title.toLowerCase().includes(search.toLowerCase()) && !c.controlId.toLowerCase().includes(search.toLowerCase())) return false;
    if (statusFilter !== "all" && c.status !== statusFilter) return false;
    if (categoryFilter !== "all" && c.category !== categoryFilter) return false;
    return true;
  }), [controls, search, statusFilter, categoryFilter]);

  function toggle(id: number) {
    setExpanded(prev => { const next = new Set(prev); next.has(id) ? next.delete(id) : next.add(id); return next; });
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search controls…" className="h-8 pl-8 text-xs" />
        </div>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-8 text-xs w-40"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="compliant">Compliant</SelectItem>
            <SelectItem value="in_progress">In Progress</SelectItem>
            <SelectItem value="non_compliant">Non-Compliant</SelectItem>
            <SelectItem value="not_applicable">N/A</SelectItem>
          </SelectContent>
        </Select>
        {categories.length > 0 && (
          <Select value={categoryFilter} onValueChange={setCategoryFilter}>
            <SelectTrigger className="h-8 text-xs w-48"><SelectValue placeholder="Category" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Categories</SelectItem>
              {categories.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
            </SelectContent>
          </Select>
        )}
        <span className="text-xs text-muted-foreground self-center ml-auto">{filtered.length} controls</span>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {filtered.length === 0
          ? <div className="p-8 text-center text-sm text-muted-foreground">No controls match your filters.</div>
          : (
            <div className="divide-y divide-border">
              {filtered.map(c => {
                const isOpen = expanded.has(c.globalControlId);
                const cfg = STATUS_CONFIG[c.status] ?? STATUS_CONFIG.non_compliant;
                const Icon = cfg.icon;
                return (
                  <div key={c.globalControlId}>
                    <div className="flex items-center gap-3 px-4 py-3 hover:bg-muted/20 cursor-pointer group"
                      onClick={() => toggle(c.globalControlId)}>
                      {isOpen
                        ? <ChevronDown className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                      <span className="text-xs font-mono text-muted-foreground w-20 shrink-0">{c.controlId}</span>
                      <span className="flex-1 text-xs font-medium truncate">{c.title}</span>
                      {c.category && <span className="text-xs text-muted-foreground hidden md:block truncate max-w-[140px]">{c.category}</span>}
                      <Badge className={cn("text-xs gap-1 border px-2 py-0.5 shrink-0", cfg.bg, cfg.color)}>
                        <Icon className="w-3 h-3" />{cfg.label}
                      </Badge>
                      <div className="flex items-center gap-1 shrink-0 ml-1">
                        <button className="opacity-0 group-hover:opacity-100 transition text-primary hover:text-primary/80 p-1"
                          onClick={e => { e.stopPropagation(); onEdit(c); }} title="Update status">
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        {isAdmin && (
                          <>
                            {onAdminEdit && (
                              <button className="opacity-0 group-hover:opacity-100 transition text-muted-foreground hover:text-foreground p-1"
                                onClick={e => { e.stopPropagation(); onAdminEdit({ id: c.globalControlId, frameworkId: c.frameworkId, controlId: c.controlId, title: c.title, description: c.description, category: c.category, guidance: c.guidance, isEnabled: c.isEnabled, sortOrder: c.sortOrder, frameworkName: c.frameworkName, frameworkShortName: c.frameworkShortName }); }}
                                title="Edit control definition">
                                <BookOpen className="w-3.5 h-3.5" />
                              </button>
                            )}
                            {onToggleEnabled && (
                              <button className="opacity-0 group-hover:opacity-100 transition p-1"
                                onClick={e => { e.stopPropagation(); onToggleEnabled(c.globalControlId, !c.isEnabled); }}
                                title={c.isEnabled ? "Disable" : "Enable"}>
                                {c.isEnabled
                                  ? <ToggleRight className="w-3.5 h-3.5 text-green-400" />
                                  : <ToggleLeft className="w-3.5 h-3.5 text-muted-foreground" />}
                              </button>
                            )}
                            {onDelete && (
                              <button className="opacity-0 group-hover:opacity-100 transition text-red-400 hover:text-red-300 p-1"
                                onClick={e => { e.stopPropagation(); onDelete(c.globalControlId); }}
                                title="Delete control">
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                    {isOpen && (
                      <div className="px-10 pb-4 pt-1 bg-muted/10 space-y-3">
                        {c.description && <p className="text-xs text-muted-foreground leading-relaxed">{c.description}</p>}
                        {c.guidance && (
                          <div className="bg-primary/5 border border-primary/20 rounded p-2.5 text-xs text-muted-foreground">
                            <span className="font-medium text-primary/80">Guidance: </span>{c.guidance}
                          </div>
                        )}
                        <div className="flex flex-wrap gap-4 text-xs">
                          {c.assignedTo && <span className="text-muted-foreground">Assigned: <span className="text-foreground">{c.assignedTo}</span></span>}
                          {c.dueDate && <span className="text-muted-foreground">Due: <span className="text-foreground">{c.dueDate}</span></span>}
                          {c.notes && <span className="text-muted-foreground">Notes: <span className="text-foreground">{c.notes}</span></span>}
                          {c.reviewedAt && <span className="text-muted-foreground">Reviewed: <span className="text-foreground">{new Date(c.reviewedAt).toLocaleDateString()}</span></span>}
                        </div>
                        {parseEvidence(c.evidence).length > 0 && (
                          <div className="flex flex-wrap gap-2">
                            {parseEvidence(c.evidence).map(f => (
                              <a key={f.path} href={`${BASE}/api/compliance/answers/${c.globalControlId}/evidence/${f.path}`}
                                target="_blank" rel="noopener noreferrer"
                                className="flex items-center gap-1.5 bg-muted/40 hover:bg-muted/60 rounded px-2.5 py-1 text-xs transition">
                                <FileText className="w-3 h-3 text-muted-foreground" />{f.name}
                              </a>
                            ))}
                          </div>
                        )}
                        <Button size="sm" variant="outline" className="h-7 text-xs gap-1.5" onClick={() => onEdit(c)}>
                          <Pencil className="w-3 h-3" />Update Status
                        </Button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
      </div>
    </div>
  );
}

// ── Library Tab ───────────────────────────────────────────────────────────────
function LibraryTab({ isAdmin, frameworkId, frameworks }: { isAdmin: boolean; frameworkId: number; frameworks: Framework[] }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [editControl, setEditControl] = useState<GlobalControl | null | undefined>(undefined);
  const [search, setSearch] = useState("");
  const [fwFilter, setFwFilter] = useState(String(frameworkId));

  const { data: controls = [], isLoading } = useQuery<GlobalControl[]>({
    queryKey: ["compliance-library", fwFilter],
    queryFn: () => apiFetch(`${BASE}/api/compliance/library${fwFilter !== "all" ? `?frameworkId=${fwFilter}` : ""}`),
  });

  const toggleEnabled = useMutation({
    mutationFn: ({ id, isEnabled }: { id: number; isEnabled: boolean }) =>
      apiFetch(`${BASE}/api/compliance/library/${id}`, { method: "PATCH", body: JSON.stringify({ isEnabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-library"] }),
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteCtrl = useMutation({
    mutationFn: (id: number) => apiFetch(`${BASE}/api/compliance/library/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["compliance-library"] }); toast({ title: "Control deleted" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const filtered = useMemo(() => controls.filter(c =>
    !search || c.title.toLowerCase().includes(search.toLowerCase()) || c.controlId.toLowerCase().includes(search.toLowerCase())
  ), [controls, search]);

  const selectedFwId = fwFilter !== "all" ? parseInt(fwFilter) : frameworkId;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center">
        <Select value={fwFilter} onValueChange={setFwFilter}>
          <SelectTrigger className="h-8 text-xs w-52"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Frameworks</SelectItem>
            {frameworks.map(fw => <SelectItem key={fw.id} value={String(fw.id)}>{fw.name}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search controls…" className="h-8 pl-8 text-xs" />
        </div>
        <span className="text-xs text-muted-foreground ml-auto">{filtered.length} controls</span>
        {isAdmin && (
          <Button size="sm" className="h-8 text-xs gap-1.5" onClick={() => setEditControl(null)}>
            <Plus className="w-3.5 h-3.5" />Add Control
          </Button>
        )}
      </div>

      {isLoading
        ? <div className="space-y-1.5">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 rounded-lg" />)}</div>
        : (
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            {filtered.length === 0
              ? <div className="p-8 text-center text-sm text-muted-foreground">No controls found.</div>
              : (
                <div className="divide-y divide-border">
                  {filtered.map(c => (
                    <div key={c.id} className={cn("flex items-center gap-3 px-4 py-2.5 group hover:bg-muted/20", !c.isEnabled && "opacity-50")}>
                      <Badge className={cn("text-xs border font-mono shrink-0", fwColor(c.frameworkShortName))}>{c.frameworkShortName}</Badge>
                      <span className="text-xs font-mono text-muted-foreground w-20 shrink-0">{c.controlId}</span>
                      <span className="flex-1 text-xs truncate">{c.title}</span>
                      {c.category && <span className="text-xs text-muted-foreground hidden lg:block truncate max-w-[160px]">{c.category}</span>}
                      {!c.isEnabled && <Badge className="text-xs bg-muted text-muted-foreground shrink-0">Disabled</Badge>}
                      {isAdmin && (
                        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition shrink-0">
                          <button onClick={() => setEditControl(c)} className="text-muted-foreground hover:text-foreground p-1"><Pencil className="w-3.5 h-3.5" /></button>
                          <button onClick={() => toggleEnabled.mutate({ id: c.id, isEnabled: !c.isEnabled })} className="p-1">
                            {c.isEnabled
                              ? <ToggleRight className="w-3.5 h-3.5 text-green-400" />
                              : <ToggleLeft className="w-3.5 h-3.5 text-muted-foreground" />}
                          </button>
                          <button onClick={() => { if (confirm("Delete this control?")) deleteCtrl.mutate(c.id); }} className="text-red-400 hover:text-red-300 p-1">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
          </div>
        )}

      {editControl !== undefined && (
        <GlobalControlDialog control={editControl} frameworkId={selectedFwId} onClose={() => setEditControl(undefined)} />
      )}
    </div>
  );
}

// ── Asset Compliance Tab ──────────────────────────────────────────────────────
function AssetComplianceTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [selectedFramework, setSelectedFramework] = useState<number | null>(null);

  const { data: assetsRes = [] } = useQuery<any>({
    queryKey: ["assets-list-compliance"],
    queryFn: () => apiFetch(`${BASE}/api/assets`),
    select: (d: any) => Array.isArray(d) ? d : (d.assets ?? []),
  });
  const assets: Asset[] = assetsRes;

  const { data: frameworks = [] } = useQuery<Framework[]>({
    queryKey: ["compliance-frameworks"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/frameworks`),
  });

  const { data: assetControls = [], isLoading: loadingCtrls } = useQuery<any[]>({
    queryKey: ["compliance-asset-controls", selectedAsset?.id, selectedFramework],
    queryFn: () => apiFetch(`${BASE}/api/compliance/assets/${selectedAsset!.id}${selectedFramework ? `?frameworkId=${selectedFramework}` : ""}`),
    enabled: !!selectedAsset,
  });

  const updateStatus = useMutation({
    mutationFn: ({ assetId, globalControlId, status }: any) =>
      apiFetch(`${BASE}/api/compliance/assets/${assetId}/${globalControlId}`, { method: "PUT", body: JSON.stringify({ status }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["compliance-asset-controls", selectedAsset?.id, selectedFramework] }); toast({ title: "Updated" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const scopeFramework = useMutation({
    mutationFn: ({ assetId, frameworkId }: any) =>
      apiFetch(`${BASE}/api/compliance/assets/${assetId}/scope`, { method: "POST", body: JSON.stringify({ frameworkId }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["compliance-asset-controls", selectedAsset?.id, selectedFramework] }); toast({ title: "Framework scoped to asset" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end">
        <div className="flex-1 min-w-[200px] max-w-xs">
          <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Asset</label>
          <Select value={selectedAsset ? String(selectedAsset.id) : ""} onValueChange={v => setSelectedAsset(assets.find(a => String(a.id) === v) ?? null)}>
            <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Select an asset…" /></SelectTrigger>
            <SelectContent>
              {assets.map(a => <SelectItem key={a.id} value={String(a.id)}>{a.name}{a.domain ? ` (${a.domain})` : ""}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="flex-1 min-w-[180px] max-w-xs">
          <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Framework</label>
          <Select value={selectedFramework ? String(selectedFramework) : "all"} onValueChange={v => setSelectedFramework(v === "all" ? null : parseInt(v))}>
            <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="All frameworks" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Frameworks</SelectItem>
              {frameworks.map(fw => <SelectItem key={fw.id} value={String(fw.id)}>{fw.name}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        {selectedAsset && selectedFramework && (
          <Button size="sm" variant="outline" className="h-8 text-xs gap-1.5"
            onClick={() => scopeFramework.mutate({ assetId: selectedAsset.id, frameworkId: selectedFramework })}
            disabled={scopeFramework.isPending}>
            <Plus className="w-3.5 h-3.5" />Scope Framework
          </Button>
        )}
      </div>

      {!selectedAsset ? (
        <div className="bg-card border border-border rounded-xl p-10 text-center">
          <Server className="w-8 h-8 text-muted-foreground/40 mx-auto mb-2" />
          <p className="text-sm text-muted-foreground">Select an asset to view its compliance posture</p>
        </div>
      ) : loadingCtrls ? (
        <div className="space-y-2">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10 w-full rounded-lg" />)}</div>
      ) : assetControls.length === 0 ? (
        <div className="bg-card border border-border rounded-xl p-8 text-center">
          <p className="text-sm text-muted-foreground mb-3">No controls scoped to this asset yet.</p>
          {selectedFramework && (
            <Button size="sm" variant="outline" onClick={() => scopeFramework.mutate({ assetId: selectedAsset.id, frameworkId: selectedFramework })} disabled={scopeFramework.isPending}>
              <Plus className="w-3.5 h-3.5 mr-1.5" />Scope framework controls to this asset
            </Button>
          )}
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="divide-y divide-border">
            {assetControls.map((c: any) => {
              const status: StatusKey = c.assetStatus ?? c.tenantStatus ?? "non_compliant";
              const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.non_compliant;
              const Icon = cfg.icon;
              return (
                <div key={c.globalControlId} className="flex items-center gap-3 px-4 py-2.5 hover:bg-muted/20 group">
                  <Badge className={cn("text-xs border font-mono shrink-0", fwColor(c.frameworkShortName))}>{c.frameworkShortName}</Badge>
                  <span className="text-xs font-mono text-muted-foreground w-20 shrink-0">{c.controlId}</span>
                  <span className="flex-1 text-xs truncate">{c.title}</span>
                  <Badge className={cn("text-xs border shrink-0 gap-1 px-2 py-0.5", cfg.bg, cfg.color)}>
                    <Icon className="w-3 h-3" />{cfg.label}
                  </Badge>
                  <Select value={status} onValueChange={v => updateStatus.mutate({ assetId: selectedAsset.id, globalControlId: c.globalControlId, status: v })}>
                    <SelectTrigger className="h-7 text-xs w-36 opacity-0 group-hover:opacity-100 transition">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                      <SelectItem value="in_progress">In Progress</SelectItem>
                      <SelectItem value="compliant">Compliant</SelectItem>
                      <SelectItem value="not_applicable">N/A</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Assignments Tab ───────────────────────────────────────────────────────────
function AssignmentsTab() {
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: assignments = [], isLoading } = useQuery<TenantAssignment[]>({
    queryKey: ["compliance-assignments"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/module/assignments`),
  });

  const toggle = useMutation({
    mutationFn: ({ tenantId, isEnabled }: { tenantId: number; isEnabled: boolean }) =>
      apiFetch(`${BASE}/api/compliance/module`, { method: "PATCH", body: JSON.stringify({ isEnabled, tenantId }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["compliance-assignments"] }); toast({ title: "Updated" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  return (
    <div className="space-y-3">
      <div className="bg-primary/5 border border-primary/20 rounded-lg px-4 py-3 text-xs text-muted-foreground flex items-start gap-2">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <span>Toggle the Compliance module on or off for each client tenant. Admins and account managers always have access regardless.</span>
      </div>
      {isLoading
        ? <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-14 w-full rounded-xl" />)}</div>
        : assignments.length === 0
          ? <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">No client tenants found.</div>
          : (
            <div className="bg-card border border-border rounded-xl divide-y divide-border overflow-hidden">
              {assignments.map(a => (
                <div key={a.tenantId} className="flex items-center gap-4 px-4 py-3">
                  <Building2 className="w-4 h-4 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{a.tenantName}</p>
                    {a.enabledAt && <p className="text-xs text-muted-foreground">Enabled {new Date(a.enabledAt).toLocaleDateString()}</p>}
                  </div>
                  {a.isEnabled && <Badge className="text-xs bg-green-500/20 text-green-400 border-green-500/30">Active</Badge>}
                  <button onClick={() => toggle.mutate({ tenantId: a.tenantId, isEnabled: !a.isEnabled })} disabled={toggle.isPending}>
                    {a.isEnabled
                      ? <ToggleRight className="w-8 h-8 text-green-400 hover:text-green-300 transition" />
                      : <ToggleLeft className="w-8 h-8 text-muted-foreground hover:text-foreground transition" />}
                  </button>
                </div>
              ))}
            </div>
          )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
type TabId = "overview" | "controls" | "library" | "assets" | "assignments";

export default function CompliancePage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const isAdminOrAM = isAdmin || user?.role === "account_manager";

  const initialTab: TabId = useMemo(() => {
    const t = new URLSearchParams(window.location.search).get("tab");
    if (t === "library" && isAdminOrAM) return "library";
    if (t === "assets") return "assets";
    if (t === "assignments" && isAdminOrAM) return "assignments";
    return "overview";
  }, []);

  const [activeTab, setActiveTab] = useState<TabId>(initialTab);
  const [selectedFrameworkId, setSelectedFrameworkId] = useState(1);
  const [editingControl, setEditingControl] = useState<ControlAnswer | null>(null);
  const [adminEditControl, setAdminEditControl] = useState<GlobalControl | null | undefined>(undefined);
  const qc = useQueryClient();
  const { toast } = useToast();

  const { data: frameworks = [], isLoading: loadingFw } = useQuery<Framework[]>({
    queryKey: ["compliance-frameworks"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/frameworks`),
  });

  const { data: summary = [], isLoading: loadingSummary, refetch: refetchSummary } = useQuery<FrameworkSummary[]>({
    queryKey: ["compliance-summary"],
    queryFn: () => apiFetch(`${BASE}/api/compliance/summary`),
  });

  const { data: controls = [], isLoading: loadingControls } = useQuery<ControlAnswer[]>({
    queryKey: ["compliance-answers", selectedFrameworkId],
    queryFn: () => apiFetch(`${BASE}/api/compliance/answers?frameworkId=${selectedFrameworkId}`),
    enabled: activeTab === "controls",
  });

  const toggleGlobalEnabled = useMutation({
    mutationFn: ({ id, isEnabled }: { id: number; isEnabled: boolean }) =>
      apiFetch(`${BASE}/api/compliance/library/${id}`, { method: "PATCH", body: JSON.stringify({ isEnabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-answers", selectedFrameworkId] }),
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteGlobal = useMutation({
    mutationFn: (id: number) => apiFetch(`${BASE}/api/compliance/library/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["compliance-answers", selectedFrameworkId] }),
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const selectedFw = summary.find(fw => fw.frameworkId === selectedFrameworkId);
  const overallScore = summary.length > 0
    ? Math.round(summary.reduce((a, b) => a + b.score, 0) / summary.length)
    : 0;

  const tabs = [
    { id: "overview" as TabId, label: "Overview" },
    { id: "controls" as TabId, label: "Controls" },
    { id: "library" as TabId, label: "Control Library", adminOnly: true },
    { id: "assets" as TabId, label: "Asset Compliance" },
    { id: "assignments" as TabId, label: "Module Assignments", adminOnly: true },
  ].filter(t => !t.adminOnly || isAdminOrAM);

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-6 pt-6 pb-0 border-b border-border flex-none">
        <div className="flex items-center justify-between gap-4 mb-4">
          <div>
            <h1 className="text-lg font-semibold flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-primary" />
              Compliance Management
            </h1>
            <p className="text-xs text-muted-foreground mt-0.5">
              ISO 27001 · SOC 2 · PCI DSS v4 · HIPAA · CIS v8 · NIST CSF 2.0
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right hidden sm:block">
              <p className="text-xs text-muted-foreground">Overall Score</p>
              <p className="text-xl font-bold text-primary">{overallScore}%</p>
            </div>
            <ScoreRing score={overallScore} size={52} />
            <Button size="sm" variant="outline" className="h-8 w-8 p-0" onClick={() => refetchSummary()}>
              <RefreshCw className="w-3.5 h-3.5" />
            </Button>
          </div>
        </div>
        <div className="flex gap-1 -mb-px">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={cn(
                "px-3.5 py-1.5 text-xs font-medium rounded-t border-b-2 transition-colors",
                activeTab === t.id ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground",
              )}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-6">
        {/* OVERVIEW */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            {loadingSummary
              ? <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-40 rounded-xl" />)}</div>
              : (
                <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
                  {summary.map(fw => (
                    <FrameworkCard key={fw.frameworkId} fw={fw} isSelected={selectedFrameworkId === fw.frameworkId}
                      onClick={() => { setSelectedFrameworkId(fw.frameworkId); setActiveTab("controls"); }} />
                  ))}
                </div>
              )}
            {summary.length > 0 && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {([
                  ["Total Controls", summary.reduce((a, b) => a + b.total, 0), "text-foreground"],
                  ["Compliant", summary.reduce((a, b) => a + b.compliant, 0), "text-green-400"],
                  ["In Progress", summary.reduce((a, b) => a + b.inProgress, 0), "text-yellow-400"],
                  ["Non-Compliant", summary.reduce((a, b) => a + b.nonCompliant, 0), "text-red-400"],
                ] as [string, number, string][]).map(([label, val, cls]) => (
                  <div key={label} className="bg-card border border-border rounded-xl p-4 text-center">
                    <p className={cn("text-2xl font-bold", cls)}>{val}</p>
                    <p className="text-xs text-muted-foreground mt-1">{label}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* CONTROLS */}
        {activeTab === "controls" && (
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {(loadingFw ? [] : frameworks).map(fw => (
                <button key={fw.id} onClick={() => setSelectedFrameworkId(fw.id)}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-xs font-medium border transition-all",
                    selectedFrameworkId === fw.id ? fwColor(fw.shortName) : "border-border text-muted-foreground hover:border-primary/30",
                  )}>
                  {fw.shortName}
                  {selectedFw?.frameworkId === fw.id && <span className="ml-1.5 opacity-70">{selectedFw.score}%</span>}
                </button>
              ))}
            </div>

            {selectedFw && (
              <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-6">
                <ScoreRing score={selectedFw.score} size={60} />
                <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {([
                    ["Compliant", selectedFw.compliant, "text-green-400"],
                    ["In Progress", selectedFw.inProgress, "text-yellow-400"],
                    ["Non-Compliant", selectedFw.nonCompliant, "text-red-400"],
                    ["N/A", selectedFw.notApplicable, "text-slate-400"],
                  ] as [string, number, string][]).map(([label, val, cls]) => (
                    <div key={label}>
                      <p className={cn("text-lg font-bold", cls)}>{val}</p>
                      <p className="text-xs text-muted-foreground">{label}</p>
                    </div>
                  ))}
                </div>
                {isAdmin && (
                  <Button size="sm" variant="outline" className="h-8 text-xs gap-1.5 shrink-0" onClick={() => setActiveTab("library")}>
                    <BookOpen className="w-3.5 h-3.5" />Manage Library
                  </Button>
                )}
              </div>
            )}

            {loadingControls
              ? <div className="space-y-2">{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-10 rounded-lg" />)}</div>
              : (
                <ControlsTable
                  controls={controls}
                  isAdmin={isAdmin}
                  frameworkId={selectedFrameworkId}
                  onEdit={c => setEditingControl(c)}
                  onAdminEdit={isAdmin ? c => setAdminEditControl(c) : undefined}
                  onToggleEnabled={isAdmin ? (id, en) => toggleGlobalEnabled.mutate({ id, isEnabled: en }) : undefined}
                  onDelete={isAdmin ? id => { if (confirm("Delete this control from the global library?")) deleteGlobal.mutate(id); } : undefined}
                />
              )}
          </div>
        )}

        {/* LIBRARY */}
        {activeTab === "library" && (
          <LibraryTab isAdmin={isAdmin} frameworkId={selectedFrameworkId} frameworks={frameworks} />
        )}

        {/* ASSETS */}
        {activeTab === "assets" && <AssetComplianceTab />}

        {/* ASSIGNMENTS */}
        {activeTab === "assignments" && isAdminOrAM && <AssignmentsTab />}
      </div>

      {/* Control Edit Drawer */}
      {editingControl && (
        <ControlEditDrawer control={editingControl} frameworkId={selectedFrameworkId} onClose={() => setEditingControl(null)} />
      )}

      {/* Admin Edit Dialog */}
      {adminEditControl !== undefined && (
        <GlobalControlDialog control={adminEditControl} frameworkId={selectedFrameworkId} onClose={() => setAdminEditControl(undefined)} />
      )}
    </div>
  );
}
