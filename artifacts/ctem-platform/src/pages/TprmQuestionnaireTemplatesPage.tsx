import { useEffect, useState, useMemo } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  Plus, Trash2, Edit2, Loader2, FileText,
  ChevronDown, ChevronUp, GripVertical, X,
  ChevronLeft, ChevronRight, ChevronFirst, ChevronLast,
} from "lucide-react";

const PAGE_SIZE = 10;

// ── Types ─────────────────────────────────────────────────────────────────────

type QuestionType = "boolean" | "text" | "rating" | "select" | "multi_choice" | "file_upload";

interface Question {
  id:       string;
  text:     string;
  type:     QuestionType;
  category: string;
  required: boolean;
  weight:   number;
  options?: string[];
}

interface Template {
  id:          number;
  name:        string;
  description: string | null;
  category:    string;
  questions:   Question[];
  isGlobal:    boolean;
  isActive:    boolean;
  createdAt:   string;
  updatedAt:   string;
}

const QUESTION_TYPE_LABELS: Record<QuestionType, string> = {
  boolean:      "Yes / No",
  text:         "Free Text",
  rating:       "Rating (1–5)",
  select:       "Single Choice",
  multi_choice: "Multi Choice",
  file_upload:  "File Upload",
};

const BUILTIN_QUESTIONS: Question[] = [
  { id: "bq1",  text: "Does the vendor have an information security policy?",            type: "boolean",      category: "governance",         required: true,  weight: 2 },
  { id: "bq2",  text: "Is the vendor ISO 27001 certified?",                              type: "boolean",      category: "compliance",         required: true,  weight: 2 },
  { id: "bq3",  text: "Does the vendor perform annual penetration testing?",             type: "boolean",      category: "testing",            required: true,  weight: 2 },
  { id: "bq4",  text: "Does the vendor encrypt data at rest?",                           type: "boolean",      category: "data_protection",    required: true,  weight: 2 },
  { id: "bq5",  text: "Does the vendor encrypt data in transit?",                        type: "boolean",      category: "data_protection",    required: true,  weight: 2 },
  { id: "bq6",  text: "Does the vendor have a formal incident response plan?",           type: "boolean",      category: "incident_response",  required: true,  weight: 2 },
  { id: "bq7",  text: "Does the vendor perform background checks on employees?",         type: "boolean",      category: "hr_security",        required: false, weight: 1 },
  { id: "bq8",  text: "Does the vendor use multi-factor authentication?",                type: "boolean",      category: "access_control",     required: true,  weight: 2 },
  { id: "bq9",  text: "Rate the vendor's overall security maturity level (1–5)",         type: "rating",       category: "maturity",           required: false, weight: 3 },
  { id: "bq10", text: "Does the vendor have SOC 2 Type II certification?",               type: "boolean",      category: "compliance",         required: false, weight: 2 },
  { id: "bq11", text: "What is the vendor's SLA for critical security incidents (hrs)?", type: "text",         category: "incident_response",  required: false, weight: 1 },
  { id: "bq12", text: "Does the vendor maintain a vulnerability disclosure program?",    type: "boolean",      category: "vulnerability_mgmt", required: false, weight: 1 },
  { id: "bq13", text: "Which compliance frameworks does the vendor adhere to?",          type: "multi_choice", category: "compliance",         required: false, weight: 1, options: ["ISO 27001","SOC 2","PCI DSS","HIPAA","GDPR","NIST CSF","CIS Controls"] },
  { id: "bq14", text: "Please upload the latest third-party audit report",               type: "file_upload",  category: "compliance",         required: false, weight: 2 },
];

function newQuestion(): Question {
  return {
    id:       `cq_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    text:     "",
    type:     "boolean",
    category: "general",
    required: false,
    weight:   1,
  };
}

// ── Pagination helpers ─────────────────────────────────────────────────────────

function getPageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 9) return Array.from({ length: total }, (_, i) => i + 1);

  const always = new Set([1, Math.max(1, total - 2), Math.max(1, total - 1), total].filter(p => p >= 1));
  const near   = new Set(
    [current - 2, current - 1, current, current + 1, current + 2].filter(p => p >= 1 && p <= total),
  );
  const all    = [...new Set([...always, ...near])].sort((a, b) => a - b);

  const result: (number | "...")[] = [];
  for (let i = 0; i < all.length; i++) {
    result.push(all[i]);
    if (i + 1 < all.length && (all[i + 1] as number) - (all[i] as number) > 1) result.push("...");
  }
  return result;
}

function SmartPagination({
  page, totalPages, total, pageSize, onPage,
}: {
  page: number; totalPages: number; total: number; pageSize: number;
  onPage: (p: number) => void;
}) {
  if (totalPages <= 1) return null;
  const safe = Math.min(page, totalPages);
  const nums = getPageNumbers(safe, totalPages);

  return (
    <div className="flex items-center justify-between border-t border-border/40 px-4 py-3">
      <p className="text-xs text-muted-foreground">
        Showing {(safe - 1) * pageSize + 1}–{Math.min(safe * pageSize, total)} of {total} templates
      </p>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(1)} title="First page">
          <ChevronFirst className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(safe - 1)}>
          <ChevronLeft className="w-3.5 h-3.5" />
        </Button>
        {nums.map((p, i) =>
          p === "..." ? (
            <span key={`e-${i}`} className="text-xs text-muted-foreground px-1 select-none">…</span>
          ) : (
            <Button
              key={p}
              variant={p === safe ? "default" : "ghost"}
              size="icon"
              className="h-7 w-7 text-xs"
              onClick={() => onPage(p as number)}
            >
              {p}
            </Button>
          )
        )}
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(safe + 1)}>
          <ChevronRight className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(totalPages)} title="Last page">
          <ChevronLast className="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function TprmQuestionnaireTemplatesPage() {
  const { toast }      = useToast();
  const { user }       = useAuth();
  const isSuperAdmin   = user?.role === "super_admin";

  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit]   = useState<Template | null>(null);
  const [expanded, setExpanded]   = useState<number | null>(null);
  const [saving, setSaving]       = useState(false);
  const [page, setPage]           = useState(1);

  // Per-template toggle saving state
  const [togglingId, setTogglingId] = useState<number | null>(null);

  const [form, setForm]           = useState({ name: "", description: "", category: "security" });
  const [questions, setQuestions] = useState<Question[]>([]);
  const [newQ, setNewQ]           = useState<Question>(newQuestion());
  const [addingCustom, setAddingCustom] = useState(false);
  const [optionInput, setOptionInput]   = useState("");
  const [libOpen, setLibOpen]     = useState(false);
  const [libSelected, setLibSelected] = useState<Set<string>>(new Set());
  const [dragIdx, setDragIdx]     = useState<number | null>(null);
  const [dragOverIdx, setDragOverIdx] = useState<number | null>(null);

  const load = () => {
    setLoading(true);
    apiFetch<Template[]>("/api/tprm/questionnaire-templates")
      .then(setTemplates)
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  // Pagination — client-side on loaded list
  const totalPages = Math.max(1, Math.ceil(templates.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pagedTemplates = useMemo(
    () => templates.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE),
    [templates, safePage],
  );

  // ── Open create / edit ───────────────────────────────────────────────────────

  const openCreate = () => {
    setForm({ name: "", description: "", category: "security" });
    const required = BUILTIN_QUESTIONS.filter(q => q.required);
    setQuestions(required);
    setLibSelected(new Set(required.map(q => q.id)));
    setAddingCustom(false);
    setLibOpen(false);
    setNewQ(newQuestion());
    setShowCreate(true);
  };

  const openEdit = (t: Template) => {
    setForm({ name: t.name, description: t.description ?? "", category: t.category });
    const qs = (t.questions ?? []).map(q => ({ ...q, weight: q.weight ?? 1 }));
    setQuestions(qs);
    setLibSelected(new Set(qs.map(q => q.id)));
    setAddingCustom(false);
    setLibOpen(false);
    setNewQ(newQuestion());
    setShowEdit(t);
  };

  const closeDialog = () => { setShowCreate(false); setShowEdit(null); };

  // ── Save (create or update) ──────────────────────────────────────────────────

  const save = async () => {
    if (!form.name.trim() || questions.length === 0) return;
    setSaving(true);
    try {
      if (showEdit) {
        const updated = await apiFetch<Template>(`/api/tprm/questionnaire-templates/${showEdit.id}`, {
          method: "PATCH",
          body: JSON.stringify({ ...form, questions }),
        });
        setTemplates(prev => prev.map(t => t.id === updated.id ? updated : t));
        toast({ title: "Template updated", description: updated.name });
      } else {
        const created = await apiFetch<Template>("/api/tprm/questionnaire-templates", {
          method: "POST",
          body: JSON.stringify({ ...form, questions }),
        });
        setTemplates(prev => [created, ...prev]);
        toast({ title: "Template created", description: created.name });
      }
      closeDialog();
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message ?? "Could not save template", variant: "destructive" });
    }
    setSaving(false);
  };

  // ── Delete ───────────────────────────────────────────────────────────────────

  const del = async (t: Template) => {
    if (!confirm(`Delete "${t.name}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`/api/tprm/questionnaire-templates/${t.id}`, { method: "DELETE" });
      setTemplates(prev => prev.filter(x => x.id !== t.id));
      toast({ title: "Template deleted" });
    } catch {
      toast({ title: "Delete failed", variant: "destructive" });
    }
  };

  // ── Active / Inactive toggle ─────────────────────────────────────────────────

  const toggleActive = async (t: Template) => {
    if (t.isGlobal && !isSuperAdmin) {
      toast({ title: "Permission denied", description: "Only super_admin can toggle global templates", variant: "destructive" });
      return;
    }
    setTogglingId(t.id);
    const newActive = !t.isActive;
    // Optimistic update
    setTemplates(prev => prev.map(x => x.id === t.id ? { ...x, isActive: newActive } : x));
    try {
      const updated = await apiFetch<Template>(`/api/tprm/questionnaire-templates/${t.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isActive: newActive }),
      });
      setTemplates(prev => prev.map(x => x.id === updated.id ? updated : x));
      toast({ title: newActive ? "Template activated" : "Template deactivated", description: t.name });
    } catch (err: any) {
      // Rollback
      setTemplates(prev => prev.map(x => x.id === t.id ? { ...x, isActive: t.isActive } : x));
      toast({ title: "Toggle failed", description: err?.message ?? "Could not update template", variant: "destructive" });
    }
    setTogglingId(null);
  };

  // ── Question list helpers ─────────────────────────────────────────────────────

  const moveQ = (idx: number, dir: -1 | 1) => {
    const next   = [...questions];
    const target = idx + dir;
    if (target < 0 || target >= next.length) return;
    [next[idx], next[target]] = [next[target], next[idx]];
    setQuestions(next);
  };

  const handleDragStart  = (e: React.DragEvent, idx: number) => { setDragIdx(idx); e.dataTransfer.effectAllowed = "move"; };
  const handleDragOver   = (e: React.DragEvent, idx: number) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; if (idx !== dragOverIdx) setDragOverIdx(idx); };
  const handleDrop       = (e: React.DragEvent, toIdx: number) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === toIdx) { setDragIdx(null); setDragOverIdx(null); return; }
    const next = [...questions];
    const [moved] = next.splice(dragIdx, 1);
    next.splice(toIdx, 0, moved);
    setQuestions(next);
    setDragIdx(null); setDragOverIdx(null);
  };
  const handleDragEnd    = () => { setDragIdx(null); setDragOverIdx(null); };
  const removeQ          = (idx: number) => setQuestions(q => q.filter((_, i) => i !== idx));

  const commitCustomQ = () => {
    if (!newQ.text.trim()) return;
    setQuestions(prev => [...prev, { ...newQ }]);
    setNewQ(newQuestion()); setOptionInput(""); setAddingCustom(false);
  };

  const toggleLibQ = (q: Question) => {
    const next = new Set(libSelected);
    if (next.has(q.id)) { next.delete(q.id); setQuestions(prev => prev.filter(p => p.id !== q.id)); }
    else                { next.add(q.id);    setQuestions(prev => [...prev, q]); }
    setLibSelected(next);
  };

  const addOptionToNewQ = () => {
    const val = optionInput.trim();
    if (!val) return;
    setNewQ(q => ({ ...q, options: [...(q.options ?? []), val] }));
    setOptionInput("");
  };

  const isOpen         = showCreate || !!showEdit;
  const canEditGlobal  = isSuperAdmin;

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Questionnaire Templates</h1>
          <p className="text-muted-foreground text-sm">
            Build and manage security assessment questionnaires for vendor portals
          </p>
        </div>
        <Button size="sm" onClick={openCreate}>
          <Plus className="w-4 h-4 mr-1.5" />New Template
        </Button>
      </div>

      {/* Template list */}
      {loading ? (
        <div className="space-y-3">{Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-20" />)}</div>
      ) : templates.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-16 text-center">
            <FileText className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
            <p className="text-sm font-medium">No templates yet</p>
            <p className="text-xs text-muted-foreground mt-1">Create a template to send questionnaires to your vendors</p>
            <Button size="sm" className="mt-4" onClick={openCreate}><Plus className="w-4 h-4 mr-1.5" />New Template</Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="divide-y divide-border/40">
              {pagedTemplates.map(t => {
                const qs        = t.questions as Question[];
                const isExpanded = expanded === t.id;
                const canEdit   = !t.isGlobal || canEditGlobal;
                const isToggling = togglingId === t.id;

                return (
                  <div key={t.id} className="p-4 hover:bg-accent/10 transition-colors">
                    <div className="flex items-start gap-3">
                      <FileText className={`w-5 h-5 shrink-0 mt-0.5 ${t.isActive ? "text-primary" : "text-muted-foreground/40"}`} />

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className={`text-sm font-semibold ${!t.isActive ? "text-muted-foreground line-through" : ""}`}>
                            {t.name}
                          </p>
                          {t.isGlobal && (
                            <Badge variant="secondary" className="text-[10px]">Global</Badge>
                          )}
                          <Badge variant="outline" className="text-[10px] capitalize">
                            {t.category.replace(/_/g, " ")}
                          </Badge>
                          <Badge
                            variant={t.isActive ? "default" : "secondary"}
                            className={`text-[10px] ${t.isActive ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-slate-500/20 text-slate-400 border-slate-500/30"}`}
                          >
                            {t.isActive ? "Active" : "Inactive"}
                          </Badge>
                        </div>
                        {t.description && (
                          <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-[500px]">{t.description}</p>
                        )}
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {qs.length} question{qs.length !== 1 ? "s" : ""} · Updated {new Date(t.updatedAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                        </p>
                      </div>

                      {/* Controls: toggle + expand + edit + delete */}
                      <div className="flex items-center gap-2 shrink-0">
                        {/* Active / Inactive toggle */}
                        <div className="flex items-center gap-1.5" title={t.isActive ? "Deactivate template" : "Activate template"}>
                          <span className="text-[10px] text-muted-foreground hidden sm:block">
                            {t.isActive ? "Active" : "Inactive"}
                          </span>
                          {isToggling ? (
                            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                          ) : (
                            <Switch
                              checked={t.isActive}
                              onCheckedChange={() => toggleActive(t)}
                              disabled={t.isGlobal && !canEditGlobal}
                              className="scale-75"
                            />
                          )}
                        </div>

                        {/* Expand / collapse */}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7"
                          onClick={() => setExpanded(isExpanded ? null : t.id)}
                          title={isExpanded ? "Collapse" : "Expand questions"}
                        >
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </Button>

                        {/* Edit — available for custom templates and for global if super_admin */}
                        {canEdit && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => openEdit(t)}
                            title="Edit template"
                          >
                            <Edit2 className="w-3.5 h-3.5" />
                          </Button>
                        )}

                        {/* Delete — only for custom (non-global) templates */}
                        {!t.isGlobal && (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7 text-destructive hover:text-destructive"
                            onClick={() => del(t)}
                            title="Delete template"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        )}
                      </div>
                    </div>

                    {/* Expanded question list */}
                    {isExpanded && (
                      <div className="mt-3 space-y-1.5 pl-8 border-t border-border/30 pt-3">
                        {qs.length === 0 ? (
                          <p className="text-xs text-muted-foreground italic">No questions in this template</p>
                        ) : qs.map((q, i) => (
                          <div key={q.id} className="flex items-start gap-2 text-sm">
                            <span className="text-muted-foreground w-5 shrink-0 text-xs">{i + 1}.</span>
                            <span className="flex-1 text-xs">{q.text}</span>
                            <Badge variant="outline" className="text-[10px] shrink-0">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                            {q.required && <Badge variant="secondary" className="text-[10px] shrink-0">Req</Badge>}
                            {(q.weight ?? 1) > 1 && <Badge variant="secondary" className="text-[10px] shrink-0">w:{q.weight}</Badge>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Smart pagination */}
            <SmartPagination
              page={safePage}
              totalPages={totalPages}
              total={templates.length}
              pageSize={PAGE_SIZE}
              onPage={p => setPage(p)}
            />
          </CardContent>
        </Card>
      )}

      {/* ── Create / Edit Dialog ─────────────────────────────────────────────── */}
      {isOpen && (
        <Dialog open onOpenChange={closeDialog}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{showEdit ? `Edit: ${showEdit.name}` : "Create Template"}</DialogTitle>
            </DialogHeader>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <Label className="text-xs">Name *</Label>
                <Input
                  className="mt-1"
                  value={form.name}
                  onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g. Annual Security Review"
                />
              </div>

              {/* Category */}
              <div>
                <Label className="text-xs">Category</Label>
                <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["security","privacy","compliance","business_continuity","due_diligence"].map(c => (
                      <SelectItem key={c} value={c}>
                        {c.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Description */}
              <div>
                <Label className="text-xs">Description</Label>
                <Textarea
                  className="mt-1 text-sm"
                  rows={2}
                  value={form.description}
                  onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                  placeholder="Brief description of the questionnaire purpose…"
                />
              </div>

              {/* Question builder */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <Label className="text-xs">Questions ({questions.length})</Label>
                  <div className="flex gap-1.5">
                    <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setLibOpen(o => !o)}>
                      {libOpen ? "Hide Library" : "Add from Library"}
                    </Button>
                    <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setAddingCustom(a => !a)}>
                      <Plus className="w-3 h-3 mr-1" />Custom Question
                    </Button>
                  </div>
                </div>

                {/* Library picker */}
                {libOpen && (
                  <div className="mb-3 border rounded-md p-2 space-y-1 max-h-48 overflow-y-auto bg-muted/20">
                    <p className="text-[10px] text-muted-foreground mb-1.5 font-medium">
                      Pre-built library — click to add or remove:
                    </p>
                    {BUILTIN_QUESTIONS.map(q => (
                      <label key={q.id} className="flex items-start gap-2 cursor-pointer p-1 rounded hover:bg-accent/30">
                        <input type="checkbox" className="mt-0.5 shrink-0 accent-primary" checked={libSelected.has(q.id)} onChange={() => toggleLibQ(q)} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs">{q.text}</p>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type]}</Badge>
                            <Badge variant="outline" className="text-[10px]">{q.category}</Badge>
                            {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                )}

                {/* Custom question form */}
                {addingCustom && (
                  <div className="mb-3 border rounded-md p-3 space-y-3 bg-muted/20">
                    <p className="text-xs font-medium">Custom Question</p>
                    <div>
                      <Label className="text-[10px]">Question Text *</Label>
                      <Textarea className="mt-1 text-xs" rows={2} value={newQ.text} onChange={e => setNewQ(q => ({ ...q, text: e.target.value }))} placeholder="Enter your question…" />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <Label className="text-[10px]">Answer Type</Label>
                        <Select value={newQ.type} onValueChange={v => setNewQ(q => ({ ...q, type: v as QuestionType, options: undefined }))}>
                          <SelectTrigger className="mt-1 h-7 text-xs"><SelectValue /></SelectTrigger>
                          <SelectContent>
                            {(Object.entries(QUESTION_TYPE_LABELS) as [QuestionType, string][]).map(([k, v]) => (
                              <SelectItem key={k} value={k}>{v}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label className="text-[10px]">Category</Label>
                        <Input className="mt-1 h-7 text-xs" value={newQ.category} onChange={e => setNewQ(q => ({ ...q, category: e.target.value }))} placeholder="e.g. access_control" />
                      </div>
                      <div>
                        <Label className="text-[10px]">Weight (1–5)</Label>
                        <Input
                          type="number" min={1} max={5}
                          className="mt-1 h-7 text-xs"
                          value={newQ.weight}
                          onChange={e => setNewQ(q => ({ ...q, weight: Math.max(1, Math.min(5, parseInt(e.target.value) || 1)) }))}
                        />
                      </div>
                      <div className="flex items-end pb-1">
                        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                          <input type="checkbox" className="accent-primary" checked={newQ.required} onChange={e => setNewQ(q => ({ ...q, required: e.target.checked }))} />
                          Required
                        </label>
                      </div>
                    </div>

                    {/* Options for select / multi_choice */}
                    {(newQ.type === "select" || newQ.type === "multi_choice") && (
                      <div>
                        <Label className="text-[10px]">Options</Label>
                        <div className="flex gap-1 mt-1">
                          <Input
                            className="h-7 text-xs flex-1"
                            placeholder="Type an option and press Enter…"
                            value={optionInput}
                            onChange={e => setOptionInput(e.target.value)}
                            onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addOptionToNewQ(); } }}
                          />
                          <Button variant="outline" size="sm" className="h-7 text-xs" onClick={addOptionToNewQ}>Add</Button>
                        </div>
                        {(newQ.options ?? []).length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {(newQ.options ?? []).map((o, i) => (
                              <span key={i} className="inline-flex items-center gap-0.5 text-[10px] border rounded px-1.5 py-0.5 bg-muted/30">
                                {o}
                                <button onClick={() => setNewQ(q => ({ ...q, options: (q.options ?? []).filter((_, j) => j !== i) }))} className="ml-0.5 text-muted-foreground hover:text-destructive">
                                  <X className="w-2.5 h-2.5" />
                                </button>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    <div className="flex gap-2 pt-1">
                      <Button size="sm" className="h-7 text-xs" onClick={commitCustomQ} disabled={!newQ.text.trim()}>
                        Add Question
                      </Button>
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setAddingCustom(false); setNewQ(newQuestion()); setOptionInput(""); }}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                )}

                {/* Ordered drag-and-drop question list */}
                {questions.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-6 border rounded-md border-dashed">
                    No questions yet — add from the library or create custom ones above
                  </p>
                ) : (
                  <div className="space-y-1 max-h-60 overflow-y-auto border rounded-md p-2">
                    {questions.map((q, i) => (
                      <div
                        key={q.id}
                        draggable
                        onDragStart={e => handleDragStart(e, i)}
                        onDragOver={e => handleDragOver(e, i)}
                        onDrop={e => handleDrop(e, i)}
                        onDragEnd={handleDragEnd}
                        className={`flex items-start gap-1.5 p-1.5 rounded hover:bg-accent/20 group transition-colors
                          ${dragOverIdx === i && dragIdx !== i ? "border border-primary/50 bg-primary/5" : ""}
                          ${dragIdx === i ? "opacity-40" : ""}`}
                      >
                        <GripVertical className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5 cursor-grab active:cursor-grabbing" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs">
                            <span className="text-muted-foreground mr-1">{i + 1}.</span>
                            {q.text || <span className="text-muted-foreground italic">empty question</span>}
                          </p>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                            {q.category && <Badge variant="outline" className="text-[10px]">{q.category}</Badge>}
                            {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                            {(q.weight ?? 1) > 1 && <Badge variant="outline" className="text-[10px]">w:{q.weight}</Badge>}
                          </div>
                        </div>
                        <div className="flex flex-col opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                          <button onClick={() => moveQ(i, -1)} disabled={i === 0} className="text-muted-foreground hover:text-foreground disabled:opacity-30 p-0.5">
                            <ChevronUp className="w-3 h-3" />
                          </button>
                          <button onClick={() => moveQ(i, 1)} disabled={i === questions.length - 1} className="text-muted-foreground hover:text-foreground disabled:opacity-30 p-0.5">
                            <ChevronDown className="w-3 h-3" />
                          </button>
                        </div>
                        <button
                          onClick={() => removeQ(i)}
                          className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive transition-opacity shrink-0 p-0.5"
                          title="Remove question"
                        >
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <DialogFooter className="mt-4">
              <Button variant="outline" onClick={closeDialog}>Cancel</Button>
              <Button onClick={save} disabled={saving || !form.name.trim() || questions.length === 0}>
                {saving && <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />}
                {showEdit ? "Update Template" : "Create Template"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
