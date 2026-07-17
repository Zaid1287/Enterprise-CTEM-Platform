import { useEffect, useState, useMemo } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  Plus, Trash2, Edit2, Loader2, FileText, Library,
  ChevronDown, ChevronUp, GripVertical, X,
  ChevronLeft, ChevronRight, ChevronFirst, ChevronLast,
  Save,
} from "lucide-react";

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

interface LibraryQuestion {
  id:        number;
  tenantId:  number | null;
  text:      string;
  type:      QuestionType;
  category:  string;
  required:  boolean;
  weight:    number;
  options:   string[] | null;
  isGlobal:  boolean;
  isActive:  boolean;
  createdAt: string;
}

const QUESTION_TYPE_LABELS: Record<QuestionType, string> = {
  boolean:      "Yes / No",
  text:         "Free Text",
  rating:       "Rating (1–5)",
  select:       "Single Choice",
  multi_choice: "Multi Choice",
  file_upload:  "File Upload",
};


function newQuestion(): Question {
  return { id: `cq_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, text: "", type: "boolean", category: "general", required: false, weight: 1 };
}

function getPageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 9) return Array.from({ length: total }, (_, i) => i + 1);
  const always = new Set([1, Math.max(1, total - 2), Math.max(1, total - 1), total].filter(p => p >= 1));
  const near   = new Set([current - 2, current - 1, current, current + 1, current + 2].filter(p => p >= 1 && p <= total));
  const all    = [...new Set([...always, ...near])].sort((a, b) => a - b);
  const result: (number | "...")[] = [];
  for (let i = 0; i < all.length; i++) {
    result.push(all[i]);
    if (i + 1 < all.length && (all[i + 1] as number) - (all[i] as number) > 1) result.push("...");
  }
  return result;
}

function SmartPagination({ page, totalPages, total, pageSize, onPage }: { page: number; totalPages: number; total: number; pageSize: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return null;
  const safe = Math.min(page, totalPages);
  const nums = getPageNumbers(safe, totalPages);
  return (
    <div className="flex items-center justify-between border-t border-border/40 px-4 py-3">
      <p className="text-xs text-muted-foreground">Showing {(safe - 1) * pageSize + 1}–{Math.min(safe * pageSize, total)} of {total}</p>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(1)}><ChevronFirst className="w-3.5 h-3.5" /></Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(safe - 1)}><ChevronLeft className="w-3.5 h-3.5" /></Button>
        {nums.map((p, i) =>
          p === "..." ? <span key={`e-${i}`} className="text-xs text-muted-foreground px-1">…</span>
            : <Button key={p} variant={p === safe ? "default" : "ghost"} size="icon" className="h-7 w-7 text-xs" onClick={() => onPage(p as number)}>{p}</Button>
        )}
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(safe + 1)}><ChevronRight className="w-3.5 h-3.5" /></Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(totalPages)}><ChevronLast className="w-3.5 h-3.5" /></Button>
      </div>
    </div>
  );
}

const PAGE_SIZE = 10;
const LIB_PAGE_SIZE = 15;

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function TprmQuestionnaireTemplatesPage() {
  const { toast }    = useToast();
  const { user }     = useAuth();
  const isSuperAdmin = user?.role === "super_admin";

  const [mainTab, setMainTab] = useState<"templates" | "library">("templates");

  // ── Template state ────────────────────────────────────────────────────────
  const [templates, setTemplates]   = useState<Template[]>([]);
  const [loadingTpl, setLoadingTpl] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit]     = useState<Template | null>(null);
  const [expanded, setExpanded]     = useState<number | null>(null);
  const [saving, setSaving]         = useState(false);
  const [tplPage, setTplPage]       = useState(1);
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

  // ── Library state ─────────────────────────────────────────────────────────
  const [libQuestions, setLibQuestions]     = useState<LibraryQuestion[]>([]);
  const [loadingLib, setLoadingLib]         = useState(false);
  const [libPage, setLibPage]               = useState(1);
  const [libCategoryFilter, setLibCategoryFilter] = useState("all");
  const [showAddLibQ, setShowAddLibQ]       = useState(false);
  const [editingLibQ, setEditingLibQ]       = useState<LibraryQuestion | null>(null);
  const [savingLibQ, setSavingLibQ]         = useState(false);
  const [libQForm, setLibQForm]             = useState({ text: "", type: "boolean" as QuestionType, category: "", required: false, weight: 1, options: [] as string[], isGlobal: false });
  const [libOptionInput, setLibOptionInput] = useState("");

  // ── Load templates ────────────────────────────────────────────────────────
  const loadTemplates = () => {
    setLoadingTpl(true);
    apiFetch<Template[]>("/api/tprm/questionnaire-templates")
      .then(setTemplates).catch(() => {}).finally(() => setLoadingTpl(false));
  };
  useEffect(() => { loadTemplates(); }, []);

  // ── Load library (auto-seeds defaults on first ever load) ─────────────────
  const loadLibrary = async () => {
    setLoadingLib(true);
    try {
      const qs = await apiFetch<LibraryQuestion[]>("/api/tprm/question-library");
      if (qs.length === 0) {
        await apiFetch("/api/tprm/question-library/seed-defaults", { method: "POST" });
        const seeded = await apiFetch<LibraryQuestion[]>("/api/tprm/question-library");
        setLibQuestions(seeded);
      } else {
        setLibQuestions(qs);
      }
    } catch { /* ignore */ }
    setLoadingLib(false);
  };
  useEffect(() => { loadLibrary(); }, []);

  // ── Pagination ────────────────────────────────────────────────────────────
  const tplTotal     = templates.length;
  const tplTotalPgs  = Math.max(1, Math.ceil(tplTotal / PAGE_SIZE));
  const safeTplPage  = Math.min(tplPage, tplTotalPgs);
  const pagedTpl     = useMemo(() => templates.slice((safeTplPage - 1) * PAGE_SIZE, safeTplPage * PAGE_SIZE), [templates, safeTplPage]);

  const filteredLib  = useMemo(() =>
    libCategoryFilter === "all" ? libQuestions : libQuestions.filter(q => q.category === libCategoryFilter),
    [libQuestions, libCategoryFilter]);
  const libTotal     = filteredLib.length;
  const libTotalPgs  = Math.max(1, Math.ceil(libTotal / LIB_PAGE_SIZE));
  const safeLibPage  = Math.min(libPage, libTotalPgs);
  const pagedLib     = useMemo(() => filteredLib.slice((safeLibPage - 1) * LIB_PAGE_SIZE, safeLibPage * LIB_PAGE_SIZE), [filteredLib, safeLibPage]);
  const libCategories = useMemo(() => ["all", ...Array.from(new Set(libQuestions.map(q => q.category).filter(Boolean)))], [libQuestions]);

  // All available questions for template builder = active DB library questions
  const allLibQs: Question[] = useMemo(() =>
    libQuestions.filter(q => q.isActive).map(q => ({
      id: `lib_${q.id}`, text: q.text, type: q.type, category: q.category,
      required: q.required, weight: q.weight, options: q.options ?? undefined,
    })),
  [libQuestions]);

  // ── Template CRUD ─────────────────────────────────────────────────────────
  const openCreate = () => {
    setForm({ name: "", description: "", category: "security" });
    const req = allLibQs.filter(q => q.required);
    setQuestions(req);
    setLibSelected(new Set(req.map(q => q.id)));
    setAddingCustom(false); setLibOpen(false); setNewQ(newQuestion());
    setShowCreate(true);
  };

  const openEdit = (t: Template) => {
    setForm({ name: t.name, description: t.description ?? "", category: t.category });
    const qs = (t.questions ?? []).map(q => ({ ...q, weight: q.weight ?? 1 }));
    setQuestions(qs);
    setLibSelected(new Set(qs.map(q => q.id)));
    setAddingCustom(false); setLibOpen(false); setNewQ(newQuestion());
    setShowEdit(t);
  };

  const closeDialog = () => { setShowCreate(false); setShowEdit(null); };

  const save = async () => {
    if (!form.name.trim() || questions.length === 0) return;
    setSaving(true);
    try {
      if (showEdit) {
        const updated = await apiFetch<Template>(`/api/tprm/questionnaire-templates/${showEdit.id}`, { method: "PATCH", body: JSON.stringify({ ...form, questions }) });
        setTemplates(prev => prev.map(t => t.id === updated.id ? updated : t));
        toast({ title: "Template updated", description: updated.name });
      } else {
        const created = await apiFetch<Template>("/api/tprm/questionnaire-templates", { method: "POST", body: JSON.stringify({ ...form, questions }) });
        setTemplates(prev => [created, ...prev]);
        toast({ title: "Template created", description: created.name });
      }
      closeDialog();
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message ?? "Could not save template", variant: "destructive" });
    }
    setSaving(false);
  };

  const del = async (t: Template) => {
    if (!confirm(`Delete "${t.name}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`/api/tprm/questionnaire-templates/${t.id}`, { method: "DELETE" });
      setTemplates(prev => prev.filter(x => x.id !== t.id));
      toast({ title: "Template deleted" });
    } catch { toast({ title: "Delete failed", variant: "destructive" }); }
  };

  const toggleActive = async (t: Template) => {
    if (t.isGlobal && !isSuperAdmin) { toast({ title: "Permission denied", variant: "destructive" }); return; }
    setTogglingId(t.id);
    const newActive = !t.isActive;
    setTemplates(prev => prev.map(x => x.id === t.id ? { ...x, isActive: newActive } : x));
    try {
      const updated = await apiFetch<Template>(`/api/tprm/questionnaire-templates/${t.id}`, { method: "PATCH", body: JSON.stringify({ isActive: newActive }) });
      setTemplates(prev => prev.map(x => x.id === updated.id ? updated : x));
      toast({ title: newActive ? "Template activated" : "Template deactivated" });
    } catch {
      setTemplates(prev => prev.map(x => x.id === t.id ? { ...x, isActive: t.isActive } : x));
      toast({ title: "Toggle failed", variant: "destructive" });
    }
    setTogglingId(null);
  };

  // ── Question builder helpers ───────────────────────────────────────────────
  const moveQ = (idx: number, dir: -1 | 1) => {
    const next = [...questions]; const target = idx + dir;
    if (target < 0 || target >= next.length) return;
    [next[idx], next[target]] = [next[target], next[idx]]; setQuestions(next);
  };
  const handleDragStart = (e: React.DragEvent, idx: number) => { setDragIdx(idx); e.dataTransfer.effectAllowed = "move"; };
  const handleDragOver  = (e: React.DragEvent, idx: number) => { e.preventDefault(); if (idx !== dragOverIdx) setDragOverIdx(idx); };
  const handleDrop      = (e: React.DragEvent, toIdx: number) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === toIdx) { setDragIdx(null); setDragOverIdx(null); return; }
    const next = [...questions]; const [moved] = next.splice(dragIdx, 1); next.splice(toIdx, 0, moved);
    setQuestions(next); setDragIdx(null); setDragOverIdx(null);
  };
  const handleDragEnd   = () => { setDragIdx(null); setDragOverIdx(null); };
  const removeQ         = (idx: number) => setQuestions(q => q.filter((_, i) => i !== idx));

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
    const val = optionInput.trim(); if (!val) return;
    setNewQ(q => ({ ...q, options: [...(q.options ?? []), val] })); setOptionInput("");
  };

  // ── Library CRUD ──────────────────────────────────────────────────────────
  const openAddLibQ = () => {
    setLibQForm({ text: "", type: "boolean", category: "", required: false, weight: 1, options: [], isGlobal: false });
    setLibOptionInput(""); setEditingLibQ(null); setShowAddLibQ(true);
  };

  const openEditLibQ = (q: LibraryQuestion) => {
    setLibQForm({ text: q.text, type: q.type, category: q.category, required: q.required, weight: q.weight, options: q.options ?? [], isGlobal: q.isGlobal });
    setLibOptionInput(""); setEditingLibQ(q); setShowAddLibQ(true);
  };

  const saveLibQ = async () => {
    if (!libQForm.text.trim()) return;
    setSavingLibQ(true);
    try {
      if (editingLibQ) {
        const updated = await apiFetch<LibraryQuestion>(`/api/tprm/question-library/${editingLibQ.id}`, { method: "PATCH", body: JSON.stringify(libQForm) });
        setLibQuestions(prev => prev.map(q => q.id === updated.id ? updated : q));
        toast({ title: "Question updated" });
      } else {
        const created = await apiFetch<LibraryQuestion>("/api/tprm/question-library", { method: "POST", body: JSON.stringify(libQForm) });
        setLibQuestions(prev => [created, ...prev]);
        toast({ title: "Question added to library" });
      }
      setShowAddLibQ(false); setEditingLibQ(null);
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message, variant: "destructive" });
    }
    setSavingLibQ(false);
  };

  const deleteLibQ = async (q: LibraryQuestion) => {
    if (!confirm(`Delete question "${q.text.slice(0, 60)}…"?`)) return;
    try {
      await apiFetch(`/api/tprm/question-library/${q.id}`, { method: "DELETE" });
      setLibQuestions(prev => prev.filter(x => x.id !== q.id));
      toast({ title: "Question deleted" });
    } catch { toast({ title: "Delete failed", variant: "destructive" }); }
  };

  const toggleLibQActive = async (q: LibraryQuestion) => {
    try {
      const updated = await apiFetch<LibraryQuestion>(`/api/tprm/question-library/${q.id}`, { method: "PATCH", body: JSON.stringify({ isActive: !q.isActive }) });
      setLibQuestions(prev => prev.map(x => x.id === updated.id ? updated : x));
    } catch { toast({ title: "Toggle failed", variant: "destructive" }); }
  };

  const addLibOption = () => { const v = libOptionInput.trim(); if (!v) return; setLibQForm(f => ({ ...f, options: [...f.options, v] })); setLibOptionInput(""); };

  const isOpen = showCreate || !!showEdit;
  const canEditGlobal = isSuperAdmin;

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Questionnaire Management</h1>
          <p className="text-muted-foreground text-sm">Manage templates, question library, and assessment workflows</p>
        </div>
        {mainTab === "templates" ? (
          <Button size="sm" onClick={openCreate}><Plus className="w-4 h-4 mr-1.5" />New Template</Button>
        ) : (
          <Button size="sm" onClick={openAddLibQ}><Plus className="w-4 h-4 mr-1.5" />Add Question</Button>
        )}
      </div>

      {/* Main tabs */}
      <div className="flex gap-1 border-b border-border/50">
        {([["templates", FileText, "Templates"], ["library", Library, "Question Library"]] as const).map(([val, Icon, label]) => (
          <button key={val} onClick={() => setMainTab(val)}
            className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${mainTab === val ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
            <Icon className="w-3.5 h-3.5" />{label}
          </button>
        ))}
      </div>

      {/* ── TEMPLATES TAB ─────────────────────────────────────────────────── */}
      {mainTab === "templates" && (
        <>
          {loadingTpl ? (
            <div className="space-y-3">{Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-20" />)}</div>
          ) : templates.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-16 text-center">
                <FileText className="w-10 h-10 mx-auto text-muted-foreground mb-3" />
                <p className="text-sm font-medium">No templates yet</p>
                <p className="text-xs text-muted-foreground mt-1">Create a template to send questionnaires to vendors</p>
                <Button size="sm" className="mt-4" onClick={openCreate}><Plus className="w-4 h-4 mr-1.5" />New Template</Button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="divide-y divide-border/40">
                  {pagedTpl.map(t => {
                    const qs         = t.questions as Question[];
                    const isExpanded = expanded === t.id;
                    const canEdit    = !t.isGlobal || canEditGlobal;
                    const isToggling = togglingId === t.id;
                    return (
                      <div key={t.id} className="p-4 hover:bg-accent/10 transition-colors">
                        <div className="flex items-start gap-3">
                          <FileText className={`w-5 h-5 shrink-0 mt-0.5 ${t.isActive ? "text-primary" : "text-muted-foreground/40"}`} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <p className={`text-sm font-semibold ${!t.isActive ? "text-muted-foreground line-through" : ""}`}>{t.name}</p>
                              {t.isGlobal && <Badge variant="secondary" className="text-[10px]">Global</Badge>}
                              <Badge variant="outline" className="text-[10px] capitalize">{t.category.replace(/_/g, " ")}</Badge>
                              <Badge variant={t.isActive ? "default" : "secondary"} className={`text-[10px] ${t.isActive ? "bg-green-500/20 text-green-400 border-green-500/30" : "bg-slate-500/20 text-slate-400"}`}>
                                {t.isActive ? "Active" : "Inactive"}
                              </Badge>
                            </div>
                            {t.description && <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-[500px]">{t.description}</p>}
                            <p className="text-xs text-muted-foreground mt-0.5">
                              {qs.length} question{qs.length !== 1 ? "s" : ""} · Updated {new Date(t.updatedAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                            </p>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <div className="flex items-center gap-1.5" title={t.isActive ? "Deactivate" : "Activate"}>
                              <span className="text-[10px] text-muted-foreground hidden sm:block">{t.isActive ? "Active" : "Inactive"}</span>
                              {isToggling ? <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" /> : (
                                <Switch checked={t.isActive} onCheckedChange={() => toggleActive(t)} disabled={t.isGlobal && !canEditGlobal} className="scale-75" />
                              )}
                            </div>
                            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setExpanded(isExpanded ? null : t.id)}>
                              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </Button>
                            {canEdit && (
                              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEdit(t)} title="Edit template">
                                <Edit2 className="w-3.5 h-3.5" />
                              </Button>
                            )}
                            {!t.isGlobal && (
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => del(t)} title="Delete template">
                                <Trash2 className="w-3.5 h-3.5" />
                              </Button>
                            )}
                          </div>
                        </div>
                        {isExpanded && (
                          <div className="mt-3 space-y-1.5 pl-8 border-t border-border/30 pt-3">
                            {qs.length === 0 ? (
                              <p className="text-xs text-muted-foreground italic">No questions</p>
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
                <SmartPagination page={safeTplPage} totalPages={tplTotalPgs} total={tplTotal} pageSize={PAGE_SIZE} onPage={setTplPage} />
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* ── QUESTION LIBRARY TAB ──────────────────────────────────────────── */}
      {mainTab === "library" && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <p className="text-sm text-muted-foreground flex-1">
              {libQuestions.length} question{libQuestions.length !== 1 ? "s" : ""} in library · edit, delete, or enable/disable any question · all questions appear in the template builder
            </p>
            <Select value={libCategoryFilter} onValueChange={v => { setLibCategoryFilter(v); setLibPage(1); }}>
              <SelectTrigger className="h-8 text-xs w-40"><SelectValue placeholder="All categories" /></SelectTrigger>
              <SelectContent>
                {libCategories.map(c => <SelectItem key={c} value={c}>{c === "all" ? "All categories" : c}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>

          {/* All library questions — edit, delete, enable/disable any question */}
          {loadingLib ? (
            <Skeleton className="h-40" />
          ) : filteredLib.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center">
                <Library className="w-8 h-8 mx-auto text-muted-foreground mb-2" />
                <p className="text-sm font-medium">No questions found</p>
                <p className="text-xs text-muted-foreground mt-1">Add a new question or change the category filter</p>
                <Button size="sm" className="mt-4" onClick={openAddLibQ}><Plus className="w-4 h-4 mr-1.5" />Add Question</Button>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="p-0">
                <div className="divide-y divide-border/40">
                  {pagedLib.map(q => (
                    <div key={q.id} className={`p-3 hover:bg-accent/10 transition-colors ${!q.isActive ? "opacity-50" : ""}`}>
                      <div className="flex items-start gap-3">
                        <div className="flex-1 min-w-0">
                          <p className={`text-sm ${!q.isActive ? "line-through text-muted-foreground" : ""}`}>{q.text}</p>
                          <div className="flex gap-1.5 mt-1 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                            {q.category && <Badge variant="outline" className="text-[10px]">{q.category}</Badge>}
                            {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                            {(q.weight ?? 1) > 1 && <Badge variant="secondary" className="text-[10px]">Weight: {q.weight}</Badge>}
                            {q.isGlobal
                              ? <Badge className="text-[10px] bg-blue-500/15 text-blue-400 border-blue-500/30">Default</Badge>
                              : <Badge variant="outline" className="text-[10px] text-violet-400 border-violet-500/30">Custom</Badge>
                            }
                            <Badge className={`text-[10px] ${q.isActive ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-slate-500/15 text-slate-400 border-slate-500/30"}`}>
                              {q.isActive ? "Enabled" : "Disabled"}
                            </Badge>
                          </div>
                          {q.options && q.options.length > 0 && (
                            <p className="text-[10px] text-muted-foreground mt-0.5">Options: {q.options.join(", ")}</p>
                          )}
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          <Switch
                            checked={q.isActive}
                            onCheckedChange={() => toggleLibQActive(q)}
                            className="scale-75"
                            title={q.isActive ? "Disable question" : "Enable question"}
                          />
                          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEditLibQ(q)} title="Edit question">
                            <Edit2 className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                            onClick={() => deleteLibQ(q)}
                            title="Delete question"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
                <SmartPagination page={safeLibPage} totalPages={libTotalPgs} total={libTotal} pageSize={LIB_PAGE_SIZE} onPage={setLibPage} />
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ── Create / Edit Template Dialog ─────────────────────────────────── */}
      {isOpen && (
        <Dialog open onOpenChange={closeDialog}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{showEdit ? `Edit Template: ${showEdit.name}` : "Create Template"}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4">
              <div>
                <Label className="text-xs">Name *</Label>
                <Input className="mt-1" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Annual Security Review" />
              </div>
              <div>
                <Label className="text-xs">Category</Label>
                <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["security","privacy","compliance","business_continuity","due_diligence"].map(c => (
                      <SelectItem key={c} value={c}>{c.replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase())}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Description</Label>
                <Textarea className="mt-1 text-sm" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Brief description…" />
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

                {/* Library picker — shows BUILTIN + DB library */}
                {libOpen && (
                  <div className="mb-3 border rounded-md p-2 space-y-1 max-h-56 overflow-y-auto bg-muted/20">
                    {allLibQs.map(q => (
                      <label key={q.id} className="flex items-start gap-2 cursor-pointer p-1 rounded hover:bg-accent/30">
                        <input type="checkbox" className="mt-0.5 shrink-0 accent-primary" checked={libSelected.has(q.id)} onChange={() => toggleLibQ(q)} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs">{q.text}</p>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type]}</Badge>
                            <Badge variant="outline" className="text-[10px]">{q.category}</Badge>
                            {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                            <Badge variant="outline" className="text-[10px] text-blue-400 border-blue-500/30">Library</Badge>
                          </div>
                        </div>
                      </label>
                    ))}
                  </div>
                )}

                {/* Custom question form */}
                {addingCustom && (
                  <div className="mb-3 border rounded-md p-3 space-y-3 bg-muted/20">
                    <p className="text-xs font-medium">Add Custom Question</p>
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
                            {(Object.entries(QUESTION_TYPE_LABELS) as [QuestionType, string][]).map(([k, v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label className="text-[10px]">Category</Label>
                        <Input className="mt-1 h-7 text-xs" value={newQ.category} onChange={e => setNewQ(q => ({ ...q, category: e.target.value }))} placeholder="e.g. access_control" />
                      </div>
                      <div>
                        <Label className="text-[10px]">Weight (1–5)</Label>
                        <Input type="number" min={1} max={5} className="mt-1 h-7 text-xs" value={newQ.weight} onChange={e => setNewQ(q => ({ ...q, weight: Math.max(1, Math.min(5, parseInt(e.target.value) || 1)) }))} />
                      </div>
                      <div className="flex items-end pb-1">
                        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                          <input type="checkbox" className="accent-primary" checked={newQ.required} onChange={e => setNewQ(q => ({ ...q, required: e.target.checked }))} />
                          Required
                        </label>
                      </div>
                    </div>
                    {(newQ.type === "select" || newQ.type === "multi_choice") && (
                      <div>
                        <Label className="text-[10px]">Options</Label>
                        <div className="flex gap-1 mt-1">
                          <Input className="h-7 text-xs flex-1" placeholder="Type an option…" value={optionInput} onChange={e => setOptionInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addOptionToNewQ(); } }} />
                          <Button variant="outline" size="sm" className="h-7 text-xs" onClick={addOptionToNewQ}>Add</Button>
                        </div>
                        {(newQ.options ?? []).length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {(newQ.options ?? []).map((o, i) => (
                              <span key={i} className="inline-flex items-center gap-0.5 text-[10px] border rounded px-1.5 py-0.5 bg-muted/30">
                                {o}
                                <button onClick={() => setNewQ(q => ({ ...q, options: (q.options ?? []).filter((_, j) => j !== i) }))} className="ml-0.5 hover:text-destructive">
                                  <X className="w-2.5 h-2.5" />
                                </button>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    <div className="flex gap-2 pt-1">
                      <Button size="sm" className="h-7 text-xs" onClick={commitCustomQ} disabled={!newQ.text.trim()}>Add to Template</Button>
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setAddingCustom(false); setNewQ(newQuestion()); setOptionInput(""); }}>Cancel</Button>
                    </div>
                  </div>
                )}

                {/* Ordered drag-and-drop list */}
                {questions.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-6 border rounded-md border-dashed">No questions yet — add from the library or create custom ones</p>
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
                        <GripVertical className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5 cursor-grab" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs"><span className="text-muted-foreground mr-1">{i + 1}.</span>{q.text || <span className="italic text-muted-foreground">empty</span>}</p>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                            {q.category && <Badge variant="outline" className="text-[10px]">{q.category}</Badge>}
                            {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                            {(q.weight ?? 1) > 1 && <Badge variant="secondary" className="text-[10px]">w:{q.weight}</Badge>}
                          </div>
                        </div>
                        <div className="flex gap-0.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                          <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => moveQ(i, -1)} disabled={i === 0}><ChevronUp className="w-3 h-3" /></Button>
                          <Button variant="ghost" size="icon" className="h-5 w-5" onClick={() => moveQ(i, 1)} disabled={i === questions.length - 1}><ChevronDown className="w-3 h-3" /></Button>
                          <Button variant="ghost" size="icon" className="h-5 w-5 text-destructive" onClick={() => removeQ(i)}><X className="w-3 h-3" /></Button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={closeDialog}>Cancel</Button>
              <Button onClick={save} disabled={saving || !form.name.trim() || questions.length === 0}>
                {saving ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Save className="w-4 h-4 mr-1" />}
                {showEdit ? "Update Template" : "Create Template"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* ── Add / Edit Library Question Dialog ──────────────────────────────── */}
      <Dialog open={showAddLibQ} onOpenChange={o => { if (!o) { setShowAddLibQ(false); setEditingLibQ(null); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Library className="w-4 h-4" />{editingLibQ ? "Edit Library Question" : "Add to Question Library"}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Question Text *</Label>
              <Textarea className="mt-1 text-sm" rows={2} value={libQForm.text} onChange={e => setLibQForm(f => ({ ...f, text: e.target.value }))} placeholder="e.g. Is the vendor ISO 27001 certified?" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Answer Type</Label>
                <Select value={libQForm.type} onValueChange={v => setLibQForm(f => ({ ...f, type: v as QuestionType, options: [] }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {(Object.entries(QUESTION_TYPE_LABELS) as [QuestionType, string][]).map(([k, v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Category</Label>
                <Input className="mt-1 h-8 text-sm" value={libQForm.category} onChange={e => setLibQForm(f => ({ ...f, category: e.target.value }))} placeholder="e.g. Compliance, Access Control" />
              </div>
              <div>
                <Label className="text-xs">Weight (1–5)</Label>
                <Input type="number" min={1} max={5} className="mt-1 h-8 text-sm" value={libQForm.weight} onChange={e => setLibQForm(f => ({ ...f, weight: Math.max(1, Math.min(5, parseInt(e.target.value) || 1)) }))} />
              </div>
              <div className="flex items-end pb-1 gap-4">
                <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                  <input type="checkbox" className="accent-primary" checked={libQForm.required} onChange={e => setLibQForm(f => ({ ...f, required: e.target.checked }))} />
                  Required
                </label>
                {isSuperAdmin && (
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <input type="checkbox" className="accent-primary" checked={libQForm.isGlobal} onChange={e => setLibQForm(f => ({ ...f, isGlobal: e.target.checked }))} />
                    Global
                  </label>
                )}
              </div>
            </div>
            {(libQForm.type === "select" || libQForm.type === "multi_choice") && (
              <div>
                <Label className="text-xs">Answer Options</Label>
                <div className="flex gap-1 mt-1">
                  <Input className="h-8 text-sm flex-1" placeholder="Type an option and press Enter…" value={libOptionInput} onChange={e => setLibOptionInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addLibOption(); } }} />
                  <Button variant="outline" size="sm" className="h-8" onClick={addLibOption}>Add</Button>
                </div>
                {libQForm.options.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {libQForm.options.map((o, i) => (
                      <span key={i} className="inline-flex items-center gap-0.5 text-[10px] border rounded px-1.5 py-0.5 bg-muted/30">
                        {o}
                        <button onClick={() => setLibQForm(f => ({ ...f, options: f.options.filter((_, j) => j !== i) }))} className="ml-0.5 hover:text-destructive">
                          <X className="w-2.5 h-2.5" />
                        </button>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowAddLibQ(false); setEditingLibQ(null); }}>Cancel</Button>
            <Button onClick={saveLibQ} disabled={savingLibQ || !libQForm.text.trim()}>
              {savingLibQ ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Save className="w-4 h-4 mr-1" />}
              {editingLibQ ? "Update Question" : "Add to Library"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
