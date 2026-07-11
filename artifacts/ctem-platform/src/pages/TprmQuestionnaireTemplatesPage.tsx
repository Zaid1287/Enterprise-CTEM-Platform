import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Plus, Trash2, Edit2, Loader2, FileText, ChevronDown, ChevronUp, GripVertical, X } from "lucide-react";

type QuestionType = "boolean" | "text" | "rating" | "select" | "multi_choice" | "file_upload";

interface Question {
  id: string;
  text: string;
  type: QuestionType;
  category: string;
  required: boolean;
  weight: number;
  options?: string[];
}

interface Template {
  id: number;
  name: string;
  description: string | null;
  category: string;
  questions: Question[];
  isGlobal: boolean;
  createdAt: string;
}

const QUESTION_TYPE_LABELS: Record<QuestionType, string> = {
  boolean:     "Yes / No",
  text:        "Free Text",
  rating:      "Rating (1–5)",
  select:      "Single Choice",
  multi_choice:"Multi Choice",
  file_upload: "File Upload",
};

const BUILTIN_QUESTIONS: Question[] = [
  { id: "bq1",  text: "Does the vendor have an information security policy?",            type: "boolean",  category: "governance",          required: true,  weight: 2 },
  { id: "bq2",  text: "Is the vendor ISO 27001 certified?",                              type: "boolean",  category: "compliance",          required: true,  weight: 2 },
  { id: "bq3",  text: "Does the vendor perform annual penetration testing?",             type: "boolean",  category: "testing",             required: true,  weight: 2 },
  { id: "bq4",  text: "Does the vendor encrypt data at rest?",                           type: "boolean",  category: "data_protection",     required: true,  weight: 2 },
  { id: "bq5",  text: "Does the vendor encrypt data in transit?",                        type: "boolean",  category: "data_protection",     required: true,  weight: 2 },
  { id: "bq6",  text: "Does the vendor have a formal incident response plan?",           type: "boolean",  category: "incident_response",   required: true,  weight: 2 },
  { id: "bq7",  text: "Does the vendor perform background checks on employees?",         type: "boolean",  category: "hr_security",         required: false, weight: 1 },
  { id: "bq8",  text: "Does the vendor use multi-factor authentication?",                type: "boolean",  category: "access_control",      required: true,  weight: 2 },
  { id: "bq9",  text: "Rate the vendor's overall security maturity level (1–5)",         type: "rating",   category: "maturity",            required: false, weight: 3 },
  { id: "bq10", text: "Does the vendor have SOC 2 Type II certification?",               type: "boolean",  category: "compliance",          required: false, weight: 2 },
  { id: "bq11", text: "What is the vendor's SLA for critical security incidents (hrs)?", type: "text",     category: "incident_response",   required: false, weight: 1 },
  { id: "bq12", text: "Does the vendor maintain a vulnerability disclosure program?",    type: "boolean",  category: "vulnerability_mgmt",  required: false, weight: 1 },
  { id: "bq13", text: "Which compliance frameworks does the vendor adhere to?",          type: "multi_choice", category: "compliance",       required: false, weight: 1, options: ["ISO 27001","SOC 2","PCI DSS","HIPAA","GDPR","NIST CSF","CIS Controls"] },
  { id: "bq14", text: "Please upload the latest third-party audit report",               type: "file_upload",  category: "compliance",       required: false, weight: 2 },
];

function newQuestion(): Question {
  return { id: `cq_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`, text: "", type: "boolean", category: "general", required: false, weight: 1 };
}

export default function TprmQuestionnaireTemplatesPage() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit]   = useState<Template | null>(null);
  const [expanded, setExpanded]   = useState<number | null>(null);
  const [saving, setSaving]       = useState(false);

  const [form, setForm]           = useState({ name: "", description: "", category: "security" });
  const [questions, setQuestions] = useState<Question[]>([]);
  const [newQ, setNewQ]           = useState<Question>(newQuestion());
  const [addingCustom, setAddingCustom] = useState(false);
  const [optionInput, setOptionInput]   = useState("");
  const [libOpen, setLibOpen]     = useState(false);
  const [libSelected, setLibSelected] = useState<Set<string>>(new Set());

  const load = () => {
    setLoading(true);
    apiFetch<Template[]>("/api/tprm/questionnaire-templates").then(setTemplates).catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

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
    const qs = t.questions as Question[];
    setQuestions(qs.map(q => ({ ...q, weight: q.weight ?? 1 })));
    setLibSelected(new Set(qs.map(q => q.id)));
    setAddingCustom(false);
    setLibOpen(false);
    setNewQ(newQuestion());
    setShowEdit(t);
  };

  const closeDialog = () => { setShowCreate(false); setShowEdit(null); };

  const save = async () => {
    if (!form.name || questions.length === 0) return;
    setSaving(true);
    try {
      if (showEdit) {
        await apiFetch(`/api/tprm/questionnaire-templates/${showEdit.id}`, { method: "PATCH", body: JSON.stringify({ ...form, questions }) });
      } else {
        await apiFetch("/api/tprm/questionnaire-templates", { method: "POST", body: JSON.stringify({ ...form, questions }) });
      }
      closeDialog();
      load();
    } catch { /* ignore */ }
    setSaving(false);
  };

  const del = async (id: number) => {
    if (!confirm("Delete this template?")) return;
    await apiFetch(`/api/tprm/questionnaire-templates/${id}`, { method: "DELETE" });
    load();
  };

  const moveQ = (idx: number, dir: -1 | 1) => {
    const next = [...questions];
    const target = idx + dir;
    if (target < 0 || target >= next.length) return;
    [next[idx], next[target]] = [next[target], next[idx]];
    setQuestions(next);
  };

  const removeQ = (idx: number) => setQuestions(q => q.filter((_, i) => i !== idx));

  const commitCustomQ = () => {
    if (!newQ.text.trim()) return;
    setQuestions(prev => [...prev, { ...newQ }]);
    setNewQ(newQuestion());
    setOptionInput("");
    setAddingCustom(false);
  };

  const toggleLibQ = (q: Question) => {
    const next = new Set(libSelected);
    if (next.has(q.id)) {
      next.delete(q.id);
      setQuestions(prev => prev.filter(p => p.id !== q.id));
    } else {
      next.add(q.id);
      setQuestions(prev => [...prev, q]);
    }
    setLibSelected(next);
  };

  const addOptionToNewQ = () => {
    const val = optionInput.trim();
    if (!val) return;
    setNewQ(q => ({ ...q, options: [...(q.options ?? []), val] }));
    setOptionInput("");
  };

  const isOpen = showCreate || !!showEdit;

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Questionnaire Templates</h1>
          <p className="text-muted-foreground text-sm">Build security assessment questionnaires for vendor portals</p>
        </div>
        <Button size="sm" onClick={openCreate}><Plus className="w-4 h-4 mr-1.5" />New Template</Button>
      </div>

      {loading ? (
        <div className="space-y-3">{Array(3).fill(0).map((_, i) => <Skeleton key={i} className="h-24" />)}</div>
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
        <div className="space-y-3">
          {templates.map(t => (
            <Card key={t.id} className="bg-card/60">
              <CardContent className="py-3">
                <div className="flex items-center gap-3">
                  <FileText className="w-5 h-5 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold">{t.name}</p>
                      {t.isGlobal && <Badge variant="secondary" className="text-[10px]">Global</Badge>}
                      <Badge variant="outline" className="text-[10px]">{t.category}</Badge>
                    </div>
                    {t.description && <p className="text-xs text-muted-foreground mt-0.5">{t.description}</p>}
                    <p className="text-xs text-muted-foreground mt-0.5">{(t.questions as Question[]).length} question{(t.questions as Question[]).length !== 1 ? "s" : ""}</p>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setExpanded(expanded === t.id ? null : t.id)}>
                      {expanded === t.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </Button>
                    {!t.isGlobal && <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEdit(t)}><Edit2 className="w-3.5 h-3.5" /></Button>}
                    {!t.isGlobal && <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => del(t.id)}><Trash2 className="w-3.5 h-3.5" /></Button>}
                  </div>
                </div>
                {expanded === t.id && (
                  <div className="mt-3 space-y-1.5 pl-8">
                    {(t.questions as Question[]).map((q, i) => (
                      <div key={q.id} className="flex items-start gap-2 text-sm">
                        <span className="text-muted-foreground w-5 shrink-0 text-xs">{i + 1}.</span>
                        <span className="flex-1 text-xs">{q.text}</span>
                        <Badge variant="outline" className="text-[10px] shrink-0">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                        {(q.weight ?? 1) > 1 && <Badge variant="secondary" className="text-[10px] shrink-0">w:{q.weight}</Badge>}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {isOpen && (
        <Dialog open onOpenChange={closeDialog}>
          <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
            <DialogHeader><DialogTitle>{showEdit ? "Edit Template" : "Create Template"}</DialogTitle></DialogHeader>
            <div className="space-y-4">

              {/* Metadata */}
              <div><Label className="text-xs">Name *</Label><Input className="mt-1" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></div>
              <div className="grid grid-cols-2 gap-3">
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
              </div>
              <div><Label className="text-xs">Description</Label><Textarea className="mt-1 text-sm" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} /></div>

              {/* Question list */}
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

                {/* Built-in library picker */}
                {libOpen && (
                  <div className="mb-3 border rounded-md p-2 space-y-1 max-h-48 overflow-y-auto bg-muted/20">
                    <p className="text-[10px] text-muted-foreground mb-1">Click to add/remove pre-built questions:</p>
                    {BUILTIN_QUESTIONS.map(q => (
                      <label key={q.id} className="flex items-start gap-2 cursor-pointer p-1 rounded hover:bg-accent/30">
                        <input type="checkbox" className="mt-0.5 shrink-0" checked={libSelected.has(q.id)} onChange={() => toggleLibQ(q)} />
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
                    <p className="text-xs font-medium">New Custom Question</p>
                    <div><Label className="text-[10px]">Question Text *</Label><Textarea className="mt-1 text-xs" rows={2} value={newQ.text} onChange={e => setNewQ(q => ({ ...q, text: e.target.value }))} /></div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <Label className="text-[10px]">Type</Label>
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
                        <Input className="mt-1 h-7 text-xs" value={newQ.category} onChange={e => setNewQ(q => ({ ...q, category: e.target.value }))} />
                      </div>
                      <div>
                        <Label className="text-[10px]">Weight (1–5)</Label>
                        <Input type="number" min={1} max={5} className="mt-1 h-7 text-xs" value={newQ.weight} onChange={e => setNewQ(q => ({ ...q, weight: Math.max(1, Math.min(5, parseInt(e.target.value) || 1)) }))} />
                      </div>
                      <div className="flex items-end pb-1">
                        <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                          <input type="checkbox" checked={newQ.required} onChange={e => setNewQ(q => ({ ...q, required: e.target.checked }))} />
                          Required
                        </label>
                      </div>
                    </div>
                    {(newQ.type === "select" || newQ.type === "multi_choice") && (
                      <div>
                        <Label className="text-[10px]">Options</Label>
                        <div className="flex gap-1 mt-1">
                          <Input className="h-7 text-xs flex-1" placeholder="Add option…" value={optionInput} onChange={e => setOptionInput(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addOptionToNewQ(); }}} />
                          <Button variant="outline" size="sm" className="h-7 text-xs" onClick={addOptionToNewQ}>Add</Button>
                        </div>
                        {(newQ.options ?? []).length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {(newQ.options ?? []).map((o, i) => (
                              <span key={i} className="inline-flex items-center gap-0.5 text-[10px] border rounded px-1.5 py-0.5">
                                {o}<button onClick={() => setNewQ(q => ({ ...q, options: (q.options ?? []).filter((_, j) => j !== i) }))} className="ml-0.5 text-muted-foreground hover:text-destructive"><X className="w-2.5 h-2.5" /></button>
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    )}
                    <div className="flex gap-2 pt-1">
                      <Button size="sm" className="h-7 text-xs" onClick={commitCustomQ} disabled={!newQ.text.trim()}>Add Question</Button>
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setAddingCustom(false); setNewQ(newQuestion()); setOptionInput(""); }}>Cancel</Button>
                    </div>
                  </div>
                )}

                {/* Ordered question list */}
                {questions.length === 0 ? (
                  <p className="text-xs text-muted-foreground text-center py-4 border rounded-md border-dashed">No questions yet — add from the library or create custom ones above</p>
                ) : (
                  <div className="space-y-1.5 max-h-56 overflow-y-auto border rounded-md p-2">
                    {questions.map((q, i) => (
                      <div key={q.id} className="flex items-start gap-1.5 p-1.5 rounded hover:bg-accent/20 group">
                        <GripVertical className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs truncate">{q.text || <span className="text-muted-foreground italic">empty</span>}</p>
                          <div className="flex gap-1 mt-0.5 flex-wrap">
                            <Badge variant="outline" className="text-[10px]">{QUESTION_TYPE_LABELS[q.type] ?? q.type}</Badge>
                            {q.required && <Badge variant="secondary" className="text-[10px]">Req</Badge>}
                            {(q.weight ?? 1) > 1 && <Badge variant="outline" className="text-[10px]">w:{q.weight}</Badge>}
                          </div>
                        </div>
                        <div className="flex flex-col opacity-0 group-hover:opacity-100 transition-opacity">
                          <button onClick={() => moveQ(i, -1)} disabled={i === 0} className="text-muted-foreground hover:text-foreground disabled:opacity-30"><ChevronUp className="w-3 h-3" /></button>
                          <button onClick={() => moveQ(i, 1)} disabled={i === questions.length - 1} className="text-muted-foreground hover:text-foreground disabled:opacity-30"><ChevronDown className="w-3 h-3" /></button>
                        </div>
                        <button onClick={() => removeQ(i)} className="opacity-0 group-hover:opacity-100 text-muted-foreground hover:text-destructive transition-opacity shrink-0"><X className="w-3.5 h-3.5" /></button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <DialogFooter className="mt-2">
              <Button variant="outline" onClick={closeDialog}>Cancel</Button>
              <Button onClick={save} disabled={saving || !form.name || questions.length === 0}>
                {saving && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save Template
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
