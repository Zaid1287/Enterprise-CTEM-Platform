import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Plus, Trash2, Edit2, Loader2, FileText, ChevronDown, ChevronUp } from "lucide-react";

interface Question {
  id: string;
  text: string;
  type: "boolean" | "text" | "rating" | "select";
  category: string;
  required: boolean;
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

const BUILT_IN_QUESTIONS: Question[] = [
  { id: "q1",  text: "Does the vendor have an information security policy?", type: "boolean", category: "governance", required: true },
  { id: "q2",  text: "Is the vendor ISO 27001 certified?", type: "boolean", category: "compliance", required: true },
  { id: "q3",  text: "Does the vendor perform annual penetration testing?", type: "boolean", category: "testing", required: true },
  { id: "q4",  text: "Does the vendor encrypt data at rest?", type: "boolean", category: "data_protection", required: true },
  { id: "q5",  text: "Does the vendor encrypt data in transit?", type: "boolean", category: "data_protection", required: true },
  { id: "q6",  text: "Does the vendor have a formal incident response plan?", type: "boolean", category: "incident_response", required: true },
  { id: "q7",  text: "Does the vendor perform background checks on employees?", type: "boolean", category: "hr_security", required: false },
  { id: "q8",  text: "Does the vendor use multi-factor authentication?", type: "boolean", category: "access_control", required: true },
  { id: "q9",  text: "Rate the vendor's security maturity level (1–5)", type: "rating", category: "maturity", required: false },
  { id: "q10", text: "Does the vendor have SOC 2 Type II certification?", type: "boolean", category: "compliance", required: false },
  { id: "q11", text: "What is the vendor's SLA for critical security incidents (hours)?", type: "text", category: "incident_response", required: false },
  { id: "q12", text: "Does the vendor maintain a vulnerability disclosure program?", type: "boolean", category: "vulnerability_mgmt", required: false },
];

export default function TprmQuestionnaireTemplatesPage() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading]     = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit]   = useState<Template | null>(null);
  const [expanded, setExpanded]   = useState<number | null>(null);
  const [form, setForm]           = useState({ name: "", description: "", category: "security" });
  const [selectedQIds, setSelectedQIds] = useState<Set<string>>(new Set());
  const [saving, setSaving]       = useState(false);

  const load = () => {
    setLoading(true);
    apiFetch<Template[]>("/api/tprm/questionnaire-templates")
      .then(setTemplates)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const openCreate = () => {
    setForm({ name: "", description: "", category: "security" });
    setSelectedQIds(new Set(BUILT_IN_QUESTIONS.filter(q => q.required).map(q => q.id)));
    setShowCreate(true);
  };

  const save = async () => {
    if (!form.name) return;
    setSaving(true);
    const questions = BUILT_IN_QUESTIONS.filter(q => selectedQIds.has(q.id));
    try {
      await apiFetch("/api/tprm/questionnaire-templates", { method: "POST", body: JSON.stringify({ ...form, questions }) });
      setShowCreate(false);
      load();
    } catch { /* ignore */ }
    setSaving(false);
  };

  const saveEdit = async () => {
    if (!showEdit || !form.name) return;
    setSaving(true);
    const questions = BUILT_IN_QUESTIONS.filter(q => selectedQIds.has(q.id));
    try {
      await apiFetch(`/api/tprm/questionnaire-templates/${showEdit.id}`, { method: "PATCH", body: JSON.stringify({ ...form, questions }) });
      setShowEdit(null);
      load();
    } catch { /* ignore */ }
    setSaving(false);
  };

  const del = async (id: number) => {
    if (!confirm("Delete this template?")) return;
    await apiFetch(`/api/tprm/questionnaire-templates/${id}`, { method: "DELETE" });
    load();
  };

  const openEdit = (t: Template) => {
    setForm({ name: t.name, description: t.description ?? "", category: t.category });
    setSelectedQIds(new Set((t.questions as Question[]).map(q => q.id)));
    setShowEdit(t);
  };

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
                    <div className="flex items-center gap-2">
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
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEdit(t)}><Edit2 className="w-3.5 h-3.5" /></Button>
                    {!t.isGlobal && <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive" onClick={() => del(t.id)}><Trash2 className="w-3.5 h-3.5" /></Button>}
                  </div>
                </div>
                {expanded === t.id && (
                  <div className="mt-3 space-y-1.5 pl-8">
                    {(t.questions as Question[]).map((q, i) => (
                      <div key={q.id} className="flex items-start gap-2 text-sm">
                        <span className="text-muted-foreground w-5 shrink-0 text-xs">{i + 1}.</span>
                        <span className="flex-1">{q.text}</span>
                        <Badge variant="outline" className="text-[10px] shrink-0">{q.type}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* Create/Edit Dialog */}
      {(showCreate || showEdit) && (
        <Dialog open onOpenChange={() => { setShowCreate(false); setShowEdit(null); }}>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
            <DialogHeader><DialogTitle>{showCreate ? "Create Template" : "Edit Template"}</DialogTitle></DialogHeader>
            <div className="space-y-4">
              <div><Label className="text-xs">Name *</Label><Input className="mt-1" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} /></div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <Label className="text-xs">Category</Label>
                  <Select value={form.category} onValueChange={v => setForm(f => ({ ...f, category: v }))}>
                    <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="security">Security</SelectItem>
                      <SelectItem value="privacy">Privacy</SelectItem>
                      <SelectItem value="compliance">Compliance</SelectItem>
                      <SelectItem value="business_continuity">Business Continuity</SelectItem>
                      <SelectItem value="due_diligence">Due Diligence</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div><Label className="text-xs">Description</Label><Textarea className="mt-1 text-sm" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} /></div>
              <div>
                <Label className="text-xs">Questions</Label>
                <p className="text-xs text-muted-foreground mt-0.5 mb-2">Select from the built-in question library. Required questions are pre-selected.</p>
                <div className="space-y-1.5 max-h-64 overflow-y-auto border rounded-md p-2">
                  {BUILT_IN_QUESTIONS.map(q => (
                    <label key={q.id} className="flex items-start gap-2 cursor-pointer p-1.5 rounded hover:bg-accent/30">
                      <input type="checkbox" className="mt-0.5" checked={selectedQIds.has(q.id)} onChange={e => {
                        const next = new Set(selectedQIds);
                        if (e.target.checked) next.add(q.id); else next.delete(q.id);
                        setSelectedQIds(next);
                      }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs">{q.text}</p>
                        <div className="flex gap-1 mt-0.5">
                          <Badge variant="outline" className="text-[10px]">{q.type}</Badge>
                          <Badge variant="outline" className="text-[10px]">{q.category}</Badge>
                          {q.required && <Badge variant="secondary" className="text-[10px]">Required</Badge>}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground mt-1">{selectedQIds.size} question{selectedQIds.size !== 1 ? "s" : ""} selected</p>
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => { setShowCreate(false); setShowEdit(null); }}>Cancel</Button>
              <Button onClick={showCreate ? save : saveEdit} disabled={saving || !form.name}>
                {saving && <Loader2 className="w-4 h-4 mr-1 animate-spin" />} Save Template
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
