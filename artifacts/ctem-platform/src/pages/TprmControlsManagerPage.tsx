import { useEffect, useState, useMemo } from "react";
import { useSearch, Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import {
  ArrowLeft, RefreshCw, Plus, Edit2, Trash2, Loader2,
  ClipboardList, Shield, ChevronDown, ChevronUp, CheckCircle2,
  AlertTriangle, Database,
} from "lucide-react";

const FRAMEWORKS = [
  { value: "iso27001", label: "ISO 27001:2022" },
  { value: "soc2",     label: "SOC 2" },
  { value: "pcidss",   label: "PCI DSS v4.0" },
  { value: "hipaa",    label: "HIPAA" },
  { value: "nist_csf", label: "NIST CSF 2.0" },
];

const CTRL_STATUS_MAP: Record<string, { label: string; color: string; border: string }> = {
  compliant:      { label: "Compliant",     color: "text-green-400",  border: "border-green-500/30"  },
  partial:        { label: "Partial",        color: "text-yellow-400", border: "border-yellow-500/30" },
  non_compliant:  { label: "Non-Compliant",  color: "text-red-400",   border: "border-red-500/30"    },
  pending_review: { label: "Pending Review", color: "text-blue-400",  border: "border-blue-500/30"   },
  not_applicable: { label: "N/A",            color: "text-slate-400", border: "border-slate-500/30"  },
};

interface CtrlEditForm {
  controlId: string;
  controlTitle: string;
  category: string;
  status: string;
  evidence: string;
  assignedTo: string;
  notes: string;
  isActive: boolean;
}

const BLANK_FORM: CtrlEditForm = {
  controlId: "", controlTitle: "", category: "",
  status: "pending_review", evidence: "",
  assignedTo: "", notes: "", isActive: true,
};

export default function TprmControlsManagerPage() {
  const { toast } = useToast();
  const search = new URLSearchParams(useSearch());

  // Vendor + framework state (from query params or selectors)
  const [vendors, setVendors]         = useState<any[]>([]);
  const [vendorId, setVendorId]       = useState<string>(search.get("vendor") ?? "");
  const [framework, setFramework]     = useState(search.get("framework") ?? "iso27001");
  const [vendorsLoading, setVendorsLoading] = useState(true);

  // Controls state
  const [controls, setControls]       = useState<any[]>([]);
  const [ctrlsLoading, setCtrlsLoading] = useState(false);
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set());

  // Edit dialog
  const [editCtrl, setEditCtrl]       = useState<any | null>(null);
  const [editForm, setEditForm]       = useState<CtrlEditForm>(BLANK_FORM);
  const [saving, setSaving]           = useState(false);

  // Add new control dialog
  const [showAdd, setShowAdd]         = useState(false);
  const [addForm, setAddForm]         = useState<CtrlEditForm>(BLANK_FORM);
  const [adding, setAdding]           = useState(false);

  // Seed dialog
  const [showSeed, setShowSeed]       = useState(false);
  const [seeding, setSeeding]         = useState(false);

  // Toggle active
  const [togglingId, setTogglingId]   = useState<number | null>(null);

  // Users for assigned-to dropdown
  const [users, setUsers]             = useState<any[]>([]);

  // Load vendors list
  useEffect(() => {
    setVendorsLoading(true);
    apiFetch<any>("/api/tprm/vendors?limit=200")
      .then(d => setVendors(d.vendors ?? []))
      .catch(() => {})
      .finally(() => setVendorsLoading(false));
    apiFetch<any[]>("/api/users")
      .then(setUsers)
      .catch(() => {});
  }, []);

  // Auto-select first vendor if none selected
  useEffect(() => {
    if (!vendorId && vendors.length > 0) setVendorId(String(vendors[0].id));
  }, [vendors]);

  // Load controls when vendor or framework changes
  useEffect(() => {
    if (!vendorId) return;
    loadControls();
  }, [vendorId, framework]);

  const loadControls = async () => {
    if (!vendorId) return;
    setCtrlsLoading(true);
    try {
      const ctrls = await apiFetch<any[]>(
        `/api/tprm/vendors/${vendorId}/compliance-controls?framework=${framework}`
      );
      setControls(ctrls);
      // Expand all categories by default
      const cats = new Set(ctrls.map((c: any) => c.category ?? "General"));
      setExpandedCats(cats);
    } catch { /* ignore */ }
    setCtrlsLoading(false);
  };

  const selectedVendor = vendors.find(v => String(v.id) === vendorId);

  // Group controls by category
  const grouped = useMemo(() => {
    const map = new Map<string, any[]>();
    for (const c of controls) {
      const cat = c.category ?? "General";
      if (!map.has(cat)) map.set(cat, []);
      map.get(cat)!.push(c);
    }
    return [...map.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [controls]);

  const toggleCat = (cat: string) => setExpandedCats(prev => {
    const next = new Set(prev);
    next.has(cat) ? next.delete(cat) : next.add(cat);
    return next;
  });

  // Stats
  const stats = useMemo(() => {
    const total     = controls.length;
    const active    = controls.filter(c => c.isActive !== false).length;
    const compliant = controls.filter(c => c.status === "compliant" && c.isActive !== false).length;
    const partial   = controls.filter(c => c.status === "partial"   && c.isActive !== false).length;
    const nonC      = controls.filter(c => c.status === "non_compliant" && c.isActive !== false).length;
    const score     = active > 0 ? Math.round(((compliant + partial * 0.5) / active) * 100) : 0;
    return { total, active, compliant, partial, nonC, score };
  }, [controls]);

  // Open edit dialog
  const openEdit = (ctrl: any) => {
    setEditCtrl(ctrl);
    setEditForm({
      controlId:    ctrl.controlId    ?? "",
      controlTitle: ctrl.controlTitle ?? "",
      category:     ctrl.category     ?? "",
      status:       ctrl.status       ?? "pending_review",
      evidence:     ctrl.evidence     ?? "",
      assignedTo:   ctrl.assignedTo   ?? "__none__",
      notes:        ctrl.notes        ?? "",
      isActive:     ctrl.isActive     !== false,
    });
  };

  const saveEdit = async () => {
    if (!editCtrl) return;
    setSaving(true);
    try {
      const updated = await apiFetch<any>(
        `/api/tprm/vendors/${vendorId}/compliance-controls/${editCtrl.id}`,
        {
          method: "PATCH",
          body: JSON.stringify({
            controlId:    editForm.controlId    || undefined,
            controlTitle: editForm.controlTitle || undefined,
            category:     editForm.category     || undefined,
            status:       editForm.status       || undefined,
            evidence:     editForm.evidence     || undefined,
            assignedTo:   editForm.assignedTo === "__none__" ? null : (editForm.assignedTo || undefined),
            notes:        editForm.notes        || undefined,
            isActive:     editForm.isActive,
          }),
        }
      );
      setControls(prev => prev.map(c => c.id === updated.id ? { ...c, ...updated } : c));

      // Propagate controlId / controlTitle / category to ALL vendors with the same control
      const idChanged    = editForm.controlId    !== editCtrl.controlId;
      const titleChanged = editForm.controlTitle !== editCtrl.controlTitle;
      const catChanged   = editForm.category     !== (editCtrl.category ?? "");
      if (idChanged || titleChanged || catChanged) {
        await apiFetch("/api/tprm/compliance-controls/rename-all", {
          method: "PATCH",
          body: JSON.stringify({
            framework,
            oldControlId: editCtrl.controlId,
            controlId:    editForm.controlId    || undefined,
            controlTitle: editForm.controlTitle || undefined,
            category:     editForm.category     || undefined,
          }),
        });
        toast({ title: "Control updated", description: "ID / title / category applied to all vendors." });
      } else {
        toast({ title: "Control updated" });
      }
      setEditCtrl(null);
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message, variant: "destructive" });
    }
    setSaving(false);
  };

  // Add new control
  const addControl = async () => {
    if (!addForm.controlId.trim() || !addForm.controlTitle.trim()) {
      toast({ title: "Control ID and Title are required", variant: "destructive" }); return;
    }
    setAdding(true);
    try {
      const ctrl = await apiFetch<any>(
        `/api/tprm/vendors/${vendorId}/compliance-controls`,
        {
          method: "POST",
          body: JSON.stringify({
            framework,
            controlId:    addForm.controlId.trim(),
            controlTitle: addForm.controlTitle.trim(),
            category:     addForm.category.trim() || null,
            status:       addForm.status,
            evidence:     addForm.evidence  || null,
            assignedTo:   addForm.assignedTo === "__none__" ? null : (addForm.assignedTo || null),
            notes:        addForm.notes     || null,
          }),
        }
      );
      setControls(prev => [...prev, ctrl].sort((a, b) => a.controlId.localeCompare(b.controlId)));
      toast({ title: "Control added" });
      setShowAdd(false);
      setAddForm(BLANK_FORM);
    } catch (err: any) {
      toast({ title: "Create failed", description: err?.message, variant: "destructive" });
    }
    setAdding(false);
  };

  // Seed framework controls
  const seedControls = async () => {
    setSeeding(true);
    try {
      const result = await apiFetch<any>(
        `/api/tprm/vendors/${vendorId}/compliance-controls/seed`,
        { method: "POST", body: JSON.stringify({ framework }) }
      );
      toast({ title: "Controls seeded", description: result.message });
      setShowSeed(false);
      loadControls();
    } catch (err: any) {
      toast({ title: "Seed failed", description: err?.message, variant: "destructive" });
    }
    setSeeding(false);
  };

  // Toggle isActive
  const toggleActive = async (ctrl: any) => {
    setTogglingId(ctrl.id);
    try {
      const updated = await apiFetch<any>(
        `/api/tprm/vendors/${vendorId}/compliance-controls/${ctrl.id}`,
        { method: "PATCH", body: JSON.stringify({ isActive: !ctrl.isActive }) }
      );
      setControls(prev => prev.map(c => c.id === updated.id ? { ...c, isActive: updated.isActive } : c));
      toast({ title: updated.isActive ? "Control enabled" : "Control disabled" });
    } catch {
      toast({ title: "Toggle failed", variant: "destructive" });
    }
    setTogglingId(null);
  };

  // Delete control
  const deleteCtrl = async (ctrl: any) => {
    if (!confirm(`Delete control "${ctrl.controlId} — ${ctrl.controlTitle}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`/api/tprm/vendors/${vendorId}/compliance-controls/${ctrl.id}`, { method: "DELETE" });
      setControls(prev => prev.filter(c => c.id !== ctrl.id));
      toast({ title: "Control deleted" });
    } catch {
      toast({ title: "Delete failed", variant: "destructive" });
    }
  };

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Link href="/tprm/compliance">
          <Button variant="ghost" size="sm" className="h-8 px-2 text-muted-foreground hover:text-foreground">
            <ArrowLeft className="w-4 h-4 mr-1" />Back
          </Button>
        </Link>
        <div className="flex-1">
          <h1 className="text-xl font-bold flex items-center gap-2">
            <ClipboardList className="w-5 h-5" />
            Manage Compliance Controls
          </h1>
          <p className="text-sm text-muted-foreground">
            Create, edit, rename, and enable/disable controls per vendor and framework
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadControls} disabled={ctrlsLoading}>
          <RefreshCw className={`w-4 h-4 ${ctrlsLoading ? "animate-spin" : ""}`} />
        </Button>
      </div>

      {/* Vendor + Framework selectors */}
      <Card>
        <CardContent className="py-3">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex items-center gap-2 flex-1 min-w-[200px]">
              <Label className="text-xs whitespace-nowrap text-muted-foreground">Vendor</Label>
              {vendorsLoading ? (
                <Skeleton className="h-8 w-48" />
              ) : (
                <Select value={vendorId} onValueChange={setVendorId}>
                  <SelectTrigger className="h-8 text-sm flex-1">
                    <SelectValue placeholder="Select a vendor…" />
                  </SelectTrigger>
                  <SelectContent>
                    {vendors.map(v => (
                      <SelectItem key={v.id} value={String(v.id)}>
                        {v.companyName}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            <div className="flex items-center gap-2 flex-1 min-w-[180px]">
              <Label className="text-xs whitespace-nowrap text-muted-foreground">Framework</Label>
              <Select value={framework} onValueChange={setFramework}>
                <SelectTrigger className="h-8 text-sm flex-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {FRAMEWORKS.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2">
              <Button size="sm" className="h-8 gap-1.5" onClick={() => { setAddForm(BLANK_FORM); setShowAdd(true); }} disabled={!vendorId}>
                <Plus className="w-3.5 h-3.5" />Add Control
              </Button>
              <Button variant="outline" size="sm" className="h-8 gap-1.5 text-muted-foreground" onClick={() => setShowSeed(true)} disabled={!vendorId}>
                <Database className="w-3.5 h-3.5" />Seed Framework
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats bar */}
      {controls.length > 0 && (
        <div className="grid grid-cols-5 gap-2">
          {[
            { label: "Total Controls", value: stats.total,     color: "text-foreground",  bg: "bg-muted/30"       },
            { label: "Active",         value: stats.active,    color: "text-blue-400",    bg: "bg-blue-500/10"    },
            { label: "Compliant",      value: stats.compliant, color: "text-green-400",   bg: "bg-green-500/10"   },
            { label: "Partial",        value: stats.partial,   color: "text-yellow-400",  bg: "bg-yellow-500/10"  },
            { label: "Score",          value: `${stats.score}%`, color: stats.score >= 80 ? "text-green-400" : stats.score >= 50 ? "text-yellow-400" : "text-red-400", bg: "bg-muted/30" },
          ].map(s => (
            <Card key={s.label}>
              <CardContent className={`py-3 text-center ${s.bg} rounded-xl`}>
                <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
                <p className="text-[10px] text-muted-foreground">{s.label}</p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {/* No vendor selected */}
      {!vendorId && !vendorsLoading && (
        <Card className="border-dashed">
          <CardContent className="py-14 text-center text-sm text-muted-foreground">
            <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>Select a vendor above to manage their compliance controls.</p>
          </CardContent>
        </Card>
      )}

      {/* Loading */}
      {ctrlsLoading && <Skeleton className="h-64" />}

      {/* Empty state */}
      {!ctrlsLoading && vendorId && controls.length === 0 && (
        <Card className="border-dashed">
          <CardContent className="py-14 text-center text-sm text-muted-foreground">
            <ClipboardList className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p className="font-medium">No controls for this vendor + framework</p>
            <p className="text-xs mt-1 mb-4">Seed the standard framework controls or add them manually.</p>
            <div className="flex gap-2 justify-center">
              <Button size="sm" onClick={() => { setAddForm(BLANK_FORM); setShowAdd(true); }}>
                <Plus className="w-3.5 h-3.5 mr-1" />Add Control
              </Button>
              <Button variant="outline" size="sm" onClick={() => setShowSeed(true)}>
                <Database className="w-3.5 h-3.5 mr-1" />Seed {FRAMEWORKS.find(f => f.value === framework)?.label} Controls
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Controls grouped by category */}
      {!ctrlsLoading && controls.length > 0 && (
        <div className="space-y-2">
          {/* Collapse / expand all */}
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>{controls.length} control{controls.length !== 1 ? "s" : ""} in {grouped.length} categor{grouped.length !== 1 ? "ies" : "y"}</span>
            <div className="flex gap-2">
              <button onClick={() => setExpandedCats(new Set(grouped.map(([cat]) => cat)))} className="underline hover:text-foreground">Expand all</button>
              <button onClick={() => setExpandedCats(new Set())} className="underline hover:text-foreground">Collapse all</button>
            </div>
          </div>

          {grouped.map(([cat, catCtrls]) => {
            const isOpen = expandedCats.has(cat);
            const catCompliant = catCtrls.filter(c => c.status === "compliant").length;
            return (
              <Card key={cat} className={isOpen ? "border-border" : "border-border/60"}>
                <button className="w-full text-left" onClick={() => toggleCat(cat)}>
                  <CardHeader className="py-2.5 px-4">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-2 font-medium">
                        <span>{cat}</span>
                        <span className="text-xs text-muted-foreground font-normal">({catCtrls.length} controls)</span>
                        <span className={`text-xs font-medium ${catCompliant === catCtrls.length ? "text-green-400" : catCompliant > 0 ? "text-yellow-400" : "text-muted-foreground"}`}>
                          {catCompliant}/{catCtrls.length} compliant
                        </span>
                      </div>
                      {isOpen
                        ? <ChevronUp className="w-4 h-4 text-muted-foreground" />
                        : <ChevronDown className="w-4 h-4 text-muted-foreground" />
                      }
                    </div>
                  </CardHeader>
                </button>

                {isOpen && (
                  <CardContent className="pb-3 pt-0 px-4">
                    <div className="space-y-1.5 border-t border-border/40 pt-3">
                      {catCtrls.map(ctrl => {
                        const sm = CTRL_STATUS_MAP[ctrl.status] ?? CTRL_STATUS_MAP.pending_review;
                        const disabled = ctrl.isActive === false;
                        return (
                          <div key={ctrl.id} className={`flex items-start gap-3 p-3 rounded-lg border transition-colors ${disabled ? "border-border/30 bg-muted/10 opacity-60" : `border-l-2 ${sm.border} bg-muted/20 border-r border-t border-b border-border/30`}`}>
                            <div className="flex-1 min-w-0">
                              {/* Control ID + status badges */}
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs font-mono font-bold text-muted-foreground">{ctrl.controlId}</span>
                                {disabled
                                  ? <Badge variant="outline" className="text-[10px] h-4 py-0 text-slate-400 border-slate-500/30">Disabled</Badge>
                                  : <Badge variant="outline" className={`text-[10px] h-4 py-0 ${sm.color} border-current`}>{sm.label}</Badge>
                                }
                                {ctrl.category && (
                                  <Badge variant="outline" className="text-[10px] h-4 py-0">{ctrl.category}</Badge>
                                )}
                              </div>
                              {/* Title */}
                              <p className="text-sm font-medium mt-0.5">{ctrl.controlTitle}</p>
                              {/* Evidence / Assigned */}
                              <div className="flex gap-3 mt-0.5 flex-wrap">
                                {ctrl.evidence && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Evidence:</span> {ctrl.evidence}</p>}
                                {ctrl.assignedTo && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Assigned:</span> {ctrl.assignedTo}</p>}
                                {ctrl.notes && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Notes:</span> {ctrl.notes}</p>}
                              </div>
                            </div>
                            {/* Actions */}
                            <div className="flex items-center gap-1.5 shrink-0">
                              {/* Enable / Disable */}
                              <button
                                disabled={togglingId === ctrl.id}
                                onClick={() => toggleActive(ctrl)}
                                className={`text-[10px] px-2 py-1 rounded border transition-colors whitespace-nowrap ${disabled ? "border-green-500/40 text-green-400 hover:bg-green-500/10" : "border-slate-500/40 text-slate-400 hover:bg-slate-500/10"}`}
                              >
                                {togglingId === ctrl.id
                                  ? <Loader2 className="w-3 h-3 animate-spin inline" />
                                  : disabled ? "Enable" : "Disable"
                                }
                              </button>
                              <Button variant="ghost" size="sm" className="h-7 text-[10px] px-2 text-blue-400 hover:text-blue-300" onClick={() => openEdit(ctrl)}>
                                <Edit2 className="w-3 h-3 mr-0.5" />Edit
                              </Button>
                              <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-red-400" onClick={() => deleteCtrl(ctrl)}>
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </CardContent>
                )}
              </Card>
            );
          })}
        </div>
      )}

      {/* ── Edit Control Dialog ─────────────────────────────────────────── */}
      <Dialog open={!!editCtrl} onOpenChange={o => { if (!o) setEditCtrl(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Edit2 className="w-4 h-4" />Edit Control
            </DialogTitle>
          </DialogHeader>
          {editCtrl && (
            <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
              {/* Control ID */}
              <div>
                <Label className="text-xs">Control ID <span className="text-muted-foreground">(e.g. A.5.1)</span></Label>
                <Input className="mt-1 h-8 text-sm font-mono" value={editForm.controlId} onChange={e => setEditForm(f => ({ ...f, controlId: e.target.value }))} />
              </div>
              {/* Control Title */}
              <div>
                <Label className="text-xs">Control Title</Label>
                <Input className="mt-1 h-8 text-sm" value={editForm.controlTitle} onChange={e => setEditForm(f => ({ ...f, controlTitle: e.target.value }))} placeholder="e.g. Confidential information protection and disposal" />
                {editCtrl.controlTitle !== editForm.controlTitle && editForm.controlTitle && (
                  <p className="text-[10px] text-yellow-400 mt-0.5">Was: "{editCtrl.controlTitle}"</p>
                )}
              </div>
              {/* Category */}
              <div>
                <Label className="text-xs">Category</Label>
                <Input className="mt-1 h-8 text-sm" value={editForm.category} onChange={e => setEditForm(f => ({ ...f, category: e.target.value }))} placeholder="e.g. Organizational, Technical, People…" />
              </div>
              {/* Status */}
              <div>
                <Label className="text-xs">Compliance Status</Label>
                <Select value={editForm.status} onValueChange={v => setEditForm(f => ({ ...f, status: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pending_review">Pending Review</SelectItem>
                    <SelectItem value="compliant">Compliant</SelectItem>
                    <SelectItem value="partial">Partial</SelectItem>
                    <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                    <SelectItem value="not_applicable">Not Applicable</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {/* Evidence */}
              <div>
                <Label className="text-xs">Evidence / Reference</Label>
                <Input className="mt-1 h-8 text-sm" value={editForm.evidence} onChange={e => setEditForm(f => ({ ...f, evidence: e.target.value }))} placeholder="e.g. SOC2 report §6.1, policy doc URL…" />
              </div>
              {/* Assigned To — dropdown of users */}
              <div>
                <Label className="text-xs">Assigned To</Label>
                <Select value={editForm.assignedTo} onValueChange={v => setEditForm(f => ({ ...f, assignedTo: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select user…" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">— None —</SelectItem>
                    {users.map((u: any) => (
                      <SelectItem key={u.id} value={u.email}>
                        {u.name ?? u.email} {u.role === "account_manager" ? "(AM)" : u.role === "admin" ? "(Admin)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {/* Notes */}
              <div>
                <Label className="text-xs">Notes</Label>
                <Input className="mt-1 h-8 text-sm" value={editForm.notes} onChange={e => setEditForm(f => ({ ...f, notes: e.target.value }))} placeholder="Additional context…" />
              </div>
              {/* Enable / Disable */}
              <div className="flex items-center justify-between rounded border border-border/50 p-3 bg-muted/20">
                <div>
                  <p className="text-sm font-medium">Control Active</p>
                  <p className="text-xs text-muted-foreground">Disabled controls are excluded from compliance scoring</p>
                </div>
                <Switch checked={editForm.isActive} onCheckedChange={v => setEditForm(f => ({ ...f, isActive: v }))} />
              </div>
              <p className="text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded p-2">
                Control ID, title, and category changes apply to this control across <strong>all vendors</strong>.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditCtrl(null)}>Cancel</Button>
            <Button onClick={saveEdit} disabled={saving}>
              {saving && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Control Dialog ──────────────────────────────────────────── */}
      <Dialog open={showAdd} onOpenChange={o => { if (!o) setShowAdd(false); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="w-4 h-4" />Add New Control
              {selectedVendor && <span className="text-muted-foreground font-normal text-sm">— {selectedVendor.companyName}</span>}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3 max-h-[60vh] overflow-y-auto pr-1">
            <div className="p-2 rounded bg-muted/30 border border-border/40 text-xs text-muted-foreground">
              Framework: <span className="font-medium text-foreground">{FRAMEWORKS.find(f => f.value === framework)?.label}</span>
            </div>
            <div>
              <Label className="text-xs">Control ID <span className="text-red-400">*</span></Label>
              <Input className="mt-1 h-8 text-sm font-mono" value={addForm.controlId} onChange={e => setAddForm(f => ({ ...f, controlId: e.target.value }))} placeholder="e.g. A.5.1 or CUSTOM-001" />
            </div>
            <div>
              <Label className="text-xs">Control Title <span className="text-red-400">*</span></Label>
              <Input className="mt-1 h-8 text-sm" value={addForm.controlTitle} onChange={e => setAddForm(f => ({ ...f, controlTitle: e.target.value }))} placeholder="e.g. Confidential information protection and disposal" />
            </div>
            <div>
              <Label className="text-xs">Category</Label>
              <Input className="mt-1 h-8 text-sm" value={addForm.category} onChange={e => setAddForm(f => ({ ...f, category: e.target.value }))} placeholder="e.g. Organizational, Technical, People…" />
            </div>
            <div>
              <Label className="text-xs">Initial Status</Label>
              <Select value={addForm.status} onValueChange={v => setAddForm(f => ({ ...f, status: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="pending_review">Pending Review</SelectItem>
                  <SelectItem value="compliant">Compliant</SelectItem>
                  <SelectItem value="partial">Partial</SelectItem>
                  <SelectItem value="non_compliant">Non-Compliant</SelectItem>
                  <SelectItem value="not_applicable">Not Applicable</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Evidence / Reference</Label>
              <Input className="mt-1 h-8 text-sm" value={addForm.evidence} onChange={e => setAddForm(f => ({ ...f, evidence: e.target.value }))} placeholder="Optional policy link or doc reference" />
            </div>
            <div>
              <Label className="text-xs">Assigned To</Label>
              <Select value={addForm.assignedTo} onValueChange={v => setAddForm(f => ({ ...f, assignedTo: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select user…" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">— None —</SelectItem>
                  {users.map((u: any) => (
                    <SelectItem key={u.id} value={u.email}>
                      {u.name ?? u.email} {u.role === "account_manager" ? "(AM)" : u.role === "admin" ? "(Admin)" : ""}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Notes</Label>
              <Input className="mt-1 h-8 text-sm" value={addForm.notes} onChange={e => setAddForm(f => ({ ...f, notes: e.target.value }))} placeholder="Optional notes" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={addControl} disabled={adding || !addForm.controlId.trim() || !addForm.controlTitle.trim()}>
              {adding && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Add Control
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Seed Framework Dialog ────────────────────────────────────────── */}
      <Dialog open={showSeed} onOpenChange={o => { if (!o) setShowSeed(false); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Database className="w-4 h-4" />Seed Framework Controls
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              This will insert all standard <strong className="text-foreground">{FRAMEWORKS.find(f => f.value === framework)?.label}</strong> controls for <strong className="text-foreground">{selectedVendor?.companyName ?? "this vendor"}</strong>.
            </p>
            <p className="text-xs text-muted-foreground bg-muted/30 rounded p-2 border border-border/40">
              Controls that already exist will be skipped. All newly inserted controls will start as <em>Pending Review</em>.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSeed(false)}>Cancel</Button>
            <Button onClick={seedControls} disabled={seeding}>
              {seeding && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}
              {seeding ? "Seeding…" : "Seed Controls"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
