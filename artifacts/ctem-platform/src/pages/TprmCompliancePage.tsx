import { useEffect, useState, useMemo } from "react";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  RefreshCw, CheckCircle2, AlertTriangle, XCircle, Clock,
  ChevronRight, Edit2, Trash2, Loader2, Shield, ClipboardList,
  Upload, Download, ExternalLink, ChevronDown, ChevronUp, FileText,
  Settings, Minus,
} from "lucide-react";

const DOC_TYPES = ["SOC2 Type II", "ISO 27001", "PCI DSS", "HIPAA BAA", "GDPR DPA", "ISO 27017"];

interface VendorComplianceRow {
  id: number;
  companyName: string;
  domain: string;
  logoUrl: string | null;
  docsByType: Record<string, { id: number; status: string; expiresAt: string | null; daysRemaining: number | null } | null>;
  documents: any[];
  controlsSummary?: { total: number; compliant: number; active: number; score: number } | null;
}

function cellIcon(doc: { status: string; daysRemaining: number | null } | null) {
  if (!doc) return <XCircle className="w-4 h-4 text-red-400 mx-auto" aria-label="Missing" />;
  if (doc.status === "expired" || (doc.daysRemaining !== null && doc.daysRemaining < 0))
    return <AlertTriangle className="w-4 h-4 text-red-400 mx-auto" aria-label="Expired" />;
  if (doc.daysRemaining !== null && doc.daysRemaining <= 30)
    return <Clock className="w-4 h-4 text-yellow-400 mx-auto" aria-label={`Expiring in ${doc.daysRemaining}d`} />;
  return <CheckCircle2 className="w-4 h-4 text-green-400 mx-auto" aria-label="Valid" />;
}

function controlsMatrixIcon(summary: VendorComplianceRow["controlsSummary"]) {
  if (!summary || summary.total === 0)
    return <Minus className="w-4 h-4 text-slate-500 mx-auto" aria-label="No controls" />;
  if (summary.score === 100)
    return <CheckCircle2 className="w-4 h-4 text-green-400 mx-auto" aria-label="All controls compliant" />;
  if (summary.score >= 50)
    return <AlertTriangle className="w-4 h-4 text-yellow-400 mx-auto" aria-label={`${summary.score}% compliant`} />;
  return <XCircle className="w-4 h-4 text-red-400 mx-auto" aria-label={`${summary.score}% compliant`} />;
}

const STATUS_OPTIONS = [
  { value: "valid",           label: "Valid" },
  { value: "pending_review",  label: "Pending Review" },
  { value: "expiring_soon",   label: "Expiring Soon" },
  { value: "expired",         label: "Expired" },
];

const STATUS_COLOR: Record<string, string> = {
  valid:           "text-green-400 border-green-500/30",
  pending_review:  "text-blue-400 border-blue-500/30",
  expiring_soon:   "text-yellow-400 border-yellow-500/30",
  expired:         "text-red-400 border-red-500/30",
};

const CTRL_STATUS_MAP: Record<string, { label: string; color: string; border: string }> = {
  compliant:      { label: "Compliant",     color: "text-green-400",  border: "border-green-500/30"  },
  partial:        { label: "Partial",        color: "text-yellow-400", border: "border-yellow-500/30" },
  non_compliant:  { label: "Non-Compliant",  color: "text-red-400",   border: "border-red-500/30"    },
  pending_review: { label: "Pending Review", color: "text-blue-400",  border: "border-blue-500/30"   },
  not_applicable: { label: "N/A",            color: "text-slate-400", border: "border-slate-500/30"  },
};

export default function TprmCompliancePage() {
  const { toast } = useToast();
  const [mainTab, setMainTab] = useState<"matrix" | "controls" | "documents">("matrix");

  // Matrix state
  const [rows, setRows]         = useState<VendorComplianceRow[]>([]);
  const [expiring, setExpiring] = useState<any[]>([]);
  const [loading, setLoading]   = useState(true);
  const [matrixFramework, setMatrixFramework] = useState("iso27001");

  // Controls state (cross-vendor)
  const [allControls, setAllControls]             = useState<any[]>([]);
  const [controlsLoading, setControlsLoading]     = useState(false);
  const [controlsFramework, setControlsFramework] = useState("iso27001");
  const [editingCtrl, setEditingCtrl]             = useState<any | null>(null);
  const [ctrlForm, setCtrlForm]                   = useState({ status: "", evidence: "", notes: "", assignedTo: "" });
  const [savingCtrl, setSavingCtrl]               = useState(false);
  const [togglingCtrl, setTogglingCtrl]           = useState<number | null>(null);

  // Accordion state — vendor cards collapsed by default
  const [expandedVendors, setExpandedVendors] = useState<Set<number>>(new Set());
  const toggleVendor = (id: number) => setExpandedVendors(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  // All documents across vendors
  const [allDocs, setAllDocs]                         = useState<any[]>([]);
  const [editingDoc, setEditingDoc]                   = useState<any | null>(null);
  const [docForm, setDocForm]                         = useState({ status: "", expiresAt: "", notes: "" });
  const [savingDoc, setSavingDoc]                     = useState(false);
  const [expandedDocVendors, setExpandedDocVendors]   = useState<Set<number>>(new Set());
  const toggleDocVendor = (id: number) => setExpandedDocVendors(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  // Users for Assigned To dropdown
  const [users, setUsers] = useState<any[]>([]);

  useEffect(() => {
    apiFetch<any[]>("/api/users").then(setUsers).catch(() => {});
  }, []);

  // Load matrix + controls summary
  const loadMatrix = async (fw?: string) => {
    const framework = fw ?? matrixFramework;
    setLoading(true);
    try {
      const [vendors, exp] = await Promise.all([
        apiFetch<any>("/api/tprm/vendors?limit=200"),
        apiFetch<any[]>("/api/tprm/compliance/expiring"),
      ]);
      setExpiring(exp);
      const vendorRows: VendorComplianceRow[] = [];
      await Promise.all((vendors.vendors ?? []).map(async (v: any) => {
        try {
          const [comp, ctrls] = await Promise.all([
            apiFetch<any>(`/api/tprm/vendors/${v.id}/compliance`),
            apiFetch<any[]>(`/api/tprm/vendors/${v.id}/compliance-controls?framework=${framework}`).catch(() => []),
          ]);
          const docs = comp.documents ?? [];
          const docsByType: Record<string, any> = {};
          for (const dt of DOC_TYPES) {
            const d = docs.find((x: any) => x.documentType === dt && x.status !== "expired");
            if (d) {
              const days = d.expiresAt ? Math.ceil((new Date(d.expiresAt).getTime() - Date.now()) / 86400000) : null;
              docsByType[dt] = { id: d.id, status: d.status, expiresAt: d.expiresAt, daysRemaining: days };
            } else {
              const expired = docs.find((x: any) => x.documentType === dt);
              docsByType[dt] = expired ? { id: expired.id, status: "expired", expiresAt: expired.expiresAt, daysRemaining: -1 } : null;
            }
          }
          // Controls summary for this vendor
          const activeCtrls  = (ctrls as any[]).filter(c => c.isActive !== false);
          const compliantCt  = activeCtrls.filter(c => c.status === "compliant").length;
          const partialCt    = activeCtrls.filter(c => c.status === "partial").length;
          const score        = activeCtrls.length > 0
            ? Math.round(((compliantCt + partialCt * 0.5) / activeCtrls.length) * 100)
            : 0;
          const controlsSummary = {
            total:     (ctrls as any[]).length,
            active:    activeCtrls.length,
            compliant: compliantCt,
            score,
          };
          vendorRows.push({ id: v.id, companyName: v.companyName, domain: v.domain, logoUrl: v.logoUrl, docsByType, documents: docs, controlsSummary });
        } catch { /* skip */ }
      }));
      setRows(vendorRows);
    } catch { /* ignore */ }
    setLoading(false);
  };

  // Load controls across vendors
  const loadControls = async (fw?: string) => {
    const framework = fw ?? controlsFramework;
    setControlsLoading(true);
    try {
      const vendors = await apiFetch<any>("/api/tprm/vendors?limit=200");
      const all: any[] = [];
      await Promise.all((vendors.vendors ?? []).map(async (v: any) => {
        try {
          const ctrls = await apiFetch<any[]>(`/api/tprm/vendors/${v.id}/compliance-controls?framework=${framework}`);
          ctrls.forEach(c => all.push({ ...c, vendorId: v.id, vendorName: v.companyName }));
        } catch { /* skip */ }
      }));
      setAllControls(all);
    } catch { /* ignore */ }
    setControlsLoading(false);
  };

  // Load all documents
  const loadAllDocs = async () => {
    try {
      const vendors = await apiFetch<any>("/api/tprm/vendors?limit=200");
      const all: any[] = [];
      await Promise.all((vendors.vendors ?? []).map(async (v: any) => {
        try {
          const comp = await apiFetch<any>(`/api/tprm/vendors/${v.id}/compliance`);
          (comp.documents ?? []).forEach((d: any) => all.push({ ...d, vendorId: v.id, vendorName: v.companyName }));
        } catch { /* skip */ }
      }));
      setAllDocs(all.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()));
    } catch { /* ignore */ }
  };

  useEffect(() => { loadMatrix(); }, []);
  useEffect(() => { if (mainTab === "matrix") loadMatrix(); }, [mainTab]);
  useEffect(() => { if (mainTab === "controls") loadControls(); }, [mainTab]);
  useEffect(() => { if (mainTab === "documents") loadAllDocs(); }, [mainTab]);

  // Edit compliance document
  const openEditDoc = (doc: any) => {
    setEditingDoc(doc);
    setDocForm({ status: doc.status ?? "pending_review", expiresAt: doc.expiresAt ? doc.expiresAt.slice(0, 10) : "", notes: doc.notes ?? "" });
  };

  const saveDoc = async () => {
    if (!editingDoc) return;
    setSavingDoc(true);
    try {
      await apiFetch(`/api/tprm/vendors/${editingDoc.vendorId}/compliance/${editingDoc.id}`, {
        method: "PATCH", body: JSON.stringify(docForm),
      });
      toast({ title: "Document updated" });
      setEditingDoc(null);
      if (mainTab === "documents") loadAllDocs();
      if (mainTab === "matrix") loadMatrix();
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message, variant: "destructive" });
    }
    setSavingDoc(false);
  };

  const deleteDoc = async (doc: any) => {
    if (!confirm(`Delete document "${doc.title}"? This cannot be undone.`)) return;
    try {
      await apiFetch(`/api/tprm/vendors/${doc.vendorId}/compliance/${doc.id}`, { method: "DELETE" });
      toast({ title: "Document deleted" });
      if (mainTab === "documents") loadAllDocs();
      if (mainTab === "matrix") loadMatrix();
    } catch { toast({ title: "Delete failed", variant: "destructive" }); }
  };

  // Quick-update compliance control (Status, Evidence, Assigned To, Notes only)
  const openEditCtrl = (ctrl: any) => {
    setEditingCtrl(ctrl);
    setCtrlForm({ status: ctrl.status ?? "pending_review", evidence: ctrl.evidence ?? "", notes: ctrl.notes ?? "", assignedTo: ctrl.assignedTo ?? "__none__" });
  };

  const saveCtrl = async () => {
    if (!editingCtrl) return;
    setSavingCtrl(true);
    try {
      const updated = await apiFetch<any>(`/api/tprm/vendors/${editingCtrl.vendorId}/compliance-controls/${editingCtrl.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          status:     ctrlForm.status || undefined,
          evidence:   ctrlForm.evidence || undefined,
          notes:      ctrlForm.notes || undefined,
          assignedTo: ctrlForm.assignedTo === "__none__" ? null : (ctrlForm.assignedTo || undefined),
        }),
      });
      toast({ title: "Control updated" });
      setEditingCtrl(null);
      setAllControls(prev => prev.map(c => c.id === updated.id ? { ...c, ...updated, vendorId: c.vendorId, vendorName: c.vendorName } : c));
      loadMatrix();
    } catch (err: any) {
      toast({ title: "Save failed", description: err?.message, variant: "destructive" });
    }
    setSavingCtrl(false);
  };

  const deleteCtrl = async (ctrl: any) => {
    if (!confirm(`Delete control "${ctrl.controlId} — ${ctrl.controlTitle}"?`)) return;
    try {
      await apiFetch(`/api/tprm/vendors/${ctrl.vendorId}/compliance-controls/${ctrl.id}`, { method: "DELETE" });
      toast({ title: "Control deleted" });
      setAllControls(prev => prev.filter(c => c.id !== ctrl.id));
    } catch { toast({ title: "Delete failed", variant: "destructive" }); }
  };

  const toggleCtrlActive = async (ctrl: any) => {
    setTogglingCtrl(ctrl.id);
    try {
      const updated = await apiFetch<any>(`/api/tprm/vendors/${ctrl.vendorId}/compliance-controls/${ctrl.id}`, {
        method: "PATCH", body: JSON.stringify({ isActive: !ctrl.isActive }),
      });
      setAllControls(prev => prev.map(c => c.id === updated.id ? { ...c, isActive: updated.isActive } : c));
      toast({ title: updated.isActive ? "Control enabled" : "Control disabled" });
    } catch { toast({ title: "Toggle failed", variant: "destructive" }); }
    setTogglingCtrl(null);
  };

  const totalControls = allControls.length;

  // Documents grouped by vendor
  const docsByVendor = useMemo(() => {
    const map = new Map<number, { vendorId: number; vendorName: string; documents: any[] }>();
    for (const d of allDocs) {
      if (!map.has(d.vendorId)) map.set(d.vendorId, { vendorId: d.vendorId, vendorName: d.vendorName, documents: [] });
      map.get(d.vendorId)!.documents.push(d);
    }
    return [...map.values()].sort((a, b) => a.vendorName.localeCompare(b.vendorName));
  }, [allDocs]);

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Compliance Management</h1>
          <p className="text-muted-foreground text-sm">Cross-vendor compliance documents, controls, and coverage matrix</p>
        </div>
        <div className="flex gap-2">
          <Link href="/tprm/compliance/controls">
            <Button variant="outline" size="sm" className="gap-1.5">
              <Settings className="w-3.5 h-3.5" />Manage Controls
            </Button>
          </Link>
          <Button variant="outline" size="sm" onClick={() => {
            if (mainTab === "matrix") loadMatrix();
            else if (mainTab === "controls") loadControls();
            else loadAllDocs();
          }}>
            <RefreshCw className="w-4 h-4" />
          </Button>
        </div>
      </div>

      {/* Expiring soon banner */}
      {expiring.length > 0 && (
        <Card className="bg-yellow-500/10 border-yellow-500/30">
          <CardContent className="py-3">
            <div className="flex items-start gap-2">
              <Clock className="w-4 h-4 text-yellow-400 mt-0.5 shrink-0" />
              <div>
                <p className="text-sm font-medium text-yellow-400">Documents Expiring Soon</p>
                <div className="flex flex-wrap gap-1.5 mt-1.5">
                  {expiring.map(d => (
                    <Link key={d.id} href={`/tprm/vendors/${d.vendorId}`}>
                      <Badge variant="outline" className="text-[10px] border-yellow-500/40 cursor-pointer hover:bg-yellow-500/10">
                        {d.documentType} – {d.daysRemaining}d
                      </Badge>
                    </Link>
                  ))}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main tabs */}
      <div className="flex gap-1 border-b border-border/50">
        {([
          ["matrix",    Shield,        "Coverage Matrix"],
          ["controls",  ClipboardList, "Compliance Controls"],
          ["documents", Upload,        "All Documents"],
        ] as const).map(([val, Icon, label]) => (
          <button key={val} onClick={() => setMainTab(val)}
            className={`flex items-center gap-1.5 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${mainTab === val ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
            <Icon className="w-3.5 h-3.5" />{label}
          </button>
        ))}
      </div>

      {/* ── MATRIX TAB ─────────────────────────────────────────────────────── */}
      {mainTab === "matrix" && (
        loading ? (
          <Skeleton className="h-64" />
        ) : rows.length === 0 ? (
          <Card className="border-dashed">
            <CardContent className="py-14 text-center text-sm text-muted-foreground">
              No vendors yet. <Link href="/tprm/vendors" className="text-primary underline">Add vendors</Link> to track compliance.
            </CardContent>
          </Card>
        ) : (
          <>
            {/* Framework selector for controls column */}
            <div className="flex items-center gap-3">
              <p className="text-xs text-muted-foreground">Controls column framework:</p>
              <Select value={matrixFramework} onValueChange={fw => { setMatrixFramework(fw); loadMatrix(fw); }}>
                <SelectTrigger className="h-7 text-xs w-40"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                  <SelectItem value="soc2">SOC 2</SelectItem>
                  <SelectItem value="pcidss">PCI DSS v4.0</SelectItem>
                  <SelectItem value="hipaa">HIPAA</SelectItem>
                  <SelectItem value="nist_csf">NIST CSF 2.0</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Card>
              <CardContent className="p-0 overflow-x-auto">
                <table className="w-full text-sm border-collapse">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 sticky left-0 bg-card z-10 min-w-[200px]">Vendor</th>
                      {DOC_TYPES.map(dt => (
                        <th key={dt} className="text-center text-xs text-muted-foreground font-medium px-3 py-2.5 whitespace-nowrap">{dt}</th>
                      ))}
                      <th className="text-center text-xs text-muted-foreground font-medium px-3 py-2.5 whitespace-nowrap">Controls</th>
                      <th className="px-4 py-2.5 w-10" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(r => (
                      <tr key={r.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors group">
                        <td className="px-4 py-3 sticky left-0 bg-card z-10">
                          <div className="flex items-center gap-2">
                            {r.logoUrl ? (
                              <img src={r.logoUrl} alt="" className="w-6 h-6 rounded object-contain bg-white/10 p-0.5" />
                            ) : (
                              <div className="w-6 h-6 rounded bg-muted flex items-center justify-center text-[10px] font-bold">{r.companyName[0]}</div>
                            )}
                            <span className="font-medium truncate max-w-[150px]">{r.companyName}</span>
                          </div>
                        </td>
                        {DOC_TYPES.map(dt => {
                          const doc = r.docsByType[dt] ?? null;
                          return (
                            <td key={dt} className="px-3 py-3 text-center">
                              <div className="relative group/cell">
                                {cellIcon(doc)}
                                {doc && (
                                  <div className="absolute top-5 left-1/2 -translate-x-1/2 z-20 hidden group-hover/cell:flex flex-col items-start gap-1 bg-popover border border-border rounded shadow-lg p-2 min-w-[140px]">
                                    <span className="text-[10px] font-medium">{dt}</span>
                                    <Badge variant="outline" className={`text-[10px] ${STATUS_COLOR[doc.status] ?? ""}`}>{doc.status?.replace(/_/g, " ")}</Badge>
                                    {doc.expiresAt && <span className="text-[10px] text-muted-foreground">Expires: {new Date(doc.expiresAt).toLocaleDateString()}</span>}
                                    <div className="flex gap-1 mt-1">
                                      <Button variant="ghost" size="sm" className="h-5 text-[10px] px-1.5 text-blue-400" onClick={() => openEditDoc({ ...doc, documentType: dt, title: dt, vendorId: r.id })}>
                                        <Edit2 className="w-2.5 h-2.5 mr-0.5" />Edit
                                      </Button>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </td>
                          );
                        })}
                        {/* Controls compliance column */}
                        <td className="px-3 py-3 text-center">
                          <div className="relative group/cell">
                            {controlsMatrixIcon(r.controlsSummary)}
                            {r.controlsSummary && r.controlsSummary.total > 0 && (
                              <div className="absolute top-5 left-1/2 -translate-x-1/2 z-20 hidden group-hover/cell:flex flex-col items-start gap-1 bg-popover border border-border rounded shadow-lg p-2 min-w-[160px]">
                                <span className="text-[10px] font-medium">Controls Compliance</span>
                                <span className="text-[10px] text-muted-foreground">{r.controlsSummary.compliant}/{r.controlsSummary.active} compliant ({r.controlsSummary.score}%)</span>
                                {r.controlsSummary.score === 100 && (
                                  <Badge variant="outline" className="text-[10px] text-green-400 border-green-500/30">All Compliant ✓</Badge>
                                )}
                                <Link href={`/tprm/compliance/controls?vendor=${r.id}&framework=${matrixFramework}`} onClick={e => e.stopPropagation()}>
                                  <Button variant="ghost" size="sm" className="h-5 text-[10px] px-1.5 text-blue-400 mt-1">
                                    <Settings className="w-2.5 h-2.5 mr-0.5" />Manage
                                  </Button>
                                </Link>
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <Link href={`/tprm/vendors/${r.id}`}>
                            <ChevronRight className="w-4 h-4 text-muted-foreground hover:text-foreground cursor-pointer" />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </CardContent>
            </Card>
            <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1"><CheckCircle2 className="w-3.5 h-3.5 text-green-400" />Valid / All compliant</span>
              <span className="flex items-center gap-1"><Clock className="w-3.5 h-3.5 text-yellow-400" />Expiring ≤30d</span>
              <span className="flex items-center gap-1"><AlertTriangle className="w-3.5 h-3.5 text-yellow-400" />Partial compliance</span>
              <span className="flex items-center gap-1"><XCircle className="w-3.5 h-3.5 text-red-400" />Expired / Missing / Non-compliant</span>
              <span className="flex items-center gap-1"><Minus className="w-3.5 h-3.5 text-slate-500" />No controls set</span>
              <span className="text-muted-foreground/50">· Hover a cell to edit or manage</span>
            </div>
          </>
        )
      )}

      {/* ── CONTROLS TAB ────────────────────────────────────────────────────── */}
      {mainTab === "controls" && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <Select value={controlsFramework} onValueChange={v => { setControlsFramework(v); loadControls(v); }}>
              <SelectTrigger className="h-8 text-xs w-44"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                <SelectItem value="soc2">SOC 2</SelectItem>
                <SelectItem value="pcidss">PCI DSS v4.0</SelectItem>
                <SelectItem value="hipaa">HIPAA</SelectItem>
                <SelectItem value="nist_csf">NIST CSF 2.0</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-sm text-muted-foreground flex-1">{totalControls} control{totalControls !== 1 ? "s" : ""} across all vendors</p>
            <Link href={`/tprm/compliance/controls?framework=${controlsFramework}`}>
              <Button variant="outline" size="sm" className="h-8 gap-1.5">
                <Settings className="w-3.5 h-3.5" />Manage Controls
              </Button>
            </Link>
          </div>

          {/* Scorecard */}
          {allControls.length > 0 && (() => {
            const total     = allControls.length;
            const compliant = allControls.filter(c => c.status === "compliant").length;
            const partial   = allControls.filter(c => c.status === "partial").length;
            const nonC      = allControls.filter(c => c.status === "non_compliant").length;
            const na        = allControls.filter(c => c.status === "not_applicable").length;
            const pending   = allControls.filter(c => c.status === "pending_review").length;
            const score     = total - na > 0 ? Math.round(((compliant + partial * 0.5) / (total - na)) * 100) : 0;
            return (
              <Card>
                <CardContent className="py-3">
                  <div className="grid grid-cols-6 gap-2">
                    {[
                      { label: "Overall Score", count: `${score}%`, color: score >= 80 ? "text-green-400" : score >= 50 ? "text-yellow-400" : "text-red-400", bg: "bg-muted/30" },
                      { label: "Compliant",     count: compliant,   color: "text-green-400",  bg: "bg-green-500/10"  },
                      { label: "Partial",        count: partial,     color: "text-yellow-400", bg: "bg-yellow-500/10" },
                      { label: "Non-Compliant",  count: nonC,        color: "text-red-400",    bg: "bg-red-500/10"    },
                      { label: "Pending",        count: pending,     color: "text-blue-400",   bg: "bg-blue-500/10"   },
                      { label: "N/A",            count: na,          color: "text-slate-400",  bg: "bg-slate-500/10"  },
                    ].map(s => (
                      <div key={s.label} className={`rounded p-2 text-center ${s.bg}`}>
                        <p className={`text-lg font-bold ${s.color}`}>{s.count}</p>
                        <p className="text-[10px] text-muted-foreground leading-tight">{s.label}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          {controlsLoading ? (
            <div className="flex items-center justify-center py-10"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
          ) : allControls.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center text-sm text-muted-foreground">
                <ClipboardList className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p>No controls for <strong>{controlsFramework.replace(/_/g, " ").toUpperCase()}</strong> across any vendors yet.</p>
                <p className="text-xs mt-1 mb-3">Use the Manage Controls page to seed or add controls per vendor.</p>
                <Link href={`/tprm/compliance/controls?framework=${controlsFramework}`}>
                  <Button size="sm" variant="outline"><Settings className="w-3.5 h-3.5 mr-1.5" />Go to Manage Controls</Button>
                </Link>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {Array.from(new Map(allControls.map(c => [c.vendorId, c.vendorName]))).map(([vid, vname]) => {
                const vControls = allControls.filter(c => c.vendorId === vid);
                const compliantCount = vControls.filter(c => c.status === "compliant" && c.isActive !== false).length;
                const activeCount    = vControls.filter(c => c.isActive !== false).length;
                const isOpen = expandedVendors.has(vid as number);
                return (
                  <Card key={vid} className={isOpen ? "border-border" : "border-border/60"}>
                    <button className="w-full text-left" onClick={() => toggleVendor(vid as number)}>
                      <CardHeader className="py-3 px-4">
                        <CardTitle className="text-sm flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-muted-foreground shrink-0" />
                            <span className="font-medium">{vname as string}</span>
                            <span className="text-xs text-muted-foreground font-normal">({vControls.length} controls)</span>
                            <span className={`text-xs font-medium ${compliantCount === activeCount && activeCount > 0 ? "text-green-400" : compliantCount > 0 ? "text-yellow-400" : "text-muted-foreground"}`}>
                              {compliantCount}/{activeCount} compliant
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Link href={`/tprm/vendors/${vid}`} onClick={e => e.stopPropagation()}>
                              <Button variant="ghost" size="sm" className="h-6 text-[10px] text-muted-foreground px-2">
                                <ExternalLink className="w-3 h-3 mr-1" />Vendor
                              </Button>
                            </Link>
                            {isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                          </div>
                        </CardTitle>
                      </CardHeader>
                    </button>

                    {isOpen && (
                      <CardContent className="pb-3 pt-0 px-4">
                        <div className="space-y-1 border-t border-border/40 pt-3">
                          {vControls.map(ctrl => {
                            const sm = CTRL_STATUS_MAP[ctrl.status] ?? CTRL_STATUS_MAP.pending_review;
                            const isDisabled = ctrl.isActive === false;
                            return (
                              <div key={ctrl.id} className={`flex items-center gap-2 p-2 rounded border-l-2 transition-colors ${isDisabled ? "bg-muted/10 border-slate-600/40 opacity-60" : `bg-muted/20 ${sm.border}`}`}>
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-1.5 flex-wrap">
                                    <span className="text-xs font-mono font-semibold text-muted-foreground">{ctrl.controlId}</span>
                                    {isDisabled
                                      ? <Badge variant="outline" className="text-[10px] py-0 h-4 text-slate-400 border-slate-500/30">Disabled</Badge>
                                      : <Badge variant="outline" className={`text-[10px] py-0 h-4 ${sm.color} border-current`}>{sm.label}</Badge>
                                    }
                                    {ctrl.category && <Badge variant="outline" className="text-[10px] py-0 h-4">{ctrl.category}</Badge>}
                                  </div>
                                  <p className="text-xs mt-0.5 truncate">{ctrl.controlTitle}</p>
                                  {ctrl.evidence && <p className="text-[10px] text-muted-foreground truncate"><span className="font-medium">Evidence:</span> {ctrl.evidence}</p>}
                                  {ctrl.assignedTo && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Assigned:</span> {ctrl.assignedTo}</p>}
                                </div>
                                <div className="flex items-center gap-1 shrink-0">
                                  <Button variant="ghost" size="sm" className="h-6 text-[10px] px-2 text-blue-400 hover:text-blue-300" onClick={() => openEditCtrl(ctrl)}>
                                    <Edit2 className="w-3 h-3 mr-0.5" />Update
                                  </Button>
                                  <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-red-400" onClick={() => deleteCtrl(ctrl)}>
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
        </div>
      )}

      {/* ── DOCUMENTS TAB ───────────────────────────────────────────────────── */}
      {mainTab === "documents" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              {allDocs.length} document{allDocs.length !== 1 ? "s" : ""} across {docsByVendor.length} vendor{docsByVendor.length !== 1 ? "s" : ""}
            </p>
            {docsByVendor.length > 0 && (
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setExpandedDocVendors(new Set(docsByVendor.map(v => v.vendorId)))}>Expand All</Button>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setExpandedDocVendors(new Set())}>Collapse All</Button>
              </div>
            )}
          </div>

          {docsByVendor.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center text-sm text-muted-foreground">
                <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
                <p>No compliance documents found.</p>
                <p className="text-xs mt-1">Upload documents on individual vendor pages.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {docsByVendor.map(group => {
                const isOpen = expandedDocVendors.has(group.vendorId);
                const validCount = group.documents.filter(d => d.status === "valid").length;
                return (
                  <Card key={group.vendorId} className={isOpen ? "border-border" : "border-border/60"}>
                    <button className="w-full text-left" onClick={() => toggleDocVendor(group.vendorId)}>
                      <CardHeader className="py-3 px-4">
                        <CardTitle className="text-sm flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <Shield className="w-4 h-4 text-muted-foreground shrink-0" />
                            <span className="font-medium">{group.vendorName}</span>
                            <span className="text-xs text-muted-foreground font-normal">({group.documents.length} document{group.documents.length !== 1 ? "s" : ""})</span>
                            {validCount > 0 && <span className="text-xs text-green-400 font-medium">{validCount} valid</span>}
                          </div>
                          <div className="flex items-center gap-2">
                            <Link href={`/tprm/vendors/${group.vendorId}`} onClick={e => e.stopPropagation()}>
                              <Button variant="ghost" size="sm" className="h-6 text-[10px] text-blue-400 px-2">
                                <ExternalLink className="w-3 h-3 mr-1" />Open Vendor
                              </Button>
                            </Link>
                            {isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                          </div>
                        </CardTitle>
                      </CardHeader>
                    </button>

                    {isOpen && (
                      <CardContent className="pb-3 pt-0 px-4">
                        <div className="space-y-1.5 border-t border-border/40 pt-3">
                          {group.documents.map(doc => {
                            const exp  = doc.expiresAt ? new Date(doc.expiresAt) : null;
                            const days = exp ? Math.ceil((exp.getTime() - Date.now()) / 86400000) : null;
                            const sc   = STATUS_COLOR[doc.status] ?? "";
                            return (
                              <div key={doc.id} className="flex items-center gap-3 p-2 rounded bg-muted/20 hover:bg-accent/20 transition-colors">
                                <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <p className="text-sm font-medium truncate">{doc.title || doc.documentType}</p>
                                    <Badge variant="outline" className={`text-[10px] ${sc}`}>{doc.status?.replace(/_/g, " ")}</Badge>
                                    <Badge variant="outline" className="text-[10px]">{doc.documentType}</Badge>
                                  </div>
                                  <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                                    {doc.auditor && <span className="text-xs text-muted-foreground">{doc.auditor}</span>}
                                    {days !== null && (
                                      <span className={`text-xs ${days < 0 ? "text-red-400" : days <= 30 ? "text-yellow-400" : "text-green-400"}`}>
                                        {days < 0 ? `Expired ${Math.abs(days)}d ago` : `${days}d remaining`}
                                      </span>
                                    )}
                                    {doc.createdAt && <span className="text-xs text-muted-foreground">Uploaded {new Date(doc.createdAt).toLocaleDateString()}</span>}
                                  </div>
                                </div>
                                <div className="flex items-center gap-1 shrink-0">
                                  {doc.fileName && (
                                    <Button variant="ghost" size="icon" className="h-7 w-7" title="Download" asChild>
                                      <a href={`/api/tprm/vendors/${doc.vendorId}/compliance/${doc.id}/download`} download={doc.fileName}>
                                        <Download className="w-3.5 h-3.5" />
                                      </a>
                                    </Button>
                                  )}
                                  <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => openEditDoc(doc)} title="Edit"><Edit2 className="w-3.5 h-3.5" /></Button>
                                  <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => deleteDoc(doc)} title="Delete"><Trash2 className="w-3.5 h-3.5" /></Button>
                                  <Link href={`/tprm/vendors/${doc.vendorId}`}>
                                    <Button variant="ghost" size="icon" className="h-7 w-7" title="Open vendor"><ExternalLink className="w-3.5 h-3.5" /></Button>
                                  </Link>
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
        </div>
      )}

      {/* ── Edit Document Dialog ──────────────────────────────────────────── */}
      <Dialog open={!!editingDoc} onOpenChange={o => { if (!o) setEditingDoc(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle className="flex items-center gap-2"><Edit2 className="w-4 h-4" />Edit Compliance Document</DialogTitle></DialogHeader>
          {editingDoc && (
            <div className="space-y-3">
              <div className="p-2 rounded bg-muted/30 border border-border/40 text-xs">
                <p className="font-medium">{editingDoc.title || editingDoc.documentType}</p>
                <p className="text-muted-foreground">{editingDoc.vendorName}</p>
              </div>
              <div>
                <Label className="text-xs">Status</Label>
                <Select value={docForm.status} onValueChange={v => setDocForm(f => ({ ...f, status: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {STATUS_OPTIONS.map(o => <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Expiry Date</Label>
                <Input type="date" className="mt-1 h-8 text-sm" value={docForm.expiresAt} onChange={e => setDocForm(f => ({ ...f, expiresAt: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Notes</Label>
                <Input className="mt-1 h-8 text-sm" value={docForm.notes} onChange={e => setDocForm(f => ({ ...f, notes: e.target.value }))} placeholder="Optional notes…" />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingDoc(null)}>Cancel</Button>
            <Button onClick={saveDoc} disabled={savingDoc}>{savingDoc && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Quick-Update Control Dialog (Status / Evidence / Assigned To / Notes only) ── */}
      <Dialog open={!!editingCtrl} onOpenChange={o => { if (!o) setEditingCtrl(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><ClipboardList className="w-4 h-4" />Update Control Status</DialogTitle>
          </DialogHeader>
          {editingCtrl && (
            <div className="space-y-3">
              <div className="p-2 rounded bg-muted/30 border border-border/40">
                <p className="text-xs font-mono font-semibold text-muted-foreground">{editingCtrl.controlId}</p>
                <p className="text-sm font-medium mt-0.5">{editingCtrl.controlTitle}</p>
                <p className="text-xs text-muted-foreground mt-0.5">Vendor: {editingCtrl.vendorName}</p>
              </div>

              <div>
                <Label className="text-xs">Compliance Status</Label>
                <Select value={ctrlForm.status} onValueChange={v => setCtrlForm(f => ({ ...f, status: v }))}>
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
                <Input className="mt-1 h-8 text-sm" value={ctrlForm.evidence} onChange={e => setCtrlForm(f => ({ ...f, evidence: e.target.value }))} placeholder="e.g. SOC2 report §6.1, policy link…" />
              </div>

              <div>
                <Label className="text-xs">Assigned To</Label>
                <Select value={ctrlForm.assignedTo} onValueChange={v => setCtrlForm(f => ({ ...f, assignedTo: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select account manager…" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__none__">— None —</SelectItem>
                    {users.map((u: any) => (
                      <SelectItem key={u.id} value={u.email}>
                        {u.name ?? u.email}
                        {u.role === "account_manager" ? " (AM)" : u.role === "admin" ? " (Admin)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label className="text-xs">Notes</Label>
                <Input className="mt-1 h-8 text-sm" value={ctrlForm.notes} onChange={e => setCtrlForm(f => ({ ...f, notes: e.target.value }))} placeholder="Additional context…" />
              </div>

              <p className="text-[10px] text-muted-foreground">
                To rename the control ID/title or change category, use{" "}
                <Link href={`/tprm/compliance/controls?vendor=${editingCtrl.vendorId}`} className="text-blue-400 underline" onClick={() => setEditingCtrl(null)}>
                  Manage Controls
                </Link>.
              </p>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingCtrl(null)}>Cancel</Button>
            <Button onClick={saveCtrl} disabled={savingCtrl}>{savingCtrl && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
