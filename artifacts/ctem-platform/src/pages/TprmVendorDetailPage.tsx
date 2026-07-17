import { useEffect, useRef, useState } from "react";
import { useParams, Link, useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import {
  ArrowLeft, RefreshCw, Globe, Shield, Bug, Package, FileText, AlertTriangle,
  CheckCircle2, Loader2, Upload, Plus, Mail, Phone, User,
  Building2, Clock, Download, Trash2, Send, ChevronRight, Eye, Zap, Lock, Database, Search,
  Flame, RadioTower, ScanSearch, ShieldAlert,
  Bell, BellOff, ClipboardList, XCircle, BarChart3, ChevronDown, ChevronUp, Info,
  Edit2, ExternalLink,
} from "lucide-react";
import { LineChart, Line, BarChart, Bar, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

function gradeBadge(grade: string) {
  const c = grade === "A+" || grade === "A" ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-2 py-0.5 rounded border text-xs font-bold ${c}`}>{grade}</span>;
}

function severityBadge(s: string) {
  const m: Record<string, string> = { critical: "bg-red-500/20 text-red-400", high: "bg-orange-500/20 text-orange-400", medium: "bg-yellow-500/20 text-yellow-400", low: "bg-blue-500/20 text-blue-400", info: "bg-slate-500/20 text-slate-400" };
  return <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold ${m[s] ?? m.info}`}>{s}</span>;
}

const SCORE_CATEGORIES = [
  { key: "networkScore",    label: "Network" },
  { key: "dnsScore",        label: "DNS" },
  { key: "webAppScore",     label: "Web App" },
  { key: "emailScore",      label: "Email" },
  { key: "cloudScore",      label: "Cloud" },
  { key: "endpointScore",   label: "Endpoint" },
  { key: "tlsScore",        label: "TLS/SSL" },
  { key: "infoLeakScore",   label: "Info Leak" },
  { key: "reputationScore", label: "Reputation" },
];

const DOC_TYPES = ["SOC2 Type I", "SOC2 Type II", "ISO 27001", "ISO 27017", "ISO 27701", "PCI DSS", "HIPAA BAA", "GDPR DPA", "CSA STAR", "NIST CSF", "Other"];

export default function TprmVendorDetailPage() {
  const { toast } = useToast();
  const { id } = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const [vendor, setVendor] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [tab, setTab] = useState("overview");
  const [secAnalysis, setSecAnalysis] = useState<any>(null);
  const [breachIntel, setBreachIntel] = useState<any>(null);
  const [loadingIntel, setLoadingIntel] = useState(false);
  const [rescanning4p, setRescanning4p] = useState(false);

  // Contacts state
  const [showAddContact, setShowAddContact] = useState(false);
  const [contactForm, setContactForm] = useState({ name: "", email: "", role: "", isPrimary: false });
  const [savingContact, setSavingContact] = useState(false);

  // Compliance state
  const [showUploadDoc, setShowUploadDoc] = useState(false);
  const [docForm, setDocForm] = useState({ documentType: "", title: "", auditor: "", auditPeriodStart: "", auditPeriodEnd: "", expiresAt: "", coverageScope: "" });
  const [docFile, setDocFile]   = useState<File | null>(null);
  const [savingDoc, setSavingDoc] = useState(false);

  // SBOM state
  const [sbomFile, setSbomFile]     = useState<File | null>(null);
  const [uploadingSbom, setUploadingSbom] = useState(false);
  const sbomInputRef = useRef<HTMLInputElement>(null);

  // Questionnaire state
  const [templates, setTemplates] = useState<any[]>([]);
  const [showSendQ, setShowSendQ]   = useState(false);
  const [qForm, setQForm]           = useState({ templateId: "", dueDate: "", recipientEmail: "" });
  const [sendingQ, setSendingQ]     = useState(false);
  const [qPortalLink, setQPortalLink] = useState<string | null>(null);
  const [editingQ, setEditingQ]       = useState<any | null>(null);
  const [qEditForm, setQEditForm]     = useState({ status: "", dueDate: "", respondedBy: "", notes: "", score: "" });
  const [savingQEdit, setSavingQEdit] = useState(false);
  const [savingQRisk, setSavingQRisk] = useState(false);
  const [localQuestionnaires, setLocalQuestionnaires] = useState<any[]>([]);
  // View responses state
  const [viewingQ, setViewingQ] = useState<any | null>(null);
  const [loadingQDetail, setLoadingQDetail] = useState(false);

  // SLA state
  const [slaForm, setSlaForm] = useState({ slaUptimePercent: "", slaResponseTimeHours: "", slaReviewDate: "", slaNotes: "", slaBreachCount: "" });
  const [savingSla, setSavingSla] = useState(false);
  const [slaLoaded, setSlaLoaded] = useState(false);

  // Contact email dialog
  const [emailContact, setEmailContact] = useState<any | null>(null);
  const [emailForm, setEmailForm] = useState({ subject: "", message: "" });
  const [sendingEmail, setSendingEmail] = useState(false);

  // Compliance requirements state
  const [requirements, setRequirements] = useState<any[]>([]);
  const [showAddReq, setShowAddReq] = useState(false);
  const [reqForm, setReqForm] = useState({ documentType: "", dueDate: "", reminderDays: "30", notes: "" });
  const [savingReq, setSavingReq] = useState(false);

  // Compliance controls state
  const [controls, setControls] = useState<any[]>([]);
  const [controlFramework, setControlFramework] = useState("iso27001");
  const [loadingControls, setLoadingControls] = useState(false);
  const [seedingFramework, setSeedingFramework] = useState(false);
  const [editingControl, setEditingControl] = useState<any | null>(null);
  const [controlEditForm, setControlEditForm] = useState({ status: "", evidence: "", notes: "", assignedTo: "", nextReviewAt: "" });
  const [savingControl, setSavingControl] = useState(false);
  const [showAddControl, setShowAddControl] = useState(false);
  const [addControlForm, setAddControlForm] = useState({ controlId: "", controlTitle: "", category: "", status: "pending_review", evidence: "", notes: "", assignedTo: "" });
  const [savingAddControl, setSavingAddControl] = useState(false);

  // Reminders state
  const [reminders, setReminders] = useState<any[]>([]);
  const [showAddReminder, setShowAddReminder] = useState(false);
  const [reminderForm, setReminderForm] = useState({ title: "", dueDate: "", type: "custom", notes: "" });
  const [savingReminder, setSavingReminder] = useState(false);

  // Compliance sub-tab
  const [complianceTab, setComplianceTab] = useState("controls");

  // AI parse state (per doc)
  const [parsingDocId, setParsingDocId] = useState<number | null>(null);

  // SBOM discover
  const [discoveringSbom, setDiscoveringSbom] = useState(false);

  // 4th party deep scan
  const [deepScanning4p, setDeepScanning4p] = useState(false);

  // Propagate findings
  const [propagating, setPropagating] = useState(false);
  const [propagateResult, setPropagateResult] = useState<string | null>(null);

  const loadVendor = () => {
    setLoading(true);
    apiFetch<any>(`/api/tprm/vendors/${id}`)
      .then(v => { setVendor(v); setLocalQuestionnaires(v.questionnaires ?? []); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadVendor(); }, [id]);
  useEffect(() => {
    apiFetch<any[]>("/api/tprm/questionnaire-templates").then(setTemplates).catch(() => {});
    apiFetch<any[]>(`/api/tprm/vendors/${id}/compliance-requirements`).then(setRequirements).catch(() => {});
  }, [id]);

  const loadControls = (fw?: string) => {
    const framework = fw ?? controlFramework;
    setLoadingControls(true);
    apiFetch<any[]>(`/api/tprm/vendors/${id}/compliance-controls?framework=${framework}`)
      .then(setControls).catch(() => {}).finally(() => setLoadingControls(false));
  };

  const loadReminders = () => {
    apiFetch<any[]>(`/api/tprm/vendors/${id}/reminders`).then(setReminders).catch(() => {});
  };

  useEffect(() => {
    if (tab !== "compliance") return;
    loadControls();
    loadReminders();
  }, [tab, id]);

  const seedFramework = async () => {
    setSeedingFramework(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/compliance-controls/seed`, { method: "POST", body: JSON.stringify({ framework: controlFramework }) });
      loadControls();
    } catch { /* ignore */ }
    setSeedingFramework(false);
  };

  const openEditControl = (ctrl: any) => {
    setEditingControl(ctrl);
    setControlEditForm({ status: ctrl.status, evidence: ctrl.evidence ?? "", notes: ctrl.notes ?? "", assignedTo: ctrl.assignedTo ?? "", nextReviewAt: ctrl.nextReviewAt ? ctrl.nextReviewAt.slice(0, 10) : "" });
  };

  const saveControl = async () => {
    if (!editingControl) return;
    if (!controlEditForm.status) { toast({ title: "Status is required", variant: "destructive" }); return; }
    setSavingControl(true);
    try {
      const updated = await apiFetch<any>(`/api/tprm/vendors/${id}/compliance-controls/${editingControl.id}`, { method: "PATCH", body: JSON.stringify(controlEditForm) });
      setControls(prev => prev.map(c => c.id === updated.id ? updated : c));
      setEditingControl(null);
      toast({ title: "Control updated", description: `${updated.controlId} — ${updated.status.replace(/_/g, " ")}` });
    } catch (err: any) {
      toast({ title: "Failed to save control", description: err?.message ?? "Server error — please try again", variant: "destructive" });
    }
    setSavingControl(false);
  };

  const deleteControl = async (cid: number) => {
    await apiFetch(`/api/tprm/vendors/${id}/compliance-controls/${cid}`, { method: "DELETE" });
    loadControls();
  };

  const addCustomControl = async () => {
    if (!addControlForm.controlId || !addControlForm.controlTitle) return;
    setSavingAddControl(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/compliance-controls`, { method: "POST", body: JSON.stringify({ ...addControlForm, framework: controlFramework }) });
      setShowAddControl(false);
      setAddControlForm({ controlId: "", controlTitle: "", category: "", status: "pending_review", evidence: "", notes: "", assignedTo: "" });
      loadControls();
    } catch { /* ignore */ }
    setSavingAddControl(false);
  };

  const addReminder = async () => {
    if (!reminderForm.title || !reminderForm.dueDate) return;
    setSavingReminder(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/reminders`, { method: "POST", body: JSON.stringify(reminderForm) });
      setShowAddReminder(false);
      setReminderForm({ title: "", dueDate: "", type: "custom", notes: "" });
      loadReminders();
    } catch { /* ignore */ }
    setSavingReminder(false);
  };

  const dismissReminder = async (rid: number) => {
    await apiFetch(`/api/tprm/vendors/${id}/reminders/${rid}`, { method: "PATCH", body: JSON.stringify({ isDismissed: true }) });
    loadReminders();
  };

  const deleteReminder = async (rid: number) => {
    await apiFetch(`/api/tprm/vendors/${id}/reminders/${rid}`, { method: "DELETE" });
    loadReminders();
  };

  // Pre-populate SLA form when vendor loads
  useEffect(() => {
    if (vendor && !slaLoaded) {
      setSlaForm({
        slaUptimePercent: vendor.slaUptimePercent != null ? String(vendor.slaUptimePercent) : "",
        slaResponseTimeHours: vendor.slaResponseTimeHours != null ? String(vendor.slaResponseTimeHours) : "",
        slaReviewDate: vendor.slaReviewDate ?? "",
        slaNotes: vendor.slaNotes ?? "",
        slaBreachCount: vendor.slaBreachCount != null ? String(vendor.slaBreachCount) : "0",
      });
      setSlaLoaded(true);
    }
  }, [vendor]);

  useEffect(() => {
    if (tab !== "intelligence" || !id) return;
    setLoadingIntel(true);
    Promise.allSettled([
      apiFetch<any>(`/api/tprm/vendors/${id}/security-analysis`),
      apiFetch<any>(`/api/tprm/vendors/${id}/breach-intel`),
    ]).then(([secRes, breachRes]) => {
      if (secRes.status === "fulfilled") setSecAnalysis(secRes.value);
      if (breachRes.status === "fulfilled") setBreachIntel(breachRes.value);
    }).finally(() => setLoadingIntel(false));
  }, [tab, id]);

  const rescanFourthParties = async () => {
    setRescanning4p(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/rescan-fourth-parties`, { method: "POST" });
      setTimeout(loadVendor, 5000);
    } catch { /* ignore */ }
    setRescanning4p(false);
  };

  const triggerScan = async () => {
    setScanning(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/scan`, { method: "POST" });
      setTimeout(loadVendor, 3000);
    } catch { /* ignore */ }
    setScanning(false);
  };

  const addContact = async () => {
    if (!contactForm.name || !contactForm.email) return;
    setSavingContact(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/contacts`, { method: "POST", body: JSON.stringify(contactForm) });
      setShowAddContact(false);
      setContactForm({ name: "", email: "", role: "", isPrimary: false });
      loadVendor();
    } catch { /* ignore */ }
    setSavingContact(false);
  };

  const uploadDoc = async () => {
    if (!docForm.documentType || !docForm.title) return;
    setSavingDoc(true);
    try {
      const fd = new FormData();
      Object.entries(docForm).forEach(([k, v]) => v && fd.append(k, v));
      if (docFile) fd.append("file", docFile);
      await apiFetch(`/api/tprm/vendors/${id}/compliance`, { method: "POST", body: fd });
      setShowUploadDoc(false);
      setDocForm({ documentType: "", title: "", auditor: "", auditPeriodStart: "", auditPeriodEnd: "", expiresAt: "", coverageScope: "" });
      setDocFile(null);
      loadVendor();
    } catch { /* ignore */ }
    setSavingDoc(false);
  };

  const uploadSbom = async () => {
    if (!sbomFile) return;
    setUploadingSbom(true);
    try {
      const fd = new FormData();
      fd.append("file", sbomFile);
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/sbom`, { method: "POST", body: fd });
      setSbomFile(null);
      if (sbomInputRef.current) sbomInputRef.current.value = "";
      loadVendor();
    } catch { /* ignore */ }
    setUploadingSbom(false);
  };

  const sendQuestionnaire = async () => {
    if (!qForm.templateId) { toast({ title: "Template is required", variant: "destructive" }); return; }
    if (!qForm.recipientEmail.trim()) { toast({ title: "Recipient email is required", variant: "destructive" }); return; }
    const emailRx = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRx.test(qForm.recipientEmail.trim())) { toast({ title: "Invalid email address", description: "Enter a valid email like vendor@company.com", variant: "destructive" }); return; }
    setSendingQ(true);
    try {
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/questionnaires`, { method: "POST", body: JSON.stringify({ ...qForm, recipientEmail: qForm.recipientEmail.trim() }) });
      setQPortalLink(r.portalLink ?? null);
      setShowSendQ(false);
      setQForm({ templateId: "", dueDate: "", recipientEmail: "" });
      toast({ title: "Questionnaire sent", description: `Sent to ${qForm.recipientEmail.trim()}` });
      const newQ = { ...r, portalLink: undefined };
      setLocalQuestionnaires(prev => [newQ, ...prev]);
      loadVendor();
    } catch (err: any) {
      toast({ title: "Failed to send questionnaire", description: err?.message ?? "Server error — please try again", variant: "destructive" });
    }
    setSendingQ(false);
  };

  const openEditQ = (q: any) => {
    setEditingQ(q);
    setQEditForm({
      status:      q.status ?? "sent",
      dueDate:     q.dueDate ? new Date(q.dueDate).toISOString().slice(0, 10) : "",
      respondedBy: q.respondedBy ?? "",
      notes:       q.notes ?? "",
      score:       q.score !== null && q.score !== undefined ? String(q.score) : "",
    });
  };

  const saveQEdit = async () => {
    if (!editingQ) return;
    setSavingQEdit(true);
    try {
      const payload: any = {
        status:      qEditForm.status,
        respondedBy: qEditForm.respondedBy || null,
        notes:       qEditForm.notes || null,
        dueDate:     qEditForm.dueDate || null,
        score:       qEditForm.score !== "" ? parseInt(qEditForm.score) : null,
      };
      const updated = await apiFetch<any>(`/api/tprm/vendors/${id}/questionnaires/${editingQ.id}`, { method: "PATCH", body: JSON.stringify(payload) });
      setLocalQuestionnaires(prev => prev.map(q => q.id === updated.id ? updated : q));
      setEditingQ(null);
      toast({ title: "Questionnaire updated", description: `Status: ${updated.status}` });
    } catch (err: any) {
      toast({ title: "Failed to update questionnaire", description: err?.message ?? "Server error", variant: "destructive" });
    }
    setSavingQEdit(false);
  };

  const viewQuestionnaire = async (q: any) => {
    setLoadingQDetail(true);
    setViewingQ({ ...q, _loading: true });
    try {
      const detail = await apiFetch<any>(`/api/tprm/questionnaires/${q.id}`);
      setViewingQ(detail);
    } catch {
      setViewingQ({ ...q, _error: true });
    }
    setLoadingQDetail(false);
  };

  const applyQRisk = async (q: any) => {
    setSavingQRisk(true);
    try {
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/questionnaires/${q.id}/apply-risk`, { method: "POST" });
      toast({ title: "Risk update triggered", description: r.message ?? "Vendor risk score is being recalculated." });
      setViewingQ(null);
      setTimeout(loadVendor, 5000);
    } catch (err: any) {
      toast({ title: "Failed to trigger risk update", description: err?.message ?? "Server error", variant: "destructive" });
    }
    setSavingQRisk(false);
  };

  const deleteQ = async (q: any) => {
    if (!confirm(`Delete questionnaire #${q.id}? This cannot be undone.`)) return;
    try {
      await apiFetch(`/api/tprm/vendors/${id}/questionnaires/${q.id}`, { method: "DELETE" });
      setLocalQuestionnaires(prev => prev.filter(x => x.id !== q.id));
      toast({ title: "Questionnaire deleted" });
    } catch (err: any) {
      toast({ title: "Delete failed", description: err?.message, variant: "destructive" });
    }
  };

  const saveSla = async () => {
    setSavingSla(true);
    try {
      const body: Record<string, any> = {};
      if (slaForm.slaUptimePercent)     body.slaUptimePercent     = parseFloat(slaForm.slaUptimePercent);
      if (slaForm.slaResponseTimeHours) body.slaResponseTimeHours = parseInt(slaForm.slaResponseTimeHours);
      if (slaForm.slaReviewDate)        body.slaReviewDate        = slaForm.slaReviewDate;
      if (slaForm.slaNotes)             body.slaNotes             = slaForm.slaNotes;
      if (slaForm.slaBreachCount)       body.slaBreachCount       = parseInt(slaForm.slaBreachCount);
      await apiFetch(`/api/tprm/vendors/${id}`, { method: "PATCH", body: JSON.stringify(body) });
      loadVendor();
    } catch { /* ignore */ }
    setSavingSla(false);
  };

  const sendContactEmail = async () => {
    if (!emailContact || !emailForm.subject || !emailForm.message) return;
    setSendingEmail(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/contacts/${emailContact.id}/send-email`, { method: "POST", body: JSON.stringify(emailForm) });
      setEmailContact(null);
      setEmailForm({ subject: "", message: "" });
    } catch { /* ignore */ }
    setSendingEmail(false);
  };

  const sendContactVerification = async (contactId: number) => {
    try {
      await apiFetch(`/api/tprm/vendors/${id}/contacts/${contactId}/send-verification`, { method: "POST" });
    } catch { /* ignore */ }
  };

  const deleteContact = async (contactId: number) => {
    try {
      await apiFetch(`/api/tprm/vendors/${id}/contacts/${contactId}`, { method: "DELETE" });
      loadVendor();
    } catch { /* ignore */ }
  };

  const addRequirement = async () => {
    if (!reqForm.documentType) return;
    setSavingReq(true);
    try {
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/compliance-requirements`, { method: "POST", body: JSON.stringify({ ...reqForm, reminderDays: parseInt(reqForm.reminderDays) }) });
      setRequirements(prev => [...prev, r]);
      setShowAddReq(false);
      setReqForm({ documentType: "", dueDate: "", reminderDays: "30", notes: "" });
    } catch { /* ignore */ }
    setSavingReq(false);
  };

  const deleteRequirement = async (reqId: number) => {
    try {
      await apiFetch(`/api/tprm/vendors/${id}/compliance-requirements/${reqId}`, { method: "DELETE" });
      setRequirements(prev => prev.filter(r => r.id !== reqId));
    } catch { /* ignore */ }
  };

  const notifyRequirement = async (reqId: number) => {
    try {
      await apiFetch(`/api/tprm/vendors/${id}/compliance-requirements/${reqId}/notify`, { method: "POST" });
    } catch { /* ignore */ }
  };

  const aiParseDoc = async (docId: number) => {
    setParsingDocId(docId);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/compliance/${docId}/ai-parse`, { method: "POST" });
      loadVendor();
    } catch { /* ignore */ }
    setParsingDocId(null);
  };

  const discoverSbom = async () => {
    setDiscoveringSbom(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/sbom/discover`, { method: "POST" });
      setTimeout(loadVendor, 12000);
    } catch { /* ignore */ }
    setDiscoveringSbom(false);
  };

  const deepScanFourthParties = async () => {
    setDeepScanning4p(true);
    try {
      await apiFetch(`/api/tprm/vendors/${id}/fourth-party/deep-scan`, { method: "POST" });
      setTimeout(loadVendor, 15000);
    } catch { /* ignore */ }
    setDeepScanning4p(false);
  };

  const propagateFindings = async () => {
    setPropagating(true);
    setPropagateResult(null);
    try {
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/propagate-findings`, { method: "POST" });
      setPropagateResult(r.message);
    } catch { /* ignore */ }
    setPropagating(false);
  };

  if (loading) return <div className="p-6"><Skeleton className="h-48 w-full" /></div>;
  if (!vendor) return <div className="p-6 text-muted-foreground">Vendor not found.</div>;

  const latestScore = vendor.riskScores?.[0];
  const historyData = [...(vendor.riskScores ?? [])].reverse().map((r: any, i: number) => ({
    i: i + 1,
    score: r.overallScore,
  }));

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate("/tprm/vendors")}><ArrowLeft className="w-4 h-4" /></Button>
        <div className="flex items-center gap-3 flex-1">
          {vendor.logoUrl ? (
            <img src={vendor.logoUrl} alt={vendor.companyName} className="w-12 h-12 rounded bg-white/10 object-contain p-1 shrink-0" />
          ) : (
            <div className="w-12 h-12 rounded bg-muted flex items-center justify-center text-lg font-bold shrink-0">{vendor.companyName[0]}</div>
          )}
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold">{vendor.companyName}</h1>
              {gradeBadge(vendor.riskGrade)}
              {vendor.isGlobal && <Badge variant="secondary" className="text-[10px]">Global</Badge>}
            </div>
            <p className="text-sm text-muted-foreground flex items-center gap-1"><Globe className="w-3.5 h-3.5" />{vendor.domain}</p>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={triggerScan} disabled={scanning}>
          {scanning ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : <RefreshCw className="w-4 h-4 mr-1.5" />}
          {scanning ? "Scanning…" : "Scan Now"}
        </Button>
      </div>

      {/* Score overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card className="bg-card/60 col-span-2 md:col-span-1">
          <CardContent className="pt-4 pb-3 flex flex-col items-center justify-center h-full gap-1">
            <p className="text-xs text-muted-foreground uppercase tracking-wider">Overall Score</p>
            <p className="text-4xl font-bold">{vendor.riskScore}</p>
            {gradeBadge(vendor.riskGrade)}
          </CardContent>
        </Card>
        {SCORE_CATEGORIES.slice(0, 3).map(cat => (
          <Card key={cat.key} className="bg-card/50">
            <CardContent className="pt-3 pb-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">{cat.label}</p>
              <p className="text-xl font-semibold">{latestScore?.[cat.key] ?? "—"}</p>
              {latestScore && <Progress value={latestScore[cat.key]} className="h-1 mt-1" />}
            </CardContent>
          </Card>
        ))}
        <Card className="bg-card/50">
          <CardContent className="pt-3 pb-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Dark Web Mentions</p>
            <p className={`text-xl font-semibold ${(vendor.darkWebMentions ?? 0) > 0 ? "text-red-400" : ""}`}>{vendor.darkWebMentions ?? 0}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{vendor.assessmentType === "continuous" ? "Continuous" : vendor.assessmentType === "one_time" ? "One-Time" : "—"} scan</p>
          </CardContent>
        </Card>
      </div>

      {/* Score delta stats + Insights from last scan */}
      {(() => {
        const curr = vendor.riskScores?.[0];
        const prev = vendor.riskScores?.[1];
        const delta = curr && prev ? curr.overallScore - prev.overallScore : null;
        const openFindings   = (vendor.findings ?? []).filter((f: any) => f.status === "open");
        const mitigated      = (vendor.findings ?? []).filter((f: any) => f.status === "mitigated");
        const criticalCount  = openFindings.filter((f: any) => f.severity === "critical").length;
        return (
          <div className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {[
                {
                  label: "Score Change",
                  value: delta !== null ? (delta >= 0 ? `+${delta}` : `${delta}`) : "—",
                  sub: delta !== null ? (delta > 0 ? "Increased" : delta < 0 ? "Improved" : "No change") : "Need 2+ scans",
                  color: delta !== null ? (delta > 0 ? "text-red-400" : delta < 0 ? "text-green-400" : "text-muted-foreground") : "text-muted-foreground",
                  icon: delta !== null && delta > 0 ? "↑" : delta !== null && delta < 0 ? "↓" : "—",
                },
                { label: "Open Issues",   value: openFindings.length,  sub: "Active findings",         color: openFindings.length > 0 ? "text-red-400" : "text-green-400",    icon: "!" },
                { label: "Issues Solved", value: mitigated.length,     sub: "Mitigated",               color: mitigated.length > 0 ? "text-green-400" : "text-muted-foreground", icon: "✓" },
                { label: "Total Issues",  value: (vendor.findings ?? []).length, sub: "All findings",  color: "text-foreground",     icon: "#" },
                { label: "Total Assets",  value: (vendor.assets ?? []).length,   sub: "Discovered",   color: "text-blue-400",       icon: "◈" },
              ].map(s => (
                <Card key={s.label} className="bg-card/50">
                  <CardContent className="pt-3 pb-3">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</p>
                    <p className={`text-2xl font-bold mt-0.5 ${s.color}`}>{s.value}</p>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
            {/* Insights from last scan — always show when any findings or score change */}
            {(openFindings.length > 0 || mitigated.length > 0 || delta !== null) && (() => {
              const highCount  = openFindings.filter((f: any) => f.severity === "high").length;
              const medCount   = openFindings.filter((f: any) => f.severity === "medium").length;
              const hasWarning = criticalCount > 0 || highCount > 0 || (delta !== null && delta > 5);
              return (
                <Card className={hasWarning ? "border-orange-500/30 bg-orange-500/5" : "border-green-500/30 bg-green-500/5"}>
                  <CardContent className="py-3">
                    <p className={`text-xs font-semibold mb-1.5 ${hasWarning ? "text-orange-300" : "text-green-300"}`}>Insights from last scan</p>
                    <div className="flex flex-wrap gap-2 text-xs">
                      {criticalCount > 0 && <span className="bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded">{criticalCount} critical finding{criticalCount > 1 ? "s" : ""} require immediate attention</span>}
                      {highCount > 0 && <span className="bg-orange-500/20 text-orange-300 border border-orange-500/30 px-2 py-0.5 rounded">{highCount} high severity issue{highCount > 1 ? "s" : ""} open</span>}
                      {medCount > 0 && <span className="bg-yellow-500/20 text-yellow-300 border border-yellow-500/30 px-2 py-0.5 rounded">{medCount} medium severity issue{medCount > 1 ? "s" : ""}</span>}
                      {mitigated.length > 0 && <span className="bg-green-500/20 text-green-300 border border-green-500/30 px-2 py-0.5 rounded">{mitigated.length} issue{mitigated.length > 1 ? "s" : ""} mitigated</span>}
                      {delta !== null && delta > 5 && <span className="bg-red-500/20 text-red-300 border border-red-500/30 px-2 py-0.5 rounded">Risk score increased by {delta} points since last scan</span>}
                      {delta !== null && delta < -5 && <span className="bg-green-500/20 text-green-300 border border-green-500/30 px-2 py-0.5 rounded">Risk score improved by {Math.abs(delta)} points</span>}
                      {delta !== null && delta >= -5 && delta <= 5 && <span className="bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded">Risk score stable (Δ {delta >= 0 ? "+" : ""}{delta})</span>}
                      {openFindings.length === 0 && mitigated.length === 0 && <span className="bg-green-500/20 text-green-300 border border-green-500/30 px-2 py-0.5 rounded">No open findings — clean scan</span>}
                    </div>
                  </CardContent>
                </Card>
              );
            })()}
          </div>
        );
      })()}

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="h-8 text-xs flex-wrap gap-0.5">
          <TabsTrigger value="overview" className="text-xs">Overview</TabsTrigger>
          <TabsTrigger value="findings" className="text-xs">Findings ({vendor.findings?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="remediation" className="text-xs">Remediation & Tasks</TabsTrigger>
          <TabsTrigger value="assets" className="text-xs">Assets ({vendor.assets?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="fourth-party" className="text-xs">4th Party ({vendor.fourthParties?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="intelligence" className="text-xs">Intelligence</TabsTrigger>
          <TabsTrigger value="compliance" className="text-xs">Compliance ({vendor.complianceDocs?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="questionnaires" className="text-xs">Questionnaires ({vendor.questionnaires?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="sbom" className="text-xs">SBOM</TabsTrigger>
          <TabsTrigger value="contacts" className="text-xs">Contacts ({vendor.contacts?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="sla" className="text-xs">SLA</TabsTrigger>
        </TabsList>

        {/* Overview */}
        <TabsContent value="overview" className="space-y-4 mt-4">
          <div className="grid md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Risk Score History</CardTitle></CardHeader>
              <CardContent>
                {historyData.length < 2 ? (
                  <p className="text-xs text-muted-foreground py-6 text-center">Needs 2+ scans for history</p>
                ) : (
                  <ResponsiveContainer width="100%" height={140}>
                    <LineChart data={historyData}>
                      <CartesianGrid strokeDasharray="3 3" opacity={0.1} />
                      <XAxis dataKey="i" tick={{ fontSize: 10 }} />
                      <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} width={28} />
                      <Tooltip />
                      <Line type="monotone" dataKey="score" stroke="#3b82f6" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Score Breakdown</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {SCORE_CATEGORIES.map(cat => (
                  <div key={cat.key} className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground w-24 shrink-0">{cat.label}</span>
                    <Progress value={latestScore?.[cat.key] ?? 0} className="h-1.5 flex-1" />
                    <span className="text-xs font-medium w-8 text-right">{latestScore?.[cat.key] ?? "—"}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Company Info</CardTitle></CardHeader>
              <CardContent className="text-sm space-y-2">
                {[
                  ["Industry", vendor.industry], ["Location", vendor.location],
                  ["Company Type", vendor.companyType], ["Founded", vendor.founded],
                  ["Employees", vendor.employeeCount ? vendor.employeeCount.toLocaleString() : null],
                  ["Market Cap", vendor.marketCap ?? null],
                  ["Assessment Type", vendor.assessmentType === "continuous" ? "Continuous" : vendor.assessmentType === "one_time" ? "One-Time" : (vendor.assessmentType ?? null)],
                  ["Scan Frequency", vendor.scanFrequency ? vendor.scanFrequency.charAt(0).toUpperCase() + vendor.scanFrequency.slice(1) : null],
                  ["Inherent Risk", vendor.inherentRisk], ["Business Impact", `${vendor.businessImpact}/10`],
                ].filter(([, v]) => v).map(([k, v]) => (
                  <div key={k as string} className="flex justify-between">
                    <span className="text-muted-foreground">{k}</span>
                    <span className="font-medium capitalize">{v as string}</span>
                  </div>
                ))}
                {vendor.website && (
                  <a href={vendor.website} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-primary hover:underline text-xs mt-1">
                    <Globe className="w-3 h-3" />{vendor.website}
                  </a>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">4th Parties Detected</CardTitle></CardHeader>
              <CardContent>
                {(vendor.fourthParties ?? []).length === 0 ? (
                  <p className="text-xs text-muted-foreground">None detected yet — run a scan to discover</p>
                ) : (
                  <div className="space-y-1.5">
                    {(vendor.fourthParties ?? []).slice(0, 6).map((fp: any) => (
                      <div key={fp.id} className="flex items-center justify-between text-sm">
                        <span className="font-medium">{fp.name}</span>
                        <Badge variant="outline" className="text-[10px]">{fp.discoveryMethod.replace(/_/g, " ")}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Findings */}
        <TabsContent value="findings" className="mt-4">
          <Card>
            <CardContent className="pt-4">
              {(vendor.findings ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground py-6 text-center">No findings — run a scan to detect issues</p>
              ) : (
                <div className="space-y-1">
                  {(vendor.findings ?? []).map((f: any) => (
                    <div key={f.id} className="flex items-start gap-3 p-2.5 rounded hover:bg-accent/30 transition-colors">
                      <div className="mt-0.5">{severityBadge(f.severity)}</div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{f.title}</p>
                        <p className="text-xs text-muted-foreground truncate">{f.description}</p>
                        {f.remediation && <p className="text-xs text-blue-400 mt-0.5 truncate">Fix: {f.remediation}</p>}
                      </div>
                      <div className="text-right shrink-0">
                        {f.cvss && <span className="text-xs text-muted-foreground">CVSS {f.cvss.toFixed(1)}</span>}
                        {f.cve && <p className="text-[10px] text-orange-400">{f.cve}</p>}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Remediation & Tasks */}
        <TabsContent value="remediation" className="mt-4 space-y-3">
          {(() => {
            const remFindings = (vendor.findings ?? []).filter((f: any) => f.remediation || f.severity === "critical" || f.severity === "high");
            const byPriority = {
              critical: remFindings.filter((f: any) => f.severity === "critical"),
              high: remFindings.filter((f: any) => f.severity === "high"),
              medium: remFindings.filter((f: any) => f.severity === "medium"),
              low: remFindings.filter((f: any) => f.severity === "low" || f.severity === "info"),
            };
            return (
              <>
                {remFindings.length === 0 ? (
                  <Card className="border-dashed">
                    <CardContent className="py-12 text-center">
                      <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
                      <p className="text-sm font-medium text-green-400">No remediation tasks</p>
                      <p className="text-xs text-muted-foreground mt-1">All findings are mitigated or none detected yet</p>
                    </CardContent>
                  </Card>
                ) : (
                  <>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { label: "Critical", count: byPriority.critical.length, color: "text-red-400",    bg: "bg-red-500/10" },
                        { label: "High",     count: byPriority.high.length,     color: "text-orange-400", bg: "bg-orange-500/10" },
                        { label: "Medium",   count: byPriority.medium.length,   color: "text-yellow-400", bg: "bg-yellow-500/10" },
                        { label: "Low/Info", count: byPriority.low.length,      color: "text-blue-400",   bg: "bg-blue-500/10" },
                      ].map(p => (
                        <Card key={p.label} className={`${p.bg} border-transparent`}>
                          <CardContent className="py-3 text-center">
                            <p className={`text-2xl font-bold ${p.color}`}>{p.count}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{p.label}</p>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                    <div className="space-y-2">
                      {remFindings.map((f: any, idx: number) => (
                        <Card key={f.id} className="bg-card/60">
                          <CardContent className="py-3">
                            <div className="flex items-start gap-3">
                              <div className="shrink-0 mt-0.5">{severityBadge(f.severity)}</div>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-start justify-between gap-2">
                                  <p className="text-sm font-medium">{f.title}</p>
                                  <Badge variant="outline" className="text-[10px] shrink-0">{f.status?.replace(/_/g, " ")}</Badge>
                                </div>
                                {f.description && <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{f.description}</p>}
                                {f.remediation && (
                                  <div className="mt-2 p-2 rounded bg-blue-500/10 border border-blue-500/20">
                                    <p className="text-[10px] text-blue-400 font-semibold uppercase tracking-wider mb-0.5">Remediation Task</p>
                                    <p className="text-xs text-blue-300">{f.remediation}</p>
                                  </div>
                                )}
                                <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                                  {f.cvss && <span>CVSS {f.cvss.toFixed(1)}</span>}
                                  {f.cve && <span className="text-orange-400">{f.cve}</span>}
                                  {f.isKev && <span className="bg-red-600/20 text-red-400 border border-red-600/30 px-1 py-0.5 rounded text-[9px] font-bold flex items-center gap-0.5"><Flame className="w-2.5 h-2.5" />KEV</span>}
                                  {f.epss != null && <span className="text-purple-400">EPSS {(f.epss * 100).toFixed(1)}%</span>}
                                  {f.category && <span className="capitalize">{f.category.replace(/_/g, " ")}</span>}
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </>
                )}
              </>
            );
          })()}
        </TabsContent>

        {/* Assets */}
        <TabsContent value="assets" className="mt-4 space-y-4">
          {(() => {
            const assets = vendor.assets ?? [];
            const typeCounts: Record<string, number> = {};
            for (const a of assets) typeCounts[a.assetType] = (typeCounts[a.assetType] ?? 0) + 1;
            const typeChartData = Object.entries(typeCounts).map(([type, count]) => ({ type: type.replace(/_/g, " "), count })).sort((a, b) => b.count - a.count);
            const ipAssets = assets.filter((a: any) => a.assetType === "ip");
            return (
              <>
                {/* IPs Distribution */}
                {typeChartData.length > 0 && (
                  <div className="grid md:grid-cols-2 gap-4">
                    <Card>
                      <CardHeader className="pb-2"><CardTitle className="text-sm">IPs Distribution by Asset Type</CardTitle></CardHeader>
                      <CardContent>
                        <ResponsiveContainer width="100%" height={160}>
                          <BarChart data={typeChartData} barSize={28} layout="vertical">
                            <XAxis type="number" tick={{ fontSize: 10 }} allowDecimals={false} />
                            <YAxis type="category" dataKey="type" tick={{ fontSize: 10 }} width={80} />
                            <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} />
                            <Bar dataKey="count" name="Assets" fill="#3b82f6" radius={[0, 3, 3, 0]} />
                          </BarChart>
                        </ResponsiveContainer>
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader className="pb-2"><CardTitle className="text-sm">Geolocation</CardTitle></CardHeader>
                      <CardContent>
                        {ipAssets.length === 0 ? (
                          <p className="text-xs text-muted-foreground py-4 text-center">No IP assets to geolocate</p>
                        ) : (
                          <div className="space-y-1.5">
                            <p className="text-xs text-muted-foreground mb-2">{ipAssets.length} IP address{ipAssets.length > 1 ? "es" : ""} discovered</p>
                            {ipAssets.slice(0, 8).map((a: any) => (
                              <div key={a.id} className="flex items-center gap-2 text-xs">
                                <Badge variant="outline" className="text-[10px]">IP</Badge>
                                <span className="font-mono flex-1 truncate">{a.value}</span>
                                {a.riskLevel && <Badge variant="outline" className="text-[10px]">{a.riskLevel}</Badge>}
                              </div>
                            ))}
                            {ipAssets.length > 8 && <p className="text-[10px] text-muted-foreground text-center">+{ipAssets.length - 8} more IPs</p>}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>
                )}
                <Card>
                  <CardContent className="pt-4">
                    {assets.length === 0 ? (
                      <p className="text-sm text-muted-foreground py-6 text-center">No assets discovered yet</p>
                    ) : (
                      <div className="divide-y divide-border/50">
                        {assets.map((a: any) => (
                          <div key={a.id} className="flex items-center gap-3 py-2">
                            <Badge variant="outline" className="text-[10px] shrink-0">{a.assetType}</Badge>
                            <span className="text-sm font-mono flex-1 truncate">{a.value}</span>
                            <Badge variant="outline" className="text-[10px]">{a.riskLevel}</Badge>
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              </>
            );
          })()}
        </TabsContent>

        {/* 4th Party */}
        <TabsContent value="fourth-party" className="mt-4 space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <p className="text-sm text-muted-foreground">{(vendor.fourthParties ?? []).length} dependencies across {new Set((vendor.fourthParties ?? []).map((f: any) => f.category)).size} categories</p>
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={deepScanFourthParties} disabled={deepScanning4p}>
                {deepScanning4p ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <ScanSearch className="w-3.5 h-3.5 mr-1.5" />}
                Deep Security Scan
              </Button>
              <Button size="sm" variant="outline" onClick={rescanFourthParties} disabled={rescanning4p}>
                {rescanning4p ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Search className="w-3.5 h-3.5 mr-1.5" />}
                Rescan Dependencies
              </Button>
              <Button size="sm" variant="outline" onClick={propagateFindings} disabled={propagating}>
                {propagating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5 mr-1.5" />}
                Propagate to Platform
              </Button>
            </div>
          </div>
          {propagateResult && (
            <Card className="bg-blue-500/10 border-blue-500/30"><CardContent className="py-2 text-sm text-blue-300">{propagateResult}</CardContent></Card>
          )}
          {(() => {
            const fps: any[] = vendor.fourthParties ?? [];
            const byCategory = fps.reduce((acc: Record<string, any[]>, fp: any) => {
              const cat = fp.category ?? "infrastructure";
              if (!acc[cat]) acc[cat] = [];
              acc[cat].push(fp);
              return acc;
            }, {});
            const catColors: Record<string, string> = {
              payments: "text-red-400 bg-red-500/10",
              auth: "text-orange-400 bg-orange-500/10",
              cdn: "text-blue-400 bg-blue-500/10",
              waf: "text-purple-400 bg-purple-500/10",
              analytics: "text-green-400 bg-green-500/10",
              advertising: "text-yellow-400 bg-yellow-500/10",
              monitoring: "text-cyan-400 bg-cyan-500/10",
              communication: "text-indigo-400 bg-indigo-500/10",
              marketing: "text-pink-400 bg-pink-500/10",
              infrastructure: "text-slate-400 bg-slate-500/10",
              security: "text-emerald-400 bg-emerald-500/10",
              media: "text-violet-400 bg-violet-500/10",
              devtools: "text-amber-400 bg-amber-500/10",
              cms: "text-teal-400 bg-teal-500/10",
              ca: "text-gray-400 bg-gray-500/10",
            };
            const riskColors: Record<string, string> = { critical: "text-red-400", high: "text-orange-400", medium: "text-yellow-400", low: "text-green-400" };
            if (fps.length === 0) return (
              <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No 4th parties discovered. Run a scan to detect CDNs, analytics providers, and third-party dependencies.</CardContent></Card>
            );
            return (
              <div className="space-y-4">
                {(Object.entries(byCategory) as [string, any[]][]).sort((a, b) => b[1].length - a[1].length).map(([cat, items]) => (
                  <Card key={cat} className="bg-card/60">
                    <CardHeader className="pb-2 pt-3 px-4">
                      <CardTitle className="text-xs font-semibold uppercase tracking-wide flex items-center gap-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${catColors[cat] ?? catColors.infrastructure}`}>{cat}</span>
                        <span className="text-muted-foreground font-normal normal-case tracking-normal">{items.length} {items.length === 1 ? "provider" : "providers"}</span>
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="px-4 pb-3 space-y-1.5">
                      {items.map((fp: any) => (
                        <div key={fp.id} className="flex items-center gap-2 py-1.5 border-b border-border/30 last:border-0">
                          <Building2 className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                          <div className="flex-1 min-w-0">
                            <span className="text-sm font-medium">{fp.name}</span>
                            {fp.domain && <span className="text-xs text-muted-foreground ml-2">{fp.domain}</span>}
                          </div>
                          {fp.confidence && <span className="text-[10px] text-muted-foreground">{fp.confidence}% conf.</span>}
                          <span className={`text-[10px] font-semibold ${riskColors[fp.riskLevel] ?? riskColors.low}`}>{fp.riskLevel}</span>
                          <Badge variant="outline" className="text-[10px]">{(fp.discoveryMethod ?? "").replace(/_/g, " ")}</Badge>
                          <span className="text-xs text-muted-foreground shrink-0">+{fp.riskContribution}</span>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ))}
              </div>
            );
          })()}
        </TabsContent>

        {/* Intelligence — Security Analysis + Breach Intel */}
        <TabsContent value="intelligence" className="mt-4 space-y-4">
          {loadingIntel ? (
            <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
          ) : (
            <>
              {/* Security Analysis Scorecard */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2"><Shield className="w-4 h-4" />Security Posture Analysis</CardTitle>
                </CardHeader>
                <CardContent>
                  {!secAnalysis ? (
                    <div className="text-center py-6 text-sm text-muted-foreground">
                      <p>No security analysis available. Run a vendor scan to generate a full security scorecard.</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      <div className="flex items-center gap-4">
                        <div className="flex flex-col items-center justify-center w-16 h-16 rounded-full border-2 border-current text-2xl font-bold"
                          style={{ color: secAnalysis.overallGrade?.startsWith("A") ? "#22c55e" : secAnalysis.overallGrade?.startsWith("B") ? "#3b82f6" : secAnalysis.overallGrade?.startsWith("C") ? "#eab308" : "#ef4444" }}>
                          {secAnalysis.overallGrade ?? "?"}
                        </div>
                        <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-3">
                          {[
                            { label: "Security Headers", score: secAnalysis.securityHeadersScore, icon: <Lock className="w-3 h-3" /> },
                            { label: "DNS Health",       score: secAnalysis.dnsHealthScore,       icon: <Globe className="w-3 h-3" /> },
                            { label: "TLS/SSL",          score: secAnalysis.sslScore,             icon: <Shield className="w-3 h-3" /> },
                            { label: "Cookies",          score: secAnalysis.cookieScore,          icon: <Database className="w-3 h-3" /> },
                          ].map(c => (
                            <div key={c.label} className="flex flex-col gap-1">
                              <div className="flex items-center gap-1 text-[10px] text-muted-foreground">{c.icon}{c.label}</div>
                              <div className="flex items-center gap-2">
                                <Progress value={c.score} className="h-1.5 flex-1" />
                                <span className="text-xs font-bold w-7 text-right">{c.score}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* HTTP Header Details */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-2 border-t border-border/30">
                        {[
                          { label: "HSTS",                val: secAnalysis.hsts },
                          { label: "CSP",                 val: secAnalysis.csp },
                          { label: "X-Frame-Options",     val: !!secAnalysis.xFrameOptions },
                          { label: "X-Content-Type",      val: secAnalysis.xContentType },
                          { label: "Referrer-Policy",     val: !!secAnalysis.referrerPolicy },
                          { label: "Permissions-Policy",  val: secAnalysis.permissionsPolicy },
                          { label: "COEP",                val: secAnalysis.coep },
                          { label: "COOP",                val: secAnalysis.coop },
                        ].map(h => (
                          <div key={h.label} className="flex items-center gap-1.5 text-xs">
                            {h.val ? <CheckCircle2 className="w-3 h-3 text-green-400 shrink-0" /> : <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />}
                            <span className={h.val ? "text-foreground" : "text-muted-foreground"}>{h.label}</span>
                          </div>
                        ))}
                      </div>

                      {/* DNS Details */}
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2 pt-2 border-t border-border/30">
                        <div className="flex items-center gap-1.5 text-xs">
                          {secAnalysis.spfRecord ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}
                          <span>SPF {secAnalysis.spfPolicy ? <span className="text-muted-foreground">({secAnalysis.spfPolicy})</span> : null}</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs">
                          {secAnalysis.dmarcRecord ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}
                          <span>DMARC {secAnalysis.dmarcDisposition ? <span className="text-muted-foreground">({secAnalysis.dmarcDisposition})</span> : null}</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs">
                          {(secAnalysis.dkimSelectors as any[])?.length > 0 ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}
                          <span>DKIM ({(secAnalysis.dkimSelectors as any[])?.length ?? 0} selectors)</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs">
                          {(secAnalysis.caaRecords as any[])?.length > 0 ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <AlertTriangle className="w-3 h-3 text-yellow-400" />}
                          <span>CAA Records ({(secAnalysis.caaRecords as any[])?.length ?? 0})</span>
                        </div>
                        <div className="flex items-center gap-1.5 text-xs">
                          {secAnalysis.sslGrade ? <CheckCircle2 className="w-3 h-3 text-green-400" /> : <AlertTriangle className="w-3 h-3 text-red-400" />}
                          <span>SSL Grade: {secAnalysis.sslGrade ?? "Unknown"} {secAnalysis.sslExpiryDays != null ? <span className="text-muted-foreground">({secAnalysis.sslExpiryDays}d)</span> : null}</span>
                        </div>
                      </div>

                      {secAnalysis.totalCookies > 0 && (
                        <div className="flex gap-4 pt-2 border-t border-border/30 text-xs">
                          <span className="text-muted-foreground">Cookies: {secAnalysis.totalCookies} total</span>
                          <span className={secAnalysis.cookiesSecure === secAnalysis.totalCookies ? "text-green-400" : "text-yellow-400"}>{secAnalysis.cookiesSecure} Secure</span>
                          <span className={secAnalysis.cookiesHttponly === secAnalysis.totalCookies ? "text-green-400" : "text-yellow-400"}>{secAnalysis.cookiesHttponly} HttpOnly</span>
                          <span className={secAnalysis.cookiesSamesite > 0 ? "text-green-400" : "text-red-400"}>{secAnalysis.cookiesSamesite} SameSite</span>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Breach Intelligence */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm flex items-center gap-2"><Zap className="w-4 h-4" />Breach Intelligence</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {!breachIntel ? (
                    <p className="text-center py-4 text-sm text-muted-foreground">No breach data available.</p>
                  ) : (
                    <>
                      {(breachIntel.breachEvents ?? []).length === 0 ? (
                        <div className="flex items-center gap-2 text-green-400 py-2">
                          <CheckCircle2 className="w-4 h-4" />
                          <span className="text-sm">No known data breaches found for {breachIntel.domain}</span>
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {(breachIntel.breachEvents as any[]).map((b: any) => (
                            <div key={b.id} className="p-3 rounded border border-red-500/20 bg-red-500/5 space-y-1">
                              <div className="flex items-center gap-2">
                                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                <span className="text-sm font-medium">{b.breachName}</span>
                                {b.breachDate && <span className="text-xs text-muted-foreground">{b.breachDate}</span>}
                                {b.isSensitive && <Badge variant="destructive" className="text-[10px] py-0">Sensitive</Badge>}
                                {b.isVerified && <Badge variant="outline" className="text-[10px] py-0 text-green-400 border-green-500/30">Verified</Badge>}
                              </div>
                              {b.pwnCount > 0 && (
                                <p className="text-xs text-muted-foreground">{b.pwnCount.toLocaleString()} accounts compromised</p>
                              )}
                              {(b.dataClasses as string[])?.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-1">
                                  {(b.dataClasses as string[]).slice(0, 8).map((dc: string) => (
                                    <span key={dc} className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground">{dc}</span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Lookalike Domains */}
                      {(breachIntel.lookalikes ?? []).length > 0 && (
                        <div className="space-y-2 pt-2 border-t border-border/30">
                          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide flex items-center gap-1.5"><Eye className="w-3 h-3" />Lookalike / Typosquatting Domains ({(breachIntel.lookalikes as any[]).length})</p>
                          <div className="space-y-1.5">
                            {(breachIntel.lookalikes as any[]).map((l: any, i: number) => (
                              <div key={i} className="flex items-center gap-2 p-2 rounded bg-orange-500/10 border border-orange-500/20">
                                <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                                <span className="text-sm font-mono">{l.domain}</span>
                                <span className="text-[10px] text-muted-foreground ml-auto">{l.technique}</span>
                                {l.registered && <Badge variant="destructive" className="text-[10px] py-0">Registered</Badge>}
                                {l.httpLive && <Badge className="text-[10px] py-0 bg-orange-500/20 text-orange-300 border-orange-500/30">HTTP Live</Badge>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* Compliance */}
        <TabsContent value="compliance" className="mt-4 space-y-4">

          {/* ── Active Reminders Banner ─────────────────────────────────────── */}
          {reminders.length > 0 && (
            <Card className="border-yellow-500/30 bg-yellow-500/5">
              <CardHeader className="pb-2 pt-3">
                <CardTitle className="text-sm flex items-center justify-between">
                  <span className="flex items-center gap-2 text-yellow-400"><Bell className="w-4 h-4" />Active Reminders ({reminders.length})</span>
                  <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowAddReminder(true)}>
                    <Plus className="w-3 h-3 mr-1" />Add Reminder
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-3 space-y-2">
                {reminders.map((r: any) => {
                  const due = new Date(r.dueDate);
                  const daysUntil = Math.ceil((due.getTime() - Date.now()) / 86400000);
                  const isOverdue = daysUntil < 0;
                  return (
                    <div key={r.id} className={`flex items-center gap-3 p-2 rounded border text-xs ${isOverdue ? "bg-red-500/10 border-red-500/30" : "bg-muted/30 border-border/50"}`}>
                      <div className="flex-1 min-w-0">
                        <p className="font-medium">{r.title}</p>
                        <p className={`text-[10px] mt-0.5 ${isOverdue ? "text-red-400" : "text-muted-foreground"}`}>
                          {isOverdue ? `Overdue by ${Math.abs(daysUntil)}d` : `Due in ${daysUntil}d`} • {due.toLocaleDateString()} • {r.type.replace(/_/g, " ")}
                        </p>
                        {r.notes && <p className="text-[10px] text-muted-foreground truncate">{r.notes}</p>}
                      </div>
                      <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-yellow-400 shrink-0" title="Dismiss" onClick={() => dismissReminder(r.id)}>
                        <BellOff className="w-3 h-3" />
                      </Button>
                      <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-red-400 shrink-0" title="Delete" onClick={() => deleteReminder(r.id)}>
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}
          {reminders.length === 0 && (
            <div className="flex justify-end">
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowAddReminder(true)}>
                <Bell className="w-3 h-3 mr-1" />Set Reminder
              </Button>
            </div>
          )}

          {/* ── Compliance Sub-tabs ─────────────────────────────────────────── */}
          <div className="flex gap-1 border-b border-border/50 pb-0">
            {(["controls", "documents", "requirements"] as const).map(st => (
              <button key={st} onClick={() => setComplianceTab(st)}
                className={`px-3 py-1.5 text-xs font-medium rounded-t-md border-b-2 transition-colors capitalize ${complianceTab === st ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"}`}>
                {st === "controls" ? `Controls (${controls.length})` : st === "documents" ? `Documents (${(vendor.complianceDocs ?? []).length})` : `Requirements (${requirements.length})`}
              </button>
            ))}
          </div>

          {/* ── Controls sub-tab ───────────────────────────────────────────── */}
          {complianceTab === "controls" && (
            <div className="space-y-4">
              {/* Framework selector + scorecard */}
              <Card>
                <CardContent className="py-3 space-y-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Select value={controlFramework} onValueChange={v => { setControlFramework(v); loadControls(v); }}>
                      <SelectTrigger className="h-8 text-xs w-40"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                        <SelectItem value="soc2">SOC 2</SelectItem>
                        <SelectItem value="pcidss">PCI DSS v4.0</SelectItem>
                        <SelectItem value="hipaa">HIPAA</SelectItem>
                        <SelectItem value="nist_csf">NIST CSF 2.0</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button size="sm" className="h-8 text-xs" onClick={seedFramework} disabled={seedingFramework}>
                      {seedingFramework ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <ClipboardList className="w-3.5 h-3.5 mr-1" />}
                      Seed Framework Controls
                    </Button>
                    <Button size="sm" variant="outline" className="h-8 text-xs" onClick={() => setShowAddControl(true)}>
                      <Plus className="w-3.5 h-3.5 mr-1" />Add Custom Control
                    </Button>
                    <Button size="sm" variant="ghost" className="h-8 text-xs ml-auto" onClick={() => loadControls()}>
                      <RefreshCw className={`w-3.5 h-3.5 ${loadingControls ? "animate-spin" : ""}`} />
                    </Button>
                  </div>
                  {/* Scorecard */}
                  {controls.length > 0 && (() => {
                    const total = controls.length;
                    const compliant    = controls.filter(c => c.status === "compliant").length;
                    const partial      = controls.filter(c => c.status === "partial").length;
                    const nonCompliant = controls.filter(c => c.status === "non_compliant").length;
                    const na           = controls.filter(c => c.status === "not_applicable").length;
                    const pending      = controls.filter(c => c.status === "pending_review").length;
                    const score = total - na > 0 ? Math.round(((compliant + partial * 0.5) / (total - na)) * 100) : 0;
                    return (
                      <div className="grid grid-cols-5 gap-2">
                        {[
                          { label: "Compliant",     count: compliant,    color: "text-green-400",  bg: "bg-green-500/10"  },
                          { label: "Partial",        count: partial,      color: "text-yellow-400", bg: "bg-yellow-500/10" },
                          { label: "Non-Compliant",  count: nonCompliant, color: "text-red-400",    bg: "bg-red-500/10"    },
                          { label: "Pending Review", count: pending,      color: "text-blue-400",   bg: "bg-blue-500/10"   },
                          { label: "Not Applicable", count: na,           color: "text-slate-400",  bg: "bg-slate-500/10"  },
                        ].map(s => (
                          <div key={s.label} className={`rounded p-2 text-center ${s.bg}`}>
                            <p className={`text-lg font-bold ${s.color}`}>{s.count}</p>
                            <p className="text-[10px] text-muted-foreground leading-tight">{s.label}</p>
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </CardContent>
              </Card>

              {/* Controls table */}
              {loadingControls ? (
                <div className="flex items-center justify-center py-10"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
              ) : controls.length === 0 ? (
                <Card className="border-dashed">
                  <CardContent className="py-10 text-center text-sm text-muted-foreground space-y-2">
                    <ClipboardList className="w-8 h-8 mx-auto opacity-30" />
                    <p>No controls loaded yet.</p>
                    <p className="text-xs">Click <strong>Seed Framework Controls</strong> to populate {controlFramework.replace(/_/g, " ").toUpperCase()} controls, or add custom ones.</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-1.5">
                  {controls.map((ctrl: any) => {
                    const statusMap: Record<string, { label: string; color: string; border: string }> = {
                      compliant:       { label: "Compliant",       color: "text-green-400",  border: "border-green-500/30"  },
                      partial:         { label: "Partial",         color: "text-yellow-400", border: "border-yellow-500/30" },
                      non_compliant:   { label: "Non-Compliant",   color: "text-red-400",    border: "border-red-500/30"    },
                      pending_review:  { label: "Pending Review",  color: "text-blue-400",   border: "border-blue-500/30"   },
                      not_applicable:  { label: "N/A",             color: "text-slate-400",  border: "border-slate-500/30"  },
                    };
                    const sm = statusMap[ctrl.status] ?? statusMap.pending_review;
                    const isInactive = ctrl.isActive === false;
                    return (
                      <Card key={ctrl.id} className={`border-l-2 transition-opacity ${sm.border} ${isInactive ? "opacity-50 bg-muted/20" : "bg-card/60"}`}>
                        <CardContent className="py-2.5 px-3">
                          <div className="flex items-start gap-2">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`text-xs font-mono font-semibold ${isInactive ? "text-muted-foreground/50 line-through" : "text-muted-foreground"}`}>{ctrl.controlId}</span>
                                {ctrl.category && <Badge variant="outline" className="text-[10px] py-0 h-4">{ctrl.category}</Badge>}
                                <Badge variant="outline" className={`text-[10px] py-0 h-4 ${sm.color} border-current`}>{sm.label}</Badge>
                                {isInactive && <Badge variant="secondary" className="text-[10px] py-0 h-4 bg-muted/60">Disabled</Badge>}
                              </div>
                              <p className={`text-xs mt-0.5 ${isInactive ? "text-muted-foreground/60" : ""}`}>{ctrl.controlTitle}</p>
                              {ctrl.evidence && <p className="text-[10px] text-muted-foreground mt-0.5 truncate"><span className="font-medium">Evidence:</span> {ctrl.evidence}</p>}
                              {ctrl.assignedTo && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Assigned:</span> {ctrl.assignedTo}</p>}
                              {ctrl.nextReviewAt && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Next review:</span> {new Date(ctrl.nextReviewAt).toLocaleDateString()}</p>}
                              {ctrl.notes && <p className="text-[10px] text-muted-foreground italic">{ctrl.notes}</p>}
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              <Switch
                                checked={ctrl.isActive !== false}
                                className="scale-75"
                                title={ctrl.isActive !== false ? "Disable control" : "Enable control"}
                                onCheckedChange={async (checked) => {
                                  setControls(prev => prev.map(c => c.id === ctrl.id ? { ...c, isActive: checked } : c));
                                  try {
                                    const updated = await apiFetch<any>(`/api/tprm/vendors/${id}/compliance-controls/${ctrl.id}`, { method: "PATCH", body: JSON.stringify({ isActive: checked }) });
                                    setControls(prev => prev.map(c => c.id === updated.id ? updated : c));
                                    toast({ title: checked ? "Control enabled" : "Control disabled", description: ctrl.controlId });
                                  } catch (err: any) {
                                    setControls(prev => prev.map(c => c.id === ctrl.id ? { ...c, isActive: !checked } : c));
                                    toast({ title: "Toggle failed", description: err?.message, variant: "destructive" });
                                  }
                                }}
                              />
                              <Button variant="ghost" size="sm" className="h-6 text-[10px] text-blue-400 hover:text-blue-300 px-2" onClick={() => openEditControl(ctrl)}>
                                <Edit2 className="w-3 h-3 mr-0.5" />Edit
                              </Button>
                              <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-red-400" onClick={() => deleteControl(ctrl.id)} title="Delete control">
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* ── Documents sub-tab ──────────────────────────────────────────── */}
          {complianceTab === "documents" && (
            <div className="space-y-3">
              <div className="flex justify-end gap-2">
                {(vendor.complianceDocs ?? []).some((d: any) => d.status === "pending_review" && d.expiresAt) && (
                  <Button size="sm" variant="outline" onClick={async () => {
                    try {
                      const r = await apiFetch<{ verified: number; message: string }>(`/api/tprm/vendors/${id}/compliance/auto-verify`, { method: "POST" });
                      if (r.verified > 0) loadVendor();
                    } catch { /* ignore */ }
                  }}>
                    <CheckCircle2 className="w-4 h-4 mr-1.5" />Auto-Verify All
                  </Button>
                )}
                <Button size="sm" onClick={() => setShowUploadDoc(true)}><Upload className="w-4 h-4 mr-1.5" />Upload Document</Button>
              </div>
              {(vendor.complianceDocs ?? []).length === 0 ? (
                <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No compliance documents uploaded yet</CardContent></Card>
              ) : (
                <div className="space-y-2">
                  {(vendor.complianceDocs ?? []).map((d: any) => {
                    const exp = d.expiresAt ? new Date(d.expiresAt) : null;
                    const days = exp ? Math.ceil((exp.getTime() - Date.now()) / 86400000) : null;
                    const statusColor = d.status === "valid" ? "border-green-500/40 text-green-400"
                      : d.status === "expiring_soon" ? "border-yellow-500/40 text-yellow-400"
                      : d.status === "expired" ? "border-red-500/40 text-red-400"
                      : "border-muted-foreground/40 text-muted-foreground";
                    return (
                      <Card key={d.id} className="bg-card/60">
                        <CardContent className="py-3 flex items-center gap-3">
                          <FileText className="w-5 h-5 text-muted-foreground shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium">{d.title}</p>
                            <p className="text-xs text-muted-foreground">{d.documentType}{d.auditor ? ` • ${d.auditor}` : ""}</p>
                            {d.auditPeriodStart && <p className="text-xs text-muted-foreground">Period: {d.auditPeriodStart} → {d.auditPeriodEnd}</p>}
                          </div>
                          <div className="text-right shrink-0">
                            {days !== null && (
                              <p className={`text-xs ${days < 0 ? "text-red-400" : days < 30 ? "text-yellow-400" : "text-green-400"}`}>
                                {days < 0 ? `Expired ${Math.abs(days)}d ago` : `${days}d remaining`}
                              </p>
                            )}
                            {d.status && <Badge variant="outline" className={`text-[10px] mt-0.5 ${statusColor}`}>{d.status.replace(/_/g, " ")}</Badge>}
                          </div>
                          {d.fileData && (
                            <Button variant="ghost" size="sm" className="h-7 text-xs text-purple-400 hover:text-purple-300" onClick={() => aiParseDoc(d.id)} disabled={parsingDocId === d.id}>
                              {parsingDocId === d.id ? <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" /> : <Zap className="w-3.5 h-3.5 mr-1" />}AI Parse
                            </Button>
                          )}
                          {d.status === "pending_review" && (
                            <Button variant="ghost" size="sm" className="h-7 text-xs text-green-400 hover:text-green-300" onClick={async () => {
                              try {
                                await apiFetch(`/api/tprm/vendors/${id}/compliance/${d.id}`, { method: "PATCH", body: JSON.stringify({ status: "valid" }) });
                                loadVendor();
                              } catch { /* ignore */ }
                            }}>
                              <CheckCircle2 className="w-3.5 h-3.5 mr-1" />Verify
                            </Button>
                          )}
                          {d.fileName && (
                            <Button variant="ghost" size="icon" className="h-7 w-7" asChild>
                              <a href={`/api/tprm/vendors/${id}/compliance/${d.id}/download`} download={d.fileName}><Download className="w-4 h-4" /></a>
                            </Button>
                          )}
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* ── Requirements sub-tab ───────────────────────────────────────── */}
          {complianceTab === "requirements" && (
            <Card>
              <CardHeader className="pb-2 pt-3">
                <CardTitle className="text-sm flex items-center justify-between">
                  <span className="flex items-center gap-2"><FileText className="w-4 h-4" />Document Requirements</span>
                  <Button size="sm" variant="outline" onClick={() => setShowAddReq(true)}><Plus className="w-3.5 h-3.5 mr-1" />Add Requirement</Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="pb-3">
                {requirements.length === 0 ? (
                  <p className="text-xs text-muted-foreground py-3 text-center">No requirements defined. Add required documents to track vendor compliance obligations.</p>
                ) : (
                  <div className="space-y-2">
                    {requirements.map((r: any) => (
                      <div key={r.id} className="flex items-center gap-3 p-2 rounded bg-muted/30 border border-border/50">
                        <div className="flex-1 min-w-0">
                          <p className="text-xs font-medium">{r.documentType}</p>
                          {r.dueDate && <p className="text-[10px] text-muted-foreground">Due: {new Date(r.dueDate).toLocaleDateString()} • Reminder: {r.reminderDays}d before</p>}
                          {r.notes && <p className="text-[10px] text-muted-foreground">{r.notes}</p>}
                        </div>
                        <Button variant="ghost" size="sm" className="h-6 text-[10px] text-blue-400 hover:text-blue-300" onClick={() => notifyRequirement(r.id)}>
                          <Mail className="w-3 h-3 mr-1" />Notify
                        </Button>
                        <Button variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-red-400" onClick={() => deleteRequirement(r.id)}>
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Questionnaires */}
        <TabsContent value="questionnaires" className="mt-4 space-y-3">
          <div className="flex justify-end gap-2">
            <Button size="sm" asChild><Link href="/tprm/questionnaire-templates"><FileText className="w-4 h-4 mr-1.5" />Manage Templates</Link></Button>
            <Button size="sm" variant="outline" onClick={() => setShowSendQ(true)}><Send className="w-4 h-4 mr-1.5" />Send Questionnaire</Button>
          </div>
          {qPortalLink && (
            <Card className="bg-blue-500/10 border-blue-500/30">
              <CardContent className="py-3 text-sm">
                <p className="font-medium">Questionnaire link ready</p>
                <p className="text-xs text-muted-foreground mt-0.5 font-mono break-all">{qPortalLink}</p>
                <Button variant="link" className="text-xs p-0 h-auto mt-1" onClick={() => { navigator.clipboard.writeText(qPortalLink); }}>Copy link</Button>
              </CardContent>
            </Card>
          )}
          {localQuestionnaires.length === 0 ? (
            <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No questionnaires sent yet</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {localQuestionnaires.map((q: any) => {
                const qStatusColor: Record<string, string> = {
                  sent:        "text-blue-400 border-blue-500/40",
                  in_progress: "text-yellow-400 border-yellow-500/40",
                  completed:   "text-green-400 border-green-500/40",
                  overdue:     "text-red-400 border-red-500/40",
                  expired:     "text-slate-400 border-slate-500/40",
                };
                const qsc = qStatusColor[q.status] ?? "text-slate-400";
                return (
                  <Card key={q.id} className="bg-card/60">
                    <CardContent className="py-3">
                      <div className="flex items-start gap-3">
                        <FileText className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-medium">
                              {q.templateName ?? templates.find((t: any) => t.id === q.templateId)?.name ?? `Questionnaire #${q.id}`}
                            </p>
                            <Badge variant="outline" className={`text-[10px] capitalize ${qsc}`}>{q.status?.replace("_", " ")}</Badge>
                            {q.score !== null && q.score !== undefined && (
                              <span className={`text-xs font-semibold ${q.score >= 80 ? "text-green-400" : q.score >= 50 ? "text-yellow-400" : "text-red-400"}`}>{q.score}/100</span>
                            )}
                            {q.riskLevel && <span className={`text-[10px] font-medium capitalize px-1.5 py-0.5 rounded ${q.riskLevel === "low" ? "bg-green-500/20 text-green-400" : q.riskLevel === "medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-red-500/20 text-red-400"}`}>{q.riskLevel} risk</span>}
                          </div>
                          <div className="flex flex-wrap gap-x-3 mt-0.5">
                            {q.respondedBy && <p className="text-[10px] text-muted-foreground"><span className="font-medium">Respondent:</span> {q.respondedBy}</p>}
                            {q.sentAt && <p className="text-[10px] text-muted-foreground">Sent {new Date(q.sentAt).toLocaleDateString()}</p>}
                            {q.dueDate && <p className="text-[10px] text-muted-foreground">Due {new Date(q.dueDate).toLocaleDateString()}</p>}
                            {q.completedAt && <p className="text-[10px] text-muted-foreground">Completed {new Date(q.completedAt).toLocaleDateString()}</p>}
                          </div>
                          {q.notes && <p className="text-[10px] text-muted-foreground italic mt-0.5">{q.notes}</p>}
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 text-[10px] text-violet-400 hover:text-violet-300 px-2"
                            onClick={() => viewQuestionnaire(q)}
                          >
                            <Eye className="w-3 h-3 mr-0.5" />Responses
                          </Button>
                          <Button
                            variant="ghost" size="sm"
                            className="h-7 text-[10px] text-blue-400 hover:text-blue-300 px-2"
                            onClick={() => openEditQ(q)}
                          >
                            <Edit2 className="w-3 h-3 mr-0.5" />Edit
                          </Button>
                          {q.accessToken && (
                            <Button
                              variant="ghost" size="sm"
                              className="h-7 text-[10px] text-slate-400 hover:text-slate-300 px-2"
                              title="Open vendor questionnaire portal"
                              onClick={() => {
                                const link = `${window.location.origin}/tprm/respond/${q.accessToken}`;
                                window.open(link, "_blank");
                              }}
                            >
                              <ExternalLink className="w-3 h-3 mr-0.5" />Portal
                            </Button>
                          )}
                          <Button
                            variant="ghost" size="icon"
                            className="h-7 w-7 text-muted-foreground hover:text-red-400"
                            title="Delete questionnaire"
                            onClick={() => deleteQ(q)}
                          >
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* SBOM */}
        <TabsContent value="sbom" className="mt-4 space-y-3">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center justify-between">
              <span>Upload SBOM File</span>
              <Button size="sm" variant="outline" onClick={discoverSbom} disabled={discoveringSbom || !vendor.domain}>
                {discoveringSbom ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Search className="w-3.5 h-3.5 mr-1.5" />}
                Auto-Discover
              </Button>
            </CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">Supports CycloneDX JSON/XML and SPDX JSON/tag-value formats. Components are automatically enriched with CVE data from the OSV database. Use <strong>Auto-Discover</strong> to automatically find SBOM files at well-known paths on the vendor domain.</p>
              <div className="flex items-center gap-2">
                <input ref={sbomInputRef} type="file" accept=".json,.xml,.spdx,.txt" className="text-sm file:mr-2 file:text-xs file:py-1 file:px-2 file:rounded file:border-0 file:bg-primary/10 file:text-primary cursor-pointer" onChange={e => setSbomFile(e.target.files?.[0] ?? null)} />
                <Button size="sm" onClick={uploadSbom} disabled={!sbomFile || uploadingSbom}>
                  {uploadingSbom ? <Loader2 className="w-4 h-4 mr-1 animate-spin" /> : <Upload className="w-4 h-4 mr-1" />}
                  {uploadingSbom ? "Processing…" : "Upload"}
                </Button>
              </div>
            </CardContent>
          </Card>
          <Link href={`/tprm/supply-chain?vendorId=${id}`}>
            <Card className="hover:bg-accent/30 cursor-pointer transition-colors">
              <CardContent className="py-3 flex items-center gap-2 text-sm">
                <Package className="w-4 h-4 text-muted-foreground" />
                <span>View supply chain nodes for this vendor</span>
                <ChevronRight className="w-4 h-4 ml-auto text-muted-foreground" />
              </CardContent>
            </Card>
          </Link>
        </TabsContent>

        {/* SLA */}
        <TabsContent value="sla" className="mt-4 space-y-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><RadioTower className="w-4 h-4" />Service Level Agreement</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs">Target Uptime (%)</Label>
                  <Input className="mt-1 h-8 text-sm" type="number" min="0" max="100" step="0.001" placeholder="e.g. 99.9" value={slaForm.slaUptimePercent} onChange={e => setSlaForm(f => ({ ...f, slaUptimePercent: e.target.value }))} />
                </div>
                <div>
                  <Label className="text-xs">Response Time SLA (hours)</Label>
                  <Input className="mt-1 h-8 text-sm" type="number" min="0" placeholder="e.g. 4" value={slaForm.slaResponseTimeHours} onChange={e => setSlaForm(f => ({ ...f, slaResponseTimeHours: e.target.value }))} />
                </div>
                <div>
                  <Label className="text-xs">Review Date</Label>
                  <Input className="mt-1 h-8 text-sm" type="date" value={slaForm.slaReviewDate} onChange={e => setSlaForm(f => ({ ...f, slaReviewDate: e.target.value }))} />
                </div>
                <div>
                  <Label className="text-xs">Breach Count</Label>
                  <Input className="mt-1 h-8 text-sm" type="number" min="0" placeholder="0" value={slaForm.slaBreachCount} onChange={e => setSlaForm(f => ({ ...f, slaBreachCount: e.target.value }))} />
                </div>
              </div>
              <div>
                <Label className="text-xs">SLA Notes</Label>
                <Textarea className="mt-1 text-sm" rows={3} placeholder="Key SLA terms, penalties, exclusions…" value={slaForm.slaNotes} onChange={e => setSlaForm(f => ({ ...f, slaNotes: e.target.value }))} />
              </div>
              <Button size="sm" onClick={saveSla} disabled={savingSla}>
                {savingSla && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save SLA
              </Button>
            </CardContent>
          </Card>

          {/* SLA status summary */}
          {(vendor.slaUptimePercent != null || vendor.slaResponseTimeHours != null) && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {vendor.slaUptimePercent != null && (
                <Card className="bg-card/50">
                  <CardContent className="pt-3 pb-3 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Target Uptime</p>
                    <p className={`text-2xl font-bold ${vendor.slaUptimePercent >= 99.9 ? "text-green-400" : vendor.slaUptimePercent >= 99 ? "text-yellow-400" : "text-red-400"}`}>{vendor.slaUptimePercent}%</p>
                  </CardContent>
                </Card>
              )}
              {vendor.slaResponseTimeHours != null && (
                <Card className="bg-card/50">
                  <CardContent className="pt-3 pb-3 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Response SLA</p>
                    <p className="text-2xl font-bold">{vendor.slaResponseTimeHours}h</p>
                  </CardContent>
                </Card>
              )}
              {vendor.slaBreachCount != null && (
                <Card className={`bg-card/50 ${vendor.slaBreachCount > 0 ? "border-red-500/30" : ""}`}>
                  <CardContent className="pt-3 pb-3 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">SLA Breaches</p>
                    <p className={`text-2xl font-bold ${vendor.slaBreachCount > 0 ? "text-red-400" : "text-green-400"}`}>{vendor.slaBreachCount}</p>
                  </CardContent>
                </Card>
              )}
              {vendor.slaReviewDate && (
                <Card className="bg-card/50">
                  <CardContent className="pt-3 pb-3 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Next Review</p>
                    <p className="text-sm font-medium">{new Date(vendor.slaReviewDate).toLocaleDateString()}</p>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* Contacts */}
        <TabsContent value="contacts" className="mt-4 space-y-3">
          <div className="flex justify-end">
            <Button size="sm" onClick={() => setShowAddContact(true)}><Plus className="w-4 h-4 mr-1.5" />Add Contact</Button>
          </div>
          {(vendor.contacts ?? []).length === 0 ? (
            <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No contacts added</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {(vendor.contacts ?? []).map((c: any) => (
                <Card key={c.id} className="bg-card/60">
                  <CardContent className="py-3 flex items-center gap-3">
                    <User className="w-4 h-4 text-muted-foreground shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <p className="text-sm font-medium">{c.name}</p>
                        {c.isPrimary && <Badge variant="secondary" className="text-[10px]">Primary</Badge>}
                        {c.isEmailVerified
                          ? <Badge className="text-[10px] bg-green-500/20 text-green-400 border-green-500/30">✓ Verified</Badge>
                          : <Badge variant="outline" className="text-[10px] text-muted-foreground">Unverified</Badge>
                        }
                      </div>
                      <p className="text-xs text-muted-foreground">{c.email}{c.role ? ` • ${c.role}` : ""}</p>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {!c.isEmailVerified && (
                        <Button variant="ghost" size="sm" className="h-7 text-xs text-yellow-400 hover:text-yellow-300" onClick={() => sendContactVerification(c.id)}>
                          <Mail className="w-3.5 h-3.5 mr-1" />Verify
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => { setEmailContact(c); setEmailForm({ subject: `Security Update — ${vendor.companyName}`, message: "" }); }}>
                        <Send className="w-3.5 h-3.5 mr-1" />Email
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-red-400" onClick={() => deleteContact(c.id)}>
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>

      {/* Add Contact Dialog */}
      <Dialog open={showAddContact} onOpenChange={setShowAddContact}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add Contact</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div><Label className="text-xs">Name *</Label><Input className="mt-1" value={contactForm.name} onChange={e => setContactForm(f => ({ ...f, name: e.target.value }))} /></div>
            <div><Label className="text-xs">Email *</Label><Input type="email" className="mt-1" value={contactForm.email} onChange={e => setContactForm(f => ({ ...f, email: e.target.value }))} /></div>
            <div><Label className="text-xs">Role</Label><Input className="mt-1" placeholder="e.g. Security Officer" value={contactForm.role} onChange={e => setContactForm(f => ({ ...f, role: e.target.value }))} /></div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddContact(false)}>Cancel</Button>
            <Button onClick={addContact} disabled={savingContact || !contactForm.name || !contactForm.email}>
              {savingContact && <Loader2 className="w-4 h-4 mr-1 animate-spin" />} Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Send Email to Contact Dialog */}
      <Dialog open={!!emailContact} onOpenChange={o => { if (!o) setEmailContact(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>Email {emailContact?.name}</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div><Label className="text-xs">To</Label><Input className="mt-1 h-8 text-sm bg-muted" readOnly value={emailContact?.email ?? ""} /></div>
            <div><Label className="text-xs">Subject *</Label><Input className="mt-1 h-8 text-sm" value={emailForm.subject} onChange={e => setEmailForm(f => ({ ...f, subject: e.target.value }))} /></div>
            <div><Label className="text-xs">Message *</Label><Textarea className="mt-1 text-sm" rows={5} value={emailForm.message} onChange={e => setEmailForm(f => ({ ...f, message: e.target.value }))} placeholder="Enter your message…" /></div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEmailContact(null)}>Cancel</Button>
            <Button onClick={sendContactEmail} disabled={sendingEmail || !emailForm.subject || !emailForm.message}>
              {sendingEmail && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}<Send className="w-4 h-4 mr-1" />Send Email
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Compliance Requirement Dialog */}
      <Dialog open={showAddReq} onOpenChange={setShowAddReq}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add Compliance Requirement</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Document Type *</Label>
              <Select value={reqForm.documentType} onValueChange={v => setReqForm(f => ({ ...f, documentType: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select type" /></SelectTrigger>
                <SelectContent>{["SOC2 Type I", "SOC2 Type II", "ISO 27001", "ISO 27017", "ISO 27701", "PCI DSS", "HIPAA BAA", "GDPR DPA", "CSA STAR", "NIST CSF", "Penetration Test Report", "Insurance Certificate", "Other"].map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div><Label className="text-xs">Due Date</Label><Input type="date" className="mt-1 h-8 text-sm" value={reqForm.dueDate} onChange={e => setReqForm(f => ({ ...f, dueDate: e.target.value }))} /></div>
            <div><Label className="text-xs">Reminder (days before due)</Label><Input type="number" min="1" className="mt-1 h-8 text-sm" value={reqForm.reminderDays} onChange={e => setReqForm(f => ({ ...f, reminderDays: e.target.value }))} /></div>
            <div><Label className="text-xs">Notes</Label><Textarea className="mt-1 text-sm" rows={2} value={reqForm.notes} onChange={e => setReqForm(f => ({ ...f, notes: e.target.value }))} placeholder="Specific requirements or instructions…" /></div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddReq(false)}>Cancel</Button>
            <Button onClick={addRequirement} disabled={savingReq || !reqForm.documentType}>
              {savingReq && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Upload Compliance Document Dialog */}
      <Dialog open={showUploadDoc} onOpenChange={setShowUploadDoc}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle>Upload Compliance Document</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Document Type *</Label>
              <Select value={docForm.documentType} onValueChange={v => setDocForm(f => ({ ...f, documentType: v, title: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select type" /></SelectTrigger>
                <SelectContent>{DOC_TYPES.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div><Label className="text-xs">Title *</Label><Input className="mt-1" value={docForm.title} onChange={e => setDocForm(f => ({ ...f, title: e.target.value }))} /></div>
            <div><Label className="text-xs">Auditor / Certifying Body</Label><Input className="mt-1" placeholder="e.g. Deloitte, KPMG" value={docForm.auditor} onChange={e => setDocForm(f => ({ ...f, auditor: e.target.value }))} /></div>
            <div className="grid grid-cols-2 gap-2">
              <div><Label className="text-xs">Audit Period Start</Label><Input type="date" className="mt-1 h-8 text-sm" value={docForm.auditPeriodStart} onChange={e => setDocForm(f => ({ ...f, auditPeriodStart: e.target.value }))} /></div>
              <div><Label className="text-xs">Audit Period End</Label><Input type="date" className="mt-1 h-8 text-sm" value={docForm.auditPeriodEnd} onChange={e => setDocForm(f => ({ ...f, auditPeriodEnd: e.target.value }))} /></div>
            </div>
            <div><Label className="text-xs">Expiry Date</Label><Input type="date" className="mt-1 h-8 text-sm" value={docForm.expiresAt} onChange={e => setDocForm(f => ({ ...f, expiresAt: e.target.value }))} /></div>
            <div><Label className="text-xs">File (optional)</Label><input type="file" className="mt-1 text-sm w-full file:mr-2 file:text-xs file:py-1 file:px-2 file:rounded file:border-0 file:bg-primary/10 cursor-pointer" onChange={e => setDocFile(e.target.files?.[0] ?? null)} /></div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowUploadDoc(false)}>Cancel</Button>
            <Button onClick={uploadDoc} disabled={savingDoc || !docForm.documentType || !docForm.title}>
              {savingDoc && <Loader2 className="w-4 h-4 mr-1 animate-spin" />} Upload
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Edit Compliance Control Dialog ───────────────────────────────── */}
      <Dialog open={!!editingControl} onOpenChange={o => { if (!o) setEditingControl(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle className="text-base flex items-center gap-2"><ClipboardList className="w-4 h-4" />Update Control Status</DialogTitle></DialogHeader>
          {editingControl && (
            <div className="space-y-3">
              <div className="p-2 rounded bg-muted/30 border border-border/40">
                <p className="text-xs font-mono font-semibold text-muted-foreground">{editingControl.controlId}</p>
                <p className="text-sm font-medium mt-0.5">{editingControl.controlTitle}</p>
              </div>
              <div>
                <Label className="text-xs">Status *</Label>
                <Select value={controlEditForm.status} onValueChange={v => setControlEditForm(f => ({ ...f, status: v }))}>
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
                <Input className="mt-1 h-8 text-sm" placeholder="e.g. SOC2 report §6.1, policy doc link…" value={controlEditForm.evidence} onChange={e => setControlEditForm(f => ({ ...f, evidence: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Assigned To</Label>
                <Input className="mt-1 h-8 text-sm" placeholder="Name or email" value={controlEditForm.assignedTo} onChange={e => setControlEditForm(f => ({ ...f, assignedTo: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Next Review Date</Label>
                <Input type="date" className="mt-1 h-8 text-sm" value={controlEditForm.nextReviewAt} onChange={e => setControlEditForm(f => ({ ...f, nextReviewAt: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Notes</Label>
                <Textarea className="mt-1 text-sm" rows={2} placeholder="Additional context, gaps, remediation plan…" value={controlEditForm.notes} onChange={e => setControlEditForm(f => ({ ...f, notes: e.target.value }))} />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingControl(null)}>Cancel</Button>
            <Button onClick={saveControl} disabled={savingControl}>
              {savingControl && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Custom Control Dialog ─────────────────────────────────────── */}
      <Dialog open={showAddControl} onOpenChange={setShowAddControl}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle className="text-base">Add Custom Control</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Control ID *</Label>
                <Input className="mt-1 h-8 text-sm" placeholder="e.g. CUSTOM-1" value={addControlForm.controlId} onChange={e => setAddControlForm(f => ({ ...f, controlId: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Category</Label>
                <Input className="mt-1 h-8 text-sm" placeholder="e.g. Access Control" value={addControlForm.category} onChange={e => setAddControlForm(f => ({ ...f, category: e.target.value }))} />
              </div>
            </div>
            <div>
              <Label className="text-xs">Control Title *</Label>
              <Input className="mt-1 h-8 text-sm" placeholder="Describe the control requirement" value={addControlForm.controlTitle} onChange={e => setAddControlForm(f => ({ ...f, controlTitle: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Initial Status</Label>
              <Select value={addControlForm.status} onValueChange={v => setAddControlForm(f => ({ ...f, status: v }))}>
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
              <Input className="mt-1 h-8 text-sm" placeholder="Policy doc, audit report link…" value={addControlForm.evidence} onChange={e => setAddControlForm(f => ({ ...f, evidence: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Assigned To</Label>
              <Input className="mt-1 h-8 text-sm" placeholder="Name or email" value={addControlForm.assignedTo} onChange={e => setAddControlForm(f => ({ ...f, assignedTo: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Notes</Label>
              <Textarea className="mt-1 text-sm" rows={2} placeholder="Additional context…" value={addControlForm.notes} onChange={e => setAddControlForm(f => ({ ...f, notes: e.target.value }))} />
            </div>
            <p className="text-[10px] text-muted-foreground">Will be added to framework: <strong>{controlFramework.replace(/_/g, " ").toUpperCase()}</strong></p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddControl(false)}>Cancel</Button>
            <Button onClick={addCustomControl} disabled={savingAddControl || !addControlForm.controlId || !addControlForm.controlTitle}>
              {savingAddControl && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Add Control
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Reminder Dialog ───────────────────────────────────────────── */}
      <Dialog open={showAddReminder} onOpenChange={setShowAddReminder}>
        <DialogContent className="max-w-md">
          <DialogHeader><DialogTitle className="text-base flex items-center gap-2"><Bell className="w-4 h-4" />Set Compliance Reminder</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Title *</Label>
              <Input className="mt-1 h-8 text-sm" placeholder="e.g. SOC2 report renewal, annual pen-test review" value={reminderForm.title} onChange={e => setReminderForm(f => ({ ...f, title: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Type</Label>
              <Select value={reminderForm.type} onValueChange={v => setReminderForm(f => ({ ...f, type: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="custom">Custom</SelectItem>
                  <SelectItem value="document_expiry">Document Expiry</SelectItem>
                  <SelectItem value="control_review">Control Review</SelectItem>
                  <SelectItem value="questionnaire_due">Questionnaire Due</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Due Date *</Label>
              <Input type="date" className="mt-1 h-8 text-sm" value={reminderForm.dueDate} onChange={e => setReminderForm(f => ({ ...f, dueDate: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Notes</Label>
              <Textarea className="mt-1 text-sm" rows={2} placeholder="Additional context or action needed…" value={reminderForm.notes} onChange={e => setReminderForm(f => ({ ...f, notes: e.target.value }))} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddReminder(false)}>Cancel</Button>
            <Button onClick={addReminder} disabled={savingReminder || !reminderForm.title || !reminderForm.dueDate}>
              {savingReminder && <Loader2 className="w-4 h-4 mr-1 animate-spin" />}Save Reminder
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* View Responses Dialog */}
      <Dialog open={!!viewingQ} onOpenChange={open => { if (!open) setViewingQ(null); }}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ClipboardList className="w-4 h-4" />
              {viewingQ?._loading ? "Loading…" : (viewingQ?.template?.name ?? viewingQ?.templateName ?? `Questionnaire #${viewingQ?.id}`)}
            </DialogTitle>
          </DialogHeader>
          {viewingQ?._loading ? (
            <div className="flex items-center justify-center py-12"><Loader2 className="w-6 h-6 animate-spin text-muted-foreground" /></div>
          ) : viewingQ?._error ? (
            <p className="text-sm text-destructive py-6 text-center">Failed to load questionnaire details.</p>
          ) : viewingQ && (
            <div className="space-y-4">
              {/* Summary row */}
              <div className="flex flex-wrap gap-3 p-3 rounded-lg bg-muted/40 text-xs">
                <div><span className="text-muted-foreground">Status: </span><span className="capitalize font-medium">{viewingQ.status?.replace("_", " ")}</span></div>
                {viewingQ.respondedBy && <div><span className="text-muted-foreground">Respondent: </span><span className="font-medium">{viewingQ.respondedBy}</span></div>}
                {viewingQ.sentAt && <div><span className="text-muted-foreground">Sent: </span><span className="font-medium">{new Date(viewingQ.sentAt).toLocaleDateString()}</span></div>}
                {viewingQ.dueDate && <div><span className="text-muted-foreground">Due: </span><span className="font-medium">{new Date(viewingQ.dueDate).toLocaleDateString()}</span></div>}
                {viewingQ.completedAt && <div><span className="text-muted-foreground">Completed: </span><span className="font-medium">{new Date(viewingQ.completedAt).toLocaleDateString()}</span></div>}
                {viewingQ.score !== null && viewingQ.score !== undefined && (
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">Score: </span>
                    <span className={`font-bold ${viewingQ.score >= 80 ? "text-green-400" : viewingQ.score >= 50 ? "text-yellow-400" : "text-red-400"}`}>{viewingQ.score}/100</span>
                    {viewingQ.riskLevel && <span className={`capitalize px-1.5 py-0.5 rounded font-medium ${viewingQ.riskLevel === "low" ? "bg-green-500/20 text-green-400" : viewingQ.riskLevel === "medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-red-500/20 text-red-400"}`}>{viewingQ.riskLevel} risk</span>}
                  </div>
                )}
              </div>

              {/* Questionnaire responses */}
              {(() => {
                const questions: any[] = viewingQ.template?.questions ?? [];
                const responses: any[] = viewingQ.responses ?? [];
                const respMap = new Map(responses.map((r: any) => [r.questionId, r.answer]));
                const categories = [...new Set(questions.map((q: any) => q.category))];
                if (questions.length === 0) {
                  return (
                    <div className="text-center py-8 text-sm text-muted-foreground">
                      {viewingQ.status === "completed"
                        ? "Response recorded but template questions are no longer available."
                        : "Awaiting vendor response — questionnaire has not been completed yet."}
                    </div>
                  );
                }
                return (
                  <div className="space-y-4">
                    {categories.map(cat => {
                      const catQs = questions.filter((q: any) => q.category === cat);
                      return (
                        <div key={cat} className="space-y-2">
                          <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground capitalize">{String(cat).replace(/_/g, " ")}</p>
                          {catQs.map((q: any, i: number) => {
                            const answer = respMap.get(q.id);
                            const hasAnswer = answer !== undefined && answer !== null;
                            return (
                              <div key={q.id} className="rounded-lg border border-border/60 p-3 space-y-1.5">
                                <p className="text-sm font-medium">{i + 1}. {q.text}{q.required && <span className="text-red-400 ml-1 text-[10px]">*</span>}</p>
                                <div className={`text-sm rounded px-2 py-1.5 ${hasAnswer ? "bg-muted/50" : "bg-muted/20 text-muted-foreground italic"}`}>
                                  {!hasAnswer ? "No answer provided" :
                                    q.type === "boolean" ? (
                                      <span className={answer === true ? "text-green-400 font-medium" : "text-red-400 font-medium"}>{answer === true ? "✓ Yes" : "✗ No"}</span>
                                    ) : q.type === "rating" ? (
                                      <span className="font-medium">{answer}/5 {["★","★★","★★★","★★★★","★★★★★"][Number(answer) - 1] ?? ""}</span>
                                    ) : q.type === "file" ? (
                                      <span className="flex items-center gap-1.5"><Download className="w-3.5 h-3.5" />{typeof answer === "object" ? answer?.name ?? "File uploaded" : String(answer)}</span>
                                    ) : (
                                      <span>{String(answer)}</span>
                                    )
                                  }
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      );
                    })}
                  </div>
                );
              })()}

              {/* Portal link copy */}
              {viewingQ.accessToken && (
                <div className="flex items-center gap-2 p-2 rounded bg-muted/30 border border-border/40">
                  <span className="text-[10px] text-muted-foreground font-mono truncate flex-1">{window.location.origin}/tprm/respond/{viewingQ.accessToken}</span>
                  <Button size="sm" variant="ghost" className="h-6 text-[10px] px-2 shrink-0" onClick={() => navigator.clipboard.writeText(`${window.location.origin}/tprm/respond/${viewingQ.accessToken}`)}>
                    Copy Link
                  </Button>
                  <Button size="sm" variant="ghost" className="h-6 text-[10px] px-2 shrink-0" onClick={() => window.open(`${window.location.origin}/tprm/respond/${viewingQ.accessToken}`, "_blank")}>
                    <ExternalLink className="w-3 h-3 mr-0.5" />Open Portal
                  </Button>
                </div>
              )}
            </div>
          )}
          <DialogFooter className="mt-4 flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={() => setViewingQ(null)}>Close</Button>
            {viewingQ && !viewingQ._loading && !viewingQ._error && (
              <>
                <Button variant="outline" size="sm" onClick={() => { const q = viewingQ; setViewingQ(null); openEditQ(q); }}>
                  <Edit2 className="w-3 h-3 mr-1.5" />Edit Status / Score
                </Button>
                <Button size="sm" onClick={() => applyQRisk(viewingQ)} disabled={savingQRisk}>
                  {savingQRisk ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <RefreshCw className="w-3 h-3 mr-1.5" />}
                  Recalculate Vendor Risk
                </Button>
              </>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit Questionnaire Dialog */}
      <Dialog open={!!editingQ} onOpenChange={open => { if (!open) setEditingQ(null); }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Edit Questionnaire #{editingQ?.id}</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Status</Label>
              <Select value={qEditForm.status} onValueChange={v => setQEditForm(f => ({ ...f, status: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="sent">Sent</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="completed">Completed</SelectItem>
                  <SelectItem value="overdue">Overdue</SelectItem>
                  <SelectItem value="expired">Expired</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Due Date</Label>
              <Input type="date" className="mt-1 h-8 text-sm" value={qEditForm.dueDate} onChange={e => setQEditForm(f => ({ ...f, dueDate: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Respondent</Label>
              <Input className="mt-1 h-8 text-sm" placeholder="Vendor contact name" value={qEditForm.respondedBy} onChange={e => setQEditForm(f => ({ ...f, respondedBy: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Score (0–100)</Label>
              <Input type="number" min={0} max={100} className="mt-1 h-8 text-sm" placeholder="Leave blank if not scored" value={qEditForm.score} onChange={e => setQEditForm(f => ({ ...f, score: e.target.value }))} />
            </div>
            <div>
              <Label className="text-xs">Notes</Label>
              <Textarea className="mt-1 text-sm" rows={3} placeholder="Internal notes…" value={qEditForm.notes} onChange={e => setQEditForm(f => ({ ...f, notes: e.target.value }))} />
            </div>
          </div>
          <DialogFooter className="mt-2">
            <Button variant="outline" size="sm" onClick={() => setEditingQ(null)}>Cancel</Button>
            <Button size="sm" onClick={saveQEdit} disabled={savingQEdit}>{savingQEdit ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" />Saving…</> : "Save Changes"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Send Questionnaire Dialog */}
      <Dialog open={showSendQ} onOpenChange={setShowSendQ}>
        <DialogContent>
          <DialogHeader><DialogTitle>Send Security Questionnaire</DialogTitle></DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Template *</Label>
              <Select value={qForm.templateId} onValueChange={v => setQForm(f => ({ ...f, templateId: v }))}>
                <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue placeholder="Select template" /></SelectTrigger>
                <SelectContent>
                  {templates.length === 0 ? (
                    <SelectItem value="" disabled>No templates — create one first</SelectItem>
                  ) : (
                    templates.map(t => <SelectItem key={t.id} value={String(t.id)}>{t.name}</SelectItem>)
                  )}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs">Recipient Email <span className="text-destructive">*</span></Label>
              <Input
                type="email"
                className={`mt-1 ${qForm.recipientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(qForm.recipientEmail) ? "border-destructive" : ""}`}
                placeholder="vendor@company.com"
                value={qForm.recipientEmail}
                onChange={e => setQForm(f => ({ ...f, recipientEmail: e.target.value }))}
              />
              {qForm.recipientEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(qForm.recipientEmail) && (
                <p className="text-[11px] text-destructive mt-0.5">Enter a valid email address</p>
              )}
            </div>
            <div><Label className="text-xs">Due Date</Label><Input type="date" className="mt-1 h-8 text-sm" value={qForm.dueDate} onChange={e => setQForm(f => ({ ...f, dueDate: e.target.value }))} /></div>
            {templates.length === 0 && <p className="text-xs text-muted-foreground">Create a template at <Link href="/tprm/questionnaire-templates" className="text-primary underline">Questionnaire Templates</Link></p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSendQ(false)}>Cancel</Button>
            <Button
              onClick={sendQuestionnaire}
              disabled={sendingQ || !qForm.templateId || !qForm.recipientEmail.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(qForm.recipientEmail)}
            >
              {sendingQ && <Loader2 className="w-4 h-4 mr-1 animate-spin" />} Send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
