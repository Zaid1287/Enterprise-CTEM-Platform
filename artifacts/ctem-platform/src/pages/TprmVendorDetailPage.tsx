import { useEffect, useRef, useState } from "react";
import { useParams, Link, useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
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
import {
  ArrowLeft, RefreshCw, Globe, Shield, Bug, Package, FileText, AlertTriangle,
  CheckCircle2, Loader2, Upload, Plus, Mail, Phone, User,
  Building2, Clock, Download, Trash2, Send, ChevronRight,
} from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

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
  const { id } = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const [vendor, setVendor] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [tab, setTab] = useState("overview");

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

  const loadVendor = () => {
    setLoading(true);
    apiFetch<any>(`/api/tprm/vendors/${id}`)
      .then(setVendor)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadVendor(); }, [id]);
  useEffect(() => {
    apiFetch<any[]>("/api/tprm/questionnaire-templates").then(setTemplates).catch(() => {});
  }, []);

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
    if (!qForm.templateId) return;
    setSendingQ(true);
    try {
      const r = await apiFetch<any>(`/api/tprm/vendors/${id}/questionnaires`, { method: "POST", body: JSON.stringify(qForm) });
      setQPortalLink(r.portalLink ?? null);
      setShowSendQ(false);
      setQForm({ templateId: "", dueDate: "", recipientEmail: "" });
      loadVendor();
    } catch { /* ignore */ }
    setSendingQ(false);
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
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
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
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="h-8 text-xs">
          <TabsTrigger value="overview" className="text-xs">Overview</TabsTrigger>
          <TabsTrigger value="findings" className="text-xs">Findings ({vendor.findings?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="assets" className="text-xs">Assets ({vendor.assets?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="fourth-party" className="text-xs">4th Party ({vendor.fourthParties?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="compliance" className="text-xs">Compliance ({vendor.complianceDocs?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="questionnaires" className="text-xs">Questionnaires ({vendor.questionnaires?.length ?? 0})</TabsTrigger>
          <TabsTrigger value="sbom" className="text-xs">SBOM</TabsTrigger>
          <TabsTrigger value="contacts" className="text-xs">Contacts ({vendor.contacts?.length ?? 0})</TabsTrigger>
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

        {/* Assets */}
        <TabsContent value="assets" className="mt-4">
          <Card>
            <CardContent className="pt-4">
              {(vendor.assets ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground py-6 text-center">No assets discovered yet</p>
              ) : (
                <div className="divide-y divide-border/50">
                  {(vendor.assets ?? []).map((a: any) => (
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
        </TabsContent>

        {/* 4th Party */}
        <TabsContent value="fourth-party" className="mt-4">
          <Card>
            <CardHeader className="pb-2 flex flex-row items-center justify-between">
              <CardTitle className="text-sm">Fourth-Party Dependencies</CardTitle>
            </CardHeader>
            <CardContent>
              {(vendor.fourthParties ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground py-4 text-center">No 4th parties discovered. Run a scan to detect CDNs, analytics providers, and third-party dependencies.</p>
              ) : (
                <div className="space-y-2">
                  {(vendor.fourthParties ?? []).map((fp: any) => (
                    <div key={fp.id} className="flex items-center gap-3 p-2.5 rounded bg-muted/30">
                      <Building2 className="w-4 h-4 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium">{fp.name}</p>
                        {fp.domain && <p className="text-xs text-muted-foreground">{fp.domain}</p>}
                      </div>
                      <Badge variant="outline" className="text-[10px]">{fp.discoveryMethod.replace(/_/g, " ")}</Badge>
                      <span className="text-xs text-muted-foreground">+{fp.riskContribution} pts</span>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Compliance */}
        <TabsContent value="compliance" className="mt-4 space-y-3">
          <div className="flex justify-end">
            <Button size="sm" onClick={() => setShowUploadDoc(true)}><Upload className="w-4 h-4 mr-1.5" />Upload Document</Button>
          </div>
          {(vendor.complianceDocs ?? []).length === 0 ? (
            <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No compliance documents uploaded</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {(vendor.complianceDocs ?? []).map((d: any) => {
                const exp = d.expiresAt ? new Date(d.expiresAt) : null;
                const days = exp ? Math.ceil((exp.getTime() - Date.now()) / 86400000) : null;
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
                        {d.status && <Badge variant="outline" className="text-[10px] mt-0.5">{d.status.replace(/_/g, " ")}</Badge>}
                      </div>
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
          {(vendor.questionnaires ?? []).length === 0 ? (
            <Card className="border-dashed"><CardContent className="py-10 text-center text-sm text-muted-foreground">No questionnaires sent yet</CardContent></Card>
          ) : (
            <div className="space-y-2">
              {(vendor.questionnaires ?? []).map((q: any) => (
                <Card key={q.id} className="bg-card/60">
                  <CardContent className="py-3 flex items-center gap-3">
                    <FileText className="w-4 h-4 text-muted-foreground shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium">Questionnaire #{q.id}</p>
                      <p className="text-xs text-muted-foreground">{q.respondedBy ?? "No respondent set"}{q.sentAt ? ` • Sent ${new Date(q.sentAt).toLocaleDateString()}` : ""}</p>
                    </div>
                    <Badge variant="outline" className="text-[10px] capitalize">{q.status}</Badge>
                    {q.score !== null && q.score !== undefined && <span className="text-sm font-semibold">{q.score}/100</span>}
                    {q.dueDate && <span className="text-xs text-muted-foreground">Due {new Date(q.dueDate).toLocaleDateString()}</span>}
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* SBOM */}
        <TabsContent value="sbom" className="mt-4 space-y-3">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm">Upload SBOM File</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">Supports CycloneDX JSON/XML and SPDX JSON/tag-value formats. Components are automatically enriched with CVE data from the OSV database.</p>
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
                    <div>
                      <p className="text-sm font-medium">{c.name}{c.isPrimary && <Badge variant="secondary" className="ml-1.5 text-[10px]">Primary</Badge>}</p>
                      <p className="text-xs text-muted-foreground">{c.email}{c.role ? ` • ${c.role}` : ""}</p>
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
            <div><Label className="text-xs">Recipient Email</Label><Input type="email" className="mt-1" placeholder="vendor@company.com" value={qForm.recipientEmail} onChange={e => setQForm(f => ({ ...f, recipientEmail: e.target.value }))} /></div>
            <div><Label className="text-xs">Due Date</Label><Input type="date" className="mt-1 h-8 text-sm" value={qForm.dueDate} onChange={e => setQForm(f => ({ ...f, dueDate: e.target.value }))} /></div>
            {templates.length === 0 && <p className="text-xs text-muted-foreground">Create a template at <Link href="/tprm/questionnaire-templates" className="text-primary underline">Questionnaire Templates</Link></p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSendQ(false)}>Cancel</Button>
            <Button onClick={sendQuestionnaire} disabled={sendingQ || !qForm.templateId}>
              {sendingQ && <Loader2 className="w-4 h-4 mr-1 animate-spin" />} Send
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
