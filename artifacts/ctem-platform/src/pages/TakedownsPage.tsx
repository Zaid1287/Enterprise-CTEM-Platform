import { useState, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { cn } from "@/lib/utils";
import {
  ShieldOff, Globe, Flag, CheckCircle2, Clock, XCircle, Plus,
  ChevronRight, Loader2, Upload, X, FileText, Image, AlertTriangle,
  ArrowRight, Search, Eye, Package,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { getToken } from "@/lib/auth";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const TYPE_LABELS: Record<string, string> = {
  phishing: "Phishing Page",
  brand_impersonation: "Brand Impersonation",
  domain_squatting: "Domain Squatting",
  fake_social: "Fake Social Media",
  malware_hosting: "Malware Hosting",
  other: "Other",
};

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: React.ElementType }> = {
  submitted:   { label: "Submitted",   color: "bg-blue-500/15 text-blue-400 border-blue-500/30",   icon: Clock },
  in_progress: { label: "In Progress", color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Loader2 },
  closed:      { label: "Closed",      color: "bg-green-500/15 text-green-400 border-green-500/30", icon: CheckCircle2 },
  rejected:    { label: "Rejected",    color: "bg-red-500/15 text-red-400 border-red-500/30",       icon: XCircle },
};

const PRIORITY_CONFIG: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-muted text-muted-foreground border-border",
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status] ?? STATUS_CONFIG.submitted;
  const Icon = cfg.icon;
  return (
    <span className={cn("inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-md font-medium border", cfg.color)}>
      <Icon className="w-3 h-3" />
      {cfg.label}
    </span>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  return (
    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border capitalize", PRIORITY_CONFIG[priority] ?? PRIORITY_CONFIG.medium)}>
      {priority}
    </span>
  );
}

const PROCESS_STEPS = [
  { icon: Search, label: "You Submit", desc: "Fill in the target URL, type, and upload any evidence" },
  { icon: Eye, label: "We Review", desc: "Our team validates the threat and contacts the relevant authority" },
  { icon: Package, label: "Takedown Filed", desc: "We file the formal takedown with the host, registrar, or platform" },
  { icon: CheckCircle2, label: "Resolved", desc: "Malicious content is removed. You'll be notified when closed." },
];

const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain", "application/zip", "video/mp4", "video/webm"];
const MAX_SIZE_MB = 20;

export default function TakedownsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [showNew, setShowNew] = useState(false);
  const [selected, setSelected] = useState<any>(null);
  const [form, setForm] = useState({
    type: "phishing", targetUrl: "", targetDomain: "", hostingProvider: "",
    registrar: "", title: "", description: "", brandAbused: "", priority: "high",
  });
  const [files, setFiles] = useState<File[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const { data: requests = [], isLoading } = useQuery<any[]>({
    queryKey: ["takedowns"],
    queryFn: () => apiFetch(`${BASE}/api/takedowns`),
  });

  const createMutation = useMutation({
    mutationFn: async (body: typeof form) => {
      const fd = new FormData();
      Object.entries(body).forEach(([k, v]) => { if (v) fd.append(k, v); });
      files.forEach(f => fd.append("evidenceFiles", f));
      const token = getToken();
      const res = await fetch(`${BASE}/api/takedowns`, {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: fd,
      });
      if (!res.ok) throw new Error("Failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["takedowns"] });
      setShowNew(false);
      resetForm();
      toast({ title: "Takedown request submitted", description: "Our team will review your request shortly." });
    },
    onError: () => toast({ title: "Failed to submit request", variant: "destructive" }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, ...body }: any) =>
      apiFetch(`${BASE}/api/takedowns/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["takedowns"] });
      setSelected(null);
      toast({ title: "Request updated" });
    },
  });

  function resetForm() {
    setForm({ type: "phishing", targetUrl: "", targetDomain: "", hostingProvider: "",
      registrar: "", title: "", description: "", brandAbused: "", priority: "high" });
    setFiles([]);
  }

  function handleFileAdd(newFiles: FileList | null) {
    if (!newFiles) return;
    const valid = Array.from(newFiles).filter(f => {
      if (!ALLOWED_TYPES.includes(f.type)) { toast({ title: `${f.name}: unsupported file type`, variant: "destructive" }); return false; }
      if (f.size > MAX_SIZE_MB * 1024 * 1024) { toast({ title: `${f.name}: file too large (max ${MAX_SIZE_MB}MB)`, variant: "destructive" }); return false; }
      return true;
    });
    setFiles(prev => [...prev, ...valid].slice(0, 10));
  }

  function removeFile(idx: number) {
    setFiles(prev => prev.filter((_, i) => i !== idx));
  }

  function fileIcon(type: string) {
    if (type.startsWith("image/")) return <Image className="w-4 h-4 text-blue-400" />;
    if (type === "application/pdf") return <FileText className="w-4 h-4 text-red-400" />;
    return <FileText className="w-4 h-4 text-muted-foreground" />;
  }

  const total = requests.length;
  const submitted = requests.filter(r => r.status === "submitted").length;
  const inProgress = requests.filter(r => r.status === "in_progress").length;
  const closed = requests.filter(r => r.status === "closed").length;
  const rejected = requests.filter(r => r.status === "rejected").length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Takedown Requests</h1>
          <p className="text-sm text-muted-foreground">
            Report phishing, brand impersonation, domain squatting & abuse for removal
          </p>
        </div>
        <Button size="sm" onClick={() => setShowNew(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> New Request
        </Button>
      </div>

      {/* How it works — shown when empty or always */}
      {total === 0 && !isLoading && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-5 py-4 border-b border-border bg-accent/20">
            <h3 className="text-sm font-semibold">How the Takedown Process Works</h3>
            <p className="text-xs text-muted-foreground mt-0.5">We handle the entire process once you submit a request</p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-0 divide-x divide-y md:divide-y-0 divide-border">
            {PROCESS_STEPS.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={i} className="p-5 flex flex-col items-center text-center gap-2 relative">
                  <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center mb-1">
                    <Icon className="w-5 h-5 text-primary" />
                  </div>
                  <p className="text-xs font-semibold">{step.label}</p>
                  <p className="text-xs text-muted-foreground leading-relaxed">{step.desc}</p>
                  {i < PROCESS_STEPS.length - 1 && (
                    <ArrowRight className="hidden md:block absolute right-0 top-1/2 -translate-y-1/2 translate-x-1/2 w-4 h-4 text-muted-foreground/40 z-10" />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Total",       value: total,      color: "text-foreground",   icon: ShieldOff },
          { label: "Submitted",   value: submitted,  color: "text-blue-400",     icon: Clock },
          { label: "In Progress", value: inProgress, color: "text-amber-400",    icon: Loader2 },
          { label: "Closed",      value: closed,     color: "text-green-400",    icon: CheckCircle2 },
          { label: "Rejected",    value: rejected,   color: "text-red-400",      icon: XCircle },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-1">
              <p className="text-xs text-muted-foreground">{label}</p>
              <Icon className="w-4 h-4 text-muted-foreground" />
            </div>
            <p className={cn("text-2xl font-bold tabular-nums", color)}>{value}</p>
          </div>
        ))}
      </div>

      {/* Process steps — compact, shown when there are requests */}
      {total > 0 && (
        <div className="bg-card border border-border rounded-xl px-5 py-4">
          <p className="text-xs font-medium text-muted-foreground mb-3">Takedown Process</p>
          <div className="flex items-center gap-2 flex-wrap">
            {PROCESS_STEPS.map((step, i) => {
              const Icon = step.icon;
              return (
                <div key={i} className="flex items-center gap-1.5">
                  <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                    <Icon className="w-3.5 h-3.5 text-primary" />
                    <span>{step.label}</span>
                  </div>
                  {i < PROCESS_STEPS.length - 1 && <ArrowRight className="w-3.5 h-3.5 text-muted-foreground/30" />}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-border">
          <h3 className="text-sm font-medium">All Requests</h3>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : requests.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center px-6">
            <Globe className="w-10 h-10 text-muted-foreground/30 mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No takedown requests yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1 max-w-xs">
              Found a phishing page, fake profile, or domain squatter? Submit a request and we'll handle the takedown.
            </p>
            <Button size="sm" className="mt-4" onClick={() => setShowNew(true)}>
              <Plus className="w-4 h-4 mr-1.5" /> Submit First Request
            </Button>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-accent/20">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Title</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Type</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground hidden md:table-cell">Target</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Priority</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground hidden lg:table-cell">Files</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground hidden lg:table-cell">Submitted</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {requests.map((r: any) => (
                <tr
                  key={r.id}
                  className="border-b border-border/50 hover:bg-accent/30 cursor-pointer"
                  onClick={() => setSelected(r)}
                >
                  <td className="px-4 py-3">
                    <p className="font-medium truncate max-w-[180px]">{r.title}</p>
                    {r.brandAbused && <p className="text-[10px] text-muted-foreground">Brand: {r.brandAbused}</p>}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{TYPE_LABELS[r.type] ?? r.type}</td>
                  <td className="px-4 py-3 hidden md:table-cell">
                    <p className="text-xs text-muted-foreground truncate max-w-[180px]">{r.targetUrl}</p>
                  </td>
                  <td className="px-4 py-3"><PriorityBadge priority={r.priority} /></td>
                  <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                  <td className="px-4 py-3 hidden lg:table-cell text-xs text-muted-foreground">
                    {(r.evidenceFiles?.length ?? 0) > 0
                      ? <span className="inline-flex items-center gap-1"><FileText className="w-3 h-3" />{r.evidenceFiles.length}</span>
                      : <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="px-4 py-3 hidden lg:table-cell text-xs text-muted-foreground">
                    {new Date(r.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3"><ChevronRight className="w-4 h-4 text-muted-foreground" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* ── New Request Dialog ── */}
      <Dialog open={showNew} onOpenChange={v => { setShowNew(v); if (!v) resetForm(); }}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>New Takedown Request</DialogTitle>
            <DialogDescription>
              Submit a request to remove phishing pages, impersonating domains, or brand abuse. Our team handles the rest.
            </DialogDescription>
          </DialogHeader>

          {/* Process reminder */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground bg-accent/30 rounded-lg px-3 py-2 flex-wrap">
            {PROCESS_STEPS.map((s, i) => {
              const Icon = s.icon;
              return (
                <div key={i} className="flex items-center gap-1.5">
                  <Icon className="w-3.5 h-3.5 text-primary" /><span>{s.label}</span>
                  {i < PROCESS_STEPS.length - 1 && <ArrowRight className="w-3 h-3 text-muted-foreground/30" />}
                </div>
              );
            })}
          </div>

          <div className="space-y-4 py-1">
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Threat Type *</Label>
                <Select value={form.type} onValueChange={v => setForm(f => ({ ...f, type: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(TYPE_LABELS).map(([v, l]) => (
                      <SelectItem key={v} value={v}>{l}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>Priority</Label>
                <Select value={form.priority} onValueChange={v => setForm(f => ({ ...f, priority: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical — immediate risk</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Request Title *</Label>
              <Input
                placeholder="e.g. Fake login page impersonating our portal"
                value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
              />
            </div>

            <div className="space-y-1.5">
              <Label>Malicious URL *</Label>
              <Input
                placeholder="https://evil-site.com/fake-login"
                value={form.targetUrl} onChange={e => setForm(f => ({ ...f, targetUrl: e.target.value }))}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Target Domain</Label>
                <Input placeholder="evil-site.com"
                  value={form.targetDomain} onChange={e => setForm(f => ({ ...f, targetDomain: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Brand Being Abused</Label>
                <Input placeholder="Your company / brand name"
                  value={form.brandAbused} onChange={e => setForm(f => ({ ...f, brandAbused: e.target.value }))} />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <Label>Hosting Provider</Label>
                <Input placeholder="e.g. Cloudflare, AWS, GCP"
                  value={form.hostingProvider} onChange={e => setForm(f => ({ ...f, hostingProvider: e.target.value }))} />
              </div>
              <div className="space-y-1.5">
                <Label>Domain Registrar</Label>
                <Input placeholder="e.g. GoDaddy, Namecheap"
                  value={form.registrar} onChange={e => setForm(f => ({ ...f, registrar: e.target.value }))} />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label>Description / Context</Label>
              <Textarea
                placeholder="Describe the abuse. Include how you discovered it, what data is at risk, any WHOIS info, etc."
                value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                rows={3}
              />
            </div>

            {/* File upload */}
            <div className="space-y-2">
              <Label>Evidence Files <span className="text-muted-foreground text-xs">(screenshots, logs, PDFs — max 20MB each, up to 10 files)</span></Label>
              <div
                className={cn(
                  "border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-colors",
                  dragOver ? "border-primary bg-primary/5" : "border-border hover:border-primary/50 hover:bg-accent/20",
                )}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={e => { e.preventDefault(); setDragOver(false); handleFileAdd(e.dataTransfer.files); }}
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="w-8 h-8 text-muted-foreground/50 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">Drag & drop files here, or click to browse</p>
                <p className="text-xs text-muted-foreground/60 mt-1">PNG, JPG, PDF, ZIP, MP4, TXT supported</p>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  accept={ALLOWED_TYPES.join(",")}
                  className="hidden"
                  onChange={e => handleFileAdd(e.target.files)}
                />
              </div>

              {files.length > 0 && (
                <div className="space-y-1.5 mt-2">
                  {files.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 bg-accent/30 rounded-lg px-3 py-2 text-xs">
                      {fileIcon(f.type)}
                      <span className="flex-1 truncate font-medium">{f.name}</span>
                      <span className="text-muted-foreground shrink-0">{(f.size / 1024).toFixed(0)} KB</span>
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); removeFile(i); }}
                        className="text-muted-foreground hover:text-destructive ml-1"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowNew(false); resetForm(); }}>Cancel</Button>
            <Button
              disabled={!form.title || !form.targetUrl || createMutation.isPending}
              onClick={() => createMutation.mutate(form)}
            >
              {createMutation.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : <Flag className="w-4 h-4 mr-1.5" />}
              Submit Request
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Detail Dialog ── */}
      {selected && (
        <Dialog open={!!selected} onOpenChange={() => setSelected(null)}>
          <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <ShieldOff className="w-4 h-4" />
                {selected.title}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-2 text-sm">
              <div className="flex items-center gap-2 flex-wrap">
                <StatusBadge status={selected.status} />
                <PriorityBadge priority={selected.priority} />
                <Badge variant="outline" className="text-xs">{TYPE_LABELS[selected.type] ?? selected.type}</Badge>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Target URL</p>
                  <p className="font-medium break-all text-xs">{selected.targetUrl}</p>
                </div>
                {selected.targetDomain && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Domain</p>
                    <p className="font-medium text-xs">{selected.targetDomain}</p>
                  </div>
                )}
                {selected.brandAbused && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Brand Abused</p>
                    <p className="font-medium text-xs">{selected.brandAbused}</p>
                  </div>
                )}
                {selected.hostingProvider && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Host Provider</p>
                    <p className="font-medium text-xs">{selected.hostingProvider}</p>
                  </div>
                )}
                {selected.registrar && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-0.5">Registrar</p>
                    <p className="font-medium text-xs">{selected.registrar}</p>
                  </div>
                )}
                <div>
                  <p className="text-xs text-muted-foreground mb-0.5">Submitted</p>
                  <p className="font-medium text-xs">{new Date(selected.createdAt).toLocaleString()}</p>
                </div>
              </div>

              {selected.description && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Description</p>
                  <p className="text-xs bg-muted/30 rounded-lg p-3 whitespace-pre-wrap">{selected.description}</p>
                </div>
              )}

              {/* Evidence files */}
              {(selected.evidenceFiles?.length ?? 0) > 0 && (
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Evidence Files ({selected.evidenceFiles.length})</p>
                  <div className="space-y-1.5">
                    {selected.evidenceFiles.map((fname: string, i: number) => (
                      <a
                        key={i}
                        href={`${BASE}/api/takedowns/evidence/${fname}`}
                        target="_blank"
                        rel="noreferrer"
                        className="flex items-center gap-2 bg-accent/30 rounded-lg px-3 py-2 text-xs hover:bg-accent/50 transition-colors"
                      >
                        <FileText className="w-3.5 h-3.5 text-primary" />
                        <span className="flex-1 truncate">{fname.replace(/^\d+-[a-f0-9]+-td-\d+-[a-f0-9]+-/, "")}</span>
                        <ExternalLinkIcon className="w-3 h-3 text-muted-foreground" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {selected.resolutionNote && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Resolution Note</p>
                  <p className="text-xs bg-muted/30 rounded-lg p-3 whitespace-pre-wrap">{selected.resolutionNote}</p>
                </div>
              )}

              {selected.status !== "closed" && selected.status !== "rejected" && (
                <div className="pt-2 border-t border-border">
                  <p className="text-xs text-muted-foreground mb-2">Update Status</p>
                  <div className="flex gap-2 flex-wrap">
                    {selected.status === "submitted" && (
                      <Button size="sm" variant="outline"
                        onClick={() => updateMutation.mutate({ id: selected.id, status: "in_progress" })}>
                        Mark In Progress
                      </Button>
                    )}
                    <Button size="sm" variant="outline" className="text-green-400 border-green-500/30 hover:bg-green-500/10"
                      onClick={() => updateMutation.mutate({ id: selected.id, status: "closed", isSuccessful: true })}>
                      Mark Closed
                    </Button>
                    <Button size="sm" variant="outline" className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                      onClick={() => updateMutation.mutate({ id: selected.id, status: "rejected" })}>
                      Reject
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}

function ExternalLinkIcon({ className }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
      <polyline points="15 3 21 3 21 9" />
      <line x1="10" y1="14" x2="21" y2="3" />
    </svg>
  );
}
