import { useState } from "react";
import { Link, useParams } from "wouter";
import {
  useGetFinding, useGetFindingScanData, useListFindings, useUpdateFinding,
  useListFindingComments, useCreateFindingComment,
  useListAssetTechnologies, useRunTechScan,
  useListAssetScreenshots, useRunScreenshotScan,
  getGetFindingQueryKey, getGetFindingScanDataQueryKey, getListFindingsQueryKey,
  getListFindingCommentsQueryKey, getListAssetTechnologiesQueryKey,
  getListAssetScreenshotsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, ShieldAlert, Globe, Network, Server, Cpu, Code2,
  Clock, AlertCircle, CheckCircle2, Info, Minus, ExternalLink,
  Wifi, Tag, MapPin, Building2, Layers, Monitor, Hash, Lock, Unlock,
  Activity, BarChart3, Zap, Bot, ChevronDown, ChevronRight,
  Copy, CheckCheck, MessageSquare, Send, Brain, Wrench,
  Camera, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, capitalize, formatDate, formatDateTime } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { Loader2, RefreshCw } from "lucide-react";
import { getToken } from "@/lib/auth";

// ── Style maps ─────────────────────────────────────────────────────────────

const SEV: Record<string, { bg: string; text: string; border: string; bar: string; dot: string }> = {
  critical: { bg: "bg-red-500/10",    text: "text-red-400",          border: "border-red-500/30",    bar: "bg-red-500",    dot: "bg-red-500" },
  high:     { bg: "bg-orange-500/10", text: "text-orange-400",       border: "border-orange-500/30", bar: "bg-orange-500", dot: "bg-orange-500" },
  medium:   { bg: "bg-yellow-500/10", text: "text-yellow-400",       border: "border-yellow-500/30", bar: "bg-yellow-500", dot: "bg-yellow-500" },
  low:      { bg: "bg-blue-500/10",   text: "text-blue-400",         border: "border-blue-500/30",   bar: "bg-blue-500",   dot: "bg-blue-500" },
  info:     { bg: "bg-muted",         text: "text-muted-foreground", border: "border-border",        bar: "bg-muted-foreground", dot: "bg-muted-foreground" },
};

const STA: Record<string, { bg: string; text: string; border: string }> = {
  open:           { bg: "bg-red-500/10",    text: "text-red-400",          border: "border-red-500/30" },
  in_progress:    { bg: "bg-blue-500/10",   text: "text-blue-400",         border: "border-blue-500/30" },
  accepted_risk:  { bg: "bg-amber-500/10",  text: "text-amber-400",        border: "border-amber-500/30" },
  false_positive: { bg: "bg-muted",         text: "text-muted-foreground", border: "border-border" },
  mitigated:      { bg: "bg-green-500/10",  text: "text-green-400",        border: "border-green-500/30" },
};

const STATUS_ICON: Record<string, React.ElementType> = {
  open: AlertCircle, in_progress: Clock,
  accepted_risk: Info, false_positive: Minus, mitigated: CheckCircle2,
};

const ASSET_TYPE_ICON: Record<string, React.ElementType> = {
  domain: Globe, subdomain: Network, ip: Server, url: Globe,
  cidr: Network, api: Code2, ssl_cert: Lock, cloud_asset: Cpu, host: Server,
};

const STATUSES = ["open", "in_progress", "accepted_risk", "false_positive", "mitigated"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Importance score 0–100.
 * Weighted: CVSS (0–50 pts) + EPSS (0–30 pts) + KEV bonus (20 pts) = max 100.
 * Falls back to severity label only when no CVSS, EPSS, or KEV data exists.
 * SINGLE SOURCE OF TRUTH — keep in sync with FindingsPage.tsx.
 */
function importanceScore(f: any): number | null {
  const SEV: Record<string, number> = { critical: 85, high: 65, medium: 40, low: 20, info: 10 };
  const cvssRaw = typeof f.cvss === "number" ? f.cvss : parseFloat(String(f.cvss ?? ""));
  const epssRaw = typeof f.epss === "number" ? f.epss : parseFloat(String(f.epss ?? ""));
  const cvssVal = isNaN(cvssRaw) ? 0 : cvssRaw;
  const epssVal = isNaN(epssRaw) ? 0 : epssRaw;
  const kevPts  = f.isKev ? 20 : 0;
  if (cvssVal === 0 && epssVal === 0 && !f.isKev) return SEV[f.severity ?? ""] ?? null;
  return Math.min(100, Math.round(cvssVal * 5 + epssVal * 30 + kevPts));
}

function scoreColor(s: number) {
  return s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-blue-400";
}

function CopyBtn({ text }: { text: string }) {
  const [ok, setOk] = useState(false);
  function go() { navigator.clipboard.writeText(text).then(() => { setOk(true); setTimeout(() => setOk(false), 1500); }); }
  return (
    <button onClick={go} className="ml-1 text-muted-foreground hover:text-foreground transition-colors">
      {ok ? <CheckCheck className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function Section({ title, icon: Icon, children, className }: { title: string; icon: React.ElementType; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("bg-card border border-border rounded-xl overflow-hidden", className)}>
      <div className="flex items-center gap-2 px-5 py-3 border-b border-border/60 bg-muted/20">
        <Icon className="w-3.5 h-3.5 text-primary" />
        <h2 className="text-xs font-semibold uppercase tracking-wide">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

function KV({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-border/40 last:border-0">
      <span className="text-xs text-muted-foreground shrink-0 w-32">{label}</span>
      <div className="text-xs font-medium text-right">{children ?? <span className="text-muted-foreground/40">—</span>}</div>
    </div>
  );
}

// ── AI Analysis ────────────────────────────────────────────────────────────

function AiSection({ findingId, finding }: { findingId: number; finding: any }) {
  const [tab, setTab] = useState<"explanation" | "remediation">("explanation");
  const [expl, setExpl] = useState<string | null>(null);
  const [rem, setRem]   = useState<any | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr]   = useState<string | null>(null);

  const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

  async function callAi(endpoint: string, body: object): Promise<any> {
    const token = sessionStorage.getItem("access_token");
    const r = await fetch(`${BASE}/api/ai/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error("AI request failed");
    return r.json();
  }

  async function generate() {
    setBusy(true); setErr(null);
    try {
      if (tab === "explanation" && !expl) {
        const d = await callAi("explain-finding", { findingId });
        setExpl(d.content ?? "");
      } else if (tab === "remediation" && !rem) {
        const d = await callAi("remediation", { findingId });
        setRem(d);
      }
    } catch (e: any) { setErr(e.message); }
    finally { setBusy(false); }
  }

  function renderMd(text: string) {
    return text.split("\n").map((line, i) => {
      if (line.startsWith("## "))  return <h3 key={i} className="text-sm font-bold mt-4 mb-1">{line.slice(3)}</h3>;
      if (line.startsWith("### ")) return <h4 key={i} className="text-xs font-semibold mt-3 mb-0.5 text-foreground/80">{line.slice(4)}</h4>;
      if (line.startsWith("- ") || line.startsWith("* ")) {
        const html = line.slice(2).replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        return <li key={i} className="text-xs text-muted-foreground ml-4 list-disc leading-relaxed" dangerouslySetInnerHTML={{ __html: html }} />;
      }
      if (!line.trim()) return <div key={i} className="h-1" />;
      const html = line.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
      return <p key={i} className="text-xs text-muted-foreground leading-relaxed" dangerouslySetInnerHTML={{ __html: html }} />;
    });
  }

  const hasContent = tab === "explanation" ? !!expl : !!rem;

  return (
    <Section title="AI Analysis" icon={Bot}>
      {/* Tabs */}
      <div className="flex gap-1 mb-4 bg-muted/30 rounded-lg p-1 w-fit">
        {(["explanation", "remediation"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={cn("text-xs px-3 py-1.5 rounded-md font-medium transition-colors",
              tab === t ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}>
            {t === "explanation" ? "Explanation" : "Remediation Steps"}
          </button>
        ))}
      </div>

      {!hasContent && !busy && (
        <div className="flex flex-col items-center gap-3 py-6 text-center">
          <Bot className="w-8 h-8 text-muted-foreground/20" />
          <p className="text-xs text-muted-foreground">
            {tab === "explanation"
              ? "Generate an AI-powered security analysis of this finding."
              : "Get a step-by-step remediation plan for this vulnerability."}
          </p>
          <Button size="sm" onClick={generate} className="gap-2">
            {tab === "explanation" ? <Brain className="w-3.5 h-3.5" /> : <Wrench className="w-3.5 h-3.5" />}
            Generate {capitalize(tab)}
          </Button>
        </div>
      )}

      {busy && <div className="space-y-2 py-2"><Skeleton className="h-4 w-3/4" /><Skeleton className="h-4 w-full" /><Skeleton className="h-4 w-5/6" /><Skeleton className="h-4 w-2/3" /></div>}
      {err && <p className="text-xs text-red-400">{err} — <button className="underline" onClick={generate}>Retry</button></p>}

      {tab === "explanation" && expl && (
        <div className="space-y-0.5">{renderMd(expl)}</div>
      )}

      {tab === "remediation" && rem && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-4 text-xs">
            <div><span className="text-muted-foreground">Priority: </span><span className="font-semibold">{rem.priority}</span></div>
            <div><span className="text-muted-foreground">Est. Effort: </span><span className="font-semibold">{rem.estimatedEffort}</span></div>
          </div>
          <ol className="space-y-2">
            {rem.steps?.map((step: string, i: number) => (
              <li key={i} className="flex gap-3 text-xs">
                <span className="text-primary font-bold shrink-0 w-4">{i + 1}.</span>
                <span className="text-muted-foreground leading-relaxed">{step}</span>
              </li>
            ))}
          </ol>
          {rem.references?.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wide">References</p>
              {rem.references.map((r: string) => (
                <a key={r} href={r} target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-1 text-xs text-primary hover:underline">
                  <ExternalLink className="w-3 h-3 shrink-0" />{r}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {hasContent && !busy && (
        <Button variant="outline" size="sm" className="mt-4 gap-2 text-xs" onClick={() => { if (tab === "explanation") setExpl(null); else setRem(null); }}>
          Regenerate
        </Button>
      )}
    </Section>
  );
}

// ── Comments ───────────────────────────────────────────────────────────────

function CommentsSection({ findingId }: { findingId: number }) {
  const qc = useQueryClient();
  const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
  const [text, setText] = useState("");
  const { data: comments } = useListFindingComments(findingId, {
    query: { queryKey: getListFindingCommentsQueryKey(findingId) },
  });
  const addComment = useCreateFindingComment();
  const [deletingCommentId, setDeletingCommentId] = useState<number | null>(null);

  const deleteComment = async (commentId: number) => {
    setDeletingCommentId(commentId);
    try {
      await fetch(`${BASE}/api/findings/${findingId}/comments/${commentId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${getToken() ?? ""}` },
      });
      qc.invalidateQueries({ queryKey: getListFindingCommentsQueryKey(findingId) });
    } finally {
      setDeletingCommentId(null);
    }
  };

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!text.trim()) return;
    await addComment.mutateAsync({ findingId, data: { content: text } });
    qc.invalidateQueries({ queryKey: getListFindingCommentsQueryKey(findingId) });
    setText("");
  }

  const list = (comments as any[]) ?? [];

  return (
    <Section title={`Comments (${list.length})`} icon={MessageSquare}>
      <div className="space-y-3 mb-4 max-h-52 overflow-y-auto">
        {list.map((c: any) => (
          <div key={c.id} className="bg-muted/30 rounded-lg p-3 border border-border/40">
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold">{c.authorName}</span>
              <div className="flex items-center gap-1">
                <span className="text-[10px] text-muted-foreground">{formatDateTime(c.createdAt)}</span>
                <button
                  onClick={() => deleteComment(c.id)}
                  disabled={deletingCommentId === c.id}
                  className="ml-1 p-0.5 rounded text-muted-foreground/50 hover:text-destructive transition-colors disabled:opacity-40"
                  title="Delete comment"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">{c.content}</p>
          </div>
        ))}
        {list.length === 0 && <p className="text-xs text-muted-foreground">No comments yet.</p>}
      </div>
      <form onSubmit={submit} className="flex gap-2">
        <Textarea value={text} onChange={e => setText(e.target.value)} placeholder="Add a comment…" className="text-xs resize-none h-14 flex-1" />
        <Button type="submit" size="icon" disabled={addComment.isPending || !text.trim()}><Send className="w-4 h-4" /></Button>
      </form>
    </Section>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────

const TECH_CATEGORY_COLOR: Record<string, string> = {
  "Web Server":           "bg-blue-500/10 text-blue-400 border-blue-500/20",
  "CMS":                  "bg-purple-500/10 text-purple-400 border-purple-500/20",
  "E-commerce":           "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  "JavaScript Framework": "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  "JavaScript Library":   "bg-sky-500/10 text-sky-400 border-sky-500/20",
  "UI Framework":         "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  "CSS Framework":        "bg-violet-500/10 text-violet-400 border-violet-500/20",
  "Programming Language": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "Web Framework":        "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "CDN":                  "bg-slate-500/10 text-slate-400 border-slate-500/20",
  "Analytics":            "bg-rose-500/10 text-rose-400 border-rose-500/20",
  "Security":             "bg-red-500/10 text-red-400 border-red-500/20",
  "Payment":              "bg-green-500/10 text-green-400 border-green-500/20",
  "PaaS":                 "bg-teal-500/10 text-teal-400 border-teal-500/20",
};

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const findingId = parseInt(id ?? "0", 10);
  const qc = useQueryClient();
  const { toast } = useToast();
  const [techScanning, setTechScanning]     = useState(false);
  const [screenshotting, setScreenshotting] = useState(false);
  const [shotLightbox, setShotLightbox]     = useState<any | null>(null);

  const { data: finding, isLoading: loadingF } = useGetFinding(
    findingId,
    { query: { queryKey: getGetFindingQueryKey(findingId) } },
  );

  const { data: scanData, isLoading: loadingScan } = useGetFindingScanData(
    findingId,
    { query: { queryKey: getGetFindingScanDataQueryKey(findingId) } },
  );

  const f = finding as any;

  const { data: siblings } = useListFindings(
    { assetId: f?.assetId } as any,
    {
      query: {
        queryKey: getListFindingsQueryKey({ assetId: f?.assetId } as any),
        enabled: !!f?.assetId,
      },
    },
  );

  const { data: assetTechs, refetch: refetchTechs } = useListAssetTechnologies(
    f?.assetId ?? 0,
    {
      query: {
        queryKey: getListAssetTechnologiesQueryKey(f?.assetId ?? 0),
        enabled: !!f?.assetId,
      },
    },
  );
  const { data: assetScreenshots, refetch: refetchScreenshots } = useListAssetScreenshots(
    f?.assetId ?? 0,
    {
      query: {
        queryKey: getListAssetScreenshotsQueryKey(f?.assetId ?? 0),
        enabled: !!f?.assetId,
      },
    },
  );
  const runTechScan = useRunTechScan();
  const runShotScan = useRunScreenshotScan();

  const updateFinding = useUpdateFinding();
  const otherFindings = ((siblings as any[]) ?? []).filter((s: any) => s.id !== findingId);

  async function handleStatusChange(status: string) {
    await updateFinding.mutateAsync({ findingId, data: { status } });
    qc.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
    qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
  }

  async function handleSeverityChange(severity: string) {
    await updateFinding.mutateAsync({ findingId, data: { severity } as any });
    qc.invalidateQueries({ queryKey: getGetFindingQueryKey(findingId) });
    qc.invalidateQueries({ queryKey: getListFindingsQueryKey() });
    toast({ title: "Severity updated", description: `Finding severity changed to ${severity}. Risk score recalculated.` });
  }

  async function handleTechScan() {
    if (!f?.assetId) return;
    setTechScanning(true);
    try {
      const res = await runTechScan.mutateAsync({ assetId: f.assetId });
      await refetchTechs();
      const count = (res as any)?.technologies?.length ?? 0;
      toast({ title: "Tech scan complete", description: `${count} technolog${count === 1 ? "y" : "ies"} detected.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Tech scan failed", variant: "destructive" });
    } finally {
      setTechScanning(false);
    }
  }

  async function handleScreenshotScan() {
    if (!f?.assetId) return;
    setScreenshotting(true);
    try {
      const res = await runShotScan.mutateAsync({ assetId: f.assetId });
      await refetchScreenshots();
      const count = (res as any)?.screenshots?.length ?? 0;
      toast({ title: "Screenshots captured", description: `${count} page${count === 1 ? "" : "s"} captured.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Screenshot scan failed", variant: "destructive" });
    } finally {
      setScreenshotting(false);
    }
  }

  if (loadingF) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-40 w-full" />
        <div className="grid grid-cols-3 gap-4"><Skeleton className="h-28" /><Skeleton className="h-28" /><Skeleton className="h-28" /></div>
      </div>
    );
  }
  if (!f) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        <ShieldAlert className="w-10 h-10 mx-auto mb-3 opacity-20" />
        <p className="text-sm">Finding not found.</p>
        <Link href="/findings"><Button variant="outline" size="sm" className="mt-4">← Back to Findings</Button></Link>
      </div>
    );
  }

  const sev        = SEV[f.severity]  ?? SEV.info;
  const sta        = STA[f.status]    ?? STA.open;
  const StatusIcon = STATUS_ICON[f.status] ?? Minus;
  const TypeIcon   = ASSET_TYPE_ICON[f.assetType ?? ""] ?? Globe;
  const impScore   = importanceScore(f);

  const scan = scanData as any;

  // Gather IPs: from asset + subdomain IPs from scan
  const ipSet = new Set<string>();
  if (f.assetIpAddress) ipSet.add(f.assetIpAddress);
  if (scan?.subdomains) for (const s of scan.subdomains) { if (s.ip) ipSet.add(s.ip); }
  const ips = [...ipSet];

  // Intel map
  const intel: Record<string, string> = {};
  if (scan?.intelligence) for (const item of scan.intelligence) intel[item.key] = item.value;
  const geoLabel     = [intel["City"], intel["Region"], intel["Country"]].filter(Boolean).join(", ") || null;
  const hostingLabel = [intel["Organization"], intel["AS Number"]].filter(Boolean).join(" · ") || null;

  // Ports: from scan, fallback to asset.port
  const ports: any[] = scan?.ports?.length
    ? scan.ports
    : f.assetPort
      ? [{ port: f.assetPort, protocol: "tcp", service: "—", version: "—", state: "open" }]
      : [];

  // Technologies from httpInfo (legacy) + DB detections
  const httpTechs: string[] = scan?.httpInfo?.tech ?? [];
  const detectedTechs = (assetTechs as any[]) ?? [];
  const shots         = (assetScreenshots as any[]) ?? [];
  const techGrouped: Record<string, any[]> = {};
  for (const t of detectedTechs) {
    if (!techGrouped[t.category]) techGrouped[t.category] = [];
    techGrouped[t.category].push(t);
  }

  // Scan CVEs (excluding internal codes)
  const scanCves: any[] = (scan?.vulnerabilities ?? [])
    .filter((v: any) => v.cve && !v.cve.startsWith("SEC-") && !v.cve.startsWith("HDR-") && !v.cve.startsWith("CWE-") && !v.cve.startsWith("CRED-"));

  return (
    <div className="space-y-5">

      {/* Breadcrumb */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Link href="/findings">
            <button className="flex items-center gap-1.5 hover:text-foreground transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" /> Findings
            </button>
          </Link>
          <span className="opacity-40">/</span>
          <span className="truncate max-w-sm text-foreground/70">{f.title}</span>
        </div>
        <div className="flex items-center gap-2">
          <Select value={f.severity} onValueChange={handleSeverityChange}>
            <SelectTrigger className="h-7 w-28 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SEVERITIES.map(s => <SelectItem key={s} value={s} className="text-xs capitalize">{capitalize(s)}</SelectItem>)}
            </SelectContent>
          </Select>
          <Select value={f.status} onValueChange={handleStatusChange}>
            <SelectTrigger className="h-7 w-36 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map(s => <SelectItem key={s} value={s} className="text-xs">{capitalize(s.replace(/_/g, " "))}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className={cn("h-1", sev.bar)} />
        <div className="p-5">
          <div className="flex items-start gap-4">
            <div className={cn("p-3 rounded-xl border shrink-0", sev.bg, sev.border)}>
              <ShieldAlert className={cn("w-6 h-6", sev.text)} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-2">
                {f.isKev && (
                  <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-md font-bold uppercase tracking-wide">CISA KEV</span>
                )}
                <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-bold uppercase border", sev.bg, sev.text, sev.border)}>{f.severity}</span>
                <span className={cn("text-[10px] flex items-center gap-1 px-2 py-0.5 rounded-md font-semibold uppercase border", sta.bg, sta.text, sta.border)}>
                  <StatusIcon className="w-3 h-3" />{f.status?.replace(/_/g, " ")}
                </span>
              </div>
              <h1 className="text-base font-semibold leading-snug">{f.title}</h1>
              {f.description && <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{f.description}</p>}
            </div>
          </div>

          {/* Score tiles */}
          <div className="grid grid-cols-3 gap-3 mt-5">
            <div className="bg-muted/30 border border-border rounded-xl p-4 text-center">
              <div className="flex items-center justify-center gap-1.5 mb-2">
                <Activity className="w-3.5 h-3.5 text-primary" />
                <span className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">ASM Score</span>
              </div>
              {f.riskScore != null
                ? <p className={cn("text-3xl font-bold tabular-nums", scoreColor(f.riskScore))}>{Math.round(f.riskScore)}</p>
                : <p className="text-3xl font-bold text-muted-foreground/30">—</p>}
              <p className="text-[10px] text-muted-foreground/50 mt-1">Attack Surface</p>
            </div>

            <div className={cn("border rounded-xl p-4 text-center", sev.bg, sev.border)}>
              <div className="flex items-center justify-center gap-1.5 mb-2">
                <ShieldAlert className={cn("w-3.5 h-3.5", sev.text)} />
                <span className={cn("text-[10px] font-semibold uppercase tracking-wider", sev.text)}>Severity</span>
              </div>
              <p className={cn("text-3xl font-bold uppercase", sev.text)}>{f.severity}</p>
              {f.cvss != null && <p className={cn("text-[10px] mt-1", sev.text)}>CVSS {f.cvss}</p>}
            </div>

            <div className="bg-muted/30 border border-border rounded-xl p-4 text-center">
              <div className="flex items-center justify-center gap-1.5 mb-2">
                <Zap className="w-3.5 h-3.5 text-amber-400" />
                <span className="text-[10px] text-muted-foreground font-semibold uppercase tracking-wider">Importance</span>
              </div>
              {impScore != null
                ? <p className={cn("text-3xl font-bold tabular-nums", scoreColor(impScore))}>{impScore}</p>
                : <p className="text-3xl font-bold text-muted-foreground/30">—</p>}
              <p className="text-[10px] text-muted-foreground/50 mt-1">CVSS · EPSS · KEV</p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Two-column body ──────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* ── Left 2/3 ──────────────────────────────────────────── */}
        <div className="lg:col-span-2 space-y-5">

          {/* Asset Information */}
          <Section title="Asset Information" icon={TypeIcon}>
            <KV label="Target">
              <span className="font-mono flex items-center gap-1">
                {f.assetValue ?? f.assetName ?? "—"}
                {f.assetValue && <CopyBtn text={f.assetValue} />}
              </span>
            </KV>
            <KV label="Asset Name">{f.assetName}</KV>
            <KV label="Asset Type">
              <span className="flex items-center gap-1.5">
                <TypeIcon className="w-3.5 h-3.5 text-muted-foreground" />
                {f.assetType ? capitalize(f.assetType.replace(/_/g, " ")) : null}
              </span>
            </KV>

            {geoLabel && <KV label="Country / Location">
              <span className="flex items-center gap-1.5"><MapPin className="w-3 h-3 text-muted-foreground" />{geoLabel}</span>
            </KV>}
            {hostingLabel && <KV label="Hosting / ASN">
              <span className="flex items-center gap-1.5"><Building2 className="w-3 h-3 text-muted-foreground" />{hostingLabel}</span>
            </KV>}
            {scan?.httpInfo?.waf && <KV label="WAF / CDN">
              <span className="flex items-center gap-1.5">
                <Lock className="w-3 h-3 text-green-400" />
                {[scan.httpInfo.waf, scan.httpInfo.cdn].filter(Boolean).join(" · ")}
              </span>
            </KV>}
            {scan?.httpInfo?.server && <KV label="Server"><span className="font-mono">{scan.httpInfo.server}</span></KV>}

            {httpTechs.length > 0 && detectedTechs.length === 0 && (
              <div className="flex items-start justify-between gap-4 py-2 border-b border-border/40">
                <span className="text-xs text-muted-foreground shrink-0 w-32 flex items-center gap-1.5">
                  <Layers className="w-3 h-3" /> Technologies
                </span>
                <div className="flex flex-wrap gap-1 justify-end">
                  {httpTechs.map((t: string) => (
                    <span key={t} className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{t}</span>
                  ))}
                </div>
              </div>
            )}

            {f.assetTags?.length > 0 && (
              <div className="flex items-start justify-between gap-4 py-2 border-b border-border/40">
                <span className="text-xs text-muted-foreground shrink-0 w-32 flex items-center gap-1.5">
                  <Tag className="w-3 h-3" /> Tags
                </span>
                <div className="flex flex-wrap gap-1 justify-end">
                  {f.assetTags.map((t: string) => (
                    <span key={t} className="text-[10px] bg-muted border border-border px-1.5 py-0.5 rounded text-muted-foreground">{t}</span>
                  ))}
                </div>
              </div>
            )}

            {f.cve && <KV label="CVE">
              <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noopener noreferrer"
                 className="font-mono text-amber-400 hover:underline flex items-center gap-1">
                {f.cve} <ExternalLink className="w-3 h-3" />
              </a>
            </KV>}
            {f.cwe && <KV label="CWE"><span className="font-mono text-orange-400">{f.cwe}</span></KV>}
            {f.cvss != null && <KV label="CVSS Score"><span className="font-bold text-orange-400">{f.cvss}</span></KV>}
            {f.epss != null && <KV label="EPSS">{(f.epss * 100).toFixed(2)}% exploit probability</KV>}

            {/* Main Page preview */}
            {scan?.httpInfo?.url && (
              <div className="mt-4 border border-border/50 rounded-lg overflow-hidden">
                <div className="flex items-center gap-2 px-3 py-2 bg-muted/30 border-b border-border/40">
                  <Monitor className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Main Page</span>
                  {scan.httpInfo.status && (
                    <span className="text-[10px] bg-green-500/10 text-green-400 border border-green-500/20 px-1.5 py-0.5 rounded font-mono ml-1">
                      HTTP {scan.httpInfo.status}
                    </span>
                  )}
                  <a href={scan.httpInfo.url} target="_blank" rel="noopener noreferrer"
                     className="ml-auto text-[10px] text-primary hover:underline flex items-center gap-1 font-mono">
                    {scan.httpInfo.url} <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="bg-muted/10 px-4 py-5 text-center">
                  {scan.httpInfo.title
                    ? <p className="text-xs text-muted-foreground italic">"{scan.httpInfo.title}"</p>
                    : <p className="text-xs text-muted-foreground/40">No page title captured</p>}
                </div>
              </div>
            )}
          </Section>

          {/* Open Ports */}
          {(ports.length > 0 || loadingScan) && (
            <Section title={`Open Ports${ports.length ? ` (${ports.length})` : ""}`} icon={Unlock}>
              {loadingScan ? (
                <div className="space-y-2"><Skeleton className="h-12" /><Skeleton className="h-12" /></div>
              ) : (
                <div className="space-y-2">
                  {ports.map((p: any) => (
                    <div key={p.port} className="border border-border rounded-lg overflow-hidden">
                      <div className="flex items-center gap-3 px-4 py-2.5 bg-muted/20">
                        <span className="inline-flex items-center justify-center w-5 h-5 rounded-full bg-green-500/15 border border-green-500/30">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-500" />
                        </span>
                        <span className="text-sm font-bold tabular-nums w-14">{p.port}</span>
                        <span className="text-[10px] font-mono uppercase text-muted-foreground w-10">{p.protocol ?? "tcp"}</span>
                        <span className="text-xs font-semibold text-primary">{p.service ?? "unknown"}</span>
                        {p.version && p.version !== "—" && (
                          <span className="text-xs text-muted-foreground font-mono">{p.version}</span>
                        )}
                        <span className="ml-auto text-[10px] bg-green-500/10 text-green-400 border border-green-500/30 px-1.5 py-0.5 rounded font-semibold uppercase">
                          {p.state ?? "open"}
                        </span>
                      </div>
                      {/* Inline HTTP headers for web ports */}
                      {(p.port === 80 || p.port === 443 || p.port === 8080 || p.port === 8443) && scan?.httpInfo?.headers && (
                        <details className="group">
                          <summary className="flex items-center gap-1.5 px-4 py-1.5 text-[10px] text-muted-foreground cursor-pointer hover:text-foreground list-none select-none">
                            <ChevronRight className="w-3 h-3 group-open:rotate-90 transition-transform" />
                            HTTP response headers
                          </summary>
                          <div className="border-t border-border/40 divide-y divide-border/30 bg-muted/5">
                            {Object.entries(scan.httpInfo.headers).slice(0, 20).map(([k, v]) => (
                              <div key={k} className="px-4 py-1.5 grid grid-cols-2 gap-4">
                                <span className="text-[10px] font-mono text-primary/70 truncate">{k}</span>
                                <span className="text-[10px] font-mono text-muted-foreground break-all">{String(v)}</span>
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Section>
          )}

          {/* Security Risks for this Asset */}
          {otherFindings.length > 0 && (
            <Section title={`Security Risks — This Asset (${otherFindings.length})`} icon={ShieldAlert}>
              <div className="space-y-1.5">
                {otherFindings.slice(0, 15).map((s: any) => {
                  const ss = SEV[s.severity] ?? SEV.info;
                  return (
                    <Link key={s.id} href={`/findings/${s.id}`}>
                      <div className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:bg-accent/20 hover:border-border transition-colors cursor-pointer group">
                        <span className={cn("w-2 h-2 rounded-full shrink-0", ss.dot)} />
                        <div className="flex items-center gap-2 shrink-0">
                          <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-bold uppercase", ss.bg, ss.text, ss.border)}>{s.severity}</span>
                          {s.isKev && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold">KEV</span>}
                        </div>
                        <p className="text-xs flex-1 min-w-0 truncate">{s.title}</p>
                        {s.cve && <span className="text-[10px] font-mono text-amber-400/70 shrink-0">{s.cve}</span>}
                        <ChevronRight className="w-3.5 h-3.5 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
                      </div>
                    </Link>
                  );
                })}
                {otherFindings.length > 15 && (
                  <p className="text-xs text-muted-foreground text-center pt-1">
                    + {otherFindings.length - 15} more risks
                  </p>
                )}
              </div>
            </Section>
          )}

          {/* AI Analysis */}
          <AiSection findingId={f.id} finding={f} />

          {/* Comments */}
          <CommentsSection findingId={f.id} />
        </div>

        {/* ── Right 1/3 ─────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Information (timestamps) */}
          <Section title="Information" icon={Info}>
            <div className="space-y-4 text-xs">
              <div>
                <p className="text-muted-foreground text-[10px] uppercase tracking-wide mb-1">First Seen</p>
                <p className="font-medium flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-muted-foreground" />
                  {formatDateTime(f.createdAt)}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground text-[10px] uppercase tracking-wide mb-1">Last Seen</p>
                <p className="font-medium flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-muted-foreground" />
                  {formatDateTime(f.assetLastScannedAt ?? f.updatedAt)}
                </p>
              </div>
              <div>
                <p className="text-muted-foreground text-[10px] uppercase tracking-wide mb-1">Finding Updated</p>
                <p className="font-medium flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5 text-muted-foreground" />
                  {formatDateTime(f.updatedAt)}
                </p>
              </div>
            </div>
          </Section>

          {/* IP Addresses */}
          {(ips.length > 0 || loadingScan) && (
            <Section title="IP Addresses" icon={Wifi}>
              {loadingScan ? (
                <div className="space-y-2"><Skeleton className="h-8" /><Skeleton className="h-8 w-3/4" /></div>
              ) : (
                <div className="space-y-1.5">
                  {ips.map(ip => (
                    <div key={ip} className="flex items-center gap-2 p-2.5 rounded-lg bg-muted/30 border border-border/40">
                      <Server className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                      <span className="text-xs font-mono">{ip}</span>
                      <CopyBtn text={ip} />
                    </div>
                  ))}
                  {ips.length === 0 && !loadingScan && (
                    <p className="text-xs text-muted-foreground/50">No IP data available.</p>
                  )}
                </div>
              )}
            </Section>
          )}

          {/* Score bars */}
          <Section title="Vulnerability Scores" icon={BarChart3}>
            <div className="space-y-4">
              {[
                { label: "CVSS",       raw: f.cvss,                             max: 10, display: f.cvss?.toFixed(1),                          color: "bg-orange-500" },
                { label: "EPSS",       raw: f.epss != null ? f.epss * 10 : null, max: 10, display: f.epss != null ? `${(f.epss*100).toFixed(2)}%` : null, color: "bg-blue-500" },
                { label: "ASM Score",  raw: f.riskScore != null ? f.riskScore / 10 : null, max: 10, display: f.riskScore != null ? String(Math.round(f.riskScore)) : null, color: "bg-primary" },
                { label: "Importance", raw: impScore != null ? impScore / 10 : null,        max: 10, display: impScore != null ? String(impScore) : null,                color: "bg-amber-500" },
              ].map(({ label, raw, max, display, color }) => (
                <div key={label}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] text-muted-foreground">{label}</span>
                    <span className="text-[10px] font-bold">{display ?? "—"}</span>
                  </div>
                  <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                    {raw != null && <div className={cn("h-full rounded-full transition-all", color)} style={{ width: `${Math.min(100, (raw / max) * 100)}%` }} />}
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* Remediation */}
          {f.remediation && (
            <Section title="Remediation" icon={CheckCircle2}>
              <p className="text-xs text-muted-foreground leading-relaxed">{f.remediation}</p>
            </Section>
          )}

          {/* CVEs from scan data */}
          {scanCves.length > 0 && (
            <Section title={`Scan CVEs (${scanCves.length})`} icon={Hash}>
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {scanCves.map((v: any, i: number) => {
                  const vs = SEV[v.severity] ?? SEV.info;
                  return (
                    <div key={v.cve ?? i} className="p-2.5 rounded-lg border border-border/50">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn("text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase", vs.bg, vs.text, vs.border)}>{v.severity}</span>
                        {v.cve && (
                          <a href={`https://nvd.nist.gov/vuln/detail/${v.cve}`} target="_blank" rel="noopener noreferrer"
                             className="text-[10px] font-mono text-amber-400 hover:underline flex items-center gap-0.5">
                            {v.cve} <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        )}
                        {v.cvss && <span className="text-[10px] text-muted-foreground ml-auto">CVSS {v.cvss}</span>}
                      </div>
                      {v.title && <p className="text-[10px] text-muted-foreground leading-snug">{v.title}</p>}
                    </div>
                  );
                })}
              </div>
            </Section>
          )}

          {/* Asset Screenshots */}
          {f?.assetId && (
            <Section
              title={`Screenshots${shots.length > 0 ? ` (${shots.length})` : ""}`}
              icon={Camera}
            >
              <div className="space-y-3">
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full h-7 text-xs gap-1.5"
                  disabled={screenshotting}
                  onClick={handleScreenshotScan}
                >
                  {screenshotting
                    ? <><Loader2 className="w-3 h-3 animate-spin" /> Capturing…</>
                    : <><Camera className="w-3 h-3" /> {shots.length > 0 ? "Re-capture" : "Capture Screenshots"}</>}
                </Button>

                {screenshotting && (
                  <div className="py-3 flex flex-col items-center gap-1.5 text-muted-foreground">
                    <Loader2 className="w-5 h-5 animate-spin text-primary" />
                    <p className="text-[10px]">Capturing pages…</p>
                  </div>
                )}

                {!screenshotting && shots.length === 0 && (
                  <p className="text-[10px] text-muted-foreground/60 text-center py-2">
                    No screenshots yet. Screenshots are captured automatically on each scan, or click above to run now.
                  </p>
                )}

                {!screenshotting && shots.length > 0 && (
                  <>
                    {shots.some((s: any) => (s.findings ?? []).some((f: any) => f.severity === "critical" || f.severity === "high")) && (
                      <div className="flex items-start gap-1.5 p-2 bg-red-500/5 border border-red-500/20 rounded-lg">
                        <AlertCircle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                        <p className="text-[10px] text-red-300 leading-snug">Sensitive data found in page source — credentials or secrets detected.</p>
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-2">
                      {shots.map((s: any, i: number) => {
                        const findings: any[] = s.findings ?? [];
                        const hasCrit = findings.some((ff: any) => ff.severity === "critical" || ff.severity === "high");
                        const PT_CLS: Record<string, string> = {
                          index:     "bg-blue-500/20 text-blue-400",
                          login:     "bg-violet-500/20 text-violet-400",
                          signup:    "bg-cyan-500/20 text-cyan-400",
                          admin:     "bg-orange-500/20 text-orange-400",
                          api:       "bg-green-500/20 text-green-400",
                          sensitive: "bg-red-500/20 text-red-400",
                        };
                        return (
                          <div
                            key={i}
                            className={cn(
                              "border rounded-lg overflow-hidden cursor-pointer hover:bg-accent/20 transition-colors",
                              hasCrit ? "border-red-500/30" : "border-border/50"
                            )}
                            onClick={() => setShotLightbox(s)}
                          >
                            <div className="relative w-full h-20 bg-muted/40">
                              {s.screenshotData ? (
                                <img
                                  src={`data:image/png;base64,${s.screenshotData}`}
                                  alt={s.title || s.url}
                                  className="w-full h-full object-cover object-top"
                                />
                              ) : (
                                <div className="w-full h-full flex items-center justify-center">
                                  <Camera className="w-5 h-5 text-muted-foreground/30" />
                                </div>
                              )}
                              <span className={cn(
                                "absolute top-1 left-1 text-[9px] font-bold px-1 py-0.5 rounded",
                                PT_CLS[s.pageType] ?? "bg-muted text-muted-foreground"
                              )}>{s.pageType}</span>
                              <span className="absolute top-1 right-1 text-[9px] font-mono bg-black/60 text-white px-1 py-0.5 rounded">{s.statusCode}</span>
                            </div>
                            <div className="px-2 py-1.5">
                              <p className="text-[10px] truncate text-muted-foreground font-mono">{s.url?.replace(/^https?:\/\//, "")}</p>
                              {findings.length > 0 && (
                                <p className={cn("text-[9px] mt-0.5 font-semibold", hasCrit ? "text-red-400" : "text-yellow-400")}>
                                  {findings.length} finding{findings.length > 1 ? "s" : ""}
                                </p>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {shots[0]?.capturedAt && (
                      <p className="text-[9px] text-muted-foreground/40 pt-1">
                        Captured {formatDate(shots[0].capturedAt)}
                      </p>
                    )}
                  </>
                )}
              </div>
            </Section>
          )}

          {/* Lightbox */}
          {shotLightbox && (
            <div
              className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
              onClick={() => setShotLightbox(null)}
            >
              <div
                className="bg-card border border-border rounded-2xl overflow-hidden max-w-3xl w-full max-h-[90vh] flex flex-col"
                onClick={e => e.stopPropagation()}
              >
                <div className="flex items-center justify-between px-4 py-3 border-b border-border shrink-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] font-semibold bg-accent/60 px-1.5 py-0.5 rounded uppercase">{shotLightbox.pageType}</span>
                    <span className="text-xs font-mono text-muted-foreground truncate">{shotLightbox.url}</span>
                  </div>
                  <button onClick={() => setShotLightbox(null)} className="w-7 h-7 rounded-lg bg-accent/60 hover:bg-accent flex items-center justify-center shrink-0 ml-2">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="overflow-y-auto flex-1">
                  {shotLightbox.screenshotData
                    ? <img src={`data:image/png;base64,${shotLightbox.screenshotData}`} alt={shotLightbox.title} className="w-full" />
                    : <div className="h-48 flex items-center justify-center text-muted-foreground/30"><Camera className="w-10 h-10" /></div>}
                </div>
                {(shotLightbox.findings ?? []).length > 0 && (
                  <div className="border-t border-border px-4 py-3 shrink-0">
                    <p className="text-[10px] font-semibold text-muted-foreground mb-2">Sensitive Findings ({shotLightbox.findings.length})</p>
                    <div className="space-y-1.5 max-h-36 overflow-y-auto">
                      {shotLightbox.findings.map((ff: any, i: number) => (
                        <div key={i} className={cn(
                          "flex items-start gap-2 text-xs rounded px-2.5 py-1.5 border",
                          ff.severity === "critical" ? "border-red-500/30 bg-red-500/5 text-red-300" :
                          ff.severity === "high" ? "border-orange-500/30 bg-orange-500/5 text-orange-300" :
                          "border-yellow-500/20 bg-yellow-500/5 text-yellow-300"
                        )}>
                          <span className="font-semibold shrink-0">{ff.type}:</span>
                          <span className="font-mono text-[10px] opacity-80 break-all">{ff.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Detected Technologies */}
          {f?.assetId && (
            <Section
              title={`Detected Technologies${detectedTechs.length > 0 ? ` (${detectedTechs.length})` : ""}`}
              icon={Cpu}
            >
              <div className="space-y-3">
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full h-7 text-xs gap-1.5"
                  disabled={techScanning}
                  onClick={handleTechScan}
                >
                  {techScanning
                    ? <><Loader2 className="w-3 h-3 animate-spin" /> Scanning…</>
                    : <><RefreshCw className="w-3 h-3" /> {detectedTechs.length > 0 ? "Re-scan" : "Detect Technologies"}</>}
                </Button>

                {techScanning && (
                  <div className="py-3 flex flex-col items-center gap-1.5 text-muted-foreground">
                    <Loader2 className="w-5 h-5 animate-spin text-primary" />
                    <p className="text-[10px]">Fingerprinting asset…</p>
                  </div>
                )}

                {!techScanning && detectedTechs.length === 0 && (
                  <p className="text-[10px] text-muted-foreground/60 text-center py-2">
                    No technologies detected yet. Run a scan to fingerprint this asset.
                  </p>
                )}

                {!techScanning && detectedTechs.length > 0 && (
                  <div className="space-y-3">
                    {Object.entries(techGrouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, items]) => (
                      <div key={category}>
                        <p className="text-[9px] font-semibold uppercase tracking-wider text-muted-foreground mb-1.5">{category}</p>
                        <div className="flex flex-wrap gap-1.5">
                          {items.map((t: any) => (
                            <div
                              key={t.id}
                              className={cn(
                                "flex items-center gap-1 px-2 py-1 rounded-md border text-[10px] font-medium",
                                TECH_CATEGORY_COLOR[t.category] ?? "bg-muted text-muted-foreground border-border"
                              )}
                            >
                              {t.icon && <span>{t.icon}</span>}
                              <span>{t.technology}</span>
                              {t.version && (
                                <span className="opacity-60 font-mono bg-black/10 px-1 rounded text-[9px]">{t.version}</span>
                              )}
                              {t.confidence < 100 && (
                                <span className="opacity-40 text-[9px]">{t.confidence}%</span>
                              )}
                              {t.website && (
                                <a href={t.website} target="_blank" rel="noopener noreferrer"
                                   className="opacity-40 hover:opacity-80 transition-opacity"
                                   onClick={e => e.stopPropagation()}>
                                  <ExternalLink className="w-2 h-2" />
                                </a>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                    {detectedTechs[0]?.detectedAt && (
                      <p className="text-[9px] text-muted-foreground/40 pt-1">
                        Last scanned {formatDate(detectedTechs[0].detectedAt)}
                      </p>
                    )}
                  </div>
                )}
              </div>
            </Section>
          )}
        </div>
      </div>
    </div>
  );
}
