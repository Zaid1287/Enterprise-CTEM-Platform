import { useState, useEffect, useMemo } from "react";
import { useParams, useLocation } from "wouter";
import { useGetBrandThreatScan, getGetBrandThreatScanQueryKey, useDeleteBrandThreatScan, getListBrandThreatsQueryKey, useListBrandThreats } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import {
  ArrowLeft, Globe, AlertTriangle, CheckCircle2, XCircle,
  Loader2, Mail, Server, ChevronDown, ChevronUp, RefreshCw,
  ShieldAlert, Eye, Activity, Zap, Fingerprint, ExternalLink,
  Hash, Search, ChevronRight, Download, Fish, Database, Target,
  MapPin, Building2, Calendar, Shield, Info, Lock, Plus, Trash2,
  TrendingUp, Megaphone, History, BookmarkCheck, Clock, AtSign,
  Tag, Smartphone, RotateCw, Ban, CheckCircle, AlertCircle, Send,
  Twitter, Facebook, Instagram, Youtube, Linkedin, Flag, Key,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { downloadBrandThreatPdf, downloadBrandThreatCsv } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

const RISK_META: Record<string, { label: string; color: string; bg: string; border: string; bar: string }> = {
  critical: { label: "Critical",  color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "#f87171" },
  high:     { label: "High",      color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "#fb923c" },
  medium:   { label: "Medium",    color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "#facc15" },
  low:      { label: "Low",       color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  bar: "#4ade80" },
};

const SCORE_COLOR = (s: number) =>
  s >= 75 ? "#f87171" : s >= 50 ? "#fb923c" : s >= 25 ? "#facc15" : "#4ade80";

const FUZZER_META: Record<string, { label: string; color: string; bg: string; chartColor: string }> = {
  "omission":      { label: "Omission",     color: "text-blue-400",   bg: "bg-blue-500/10",   chartColor: "#60a5fa" },
  "repetition":    { label: "Repetition",   color: "text-purple-400", bg: "bg-purple-500/10", chartColor: "#c084fc" },
  "transposition": { label: "Transposition",color: "text-indigo-400", bg: "bg-indigo-500/10", chartColor: "#818cf8" },
  "replacement":   { label: "Keyboard Sub", color: "text-cyan-400",   bg: "bg-cyan-500/10",   chartColor: "#22d3ee" },
  "insertion":     { label: "Insertion",    color: "text-teal-400",   bg: "bg-teal-500/10",   chartColor: "#2dd4bf" },
  "vowel-swap":    { label: "Vowel Swap",   color: "text-sky-400",    bg: "bg-sky-500/10",    chartColor: "#38bdf8" },
  "hyphenation":   { label: "Hyphenation",  color: "text-violet-400", bg: "bg-violet-500/10", chartColor: "#a78bfa" },
  "homoglyph":     { label: "Homoglyph",    color: "text-rose-400",   bg: "bg-rose-500/10",   chartColor: "#fb7185" },
  "subdomain":     { label: "Subdomain",    color: "text-amber-400",  bg: "bg-amber-500/10",  chartColor: "#fbbf24" },
  "addition":      { label: "Addition",     color: "text-lime-400",   bg: "bg-lime-500/10",   chartColor: "#a3e635" },
  "tld-swap":      { label: "TLD Swap",     color: "text-pink-400",   bg: "bg-pink-500/10",   chartColor: "#f472b6" },
  "bitsquatting":  { label: "Bitsquatting", color: "text-orange-400", bg: "bg-orange-500/10", chartColor: "#fb923c" },
};

const ENGINE_META: Record<string, { color: string; bg: string; border: string }> = {
  "Shodan":       { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25" },
  "Censys":       { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/25" },
  "FOFA":         { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25" },
  "Netlas":       { color: "text-teal-400",   bg: "bg-teal-500/10",   border: "border-teal-500/25" },
  "Hunter-How":   { color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/25" },
  "Criminal IP":  { color: "text-rose-400",   bg: "bg-rose-500/10",   border: "border-rose-500/25" },
  "Zoomeye":      { color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/25" },
  "Silent Push":  { color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/25" },
  "ODIN":         { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/25" },
  "Validin":      { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/25" },
};

function SeverityPill({ risk: initialRisk, onPatch }: { risk: string; onPatch: (r: string) => Promise<void>; }) {
  const [risk, setRisk] = useState(initialRisk);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  useEffect(() => { setRisk(initialRisk); }, [initialRisk]);
  const rm = RISK_META[risk] ?? RISK_META.medium!;
  async function pick(newRisk: string) {
    if (newRisk === risk) { setOpen(false); return; }
    setLoading(true);
    try { await onPatch(newRisk); setRisk(newRisk); } catch { /* keep old */ }
    finally { setLoading(false); setOpen(false); }
  }
  return (
    <div className="relative" onClick={e => e.stopPropagation()}>
      <button disabled={loading} onClick={() => setOpen(o => !o)}
        className={cn("flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize hover:opacity-80 cursor-pointer transition-all", rm.color, rm.bg, rm.border)}>
        {loading ? <Loader2 className="w-2.5 h-2.5 animate-spin" /> : risk}
        <ChevronDown className="w-2 h-2 opacity-60" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-50 bg-popover border border-border rounded-xl shadow-2xl overflow-hidden min-w-[110px]">
          {(["critical","high","medium","low"] as const).map(r => {
            const m = RISK_META[r]!;
            return (
              <button key={r} onClick={() => void pick(r)}
                className={cn("w-full text-left px-3 py-1.5 text-xs font-semibold hover:bg-muted/40 transition-colors capitalize", m.color, r === risk && "bg-muted/30")}>
                {m.label}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

type FilterMode = "all" | "live" | "mx" | "suspicious" | "phishing";
type TabMode = "typosquatting" | "phishing" | "data_leaks" | "mobile_apps" | "suspicious_certs" | "social_media" | "malicious_ads" | "logo_brand" | "takedowns" | "favicon_clones" | "subdomains" | "watchlist";

interface FalsePositive {
  id: number;
  item_type: string;
  item_id: number | null;
  item_ref: string;
  comment: string | null;
  status: "pending" | "confirmed" | "rejected";
  created_at: string;
  review_note: string | null;
}

function FalsePositiveButton({
  scanId, itemType, itemId, itemRef, existingFp, onCreated,
}: {
  scanId: number; itemType: string; itemId?: number; itemRef: string;
  existingFp?: FalsePositive; onCreated?: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  const status = existingFp?.status;

  const STATUS_META: Record<string, { label: string; icon: React.ReactNode; color: string; bg: string; border: string }> = {
    pending:   { label: "FP Review",  icon: <Clock className="w-3 h-3" />,        color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/30" },
    confirmed: { label: "Confirmed",  icon: <CheckCircle className="w-3 h-3" />,   color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30" },
    rejected:  { label: "Rejected",   icon: <AlertCircle className="w-3 h-3" />,   color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
  };

  if (status) {
    const meta = STATUS_META[status]!;
    return (
      <span
        title={existingFp?.comment ?? undefined}
        className={cn("inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border cursor-default", meta.color, meta.bg, meta.border)}
      >
        {meta.icon} {meta.label}
        {existingFp?.review_note && <span className="opacity-70 ml-0.5">· {existingFp.review_note.slice(0, 20)}</span>}
      </span>
    );
  }

  async function submit() {
    if (saving) return;
    setSaving(true);
    try {
      const res = await apiFetch(`/api/brand-threats/${scanId}/false-positives`, {
        method: "POST",
        body: JSON.stringify({ itemType, itemId, itemRef, comment: comment.trim() || undefined }),
      }) as Response;
      if (!res.ok) throw new Error("Failed");
      toast({ title: "False positive submitted", description: `${itemRef} marked for review.` });
      setOpen(false);
      setComment("");
      onCreated?.();
    } catch {
      toast({ title: "Error", description: "Could not submit false positive.", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <button
        onClick={e => { e.stopPropagation(); setOpen(true); }}
        title="Mark as false positive"
        className="inline-flex items-center gap-1 text-[10px] text-muted-foreground hover:text-amber-400 hover:bg-amber-500/10 border border-transparent hover:border-amber-500/20 px-1.5 py-0.5 rounded-full transition-all"
      >
        <Ban className="w-3 h-3" /> FP
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg w-full">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <span className="flex items-center justify-center w-8 h-8 rounded-full bg-amber-500/10 shrink-0">
                <Ban className="w-4 h-4 text-amber-400" />
              </span>
              <span>
                <span className="block text-sm font-semibold">Mark as False Positive</span>
                <span className="block text-xs text-muted-foreground font-normal mt-0.5">Flag this item for admin review</span>
              </span>
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="rounded-xl bg-muted/30 border border-border px-4 py-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-1">
                {itemType.replace(/_/g, " ")}
              </p>
              <p className="text-sm font-mono font-medium break-all leading-relaxed text-foreground">{itemRef}</p>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground font-medium block">
                Reason <span className="text-muted-foreground/50">(optional)</span>
              </label>
              <textarea
                value={comment}
                onChange={e => setComment(e.target.value)}
                placeholder="Explain why this is a false positive (e.g. internal test domain, known partner, etc.)"
                rows={4}
                className="w-full bg-background border border-border rounded-xl px-3 py-2.5 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-primary/30 focus:border-primary/50 transition-all placeholder:text-muted-foreground/40"
              />
            </div>
            <div className="flex items-start gap-2 rounded-lg bg-blue-500/5 border border-blue-500/15 px-3 py-2.5">
              <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
              <p className="text-[11px] text-muted-foreground/80 leading-relaxed">
                This item will be queued for admin review. Once confirmed, it will be marked across all tabs and excluded from future risk scoring.
              </p>
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" size="sm" onClick={() => setOpen(false)} className="min-w-[80px]">Cancel</Button>
            <Button size="sm" onClick={submit} disabled={saving} className="gap-1.5 min-w-[100px]">
              {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
              {saving ? "Submitting…" : "Submit"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function RiskScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${score}%`, backgroundColor: SCORE_COLOR(score) }} />
      </div>
      <span className="text-xs font-bold tabular-nums w-6 text-right" style={{ color: SCORE_COLOR(score) }}>
        {score}
      </span>
    </div>
  );
}

function HashChip({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button
      onClick={copy}
      title="Click to copy"
      className="flex flex-col gap-0.5 text-left group hover:bg-muted/60 rounded-lg px-2.5 py-2 transition-colors w-full"
    >
      <span className="text-[9px] uppercase tracking-widest text-muted-foreground font-semibold">{label}</span>
      <span className="font-mono text-[11px] text-foreground/80 break-all leading-snug group-hover:text-foreground transition-colors">
        {copied ? <span className="text-green-400">Copied!</span> : value}
      </span>
    </button>
  );
}

function FaviconIntelPanel({ scan }: { scan: any }) {
  const [collapsed, setCollapsed] = useState(false);
  const status: string = scan.favihunterStatus ?? "pending";
  const searchUrls: Record<string, { url: string; hash_type: string }> = scan.faviconSearchUrls ?? {};

  if (status === "pending" || status === "running") {
    return (
      <div className="bg-violet-500/5 border border-violet-500/20 rounded-xl p-4 flex items-center gap-3">
        <Loader2 className="w-4 h-4 animate-spin text-violet-400 shrink-0" />
        <div>
          <p className="text-sm font-medium text-violet-400">Favicon intelligence scan in progress</p>
          <p className="text-xs text-muted-foreground">favihunter is computing favicon hashes and generating search engine pivot URLs…</p>
        </div>
      </div>
    );
  }
  if (status === "skipped" || status === "error" || !scan.faviconMd5) {
    return (
      <div className="bg-muted/30 border border-border rounded-xl p-4 flex items-center gap-3">
        <Fingerprint className="w-4 h-4 text-muted-foreground/40 shrink-0" />
        <p className="text-xs text-muted-foreground">
          {status === "error"
            ? `Favicon intelligence unavailable: ${scan.favihunterError ?? "unknown error"}`
            : "No favicon found for this domain — skipping favicon intelligence."}
        </p>
      </div>
    );
  }

  const engines = Object.entries(searchUrls).filter(([k]) => k !== "_error");

  return (
    <div className="border border-violet-500/20 rounded-xl overflow-hidden bg-violet-500/3">
      <button className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-violet-500/5 transition-colors" onClick={() => setCollapsed(c => !c)}>
        <Fingerprint className="w-4 h-4 text-violet-400 shrink-0" />
        <span className="text-sm font-semibold text-violet-300">Favicon Intelligence</span>
        <span className="text-[10px] text-violet-400/60 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-mono ml-1">
          powered by favihunter
        </span>
        <div className="flex-1" />
        <span className="text-xs text-muted-foreground mr-1">{engines.length} search engines</span>
        {collapsed ? <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {!collapsed && (
        <div className="border-t border-violet-500/15 px-5 py-4">
          <div className="flex gap-6 flex-wrap">
            <div className="flex flex-col items-center gap-2 shrink-0">
              <div className="w-12 h-12 rounded-xl border border-border bg-background flex items-center justify-center overflow-hidden">
                <img src={scan.faviconUrl} alt="favicon" className="w-10 h-10 object-contain" onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
              </div>
              <p className="text-[9px] text-muted-foreground text-center max-w-[60px] break-all leading-tight font-mono">favicon.ico</p>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-2">
                <Hash className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Favicon Hashes</span>
                <span className="text-[9px] text-muted-foreground/50">(click to copy)</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-0.5">
                <HashChip label="MMH3 (Shodan / FOFA)" value={String(scan.faviconMmh3)} />
                <HashChip label="MMH3-HEX (Criminal IP)" value={scan.faviconMmh3Hex} />
                <HashChip label="MD5 (Censys / Hunter-How / ODIN / Validin)" value={scan.faviconMd5} />
                <HashChip label="SHA256 (Netlas)" value={scan.faviconSha256} />
              </div>
            </div>
          </div>
          {engines.length > 0 && (
            <div className="mt-4">
              <div className="flex items-center gap-1.5 mb-2">
                <Search className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Search Engine Pivots</span>
                <span className="text-[9px] text-muted-foreground/50 ml-1">— click to find hosts using the same favicon</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {engines.map(([name, { url, hash_type }]) => {
                  const meta = ENGINE_META[name] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
                  return (
                    <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                      className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all hover:scale-105 hover:shadow-sm", meta.color, meta.bg, meta.border)}
                      title={`Search ${name} using ${hash_type} hash`}
                    >
                      {name} <ExternalLink className="w-3 h-3 opacity-60" />
                    </a>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground/40 mt-2">
                These links pivot on the domain's actual favicon fingerprint to find clones, phishing infrastructure, or related assets.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ShodanFaviconPanel({ matches }: { matches: any[] }) {
  const [collapsed, setCollapsed] = useState(true);
  if (!matches || matches.length === 0) return null;
  return (
    <div className="border border-red-500/20 rounded-xl overflow-hidden bg-red-500/3 mt-3">
      <button className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-red-500/5 transition-colors" onClick={() => setCollapsed(c => !c)}>
        <Search className="w-4 h-4 text-red-400 shrink-0" />
        <span className="text-sm font-semibold text-red-300">Shodan Favicon Clone Hosts</span>
        <span className="ml-1 text-[10px] font-bold bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
          {matches.length} host{matches.length !== 1 ? "s" : ""} detected
        </span>
        <div className="flex-1" />
        <span className="text-[10px] text-muted-foreground mr-1">Hosts sharing the same favicon fingerprint</span>
        {collapsed ? <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
      </button>
      {!collapsed && (
        <div className="border-t border-red-500/15 px-5 py-4 space-y-2">
          <p className="text-[10px] text-muted-foreground/60 mb-3">
            These IPs/hostnames were found by Shodan using the same favicon hash as your domain. They may be phishing infrastructure or brand clones.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {matches.map((m: any, i: number) => (
              <div key={i} className="flex items-center gap-2 bg-background/60 border border-red-500/20 rounded-lg px-3 py-2">
                <Server className="w-3 h-3 text-red-400 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-mono truncate">{m.ip_str ?? m.ip ?? m.hostname ?? "unknown"}</p>
                  {m.hostnames?.length > 0 && <p className="text-[10px] text-muted-foreground truncate">{m.hostnames[0]}</p>}
                  {(m.org || m.isp) && <p className="text-[10px] text-muted-foreground/60 truncate">{m.org ?? m.isp}</p>}
                </div>
                {m.country_code && (
                  <span className="text-[10px] font-bold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-sm shrink-0">{m.country_code}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── TakedownButton ────────────────────────────────────────────────────────────
interface TakedownPrefill {
  type: string;
  targetUrl: string;
  targetDomain?: string;
  targetIp?: string;
  registrar?: string;
  title: string;
  description?: string;
  brandAbused?: string;
  priority?: string;
}

function TakedownButton({ prefill, onCreated }: { prefill: TakedownPrefill; onCreated?: () => void }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<TakedownPrefill>(prefill);
  const [saving, setSaving] = useState(false);
  const { toast } = useToast();

  function openModal(e: React.MouseEvent) {
    e.stopPropagation();
    setForm({ ...prefill });
    setOpen(true);
  }

  async function submit() {
    if (!form.targetUrl || !form.title) return;
    setSaving(true);
    try {
      await apiFetch("/api/takedowns", {
        method: "POST",
        body: JSON.stringify({
          type: form.type,
          targetUrl: form.targetUrl,
          targetDomain: form.targetDomain ?? null,
          targetIp: form.targetIp ?? null,
          registrar: form.registrar ?? null,
          title: form.title,
          description: form.description ?? null,
          brandAbused: form.brandAbused ?? null,
          priority: form.priority ?? "medium",
        }),
      });
      toast({ title: "Takedown request submitted", description: form.targetDomain ?? form.targetUrl });
      setOpen(false);
      onCreated?.();
    } catch (err: any) {
      toast({ title: "Failed to submit takedown", description: (err as Error).message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <>
      <button onClick={openModal} title="Request Takedown"
        className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-semibold text-amber-400 bg-amber-500/10 border-amber-500/30 hover:bg-amber-500/20 transition-all shrink-0">
        <Flag className="w-2.5 h-2.5" /> Takedown
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg" onClick={e => e.stopPropagation()}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <Flag className="w-4 h-4 text-amber-400" />
              Submit Takedown Request
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Type</label>
                <select value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}
                  className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground">
                  {(["phishing","brand_impersonation","domain_squatting","fake_social","malware_hosting","other"] as const).map(t =>
                    <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
                  )}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Priority</label>
                <select value={form.priority ?? "medium"} onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}
                  className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground">
                  {(["critical","high","medium","low"] as const).map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Title</label>
              <input value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))}
                className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Target URL</label>
              <input value={form.targetUrl} onChange={e => setForm(f => ({ ...f, targetUrl: e.target.value }))}
                className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground font-mono" />
            </div>
            {form.targetDomain !== undefined && (
              <div>
                <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Target Domain</label>
                <input value={form.targetDomain ?? ""} onChange={e => setForm(f => ({ ...f, targetDomain: e.target.value }))}
                  className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground font-mono" />
              </div>
            )}
            {form.registrar !== undefined && (
              <div>
                <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Registrar</label>
                <input value={form.registrar ?? ""} onChange={e => setForm(f => ({ ...f, registrar: e.target.value }))}
                  className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground" />
              </div>
            )}
            <div>
              <label className="block text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-1">Description / Evidence</label>
              <textarea value={form.description ?? ""} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                rows={3} className="w-full text-xs bg-background border border-border rounded-lg px-2 py-1.5 text-foreground resize-none" />
            </div>
          </div>
          <DialogFooter className="mt-1">
            <Button variant="outline" size="sm" onClick={() => setOpen(false)}>Cancel</Button>
            <Button size="sm" disabled={saving || !form.targetUrl || !form.title} onClick={() => void submit()}
              className="bg-amber-500 hover:bg-amber-600 text-white border-0">
              {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : <Flag className="w-3.5 h-3.5 mr-1" />}
              Submit Takedown
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function PhishingTab({ phishing, brandAbuse = [], confirmedResults = [], scanId, falsePositives = [], onFpCreated }: {
  phishing: any[];
  brandAbuse?: any[];
  confirmedResults?: any[];
  scanId?: number;
  falsePositives?: any[];
  onFpCreated?: () => void;
}) {
  const lookalikeLive = brandAbuse.filter((a: any) => a.type === "lookalike_domain");
  const confirmedFromAbuse = brandAbuse.filter((a: any) => a.type === "phishing_domain_confirmed");
  const hasData = phishing.length > 0 || lookalikeLive.length > 0 || confirmedFromAbuse.length > 0;

  if (!hasData) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No phishing domains detected</p>
        <p className="text-sm text-muted-foreground mt-1 max-w-sm">
          PhishTank, OpenPhish, Google Safe Browsing, and abuse.ch found no confirmed phishing
          domains matching this brand's permutations.
        </p>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-8">

      {/* ── Section 1: Active Lookalike Domains ── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 pb-1 border-b border-border">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          <span className="font-semibold text-orange-300">Active Lookalike Domains</span>
          <span className="text-[10px] text-orange-400/70 bg-orange-500/10 px-2 py-0.5 rounded-full font-bold border border-orange-500/20">{lookalikeLive.length}</span>
          <span className="text-xs text-muted-foreground">— live DNS, potential phishing infrastructure</span>
        </div>

        {lookalikeLive.length > 0 ? (
          <>
            <div className="text-xs text-muted-foreground bg-orange-500/5 border border-orange-500/15 rounded-lg px-3 py-2">
              These domains resolved to real IP addresses during the scan. They mimic your brand and may be used for phishing campaigns.
              Check VirusTotal and abuse.ch for current threat classification.
            </div>
            {lookalikeLive.map((a: any) => {
              const aRef = a.url ?? a.title ?? String(a.id);
              const aFp = falsePositives.find(fp => fp.item_type === "lookalike_phishing" && fp.item_ref === aRef);
              return (
              <div key={a.id ?? a.url} className={cn("bg-card border border-orange-500/20 rounded-xl p-4 space-y-2", aFp?.status === "confirmed" && "opacity-50")}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                    <span className="font-mono text-sm text-orange-300 truncate">{(a.url ?? "").replace(/^https?:\/\//, "")}</span>
                    {a.isNew && (
                      <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full shrink-0 uppercase tracking-wide">
                        New
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityPill risk={a.risk ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${a.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
                    <span className="text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-2 py-0.5 rounded-full font-semibold">
                      Live Domain
                    </span>
                    <TakedownButton prefill={{ type: "phishing", targetUrl: a.url ?? "", targetDomain: (a.url ?? "").replace(/^https?:\/\//, "").split("/")[0], title: `Phishing Domain: ${(a.url ?? "").replace(/^https?:\/\//, "").split("/")[0]}`, description: a.description ?? a.evidenceSnippet ?? undefined, priority: (a.risk === "critical" || a.risk === "high") ? a.risk : "high" }} />
                    {scanId && <FalsePositiveButton scanId={scanId} itemType="lookalike_phishing" itemRef={aRef} existingFp={aFp} onCreated={onFpCreated} />}
                  </div>
                </div>
                {a.description && (
                  <p className="text-xs text-muted-foreground">{a.description}</p>
                )}
                {a.evidenceSnippet && (
                  <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1">{a.evidenceSnippet}</p>
                )}
              <div className="flex items-center gap-2">
                <a href={`https://www.virustotal.com/gui/domain/${(a.url ?? "").replace(/^https?:\/\//, "").split("/")[0]}`} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                  <ExternalLink className="w-3 h-3" /> VirusTotal
                </a>
                <a href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent((a.url ?? "").replace(/^https?:\/\//, "").split("/")[0])}`} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                  <ExternalLink className="w-3 h-3" /> abuse.ch
                </a>
                <a href={`https://web.archive.org/web/*/${(a.url ?? "")}`} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                  <ExternalLink className="w-3 h-3" /> Wayback
                </a>
              </div>
            </div>
            ); })}
          </>
        ) : (
          <div className="flex items-center gap-2.5 py-4 text-sm text-green-400/70">
            <CheckCircle2 className="w-4 h-4 shrink-0" /> No active lookalike domains detected
          </div>
        )}
      </div>

      {/* ── Confirmed Phishing Domains ── */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 pb-1 border-b border-border">
          <Fish className="w-4 h-4 text-red-400" />
          <span className="font-semibold">Confirmed Phishing Domains</span>
          <span className="text-[10px] text-red-400/70 bg-red-500/10 px-2 py-0.5 rounded-full font-bold border border-red-500/20">{phishing.length + confirmedResults.length + confirmedFromAbuse.length}</span>
          <span className="text-xs text-muted-foreground">— verified by threat intelligence feeds</span>
        </div>

        {(phishing.length > 0 || confirmedResults.length > 0 || confirmedFromAbuse.length > 0) ? (
          <>
            <div className="text-xs text-muted-foreground bg-red-500/5 border border-red-500/15 rounded-lg px-3 py-2">
              Confirmed by PhishTank, OpenPhish, Google Safe Browsing, URLhaus/abuse.ch, or other threat intelligence feeds as active phishing or malware infrastructure.
            </div>
            {/* URLhaus-confirmed domains from keyword scan lookalike check */}
            {confirmedFromAbuse.map((a: any) => {
              const aRef = a.url ?? a.title ?? String(a.id);
              const aFp = falsePositives.find(fp => fp.item_type === "phishing_domain_confirmed" && fp.item_ref === aRef);
              const domain = (a.url ?? "").replace(/^https?:\/\//, "").split("/")[0];
              return (
                <div key={`cpa-${a.id}`} className={cn("bg-card border border-red-500/25 rounded-xl p-4 space-y-2", aFp?.status === "confirmed" && "opacity-50")}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <Fish className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span className="font-mono text-sm text-red-300 truncate">{domain}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityPill risk="critical" onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${a.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
                      <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded-full font-semibold">{a.platform ?? "URLhaus"}</span>
                      <TakedownButton prefill={{ type: "phishing", targetUrl: a.url ?? "", targetDomain: domain, title: `Confirmed Phishing: ${domain}`, description: a.description ?? undefined, priority: "critical" }} />
                      {scanId && <FalsePositiveButton scanId={scanId} itemType="phishing_domain_confirmed" itemRef={aRef} existingFp={aFp} onCreated={onFpCreated} />}
                    </div>
                  </div>
                  {a.description && <p className="text-xs text-muted-foreground">{a.description}</p>}
                  {a.evidenceSnippet && <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1">{a.evidenceSnippet}</p>}
                  <div className="flex items-center gap-2">
                    <a href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> URLhaus</a>
                    <a href={`https://www.virustotal.com/gui/domain/${domain}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> VirusTotal</a>
                    <a href={`https://phishtank.org/phish_search.php?q=${encodeURIComponent(domain)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> PhishTank</a>
                  </div>
                </div>
              );
            })}
            {confirmedResults.map((r: any) => {
              const rRef = r.permutation ?? String(r.id);
              const rFp = falsePositives.find(fp => fp.item_type === "permutation" && fp.item_ref === rRef);
              const riskLvl = (r.riskScore ?? 0) >= 80 ? "critical" : (r.riskScore ?? 0) >= 60 ? "high" : (r.riskScore ?? 0) >= 40 ? "medium" : "low";
              return (
                <div key={`cr-${r.id}`} className={cn("bg-card border border-red-500/20 rounded-xl p-4 space-y-2", rFp?.status === "confirmed" && "opacity-50")}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <Fish className="w-3.5 h-3.5 text-red-400 shrink-0" />
                      <span className="font-mono text-sm text-red-300 truncate">{r.permutation}</span>
                      {r.isNew && <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full shrink-0 uppercase">New</span>}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <SeverityPill risk={riskLvl} onPatch={async (nr) => { await apiFetch(`/api/brand-threats/results/${r.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: nr }) }); }} />
                      {r.phishingSource && <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded-full font-semibold">{r.phishingSource}</span>}
                      <TakedownButton prefill={{ type: "phishing", targetUrl: `https://${r.permutation}`, targetDomain: r.permutation, registrar: r.whoisRegistrar ?? undefined, title: `Confirmed Phishing: ${r.permutation}`, priority: riskLvl }} />
                      {scanId && <FalsePositiveButton scanId={scanId} itemType="permutation" itemRef={rRef} existingFp={rFp} onCreated={onFpCreated} />}
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                    {r.dnsA?.[0] && <span><span className="font-medium text-foreground/70">IP:</span> <span className="font-mono">{r.dnsA[0]}</span></span>}
                    {r.geoCountry && <span><span className="font-medium text-foreground/70">Country:</span> {r.geoCountry}</span>}
                    {r.vtMalicious != null && <span className={r.vtMalicious > 0 ? "text-red-400 font-medium" : "text-green-400/70"}>VT: {r.vtMalicious} malicious</span>}
                  </div>
                  <div className="flex items-center gap-2">
                    <a href={`https://www.virustotal.com/gui/domain/${r.permutation}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> VirusTotal</a>
                    <a href={`https://phishtank.org/phish_search.php?q=${encodeURIComponent(r.permutation ?? "")}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> PhishTank</a>
                  </div>
                </div>
              );
            })}
            {phishing.map((p: any) => {
              const pRef = p.url ?? String(p.id);
              const pFp = falsePositives.find(fp => fp.item_type === "phishing" && fp.item_ref === pRef);
              return (
              <div key={`feed-${p.id}`} className={cn("bg-card border border-red-500/20 rounded-xl p-4 space-y-2", pFp?.status === "confirmed" && "opacity-50")}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <Fish className="w-3.5 h-3.5 text-red-400 shrink-0" />
                    <span className="font-mono text-sm text-red-300 truncate">{p.url}</span>
                    {p.isNew && <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full shrink-0 uppercase">New</span>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-2 py-0.5 rounded-full font-semibold">{p.source}</span>
                    <TakedownButton prefill={{ type: "phishing", targetUrl: p.url ?? "", targetDomain: (p.url ?? "").replace(/^https?:\/\//, "").split("/")[0], title: `Phishing URL: ${(p.url ?? "").replace(/^https?:\/\//, "").split("/")[0]}`, description: p.targetBrand ? `Brand targeted: ${p.targetBrand}` : undefined, priority: "high" }} />
                    {scanId && <FalsePositiveButton scanId={scanId} itemType="phishing" itemRef={pRef} existingFp={pFp} onCreated={onFpCreated} />}
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                  {p.targetBrand && <span><span className="font-medium text-foreground/70">Target:</span> {p.targetBrand}</span>}
                  {p.threatType && <span><span className="font-medium text-foreground/70">Type:</span> {p.threatType.replace(/_/g, " ")}</span>}
                  {p.submittedAt && <span><span className="font-medium text-foreground/70">Detected:</span> {formatDate(p.submittedAt)}</span>}
                  {p.verified && <span className="text-green-400 flex items-center gap-0.5"><CheckCircle2 className="w-3 h-3" /> Verified</span>}
                </div>
                <div className="flex items-center gap-2">
                  <a href={`https://www.virustotal.com/gui/url/${btoa(p.url)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> VirusTotal</a>
                  <a href={`https://phishtank.org/phish_search.php?q=${encodeURIComponent(p.url)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1"><ExternalLink className="w-3 h-3" /> PhishTank</a>
                </div>
              </div>
              );
            })}
          </>
        ) : (
          <div className="flex items-center gap-2.5 py-4 text-sm text-green-400/70">
            <Shield className="w-4 h-4 shrink-0" /> No confirmed phishing domains found in threat feeds
          </div>
        )}
      </div>
    </div>
  );
}

// Types that represent informational/reference cards, not actual findings
const LEAK_INFO_TYPES = new Set(["osint_reference", "email_rep_clean", "mx_record_found", "no_breach_found"]);
// Types that represent actual breach/exposure findings (shown prominently)
const LEAK_FINDING_TYPES = new Set([
  "email_breach", "email_in_breach_db", "email_credentials_leaked", "email_in_paste_dump",
  "email_paste_hit", "email_in_paste", "email_web_exposure", "email_paste_mention",
  "email_malicious_activity", "intelx_credentials", "intelx_paste", "intelx_darkweb",
]);

const SOURCE_ICON: Record<string, { label: string; color: string }> = {
  "HaveIBeenPwned": { label: "HIBP", color: "text-red-400" },
  "EmailRep.io":    { label: "EmailRep", color: "text-orange-400" },
  "Pastebin Dump Search": { label: "PasteDump", color: "text-yellow-400" },
  "LeakCheck.io":   { label: "LeakCheck", color: "text-orange-400" },
  "IntelX":         { label: "IntelX", color: "text-violet-400" },
  "IntelX-DarkWeb": { label: "IntelX DarkWeb", color: "text-red-400" },
  "IntelX-Paste":   { label: "IntelX Paste", color: "text-orange-400" },
  "IntelX-Credentials": { label: "IntelX Creds", color: "text-red-500" },
  "Reddit":         { label: "Reddit", color: "text-orange-400" },
  "DNS Validation": { label: "DNS", color: "text-blue-400" },
  "HIBP (No Key)":  { label: "HIBP", color: "text-muted-foreground" },
  "Paste Site":     { label: "Paste Site", color: "text-yellow-400" },
  "Web Exposure":   { label: "Web", color: "text-blue-400" },
};

function DataLeaksTab({ leaks, scanId, falsePositives = [], onFpCreated }: {
  leaks: any[];
  scanId?: number;
  falsePositives?: any[];
  onFpCreated?: () => void;
}) {
  // Separate actual findings from informational cards
  const findings = leaks.filter(l => !LEAK_INFO_TYPES.has(l.type ?? ""));
  const infoCards = leaks.filter(l => LEAK_INFO_TYPES.has(l.type ?? ""));

  // Sources used (for the header)
  const sourcesUsed = Array.from(new Set(leaks.map(l => l.source ?? l.platform).filter(Boolean)));

  const SEV_META: Record<string, { color: string; bg: string; border: string }> = {
    critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
    high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20" },
    medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20" },
    low:      { color: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/20" },
    info:     { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20" },
  };

  if (!leaks.length) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Shield className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No data breaches found</p>
        <p className="text-sm text-muted-foreground mt-1">
          Automatic breach checks (EmailRep.io, Pastebin Dump Search, Reddit) found no known exposures.
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          Add an HIBP API key in Platform Settings for the most comprehensive check.
        </p>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2 flex-wrap">
        <Database className="w-4 h-4 text-orange-400 shrink-0" />
        <span className="font-semibold">
          {findings.length > 0
            ? `${findings.length} breach/exposure finding${findings.length !== 1 ? "s" : ""}`
            : "No active exposures detected"}
        </span>
        {sourcesUsed.length > 0 && (
          <span className="text-xs text-muted-foreground">
            — checked: {sourcesUsed.slice(0, 5).join(", ")}
          </span>
        )}
      </div>

      {/* Actual findings */}
      {findings.map((leak: any) => {
        const sev = SEV_META[leak.severity] ?? SEV_META.info;
        const dataClasses: string[] = Array.isArray(leak.exposedData) ? leak.exposedData : [];
        const lRef = leak.title ?? String(leak.id);
        const lFp = falsePositives.find(fp => fp.item_type === "data_leak" && fp.item_ref === lRef);
        const srcMeta = SOURCE_ICON[leak.source ?? leak.platform ?? ""] ?? null;
        return (
          <div key={leak.id} className={cn("bg-card border rounded-xl p-4 space-y-3", sev.border, lFp?.status === "confirmed" && "opacity-50")}>
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <Database className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                  <span className="font-semibold text-sm">{leak.title}</span>
                  <SeverityPill risk={leak.severity ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/data-leaks/${leak.id}/severity`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ severity: r }) }); }} />
                  {srcMeta && (
                    <span className={cn("text-[9px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border bg-muted/40", srcMeta.color, "border-current/30")}>
                      {srcMeta.label}
                    </span>
                  )}
                  {leak.isNew && (
                    <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide">
                      New
                    </span>
                  )}
                </div>
                {(leak.domainMatch || leak.emailMatch) && (
                  <p className="text-[11px] text-muted-foreground mt-0.5 ml-5">
                    {leak.emailMatch && <>Email: {leak.emailMatch}</>}
                    {leak.domainMatch && <> | Domain: {leak.domainMatch}</>}
                  </p>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {leak.breachDate && (
                  <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                    <Calendar className="w-3 h-3" /> {leak.breachDate}
                  </span>
                )}
                <TakedownButton prefill={{ type: "other", targetUrl: leak.url ?? (leak.domainMatch ? `https://${leak.domainMatch}` : ""), title: `Data Breach: ${leak.title}`, description: leak.description ?? undefined, priority: leak.severity === "critical" || leak.severity === "high" ? leak.severity : "medium" }} />
                {scanId && <FalsePositiveButton scanId={scanId} itemType="data_leak" itemRef={lRef} existingFp={lFp} onCreated={onFpCreated} />}
              </div>
            </div>
            {leak.description && (
              <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{leak.description}</p>
            )}
            {leak.evidenceSnippet && (
              <p className="text-[10px] font-mono text-muted-foreground/60 bg-muted/30 rounded px-2 py-1 ml-5 truncate">{leak.evidenceSnippet}</p>
            )}
            {dataClasses.length > 0 && (
              <div className="ml-5">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Exposed Data Classes</p>
                <div className="flex flex-wrap gap-1.5">
                  {dataClasses.map((dc: string) => (
                    <span key={dc} className="text-[10px] bg-muted/50 border border-border px-2 py-0.5 rounded-full text-foreground/70">
                      {dc}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {leak.url && (
              <div className="ml-5">
                <a href={leak.url} target="_blank" rel="noopener noreferrer"
                  className="text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                  <ExternalLink className="w-3 h-3" /> View source →
                </a>
              </div>
            )}
          </div>
        );
      })}

      {/* Informational / status cards (clean results, HIBP upsell, DNS info) — collapsed at bottom */}
      {infoCards.length > 0 && (
        <div className="mt-4 space-y-2">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Scan Status & Additional Info</p>
          {infoCards.map((leak: any) => {
            const isHibpRef = leak.type === "osint_reference";
            return (
              <div key={leak.id ?? leak.title} className={cn(
                "bg-muted/20 border rounded-lg p-3 flex items-start gap-3",
                isHibpRef ? "border-blue-500/20" : "border-border/50"
              )}>
                {isHibpRef
                  ? <Key className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
                  : <Shield className="w-3.5 h-3.5 text-green-400 shrink-0 mt-0.5" />
                }
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-foreground/80">{leak.title}</p>
                  <p className="text-[11px] text-muted-foreground mt-0.5">{leak.description}</p>
                  {leak.url && (
                    <a href={leak.url} target="_blank" rel="noopener noreferrer"
                      className="text-[11px] text-blue-400 hover:text-blue-300 flex items-center gap-1 mt-1 w-fit">
                      <ExternalLink className="w-3 h-3" />
                      {isHibpRef ? "Configure HIBP in Platform Settings →" : "View →"}
                    </a>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

const PLATFORM_META: Record<string, { color: string; bg: string; border: string }> = {
  "Google Play Store":      { color: "text-green-400",   bg: "bg-green-500/10",   border: "border-green-500/25" },
  "Apple App Store":        { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "APKPure":                { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  "Aptoide":                { color: "text-purple-400",  bg: "bg-purple-500/10",  border: "border-purple-500/25" },
  "Samsung Galaxy Store":   { color: "text-teal-400",    bg: "bg-teal-500/10",    border: "border-teal-500/25" },
  "Huawei AppGallery":      { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  "Amazon Appstore":        { color: "text-yellow-400",  bg: "bg-yellow-500/10",  border: "border-yellow-500/25" },
  "Cydia/Sileo (Chariz)":   { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo (Havoc)":    { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo (BigBoss)":  { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Cydia/Sileo":            { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Certificate Transparency": { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/25" },
  "DNS":                    { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "YouTube":                { color: "text-red-400",     bg: "bg-red-500/10",     border: "border-red-500/25" },
  "Reddit":                 { color: "text-orange-400",  bg: "bg-orange-500/10",  border: "border-orange-500/25" },
  "Twitter/X":              { color: "text-slate-400",   bg: "bg-slate-500/10",   border: "border-slate-500/25" },
  "Instagram":              { color: "text-pink-400",    bg: "bg-pink-500/10",    border: "border-pink-500/25" },
  "Facebook":               { color: "text-blue-400",    bg: "bg-blue-500/10",    border: "border-blue-500/25" },
  "TikTok":                 { color: "text-cyan-400",    bg: "bg-cyan-500/10",    border: "border-cyan-500/25" },
};

const APP_STORE_PLATFORMS = new Set([
  "Google Play Store", "Apple App Store", "APKPure", "Aptoide",
  "Samsung Galaxy Store", "Huawei AppGallery", "Amazon Appstore",
  "Cydia/Sileo (Chariz)", "Cydia/Sileo (Havoc)", "Cydia/Sileo (BigBoss)", "Cydia/Sileo",
]);

function PlatformBadge({ platform }: { platform: string }) {
  const meta = PLATFORM_META[platform] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
  return (
    <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-medium shrink-0", meta.color, meta.bg, meta.border)}>
      {platform}
    </span>
  );
}

interface SocialSourceStatus {
  twitter_x: boolean;
  instagram: boolean;
  tiktok: boolean;
  youtube: boolean;
  meta_ads: boolean;
  linkedin: boolean;
}

const SOCIAL_SOURCES: { key: keyof SocialSourceStatus; label: string; settingsPath: string }[] = [
  { key: "twitter_x", label: "Twitter/X", settingsPath: "/settings/platform" },
  { key: "instagram", label: "Instagram",  settingsPath: "/settings/platform" },
  { key: "tiktok",   label: "TikTok",     settingsPath: "/settings/platform" },
  { key: "youtube",  label: "YouTube",    settingsPath: "/settings/platform" },
  { key: "meta_ads", label: "Meta Ads",   settingsPath: "/settings/platform" },
  { key: "linkedin", label: "LinkedIn",   settingsPath: "/settings/platform" },
];

const BASE_URL = import.meta.env.BASE_URL.replace(/\/$/, "");

function SocialSourceBadges() {
  const [status, setStatus] = useState<SocialSourceStatus | null>(null);

  useEffect(() => {
    apiFetch<SocialSourceStatus>(`${BASE_URL}/api/platform/social-source-status`)
      .then(data => setStatus(data))
      .catch(() => {});
  }, []);

  if (!status) return null;

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      {SOCIAL_SOURCES.map(({ key, label, settingsPath }) =>
        status[key] ? (
          <span
            key={key}
            className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border bg-emerald-500/10 border-emerald-500/25 text-emerald-400"
          >
            <CheckCircle2 className="w-2.5 h-2.5" />
            {label}
          </span>
        ) : (
          <a
            key={key}
            href={settingsPath}
            className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full border bg-muted/40 border-border text-muted-foreground hover:text-foreground hover:border-muted-foreground/40 transition-colors"
            title={`${label} API key not configured — click to set up`}
          >
            <XCircle className="w-2.5 h-2.5" />
            {label}
          </a>
        )
      )}
    </div>
  );
}

interface ScanWarning {
  platform: string;
  code: string;
  message: string;
  timestamp: string;
}

const SOCIAL_PLATFORM_LINKS: { name: string; searchUrl: (brand: string) => string; color: string; bg: string; border: string }[] = [
  {
    name: "Twitter/X",
    searchUrl: (b) => `https://twitter.com/search?q=%22${encodeURIComponent(b)}%22&f=user`,
    color: "text-slate-300", bg: "bg-slate-500/10", border: "border-slate-500/25",
  },
  {
    name: "Instagram",
    searchUrl: (b) => `https://www.instagram.com/explore/search/?q=${encodeURIComponent(b)}`,
    color: "text-pink-400", bg: "bg-pink-500/10", border: "border-pink-500/25",
  },
  {
    name: "TikTok",
    searchUrl: (b) => `https://www.tiktok.com/search/user?q=${encodeURIComponent(b)}`,
    color: "text-cyan-400", bg: "bg-cyan-500/10", border: "border-cyan-500/25",
  },
  {
    name: "Facebook",
    searchUrl: (b) => `https://www.facebook.com/search/pages?q=${encodeURIComponent(b)}`,
    color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/25",
  },
  {
    name: "YouTube",
    searchUrl: (b) => `https://www.youtube.com/results?search_query=${encodeURIComponent(b)}+official&sp=EgIQAg%3D%3D`,
    color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/25",
  },
  {
    name: "LinkedIn",
    searchUrl: (b) => `https://www.linkedin.com/search/results/companies/?keywords=${encodeURIComponent(b)}`,
    color: "text-sky-400", bg: "bg-sky-500/10", border: "border-sky-500/25",
  },
];

type PipelineSubdomain = { name: string; ip?: string; cname?: string; status?: string; sources?: string[] };

interface SubdomainThreat {
  name: string;
  takeoverRisk: "high" | "medium" | "none";
  takeoverService?: string;
  cnameTarget?: string;
  highValueTarget: boolean;
  squattingNote?: string;
}

function SubdomainsTab({
  subdomains,
  pipelineScanId,
  scanDomain,
  subdomainThreats = [],
}: {
  subdomains: PipelineSubdomain[];
  pipelineScanId: number;
  scanDomain: string;
  subdomainThreats?: SubdomainThreat[];
}) {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "inactive">("all");
  const [riskFilter, setRiskFilter] = useState<"all" | "high" | "medium">("all");

  const threatMap = new Map<string, SubdomainThreat>(subdomainThreats.map(t => [t.name, t]));
  const highTakeoverCount  = subdomainThreats.filter(t => t.takeoverRisk === "high").length;
  const highValueCount     = subdomainThreats.filter(t => t.highValueTarget).length;

  const filtered = subdomains.filter(s => {
    const q = search.trim().toLowerCase();
    if (q && !s.name.includes(q) && !(s.ip ?? "").includes(q) && !(s.cname ?? "").includes(q)) return false;
    if (statusFilter === "active" && s.status !== "active") return false;
    if (statusFilter === "inactive" && s.status === "active") return false;
    if (riskFilter !== "all") {
      const threat = threatMap.get(s.name);
      if (riskFilter === "high" && threat?.takeoverRisk !== "high") return false;
      if (riskFilter === "medium" && !["high","medium"].includes(threat?.takeoverRisk ?? "")) return false;
    }
    return true;
  });

  const activeCount = subdomains.filter(s => s.status === "active").length;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start gap-4 p-5 bg-blue-500/5 border border-blue-500/20 rounded-xl">
        <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center shrink-0">
          <Server className="w-5 h-5 text-blue-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm font-semibold">Discovered Subdomains</span>
            <span className="text-[10px] font-mono text-blue-400/70 bg-blue-500/10 border border-blue-500/20 px-1.5 py-0.5 rounded-full">
              pipeline scan #{pipelineScanId}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            {subdomains.length} subdomain{subdomains.length !== 1 ? "s" : ""} enumerated for{" "}
            <span className="font-mono text-foreground">{scanDomain}</span> — {activeCount} active.
            {highTakeoverCount > 0 && <span className="text-red-400 font-medium"> {highTakeoverCount} high takeover risk.</span>}
            {highValueCount > 0 && <span className="text-amber-400 font-medium"> {highValueCount} high-value squatting targets.</span>}
          </p>
        </div>
        <div className="flex gap-4 shrink-0">
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-400">{subdomains.length}</p>
            <p className="text-[10px] text-muted-foreground">total</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-green-400">{activeCount}</p>
            <p className="text-[10px] text-muted-foreground">active</p>
          </div>
          {highTakeoverCount > 0 && (
            <div className="text-center">
              <p className="text-2xl font-bold text-red-400">{highTakeoverCount}</p>
              <p className="text-[10px] text-muted-foreground">takeover</p>
            </div>
          )}
        </div>
      </div>

      {/* Threat summary cards */}
      {subdomainThreats.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className={cn(
            "rounded-xl border p-3 space-y-1",
            highTakeoverCount > 0 ? "bg-red-500/5 border-red-500/20" : "bg-muted/20 border-border",
          )}>
            <div className="flex items-center gap-1.5">
              <AlertTriangle className={cn("w-3.5 h-3.5 shrink-0", highTakeoverCount > 0 ? "text-red-400" : "text-muted-foreground")} />
              <p className="text-xs font-semibold">CNAME Takeover Risk</p>
            </div>
            <p className="text-2xl font-bold tabular-nums">{highTakeoverCount}</p>
            <p className="text-[11px] text-muted-foreground">subdomain{highTakeoverCount !== 1 ? "s" : ""} with CNAME to 3rd-party services</p>
          </div>
          <div className={cn(
            "rounded-xl border p-3 space-y-1",
            highValueCount > 0 ? "bg-amber-500/5 border-amber-500/20" : "bg-muted/20 border-border",
          )}>
            <div className="flex items-center gap-1.5">
              <Target className={cn("w-3.5 h-3.5 shrink-0", highValueCount > 0 ? "text-amber-400" : "text-muted-foreground")} />
              <p className="text-xs font-semibold">Squatting Targets</p>
            </div>
            <p className="text-2xl font-bold tabular-nums">{highValueCount}</p>
            <p className="text-[11px] text-muted-foreground">high-value prefix subdomains (auth, login, pay…)</p>
          </div>
          <div className="rounded-xl border bg-muted/20 border-border p-3 space-y-1">
            <div className="flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />
              <p className="text-xs font-semibold">Total Analyzed</p>
            </div>
            <p className="text-2xl font-bold tabular-nums">{subdomainThreats.length}</p>
            <p className="text-[11px] text-muted-foreground">subdomains checked for CNAME &amp; squatting exposure</p>
          </div>
        </div>
      )}

      {/* Search + filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter by subdomain, IP, or CNAME…"
            className="w-full pl-8 pr-3 py-2 text-sm bg-background border border-border rounded-xl focus:outline-none focus:ring-1 focus:ring-primary/40"
          />
          {search && (
            <button onClick={() => setSearch("")} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground text-xs">✕</button>
          )}
        </div>
        <div className="flex gap-1 bg-muted/30 rounded-xl p-1">
          {(["all", "active", "inactive"] as const).map(f => (
            <button key={f} onClick={() => setStatusFilter(f)}
              className={cn("px-3 py-1 rounded-lg text-xs font-medium transition-all capitalize",
                statusFilter === f ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}>
              {f}
            </button>
          ))}
        </div>
        {subdomainThreats.length > 0 && (
          <div className="flex gap-1 bg-muted/30 rounded-xl p-1">
            {(["all", "high", "medium"] as const).map(f => (
              <button key={f} onClick={() => setRiskFilter(f)}
                className={cn("px-3 py-1 rounded-lg text-xs font-medium transition-all",
                  riskFilter === f ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
                  f === "high" && riskFilter === "high" ? "text-red-400" : "",
                )}>
                {f === "all" ? "All Risks" : f === "high" ? "⚠ Takeover" : "CNAME"}
              </button>
            ))}
          </div>
        )}
      </div>

      {(search || statusFilter !== "all" || riskFilter !== "all") && (
        <p className="text-xs text-muted-foreground">
          Showing {filtered.length} of {subdomains.length} subdomains
          {search && <> matching <span className="font-mono text-foreground">"{search}"</span></>}
          {statusFilter !== "all" && <> · status: <span className="text-foreground">{statusFilter}</span></>}
        </p>
      )}

      {/* Results table */}
      {filtered.length > 0 ? (
        <div className="border border-border rounded-xl overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">Subdomain</th>
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">IP Address</th>
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">CNAME</th>
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">Status</th>
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">Threat Intel</th>
                <th className="px-4 py-2.5 text-left text-muted-foreground font-medium">Sources</th>
                <th className="px-2 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(sub => {
                const threat = threatMap.get(sub.name);
                return (
                  <tr key={sub.name} className={cn(
                    "hover:bg-muted/20 transition-colors group",
                    threat?.takeoverRisk === "high" ? "bg-red-500/5" : "",
                  )}>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono text-foreground">{sub.name}</span>
                        {threat?.highValueTarget && (
                          <span className="text-[9px] bg-amber-500/10 text-amber-400 border border-amber-500/20 px-1 py-0.5 rounded font-medium">HIGH-VALUE</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-muted-foreground">{sub.ip ?? "—"}</td>
                    <td className="px-4 py-2.5 font-mono text-muted-foreground max-w-[160px] truncate" title={sub.cname ?? threat?.cnameTarget}>{sub.cname ?? threat?.cnameTarget ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      {sub.status === "active"
                        ? <span className="inline-flex items-center gap-1 text-green-400 bg-green-500/10 border border-green-500/20 px-2 py-0.5 rounded-full font-medium">● active</span>
                        : sub.status
                          ? <span className="inline-flex items-center gap-1 text-muted-foreground bg-muted/30 border border-border px-2 py-0.5 rounded-full">{sub.status}</span>
                          : <span className="text-muted-foreground/50">—</span>
                      }
                    </td>
                    <td className="px-4 py-2.5">
                      {threat?.takeoverRisk === "high" ? (
                        <div className="space-y-0.5">
                          <span className="inline-flex items-center gap-1 text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full font-medium text-[10px]">
                            ⚠ Takeover Risk
                          </span>
                          {threat.takeoverService && (
                            <p className="text-[10px] text-muted-foreground font-mono">{threat.takeoverService}</p>
                          )}
                        </div>
                      ) : threat?.takeoverRisk === "medium" ? (
                        <span className="inline-flex items-center gap-1 text-amber-400 bg-amber-500/10 border border-amber-500/20 px-2 py-0.5 rounded-full font-medium text-[10px]">
                          CNAME Risk
                        </span>
                      ) : (
                        <span className="text-muted-foreground/40 text-[10px]">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {sub.sources?.map(src => (
                          <span key={src} className="text-[10px] px-1.5 py-0.5 rounded bg-muted/50 text-muted-foreground">{src}</span>
                        )) ?? <span className="text-muted-foreground/50">—</span>}
                      </div>
                    </td>
                    <td className="px-2 py-2.5">
                      <a href={`https://${sub.name}`} target="_blank" rel="noopener noreferrer"
                        className="opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                        title={`Visit https://${sub.name}`}>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center py-16 gap-3 text-center">
          <Server className="w-10 h-10 text-muted-foreground/20" />
          <p className="text-sm text-muted-foreground">No subdomains match the current filter</p>
          <button onClick={() => { setSearch(""); setStatusFilter("all"); setRiskFilter("all"); }} className="text-xs text-primary hover:underline">Clear filters</button>
        </div>
      )}

      {/* High-value squatting targets advisory */}
      {subdomainThreats.filter(t => t.squattingNote).length > 0 && (
        <div className="border border-amber-500/20 bg-amber-500/5 rounded-xl p-4 space-y-2">
          <div className="flex items-center gap-2">
            <Target className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            <p className="text-xs font-semibold text-amber-300">Subdomain Squatting Targets</p>
          </div>
          <div className="space-y-1.5">
            {subdomainThreats.filter(t => t.squattingNote).slice(0, 5).map(t => (
              <div key={t.name} className="flex items-start gap-2">
                <span className="font-mono text-[11px] text-amber-300/80 shrink-0">{t.name}</span>
                <span className="text-[11px] text-muted-foreground">{t.squattingNote}</span>
              </div>
            ))}
            {subdomainThreats.filter(t => t.squattingNote).length > 5 && (
              <p className="text-[11px] text-muted-foreground/60">…and {subdomainThreats.filter(t => t.squattingNote).length - 5} more</p>
            )}
          </div>
        </div>
      )}

      {/* Takeover advisory */}
      <div className="border border-amber-500/20 bg-amber-500/5 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />
          <p className="text-xs font-semibold text-amber-300">Subdomain Takeover Advisory</p>
        </div>
        <p className="text-xs text-muted-foreground">
          Subdomains with CNAME records pointing to 3rd-party services (GitHub Pages, Heroku, Netlify, Vercel, etc.)
          may be vulnerable to takeover if the underlying service account is deleted or expired.
          Verify each flagged subdomain is still actively claimed on the target platform.
        </p>
      </div>
    </div>
  );
}


function SocialPlatformMonitor({ scanDomain }: { scanDomain?: string }) {
  const brand = scanDomain?.replace(/\.[^.]+$/, "") ?? "brand";
  return (
    <div className="border border-border rounded-xl p-5 bg-muted/10 space-y-4">
      <div className="flex items-start gap-3">
        <AtSign className="w-4 h-4 text-pink-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold">Social Media Monitor</p>
          <p className="text-xs text-muted-foreground mt-0.5">
            Automated social platform scanning requires API tokens. Use the links below to manually investigate each platform for impersonating accounts or pages.
          </p>
        </div>
        <a href="/settings/platform" className="text-[10px] text-primary hover:text-primary/80 shrink-0 flex items-center gap-1">
          Configure APIs <ExternalLink className="w-2.5 h-2.5" />
        </a>
      </div>
      <div className="flex flex-wrap gap-2">
        {SOCIAL_PLATFORM_LINKS.map(p => (
          <a
            key={p.name}
            href={p.searchUrl(brand)}
            target="_blank"
            rel="noopener noreferrer"
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all hover:scale-105",
              p.color, p.bg, p.border,
            )}
          >
            {p.name} <ExternalLink className="w-3 h-3 opacity-60" />
          </a>
        ))}
      </div>
      <p className="text-[10px] text-muted-foreground/50">
        Search for <span className="font-mono text-muted-foreground">"{brand}"</span> on each platform to find impersonating accounts, squatted pages, or brand-abuse content.
        To enable automated scanning, configure Twitter/X Bearer Token, Instagram Graph Token, TikTok Research Token, or YouTube API Key in{" "}
        <a href="/settings/platform" className="text-primary hover:underline">Platform Settings → Brand Intelligence</a>.
      </p>
    </div>
  );
}

function MobileAppsTab({ abuse, warnings, scanId, falsePositives, onFpCreated }: {
  abuse: any[]; warnings?: ScanWarning[]; scanId: number; falsePositives: FalsePositive[]; onFpCreated: () => void;
}) {
  const activeWarnings = warnings?.filter(w => w.code === "rate_limited") ?? [];
  const MOBILE_TYPES = ["rogue_app", "apk_distribution_link", "official_app_found", "official_ios_app", "similar_app_same_dev", "official_app_on_apkpure", "fake_app", "official_app_not_found"];
  const appItems = abuse.filter(r => MOBILE_TYPES.includes(r.type));
  const fpMap = new Map(falsePositives.filter(fp => fp.item_type === "rogue_app").map(fp => [fp.item_ref, fp]));

  const RISK_COLOR: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-green-400 bg-green-500/10 border-green-500/20",
  };

  if (!appItems.length) {
    return (
      <div className="p-6 flex flex-col items-center justify-center py-20 text-center">
        <Smartphone className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No mobile app threats found</p>
        <p className="text-sm text-muted-foreground mt-1">
          No rogue or lookalike mobile applications found on app stores.
        </p>
      </div>
    );
  }

  const appsByPlatform = appItems.reduce((acc: Record<string, any[]>, r: any) => {
    const key = r.platform ?? "Unknown Store";
    if (!acc[key]) acc[key] = [];
    acc[key]!.push(r);
    return acc;
  }, {});

  const PLATFORM_ORDER = [
    "Google Play Store", "Apple App Store", "APKPure", "Aptoide",
    "Samsung Galaxy Store", "Huawei AppGallery", "Amazon Appstore",
    "Cydia/Sileo (BigBoss)", "Cydia/Sileo (Chariz)", "Cydia/Sileo (Havoc)", "Cydia/Sileo",
  ];
  const sortedPlatforms = [
    ...PLATFORM_ORDER.filter(p => appsByPlatform[p]),
    ...Object.keys(appsByPlatform).filter(p => !PLATFORM_ORDER.includes(p)),
  ];

  return (
    <div className="p-5 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Smartphone className="w-4 h-4 text-orange-400" />
          <span className="font-semibold">{appItems.length} mobile app{appItems.length !== 1 ? "s" : ""} detected</span>
          <span className="text-xs text-muted-foreground">across {sortedPlatforms.length} store{sortedPlatforms.length !== 1 ? "s" : ""}</span>
        </div>
      </div>

      {activeWarnings.length > 0 && (
        <div className="space-y-2">
          {activeWarnings.map((w, i) => (
            <div key={i} className="flex items-start gap-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-amber-300">{w.platform} rate limited — results may be incomplete</p>
                <p className="text-xs text-amber-200/80 mt-0.5">{w.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {sortedPlatforms.map(platform => {
        const items: any[] = appsByPlatform[platform] ?? [];
        const pmeta = PLATFORM_META[platform] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
        return (
          <div key={platform}>
            <div className={cn("flex items-center gap-2 mb-3 px-3 py-1.5 rounded-lg border w-fit", pmeta.bg, pmeta.border)}>
              <Smartphone className={cn("w-3.5 h-3.5", pmeta.color)} />
              <span className={cn("text-[11px] font-semibold", pmeta.color)}>{platform}</span>
              <span className={cn("text-[10px] opacity-60", pmeta.color)}>({items.length})</span>
            </div>
            <div className="space-y-3">
              {items.map((item: any) => {
                const ref = item.url ?? item.title ?? String(item.id);
                const fp = fpMap.get(ref);
                return (
                  <div key={item.id} className={cn("bg-card border rounded-xl p-4", fp?.status === "confirmed" ? "border-green-500/20 opacity-60" : "border-border")}>
                    <div className="flex items-start gap-3">
                      {item.iconUrl ? (
                        <img src={item.iconUrl} alt="" className="w-10 h-10 rounded-xl border border-border object-cover shrink-0 mt-0.5"
                          onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
                      ) : (
                        <div className="w-10 h-10 rounded-xl border border-border bg-muted/30 flex items-center justify-center shrink-0 mt-0.5">
                          <Smartphone className="w-4 h-4 text-muted-foreground/40" />
                        </div>
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2 mb-1">
                          <div className="flex items-center gap-2 flex-wrap min-w-0">
                            <span className="text-sm font-medium leading-snug">{item.title ?? item.url ?? item.platform}</span>
                            {item.isNew && (
                              <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide shrink-0">New</span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <SeverityPill risk={item.risk ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${item.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
                            <TakedownButton prefill={{ type: "brand_impersonation", targetUrl: item.url ?? "", title: `Rogue App: ${item.title ?? item.platform ?? "Unknown"}`, description: item.description ?? undefined, priority: item.risk === "critical" || item.risk === "high" ? item.risk : "high" }} />
                            <FalsePositiveButton scanId={scanId} itemType="rogue_app" itemId={item.id} itemRef={ref} existingFp={fp} onCreated={onFpCreated} />
                          </div>
                        </div>
                        {item.description && <p className="text-xs text-muted-foreground/80 leading-relaxed">{item.description}</p>}
                        <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                          {item.installCount && (
                            <span className="text-[11px] text-muted-foreground flex items-center gap-1">
                              <TrendingUp className="w-3 h-3" /> {item.installCount}
                            </span>
                          )}
                        </div>
                        {item.url && (
                          <a href={item.url} target="_blank" rel="noopener noreferrer"
                            className="mt-1.5 text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                            <ExternalLink className="w-3 h-3" /> {item.url.slice(0, 55)}{item.url.length > 55 ? "…" : ""}
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SuspiciousCertsTab({ abuse, scanId, falsePositives, onFpCreated }: {
  abuse: any[]; scanId: number; falsePositives: FalsePositive[]; onFpCreated: () => void;
}) {
  const certs = abuse.filter(r => r.type === "suspicious_certificate");
  const fpMap = new Map(falsePositives.filter(fp => fp.item_type === "suspicious_certificate").map(fp => [fp.item_ref, fp]));
  const now = Date.now();

  function getExpiryDate(item: any): Date | null {
    if (item.certValidTo) { const d = new Date(item.certValidTo); if (!isNaN(d.getTime())) return d; }
    const m = (item.description ?? "").match(/Issued:\s*(\S+)/);
    if (m?.[1] && m[1] !== "unknown.") {
      const issued = new Date(m[1].replace(/\.$/, ""));
      if (!isNaN(issued.getTime())) return new Date(issued.getTime() + 90 * 86400000);
    }
    return null;
  }

  function certStatus(item: any): "expired" | "expiring" | "suspicious" {
    const exp = getExpiryDate(item);
    if (!exp) return "suspicious";
    const ms = exp.getTime() - now;
    if (ms < 0) return "expired";
    if (ms < 30 * 86400000) return "expiring";
    return "suspicious";
  }

  const expired = certs.filter(c => certStatus(c) === "expired");
  const expiring = certs.filter(c => certStatus(c) === "expiring");
  const suspicious = certs.filter(c => certStatus(c) === "suspicious");

  function CertCard({ item }: { item: any }) {
    const ref = item.url ?? item.title ?? String(item.id);
    const fp = fpMap.get(ref);
    const expiry = getExpiryDate(item);
    return (
      <div className={cn("bg-card border rounded-xl p-4 space-y-2", fp?.status === "confirmed" ? "border-green-500/20 opacity-60" : "border-border")}>
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <Lock className="w-3.5 h-3.5 text-violet-400 shrink-0" />
            <span className="text-sm font-mono font-medium truncate">{item.title ?? item.url}</span>
            {item.isNew && <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide shrink-0">New</span>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <SeverityPill risk={item.risk ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${item.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
            <TakedownButton prefill={{ type: "phishing", targetUrl: item.url ?? "", targetDomain: item.title ?? item.url ?? undefined, title: `Suspicious Certificate: ${item.title ?? item.url ?? "Unknown"}`, description: item.evidenceSnippet ?? item.description ?? undefined, priority: item.risk === "critical" || item.risk === "high" ? item.risk : "medium" }} />
            <FalsePositiveButton scanId={scanId} itemType="suspicious_certificate" itemId={item.id} itemRef={ref} existingFp={fp} onCreated={onFpCreated} />
          </div>
        </div>
        {expiry && <p className="text-xs text-muted-foreground/70 ml-5">Expires: <span className={cn("font-medium", expiry.getTime() < now ? "text-red-400" : expiry.getTime() - now < 30*86400000 ? "text-orange-400" : "text-foreground/60")}>{expiry.toISOString().slice(0, 10)}</span></p>}
        {item.description && <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{item.description}</p>}
        {item.evidenceSnippet && <p className="text-[11px] font-mono bg-muted/30 rounded-lg px-3 py-1.5 text-muted-foreground/70">{item.evidenceSnippet}</p>}
        {item.url && <a href={item.url} target="_blank" rel="noopener noreferrer" className="ml-5 text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit"><ExternalLink className="w-3 h-3" /> {item.url.slice(0, 60)}{item.url.length > 60 ? "…" : ""}</a>}
      </div>
    );
  }

  if (!certs.length) {
    return (
      <div className="p-6 flex flex-col items-center justify-center py-20 text-center">
        <Lock className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No suspicious certificates found</p>
        <p className="text-sm text-muted-foreground mt-1">No certificate transparency entries matching brand name patterns were found.</p>
        <p className="text-xs text-muted-foreground/60 mt-2">Data sourced from crt.sh certificate transparency logs.</p>
      </div>
    );
  }

  return (
    <div className="p-5 space-y-6">
      <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 px-4 py-3 text-xs text-violet-300/80">
        <Info className="w-3.5 h-3.5 inline mr-1.5 text-violet-400" />
        Certificates issued for domains containing brand keywords may indicate phishing infrastructure. Issuance precedes domain activation by hours to days. <span className="font-semibold">{certs.length} total</span> certificates detected.
      </div>

      {expired.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 pb-1 border-b border-border">
            <XCircle className="w-4 h-4 text-red-400" />
            <span className="font-semibold text-red-300">Expired</span>
            <span className="text-[10px] text-red-400/70 bg-red-500/10 px-2 py-0.5 rounded-full font-bold border border-red-500/20">{expired.length}</span>
            <span className="text-xs text-muted-foreground">— certificate has already expired</span>
          </div>
          <div className="space-y-3">{expired.map((item: any) => <CertCard key={item.id} item={item} />)}</div>
        </div>
      )}

      {expiring.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 pb-1 border-b border-border">
            <Clock className="w-4 h-4 text-orange-400" />
            <span className="font-semibold text-orange-300">Expiring Soon</span>
            <span className="text-[10px] text-orange-400/70 bg-orange-500/10 px-2 py-0.5 rounded-full font-bold border border-orange-500/20">{expiring.length}</span>
            <span className="text-xs text-muted-foreground">— expires within 30 days</span>
          </div>
          <div className="space-y-3">{expiring.map((item: any) => <CertCard key={item.id} item={item} />)}</div>
        </div>
      )}

      {suspicious.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center gap-2 pb-1 border-b border-border">
            <ShieldAlert className="w-4 h-4 text-violet-400" />
            <span className="font-semibold text-violet-300">Suspicious</span>
            <span className="text-[10px] text-violet-400/70 bg-violet-500/10 px-2 py-0.5 rounded-full font-bold border border-violet-500/20">{suspicious.length}</span>
            <span className="text-xs text-muted-foreground">— active cert possibly impersonating brand</span>
          </div>
          <div className="space-y-3">{suspicious.map((item: any) => <CertCard key={item.id} item={item} />)}</div>
        </div>
      )}
    </div>
  );
}

function SocialMediaTab({ abuse, warnings, scanDomain, scanId, falsePositives, onFpCreated }: {
  abuse: any[]; warnings?: ScanWarning[]; scanDomain?: string;
  scanId: number; falsePositives: FalsePositive[]; onFpCreated: () => void;
}) {
  const SOCIAL_TYPES = ["fake_social", "social_handle_found", "impersonating_handle", "intelx_mention", "google_dork_mention", "social_mention", "negative_social_mention", "youtube_mention", "negative_youtube_mention", "brand_mention", "negative_brand_mention", "keyword_dork_result", "osint_reference"];
  const socialItems = abuse.filter(r => SOCIAL_TYPES.includes(r.type));
  const fpMap = new Map(falsePositives.filter(fp => fp.item_type === "fake_social").map(fp => [fp.item_ref, fp]));
  const activeWarnings = warnings?.filter(w => w.code === "rate_limited") ?? [];

  const RISK_COLOR: Record<string, string> = {
    critical: "text-red-400 bg-red-500/10 border-red-500/20",
    high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
    low: "text-green-400 bg-green-500/10 border-green-500/20",
  };

  const PLATFORM_ICONS: Record<string, React.ReactNode> = {
    Twitter: <Twitter className="w-3.5 h-3.5" />,
    "X (Twitter)": <Twitter className="w-3.5 h-3.5" />,
    Facebook: <Facebook className="w-3.5 h-3.5" />,
    Instagram: <Instagram className="w-3.5 h-3.5" />,
    YouTube: <Youtube className="w-3.5 h-3.5" />,
    LinkedIn: <Linkedin className="w-3.5 h-3.5" />,
  };

  return (
    <div className="p-5 space-y-6">
      <div className="flex items-center gap-2 mb-1">
        <AtSign className="w-4 h-4 text-pink-400" />
        <span className="font-semibold">
          {socialItems.length > 0 ? `${socialItems.length} social media threat${socialItems.length !== 1 ? "s" : ""} detected` : "Social Media Monitor"}
        </span>
        <div className="flex-1" />
        <SocialSourceBadges />
      </div>

      {activeWarnings.length > 0 && (
        <div className="space-y-2">
          {activeWarnings.map((w, i) => (
            <div key={i} className="flex items-start gap-2.5 rounded-md border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-semibold text-amber-300">{w.platform} rate limited</p>
                <p className="text-xs text-amber-200/80 mt-0.5">{w.message}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {socialItems.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            {socialItems.some(i => i.type === "social_handle_found") ? "Detected Social Profiles" : "Detected Impersonating Accounts"}
          </p>
          {socialItems.map((item: any) => {
            const ref = item.url ?? item.title ?? String(item.id);
            const fp = fpMap.get(ref);
            return (
              <div key={item.id} className={cn("bg-card border rounded-xl p-4", fp?.status === "confirmed" ? "border-green-500/20 opacity-60" : "border-border")}>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2 min-w-0 flex-wrap">
                    <span className="text-pink-400 shrink-0">
                      {PLATFORM_ICONS[item.platform ?? ""] ?? <AtSign className="w-3.5 h-3.5" />}
                    </span>
                    <span className="text-sm font-medium truncate">{item.title ?? item.url}</span>
                    {item.platform && <PlatformBadge platform={item.platform} />}
                    {item.isNew && (
                      <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide shrink-0">New</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <SeverityPill risk={item.risk ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${item.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
                    <TakedownButton prefill={{ type: "fake_social", targetUrl: item.url ?? "", title: `Fake ${item.platform ?? "Social"} Account: ${item.title ?? item.url ?? "Unknown"}`, description: item.description ?? undefined, priority: item.risk === "critical" || item.risk === "high" ? item.risk : "high" }} />
                    <FalsePositiveButton scanId={scanId} itemType="fake_social" itemId={item.id} itemRef={ref} existingFp={fp} onCreated={onFpCreated} />
                  </div>
                </div>
                {item.description && (
                  <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{item.description}</p>
                )}
                {item.evidenceSnippet && (
                  <p className="text-[11px] font-mono bg-muted/30 rounded-lg px-3 py-1.5 mt-2 text-muted-foreground/70">{item.evidenceSnippet}</p>
                )}
                {item.url && (
                  <a href={item.url} target="_blank" rel="noopener noreferrer"
                    className="mt-2 ml-5 text-[11px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1 w-fit">
                    <ExternalLink className="w-3 h-3" /> {item.url.slice(0, 60)}{item.url.length > 60 ? "…" : ""}
                  </a>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Manual platform monitor — always shown */}
      <SocialPlatformMonitor scanDomain={scanDomain} />
    </div>
  );
}

function LogoBrandTab({ abuse, scanId, falsePositives, onFpCreated }: {
  abuse: any[]; scanId: number; falsePositives: FalsePositive[]; onFpCreated: () => void;
}) {
  const LOGO_TYPES = ["logo_accessible", "logo_unreachable", "logo_fetch_error", "reverse_image_search", "logo_web_reference", "meta_ad_library_search", "google_ads_transparency_search"];
  const items = abuse.filter(r => LOGO_TYPES.includes(r.type));
  const fpMap = new Map(falsePositives.filter(fp => fp.item_type === "logo_abuse").map(fp => [fp.item_ref, fp]));

  const TYPE_META: Record<string, { label: string; color: string; icon: React.ReactNode }> = {
    logo_accessible:              { label: "Logo Accessible",         color: "text-blue-400",   icon: <CheckCircle className="w-3.5 h-3.5" /> },
    logo_unreachable:             { label: "Logo Unreachable",        color: "text-orange-400", icon: <AlertCircle className="w-3.5 h-3.5" /> },
    logo_fetch_error:             { label: "Logo Fetch Error",        color: "text-red-400",    icon: <XCircle className="w-3.5 h-3.5" /> },
    reverse_image_search:         { label: "Reverse Image Search",    color: "text-cyan-400",   icon: <Search className="w-3.5 h-3.5" /> },
    logo_web_reference:           { label: "Web Reference",           color: "text-yellow-400", icon: <ExternalLink className="w-3.5 h-3.5" /> },
    meta_ad_library_search:       { label: "Meta Ads Library",        color: "text-blue-400",   icon: <Megaphone className="w-3.5 h-3.5" /> },
    google_ads_transparency_search: { label: "Google Ads Transparency", color: "text-green-400", icon: <Search className="w-3.5 h-3.5" /> },
  };

  if (!items.length) {
    return (
      <div className="p-6 flex flex-col items-center justify-center py-20 text-center">
        <Tag className="w-10 h-10 text-green-400/40 mb-3" />
        <p className="text-base font-semibold text-green-400">No logo or brand abuse findings</p>
        <p className="text-sm text-muted-foreground mt-1">No logo accessibility issues or unauthorized brand references found.</p>
      </div>
    );
  }

  const reverseSearchItems = items.filter(r => r.type === "reverse_image_search");
  const adLibraryItems     = items.filter(r => r.type === "meta_ad_library_search" || r.type === "google_ads_transparency_search");
  const logoStatusItems    = items.filter(r => ["logo_accessible", "logo_unreachable", "logo_fetch_error"].includes(r.type));
  const webRefItems        = items.filter(r => r.type === "logo_web_reference");

  function ItemCard({ item }: { item: any }) {
    const ref = item.url ?? item.title ?? String(item.id);
    const fp = fpMap.get(ref);
    const meta = TYPE_META[item.type] ?? { label: item.type, color: "text-muted-foreground", icon: <Tag className="w-3.5 h-3.5" /> };
    return (
      <div className={cn("bg-card border rounded-xl p-4 space-y-2", fp?.status === "confirmed" ? "border-green-500/20 opacity-60" : "border-border")}>
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span className={meta.color}>{meta.icon}</span>
            <span className="text-sm font-medium truncate">{item.title ?? item.url ?? meta.label}</span>
            <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium border", meta.color, "bg-current/5 border-current/20")}>{meta.label}</span>
            {item.isNew && <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide shrink-0">New</span>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <SeverityPill risk={item.risk ?? "low"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/abuse/${item.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
            <FalsePositiveButton scanId={scanId} itemType="logo_abuse" itemId={item.id} itemRef={ref} existingFp={fp} onCreated={onFpCreated} />
          </div>
        </div>
        {item.description && <p className="text-xs text-muted-foreground/80 leading-relaxed ml-5">{item.description}</p>}
        {item.evidenceSnippet && <p className="text-[11px] font-mono bg-muted/30 rounded-lg px-3 py-1.5 text-muted-foreground/70 whitespace-pre-wrap">{item.evidenceSnippet}</p>}
        {item.url && (
          <a href={item.url} target="_blank" rel="noopener noreferrer"
            className="ml-5 text-[11px] text-primary hover:text-primary/80 transition-colors flex items-center gap-1 w-fit">
            <ExternalLink className="w-3 h-3" /> Open in browser
          </a>
        )}
      </div>
    );
  }

  return (
    <div className="p-5 space-y-6">
      <div className="flex items-center gap-2">
        <Tag className="w-4 h-4 text-cyan-400" />
        <span className="font-semibold">{items.length} logo &amp; brand intelligence finding{items.length !== 1 ? "s" : ""}</span>
      </div>

      {logoStatusItems.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider border-b border-border pb-1.5">Logo Status</p>
          {logoStatusItems.map((item: any) => <ItemCard key={item.id} item={item} />)}
        </div>
      )}

      {reverseSearchItems.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider border-b border-border pb-1.5">Reverse Image Search</p>
          <div className="rounded-xl border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 text-xs text-cyan-300/80">
            <Search className="w-3.5 h-3.5 inline mr-1.5 text-cyan-400" />
            Use these search engines to find unauthorized copies of your logo across the web, social media, and ad networks.
          </div>
          {reverseSearchItems.map((item: any) => <ItemCard key={item.id} item={item} />)}
        </div>
      )}

      {adLibraryItems.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider border-b border-border pb-1.5">Ad Library Checks</p>
          <div className="rounded-xl border border-blue-500/20 bg-blue-500/5 px-4 py-3 text-xs text-blue-300/80">
            <Megaphone className="w-3.5 h-3.5 inline mr-1.5 text-blue-400" />
            Search ad libraries to find unauthorized advertisers using your brand, logo, or trademarks. Requires manual review — click the search links below.
          </div>
          {adLibraryItems.map((item: any) => <ItemCard key={item.id} item={item} />)}
        </div>
      )}

      {webRefItems.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider border-b border-border pb-1.5">Web References to Brand Logo</p>
          {webRefItems.map((item: any) => <ItemCard key={item.id} item={item} />)}
        </div>
      )}
    </div>
  );
}

const AD_RISK_META: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: "Critical", color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30" },
  high:     { label: "High",     color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30" },
  medium:   { label: "Medium",   color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30" },
  low:      { label: "Low",      color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30" },
};

function MaliciousAdsTab({ ads, adLibraryLinks = [], hasMetaToken, scanId, falsePositives = [], onFpCreated }: {
  ads: any[];
  adLibraryLinks?: any[];
  hasMetaToken?: boolean;
  scanId?: number;
  falsePositives?: any[];
  onFpCreated?: () => void;
}) {
  // Pivot links: entries with no adId and platform is a manual-search placeholder
  const PIVOT_PLATFORMS = ["Meta Ads Library", "Google Ads Transparency"];
  const pivotLinks = ads.filter((a: any) => !a.adId && PIVOT_PLATFORMS.includes(a.platform ?? ""));
  const realAds    = ads.filter((a: any) => !(!a.adId && PIVOT_PLATFORMS.includes(a.platform ?? "")));
  const highRisk = realAds.filter((a: any) => a.risk === "critical" || a.risk === "high").length;
  const allPivotLinks = [...pivotLinks, ...adLibraryLinks];

  function PivotLinksSection({ links }: { links: any[] }) {
    if (!links.length) return null;
    return (
      <div className="border border-border rounded-xl p-4 space-y-3">
        <div className="flex items-center gap-2">
          <ExternalLink className="w-3.5 h-3.5 text-muted-foreground" />
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Manual Search Links</span>
          <span className="text-[10px] text-muted-foreground/60 ml-1">— open to review ad libraries</span>
        </div>
        <p className="text-xs text-muted-foreground/70">
          {!hasMetaToken
            ? "Configure a Meta Ads access token in Platform Settings → Brand Intelligence to enable automated ad detection."
            : "Additional manual search links for ad library review."}
        </p>
        <div className="space-y-2">
          {links.map((link: any, i: number) => {
            const isMeta = (link.platform ?? "").includes("Meta");
            const url = link.url ?? link.sourceUrl;
            if (!url) return null;
            return (
              <a
                key={i}
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 px-3.5 py-2.5 rounded-lg border border-border bg-muted/30 hover:bg-muted/60 transition-colors group"
              >
                <div className={cn("w-6 h-6 rounded-md flex items-center justify-center shrink-0", isMeta ? "bg-blue-500/10" : "bg-green-500/10")}>
                  <Megaphone className={cn("w-3.5 h-3.5", isMeta ? "text-blue-400" : "text-green-400")} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium truncate">{link.title ?? (isMeta ? "Meta Ads Library" : "Google Ads Transparency")}</p>
                  {link.body && <p className="text-[11px] text-muted-foreground/70 truncate">{link.body}</p>}
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-muted-foreground/40 group-hover:text-muted-foreground shrink-0 transition-colors" />
              </a>
            );
          })}
        </div>
      </div>
    );
  }

  if (realAds.length === 0) {
    return (
      <div className="p-6 space-y-4">
        <div className="p-6 text-center space-y-3">
          <Megaphone className="w-8 h-8 text-muted-foreground/30 mx-auto" />
          <div>
            <p className="text-sm font-medium text-muted-foreground">No suspicious ad activity detected</p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              {hasMetaToken === false ? (
                <>
                  A Meta Ads access token is required to automatically monitor the ad library.{" "}
                  <a href="/settings/platform" className="text-blue-400 hover:underline">
                    Configure it in Platform Settings → Brand Intelligence.
                  </a>
                </>
              ) : (
                "No brand-impersonating ads were found via the Meta Ads Library API or Google Ads search for this brand."
              )}
            </p>
          </div>
        </div>
        <PivotLinksSection links={allPivotLinks} />
      </div>
    );
  }

  const platforms = [...new Set(realAds.map((a: any) => a.platform).filter(Boolean))];

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-sm font-semibold">Malicious Ad Monitoring</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            {realAds.length} suspicious ad{realAds.length !== 1 ? "s" : ""} detected
            {platforms.length > 0 && <span className="ml-1">via {platforms.join(" & ")}</span>}
            {highRisk > 0 && <span className="ml-1 text-red-400 font-medium">— {highRisk} high/critical risk</span>}
          </p>
        </div>
        <span className="text-xs px-2.5 py-1 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20 font-medium">
          {platforms.length === 1 ? platforms[0] : "Ad Libraries"}
        </span>
      </div>
      <div className="space-y-3">
        {realAds.map((ad: any, i: number) => {
          const risk = AD_RISK_META[ad.risk as string] ?? AD_RISK_META.medium;
          const adRef = String(ad.id ?? ad.adId ?? i);
          const adFp = falsePositives.find(fp => fp.item_type === "malicious_ad" && fp.item_ref === adRef);
          return (
            <div key={ad.id ?? i} className={cn("rounded-xl border p-4 space-y-3", risk.bg, risk.border, adFp?.status === "confirmed" && "opacity-50")}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide", risk.color, risk.bg, risk.border)}>
                      {risk.label}
                    </span>
                    {ad.platform && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted text-muted-foreground border border-border">
                        {ad.platform}
                      </span>
                    )}
                    {ad.adType && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted/50 text-muted-foreground border border-border capitalize">
                        {ad.adType}
                      </span>
                    )}
                    {ad.isNew && (
                      <span className="text-[9px] font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full uppercase tracking-wide">
                        New
                      </span>
                    )}
                  </div>
                  {ad.title && (
                    <p className="text-sm font-semibold text-foreground leading-snug">{ad.title}</p>
                  )}
                  {ad.body && (
                    <p className="text-xs text-muted-foreground mt-1 leading-relaxed line-clamp-3">{ad.body}</p>
                  )}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {ad.snapshotUrl && (
                    <a
                      href={ad.snapshotUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 text-[10px] text-primary hover:text-primary/80 transition-colors"
                    >
                      <ExternalLink className="w-3 h-3" /> View Ad
                    </a>
                  )}
                  <SeverityPill risk={ad.risk ?? "medium"} onPatch={async (r) => { await apiFetch(`/api/brand-threats/ad-monitoring/${ad.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: r }) }); }} />
                  <TakedownButton prefill={{ type: "brand_impersonation", targetUrl: ad.snapshotUrl ?? ad.sourceUrl ?? "", title: `Malicious Ad: ${ad.title ?? ad.advertiserName ?? "Unknown Advertiser"}`, description: ad.body ? `Ad body: ${ad.body}${ad.advertiserName ? `\nAdvertiser: ${ad.advertiserName}` : ""}` : undefined, priority: ad.risk === "critical" || ad.risk === "high" ? ad.risk : "medium" }} />
                  {scanId && <FalsePositiveButton scanId={scanId} itemType="malicious_ad" itemRef={adRef} existingFp={adFp} onCreated={onFpCreated} />}
                </div>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                {ad.advertiserName && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Advertiser</p>
                    <p className="font-medium truncate">{ad.advertiserName}</p>
                  </div>
                )}
                {ad.impressions && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Impressions</p>
                    <p className="font-medium">{ad.impressions}</p>
                  </div>
                )}
                {ad.spend && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Spend</p>
                    <p className="font-medium">{ad.spend} {ad.currency ?? ""}</p>
                  </div>
                )}
                {ad.startDate && (
                  <div className="bg-background/50 rounded-lg px-2.5 py-1.5">
                    <p className="text-muted-foreground text-[10px] mb-0.5 uppercase tracking-wide">Active From</p>
                    <p className="font-medium">{ad.startDate.slice(0, 10)}</p>
                  </div>
                )}
              </div>
              {ad.advertiserPage && (
                <a
                  href={ad.advertiserPage}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors"
                >
                  <ExternalLink className="w-3 h-3" /> Advertiser Page
                </a>
              )}
            </div>
          );
        })}
      </div>
      <PivotLinksSection links={allPivotLinks} />
    </div>
  );
}

const TAKEDOWN_STATUS_COLORS: Record<string, string> = {
  pending:     "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  submitted:   "text-blue-400 bg-blue-500/10 border-blue-500/25",
  in_review:   "text-violet-400 bg-violet-500/10 border-violet-500/25",
  resolved:    "text-green-400 bg-green-500/10 border-green-500/25",
  rejected:    "text-red-400 bg-red-500/10 border-red-500/25",
};

function TakedownsTab({ scanDomain, results }: { scanId: number; scanDomain: string; results: any[] }) {
  const { toast } = useToast();
  const [takedowns, setTakedowns] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ targetDomain: "", type: "phishing", title: "", description: "" });

  const permutationSet = new Set(results.map((r: any) => r.permutation as string));

  async function fetchTakedowns() {
    setLoading(true);
    try {
      const token = getToken();
      const res = await fetch("/api/takedowns", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const all = await res.json() as any[];
        setTakedowns(all.filter((t: any) => t.targetDomain && permutationSet.has(t.targetDomain)));
      }
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void fetchTakedowns(); }, [scanDomain]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.targetDomain.trim() || !form.title.trim()) return;
    setSubmitting(true);
    try {
      const token = getToken();
      const res = await fetch("/api/takedowns", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          type: form.type,
          targetUrl: `https://${form.targetDomain.trim()}`,
          targetDomain: form.targetDomain.trim(),
          title: form.title.trim(),
          description: form.description,
          brandAbused: scanDomain,
          priority: "high",
        }),
      });
      if (!res.ok) throw new Error("Failed");
      toast({ title: "Takedown request submitted" });
      setShowForm(false);
      setForm({ targetDomain: "", type: "phishing", title: "", description: "" });
      void fetchTakedowns();
    } catch {
      toast({ title: "Failed to submit takedown request", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this takedown request?")) return;
    try {
      const token = getToken();
      await fetch(`/api/takedowns/${id}`, { method: "DELETE", headers: { Authorization: `Bearer ${token}` } });
      void fetchTakedowns();
    } catch { /* ignore */ }
  }

  const liveDomains = results
    .filter((r: any) => r.hasA || r.registrationStatus === "registered" || r.registrationStatus === "active")
    .map((r: any) => r.permutation as string);

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold">Takedown Requests</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Submit and track DMCA/abuse takedown requests for infringing domains detected in this scan.
          </p>
        </div>
        <Button size="sm" onClick={() => setShowForm(v => !v)} className="h-8 gap-1.5">
          <Plus className="w-3.5 h-3.5" /> New Request
        </Button>
      </div>

      {showForm && (
        <form onSubmit={handleCreate} className="bg-muted/20 border border-border rounded-xl p-4 space-y-3">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">New Takedown Request</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Infringing Domain *</label>
              <input
                list="td-domains-list"
                value={form.targetDomain}
                onChange={e => setForm(v => ({ ...v, targetDomain: e.target.value }))}
                placeholder="e.g. examp1e.com"
                className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
              />
              <datalist id="td-domains-list">
                {liveDomains.map((d: string) => <option key={d} value={d} />)}
              </datalist>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Abuse Type</label>
              <select
                value={form.type}
                onChange={e => setForm(v => ({ ...v, type: e.target.value }))}
                className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
              >
                {["phishing","brand_impersonation","domain_squatting","fake_social","malware_hosting","other"].map(r => (
                  <option key={r} value={r}>{r.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</option>
                ))}
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Title *</label>
            <input
              value={form.title}
              onChange={e => setForm(v => ({ ...v, title: e.target.value }))}
              placeholder={`Brand impersonation of ${scanDomain}`}
              className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
            />
          </div>
          <div>
            <label className="text-xs text-muted-foreground block mb-1">Description</label>
            <textarea
              value={form.description}
              onChange={e => setForm(v => ({ ...v, description: e.target.value }))}
              rows={2}
              placeholder="Evidence and additional context…"
              className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none resize-none"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button type="button" variant="outline" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting || !form.targetDomain.trim() || !form.title.trim()}>
              {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
              Submit Request
            </Button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="flex items-center justify-center h-24">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : takedowns.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-40 text-center">
          <Shield className="w-8 h-8 text-muted-foreground/20 mb-3" />
          <p className="text-sm text-muted-foreground font-medium">No takedown requests yet</p>
          <p className="text-xs text-muted-foreground/60 mt-1">
            Submit requests for domains in this scan that are infringing on <span className="font-mono">{scanDomain}</span>.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {takedowns.map((td: any) => (
            <div key={td.id} className="flex items-start gap-3 bg-muted/10 border border-border rounded-xl px-4 py-3">
              <Shield className="w-4 h-4 text-primary mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-mono font-medium">{td.targetDomain ?? td.targetUrl}</span>
                  <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize", TAKEDOWN_STATUS_COLORS[td.status] ?? TAKEDOWN_STATUS_COLORS.submitted)}>
                    {td.status?.replace(/_/g, " ") ?? "submitted"}
                  </span>
                  <span className="text-[10px] text-muted-foreground capitalize">{td.type?.replace(/_/g, " ")}</span>
                </div>
                <p className="text-xs font-medium mt-0.5">{td.title}</p>
                {td.description && <p className="text-xs text-muted-foreground/70 mt-0.5">{td.description}</p>}
              </div>
              <Button variant="ghost" size="sm" onClick={() => handleDelete(td.id)} className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 shrink-0">
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const WATCHLIST_TYPE_META: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  keyword:       { icon: <Tag className="w-3.5 h-3.5" />,        label: "Keyword",       color: "text-amber-400" },
  logo_url:      { icon: <Eye className="w-3.5 h-3.5" />,        label: "Logo URL",      color: "text-purple-400" },
  domain:        { icon: <Globe className="w-3.5 h-3.5" />,       label: "Domain",        color: "text-blue-400" },
  ip:            { icon: <Server className="w-3.5 h-3.5" />,      label: "IP",            color: "text-cyan-400" },
  email:         { icon: <Mail className="w-3.5 h-3.5" />,        label: "Email",         color: "text-green-400" },
  social_handle: { icon: <AtSign className="w-3.5 h-3.5" />,      label: "Social Handle", color: "text-pink-400" },
  mobile_app:    { icon: <Smartphone className="w-3.5 h-3.5" />,  label: "Mobile App",    color: "text-orange-400" },
};

const FREQ_LABEL: Record<string, string> = { daily: "Daily", weekly: "Weekly", monthly: "Monthly" };
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function WatchlistDetailTab({
  items,
  scanDomain,
  brandAbuse = [],
  dataLeaks = [],
  adMonitoringResults = [],
  watchlistItemType,
  watchlistItemValue,
}: {
  items: any[];
  scanDomain: string;
  brandAbuse?: any[];
  dataLeaks?: any[];
  adMonitoringResults?: any[];
  watchlistItemType?: string;
  watchlistItemValue?: string;
}) {
  const [, navigate] = useLocation();
  const normalizedScanDomain = scanDomain?.toLowerCase().replace(/^www\./, "") ?? "";

  // Group findings from current scan by category
  const lookalikeDomains = brandAbuse.filter((a: any) => a.type === "lookalike_domain");
  const confirmedPhishing = brandAbuse.filter((a: any) => a.type === "phishing_domain_confirmed");
  const SOCIAL_FINDING_TYPES = ["fake_social","social_handle_found","impersonating_handle","intelx_mention","google_dork_mention","social_mention","negative_social_mention","youtube_mention","negative_youtube_mention","brand_mention","negative_brand_mention","keyword_dork_result","osint_reference"];
  const socialFindings = brandAbuse.filter((a: any) => SOCIAL_FINDING_TYPES.includes(a.type));
  const suspCerts = brandAbuse.filter((a: any) => a.type === "suspicious_certificate");
  const realAds = adMonitoringResults.filter((a: any) => !!a.adId || !!a.adTitle);
  const adPivotLinks = adMonitoringResults.filter((a: any) => !a.adId && !a.adTitle);

  const hasScanFindings = lookalikeDomains.length > 0 || confirmedPhishing.length > 0 ||
    socialFindings.length > 0 || dataLeaks.length > 0 || adMonitoringResults.length > 0 || suspCerts.length > 0;
  const isWatchlistScan = !!watchlistItemType;

  if (items.length === 0 && !hasScanFindings) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center">
        <BookmarkCheck className="w-10 h-10 text-muted-foreground/20 mb-3" />
        <p className="text-sm font-medium text-muted-foreground">No watchlist items</p>
        <p className="text-xs text-muted-foreground/60 mt-1">
          Add domains, keywords, social handles and more in the Watchlist tab on the Brand Threats page.
        </p>
        <button
          onClick={() => navigate("/brand-threats")}
          className="mt-4 inline-flex items-center gap-1.5 text-xs text-primary hover:underline"
        >
          <ArrowLeft className="w-3.5 h-3.5" /> Go to Brand Threats
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">

      {/* ── SCAN FINDINGS section (only for watchlist item scans) ── */}
      {isWatchlistScan && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 pb-1 border-b border-border">
            <ShieldAlert className="w-4 h-4 text-primary" />
            <span className="font-semibold text-sm">
              Findings for{" "}
              <span className="font-mono text-primary">{watchlistItemValue ?? "this item"}</span>
            </span>
            <span className="text-[10px] bg-primary/10 border border-primary/20 text-primary px-2 py-0.5 rounded-full font-semibold capitalize">
              {watchlistItemType}
            </span>
            {!hasScanFindings && (
              <span className="text-xs text-muted-foreground ml-1">— no findings from this scan</span>
            )}
          </div>

          {!hasScanFindings && (
            <div className="flex items-center gap-2.5 py-6 text-sm text-green-400/80 bg-green-500/5 border border-green-500/15 rounded-xl px-4">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              No threats detected in this scan. All checked sources returned clean results.
            </div>
          )}

          {/* ── Confirmed Phishing ── */}
          {confirmedPhishing.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Fish className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs font-semibold text-red-300">Confirmed Phishing Domains</span>
                <span className="text-[10px] bg-red-500/10 border border-red-500/20 text-red-400 px-1.5 py-0.5 rounded-full font-bold">{confirmedPhishing.length}</span>
              </div>
              {confirmedPhishing.map((a: any) => {
                const domain = (a.url ?? "").replace(/^https?:\/\//, "").split("/")[0];
                return (
                  <div key={`cp-${a.id}`} className="bg-card border border-red-500/25 rounded-xl p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <Fish className="w-3.5 h-3.5 text-red-400 shrink-0" />
                        <span className="font-mono text-sm text-red-300 truncate">{domain}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/20 px-1.5 py-0.5 rounded-full font-semibold">{a.platform ?? "URLhaus"}</span>
                        <TakedownButton prefill={{ type: "phishing", targetUrl: a.url ?? "", targetDomain: domain, title: `Confirmed Phishing: ${domain}`, priority: "critical" }} />
                      </div>
                    </div>
                    {a.description && <p className="text-xs text-muted-foreground">{a.description}</p>}
                    {a.evidenceSnippet && <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1">{a.evidenceSnippet}</p>}
                    <div className="flex gap-2">
                      <a href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"><ExternalLink className="w-3 h-3" />URLhaus</a>
                      <a href={`https://www.virustotal.com/gui/domain/${domain}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"><ExternalLink className="w-3 h-3" />VirusTotal</a>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ── Live Lookalike Domains ── */}
          {lookalikeDomains.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                <span className="text-xs font-semibold text-orange-300">Live Lookalike Domains</span>
                <span className="text-[10px] bg-orange-500/10 border border-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded-full font-bold">{lookalikeDomains.length}</span>
              </div>
              {lookalikeDomains.map((a: any) => {
                const domain = (a.url ?? "").replace(/^https?:\/\//, "").split("/")[0];
                return (
                  <div key={`ld-${a.id}`} className="bg-card border border-orange-500/20 rounded-xl p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                        <span className="font-mono text-sm text-orange-300 truncate">{domain}</span>
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded-full font-semibold">Live Domain</span>
                        <TakedownButton prefill={{ type: "phishing", targetUrl: a.url ?? "", targetDomain: domain, title: `Lookalike Domain: ${domain}`, priority: "high" }} />
                      </div>
                    </div>
                    {a.evidenceSnippet && <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1">{a.evidenceSnippet}</p>}
                    {a.description && <p className="text-xs text-muted-foreground">{a.description}</p>}
                    <div className="flex gap-2">
                      <a href={`https://www.virustotal.com/gui/domain/${domain}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"><ExternalLink className="w-3 h-3" />VirusTotal</a>
                      <a href={`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"><ExternalLink className="w-3 h-3" />URLhaus</a>
                      <a href={`https://web.archive.org/web/*/${a.url ?? ""}`} target="_blank" rel="noopener noreferrer" className="text-[11px] text-muted-foreground hover:text-foreground flex items-center gap-1"><ExternalLink className="w-3 h-3" />Wayback</a>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ── Social Media & Brand Abuse ── */}
          {socialFindings.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <AtSign className="w-3.5 h-3.5 text-pink-400" />
                <span className="text-xs font-semibold text-pink-300">Social Media & Brand Mentions</span>
                <span className="text-[10px] bg-pink-500/10 border border-pink-500/20 text-pink-400 px-1.5 py-0.5 rounded-full font-bold">{socialFindings.length}</span>
              </div>
              {socialFindings.map((a: any) => (
                <div key={`sf-${a.id}`} className="bg-card border border-border rounded-xl p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] bg-pink-500/10 text-pink-400 border border-pink-500/20 px-1.5 py-0.5 rounded-full font-semibold shrink-0">{a.platform ?? a.type}</span>
                      <span className="text-sm font-medium truncate">{a.title}</span>
                    </div>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full border font-semibold shrink-0 capitalize", a.risk === "high" || a.risk === "critical" ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20")}>{a.risk ?? a.severity ?? "medium"}</span>
                  </div>
                  {a.description && <p className="text-xs text-muted-foreground line-clamp-2">{a.description}</p>}
                  {a.evidenceSnippet && <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1 line-clamp-2">{a.evidenceSnippet}</p>}
                  {a.url && (
                    <a href={a.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-primary hover:underline flex items-center gap-1 truncate">
                      <ExternalLink className="w-3 h-3 shrink-0" />{a.url}
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Data Leaks ── */}
          {dataLeaks.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-orange-400" />
                <span className="text-xs font-semibold text-orange-300">Data Leaks & Breaches</span>
                <span className="text-[10px] bg-orange-500/10 border border-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded-full font-bold">{dataLeaks.length}</span>
              </div>
              {dataLeaks.map((l: any) => (
                <div key={`dl-${l.id}`} className="bg-card border border-orange-500/20 rounded-xl p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded-full font-semibold shrink-0">{l.source ?? l.type}</span>
                      <span className="text-sm font-medium truncate">{l.title}</span>
                    </div>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full border font-semibold shrink-0 capitalize", l.risk === "critical" ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-orange-500/10 text-orange-400 border-orange-500/20")}>{l.risk ?? l.severity ?? "medium"}</span>
                  </div>
                  {l.description && <p className="text-xs text-muted-foreground line-clamp-2">{l.description}</p>}
                  {l.evidenceSnippet && <p className="text-xs font-mono text-foreground/60 bg-muted/40 rounded px-2 py-1 line-clamp-2">{l.evidenceSnippet}</p>}
                  {l.url && (
                    <a href={l.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-primary hover:underline flex items-center gap-1 truncate">
                      <ExternalLink className="w-3 h-3 shrink-0" />{l.url}
                    </a>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* ── Ad Monitoring ── */}
          {adMonitoringResults.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Megaphone className="w-3.5 h-3.5 text-violet-400" />
                <span className="text-xs font-semibold text-violet-300">Ad Monitoring</span>
                <span className="text-[10px] bg-violet-500/10 border border-violet-500/20 text-violet-400 px-1.5 py-0.5 rounded-full font-bold">{adMonitoringResults.length}</span>
              </div>
              {realAds.map((a: any) => (
                <div key={`ad-${a.id}`} className="bg-card border border-violet-500/20 rounded-xl p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-[10px] bg-violet-500/10 text-violet-400 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-semibold shrink-0">{a.platform}</span>
                      <span className="text-sm font-medium truncate">{a.adTitle ?? a.adSponsor ?? a.searchTerm}</span>
                    </div>
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded-full border font-semibold shrink-0 capitalize", a.risk === "high" || a.risk === "critical" ? "bg-red-500/10 text-red-400 border-red-500/20" : "bg-violet-500/10 text-violet-400 border-violet-500/20")}>{a.risk ?? "medium"}</span>
                  </div>
                  {a.adText && <p className="text-xs text-muted-foreground line-clamp-2">{a.adText}</p>}
                  {a.adSponsor && <p className="text-xs text-muted-foreground">Sponsor: <span className="font-medium text-foreground/70">{a.adSponsor}</span></p>}
                  {a.adUrl && (
                    <a href={a.adUrl} target="_blank" rel="noopener noreferrer" className="text-[11px] text-primary hover:underline flex items-center gap-1 truncate">
                      <ExternalLink className="w-3 h-3 shrink-0" />{a.adUrl}
                    </a>
                  )}
                </div>
              ))}
              {adPivotLinks.map((a: any, i: number) => (
                <div key={`ap-${a.id ?? i}`} className="bg-muted/20 border border-border rounded-xl p-3 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-[10px] bg-muted text-muted-foreground border border-border px-1.5 py-0.5 rounded-full font-semibold shrink-0">{a.platform}</span>
                    <span className="text-xs text-muted-foreground truncate">Manual review — {a.searchTerm ?? a.notes ?? "search link available"}</span>
                  </div>
                  {a.searchUrl && (
                    <a href={a.searchUrl} target="_blank" rel="noopener noreferrer" className="text-[11px] text-primary hover:underline shrink-0 flex items-center gap-1">
                      <ExternalLink className="w-3 h-3" />Search
                    </a>
                  )}
                </div>
              ))}
              {suspCerts.length > 0 && (
                <div className="flex items-center gap-2 py-2 px-3 bg-violet-500/5 border border-violet-500/15 rounded-lg text-xs text-muted-foreground">
                  <Lock className="w-3.5 h-3.5 text-violet-400 shrink-0" />
                  {suspCerts.length} suspicious certificate{suspCerts.length !== 1 ? "s" : ""} found — see{" "}
                  <span className="text-violet-400 font-medium">Certificates</span> tab for details.
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── ALL MONITORED ITEMS section ── */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BookmarkCheck className="w-4 h-4 text-blue-400" />
            <span className="text-sm font-semibold">All Monitored Items</span>
            <span className="text-xs text-muted-foreground bg-muted/40 border border-border px-2 py-0.5 rounded-full">{items.length}</span>
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          All brand assets under continuous monitoring. Each item is scanned on its own schedule and generates separate findings.
        </p>

        <div className="space-y-2">
          {items.map((item: any) => {
            const meta = WATCHLIST_TYPE_META[item.type] ?? WATCHLIST_TYPE_META["keyword"]!;
            const isThisScan = item.type === "domain" &&
              item.value.toLowerCase().replace(/^www\./, "") === normalizedScanDomain;
            const isCurrentItem = watchlistItemType && item.type === watchlistItemType && item.value === watchlistItemValue;
            const prev = item.prevScanSummary as Record<string, number> | null;

            return (
              <div
                key={item.id}
                className={cn(
                  "rounded-xl border p-3 transition-colors",
                  isCurrentItem
                    ? "border-primary/30 bg-primary/5"
                    : isThisScan
                    ? "border-blue-500/25 bg-blue-500/5"
                    : "border-border bg-background/40",
                )}
              >
                <div className="flex items-center gap-3">
                  <div className={cn(
                    "w-7 h-7 rounded-lg border flex items-center justify-center shrink-0",
                    isCurrentItem ? "bg-primary/10 border-primary/25" : isThisScan ? "bg-blue-500/10 border-blue-500/25" : "bg-muted/40 border-border",
                    meta.color,
                  )}>
                    {meta.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{meta.label}</span>
                      {isCurrentItem && (
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary">This Scan</span>
                      )}
                      {isThisScan && !isCurrentItem && (
                        <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">This Domain</span>
                      )}
                    </div>
                    <p className="text-xs font-mono font-semibold mt-0.5 truncate">{item.value}</p>
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      {item.lastScanAt && (
                        <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                          <RotateCw className="w-2.5 h-2.5" />Last: {formatDate(item.lastScanAt)}
                        </span>
                      )}
                      {item.frequency && (
                        <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                          <Clock className="w-2.5 h-2.5" />{FREQ_LABEL[item.frequency] ?? item.frequency}
                        </span>
                      )}
                      {/* Scan finding counts */}
                      {prev && (
                        <>
                          {(prev.brandAbuseCount ?? 0) > 0 && <span className="text-[10px] text-pink-400 font-medium">{prev.brandAbuseCount} abuse</span>}
                          {(prev.dataLeakCount ?? 0) > 0 && <span className="text-[10px] text-orange-400 font-medium">{prev.dataLeakCount} leaks</span>}
                          {(prev.adMonitoringCount ?? 0) > 0 && <span className="text-[10px] text-violet-400 font-medium">{prev.adMonitoringCount} ads</span>}
                        </>
                      )}
                    </div>
                  </div>
                  {item.lastScanId && (
                    <a
                      href={`/brand-threats/${item.lastScanId}`}
                      className="shrink-0 text-[11px] text-primary/70 hover:text-primary transition-colors flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />View Intel
                    </a>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-2 rounded-xl border border-border bg-muted/20 px-4 py-3 flex items-start gap-2">
          <Info className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
          <p className="text-xs text-muted-foreground leading-relaxed">
            Manage watchlist items and configure scan schedules from the{" "}
            <button onClick={() => navigate("/brand-threats")} className="text-primary hover:underline">Brand Threats</button>{" "}
            Watchlist tab.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function BrandThreatDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [fuzzerFilter, setFuzzerFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [downloading, setDownloading] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);
  const [activeTab, setActiveTab] = useState<TabMode>("typosquatting");
  const [tabAutoSet, setTabAutoSet] = useState(false);
  const [watchlistItem, setWatchlistItem] = useState<any | null>(null);
  const [allWatchlistItems, setAllWatchlistItems] = useState<any[]>([]);
  const [confirmDeleteScan, setConfirmDeleteScan] = useState(false);
  const [falsePositives, setFalsePositives] = useState<FalsePositive[]>([]);

  function refreshFalsePositives() {
    if (!id) return;
    void (apiFetch(`/api/brand-threats/${id}/false-positives`) as Promise<Response>)
      .then(r => r.ok ? r.json() as Promise<FalsePositive[]> : Promise.resolve([] as FalsePositive[]))
      .then(rows => setFalsePositives(rows))
      .catch(() => {});
  }
  const deleteScan = useDeleteBrandThreatScan();
  const qc = useQueryClient();
  const { toast } = useToast();
  const PAGE_SIZE = 50;

  const { data: scan, isLoading, refetch } = useGetBrandThreatScan(id, {
    query: {
      enabled: !!id,
      queryKey: getGetBrandThreatScanQueryKey(id),
      staleTime: 0,
      refetchInterval: (query: any) => {
        const d = query?.state?.data as any;
        if (!d || d?.status === "running" || d?.status === "pending") return 3000;
        if (d?.favihunterStatus === "running" || d?.favihunterStatus === "pending") return 4000;
        return false;
      },
    },
  });

  const s = scan as any;

  const { data: allScans = [] } = useListBrandThreats({});

  const domainScans = useMemo(() => {
    if (!s?.domain) return [];
    const domain = s.domain.toLowerCase().replace(/^www\./, "");
    return ((allScans as any[]) ?? [])
      .filter((sc: any) => (sc.domain ?? "").toLowerCase().replace(/^www\./, "") === domain)
      .sort((a: any, b: any) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }, [allScans, s?.domain]);

  useEffect(() => {
    void fetch("/api/brand-watchlist", {
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    })
      .then(r => r.ok ? r.json() : [])
      .then((items: any[]) => {
        setAllWatchlistItems(items);
        // Match by watchlistItemId if the scan has it, otherwise fall back to domain match
        if (s?.watchlistItemId) {
          const byId = items.find((i: any) => i.id === s.watchlistItemId);
          setWatchlistItem(byId ?? null);
        } else if (s?.watchlistItemType && s?.watchlistItemValue) {
          const byTypeValue = items.find((i: any) =>
            i.type === s.watchlistItemType && i.value === s.watchlistItemValue,
          );
          setWatchlistItem(byTypeValue ?? null);
        } else if (s?.domain) {
          const domain = (s.domain as string).toLowerCase().replace(/^www\./, "");
          const match = items.find((i: any) =>
            i.type === "domain" &&
            i.value.toLowerCase().replace(/^www\./, "") === domain,
          );
          setWatchlistItem(match ?? null);
        }
      })
      .catch(() => {});
  }, [s?.domain, s?.watchlistItemId, s?.watchlistItemType, s?.watchlistItemValue]);

  // Auto-select the most relevant tab for non-domain watchlist item scans
  useEffect(() => {
    if (!s || tabAutoSet) return;
    const itemType: string = s.watchlistItemType ?? "";
    let bestTab: TabMode | null = null;
    if (itemType === "email") {
      bestTab = "data_leaks";
    } else if (itemType === "keyword") {
      // Pick the most relevant tab based on what data the scan actually produced
      const abuseItems: any[] = (s as any).brandAbuse ?? [];
      const adItems: any[] = (s as any).adMonitoringResults ?? [];
      const leakItems: any[] = (s as any).dataLeaks ?? [];
      const hasLookalike = abuseItems.some((a: any) => a.type === "lookalike_domain" || a.type === "phishing_domain_confirmed");
      const hasSocial = abuseItems.some((a: any) => ["youtube_mention", "negative_youtube_mention", "brand_mention", "negative_brand_mention", "keyword_dork_result", "osint_reference", "social_mention", "negative_social_mention"].includes(a.type));
      const hasRealAds = adItems.some((a: any) => !!a.adId);
      const hasLeaks = leakItems.length > 0;
      if (hasLookalike) bestTab = "phishing";
      else if (hasRealAds) bestTab = "malicious_ads";
      else if (hasSocial) bestTab = "social_media";
      else if (hasLeaks) bestTab = "data_leaks";
      else bestTab = "social_media";
    } else if (itemType === "social_handle") {
      bestTab = "social_media";
    } else if (itemType === "mobile_app") {
      bestTab = "mobile_apps";
    } else if (itemType === "logo_url") {
      bestTab = "logo_brand";
    }
    if (bestTab) {
      setActiveTab(bestTab);
      setTabAutoSet(true);
    }
  }, [s?.watchlistItemType, s?.faviconMd5, tabAutoSet]);

  useEffect(() => { refreshFalsePositives(); }, [id]);

  const results: any[] = s?.results ?? [];
  const phishingDetections: any[] = s?.phishingDetections ?? [];
  const dataLeaks: any[] = s?.dataLeaks ?? [];
  const brandAbuse: any[] = s?.brandAbuse ?? [];
  const adMonitoringResults: any[] = s?.adMonitoringResults ?? [];

  const filtered = results.filter((r: any) => {
    if (filter === "live"       && !(r.dnsA?.length > 0)) return false;
    if (filter === "mx"         && !(r.dnsMx?.length > 0)) return false;
    if (filter === "suspicious" && !r.isSuspicious) return false;
    if (filter === "phishing"   && !r.isPhishing) return false;
    if (fuzzerFilter !== "all"  && r.fuzzer !== fuzzerFilter) return false;
    if (search && !r.permutation.includes(search.toLowerCase())) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  if (isLoading) {
    return <div className="flex items-center justify-center h-64"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>;
  }

  if (!s) {
    return (
      <div className="p-6 flex flex-col gap-3">
        <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="w-fit">
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" /> Back
        </Button>
        <p className="text-muted-foreground text-sm">Scan not found.</p>
      </div>
    );
  }

  const fuzzerBreakdown: Record<string, number> = s.fuzzerBreakdown ?? {};
  const liveResults    = results.filter((r: any) => r.dnsA?.length > 0);
  const mxResults      = results.filter((r: any) => r.dnsMx?.length > 0);
  const suspResults    = results.filter((r: any) => r.isSuspicious);
  const phishResults   = results.filter((r: any) => r.isPhishing);
  const lookalikeDomains = brandAbuse.filter((a: any) => a.type === "lookalike_domain");
  const confirmedPhishingFromAbuse = brandAbuse.filter((a: any) => a.type === "phishing_domain_confirmed");
  const totalLiveDomains = liveResults.length + lookalikeDomains.length;
  // Phishing tab count: confirmed phishing from feeds + permutations flagged isPhishing + lookalike live domains + URLhaus-confirmed domains
  const totalPhishingData = phishingDetections.length + phishResults.length + lookalikeDomains.length + confirmedPhishingFromAbuse.length;
  const risk        = RISK_META[s.phishingRisk] ?? RISK_META.low;

  const chartData = Object.entries(fuzzerBreakdown)
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .map(([fuzzer, count]) => ({
      fuzzer,
      label: FUZZER_META[fuzzer]?.label ?? fuzzer,
      count: count as number,
      color: FUZZER_META[fuzzer]?.chartColor ?? "#94a3b8",
    }));

  const shodanCloneCount = (s?.faviconShodanMatches as any[] | null)?.length ?? 0;
  const faviconPivotCount = s?.faviconSearchUrls ? Object.keys(s.faviconSearchUrls as object).filter(k => k !== "_error").length : 0;
  const hasFaviconData = !!(s?.faviconMd5 || s?.favihunterStatus === "done");

  const pipelineSubdomains: PipelineSubdomain[] = Array.isArray(s?.pipelineSubdomains)
    ? (s.pipelineSubdomains as PipelineSubdomain[])
    : [];

  const MOBILE_TYPES = ["rogue_app", "apk_distribution_link", "official_app_found", "official_ios_app", "similar_app_same_dev", "official_app_on_apkpure", "fake_app", "official_app_not_found"];
  const SOCIAL_TYPES = ["fake_social", "social_handle_found", "impersonating_handle", "intelx_mention", "google_dork_mention", "social_mention", "negative_social_mention", "youtube_mention", "negative_youtube_mention", "brand_mention", "negative_brand_mention", "keyword_dork_result", "osint_reference"];
  const LOGO_TYPES   = ["logo_accessible", "logo_unreachable", "logo_fetch_error", "reverse_image_search", "logo_web_reference", "meta_ad_library_search", "google_ads_transparency_search"];
  const AD_LIBRARY_TYPES = ["meta_ad_library_search", "google_ads_transparency_search"];

  const mobileAppsCount   = brandAbuse.filter((a: any) => MOBILE_TYPES.includes(a.type)).length;
  const suspCertsCount    = brandAbuse.filter((a: any) => a.type === "suspicious_certificate").length;
  const socialCount       = brandAbuse.filter((a: any) => SOCIAL_TYPES.includes(a.type)).length;
  const logoCount         = brandAbuse.filter((a: any) => LOGO_TYPES.includes(a.type)).length;
  const adLibraryLinks    = brandAbuse.filter((a: any) => AD_LIBRARY_TYPES.includes(a.type));
  const watchlistCount    = allWatchlistItems.length;

  const TABS: { id: TabMode; label: string; icon: React.ReactNode; count?: number; color?: string }[] = [
    { id: "typosquatting",   label: "Typosquatting",   icon: <Globe className="w-3.5 h-3.5" />,      count: results.length },
    { id: "phishing",        label: "Phishing",        icon: <Fish className="w-3.5 h-3.5" />,        count: totalPhishingData, color: totalPhishingData > 0 ? "text-red-400" : undefined },
    { id: "data_leaks",      label: "Data Leaks",      icon: <Database className="w-3.5 h-3.5" />,    count: dataLeaks.length, color: dataLeaks.length > 0 ? "text-orange-400" : undefined },
    { id: "suspicious_certs",label: "Certificates",    icon: <Lock className="w-3.5 h-3.5" />,        count: suspCertsCount, color: suspCertsCount > 0 ? "text-violet-400" : undefined },
    { id: "social_media",    label: "Social Media",    icon: <AtSign className="w-3.5 h-3.5" />,      count: socialCount, color: socialCount > 0 ? "text-pink-400" : undefined },
    { id: "mobile_apps",     label: "Mobile Apps",     icon: <Smartphone className="w-3.5 h-3.5" />,  count: mobileAppsCount, color: mobileAppsCount > 0 ? "text-orange-400" : undefined },
    { id: "malicious_ads",   label: "Malicious Ads",   icon: <Megaphone className="w-3.5 h-3.5" />,   count: adMonitoringResults.length, color: adMonitoringResults.length > 0 ? "text-violet-400" : undefined },
    ...(logoCount > 0 ? [{ id: "logo_brand" as TabMode, label: "Logo & Brand", icon: <Tag className="w-3.5 h-3.5" />, count: logoCount, color: "text-cyan-400" }] : []),
    ...(hasFaviconData ? [{ id: "favicon_clones" as TabMode, label: "Favicon Clones", icon: <Fingerprint className="w-3.5 h-3.5" />, count: shodanCloneCount, color: shodanCloneCount > 0 ? "text-violet-400" : undefined }] : []),
    ...(pipelineSubdomains.length > 0 ? [{ id: "subdomains" as TabMode, label: "Subdomains", icon: <Server className="w-3.5 h-3.5" />, count: pipelineSubdomains.length, color: "text-blue-400" }] : []),
    { id: "watchlist",       label: "Watchlist",       icon: <BookmarkCheck className="w-3.5 h-3.5" />, count: watchlistCount, color: watchlistCount > 0 ? "text-blue-400" : undefined },
    { id: "takedowns",       label: "Takedowns",       icon: <Shield className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="flex flex-col">
      {/* ── Hero header ────────────────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-card via-card to-background border-b border-border px-6 py-5 shrink-0">
        <div className="flex items-center gap-3 mb-1">
          <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="h-8 shrink-0">
            <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
          </Button>
          <div className="w-px h-4 bg-border" />
          <ShieldAlert className="w-4 h-4 text-primary shrink-0" />
          <h1 className="text-lg font-bold font-mono truncate">{s.domain}</h1>
          {s.status === "running" && (
            <span className="flex items-center gap-1.5 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full shrink-0">
              <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
            </span>
          )}
          {s.status === "done" && s.phishingRisk && (
            <span className={cn("text-xs px-2.5 py-0.5 rounded-full border font-semibold capitalize shrink-0", risk.color, risk.bg, risk.border)}>
              {risk.label} Risk
            </span>
          )}
          {s.status === "error" && (
            <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full shrink-0">
              <XCircle className="w-3 h-3" /> Error
            </span>
          )}
          {watchlistItem && (
            <span className="flex items-center gap-1 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full shrink-0">
              <Shield className="w-3 h-3" /> Watchlist
            </span>
          )}
          <div className="flex-1" />
          <Button
            variant="outline" size="sm" className="h-8 shrink-0 gap-1.5"
            disabled={downloadingCsv || s.status !== "done"}
            onClick={async () => {
              setDownloadingCsv(true);
              try { await downloadBrandThreatCsv(id, getToken()); }
              catch { /* ignore */ }
              finally { setDownloadingCsv(false); }
            }}
          >
            {downloadingCsv ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {downloadingCsv ? "Exporting…" : "CSV"}
          </Button>
          <Button
            variant="outline" size="sm" className="h-8 shrink-0 gap-1.5"
            disabled={downloading || s.status !== "done"}
            onClick={async () => {
              setDownloading(true);
              try { await downloadBrandThreatPdf(id, getToken()); }
              catch { /* ignore */ }
              finally { setDownloading(false); }
            }}
          >
            {downloading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Download className="w-3.5 h-3.5" />}
            {downloading ? "Generating…" : "PDF"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => refetch()} className="h-8 shrink-0">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
          <Button
            variant="outline" size="sm"
            className="h-8 shrink-0 gap-1.5"
            disabled={s.status === "running" || s.status === "pending"}
            onClick={async () => {
              try {
                await fetch(`/api/brand-threats/${id}/rescan`, {
                  method: "POST",
                  headers: { Authorization: `Bearer ${getToken() ?? ""}` },
                });
                void refetch();
              } catch { /* ignore */ }
            }}
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Re-scan
          </Button>
          <Button
            variant="outline" size="sm"
            className="h-8 shrink-0 gap-1.5 text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10"
            onClick={() => setConfirmDeleteScan(true)}
          >
            <Trash2 className="w-3.5 h-3.5" /> Delete
          </Button>
          <Dialog open={confirmDeleteScan} onOpenChange={setConfirmDeleteScan}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" /> Delete Scan?
                </DialogTitle>
              </DialogHeader>
              <p className="text-sm text-muted-foreground">
                Permanently delete this brand threat scan and all associated results? This cannot be undone.
              </p>
              <DialogFooter className="mt-2">
                <Button variant="outline" onClick={() => setConfirmDeleteScan(false)} disabled={deleteScan.isPending}>Cancel</Button>
                <Button
                  variant="destructive"
                  onClick={async () => {
                    try {
                      await deleteScan.mutateAsync({ id });
                      qc.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
                      navigate("/brand-threats");
                    } finally {
                      setConfirmDeleteScan(false);
                    }
                  }}
                  disabled={deleteScan.isPending}
                >
                  {deleteScan.isPending ? "Deleting…" : "Delete"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <p className="text-xs text-muted-foreground mt-2 ml-[72px]">
          Started {formatDate(s.createdAt)}
          {s.completedAt && ` · Completed ${formatDate(s.completedAt)}`}
          {s.pipelineScanId && (
            <span className="ml-2 inline-flex items-center gap-0.5 text-violet-400">
              <Zap className="w-2.5 h-2.5" /> Auto-triggered from pipeline scan #{s.pipelineScanId}
            </span>
          )}
          {watchlistItem?.lastScanAt && (
            <span className="ml-2 inline-flex items-center gap-0.5 text-blue-400/70">
              <Shield className="w-2.5 h-2.5" />
              Last auto-scan: {formatDate(watchlistItem.lastScanAt)}
              {watchlistItem.nextScanAt && ` · Next: ${formatDate(watchlistItem.nextScanAt)}`}
            </span>
          )}
        </p>

        {/* ── Scan History Picker ──────────────────────────────────────────────── */}
        {domainScans.length > 1 && (
          <div className="flex items-center gap-2 mt-2 ml-[72px] flex-wrap">
            <History className="w-3.5 h-3.5 text-muted-foreground/60 shrink-0" />
            <span className="text-xs text-muted-foreground shrink-0">Scan history:</span>
            <select
              value={id}
              onChange={e => navigate(`/brand-threats/${e.target.value}`)}
              className="text-xs bg-card border border-border rounded px-2 py-0.5 text-foreground cursor-pointer max-w-[300px]"
            >
              {domainScans.map((sc: any, i: number) => (
                <option key={sc.id} value={sc.id}>
                  {i === 0 ? "▲ Latest — " : `#${domainScans.length - i} — `}{formatDate(sc.createdAt)} · {sc.status === "done" ? `${sc.totalPermutations ?? 0} permutations` : sc.status}
                </option>
              ))}
            </select>
            <span className="text-xs text-muted-foreground/50 shrink-0">
              {domainScans.length} total scan{domainScans.length !== 1 ? "s" : ""}
            </span>
            {/* Jump to latest button when viewing an older scan */}
            {domainScans.length > 0 && String(domainScans[0].id) !== String(id) && (
              <button
                onClick={() => navigate(`/brand-threats/${domainScans[0].id}`)}
                className="inline-flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded-full bg-primary/10 border border-primary/25 text-primary hover:bg-primary/20 transition-colors"
              >
                Jump to latest ↑
              </button>
            )}
          </div>
        )}

        {/* ── "Viewing older scan" comparison banner ───────────────────────────── */}
        {domainScans.length > 1 && String(domainScans[0]?.id) !== String(id) && s.status === "done" && (() => {
          const latest = domainScans[0] as any;
          if (!latest || latest.status !== "done") return null;
          const deltaPerms  = (latest.totalPermutations ?? 0) - (s.totalPermutations ?? 0);
          const deltaLive   = (latest.liveCount ?? 0)         - (s.liveCount ?? 0);
          const deltaPhish  = (latest.phishingCount ?? 0)     - (s.phishingCount ?? 0);
          const deltaLeaks  = (latest.dataLeakCount ?? 0)     - (s.dataLeakCount ?? 0);
          const deltaAbuse  = (latest.brandAbuseCount ?? 0)   - (s.brandAbuseCount ?? 0);
          const hasChanges  = deltaPerms !== 0 || deltaLive !== 0 || deltaPhish !== 0 || deltaLeaks !== 0 || deltaAbuse !== 0;
          const totalNew    = Math.max(0, deltaLive) + Math.max(0, deltaPhish) + Math.max(0, deltaLeaks) + Math.max(0, deltaAbuse);
          return (
            <div className={cn(
              "mx-6 mt-3 border rounded-xl p-3.5 shrink-0",
              totalNew > 0
                ? "bg-orange-500/5 border-orange-500/20"
                : "bg-blue-500/5 border-blue-500/20",
            )}>
              <div className="flex items-center justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <TrendingUp className={cn("w-3.5 h-3.5 shrink-0", totalNew > 0 ? "text-orange-400" : "text-blue-400")} />
                  <p className={cn("text-xs font-semibold", totalNew > 0 ? "text-orange-300" : "text-blue-300")}>
                    Viewing scan from {formatDate(s.createdAt)} — comparing with latest scan ({formatDate(latest.createdAt)})
                  </p>
                </div>
                <button
                  onClick={() => navigate(`/brand-threats/${latest.id}`)}
                  className="text-[10px] font-medium text-primary hover:text-primary/80 underline shrink-0"
                >
                  View latest →
                </button>
              </div>
              {hasChanges && (
                <div className="flex flex-wrap gap-3 mt-2 ml-5.5">
                  {[
                    { label: "Permutations", delta: deltaPerms, warn: false },
                    { label: "Live Domains",  delta: deltaLive,  warn: true },
                    { label: "Phishing",      delta: deltaPhish, warn: true },
                    { label: "Data Leaks",    delta: deltaLeaks, warn: true },
                    { label: "Brand Abuse",   delta: deltaAbuse, warn: true },
                  ].filter(m => m.delta !== 0).map(m => (
                    <div key={m.label} className="flex items-center gap-1">
                      <span className="text-[10px] text-muted-foreground">{m.label}:</span>
                      <span className={cn(
                        "text-[10px] font-bold",
                        m.delta > 0 && m.warn ? "text-orange-400" : m.delta > 0 ? "text-blue-400" : "text-green-400",
                      )}>
                        {m.delta > 0 ? "+" : ""}{m.delta} in latest
                      </span>
                    </div>
                  ))}
                  {!hasChanges && (
                    <span className="text-[10px] text-muted-foreground">No changes between scans</span>
                  )}
                </div>
              )}
              {!hasChanges && (
                <p className="text-[11px] text-muted-foreground mt-1 ml-5.5">No changes detected between this scan and the latest.</p>
              )}
            </div>
          );
        })()}

        {(s.status === "done" || s.status === "error") && (() => {
          const highRiskCount = (results as any[]).filter((r: any) => (r.riskScore ?? 0) >= 60).length;
          const registeredCount = s.registeredCount ?? 0;
          const stats = [
            { label: "Permutations", value: (s.totalPermutations ?? 0).toLocaleString(), color: "", sub: "total generated" },
            { label: "Registered", value: registeredCount, color: registeredCount > 0 ? "text-orange-400" : "text-green-400", sub: "DNS-active domains" },
            { label: "Live Domains", value: totalLiveDomains, color: totalLiveDomains > 0 ? "text-red-400" : "text-green-400", sub: "DNS A resolves" },
            { label: "High Risk", value: highRiskCount, color: highRiskCount > 0 ? "text-red-500" : "text-green-400", sub: "risk score ≥ 60" },
            { label: "Confirmed Phishing", value: totalPhishingData, color: totalPhishingData > 0 ? "text-red-400" : "text-green-400", sub: phishingDetections.length > 0 ? "feed verified" : "feed checked" },
            { label: "Data Breaches", value: dataLeaks.length, color: dataLeaks.length > 0 ? "text-yellow-400" : "text-green-400", sub: "HIBP matches" },
            { label: "Brand Abuse", value: s.brandAbuseCount ?? 0, color: (s.brandAbuseCount ?? 0) > 0 ? "text-orange-400" : "text-green-400", sub: "fake sites/apps" },
            { label: "Malicious Ads", value: s.adMonitoringCount ?? 0, color: (s.adMonitoringCount ?? 0) > 0 ? "text-violet-400" : "text-green-400", sub: "Meta Ads Library" },
          ];
          return (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
              {stats.map(stat => (
                <div key={stat.label} className="bg-background/60 border border-border rounded-xl px-4 py-3">
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">{stat.label}</p>
                  <p className={cn("text-2xl font-bold tabular-nums", stat.color)}>{stat.value}</p>
                  <p className="text-[10px] text-muted-foreground">{stat.sub}</p>
                </div>
              ))}
            </div>
          );
        })()}
      </div>

      {/* ── Watchlist delta banner — shown after a scheduled re-scan ─────────── */}
      {watchlistItem?.prevScanSummary && s.status === "done" && (() => {
        const prev = watchlistItem.prevScanSummary as Record<string, number>;
        const deltaLive    = (s.liveCount ?? 0)            - (prev.liveCount ?? 0);
        const deltaPhish   = (s.phishingCount ?? 0)        - (prev.phishingCount ?? 0);
        const deltaLeaks   = (s.dataLeakCount ?? 0)        - (prev.dataLeakCount ?? 0);
        const deltaAbuse   = (s.brandAbuseCount ?? 0)      - (prev.brandAbuseCount ?? 0);
        const deltaAds     = (s.adMonitoringCount ?? 0)    - (prev.adMonitoringCount ?? 0);
        const totalNew     = Math.max(0, deltaLive) + Math.max(0, deltaPhish) + Math.max(0, deltaLeaks) + Math.max(0, deltaAbuse) + Math.max(0, deltaAds);
        const hasChanges   = deltaLive !== 0 || deltaPhish !== 0 || deltaLeaks !== 0 || deltaAbuse !== 0 || deltaAds !== 0;
        if (!hasChanges) return null;
        return (
          <div className={cn(
            "mx-6 mt-4 border rounded-xl p-4 shrink-0",
            totalNew > 0
              ? "bg-orange-500/5 border-orange-500/20"
              : "bg-green-500/5 border-green-500/20",
          )}>
            <div className="flex items-center gap-2 mb-2">
              <TrendingUp className={cn("w-4 h-4 shrink-0", totalNew > 0 ? "text-orange-400" : "text-green-400")} />
              <p className={cn("text-sm font-semibold", totalNew > 0 ? "text-orange-400" : "text-green-400")}>
                {totalNew > 0
                  ? `${totalNew} new threat${totalNew !== 1 ? "s" : ""} found since last scheduled scan`
                  : "No new threats found since last scheduled scan"}
              </p>
            </div>
            <div className="flex flex-wrap gap-3 ml-6">
              {[
                { label: "Live domains",  delta: deltaLive,  warn: deltaLive > 0 },
                { label: "Phishing",      delta: deltaPhish, warn: deltaPhish > 0 },
                { label: "Data leaks",    delta: deltaLeaks, warn: deltaLeaks > 0 },
                { label: "Brand abuse",   delta: deltaAbuse, warn: deltaAbuse > 0 },
                { label: "Mal. ads",      delta: deltaAds,   warn: deltaAds > 0 },
              ].filter(d => d.delta !== 0).map(d => (
                <span key={d.label} className={cn(
                  "text-[11px] font-semibold px-2 py-1 rounded-lg border",
                  d.warn
                    ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
                    : "text-green-400 bg-green-500/10 border-green-500/20",
                )}>
                  {d.delta > 0 ? `+${d.delta}` : d.delta} {d.label}
                </span>
              ))}
            </div>
          </div>
        );
      })()}

      {/* ── Status banners ──────────────────────────────────────────────────── */}
      {(s.status === "running" || s.status === "pending") && (
        <div className="mx-6 mt-4 bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 flex items-center gap-4 shrink-0">
          <Loader2 className="w-5 h-5 animate-spin text-blue-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-blue-400">Full intelligence scan in progress</p>
            <p className="text-xs text-muted-foreground">
              {s.totalPermutations > 0
                ? `Resolving DNS for ${s.totalPermutations} domain permutations + running RDAP, GeoIP, VT, phishing feeds, HIBP, brand abuse checks…`
                : "Generating permutations via dnstwist + running favihunter favicon analysis…"}
            </p>
          </div>
        </div>
      )}
      {s.status === "error" && (() => {
        const isTimeout = s.error?.toLowerCase().includes("timed out");
        return (
          <div className="mx-6 mt-4 bg-red-500/5 border border-red-500/20 rounded-xl p-4 shrink-0">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold text-red-400">
                  {isTimeout ? "Scan timed out" : "Scan failed"}
                </p>
                <p className="text-xs text-muted-foreground mt-1 font-mono">
                  {s.error ?? "An unexpected error occurred during the scan."}
                </p>
                {isTimeout && (
                  <p className="text-xs text-muted-foreground/70 mt-1">
                    This scan was automatically stopped after exceeding the 30-minute limit. Click Retry Scan to start a fresh scan and get up-to-date results.
                  </p>
                )}
              </div>
              <Button
                size="sm"
                variant="outline"
                className="shrink-0 h-8 gap-1.5 border-red-500/30 text-red-400 hover:bg-red-500/10 hover:text-red-300"
                onClick={async () => {
                  try {
                    const res = await fetch(`/api/brand-threats/${id}/rescan`, {
                      method: "POST",
                      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
                    });
                    if (!res.ok) {
                      const body = await res.json().catch(() => ({}));
                      toast({ title: body?.error ?? "Failed to start retry", variant: "destructive" });
                      return;
                    }
                    const newScan = await res.json();
                    toast({ title: "Scan restarted", description: `A fresh scan has been queued for ${newScan.domain ?? s.domain}.` });
                    if (newScan.id && newScan.id !== id) {
                      navigate(`/brand-threats/${newScan.id}`);
                    } else {
                      void refetch();
                    }
                  } catch {
                    toast({ title: "Failed to retry scan", variant: "destructive" });
                  }
                }}
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Retry Scan
              </Button>
            </div>
          </div>
        );
      })()}

      {/* ── Scan History ─────────────────────────────────────────────────────── */}
      {(s.status === "done" || s.status === "error") && (() => {
        const history: any[] = s?.scanHistory ?? [];
        return (
          <div className="mx-6 mt-4 shrink-0">
            <details className="group bg-muted/20 border border-border rounded-xl overflow-hidden">
              <summary className="flex items-center gap-2 px-4 py-2.5 cursor-pointer select-none text-xs font-semibold text-muted-foreground hover:text-foreground transition-colors list-none">
                <History className="w-3.5 h-3.5" />
                Previous Scan Rounds
                {history.length > 0 && (
                  <span className="ml-1 bg-muted text-muted-foreground px-1.5 py-0.5 rounded-full text-[10px] font-bold">{history.length}</span>
                )}
                <ChevronRight className="ml-auto w-3.5 h-3.5 text-muted-foreground/50 group-open:hidden" />
                <ChevronDown className="ml-auto w-3.5 h-3.5 text-muted-foreground/50 hidden group-open:block" />
              </summary>
              <div className="border-t border-border">
                {history.length === 0 ? (
                  <div className="px-4 py-5 flex items-start gap-3">
                    <History className="w-4 h-4 text-muted-foreground/40 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-muted-foreground">No scan history yet</p>
                      <p className="text-[11px] text-muted-foreground/60 mt-0.5 leading-relaxed">
                        Historical comparison data appears here after the second scan of this domain.
                        Each re-scan archives the previous round's results — tracking Registered, High Risk, and Phishing counts over time.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-muted/30">
                          <th className="text-left px-4 py-2 text-muted-foreground font-medium">Scan Round</th>
                          <th className="text-right px-4 py-2 text-muted-foreground font-medium">Total</th>
                          <th className="text-right px-4 py-2 text-muted-foreground font-medium">Registered</th>
                          <th className="text-right px-4 py-2 text-muted-foreground font-medium">High Risk</th>
                          <th className="text-right px-4 py-2 text-muted-foreground font-medium">Phishing</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h: any, i: number) => (
                          <tr key={i} className="border-t border-border/50 hover:bg-muted/20 transition-colors">
                            <td className="px-4 py-2.5">
                              <p className="text-foreground/80 font-medium">{formatDate(h.archivedAt)}</p>
                              <p className="text-[10px] text-muted-foreground/60 mt-0.5">Archived scan round #{history.length - i}</p>
                            </td>
                            <td className="px-4 py-2.5 text-right text-foreground/70 font-mono">{h.total.toLocaleString()}</td>
                            <td className="px-4 py-2.5 text-right">
                              <span className={cn("font-mono font-semibold", h.registered > 0 ? "text-orange-400" : "text-muted-foreground/50")}>
                                {h.registered > 0 ? h.registered : "—"}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-right">
                              <span className={cn("font-mono font-semibold", h.highRisk > 0 ? "text-red-400" : "text-muted-foreground/50")}>
                                {h.highRisk > 0 ? h.highRisk : "—"}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-right">
                              {h.phishing > 0 ? (
                                <span className="inline-flex items-center gap-1 text-red-500 font-bold font-mono">
                                  <Fish className="w-3 h-3" />{h.phishing}
                                </span>
                              ) : (
                                <span className="text-muted-foreground/50 font-mono">—</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </details>
          </div>
        );
      })()}


      {/* ── Watchlist item context banner (non-domain scans) ─────────────────── */}
      {s.watchlistItemType && s.watchlistItemType !== "domain" && s.watchlistItemType !== "subdomain" && s.watchlistItemType !== "url" && (
        <div className="mx-6 mt-4 shrink-0">
          {(() => {
            const typeLabel: Record<string, string> = {
              keyword: "Keyword",
              email: "Email Address",
              social_handle: "Social Handle",
              mobile_app: "Mobile App",
              logo_url: "Logo / Image",
              ip: "IP Address",
            };
            const typeColor: Record<string, string> = {
              keyword: "border-violet-500/30 bg-violet-500/8 text-violet-400",
              email: "border-orange-500/30 bg-orange-500/8 text-orange-400",
              social_handle: "border-pink-500/30 bg-pink-500/8 text-pink-400",
              mobile_app: "border-blue-500/30 bg-blue-500/8 text-blue-400",
              logo_url: "border-cyan-500/30 bg-cyan-500/8 text-cyan-400",
              ip: "border-green-500/30 bg-green-500/8 text-green-400",
            };
            const tabHint: Record<string, string> = {
              keyword: "Results appear in Data Leaks and Social Media tabs.",
              email: "Results appear in the Data Leaks tab.",
              social_handle: "Results appear in the Social Media and Data Leaks tabs.",
              mobile_app: "Results appear in the Mobile Apps tab.",
              logo_url: "Results appear in the Logo & Brand and Malicious Ads tabs.",
            };
            const label = typeLabel[s.watchlistItemType] ?? s.watchlistItemType;
            const colorClass = typeColor[s.watchlistItemType] ?? "border-border bg-muted/30 text-muted-foreground";
            const hint = tabHint[s.watchlistItemType] ?? "";
            return (
              <div className={`flex items-center gap-3 px-4 py-2.5 rounded-xl border text-sm ${colorClass}`}>
                <Shield className="w-4 h-4 shrink-0" />
                <div className="flex-1 min-w-0">
                  <span className="font-semibold">{label} Intelligence Scan</span>
                  {s.watchlistItemValue && (
                    <span className="ml-2 font-mono text-xs opacity-80">{s.watchlistItemValue}</span>
                  )}
                  {hint && <span className="ml-3 text-xs opacity-60">{hint}</span>}
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* ── Tab navigation ──────────────────────────────────────────────────── */}
      {(s.status === "done" || s.status === "error") && (
        <div className="px-6 pt-4 shrink-0">
          <div className="overflow-x-auto pb-1">
            <div className="flex items-center gap-1 bg-muted/30 rounded-xl p-1 w-max min-w-full">
              {TABS.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all whitespace-nowrap shrink-0",
                    activeTab === tab.id
                      ? "bg-card shadow-sm text-foreground border border-border"
                      : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
                  )}
                >
                  <span className={cn(activeTab === tab.id ? "text-primary" : "text-muted-foreground", tab.color && activeTab !== tab.id ? tab.color : "")}>
                    {tab.icon}
                  </span>
                  {tab.label}
                  {tab.count !== undefined && (
                    <span className={cn(
                      "text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center",
                      activeTab === tab.id ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                    )}>
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab content ─────────────────────────────────────────────────────── */}
      <div>

        {/* ── PHISHING tab ── */}
        {activeTab === "phishing" && (s.status === "done" || s.status === "error") && (
          <PhishingTab phishing={phishingDetections} brandAbuse={brandAbuse} confirmedResults={results.filter((r: any) => r.isPhishing)} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── DATA LEAKS tab ── */}
        {activeTab === "data_leaks" && (s.status === "done" || s.status === "error") && (
          <DataLeaksTab leaks={dataLeaks} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── SUSPICIOUS CERTS tab ── */}
        {activeTab === "suspicious_certs" && (s.status === "done" || s.status === "error") && (
          <SuspiciousCertsTab abuse={brandAbuse} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── SOCIAL MEDIA tab ── */}
        {activeTab === "social_media" && (s.status === "done" || s.status === "error") && (
          <SocialMediaTab abuse={brandAbuse} warnings={Array.isArray(s.scanWarnings) ? (s.scanWarnings as ScanWarning[]) : undefined} scanDomain={s.domain} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── MOBILE APPS tab ── */}
        {activeTab === "mobile_apps" && (s.status === "done" || s.status === "error") && (
          <MobileAppsTab abuse={brandAbuse} warnings={Array.isArray(s.scanWarnings) ? (s.scanWarnings as ScanWarning[]) : undefined} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── MALICIOUS ADS tab ── */}
        {activeTab === "malicious_ads" && (s.status === "done" || s.status === "error") && (
          <MaliciousAdsTab ads={adMonitoringResults} adLibraryLinks={adLibraryLinks} hasMetaToken={s.metaAdsChecked ?? undefined} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── LOGO & BRAND tab ── */}
        {activeTab === "logo_brand" && (s.status === "done" || s.status === "error") && (
          <LogoBrandTab abuse={brandAbuse} scanId={id} falsePositives={falsePositives} onFpCreated={refreshFalsePositives} />
        )}

        {/* ── TAKEDOWNS tab ── */}
        {activeTab === "takedowns" && (s.status === "done" || s.status === "error") && (
          <TakedownsTab scanId={Number(id)} scanDomain={s.domain} results={results} />
        )}

        {/* ── WATCHLIST tab ── */}
        {activeTab === "watchlist" && (
          <div className="p-5">
            <WatchlistDetailTab
              items={allWatchlistItems}
              scanDomain={s.domain ?? ""}
              brandAbuse={brandAbuse}
              dataLeaks={dataLeaks}
              adMonitoringResults={adMonitoringResults}
              watchlistItemType={s.watchlistItemType ?? undefined}
              watchlistItemValue={s.watchlistItemValue ?? undefined}
            />
          </div>
        )}

        {/* ── FAVICON CLONES tab ── */}
        {activeTab === "favicon_clones" && (
          <div className="p-6 space-y-6">
            {/* Favicon identity card */}
            {s.faviconMd5 ? (
              <>
                <div className="flex items-start gap-6 p-5 bg-violet-500/5 border border-violet-500/20 rounded-xl">
                  <div className="shrink-0 flex flex-col items-center gap-2">
                    <div className="w-16 h-16 rounded-xl border border-border bg-background flex items-center justify-center overflow-hidden">
                      {s.faviconUrl
                        ? <img src={s.faviconUrl} alt="favicon" className="w-14 h-14 object-contain" onError={e => { (e.target as HTMLImageElement).style.display = "none"; }} />
                        : <Fingerprint className="w-8 h-8 text-violet-400/40" />
                      }
                    </div>
                    <span className="text-[9px] text-muted-foreground font-mono">favicon.ico</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-3">
                      <Fingerprint className="w-4 h-4 text-violet-400 shrink-0" />
                      <span className="text-sm font-semibold text-violet-300">Favicon Fingerprint</span>
                      <span className="text-[10px] text-violet-400/60 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-mono">powered by favihunter</span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                      {s.faviconMmh3 && <HashChip label="MMH3 (Shodan / FOFA)" value={String(s.faviconMmh3)} />}
                      {s.faviconMmh3Hex && <HashChip label="MMH3-HEX (Criminal IP)" value={s.faviconMmh3Hex} />}
                      {s.faviconMd5 && <HashChip label="MD5 (Censys / Hunter-How / ODIN)" value={s.faviconMd5} />}
                      {s.faviconSha256 && <HashChip label="SHA256 (Netlas)" value={s.faviconSha256} />}
                    </div>
                  </div>
                </div>

                {/* Search engine pivot links */}
                {s.faviconSearchUrls && Object.keys(s.faviconSearchUrls as object).filter(k => k !== "_error").length > 0 && (
                  <div className="border border-border rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                      <Search className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-semibold">Search Engine Pivots</span>
                      <span className="text-xs text-muted-foreground ml-1">— find hosts using the same favicon fingerprint</span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(s.faviconSearchUrls as Record<string, { url: string; hash_type: string }>)
                        .filter(([k]) => k !== "_error")
                        .map(([name, { url, hash_type }]) => {
                          const meta = ENGINE_META[name] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
                          return (
                            <a key={name} href={url} target="_blank" rel="noopener noreferrer"
                              className={cn("flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm font-medium transition-all hover:scale-105 hover:shadow-sm", meta.color, meta.bg, meta.border)}
                              title={`Search ${name} using ${hash_type} hash`}
                            >
                              {name} <ExternalLink className="w-3.5 h-3.5 opacity-60" />
                            </a>
                          );
                        })}
                    </div>
                    <p className="text-[10px] text-muted-foreground/50 mt-3">
                      These links search each engine for infrastructure sharing the same favicon — a reliable indicator of phishing clones and related threat actors.
                    </p>
                  </div>
                )}

                {/* Shodan detected clone hosts */}
                {(s.faviconShodanMatches as any[] | null)?.length ? (
                  <div className="border border-red-500/20 rounded-xl p-5 bg-red-500/3">
                    <div className="flex items-center gap-2 mb-4">
                      <Server className="w-4 h-4 text-red-400" />
                      <span className="text-sm font-semibold text-red-300">Shodan-Detected Clone Hosts</span>
                      <span className="ml-1 text-xs font-bold bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded-full">
                        {(s.faviconShodanMatches as any[]).length} host{(s.faviconShodanMatches as any[]).length !== 1 ? "s" : ""}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground/70 mb-4">
                      These IPs were found by Shodan using the same favicon hash as <strong className="text-foreground">{s.domain}</strong>. They may be phishing infrastructure, CDN mirror origins, or brand clones.
                    </p>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                      {(s.faviconShodanMatches as any[]).map((m: any, i: number) => (
                        <div key={i} className="flex items-start gap-3 bg-background/60 border border-red-500/20 rounded-lg p-3 hover:border-red-500/40 transition-colors">
                          <Server className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                          <div className="min-w-0 flex-1 space-y-0.5">
                            <p className="text-xs font-mono font-semibold truncate">{m.ip_str ?? m.ip ?? m.hostname ?? "unknown"}</p>
                            {m.hostnames?.length > 0 && <p className="text-[11px] text-muted-foreground truncate">{m.hostnames[0]}</p>}
                            {(m.org || m.isp) && <p className="text-[11px] text-muted-foreground/60 truncate">{m.org ?? m.isp}</p>}
                            {m.port && <p className="text-[11px] text-muted-foreground/50">Port {m.port}</p>}
                          </div>
                          {m.country_code && (
                            <span className="text-[10px] font-bold text-muted-foreground bg-muted px-1.5 py-0.5 rounded-sm shrink-0">{m.country_code}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="border border-border rounded-xl p-6 text-center">
                    <Server className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
                    <p className="text-sm text-muted-foreground">No Shodan clone hosts detected</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      Either no hosts share this favicon hash, or a Shodan API key has not been configured.
                    </p>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-64 gap-3">
                <Fingerprint className="w-12 h-12 text-muted-foreground/20" />
                <p className="text-muted-foreground">
                  {s.favihunterStatus === "error"
                    ? `Favicon intelligence unavailable: ${s.favihunterError ?? "unknown error"}`
                    : s.favihunterStatus === "running" || s.favihunterStatus === "pending"
                    ? "Favicon analysis in progress…"
                    : "No favicon found for this domain."}
                </p>
              </div>
            )}
          </div>
        )}

        {/* ── SUBDOMAINS tab ── */}
        {activeTab === "subdomains" && (s.status === "done" || s.status === "error") && (
          <SubdomainsTab subdomains={pipelineSubdomains} pipelineScanId={s.pipelineScanId as number} scanDomain={s.domain} subdomainThreats={(s as any).subdomainThreats ?? []} />
        )}

        {/* ── TYPOSQUATTING tab ── */}
        {(activeTab === "typosquatting" || (s.status !== "done" && s.status !== "error")) && results.length > 0 && (
          <div className="flex flex-col">

            {/* ── Top filter toolbar ── */}
            <div className="shrink-0 border-b border-border bg-card/30">
              {/* Filter chips + controls row */}
              <div className="px-5 py-3 flex flex-wrap items-center gap-2">
                {([
                  { key: "all",        label: "All",             count: results.length,        icon: <Eye className="w-3 h-3" /> },
                  { key: "live",       label: "Live (DNS)",      count: liveResults.length,    icon: <Server className="w-3 h-3" /> },
                  { key: "mx",         label: "Has MX",          count: mxResults.length,      icon: <Mail className="w-3 h-3" /> },
                  { key: "suspicious", label: "Suspicious",      count: suspResults.length,    icon: <AlertTriangle className="w-3 h-3" /> },
                  { key: "phishing",   label: "Phishing",        count: phishResults.length,   icon: <Fish className="w-3 h-3" /> },
                ] as const).map(({ key, label, count, icon }) => (
                  <button
                    key={key}
                    onClick={() => { setFilter(key); setPage(0); }}
                    className={cn(
                      "inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all whitespace-nowrap",
                      filter === key
                        ? "bg-primary/10 text-primary border-primary/30"
                        : "text-muted-foreground border-border hover:bg-muted/50 hover:text-foreground",
                    )}
                  >
                    {icon}
                    {label}
                    <span className={cn(
                      "text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[20px] text-center",
                      filter === key ? "bg-primary/20 text-primary" : "bg-muted/60 text-muted-foreground",
                    )}>
                      {count}
                    </span>
                  </button>
                ))}
                <div className="w-px h-5 bg-border mx-0.5" />
                <select
                  value={fuzzerFilter}
                  onChange={e => { setFuzzerFilter(e.target.value); setPage(0); }}
                  className="bg-background border border-border rounded-lg px-2.5 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40 h-7"
                >
                  <option value="all">All mutation types</option>
                  {Array.from(new Set(results.map((r: any) => r.fuzzer))).sort().map((f: string) => (
                    <option key={f} value={f}>{FUZZER_META[f]?.label ?? f}</option>
                  ))}
                </select>
                <div className="flex-1 min-w-0" />
                <div className="relative">
                  <input
                    type="text"
                    placeholder="Search domains…"
                    value={search}
                    onChange={e => { setSearch(e.target.value); setPage(0); }}
                    className="bg-background border border-border rounded-lg pl-8 pr-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40 w-52 h-7"
                  />
                  <Activity className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/50 pointer-events-none" />
                </div>
              </div>
              {/* Stats strip */}
              <div className="px-5 pb-2.5 flex items-center gap-5 text-xs text-muted-foreground flex-wrap">
                <span>
                  <span className="font-semibold text-foreground">{filtered.length}</span> of <span className="font-semibold text-foreground">{results.length}</span> permutations shown
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                  <span className="font-semibold text-red-400">{liveResults.length}</span> live
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0" />
                  <span className="font-semibold text-orange-400">{suspResults.length}</span> suspicious
                </span>
                {phishResults.length > 0 && (
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500 shrink-0" />
                    <span className="font-semibold text-red-400">{phishResults.length}</span> confirmed phishing
                  </span>
                )}
                {mxResults.length > 0 && (
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0" />
                    <span className="font-semibold text-yellow-400">{mxResults.length}</span> with mail server
                  </span>
                )}
              </div>
            </div>

            {/* ── Results area ── */}
            <div>
              {(() => {
                const registered = filtered.filter((r: any) =>
                  r.registrationStatus === "registered" ||
                  r.registrationStatus === "active" ||
                  r.registrationStatus === "parked" ||
                  r.registrationStatus === "protected"
                );
                const unregistered = filtered.filter((r: any) =>
                  !r.registrationStatus ||
                  r.registrationStatus === "unregistered" ||
                  r.registrationStatus === "unresolved"
                );

                const COLS = "grid-cols-[32px_minmax(0,1fr)_140px_130px_64px_64px_100px_130px_90px]";

                function PermRow({ r }: { r: any }) {
                  const fm = FUZZER_META[r.fuzzer];
                  const isExpanded = expandedId === r.id;
                  const existingFp = falsePositives.find(fp => fp.item_type === "permutation" && fp.item_ref === r.permutation);
                  return (
                    <div>
                      <div
                        className={cn(
                          `grid ${COLS} items-center px-5 py-3 hover:bg-muted/20 transition-colors cursor-pointer border-b border-border/40 last:border-0`,
                          r.isSuspicious && "bg-orange-500/[0.03]",
                          r.isPhishing && "bg-red-500/[0.04]",
                          existingFp?.status === "confirmed" && "opacity-50",
                        )}
                        onClick={() => setExpandedId(isExpanded ? null : r.id)}
                      >
                        {/* Status icon */}
                        <div className="flex items-center justify-center">
                          {r.isPhishing
                            ? <Fish className="w-3.5 h-3.5 text-red-400" />
                            : r.isSuspicious
                            ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                            : <CheckCircle2 className="w-3.5 h-3.5 text-muted-foreground/15" />
                          }
                        </div>
                        {/* Domain name */}
                        <div className="flex items-center gap-2 min-w-0 pr-3">
                          <span className="text-sm font-mono truncate text-foreground/90">{r.permutation}</span>
                          {r.isNew && (
                            <span className="shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-blue-500/15 border border-blue-500/25 text-blue-400 uppercase tracking-wide">
                              New
                            </span>
                          )}
                          {isExpanded
                            ? <ChevronUp className="w-3 h-3 text-muted-foreground/30 shrink-0 ml-auto" />
                            : <ChevronDown className="w-3 h-3 text-muted-foreground/20 shrink-0 ml-auto" />
                          }
                        </div>
                        {/* Mutation type badge */}
                        <div className="flex justify-center">
                          <span className={cn("text-[10px] px-2.5 py-1 rounded-full font-medium whitespace-nowrap", fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted")}>
                            {fm?.label ?? r.fuzzer}
                          </span>
                        </div>
                        {/* A record IP */}
                        <div className="flex items-center justify-center">
                          {r.dnsA?.length > 0 ? (
                            <span className="flex items-center gap-1 text-[11px] text-red-400 font-mono font-medium">
                              <Server className="w-2.5 h-2.5 shrink-0" />
                              <span className="truncate max-w-[80px]">{r.dnsA[0]}</span>
                            </span>
                          ) : <span className="text-xs text-muted-foreground/25">—</span>}
                        </div>
                        {/* NS */}
                        <div className="flex justify-center">
                          {r.dnsNs?.length > 0
                            ? <span className="text-[10px] text-blue-400 font-semibold bg-blue-500/10 px-1.5 py-0.5 rounded">NS</span>
                            : <span className="text-xs text-muted-foreground/25">—</span>}
                        </div>
                        {/* MX */}
                        <div className="flex justify-center">
                          {r.dnsMx?.length > 0 ? (
                            <span className="flex items-center gap-1 text-[10px] text-orange-400 font-semibold bg-orange-500/10 px-1.5 py-0.5 rounded">
                              <Mail className="w-2.5 h-2.5" /> MX
                            </span>
                          ) : <span className="text-xs text-muted-foreground/25">—</span>}
                        </div>
                        {/* VirusTotal */}
                        <div className="flex justify-center">
                          {r.vtMalicious > 0 ? (
                            <span className="inline-flex items-center gap-1 text-[11px] text-red-400 font-bold bg-red-500/10 px-2 py-0.5 rounded-full">
                              <ShieldAlert className="w-3 h-3 shrink-0" />{r.vtMalicious}
                            </span>
                          ) : r.vtMalicious === 0 ? (
                            <span className="text-[10px] text-green-400/60 font-medium">clean</span>
                          ) : <span className="text-xs text-muted-foreground/25">—</span>}
                        </div>
                        {/* Risk score bar */}
                        <div className="px-2">
                          <RiskScoreBar score={r.riskScore} />
                        </div>
                        {/* FP + severity */}
                        <div className="flex flex-col justify-center items-center gap-1.5" onClick={e => e.stopPropagation()}>
                          <SeverityPill
                            risk={(r.riskScore ?? 0) >= 80 ? "critical" : (r.riskScore ?? 0) >= 60 ? "high" : (r.riskScore ?? 0) >= 40 ? "medium" : "low"}
                            onPatch={async (nr) => { await apiFetch(`/api/brand-threats/results/${r.id}/risk`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ risk: nr }) }); }}
                          />
                          <TakedownButton prefill={{ type: "domain_squatting", targetUrl: `https://${r.permutation}`, targetDomain: r.permutation, registrar: r.whoisRegistrar ?? undefined, title: `Typosquatting Domain: ${r.permutation}`, description: r.whoisRegistrar ? `Registrar: ${r.whoisRegistrar}` : undefined, priority: (r.riskScore ?? 0) >= 80 ? "critical" : (r.riskScore ?? 0) >= 60 ? "high" : "medium" }} />
                          <FalsePositiveButton scanId={id} itemType="permutation" itemRef={r.permutation} existingFp={existingFp} onCreated={refreshFalsePositives} />
                        </div>
                      </div>

                      {/* Expanded detail panel */}
                      {isExpanded && (
                        <div className="bg-muted/10 border-b border-border px-8 py-5">
                          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6 text-xs">
                            <div>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-2.5">DNS Records</p>
                              <div className="space-y-1.5">
                                {r.dnsA?.length > 0 && r.dnsA.map((ip: string) => (
                                  <div key={ip} className="flex items-center gap-1.5">
                                    <Server className="w-3 h-3 text-red-400 shrink-0" />
                                    <span className="font-mono text-foreground/80">{ip}</span>
                                    {r.geoCountry && r.dnsA[0] === ip && <span className="text-muted-foreground/50 ml-1">({r.geoCountry})</span>}
                                  </div>
                                ))}
                                {r.dnsNs?.length > 0 && r.dnsNs.slice(0, 2).map((ns: string) => (
                                  <div key={ns} className="flex items-center gap-1.5">
                                    <Globe className="w-3 h-3 text-blue-400/60 shrink-0" />
                                    <span className="font-mono text-muted-foreground/70 truncate">{ns}</span>
                                  </div>
                                ))}
                                {r.dnsMx?.length > 0 && r.dnsMx.slice(0, 2).map((mx: string) => (
                                  <div key={mx} className="flex items-center gap-1.5">
                                    <Mail className="w-3 h-3 text-orange-400/60 shrink-0" />
                                    <span className="font-mono text-muted-foreground/70 truncate">{mx}</span>
                                  </div>
                                ))}
                                {!r.dnsA?.length && !r.dnsNs?.length && !r.dnsMx?.length && <p className="text-muted-foreground/40 italic">No DNS records</p>}
                              </div>
                            </div>
                            <div>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-2.5">RDAP / WHOIS</p>
                              {r.whoisRegistrar || r.whoisCreated || r.whoisRegistrantOrg || r.whoisExpires || r.whoisUpdated ? (
                                <div className="space-y-1.5">
                                  {r.whoisRegistrar && <p className="flex items-start gap-1.5"><Building2 className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" /><span className="text-muted-foreground/80 break-words">{r.whoisRegistrar}</span></p>}
                                  {r.whoisRegistrantOrg && <p className="flex items-start gap-1.5"><Tag className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" /><span className="text-muted-foreground/80 break-words">{r.whoisRegistrantOrg}</span></p>}
                                  {r.whoisCreated && <p className="flex items-center gap-1.5"><Calendar className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">Created {r.whoisCreated?.slice(0, 10)}</span></p>}
                                  {r.whoisExpires && <p className="flex items-center gap-1.5"><Clock className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">Expires {r.whoisExpires?.slice(0, 10)}</span></p>}
                                  {r.whoisUpdated && <p className="flex items-center gap-1.5"><RotateCw className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">Updated {r.whoisUpdated?.slice(0, 10)}</span></p>}
                                  {r.whoisCountry && <p className="flex items-center gap-1.5"><MapPin className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">{r.whoisCountry}</span></p>}
                                  {r.whoisAbuseContact && <p className="flex items-center gap-1.5 break-all"><Mail className="w-3 h-3 text-muted-foreground shrink-0" /><a href={`mailto:${r.whoisAbuseContact}`} className="text-primary hover:underline">{r.whoisAbuseContact}</a></p>}
                                  {r.whoisAgeDays !== null && r.whoisAgeDays !== undefined && (
                                    <p className={cn("flex items-center gap-1.5", r.whoisAgeDays < 90 ? "text-red-400 font-medium" : "text-muted-foreground/80")}>
                                      <Info className="w-3 h-3 shrink-0" />
                                      {r.whoisAgeDays < 90 ? `⚠ New domain (${r.whoisAgeDays}d old)` : `${r.whoisAgeDays}d old`}
                                    </p>
                                  )}
                                </div>
                              ) : <p className="text-muted-foreground/40 italic">Not resolved</p>}
                            </div>
                            <div>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-2.5">GeoIP</p>
                              {r.geoCountry || r.geoOrg ? (
                                <div className="space-y-1.5">
                                  {r.geoCountry && <p className="flex items-center gap-1.5"><MapPin className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">{r.geoCity ? `${r.geoCity}, ` : ""}{r.geoCountry}</span></p>}
                                  {r.geoAsn && <p className="flex items-center gap-1.5"><Globe className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">{r.geoAsn}</span></p>}
                                  {r.geoOrg && <p className="flex items-center gap-1.5"><Building2 className="w-3 h-3 text-muted-foreground shrink-0" /><span className="text-muted-foreground/80">{r.geoOrg.slice(0, 30)}{r.geoOrg.length > 30 ? "…" : ""}</span></p>}
                                </div>
                              ) : <p className="text-muted-foreground/40 italic">Not resolved</p>}
                            </div>
                            <div>
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-2.5">Threat Intel</p>
                              <div className="space-y-1.5">
                                {r.isPhishing && <div className="flex items-center gap-1.5 text-red-400 font-medium"><Fish className="w-3 h-3 shrink-0" /><span>Confirmed phishing ({r.phishingSource})</span></div>}
                                {r.vtMalicious !== null && r.vtMalicious !== undefined && (
                                  <div className={cn("flex items-center gap-1.5", r.vtMalicious > 0 ? "text-red-400" : "text-green-400/70")}>
                                    <ShieldAlert className="w-3 h-3 shrink-0" />
                                    <span>VT: {r.vtMalicious} malicious / {r.vtSuspicious ?? 0} suspicious</span>
                                  </div>
                                )}
                                {r.vtPermalink && (
                                  <a href={r.vtPermalink} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors">
                                    <ExternalLink className="w-3 h-3" /> VirusTotal report
                                  </a>
                                )}
                                {!r.isPhishing && (r.vtMalicious === null || r.vtMalicious === undefined) && <p className="text-muted-foreground/40 italic">No threat data</p>}
                              </div>
                            </div>
                          </div>
                          {r.screenshot && (
                            <div className="mt-5 pt-4 border-t border-border/40">
                              <p className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold mb-2.5 flex items-center gap-1.5">
                                <Eye className="w-3 h-3" /> Live Screenshot
                                <span className="text-[9px] text-orange-400/60 font-normal">(captured at scan time)</span>
                              </p>
                              <div className="rounded-xl overflow-hidden border border-border max-w-lg shadow-sm">
                                <img
                                  src={`data:image/png;base64,${r.screenshot}`}
                                  alt={`Screenshot of ${r.permutation}`}
                                  className="w-full object-cover"
                                  loading="lazy"
                                />
                              </div>
                              <p className="text-[10px] text-muted-foreground/40 mt-2 font-mono">{r.permutation}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                }

                const REG_HEADER = (
                  <div className={`grid ${COLS} items-center px-5 py-2.5 border-b border-border bg-muted/20 text-[10px] text-muted-foreground uppercase tracking-wider font-semibold`}>
                    <span />
                    <span>Domain</span>
                    <span className="text-center">Mutation Type</span>
                    <span className="text-center">IP Address</span>
                    <span className="text-center">NS</span>
                    <span className="text-center">MX</span>
                    <span className="text-center">VirusTotal</span>
                    <span className="text-center">Risk Score</span>
                    <span className="text-center">Action</span>
                  </div>
                );

                const activeThreats = registered.filter((r: any) => r.riskScore >= 70);
                const underWatch = registered.filter((r: any) => r.riskScore >= 40 && r.riskScore < 70);
                const lowRisk = registered.filter((r: any) => r.riskScore < 40);

                return (
                  <div>
                    {/* ── Active Threats (score ≥ 70) ── */}
                    <div>
                      <div className="px-5 py-3 bg-red-500/[0.04] border-b border-red-500/15 flex items-center gap-2.5">
                        <div className="w-2 h-2 rounded-full bg-red-400 shrink-0 shadow-[0_0_6px_rgba(248,113,113,0.6)]" />
                        <span className="text-xs font-bold text-red-400 uppercase tracking-wider">Active Threats</span>
                        <span className="text-[10px] text-red-400/70 bg-red-500/10 px-2 py-0.5 rounded-full font-bold border border-red-500/20">
                          {activeThreats.length}
                        </span>
                        <span className="text-[10px] text-muted-foreground/60 ml-1 hidden sm:inline">risk score ≥ 70</span>
                      </div>

                      {activeThreats.length > 0 ? (
                        <>
                          {REG_HEADER}
                          <div>
                            {activeThreats.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE).map((r: any) => <PermRow key={r.id} r={r} />)}
                          </div>
                        </>
                      ) : (
                        <div className="flex items-center gap-2.5 px-5 py-5 text-sm text-green-400/70">
                          <CheckCircle2 className="w-4 h-4 shrink-0" /> No active threats found — good signal
                        </div>
                      )}
                    </div>

                    {/* ── Under Watch (score 40–69) ── */}
                    {underWatch.length > 0 && (
                      <div>
                        <div className="px-5 py-3 bg-orange-500/[0.03] border-b border-orange-500/15 flex items-center gap-2.5">
                          <div className="w-2 h-2 rounded-full bg-orange-400 shrink-0" />
                          <span className="text-xs font-bold text-orange-400 uppercase tracking-wider">Under Watch</span>
                          <span className="text-[10px] text-orange-400/70 bg-orange-500/10 px-2 py-0.5 rounded-full font-bold border border-orange-500/20">{underWatch.length}</span>
                          <span className="text-[10px] text-muted-foreground/60 ml-1 hidden sm:inline">risk score 40–69, suspicious but not confirmed</span>
                        </div>
                        {REG_HEADER}
                        <div>
                          {underWatch.map((r: any) => <PermRow key={r.id} r={r} />)}
                        </div>
                      </div>
                    )}

                    {/* ── Low Risk Registered ── */}
                    {lowRisk.length > 0 && (
                      <div>
                        <div className="px-5 py-3 bg-muted/10 border-b border-border flex items-center gap-2.5">
                          <div className="w-2 h-2 rounded-full bg-muted-foreground/40 shrink-0" />
                          <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Registered / Low Risk</span>
                          <span className="text-[10px] text-muted-foreground/60 bg-muted/60 px-2 py-0.5 rounded-full font-bold">{lowRisk.length}</span>
                          <span className="text-[10px] text-muted-foreground/50 ml-1 hidden sm:inline">registered but below suspicion threshold</span>
                        </div>
                        {REG_HEADER}
                        <div>
                          {lowRisk.map((r: any) => <PermRow key={r.id} r={r} />)}
                        </div>
                      </div>
                    )}

                    {registered.length === 0 && (
                      <div className="flex items-center gap-2.5 px-5 py-5 text-sm text-green-400/70">
                        <CheckCircle2 className="w-4 h-4 shrink-0" /> No registered permutations found — good signal
                      </div>
                    )}

                    {/* ── Unregistered / Unresolved ── */}
                    {unregistered.length > 0 && (
                      <div>
                        <div className="px-5 py-3 bg-muted/5 border-b border-border flex items-center gap-2.5">
                          <div className="w-2 h-2 rounded-full bg-muted-foreground/25 shrink-0" />
                          <span className="text-xs font-bold text-muted-foreground/70 uppercase tracking-wider">Unregistered / Unresolved</span>
                          <span className="text-[10px] text-muted-foreground/50 bg-muted/40 px-2 py-0.5 rounded-full font-bold">{unregistered.length}</span>
                          <span className="text-[10px] text-muted-foreground/40 ml-1 hidden sm:inline">available to register — monitor for future squatting</span>
                        </div>
                        <div className="grid grid-cols-[32px_minmax(0,1fr)_140px_130px_64px_64px] items-center px-5 py-2.5 border-b border-border bg-muted/10 text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                          <span /><span>Domain</span>
                          <span className="text-center">Mutation Type</span>
                          <span className="text-center">IP Address</span>
                          <span className="text-center">NS</span>
                          <span className="text-center">MX</span>
                        </div>
                        <div>
                          {unregistered.slice(0, 150).map((r: any) => {
                            const fm = FUZZER_META[r.fuzzer];
                            return (
                              <div key={r.id} className="grid grid-cols-[32px_minmax(0,1fr)_140px_130px_64px_64px] items-center px-5 py-2.5 hover:bg-muted/10 transition-colors border-b border-border/30 last:border-0 text-xs">
                                <span />
                                <div className="flex items-center gap-2 min-w-0 pr-3">
                                  <span className="text-sm font-mono text-muted-foreground/70 truncate">{r.permutation}</span>
                                  {r.isNew && (
                                    <span className="shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded-full bg-blue-500/15 border border-blue-500/25 text-blue-400 uppercase tracking-wide">
                                      New
                                    </span>
                                  )}
                                </div>
                                <div className="flex justify-center">
                                  <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium opacity-70", fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted")}>
                                    {fm?.label ?? r.fuzzer}
                                  </span>
                                </div>
                                <div className="flex justify-center">
                                  {r.dnsA?.length > 0 ? <span className="text-[11px] text-red-400/60 font-mono">{r.dnsA[0]?.slice(0, 15)}</span> : <span className="text-muted-foreground/20">—</span>}
                                </div>
                                <div className="flex justify-center">
                                  {r.dnsNs?.length > 0 ? <span className="text-[10px] text-blue-400/50 font-semibold">NS</span> : <span className="text-muted-foreground/20">—</span>}
                                </div>
                                <div className="flex justify-center">
                                  {r.dnsMx?.length > 0 ? <span className="text-[10px] text-orange-400/50 font-semibold">MX</span> : <span className="text-muted-foreground/20">—</span>}
                                </div>
                              </div>
                            );
                          })}
                          {unregistered.length > 150 && (
                            <div className="px-5 py-3 text-xs text-muted-foreground/50 text-center border-t border-border/30">
                              Showing 150 of {unregistered.length} unregistered domains — use filters to narrow results
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {filtered.length === 0 && (
                      <div className="flex flex-col items-center justify-center h-48 text-center">
                        <Globe className="w-8 h-8 text-muted-foreground/20 mb-3" />
                        <p className="text-sm font-medium text-muted-foreground">No results match the current filters</p>
                        <button
                          onClick={() => { setFilter("all"); setFuzzerFilter("all"); setSearch(""); }}
                          className="mt-2 text-xs text-primary hover:underline"
                        >
                          Clear all filters
                        </button>
                      </div>
                    )}
                  </div>
                );
              })()}
            </div>

            {/* ── Pagination ── */}
            {totalPages > 1 && (() => {
              const showSet = new Set(
                [0, 1, totalPages - 2, totalPages - 1, page - 1, page, page + 1]
                  .filter(p => p >= 0 && p < totalPages)
              );
              const pageList = [...showSet].sort((a, b) => a - b);
              const items: (number | "…")[] = [];
              for (let i = 0; i < pageList.length; i++) {
                if (i > 0 && pageList[i]! - pageList[i - 1]! > 1) items.push("…");
                items.push(pageList[i]!);
              }
              return (
                <div className="shrink-0 flex items-center justify-between px-5 py-3 border-t border-border bg-card/30">
                  <span className="text-xs text-muted-foreground">
                    Page <span className="font-semibold text-foreground">{page + 1}</span> of <span className="font-semibold text-foreground">{totalPages}</span>
                    <span className="text-muted-foreground/60 ml-2">({filtered.length} registered domains)</span>
                  </span>
                  <div className="flex items-center gap-1.5">
                    <Button variant="outline" size="sm" onClick={() => setPage(0)} disabled={page === 0} className="h-7 px-2 text-xs" title="First page">«</Button>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="h-7 px-2.5 text-xs">‹</Button>
                    <div className="flex items-center gap-0.5">
                      {items.map((item, i) =>
                        item === "…" ? (
                          <span key={`ellipsis-${i}`} className="w-7 h-7 flex items-center justify-center text-xs text-muted-foreground/40 select-none">…</span>
                        ) : (
                          <button
                            key={item}
                            onClick={() => setPage(item as number)}
                            className={cn(
                              "w-7 h-7 rounded text-xs font-medium transition-all",
                              item === page ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:bg-muted/60",
                            )}
                          >
                            {(item as number) + 1}
                          </button>
                        )
                      )}
                    </div>
                    <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="h-7 px-2.5 text-xs">›</Button>
                    <Button variant="outline" size="sm" onClick={() => setPage(totalPages - 1)} disabled={page >= totalPages - 1} className="h-7 px-2 text-xs" title="Last page">»</Button>
                  </div>
                </div>
              );
            })()}
          </div>
        )}

        {/* Empty state for typosquatting tab */}
        {activeTab === "typosquatting" && results.length === 0 && s.status === "done" && (
          <div className="flex flex-col items-center justify-center h-64 text-center">
            <Globe className="w-8 h-8 text-green-400/40 mb-3" />
            <p className="text-base font-semibold text-green-400">No permutations found</p>
            <p className="text-sm text-muted-foreground">No domain permutations were generated for this scan.</p>
          </div>
        )}
      </div>
    </div>
  );
}
