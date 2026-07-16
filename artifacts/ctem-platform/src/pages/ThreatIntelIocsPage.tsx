import { useState, useRef, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Crosshair, Plus, Trash2, Search, Loader2, X, RefreshCw,
  Download, ChevronRight, Globe, Clock, Shield, Tag, Pencil,
  Check, ChevronDown, Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const IOC_TYPES = ["ip","domain","url","hash","email","cidr","ipv6","asn","cve","filename","registry","mutex","ja3","bitcoin"];
const SEVERITIES = ["critical","high","medium","low"] as const;
const TLP_LEVELS = ["white","green","amber","red"] as const;
const EXPLOIT_STATUSES = ["unknown","none","poc","active","weaponized"] as const;

const SEV_CLASSES: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/25",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/25",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  low:      "text-green-400 bg-green-500/10 border-green-500/25",
};
const TLP_CLASSES: Record<string, string> = {
  white: "text-gray-300 bg-gray-500/10 border-gray-500/25",
  green: "text-green-400 bg-green-500/10 border-green-500/25",
  amber: "text-amber-400 bg-amber-500/10 border-amber-500/25",
  red:   "text-red-400 bg-red-500/10 border-red-500/25",
};

/* ── Form state ─────────────────────────────────────────────────────────── */
type IocForm = {
  type: string; value: string; source: string; sourceUrl: string;
  severity: string; tlp: string; threatScore: string; confidence: string;
  firstSeen: string; lastSeen: string; expiresAt: string;
  country: string; asn: string; exploitationStatus: string;
  tags: string; malwareFamilies: string; threatActors: string; campaigns: string;
  description: string; isActive: boolean;
};

const EMPTY_FORM: IocForm = {
  type: "ip", value: "", source: "manual", sourceUrl: "",
  severity: "medium", tlp: "white", threatScore: "0", confidence: "50",
  firstSeen: "", lastSeen: "", expiresAt: "",
  country: "", asn: "", exploitationStatus: "unknown",
  tags: "", malwareFamilies: "", threatActors: "", campaigns: "",
  description: "", isActive: true,
};

function iocToForm(ioc: any): IocForm {
  const toLocal = (d: string | null) => d ? new Date(d).toISOString().slice(0, 16) : "";
  return {
    type: ioc.type ?? "ip",
    value: ioc.value ?? "",
    source: ioc.source ?? "manual",
    sourceUrl: ioc.sourceUrl ?? "",
    severity: ioc.severity ?? "medium",
    tlp: ioc.tlp ?? "white",
    threatScore: String(Math.round(ioc.threatScore ?? 0)),
    confidence: String(ioc.confidence ?? 50),
    firstSeen: toLocal(ioc.firstSeen),
    lastSeen: toLocal(ioc.lastSeen),
    expiresAt: toLocal(ioc.expiresAt),
    country: ioc.country ?? "",
    asn: ioc.asn ?? "",
    exploitationStatus: ioc.exploitationStatus ?? "unknown",
    tags: Array.isArray(ioc.tags) ? ioc.tags.join(", ") : "",
    malwareFamilies: Array.isArray(ioc.malwareFamilies) ? ioc.malwareFamilies.join(", ") : "",
    threatActors: Array.isArray(ioc.threatActors) ? ioc.threatActors.join(", ") : "",
    campaigns: Array.isArray(ioc.campaigns) ? ioc.campaigns.join(", ") : "",
    description: ioc.description ?? "",
    isActive: ioc.isActive !== false,
  };
}

function formToPayload(f: IocForm) {
  const split = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  return {
    type: f.type,
    value: f.value.trim(),
    source: f.source.trim() || "manual",
    sourceUrl: f.sourceUrl.trim() || null,
    severity: f.severity,
    tlp: f.tlp,
    threatScore: Math.max(0, Math.min(100, Number(f.threatScore) || 0)),
    confidence: Math.max(0, Math.min(100, Number(f.confidence) || 50)),
    firstSeen: f.firstSeen || undefined,
    lastSeen: f.lastSeen || undefined,
    expiresAt: f.expiresAt || null,
    country: f.country.trim() || null,
    asn: f.asn.trim() || null,
    exploitationStatus: f.exploitationStatus,
    tags: split(f.tags),
    malwareFamilies: split(f.malwareFamilies),
    threatActors: split(f.threatActors),
    campaigns: split(f.campaigns),
    description: f.description.trim() || null,
    isActive: f.isActive,
  };
}

/* ── Shared form fields ─────────────────────────────────────────────────── */
function IocFormFields({ f, setF }: { f: IocForm; setF: React.Dispatch<React.SetStateAction<IocForm>> }) {
  const txt = (key: keyof IocForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setF(x => ({ ...x, [key]: e.target.value }));
  const sel = (key: keyof IocForm) => (v: string) => setF(x => ({ ...x, [key]: v }));

  return (
    <div className="space-y-3">
      {/* Type + Severity */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Type *</label>
          <Select value={f.type} onValueChange={sel("type")}>
            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {IOC_TYPES.map(t => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Severity</label>
          <Select value={f.severity} onValueChange={sel("severity")}>
            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {SEVERITIES.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Value */}
      <div>
        <label className="text-xs font-medium text-muted-foreground block mb-1">Value *</label>
        <Input required value={f.value} onChange={txt("value")}
          placeholder="1.2.3.4 / evil.com / abc123sha256..." className="h-8 text-xs font-mono" />
      </div>

      {/* Source + Source URL */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Source</label>
          <Input value={f.source} onChange={txt("source")} className="h-8 text-xs" placeholder="manual" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Source URL</label>
          <Input value={f.sourceUrl} onChange={txt("sourceUrl")} className="h-8 text-xs" placeholder="https://..." />
        </div>
      </div>

      {/* TLP + Threat Score + Confidence */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">TLP</label>
          <Select value={f.tlp} onValueChange={sel("tlp")}>
            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {TLP_LEVELS.map(t => <SelectItem key={t} value={t}>TLP:{t.toUpperCase()}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Threat Score (0–100)</label>
          <Input type="number" min="0" max="100" value={f.threatScore} onChange={txt("threatScore")} className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Confidence (0–100)</label>
          <Input type="number" min="0" max="100" value={f.confidence} onChange={txt("confidence")} className="h-8 text-xs" />
        </div>
      </div>

      {/* First Seen + Last Seen + Expires At */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">First Seen</label>
          <Input type="datetime-local" value={f.firstSeen} onChange={txt("firstSeen")} className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Last Seen</label>
          <Input type="datetime-local" value={f.lastSeen} onChange={txt("lastSeen")} className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Expires At</label>
          <Input type="datetime-local" value={f.expiresAt} onChange={txt("expiresAt")} className="h-8 text-xs" />
        </div>
      </div>

      {/* Country + ASN + Exploitation Status */}
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Country</label>
          <Input value={f.country} onChange={txt("country")} className="h-8 text-xs" placeholder="US" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">ASN</label>
          <Input value={f.asn} onChange={txt("asn")} className="h-8 text-xs" placeholder="AS12345" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Exploitation</label>
          <Select value={f.exploitationStatus} onValueChange={sel("exploitationStatus")}>
            <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {EXPLOIT_STATUSES.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Tags */}
      <div>
        <label className="text-xs font-medium text-muted-foreground block mb-1">
          Tags <span className="font-normal opacity-60">(comma-separated)</span>
        </label>
        <Input value={f.tags} onChange={txt("tags")} className="h-8 text-xs" placeholder="phishing, c2, botnet" />
        {f.tags.trim() && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {f.tags.split(",").map(t => t.trim()).filter(Boolean).map(t => (
              <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{t}</span>
            ))}
          </div>
        )}
      </div>

      {/* Malware Families + Threat Actors */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Malware Families <span className="font-normal opacity-60">(comma-sep)</span>
          </label>
          <Input value={f.malwareFamilies} onChange={txt("malwareFamilies")} className="h-8 text-xs" placeholder="Cobalt Strike, ..." />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Threat Actors <span className="font-normal opacity-60">(comma-sep)</span>
          </label>
          <Input value={f.threatActors} onChange={txt("threatActors")} className="h-8 text-xs" placeholder="APT29, Lazarus, ..." />
        </div>
      </div>

      {/* Campaigns */}
      <div>
        <label className="text-xs font-medium text-muted-foreground block mb-1">
          Campaigns <span className="font-normal opacity-60">(comma-separated)</span>
        </label>
        <Input value={f.campaigns} onChange={txt("campaigns")} className="h-8 text-xs" placeholder="Operation Aurora, ..." />
      </div>

      {/* Description */}
      <div>
        <label className="text-xs font-medium text-muted-foreground block mb-1">Description</label>
        <textarea
          value={f.description}
          onChange={txt("description")}
          rows={2}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
          placeholder="Observed in campaign targeting financial sector..."
        />
      </div>

      {/* Is Active toggle */}
      <div className="flex items-center gap-2.5">
        <button
          type="button"
          onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}
          className={cn(
            "relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none",
            f.isActive ? "bg-primary" : "bg-muted"
          )}
        >
          <span className={cn(
            "pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-lg ring-0 transition-transform",
            f.isActive ? "translate-x-4" : "translate-x-0"
          )} />
        </button>
        <span
          className="text-xs text-muted-foreground cursor-pointer select-none"
          onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}
        >
          {f.isActive ? "Active" : "Inactive"}
        </span>
      </div>
    </div>
  );
}

/* ── Add Modal ──────────────────────────────────────────────────────────── */
function AddModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState<IocForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.value.trim()) { setErr("Value is required"); return; }
    setLoading(true); setErr("");
    try {
      await apiFetch(`${BASE}/api/threat-intel/iocs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "IOC added successfully" });
      onDone(); onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to add IOC");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Plus className="w-4 h-4 text-primary" /> Add IOC
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <IocFormFields f={f} setF={setF} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : null}
              Add IOC
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Edit Modal ─────────────────────────────────────────────────────────── */
function EditModal({ ioc, onClose, onDone }: { ioc: any; onClose: () => void; onDone: (updated: any) => void }) {
  const [f, setF] = useState<IocForm>(() => iocToForm(ioc));
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.value.trim()) { setErr("Value is required"); return; }
    setLoading(true); setErr("");
    try {
      const updated = await apiFetch<any>(`${BASE}/api/threat-intel/iocs/${ioc.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "IOC updated successfully" });
      onDone(updated);
      onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to update IOC");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Pencil className="w-4 h-4 text-primary" /> Edit IOC
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs font-mono text-muted-foreground break-all">
          ID #{ioc.id} — {ioc.value}
        </div>
        <form onSubmit={submit} className="space-y-4">
          <IocFormFields f={f} setF={setF} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : null}
              Save Changes
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── IOC View Sheet ─────────────────────────────────────────────────────── */
function IocViewSheet({
  ioc, isAdmin, onClose, onEdit, onDelete,
}: {
  ioc: any; isAdmin: boolean;
  onClose: () => void; onEdit: () => void; onDelete: () => void;
}) {
  const arr = (v: any): string[] => (Array.isArray(v) ? v.filter(Boolean) : []);

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-end sm:items-center justify-center p-4">
      <div className="bg-card border border-border rounded-2xl w-full max-w-lg p-6 space-y-4 max-h-[88vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-1.5 mb-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted border border-border uppercase">{ioc.type}</span>
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", SEV_CLASSES[ioc.severity] ?? SEV_CLASSES.low)}>{ioc.severity}</span>
              <span className={cn("text-[9px] px-1.5 py-0.5 rounded border font-mono uppercase", TLP_CLASSES[ioc.tlp ?? "white"] ?? TLP_CLASSES.white)}>
                TLP:{(ioc.tlp ?? "white").toUpperCase()}
              </span>
              {ioc.isActive === false && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">Inactive</span>
              )}
              {ioc.exploitationStatus && ioc.exploitationStatus !== "unknown" && (
                <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize",
                  ["active","weaponized"].includes(ioc.exploitationStatus)
                    ? "text-red-400 bg-red-500/10 border-red-500/20"
                    : "text-orange-400 bg-orange-500/10 border-orange-500/20"
                )}>{ioc.exploitationStatus}</span>
              )}
            </div>
            <p className="font-mono text-sm font-semibold break-all">{ioc.value}</p>
          </div>
          <button onClick={onClose} className="shrink-0 text-muted-foreground hover:text-foreground mt-0.5">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Metadata grid */}
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            { label: "Source",       val: ioc.source ?? "—" },
            { label: "Threat Score", val: Math.round(ioc.threatScore ?? 0) },
            { label: "Confidence",   val: `${ioc.confidence ?? 50}%` },
            { label: "Seen Count",   val: ioc.seenCount ?? 1 },
            { label: "Country",      val: ioc.country ?? "—" },
            { label: "ASN",          val: ioc.asn ?? "—" },
            { label: "First Seen",   val: ioc.firstSeen ? new Date(ioc.firstSeen).toLocaleDateString() : "—" },
            { label: "Last Seen",    val: ioc.lastSeen  ? new Date(ioc.lastSeen).toLocaleDateString()  : "—" },
            { label: "Expires At",   val: ioc.expiresAt ? new Date(ioc.expiresAt).toLocaleDateString() : "Never" },
            { label: "Exploitation", val: ioc.exploitationStatus ?? "unknown" },
          ].map(r => (
            <div key={r.label} className="bg-muted/30 border border-border rounded-lg p-2.5">
              <p className="text-[10px] text-muted-foreground mb-0.5">{r.label}</p>
              <p className="font-medium capitalize truncate">{String(r.val)}</p>
            </div>
          ))}
        </div>

        {/* Source URL */}
        {ioc.sourceUrl && (
          <div className="bg-muted/20 border border-border/40 rounded-lg px-3 py-2 text-xs">
            <span className="text-muted-foreground mr-2">Source URL:</span>
            <a href={ioc.sourceUrl} target="_blank" rel="noreferrer" className="text-primary hover:underline break-all">{ioc.sourceUrl}</a>
          </div>
        )}

        {/* Tags */}
        {arr(ioc.tags).length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1.5">Tags</p>
            <div className="flex flex-wrap gap-1">
              {arr(ioc.tags).map(t => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{t}</span>
              ))}
            </div>
          </div>
        )}

        {/* Malware Families */}
        {arr(ioc.malwareFamilies).length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1.5">Malware Families</p>
            <div className="flex flex-wrap gap-1">
              {arr(ioc.malwareFamilies).map(m => (
                <span key={m} className="text-[10px] px-1.5 py-0.5 rounded bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">{m}</span>
              ))}
            </div>
          </div>
        )}

        {/* Threat Actors */}
        {arr(ioc.threatActors).length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1.5">Threat Actors</p>
            <div className="flex flex-wrap gap-1">
              {arr(ioc.threatActors).map(a => (
                <span key={a} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-400">{a}</span>
              ))}
            </div>
          </div>
        )}

        {/* Campaigns */}
        {arr(ioc.campaigns).length > 0 && (
          <div>
            <p className="text-xs font-medium text-muted-foreground mb-1.5">Campaigns</p>
            <div className="flex flex-wrap gap-1">
              {arr(ioc.campaigns).map(c => (
                <span key={c} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{c}</span>
              ))}
            </div>
          </div>
        )}

        {/* Description */}
        {ioc.description && (
          <div className="bg-muted/20 border border-border/40 rounded-xl p-3">
            <p className="text-xs font-medium text-muted-foreground mb-1">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">{ioc.description}</p>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-2 pt-1 border-t border-border/50">
          {isAdmin && (
            <>
              <Button size="sm" className="flex-1" onClick={onEdit}>
                <Pencil className="w-3.5 h-3.5 mr-1.5" /> Edit IOC
              </Button>
              <Button size="sm" variant="destructive" onClick={onDelete}>
                <Trash2 className="w-3.5 h-3.5" />
              </Button>
            </>
          )}
          <Button variant="outline" size="sm" className={isAdmin ? "w-20" : "flex-1"} onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  );
}

/* ── Inline Severity Badge with quick-change dropdown ───────────────────── */
function SeverityBadge({
  ioc, isAdmin, onChanged,
}: { ioc: any; isAdmin: boolean; onChanged: (newSev: string) => void }) {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (!open) return;
    function handle(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, [open]);

  async function changeSev(newSev: string) {
    if (newSev === ioc.severity) { setOpen(false); return; }
    setSaving(true);
    try {
      await apiFetch(`${BASE}/api/threat-intel/iocs/${ioc.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ severity: newSev }),
      });
      onChanged(newSev);
      toast({ title: `Severity updated to ${newSev}` });
    } catch {
      toast({ title: "Update failed", variant: "destructive" });
    }
    setSaving(false);
    setOpen(false);
  }

  const cls = SEV_CLASSES[ioc.severity] ?? SEV_CLASSES.low;

  if (!isAdmin) {
    return <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", cls)}>{ioc.severity}</span>;
  }

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        onClick={e => { e.stopPropagation(); if (!saving) setOpen(o => !o); }}
        title="Click to change severity"
        className={cn(
          "flex items-center gap-0.5 text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize transition-opacity",
          cls,
          saving && "opacity-50 pointer-events-none"
        )}
      >
        {saving
          ? <Loader2 className="w-2.5 h-2.5 animate-spin mr-0.5" />
          : null}
        {ioc.severity}
        <ChevronDown className="w-2.5 h-2.5 opacity-60 ml-0.5" />
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 z-20 bg-card border border-border rounded-lg shadow-xl py-1 w-32">
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={e => { e.stopPropagation(); changeSev(s); }}
              className="w-full text-left px-3 py-1.5 text-xs capitalize flex items-center gap-2 hover:bg-muted/50 transition-colors"
            >
              <span className={cn("w-2 h-2 rounded-full shrink-0",
                s === "critical" ? "bg-red-400" :
                s === "high"     ? "bg-orange-400" :
                s === "medium"   ? "bg-yellow-400" : "bg-green-400"
              )} />
              {s}
              {s === ioc.severity && <Check className="w-2.5 h-2.5 ml-auto text-primary" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Main Page ──────────────────────────────────────────────────────────── */
export default function ThreatIntelIocsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const qc = useQueryClient();
  const { toast } = useToast();

  const [q, setQ]           = useState("");
  const [typeF, setTypeF]   = useState("");
  const [sev, setSev]       = useState("");
  const [tlp, setTlp]       = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo]   = useState("");
  const [page, setPage]     = useState(0);

  const [showAdd, setShowAdd]   = useState(false);
  const [editIoc, setEditIoc]   = useState<any | null>(null);
  const [viewIoc, setViewIoc]   = useState<any | null>(null);
  // local overrides for optimistic severity updates without full refetch
  const [overrides, setOverrides] = useState<Record<number, Partial<any>>>({});

  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-iocs", q, typeF, sev, tlp, dateFrom, dateTo, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q)        p.set("q", q);
      if (typeF)    p.set("type", typeF);
      if (sev)      p.set("severity", sev);
      if (tlp)      p.set("tlp", tlp);
      if (dateFrom) p.set("dateFrom", dateFrom);
      if (dateTo)   p.set("dateTo", dateTo);
      return apiFetch<any>(`${BASE}/api/threat-intel/iocs?${p}`);
    },
    staleTime: 30_000,
  });

  async function deleteIoc(id: number, e?: React.MouseEvent) {
    e?.stopPropagation();
    if (!window.confirm("Delete this IOC? This cannot be undone.")) return;
    try {
      await apiFetch(`${BASE}/api/threat-intel/iocs/${id}`, { method: "DELETE" });
      toast({ title: "IOC deleted" });
      qc.invalidateQueries({ queryKey: ["ti-iocs"] });
      if (viewIoc?.id === id) setViewIoc(null);
    } catch {
      toast({ title: "Delete failed", variant: "destructive" });
    }
  }

  function afterEdit(updated: any) {
    setOverrides(o => ({ ...o, [updated.id]: updated }));
    qc.invalidateQueries({ queryKey: ["ti-iocs"] });
    if (viewIoc?.id === updated.id) setViewIoc(updated);
  }

  function afterAdd() {
    setOverrides({});
    qc.invalidateQueries({ queryKey: ["ti-iocs"] });
  }

  function exportCsv() {
    const list: any[] = data?.iocs ?? [];
    if (!list.length) return;
    const headers = ["id","type","value","source","sourceUrl","severity","threatScore","tlp","confidence","country","asn","isActive","firstSeen","lastSeen","expiresAt","tags","malwareFamilies","threatActors","campaigns","exploitationStatus","description"];
    const rows = list.map(ioc =>
      headers.map(h => {
        const v = ioc[h];
        if (v == null) return "";
        if (Array.isArray(v)) return `"${v.join("; ")}"`;
        const s = String(v);
        return (s.includes(",") || s.includes('"')) ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(",")
    );
    const csv = [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: `iocs-${new Date().toISOString().slice(0,10)}.csv` });
    a.click(); URL.revokeObjectURL(url);
    toast({ title: "CSV exported", description: `${list.length} IOCs downloaded.` });
  }

  const rawIocs: any[] = data?.iocs ?? [];
  const iocs = rawIocs.map(ioc => overrides[ioc.id] ? { ...ioc, ...overrides[ioc.id] } : ioc);
  const total: number = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      {showAdd && (
        <AddModal onClose={() => setShowAdd(false)} onDone={afterAdd} />
      )}
      {editIoc && (
        <EditModal
          ioc={editIoc}
          onClose={() => setEditIoc(null)}
          onDone={updated => { afterEdit(updated); setEditIoc(null); }}
        />
      )}
      {viewIoc && (
        <IocViewSheet
          ioc={{ ...viewIoc, ...overrides[viewIoc.id] }}
          isAdmin={isAdmin}
          onClose={() => setViewIoc(null)}
          onEdit={() => { setEditIoc({ ...viewIoc, ...overrides[viewIoc.id] }); setViewIoc(null); }}
          onDelete={() => { deleteIoc(viewIoc.id); setViewIoc(null); }}
        />
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Crosshair className="w-5 h-5 text-orange-400" />
          <div>
            <h1 className="text-xl font-bold">IOC Database</h1>
            <p className="text-xs text-muted-foreground">{total.toLocaleString()} indicators of compromise</p>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button size="sm" variant="outline" onClick={exportCsv} disabled={iocs.length === 0}>
            <Download className="w-3.5 h-3.5 mr-1.5" />Export CSV
          </Button>
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          {isAdmin && (
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" />Add IOC
            </Button>
          )}
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-2">
        <div className="relative w-56">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search value, source…"
            value={q}
            onChange={e => { setQ(e.target.value); setPage(0); }}
            className="h-8 pl-8 text-xs"
          />
        </div>
        <Select value={typeF || "all"} onValueChange={v => { setTypeF(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Type" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {IOC_TYPES.map(t => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={sev || "all"} onValueChange={v => { setSev(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={tlp || "all"} onValueChange={v => { setTlp(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-24 text-xs"><SelectValue placeholder="TLP" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All TLP</SelectItem>
            {TLP_LEVELS.map(t => <SelectItem key={t} value={t}>TLP:{t.toUpperCase()}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="flex items-center gap-1">
          <Input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(0); }} className="h-8 w-32 text-xs" title="First seen from" />
          <span className="text-xs text-muted-foreground">–</span>
          <Input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(0); }} className="h-8 w-32 text-xs" title="First seen to" />
          {(dateFrom || dateTo) && (
            <button onClick={() => { setDateFrom(""); setDateTo(""); setPage(0); }} className="text-muted-foreground hover:text-foreground ml-0.5">
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* ── Table ── */}
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="text-left p-3 font-medium text-muted-foreground">Type</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Value</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">Source</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Severity</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Score</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">TLP</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">Last Seen</th>
              <th className="p-3 text-right font-medium text-muted-foreground w-28">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/30">
                    <td colSpan={8} className="p-3"><Skeleton className="h-4 w-full" /></td>
                  </tr>
                ))
              : iocs.map((ioc: any) => (
                  <tr
                    key={ioc.id}
                    className="border-b border-border/30 hover:bg-muted/20 transition-colors cursor-pointer group"
                    onClick={() => setViewIoc(ioc)}
                  >
                    <td className="p-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded font-mono border border-border bg-muted/40 uppercase">{ioc.type}</span>
                    </td>
                    <td className="p-3 font-mono text-[11px] max-w-[180px] truncate" title={ioc.value}>{ioc.value}</td>
                    <td className="p-3 text-muted-foreground hidden md:table-cell max-w-[120px] truncate">{ioc.source}</td>
                    <td className="p-3" onClick={e => e.stopPropagation()}>
                      <SeverityBadge
                        ioc={ioc}
                        isAdmin={isAdmin}
                        onChanged={newSev => setOverrides(o => ({ ...o, [ioc.id]: { ...o[ioc.id], severity: newSev } }))}
                      />
                    </td>
                    <td className="p-3 font-mono text-muted-foreground hidden sm:table-cell">
                      {Math.round(ioc.threatScore ?? 0)}
                    </td>
                    <td className="p-3 hidden sm:table-cell">
                      <span className={cn("text-[9px] px-1 py-0.5 rounded border font-mono uppercase", TLP_CLASSES[ioc.tlp ?? "white"] ?? TLP_CLASSES.white)}>
                        {ioc.tlp ?? "white"}
                      </span>
                    </td>
                    <td className="p-3 text-muted-foreground/70 hidden lg:table-cell text-[11px]">
                      {ioc.lastSeen ? new Date(ioc.lastSeen).toLocaleDateString() : "—"}
                    </td>
                    <td className="p-3 text-right" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-0.5">
                        <button
                          onClick={() => setViewIoc(ioc)}
                          className="p-1.5 rounded text-muted-foreground/50 hover:text-primary hover:bg-muted/40 transition-colors"
                          title="View detail"
                        ><Eye className="w-3.5 h-3.5" /></button>
                        {isAdmin && (
                          <>
                            <button
                              onClick={() => setEditIoc(ioc)}
                              className="p-1.5 rounded text-muted-foreground/50 hover:text-blue-400 hover:bg-blue-500/10 transition-colors"
                              title="Edit IOC"
                            ><Pencil className="w-3 h-3" /></button>
                            <button
                              onClick={e => deleteIoc(ioc.id, e)}
                              className="p-1.5 rounded text-muted-foreground/50 hover:text-destructive hover:bg-destructive/10 transition-colors"
                              title="Delete IOC"
                            ><Trash2 className="w-3.5 h-3.5" /></button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
            }
          </tbody>
        </table>
        {!isLoading && iocs.length === 0 && (
          <div className="p-10 text-center text-sm text-muted-foreground">
            No IOCs found. Run a feed refresh or adjust filters.
          </div>
        )}
      </div>

      {/* ── Pagination ── */}
      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Showing {page * L + 1}–{Math.min((page + 1) * L, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</Button>
            <Button size="sm" variant="outline" disabled={(page + 1) * L >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
