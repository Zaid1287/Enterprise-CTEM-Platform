import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Users, Search, RefreshCw, ExternalLink, Plus, Trash2, X,
  Pencil, Eye, Loader2, Shield, Target, Clock, AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const MOT_COLOR: Record<string, string> = {
  "financial":       "text-green-400 bg-green-500/10 border-green-500/20",
  "espionage":       "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "disruption":      "text-red-400 bg-red-500/10 border-red-500/20",
  "hacktivism":      "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "state-sponsored": "text-orange-400 bg-orange-500/10 border-orange-500/20",
};

const MOTIVATIONS  = ["financial","espionage","disruption","hacktivism","state-sponsored"];
const SOPHISTICATIONS = ["none","minimal","operational","expert","strategic"];
const RESOURCE_LEVELS = ["individual","club","contest","team","organization","government"];

/* ── Form state ─────────────────────────────────────────────────────────── */
type ActorForm = {
  name: string; aliases: string; country: string; motivation: string; source: string;
  description: string; overview: string; executiveSummary: string;
  firstSeen: string; lastSeen: string;
  sophistication: string; resourceLevel: string;
  isActive: boolean; riskScore: string; confidenceScore: string;
  targetIndustries: string; targetCountries: string;
  mitreId: string; mitreUrl: string;
  killChain: string; detectionRules: string; mitigation: string; referenceUrls: string;
};

const EMPTY_FORM: ActorForm = {
  name: "", aliases: "", country: "", motivation: "", source: "manual",
  description: "", overview: "", executiveSummary: "",
  firstSeen: "", lastSeen: "",
  sophistication: "", resourceLevel: "",
  isActive: true, riskScore: "0", confidenceScore: "0",
  targetIndustries: "", targetCountries: "",
  mitreId: "", mitreUrl: "",
  killChain: "", detectionRules: "", mitigation: "", referenceUrls: "",
};

function actorToForm(a: any): ActorForm {
  const joinArr = (v: any) => Array.isArray(v) ? v.join(", ") : (v ?? "");
  const joinKillChain = (v: any) => {
    if (!v || !Array.isArray(v)) return "";
    return v.map((item: any) => typeof item === "string" ? item : (item?.phase ?? item?.name ?? JSON.stringify(item))).join(", ");
  };
  return {
    name: a.name ?? "",
    aliases: joinArr(a.aliases),
    country: a.country ?? "",
    motivation: a.motivation ?? "",
    source: a.source ?? "manual",
    description: a.description ?? "",
    overview: a.overview ?? "",
    executiveSummary: a.executiveSummary ?? "",
    firstSeen: a.firstSeen ?? "",
    lastSeen: a.lastSeen ?? "",
    sophistication: a.sophistication ?? "",
    resourceLevel: a.resourceLevel ?? "",
    isActive: a.isActive !== false,
    riskScore: String(Math.round(a.riskScore ?? 0)),
    confidenceScore: String(Math.round(a.confidenceScore ?? 0)),
    targetIndustries: joinArr(a.targetIndustries),
    targetCountries: joinArr(a.targetCountries),
    mitreId: a.mitreId ?? "",
    mitreUrl: a.mitreUrl ?? "",
    killChain: joinKillChain(a.killChain),
    detectionRules: joinArr(a.detectionRules),
    mitigation: a.mitigation ?? "",
    referenceUrls: joinArr(a.referenceUrls),
  };
}

function formToPayload(f: ActorForm) {
  const split = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  return {
    name: f.name.trim(),
    aliases: split(f.aliases),
    country: f.country.trim() || null,
    motivation: f.motivation || null,
    source: f.source.trim() || "manual",
    description: f.description.trim() || null,
    overview: f.overview.trim() || null,
    executiveSummary: f.executiveSummary.trim() || null,
    firstSeen: f.firstSeen.trim() || null,
    lastSeen: f.lastSeen.trim() || null,
    sophistication: f.sophistication || null,
    resourceLevel: f.resourceLevel || null,
    isActive: f.isActive,
    riskScore: Math.max(0, Math.min(100, Number(f.riskScore) || 0)),
    confidenceScore: Math.max(0, Math.min(100, Number(f.confidenceScore) || 0)),
    targetIndustries: split(f.targetIndustries),
    targetCountries: split(f.targetCountries),
    mitreId: f.mitreId.trim() || null,
    mitreUrl: f.mitreUrl.trim() || null,
    killChain: split(f.killChain),
    detectionRules: split(f.detectionRules),
    mitigation: f.mitigation.trim() || null,
    referenceUrls: split(f.referenceUrls),
  };
}

/* ── Section header ─────────────────────────────────────────────────────── */
function SectionHeading({ icon: Icon, label }: { icon: any; label: string }) {
  return (
    <div className="flex items-center gap-2 pt-1 pb-0.5 border-b border-border/50 mb-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{label}</span>
    </div>
  );
}

/* ── Shared form fields ─────────────────────────────────────────────────── */
function ActorFormFields({ f, setF }: { f: ActorForm; setF: React.Dispatch<React.SetStateAction<ActorForm>> }) {
  const txt = (key: keyof ActorForm) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setF(x => ({ ...x, [key]: e.target.value }));
  const sel = (key: keyof ActorForm) => (v: string) =>
    setF(x => ({ ...x, [key]: v === "none" ? "" : v }));

  return (
    <div className="space-y-5">
      {/* ── Basic Info ── */}
      <SectionHeading icon={Users} label="Basic Info" />
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="text-xs font-medium text-muted-foreground block mb-1">Name *</label>
            <Input required value={f.name} onChange={txt("name")} placeholder="e.g. APT29, Lazarus Group" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Country / Origin</label>
            <Input value={f.country} onChange={txt("country")} placeholder="e.g. Russia, North Korea" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Motivation</label>
            <Select value={f.motivation || "none"} onValueChange={sel("motivation")}>
              <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Select motivation" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Not specified</SelectItem>
                {MOTIVATIONS.map(m => <SelectItem key={m} value={m} className="capitalize">{m}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Aliases <span className="opacity-60 font-normal">(comma-sep)</span></label>
            <Input value={f.aliases} onChange={txt("aliases")} placeholder="Cozy Bear, The Dukes" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Source</label>
            <Input value={f.source} onChange={txt("source")} placeholder="manual / mitre_attack" className="h-8 text-xs" />
          </div>
        </div>
        {/* isActive toggle */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}
            className={cn("relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors", f.isActive ? "bg-primary" : "bg-muted")}
          >
            <span className={cn("inline-block h-4 w-4 rounded-full bg-white shadow transition-transform", f.isActive ? "translate-x-4" : "translate-x-0")} />
          </button>
          <span className="text-xs text-muted-foreground cursor-pointer" onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}>
            {f.isActive ? "Active threat actor" : "Inactive / historical"}
          </span>
        </div>
      </div>

      {/* ── Description & Overview ── */}
      <SectionHeading icon={Shield} label="Description & Key Stats" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Description</label>
          <textarea value={f.description} onChange={txt("description")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Brief description of the threat actor's history and activities..." />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Overview / Detailed Profile</label>
          <textarea value={f.overview} onChange={txt("overview")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="In-depth operational overview, known campaigns, notable attacks..." />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Executive Summary / Key Stats</label>
          <textarea value={f.executiveSummary} onChange={txt("executiveSummary")} rows={2}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="High-level summary for executive reports..." />
        </div>
      </div>

      {/* ── Timeline & Profile ── */}
      <SectionHeading icon={Clock} label="Timeline & Profile" />
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">First Seen</label>
            <Input value={f.firstSeen} onChange={txt("firstSeen")} placeholder="e.g. 2015, 2015-Q3, 2015-08" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Last Seen</label>
            <Input value={f.lastSeen} onChange={txt("lastSeen")} placeholder="e.g. 2024, Present" className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Sophistication</label>
            <Select value={f.sophistication || "none"} onValueChange={sel("sophistication")}>
              <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Select level" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Not specified</SelectItem>
                {SOPHISTICATIONS.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Resource Level</label>
            <Select value={f.resourceLevel || "none"} onValueChange={sel("resourceLevel")}>
              <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Select level" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Not specified</SelectItem>
                {RESOURCE_LEVELS.map(r => <SelectItem key={r} value={r} className="capitalize">{r}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Risk Score (0–100)</label>
            <Input type="number" min="0" max="100" value={f.riskScore} onChange={txt("riskScore")} className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Confidence Score (0–100)</label>
            <Input type="number" min="0" max="100" value={f.confidenceScore} onChange={txt("confidenceScore")} className="h-8 text-xs" />
          </div>
        </div>
      </div>

      {/* ── Targeting ── */}
      <SectionHeading icon={Target} label="Targeting" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Target Industries <span className="opacity-60 font-normal">(comma-separated)</span>
          </label>
          <Input value={f.targetIndustries} onChange={txt("targetIndustries")} className="h-8 text-xs"
            placeholder="Finance, Healthcare, Energy, Government, ..." />
          {f.targetIndustries.trim() && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {f.targetIndustries.split(",").map(s => s.trim()).filter(Boolean).map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{s}</span>
              ))}
            </div>
          )}
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Target Countries <span className="opacity-60 font-normal">(comma-separated)</span>
          </label>
          <Input value={f.targetCountries} onChange={txt("targetCountries")} className="h-8 text-xs"
            placeholder="United States, Germany, South Korea, ..." />
          {f.targetCountries.trim() && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {f.targetCountries.split(",").map(s => s.trim()).filter(Boolean).map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{s}</span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── TTP / Kill Chain ── */}
      <SectionHeading icon={AlertTriangle} label="TTP Details / Kill Chain" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Kill Chain Phases / TTPs <span className="opacity-60 font-normal">(comma-separated MITRE technique names or phases)</span>
          </label>
          <textarea value={f.killChain} onChange={txt("killChain")} rows={2}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Spearphishing Attachment, PowerShell, Credential Dumping, Lateral Movement, Data Exfiltration..." />
          {f.killChain.trim() && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {f.killChain.split(",").map(s => s.trim()).filter(Boolean).map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{s}</span>
              ))}
            </div>
          )}
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Detection Summary / Rules <span className="opacity-60 font-normal">(comma-separated)</span>
          </label>
          <textarea value={f.detectionRules} onChange={txt("detectionRules")} rows={2}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Monitor for PowerShell execution, Detect lateral movement via SMB, Alert on unusual outbound DNS queries..." />
        </div>
      </div>

      {/* ── Mitigation & Intel ── */}
      <SectionHeading icon={Shield} label="Mitigation Summary & Intel Links" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Mitigation Summary</label>
          <textarea value={f.mitigation} onChange={txt("mitigation")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Enable MFA, patch known vulnerabilities, monitor for spearphishing attempts, segment network access..." />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">MITRE ATT&CK ID</label>
            <Input value={f.mitreId} onChange={txt("mitreId")} placeholder="e.g. G0016" className="h-8 text-xs font-mono" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">MITRE ATT&CK URL</label>
            <Input value={f.mitreUrl} onChange={txt("mitreUrl")} placeholder="https://attack.mitre.org/groups/..." className="h-8 text-xs" />
          </div>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Reference URLs <span className="opacity-60 font-normal">(comma-separated)</span>
          </label>
          <Input value={f.referenceUrls} onChange={txt("referenceUrls")} className="h-8 text-xs"
            placeholder="https://blog.example.com/apt29, https://nvd.nist.gov/..." />
        </div>
        <div className="rounded-lg bg-muted/20 border border-border/40 px-3 py-2.5 text-[11px] text-muted-foreground">
          <span className="font-medium text-foreground/70">Note:</span> Campaign details, malware associations, and linked IOCs are managed automatically by the MITRE ATT&amp;CK feed and can be viewed from the actor detail page. After creating this actor, navigate to its detail page to see all associated data.
        </div>
      </div>
    </div>
  );
}

/* ── Add Modal ──────────────────────────────────────────────────────────── */
function AddActorModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState<ActorForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.name.trim()) { setErr("Name is required"); return; }
    setLoading(true); setErr("");
    try {
      await apiFetch<any>(`${BASE}/api/threat-intel/actors`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "Threat actor created", description: `${f.name} added to the threat actor database.` });
      onDone(); onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to create actor");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Plus className="w-4 h-4 text-primary" /> Add Threat Actor
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <ActorFormFields f={f} setF={setF} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" /> : null}
              Create Actor
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Edit Modal ─────────────────────────────────────────────────────────── */
function EditActorModal({ actor, onClose, onDone }: { actor: any; onClose: () => void; onDone: (updated: any) => void }) {
  const [f, setF] = useState<ActorForm>(() => actorToForm(actor));
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.name.trim()) { setErr("Name is required"); return; }
    setLoading(true); setErr("");
    try {
      const updated = await apiFetch<any>(`${BASE}/api/threat-intel/actors/${actor.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "Threat actor updated" });
      onDone(updated);
      onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to update actor");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Pencil className="w-4 h-4 text-primary" /> Edit Threat Actor
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground font-mono">
          ID #{actor.id} — {actor.name}
        </div>
        <form onSubmit={submit} className="space-y-4">
          <ActorFormFields f={f} setF={setF} />
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

/* ── Main Page ──────────────────────────────────────────────────────────── */
export default function ThreatIntelActorsPage() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [q, setQ] = useState("");
  const [country, setCountry] = useState("");
  const [motivation, setMotivation] = useState("");
  const [page, setPage] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [editActor, setEditActor] = useState<any | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ id: number; name: string } | null>(null);
  // Optimistic overrides so edits reflect immediately without full refetch
  const [overrides, setOverrides] = useState<Record<number, any>>({});
  const L = 50;

  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-actors", q, country, motivation, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q);
      if (country) p.set("country", country);
      if (motivation) p.set("motivation", motivation);
      return apiFetch<any>(`${BASE}/api/threat-intel/actors?${p}`);
    },
    staleTime: 30_000,
  });

  const deleteActor = useMutation({
    mutationFn: (id: number) => apiFetch<any>(`${BASE}/api/threat-intel/actors/${id}`, { method: "DELETE" }),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: ["ti-actors"] });
      toast({ title: "Actor deleted" });
      setConfirmDelete(null);
    },
    onError: () => toast({ title: "Failed to delete actor", variant: "destructive" }),
  });

  function afterEdit(updated: any) {
    setOverrides(o => ({ ...o, [updated.id]: updated }));
    qc.invalidateQueries({ queryKey: ["ti-actors"] });
  }

  function afterAdd() {
    setOverrides({});
    qc.invalidateQueries({ queryKey: ["ti-actors"] });
  }

  const rawActors: any[] = data?.actors ?? [];
  const actors = rawActors.map(a => overrides[a.id] ? { ...a, ...overrides[a.id] } : a);
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      {/* ── Modals ── */}
      {showAdd && <AddActorModal onClose={() => setShowAdd(false)} onDone={afterAdd} />}
      {editActor && (
        <EditActorModal
          actor={editActor}
          onClose={() => setEditActor(null)}
          onDone={updated => { afterEdit(updated); setEditActor(null); }}
        />
      )}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-sm space-y-4">
            <h2 className="text-base font-semibold">Delete Threat Actor?</h2>
            <p className="text-sm text-muted-foreground">
              This will permanently remove <strong className="text-foreground">{confirmDelete.name}</strong> and all its associated data from the database.
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button
                size="sm" variant="destructive"
                onClick={() => deleteActor.mutate(confirmDelete.id)}
                disabled={deleteActor.isPending}
              >
                {deleteActor.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="w-5 h-5 text-purple-400" />
          <div>
            <h1 className="text-xl font-bold">Threat Actors</h1>
            <p className="text-xs text-muted-foreground">{total.toLocaleString()} known threat actors</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" />Add Actor
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input
            placeholder="Search actors…"
            value={q}
            onChange={e => { setQ(e.target.value); setPage(0); }}
            className="h-8 pl-8 text-xs"
          />
        </div>
        <Select value={motivation || "all"} onValueChange={v => { setMotivation(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-44 text-xs"><SelectValue placeholder="Motivation" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All motivations</SelectItem>
            {MOTIVATIONS.map(m => <SelectItem key={m} value={m} className="capitalize">{m}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input
          placeholder="Filter by country…"
          value={country}
          onChange={e => { setCountry(e.target.value); setPage(0); }}
          className="h-8 w-40 text-xs"
        />
        {(country || motivation || q) && (
          <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
            onClick={() => { setQ(""); setCountry(""); setMotivation(""); setPage(0); }}>
            <X className="w-3.5 h-3.5 mr-1" />Clear
          </Button>
        )}
      </div>

      {/* ── Actor Grid ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading
          ? Array.from({ length: 9 }).map((_, i) => <Skeleton key={i} className="h-44 rounded-xl" />)
          : actors.map((a: any) => {
              const score = Math.round(Number(a.riskScore ?? 0));
              const scoreColor = score >= 70 ? "text-red-400" : score >= 40 ? "text-orange-400" : "text-yellow-400";

              return (
                <div
                  key={a.id}
                  className="bg-card border border-border rounded-xl p-4 hover:border-primary/40 transition-all group space-y-2.5"
                >
                  {/* ── Row 1: Name/aliases + Risk score — NO OVERLAP ── */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1 cursor-pointer" onClick={() => navigate(`/threat-intel/actors/${a.id}`)}>
                      <p className="font-semibold text-sm group-hover:text-primary transition-colors truncate">{a.name}</p>
                      {((a.aliases as string[] | undefined) ?? []).length > 0 && (
                        <p className="text-[10px] text-muted-foreground truncate">
                          aka {(a.aliases as string[]).slice(0, 2).join(", ")}
                        </p>
                      )}
                    </div>
                    {/* Risk score badge — clearly separated from action buttons */}
                    <div className={cn("text-lg font-bold tabular-nums shrink-0 leading-none mt-0.5", scoreColor)}>
                      {score}
                    </div>
                  </div>

                  {/* ── Row 2: Motivation / Country / Active badges ── */}
                  <div
                    className="flex flex-wrap gap-1.5 cursor-pointer"
                    onClick={() => navigate(`/threat-intel/actors/${a.id}`)}
                  >
                    {a.country && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{a.country}</span>
                    )}
                    {a.motivation && (
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize", MOT_COLOR[a.motivation] ?? "text-muted-foreground bg-muted border-border")}>
                        {a.motivation}
                      </span>
                    )}
                    {a.sophistication && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground capitalize">{a.sophistication}</span>
                    )}
                    {a.isActive && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/20 text-green-400">Active</span>
                    )}
                  </div>

                  {/* ── Row 3: Target industries ── */}
                  {((a.targetIndustries as string[] | undefined) ?? []).length > 0 && (
                    <p
                      className="text-[10px] text-muted-foreground truncate cursor-pointer"
                      onClick={() => navigate(`/threat-intel/actors/${a.id}`)}
                    >
                      Targets: {(a.targetIndustries as string[]).slice(0, 3).join(", ")}
                      {(a.targetIndustries as string[]).length > 3 && ` +${(a.targetIndustries as string[]).length - 3}`}
                    </p>
                  )}

                  {/* ── Row 4: Action buttons — always visible, never overlap ── */}
                  <div className="flex items-center gap-1 pt-2 mt-1 border-t border-border/50">
                    <button
                      onClick={() => navigate(`/threat-intel/actors/${a.id}`)}
                      className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-primary hover:bg-muted/40 rounded transition-colors gap-0.5"
                      title="View full profile"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      View
                    </button>
                    {isAdmin && (
                      <>
                        <div className="w-px h-6 bg-border/50" />
                        <button
                          onClick={e => { e.stopPropagation(); setEditActor(a); }}
                          className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors gap-0.5"
                          title="Edit actor"
                        >
                          <Pencil className="w-3.5 h-3.5" />
                          Edit
                        </button>
                        <div className="w-px h-6 bg-border/50" />
                        <button
                          onClick={e => { e.stopPropagation(); setConfirmDelete({ id: a.id, name: a.name }); }}
                          className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded transition-colors gap-0.5"
                          title="Delete actor"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete
                        </button>
                      </>
                    )}
                  </div>
                </div>
              );
            })
        }
      </div>

      {!isLoading && actors.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">
          No threat actors found. Run a MITRE ATT&CK feed refresh or adjust filters.
        </div>
      )}

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
