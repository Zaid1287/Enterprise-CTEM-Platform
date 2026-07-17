import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Layers, Search, RefreshCw, Calendar, Plus, Trash2, X,
  Pencil, Eye, Loader2, Target, Globe, Flag, FileText, Link2,
  ChevronRight, Activity, Clock, Crosshair,
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

const STATUS_META: Record<string, { badge: string; dot: string; label: string }> = {
  active:  { badge: "text-green-400 bg-green-500/10 border-green-500/25",    dot: "bg-green-400",   label: "Active"   },
  dormant: { badge: "text-yellow-400 bg-yellow-500/10 border-yellow-500/25", dot: "bg-yellow-400",  label: "Dormant"  },
  ended:   { badge: "text-muted-foreground bg-muted border-border",           dot: "bg-muted-foreground/40", label: "Ended" },
};

const STATUSES = ["active", "dormant", "ended"];

type CampaignForm = {
  name: string; aliases: string; description: string;
  actorId: string; actorName: string; status: string;
  targetIndustries: string; targetCountries: string;
  startDate: string; endDate: string;
  mitreId: string; objectives: string; source: string;
};

const EMPTY_FORM: CampaignForm = {
  name: "", aliases: "", description: "",
  actorId: "", actorName: "", status: "active",
  targetIndustries: "", targetCountries: "",
  startDate: "", endDate: "",
  mitreId: "", objectives: "", source: "manual",
};

function campaignToForm(c: any): CampaignForm {
  const joinArr = (v: any) => (Array.isArray(v) ? v.join(", ") : (v ?? ""));
  return {
    name: c.name ?? "", aliases: joinArr(c.aliases), description: c.description ?? "",
    actorId: c.actorId != null ? String(c.actorId) : "", actorName: c.actorName ?? "",
    status: c.status ?? "active", targetIndustries: joinArr(c.targetIndustries),
    targetCountries: joinArr(c.targetCountries), startDate: c.startDate ?? "",
    endDate: c.endDate ?? "", mitreId: c.mitreId ?? "", objectives: c.objectives ?? "",
    source: c.source ?? "manual",
  };
}

function formToPayload(f: CampaignForm) {
  const split = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  return {
    name: f.name.trim(), aliases: split(f.aliases),
    description: f.description.trim() || null,
    actorId: f.actorId ? Number(f.actorId) : null,
    actorName: f.actorName.trim() || null,
    status: f.status, targetIndustries: split(f.targetIndustries),
    targetCountries: split(f.targetCountries),
    startDate: f.startDate.trim() || null, endDate: f.endDate.trim() || null,
    mitreId: f.mitreId.trim() || null, objectives: f.objectives.trim() || null,
    source: f.source.trim() || "manual",
  };
}

/* ── Section heading (modal) ─────────────────────────────────────────────── */
function SectionHeading({ icon: Icon, label }: { icon: any; label: string }) {
  return (
    <div className="flex items-center gap-2 pt-1 pb-0.5 border-b border-border/50 mb-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{label}</span>
    </div>
  );
}

/* ── Form fields ─────────────────────────────────────────────────────────── */
function CampaignFormFields({ f, setF, actors }: { f: CampaignForm; setF: React.Dispatch<React.SetStateAction<CampaignForm>>; actors: any[] }) {
  const txt = (key: keyof CampaignForm) =>
    (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF(x => ({ ...x, [key]: e.target.value }));
  const sel = (key: keyof CampaignForm) => (v: string) => setF(x => ({ ...x, [key]: v === "none" ? "" : v }));

  return (
    <div className="space-y-5">
      <SectionHeading icon={Layers} label="Campaign Identity" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Campaign Name *</label>
          <Input required value={f.name} onChange={txt("name")} placeholder="e.g. Operation Cozy Bear, SolarWinds Supply Chain" className="h-8 text-xs" />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Status</label>
            <Select value={f.status} onValueChange={sel("status")}>
              <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
              <SelectContent>{STATUSES.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Source</label>
            <Input value={f.source} onChange={txt("source")} placeholder="manual / mitre_attack" className="h-8 text-xs" />
          </div>
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Aliases <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.aliases} onChange={txt("aliases")} placeholder="e.g. SolarStorm, UNC2452" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">MITRE ATT&CK Campaign ID</label>
          <Input value={f.mitreId} onChange={txt("mitreId")} placeholder="e.g. C0004" className="h-8 text-xs font-mono" />
        </div>
      </div>

      <SectionHeading icon={Link2} label="Attribution" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">
            Attributed Threat Actor{actors.length > 0 ? " (select from known actors)" : ""}
          </label>
          {actors.length > 0 ? (
            <Select value={f.actorId || "none"} onValueChange={v => {
              if (v === "none") { setF(x => ({ ...x, actorId: "", actorName: "" })); }
              else { const actor = actors.find((a: any) => String(a.id) === v); setF(x => ({ ...x, actorId: v, actorName: actor?.name ?? "" })); }
            }}>
              <SelectTrigger className="h-8 text-xs"><SelectValue placeholder="Select actor…" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Not attributed / Unknown</SelectItem>
                {actors.map((a: any) => <SelectItem key={a.id} value={String(a.id)}>{a.name}{a.country ? ` (${a.country})` : ""}</SelectItem>)}
              </SelectContent>
            </Select>
          ) : (
            <Input value={f.actorName} onChange={txt("actorName")} placeholder="e.g. APT29, Lazarus Group" className="h-8 text-xs" />
          )}
        </div>
        {actors.length > 0 && (
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Actor Name Override <span className="opacity-60 font-normal">(auto-filled from selection)</span></label>
            <Input value={f.actorName} onChange={txt("actorName")} placeholder="Actor name" className="h-8 text-xs" />
          </div>
        )}
      </div>

      <SectionHeading icon={FileText} label="Description & Objectives" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Description</label>
          <textarea value={f.description} onChange={txt("description")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Attack vector, initial access method, key activities…" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Objectives / Goals</label>
          <textarea value={f.objectives} onChange={txt("objectives")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Data exfiltration, ransomware deployment, espionage, sabotage…" />
        </div>
      </div>

      <SectionHeading icon={Calendar} label="Timeline" />
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Start Date</label>
          <Input value={f.startDate} onChange={txt("startDate")} placeholder="e.g. 2020-03" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">End Date <span className="opacity-60 font-normal">(blank = ongoing)</span></label>
          <Input value={f.endDate} onChange={txt("endDate")} placeholder="e.g. 2020-12, Present" className="h-8 text-xs" />
        </div>
      </div>

      <SectionHeading icon={Target} label="Targeting" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Target Industries <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.targetIndustries} onChange={txt("targetIndustries")} placeholder="Finance, Energy, Government…" className="h-8 text-xs" />
          {f.targetIndustries.trim() && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {f.targetIndustries.split(",").map(s => s.trim()).filter(Boolean).map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{s}</span>
              ))}
            </div>
          )}
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Target Countries <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.targetCountries} onChange={txt("targetCountries")} placeholder="United States, Ukraine, Germany…" className="h-8 text-xs" />
          {f.targetCountries.trim() && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {f.targetCountries.split(",").map(s => s.trim()).filter(Boolean).map(s => (
                <span key={s} className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{s}</span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Add Modal ───────────────────────────────────────────────────────────── */
function AddCampaignModal({ onClose, onDone, actors }: { onClose: () => void; onDone: () => void; actors: any[] }) {
  const [f, setF] = useState<CampaignForm>(EMPTY_FORM);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.name.trim()) { setErr("Campaign name is required"); return; }
    setLoading(true); setErr("");
    try {
      await apiFetch<any>(`${BASE}/api/threat-intel/campaigns`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "Campaign created", description: `${f.name} added to the campaign database.` });
      onDone(); onClose();
    } catch (ex: any) { setErr(ex.message ?? "Failed to create campaign"); setLoading(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2"><Plus className="w-4 h-4 text-primary" /> Add Campaign</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <CampaignFormFields f={f} setF={setF} actors={actors} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}Create Campaign
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Edit Modal ──────────────────────────────────────────────────────────── */
function EditCampaignModal({ campaign, onClose, onDone, actors }: { campaign: any; onClose: () => void; onDone: (u: any) => void; actors: any[] }) {
  const [f, setF] = useState<CampaignForm>(() => campaignToForm(campaign));
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.name.trim()) { setErr("Campaign name is required"); return; }
    setLoading(true); setErr("");
    try {
      const updated = await apiFetch<any>(`${BASE}/api/threat-intel/campaigns/${campaign.id}`, {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "Campaign updated" }); onDone(updated); onClose();
    } catch (ex: any) { setErr(ex.message ?? "Failed to update campaign"); setLoading(false); }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2"><Pencil className="w-4 h-4 text-primary" /> Edit Campaign</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground font-mono">
          ID #{campaign.id} — {campaign.name}
        </div>
        <form onSubmit={submit} className="space-y-4">
          <CampaignFormFields f={f} setF={setF} actors={actors} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}Save Changes
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── View Sheet ──────────────────────────────────────────────────────────── */
function ViewCampaignSheet({ campaign, onClose, onEdit }: { campaign: any; onClose: () => void; onEdit: () => void }) {
  const c = campaign;
  const sm = STATUS_META[c.status] ?? STATUS_META.ended;

  const Field = ({ label, value }: { label: string; value?: string | null }) =>
    value ? (
      <div className="space-y-0.5">
        <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">{label}</p>
        <p className="text-xs text-foreground">{value}</p>
      </div>
    ) : null;

  const Tags = ({ label, items, color = "bg-muted border-border text-foreground" }: { label: string; items?: string[]; color?: string }) =>
    items?.length ? (
      <div className="space-y-1">
        <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">{label}</p>
        <div className="flex flex-wrap gap-1">
          {items.map(t => <span key={t} className={cn("text-[10px] px-1.5 py-0.5 rounded border", color)}>{t}</span>)}
        </div>
      </div>
    ) : null;

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-end p-4">
      <div className="bg-card border border-border rounded-2xl w-full max-w-lg h-full max-h-[calc(100vh-2rem)] flex flex-col shadow-2xl">
        <div className="flex items-start justify-between gap-3 p-5 border-b border-border">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5">
              <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-semibold capitalize flex items-center gap-1", sm.badge)}>
                <span className={cn("w-1.5 h-1.5 rounded-full", sm.dot)} />
                {sm.label}
              </span>
              {c.mitreId && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">{c.mitreId}</span>
              )}
            </div>
            <h2 className="text-base font-bold leading-snug">{c.name}</h2>
            {((c.aliases as string[] | undefined) ?? []).length > 0 && (
              <p className="text-[11px] text-muted-foreground mt-0.5">aka {(c.aliases as string[]).join(", ")}</p>
            )}
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground shrink-0 mt-0.5"><X className="w-4 h-4" /></button>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {c.actorName && (
            <div className="flex items-center gap-2.5 p-3 rounded-xl bg-purple-500/10 border border-purple-500/20">
              <Flag className="w-4 h-4 text-purple-400 shrink-0" />
              <div>
                <p className="text-[10px] text-purple-400/80 font-medium">Attributed Actor</p>
                <p className="text-xs font-semibold text-purple-300">{c.actorName}</p>
              </div>
            </div>
          )}
          {c.description && (
            <div className="space-y-1">
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide">Description</p>
              <p className="text-xs text-muted-foreground leading-relaxed">{c.description}</p>
            </div>
          )}
          {c.objectives && (
            <div className="rounded-xl bg-muted/20 border border-border/50 p-3 space-y-1">
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide flex items-center gap-1.5">
                <Target className="w-3 h-3" /> Objectives
              </p>
              <p className="text-xs text-foreground leading-relaxed">{c.objectives}</p>
            </div>
          )}
          {(c.startDate || c.endDate) && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Start Date" value={c.startDate} />
              <Field label="End Date" value={c.endDate ?? "Ongoing"} />
            </div>
          )}
          <Tags label="Target Industries" items={c.targetIndustries} />
          <Tags label="Target Countries" items={c.targetCountries} color="bg-blue-500/10 border-blue-500/20 text-blue-400" />
          <div className="grid grid-cols-2 gap-3">
            <Field label="Source" value={c.source} />
            <Field label="Last Updated" value={c.updatedAt ? new Date(c.updatedAt).toLocaleDateString() : undefined} />
          </div>
        </div>

        <div className="flex gap-2 p-4 border-t border-border">
          <Button size="sm" className="flex-1" onClick={onEdit}><Pencil className="w-3.5 h-3.5 mr-1.5" />Edit Campaign</Button>
          <Button size="sm" variant="outline" onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────────────────────── */
export default function ThreatIntelCampaignsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [editCampaign, setEditCampaign] = useState<any | null>(null);
  const [viewCampaign, setViewCampaign] = useState<any | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ id: number; name: string } | null>(null);
  const [overrides, setOverrides] = useState<Record<number, any>>({});
  const L = 50;

  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-campaigns", q, status, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q);
      if (status) p.set("status", status);
      return apiFetch<any>(`${BASE}/api/threat-intel/campaigns?${p}`);
    },
    staleTime: 30_000,
  });

  const { data: actorsData } = useQuery({
    queryKey: ["ti-actors-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/actors?limit=200`),
    staleTime: 60_000,
  });
  const actors: any[] = actorsData?.actors ?? [];

  const deleteCampaign = useMutation({
    mutationFn: (id: number) => apiFetch<any>(`${BASE}/api/threat-intel/campaigns/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["ti-campaigns"] }); toast({ title: "Campaign deleted" }); setConfirmDelete(null); },
    onError: () => toast({ title: "Failed to delete campaign", variant: "destructive" }),
  });

  function afterEdit(updated: any) {
    setOverrides(o => ({ ...o, [updated.id]: updated }));
    qc.invalidateQueries({ queryKey: ["ti-campaigns"] });
    if (viewCampaign?.id === updated.id) setViewCampaign(updated);
  }

  function afterAdd() { setOverrides({}); qc.invalidateQueries({ queryKey: ["ti-campaigns"] }); }

  const rawCampaigns: any[] = data?.campaigns ?? [];
  const campaigns = rawCampaigns.map(c => overrides[c.id] ? { ...c, ...overrides[c.id] } : c);
  const total = data?.total ?? 0;

  const activeCount  = campaigns.filter(c => c.status === "active").length;
  const dormantCount = campaigns.filter(c => c.status === "dormant").length;
  const endedCount   = campaigns.filter(c => c.status === "ended" || c.status === "historical").length;

  return (
    <div className="p-6 space-y-6">
      {/* ── Modals ── */}
      {showAdd && <AddCampaignModal actors={actors} onClose={() => setShowAdd(false)} onDone={afterAdd} />}
      {editCampaign && (
        <EditCampaignModal
          campaign={editCampaign} actors={actors}
          onClose={() => setEditCampaign(null)}
          onDone={updated => { afterEdit(updated); setEditCampaign(null); }}
        />
      )}
      {viewCampaign && (
        <ViewCampaignSheet
          campaign={viewCampaign}
          onClose={() => setViewCampaign(null)}
          onEdit={() => { setEditCampaign(viewCampaign); setViewCampaign(null); }}
        />
      )}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-sm space-y-4">
            <h2 className="text-base font-semibold">Delete Campaign?</h2>
            <p className="text-sm text-muted-foreground">
              This will permanently remove <strong className="text-foreground">{confirmDelete.name}</strong> from the database.
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button size="sm" variant="destructive" onClick={() => deleteCampaign.mutate(confirmDelete.id)} disabled={deleteCampaign.isPending}>
                {deleteCampaign.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" />}Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1.5">
            <div className="p-2 rounded-xl bg-blue-500/15 border border-blue-500/25">
              <Layers className="w-5 h-5 text-blue-400" />
            </div>
            <h1 className="text-xl font-bold tracking-tight">Campaigns</h1>
          </div>
          <p className="text-sm text-muted-foreground">
            {total.toLocaleString()} adversary campaigns tracked from MITRE ATT&CK, CISA advisories &amp; threat intelligence feeds
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0 pt-1">
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {isAdmin && (
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5" />Add Campaign
            </Button>
          )}
        </div>
      </div>

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="rounded-xl border border-border bg-card px-4 py-3">
          <div className="flex items-center gap-2 mb-1"><Activity className="w-3.5 h-3.5 text-muted-foreground" /></div>
          <p className="text-2xl font-bold tabular-nums">{total.toLocaleString()}</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">Total Campaigns</p>
        </div>
        <div className="rounded-xl border border-l-4 border-green-500/25 border-l-green-500 bg-green-500/5 px-4 py-3">
          <div className="flex items-center gap-2 mb-1"><span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" /></div>
          <p className="text-2xl font-bold tabular-nums text-green-400">{activeCount}</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">Active</p>
        </div>
        <div className="rounded-xl border border-l-4 border-yellow-500/25 border-l-yellow-500 bg-yellow-500/5 px-4 py-3">
          <div className="flex items-center gap-2 mb-1"><Clock className="w-3.5 h-3.5 text-yellow-400" /></div>
          <p className="text-2xl font-bold tabular-nums text-yellow-400">{dormantCount}</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">Dormant</p>
        </div>
        <div className="rounded-xl border border-border bg-card px-4 py-3">
          <div className="flex items-center gap-2 mb-1"><Crosshair className="w-3.5 h-3.5 text-muted-foreground" /></div>
          <p className="text-2xl font-bold tabular-nums text-muted-foreground">{endedCount}</p>
          <p className="text-[11px] text-muted-foreground mt-0.5">Historical</p>
        </div>
      </div>

      {/* ── Filter bar ── */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-56">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground pointer-events-none" />
          <Input
            placeholder="Search campaigns, actors, MITRE IDs…"
            value={q}
            onChange={e => { setQ(e.target.value); setPage(0); }}
            className="h-9 pl-8 text-sm"
          />
        </div>
        <Select value={status || "all"} onValueChange={v => { setStatus(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-9 w-36 text-sm"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}
          </SelectContent>
        </Select>
        {(q || status) && (
          <Button size="sm" variant="ghost" className="h-9 text-xs text-muted-foreground"
            onClick={() => { setQ(""); setStatus(""); setPage(0); }}>
            <X className="w-3.5 h-3.5 mr-1" />Clear
          </Button>
        )}
        <span className="text-xs text-muted-foreground ml-auto hidden sm:block">
          {total > 0 && `${campaigns.length} of ${total.toLocaleString()} shown`}
        </span>
      </div>

      {/* ── Table ── */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}
        </div>
      ) : campaigns.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4 text-center">
          <div className="p-5 rounded-2xl bg-blue-500/10 border border-blue-500/20">
            <Layers className="w-9 h-9 text-blue-400" />
          </div>
          <div>
            <p className="text-sm font-semibold">No campaigns found</p>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
              {q || status ? "Try adjusting your filters." : "Run a MITRE ATT&CK feed refresh to populate campaign data, or add campaigns manually."}
            </p>
          </div>
          {isAdmin && !q && !status && (
            <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="w-3.5 h-3.5 mr-1.5" />Add First Campaign</Button>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-border overflow-hidden">
          {/* Table header */}
          <div className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_120px_130px_minmax(0,1fr)_120px] items-center gap-3 px-4 py-2.5 bg-muted/40 border-b border-border text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">
            <span>Campaign</span>
            <span>Attributed Actor</span>
            <span>MITRE ID</span>
            <span>Timeline</span>
            <span className="hidden lg:block">Target Sectors</span>
            <span className="text-right">Actions</span>
          </div>

          {/* Table rows */}
          <div className="divide-y divide-border/60">
            {campaigns.map((c: any) => {
              const sm = STATUS_META[c.status] ?? STATUS_META.ended;
              return (
                <div key={c.id}
                  className="grid grid-cols-[minmax(0,2fr)_minmax(0,1fr)_120px_130px_minmax(0,1fr)_120px] items-center gap-3 px-4 py-3 hover:bg-muted/20 transition-colors group">

                  {/* Campaign name + status */}
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <span className={cn("text-[9px] px-1.5 py-0.5 rounded-full border font-semibold shrink-0 flex items-center gap-1", sm.badge)}>
                        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", sm.dot)} />{sm.label}
                      </span>
                    </div>
                    <p className="text-sm font-semibold truncate leading-snug">{c.name}</p>
                    {((c.aliases as string[] | undefined) ?? []).length > 0 && (
                      <p className="text-[10px] text-muted-foreground/60 truncate">aka {(c.aliases as string[]).join(", ")}</p>
                    )}
                  </div>

                  {/* Actor */}
                  <div className="min-w-0">
                    {c.actorName ? (
                      <div className="flex items-center gap-1.5 min-w-0">
                        <Flag className="w-3 h-3 text-purple-400 shrink-0" />
                        <span className="text-xs text-purple-300 font-medium truncate">{c.actorName}</span>
                      </div>
                    ) : (
                      <span className="text-[10px] text-muted-foreground/40">Unknown</span>
                    )}
                  </div>

                  {/* MITRE ID */}
                  <div>
                    {c.mitreId ? (
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">{c.mitreId}</span>
                    ) : (
                      <span className="text-[10px] text-muted-foreground/30">—</span>
                    )}
                  </div>

                  {/* Timeline */}
                  <div className="text-[11px] text-muted-foreground">
                    {c.startDate || c.endDate ? (
                      <span className="flex items-center gap-1">
                        <Calendar className="w-2.5 h-2.5 shrink-0" />
                        {c.startDate ?? "?"} → {c.endDate ?? <span className="text-green-400">now</span>}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/30">—</span>
                    )}
                  </div>

                  {/* Target industries */}
                  <div className="hidden lg:flex flex-wrap gap-1 min-w-0">
                    {((c.targetIndustries as string[] | undefined) ?? []).slice(0, 2).map((ind: string) => (
                      <span key={ind} className="text-[9px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground truncate max-w-24">{ind}</span>
                    ))}
                    {((c.targetIndustries as string[] | undefined) ?? []).length > 2 && (
                      <span className="text-[9px] text-muted-foreground/40 self-center">+{(c.targetIndustries as string[]).length - 2}</span>
                    )}
                    {((c.targetIndustries as string[] | undefined) ?? []).length === 0 && (
                      <span className="text-[10px] text-muted-foreground/30">—</span>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex items-center justify-end gap-1">
                    <Button size="sm" variant="ghost" className="h-7 px-2 text-[11px] text-muted-foreground hover:text-foreground"
                      onClick={() => setViewCampaign(c)}>
                      <Eye className="w-3 h-3 mr-1" />View
                    </Button>
                    {isAdmin && (
                      <>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-blue-400"
                          onClick={() => setEditCampaign(c)}>
                          <Pencil className="w-3 h-3" />
                        </Button>
                        <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                          onClick={() => setConfirmDelete({ id: c.id, name: c.name })}>
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Pagination ── */}
      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
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
