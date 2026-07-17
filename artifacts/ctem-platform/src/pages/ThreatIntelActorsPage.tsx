import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Users, Search, RefreshCw, Plus, Trash2, X,
  Pencil, Eye, Loader2, Shield, Target, Clock, AlertTriangle,
  ChevronDown, Bug, Layers, Check,
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

const MOTIVATIONS     = ["financial","espionage","disruption","hacktivism","state-sponsored"];
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

/* ── Multi-Select Dropdown ──────────────────────────────────────────────── */
function MultiSelectDropdown({
  label, items, selectedIds, onToggle, getLabel, getSublabel, placeholder, emptyText, accentClass,
}: {
  label: string;
  items: any[];
  selectedIds: number[];
  onToggle: (id: number) => void;
  getLabel: (item: any) => string;
  getSublabel?: (item: any) => string;
  placeholder: string;
  emptyText: string;
  accentClass: string;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    if (open) document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [open]);

  const filtered = items.filter(item =>
    getLabel(item).toLowerCase().includes(search.toLowerCase()),
  );
  const selected = items.filter(i => selectedIds.includes(i.id));

  return (
    <div ref={ref} className="space-y-1.5">
      <label className="text-xs font-medium text-muted-foreground block">{label}</label>

      {/* Selected tags */}
      {selected.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-1">
          {selected.map(item => (
            <span
              key={item.id}
              className={cn("flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border font-medium", accentClass)}
            >
              {getLabel(item)}
              <button type="button" onClick={() => onToggle(item.id)} className="opacity-70 hover:opacity-100">
                <X className="w-2.5 h-2.5" />
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Trigger button */}
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between h-8 px-3 rounded-md border border-input bg-background text-xs text-muted-foreground hover:border-ring transition-colors"
      >
        <span>{selected.length > 0 ? `${selected.length} selected` : placeholder}</span>
        <ChevronDown className={cn("w-3.5 h-3.5 transition-transform", open && "rotate-180")} />
      </button>

      {/* Dropdown panel */}
      {open && (
        <div className="relative z-50">
          <div className="absolute top-0 left-0 right-0 bg-card border border-border rounded-lg shadow-xl overflow-hidden">
            <div className="p-2 border-b border-border">
              <div className="relative">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
                <input
                  autoFocus
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder={`Search ${label.toLowerCase()}…`}
                  className="w-full h-7 pl-6 pr-2 text-xs rounded border border-input bg-background placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                />
              </div>
            </div>
            <div className="max-h-48 overflow-y-auto">
              {filtered.length === 0 ? (
                <p className="text-xs text-muted-foreground text-center py-4">{emptyText}</p>
              ) : (
                filtered.slice(0, 150).map(item => {
                  const checked = selectedIds.includes(item.id);
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => onToggle(item.id)}
                      className={cn(
                        "w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-muted/40 transition-colors border-b border-border/30 last:border-0",
                        checked && "bg-muted/20",
                      )}
                    >
                      <div className={cn(
                        "w-3.5 h-3.5 rounded border flex items-center justify-center shrink-0 transition-colors",
                        checked ? "bg-primary border-primary" : "border-muted-foreground/40",
                      )}>
                        {checked && <Check className="w-2.5 h-2.5 text-primary-foreground" />}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-xs font-medium truncate">{getLabel(item)}</p>
                        {getSublabel && (
                          <p className="text-[10px] text-muted-foreground truncate">{getSublabel(item)}</p>
                        )}
                      </div>
                    </button>
                  );
                })
              )}
              {filtered.length > 150 && (
                <p className="text-[10px] text-muted-foreground text-center py-2">
                  Showing 150 of {filtered.length} — refine your search
                </p>
              )}
            </div>
            {selected.length > 0 && (
              <div className="p-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => selected.forEach(i => onToggle(i.id))}
                  className="text-[10px] text-muted-foreground hover:text-destructive transition-colors"
                >
                  Clear all selections
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Shared form fields ─────────────────────────────────────────────────── */
function ActorFormFields({
  f, setF,
  campaigns, malware,
  selectedCampaignIds, onToggleCampaign,
  selectedMalwareIds, onToggleMalware,
}: {
  f: ActorForm;
  setF: React.Dispatch<React.SetStateAction<ActorForm>>;
  campaigns: any[];
  malware: any[];
  selectedCampaignIds: number[];
  onToggleCampaign: (id: number) => void;
  selectedMalwareIds: number[];
  onToggleMalware: (id: number) => void;
}) {
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

      {/* ── Campaigns & Malware ── */}
      <SectionHeading icon={Layers} label="Associated Campaigns & Malware" />
      <div className="space-y-4">
        <MultiSelectDropdown
          label="Linked Campaigns"
          items={campaigns}
          selectedIds={selectedCampaignIds}
          onToggle={onToggleCampaign}
          getLabel={(c: any) => c.name}
          getSublabel={(c: any) => [c.actorName ? `Actor: ${c.actorName}` : null, c.status ? c.status : null].filter(Boolean).join(" · ")}
          placeholder="Select campaigns to associate…"
          emptyText="No campaigns found"
          accentClass="text-blue-400 bg-blue-500/10 border-blue-500/20"
        />
        <MultiSelectDropdown
          label="Linked Malware Families"
          items={malware}
          selectedIds={selectedMalwareIds}
          onToggle={onToggleMalware}
          getLabel={(m: any) => m.name}
          getSublabel={(m: any) => [m.malwareType ? m.malwareType : null, m.actorNames?.length ? `Actors: ${(m.actorNames as string[]).slice(0,2).join(", ")}` : null].filter(Boolean).join(" · ")}
          placeholder="Select malware families to associate…"
          emptyText="No malware found"
          accentClass="text-red-400 bg-red-500/10 border-red-500/20"
        />
        <div className="rounded-lg bg-muted/20 border border-border/40 px-3 py-2 text-[11px] text-muted-foreground">
          Selecting items above will <span className="text-foreground/70 font-medium">update those records</span> in the Campaigns and Malware databases to link them to this actor. View them on the actor's detail page after saving.
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
            <Input value={f.firstSeen} onChange={txt("firstSeen")} placeholder="e.g. 2015, 2015-Q3" className="h-8 text-xs" />
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
            Kill Chain Phases / TTPs <span className="opacity-60 font-normal">(comma-separated)</span>
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
            placeholder="Monitor for PowerShell execution, Detect lateral movement via SMB..." />
        </div>
      </div>

      {/* ── Mitigation & Intel ── */}
      <SectionHeading icon={Shield} label="Mitigation Summary & Intel Links" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Mitigation Summary</label>
          <textarea value={f.mitigation} onChange={txt("mitigation")} rows={3}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring resize-none"
            placeholder="Enable MFA, patch known vulnerabilities, monitor for spearphishing attempts..." />
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
      </div>
    </div>
  );
}

/* ── Linking helpers ─────────────────────────────────────────────────────── */
/** After creating/editing an actor, sync campaign and malware associations */
async function syncAssociations(
  actorId: number,
  actorName: string,
  selectedCampaignIds: number[],
  prevCampaignIds: number[],   // IDs that were linked BEFORE this save
  allCampaigns: any[],
  selectedMalwareIds: number[],
  prevMalwareIds: number[],
  allMalware: any[],
) {
  const patches: Promise<any>[] = [];

  // ── Campaigns ──────────────────────────────────────────────────────────
  const toLink   = selectedCampaignIds.filter(id => !prevCampaignIds.includes(id));
  const toUnlink = prevCampaignIds.filter(id => !selectedCampaignIds.includes(id));

  toLink.forEach(id =>
    patches.push(apiFetch(`${BASE}/api/threat-intel/campaigns/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actorId, actorName }),
    }))
  );
  toUnlink.forEach(id =>
    patches.push(apiFetch(`${BASE}/api/threat-intel/campaigns/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actorId: null, actorName: null }),
    }))
  );

  // ── Malware ────────────────────────────────────────────────────────────
  const actorIdStr = String(actorId);

  const mToLink   = selectedMalwareIds.filter(id => !prevMalwareIds.includes(id));
  const mToUnlink = prevMalwareIds.filter(id => !selectedMalwareIds.includes(id));

  mToLink.forEach(id => {
    const mw = allMalware.find(m => m.id === id);
    if (!mw) return;
    const existingIds:   string[] = Array.isArray(mw.actorIds)   ? mw.actorIds   : [];
    const existingNames: string[] = Array.isArray(mw.actorNames) ? mw.actorNames : [];
    if (existingIds.includes(actorIdStr)) return; // already linked
    patches.push(apiFetch(`${BASE}/api/threat-intel/malware/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actorIds:   [...existingIds,   actorIdStr],
        actorNames: [...existingNames, actorName],
      }),
    }));
  });

  mToUnlink.forEach(id => {
    const mw = allMalware.find(m => m.id === id);
    if (!mw) return;
    const existingIds:   string[] = Array.isArray(mw.actorIds)   ? mw.actorIds   : [];
    const existingNames: string[] = Array.isArray(mw.actorNames) ? mw.actorNames : [];
    patches.push(apiFetch(`${BASE}/api/threat-intel/malware/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        actorIds:   existingIds.filter(i => i !== actorIdStr),
        actorNames: existingNames.filter(n => n !== actorName),
      }),
    }));
  });

  await Promise.allSettled(patches);
}

/* ── Add Modal ──────────────────────────────────────────────────────────── */
function AddActorModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState<ActorForm>(EMPTY_FORM);
  const [selectedCampaignIds, setSelectedCampaignIds] = useState<number[]>([]);
  const [selectedMalwareIds, setSelectedMalwareIds]   = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  const { data: campaignsData } = useQuery({
    queryKey: ["ti-campaigns-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/campaigns?limit=200`),
    staleTime: 60_000,
  });
  const { data: malwareData } = useQuery({
    queryKey: ["ti-malware-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/malware?limit=200`),
    staleTime: 60_000,
  });
  const allCampaigns: any[] = campaignsData?.campaigns ?? [];
  const allMalware:   any[] = malwareData?.malware     ?? [];

  function toggleCampaign(id: number) {
    setSelectedCampaignIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]);
  }
  function toggleMalware(id: number) {
    setSelectedMalwareIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.name.trim()) { setErr("Name is required"); return; }
    setLoading(true); setErr("");
    try {
      const res = await apiFetch<{ actor: any }>(`${BASE}/api/threat-intel/actors`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      const actor = res.actor;
      // Sync relationships
      if (selectedCampaignIds.length > 0 || selectedMalwareIds.length > 0) {
        await syncAssociations(
          actor.id, actor.name,
          selectedCampaignIds, [],
          allCampaigns,
          selectedMalwareIds, [],
          allMalware,
        );
      }
      toast({
        title: "Threat actor created",
        description: `${actor.name} added${selectedCampaignIds.length > 0 || selectedMalwareIds.length > 0 ? ` and linked to ${selectedCampaignIds.length} campaign(s), ${selectedMalwareIds.length} malware family(ies)` : ""}.`,
      });
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
          <ActorFormFields
            f={f} setF={setF}
            campaigns={allCampaigns} malware={allMalware}
            selectedCampaignIds={selectedCampaignIds} onToggleCampaign={toggleCampaign}
            selectedMalwareIds={selectedMalwareIds} onToggleMalware={toggleMalware}
          />
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

  const { data: campaignsData } = useQuery({
    queryKey: ["ti-campaigns-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/campaigns?limit=200`),
    staleTime: 60_000,
  });
  const { data: malwareData } = useQuery({
    queryKey: ["ti-malware-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/malware?limit=200`),
    staleTime: 60_000,
  });
  const allCampaigns: any[] = campaignsData?.campaigns ?? [];
  const allMalware:   any[] = malwareData?.malware     ?? [];

  // Pre-compute which campaigns and malware are already linked to this actor
  const initCampaignIds: number[] = allCampaigns
    .filter((c: any) => c.actorId === actor.id)
    .map((c: any) => c.id);

  const actorIdStr = String(actor.id);
  const initMalwareIds: number[] = allMalware
    .filter((m: any) =>
      (Array.isArray(m.actorIds) && m.actorIds.includes(actorIdStr)) ||
      (Array.isArray(m.actorNames) && m.actorNames.includes(actor.name)),
    )
    .map((m: any) => m.id);

  const [selectedCampaignIds, setSelectedCampaignIds] = useState<number[]>(() => initCampaignIds);
  const [selectedMalwareIds, setSelectedMalwareIds]   = useState<number[]>(() => initMalwareIds);

  // Re-initialize when lists load
  useEffect(() => {
    setSelectedCampaignIds(allCampaigns.filter((c: any) => c.actorId === actor.id).map((c: any) => c.id));
  }, [campaignsData]);
  useEffect(() => {
    setSelectedMalwareIds(
      allMalware
        .filter((m: any) =>
          (Array.isArray(m.actorIds) && m.actorIds.includes(actorIdStr)) ||
          (Array.isArray(m.actorNames) && m.actorNames.includes(actor.name)),
        )
        .map((m: any) => m.id),
    );
  }, [malwareData]);

  function toggleCampaign(id: number) {
    setSelectedCampaignIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]);
  }
  function toggleMalware(id: number) {
    setSelectedMalwareIds(ids => ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]);
  }

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
      await syncAssociations(
        actor.id, updated.name ?? f.name,
        selectedCampaignIds, initCampaignIds,
        allCampaigns,
        selectedMalwareIds, initMalwareIds,
        allMalware,
      );
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
          <ActorFormFields
            f={f} setF={setF}
            campaigns={allCampaigns} malware={allMalware}
            selectedCampaignIds={selectedCampaignIds} onToggleCampaign={toggleCampaign}
            selectedMalwareIds={selectedMalwareIds} onToggleMalware={toggleMalware}
          />
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
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ti-actors"] });
      toast({ title: "Actor deleted" });
      setConfirmDelete(null);
    },
    onError: () => toast({ title: "Failed to delete actor", variant: "destructive" }),
  });

  function afterEdit(updated: any) {
    setOverrides(o => ({ ...o, [updated.id]: updated }));
    qc.invalidateQueries({ queryKey: ["ti-actors"] });
    qc.invalidateQueries({ queryKey: ["ti-campaigns-mini"] });
    qc.invalidateQueries({ queryKey: ["ti-malware-mini"] });
  }

  function afterAdd() {
    setOverrides({});
    qc.invalidateQueries({ queryKey: ["ti-actors"] });
    qc.invalidateQueries({ queryKey: ["ti-campaigns-mini"] });
    qc.invalidateQueries({ queryKey: ["ti-malware-mini"] });
  }

  const rawActors: any[] = data?.actors ?? [];
  const actors = rawActors.map(a => overrides[a.id] ? { ...a, ...overrides[a.id] } : a);
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
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
              This will permanently remove <strong className="text-foreground">{confirmDelete.name}</strong> and all its associated data.
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button size="sm" variant="destructive"
                onClick={() => deleteActor.mutate(confirmDelete.id)}
                disabled={deleteActor.isPending}>
                {deleteActor.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
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

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input placeholder="Search actors…" value={q}
            onChange={e => { setQ(e.target.value); setPage(0); }}
            className="h-8 pl-8 text-xs" />
        </div>
        <Select value={motivation || "all"} onValueChange={v => { setMotivation(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-44 text-xs"><SelectValue placeholder="Motivation" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All motivations</SelectItem>
            {MOTIVATIONS.map(m => <SelectItem key={m} value={m} className="capitalize">{m}</SelectItem>)}
          </SelectContent>
        </Select>
        <Input placeholder="Filter by country…" value={country}
          onChange={e => { setCountry(e.target.value); setPage(0); }}
          className="h-8 w-40 text-xs" />
        {(country || motivation || q) && (
          <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
            onClick={() => { setQ(""); setCountry(""); setMotivation(""); setPage(0); }}>
            <X className="w-3.5 h-3.5 mr-1" />Clear
          </Button>
        )}
      </div>

      {/* Actor Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading
          ? Array.from({ length: 9 }).map((_, i) => <Skeleton key={i} className="h-44 rounded-xl" />)
          : actors.map((a: any) => {
              const score = Math.round(Number(a.riskScore ?? 0));
              const scoreColor = score >= 70 ? "text-red-400" : score >= 40 ? "text-orange-400" : "text-yellow-400";
              return (
                <div key={a.id} className="bg-card border border-border rounded-xl p-4 hover:border-primary/40 transition-all group space-y-2.5">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1 cursor-pointer" onClick={() => navigate(`/threat-intel/actors/${a.id}`)}>
                      <p className="font-semibold text-sm group-hover:text-primary transition-colors truncate">{a.name}</p>
                      {((a.aliases as string[] | undefined) ?? []).length > 0 && (
                        <p className="text-[10px] text-muted-foreground truncate">
                          aka {(a.aliases as string[]).slice(0, 2).join(", ")}
                        </p>
                      )}
                    </div>
                    <div className={cn("text-lg font-bold tabular-nums shrink-0 leading-none mt-0.5", scoreColor)}>{score}</div>
                  </div>
                  <div className="flex flex-wrap gap-1.5 cursor-pointer" onClick={() => navigate(`/threat-intel/actors/${a.id}`)}>
                    {a.country && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{a.country}</span>}
                    {a.motivation && <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize", MOT_COLOR[a.motivation] ?? "text-muted-foreground bg-muted border-border")}>{a.motivation}</span>}
                    {a.sophistication && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground capitalize">{a.sophistication}</span>}
                    {a.isActive && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/20 text-green-400">Active</span>}
                  </div>
                  {((a.targetIndustries as string[] | undefined) ?? []).length > 0 && (
                    <p className="text-[10px] text-muted-foreground truncate cursor-pointer" onClick={() => navigate(`/threat-intel/actors/${a.id}`)}>
                      Targets: {(a.targetIndustries as string[]).slice(0, 3).join(", ")}
                      {(a.targetIndustries as string[]).length > 3 && ` +${(a.targetIndustries as string[]).length - 3}`}
                    </p>
                  )}
                  <div className="flex items-center gap-1 pt-2 mt-1 border-t border-border/50">
                    <button onClick={() => navigate(`/threat-intel/actors/${a.id}`)}
                      className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-primary hover:bg-muted/40 rounded transition-colors gap-0.5">
                      <Eye className="w-3.5 h-3.5" />View
                    </button>
                    {isAdmin && (
                      <>
                        <div className="w-px h-6 bg-border/50" />
                        <button onClick={e => { e.stopPropagation(); setEditActor(a); }}
                          className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-blue-400 hover:bg-blue-500/10 rounded transition-colors gap-0.5">
                          <Pencil className="w-3.5 h-3.5" />Edit
                        </button>
                        <div className="w-px h-6 bg-border/50" />
                        <button onClick={e => { e.stopPropagation(); setConfirmDelete({ id: a.id, name: a.name }); }}
                          className="flex-1 flex flex-col items-center py-1 text-[10px] text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded transition-colors gap-0.5">
                          <Trash2 className="w-3.5 h-3.5" />Delete
                        </button>
                      </>
                    )}
                  </div>
                </div>
              );
            })}
      </div>

      {!isLoading && actors.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">
          No threat actors found. Run a MITRE ATT&CK feed refresh or adjust filters.
        </div>
      )}

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
