import { useState, useRef, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Radio, Search, RefreshCw, Plus, Trash2, X,
  Pencil, Eye, Loader2, Globe, Activity, Shield,
  Server, Tag, ChevronDown, Check, Clock, AlertTriangle,
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

/* ── Form type ──────────────────────────────────────────────────────────── */
type C2Form = {
  ip: string; port: string; domain: string;
  country: string; countryCode: string;
  asn: string; asnOrg: string; isp: string; city: string;
  lat: string; lng: string;
  malwareFamily: string; actorName: string;
  tags: string; confidence: string; isActive: boolean;
  cloudProvider: string; serviceCategory: string;
  sectorsAtRisk: string; platformsAtRisk: string; orgsAtRisk: string;
  source: string;
};

const EMPTY_FORM: C2Form = {
  ip: "", port: "", domain: "",
  country: "", countryCode: "",
  asn: "", asnOrg: "", isp: "", city: "",
  lat: "", lng: "",
  malwareFamily: "", actorName: "",
  tags: "", confidence: "70", isActive: true,
  cloudProvider: "", serviceCategory: "",
  sectorsAtRisk: "", platformsAtRisk: "", orgsAtRisk: "",
  source: "manual",
};

function c2ToForm(s: any): C2Form {
  const join = (v: any) => Array.isArray(v) ? v.join(", ") : (v ?? "");
  return {
    ip: s.ip ?? "",
    port: s.port != null ? String(s.port) : "",
    domain: s.domain ?? "",
    country: s.country ?? "",
    countryCode: s.countryCode ?? "",
    asn: s.asn ?? "",
    asnOrg: s.asnOrg ?? "",
    isp: s.isp ?? "",
    city: s.city ?? "",
    lat: s.lat != null ? String(s.lat) : "",
    lng: s.lng != null ? String(s.lng) : "",
    malwareFamily: s.malwareFamily ?? "",
    actorName: s.actorName ?? "",
    tags: join(s.tags),
    confidence: String(s.confidence ?? 70),
    isActive: s.isActive !== false,
    cloudProvider: s.cloudProvider ?? "",
    serviceCategory: s.serviceCategory ?? "",
    sectorsAtRisk: join(s.sectorsAtRisk),
    platformsAtRisk: join(s.platformsAtRisk),
    orgsAtRisk: join(s.orgsAtRisk),
    source: s.source ?? "manual",
  };
}

function formToPayload(f: C2Form) {
  const split = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  return {
    ip: f.ip.trim(),
    port: f.port ? Number(f.port) : null,
    domain: f.domain.trim() || null,
    country: f.country.trim() || null,
    countryCode: f.countryCode.trim() || null,
    asn: f.asn.trim() || null,
    asnOrg: f.asnOrg.trim() || null,
    isp: f.isp.trim() || null,
    city: f.city.trim() || null,
    lat: f.lat ? Number(f.lat) : null,
    lng: f.lng ? Number(f.lng) : null,
    malwareFamily: f.malwareFamily.trim() || null,
    actorName: f.actorName.trim() || null,
    tags: split(f.tags),
    confidence: Math.max(0, Math.min(100, Number(f.confidence) || 70)),
    isActive: f.isActive,
    cloudProvider: f.cloudProvider.trim() || null,
    serviceCategory: f.serviceCategory.trim() || null,
    sectorsAtRisk: split(f.sectorsAtRisk),
    platformsAtRisk: split(f.platformsAtRisk),
    orgsAtRisk: split(f.orgsAtRisk),
    source: f.source.trim() || "manual",
  };
}

/* ── Section heading ─────────────────────────────────────────────────────── */
function SH({ icon: Icon, label }: { icon: any; label: string }) {
  return (
    <div className="flex items-center gap-2 pt-1 pb-0.5 border-b border-border/50 mb-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">{label}</span>
    </div>
  );
}

/* ── Tag preview ─────────────────────────────────────────────────────────── */
function TagPreview({ value, cls }: { value: string; cls: string }) {
  const tags = value.split(",").map(s => s.trim()).filter(Boolean);
  if (!tags.length) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {tags.map(t => <span key={t} className={cn("text-[10px] px-1.5 py-0.5 rounded border", cls)}>{t}</span>)}
    </div>
  );
}

/* ── Malware family searchable dropdown ─────────────────────────────────── */
function MalwareFamilyDropdown({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const ref = useRef<HTMLDivElement>(null);

  const { data } = useQuery({
    queryKey: ["ti-malware-mini"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/malware?limit=200`),
    staleTime: 60_000,
  });
  const allMalware: any[] = data?.malware ?? [];

  useEffect(() => {
    function h(e: MouseEvent) { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); }
    if (open) document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  const filtered = allMalware.filter(m => m.name.toLowerCase().includes(search.toLowerCase()));

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between h-8 px-3 rounded-md border border-input bg-background text-xs hover:border-ring transition-colors"
      >
        <span className={value ? "text-foreground" : "text-muted-foreground"}>
          {value || "Select malware family…"}
        </span>
        <div className="flex items-center gap-1">
          {value && (
            <span onClick={e => { e.stopPropagation(); onChange(""); }} className="hover:text-destructive text-muted-foreground">
              <X className="w-3 h-3" />
            </span>
          )}
          <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform", open && "rotate-180")} />
        </div>
      </button>
      {open && (
        <div className="absolute z-50 top-full left-0 right-0 mt-1 bg-card border border-border rounded-lg shadow-xl overflow-hidden">
          <div className="p-2 border-b border-border">
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
              <input autoFocus value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search malware families…"
                className="w-full h-7 pl-6 pr-2 text-xs rounded border border-input bg-background focus:outline-none focus:ring-1 focus:ring-ring" />
            </div>
          </div>
          <div className="max-h-48 overflow-y-auto">
            <button type="button" onClick={() => { onChange(""); setOpen(false); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-muted-foreground hover:bg-muted/40 border-b border-border/30">
              <X className="w-3 h-3" /> Clear selection
            </button>
            {filtered.slice(0, 100).map(m => (
              <button key={m.id} type="button"
                onClick={() => { onChange(m.name); setOpen(false); }}
                className={cn("w-full flex items-center justify-between gap-2 px-3 py-2 text-left hover:bg-muted/40 transition-colors border-b border-border/30 last:border-0",
                  value === m.name && "bg-muted/20")}
              >
                <div>
                  <p className="text-xs font-medium">{m.name}</p>
                  <p className="text-[10px] text-muted-foreground capitalize">{m.malwareType}</p>
                </div>
                {value === m.name && <Check className="w-3 h-3 text-primary shrink-0" />}
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">No malware families found</p>
            )}
            {filtered.length > 100 && (
              <p className="text-[10px] text-muted-foreground text-center py-2">Showing 100 of {filtered.length} — refine search</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Shared form fields ─────────────────────────────────────────────────── */
function C2FormFields({ f, setF }: { f: C2Form; setF: React.Dispatch<React.SetStateAction<C2Form>> }) {
  const txt = (k: keyof C2Form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setF(x => ({ ...x, [k]: e.target.value }));

  return (
    <div className="space-y-5">

      {/* ── Network Identity ── */}
      <SH icon={Server} label="Network Identity (required)" />
      <div className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="text-xs font-medium text-muted-foreground block mb-1">IP Address *</label>
            <Input required value={f.ip} onChange={txt("ip")} placeholder="e.g. 192.168.1.100 or 45.33.32.156" className="h-8 text-xs font-mono" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Port</label>
            <Input type="number" value={f.port} onChange={txt("port")} placeholder="e.g. 443, 8080, 4444" className="h-8 text-xs font-mono" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Domain / Hostname</label>
            <Input value={f.domain} onChange={txt("domain")} placeholder="e.g. c2.example.com" className="h-8 text-xs font-mono" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Confidence (0–100)</label>
            <Input type="number" min="0" max="100" value={f.confidence} onChange={txt("confidence")} className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Source</label>
            <Input value={f.source} onChange={txt("source")} placeholder="manual / threatfox / abuseipdb" className="h-8 text-xs" />
          </div>
        </div>
        {/* isActive toggle */}
        <div className="flex items-center gap-2.5">
          <button type="button" onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}
            className={cn("relative inline-flex h-5 w-9 shrink-0 rounded-full border-2 border-transparent transition-colors", f.isActive ? "bg-green-500" : "bg-muted")}>
            <span className={cn("inline-block h-4 w-4 rounded-full bg-white shadow transition-transform", f.isActive ? "translate-x-4" : "translate-x-0")} />
          </button>
          <span className="text-xs text-muted-foreground cursor-pointer" onClick={() => setF(x => ({ ...x, isActive: !x.isActive }))}>
            {f.isActive ? "Active C2 server" : "Inactive / historical"}
          </span>
        </div>
      </div>

      {/* ── Attribution ── */}
      <SH icon={Shield} label="Threat Attribution" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Malware Family</label>
          <MalwareFamilyDropdown value={f.malwareFamily} onChange={v => setF(x => ({ ...x, malwareFamily: v }))} />
          <p className="text-[10px] text-muted-foreground mt-1">Select from your tracked malware families, or type a custom name below</p>
          {!f.malwareFamily && (
            <Input className="h-8 text-xs mt-1.5" placeholder="Or type custom malware family name…"
              onChange={e => setF(x => ({ ...x, malwareFamily: e.target.value }))} />
          )}
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Threat Actor Name</label>
          <Input value={f.actorName} onChange={txt("actorName")} placeholder="e.g. APT29, Lazarus Group" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Tags <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.tags} onChange={txt("tags")} placeholder="c2, proxy, vpn, tor-exit, bulletproof-host" className="h-8 text-xs" />
          <TagPreview value={f.tags} cls="bg-muted border-border text-muted-foreground" />
        </div>
      </div>

      {/* ── Geolocation ── */}
      <SH icon={Globe} label="Geolocation" />
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Country</label>
          <Input value={f.country} onChange={txt("country")} placeholder="e.g. Russia, China, Iran" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Country Code</label>
          <Input value={f.countryCode} onChange={txt("countryCode")} placeholder="e.g. RU, CN, IR" className="h-8 text-xs uppercase" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">City</label>
          <Input value={f.city} onChange={txt("city")} placeholder="e.g. Moscow, Beijing" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">ISP</label>
          <Input value={f.isp} onChange={txt("isp")} placeholder="e.g. AS12345 Hosting Provider" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">ASN</label>
          <Input value={f.asn} onChange={txt("asn")} placeholder="e.g. AS12345" className="h-8 text-xs font-mono" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">ASN Org</label>
          <Input value={f.asnOrg} onChange={txt("asnOrg")} placeholder="e.g. DIGITALOCEAN-ASN" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Latitude</label>
          <Input type="number" step="any" value={f.lat} onChange={txt("lat")} placeholder="e.g. 55.7558" className="h-8 text-xs font-mono" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Longitude</label>
          <Input type="number" step="any" value={f.lng} onChange={txt("lng")} placeholder="e.g. 37.6176" className="h-8 text-xs font-mono" />
        </div>
      </div>

      {/* ── Cloud & Service ── */}
      <SH icon={Activity} label="Cloud & Service Classification" />
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Cloud Provider</label>
          <Input value={f.cloudProvider} onChange={txt("cloudProvider")} placeholder="e.g. AWS, Azure, DigitalOcean" className="h-8 text-xs" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Service Category</label>
          <Input value={f.serviceCategory} onChange={txt("serviceCategory")} placeholder="e.g. VPS, Bulletproof Hosting" className="h-8 text-xs" />
        </div>
      </div>

      {/* ── Risk Impact ── */}
      <SH icon={AlertTriangle} label="Risk & Impact" />
      <div className="space-y-3">
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Sectors at Risk <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.sectorsAtRisk} onChange={txt("sectorsAtRisk")} className="h-8 text-xs"
            placeholder="Finance, Healthcare, Energy, Government..." />
          <TagPreview value={f.sectorsAtRisk} cls="bg-orange-500/10 border-orange-500/20 text-orange-400" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Platforms at Risk <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.platformsAtRisk} onChange={txt("platformsAtRisk")} className="h-8 text-xs"
            placeholder="Windows, Linux, macOS, Android..." />
          <TagPreview value={f.platformsAtRisk} cls="bg-blue-500/10 border-blue-500/20 text-blue-400" />
        </div>
        <div>
          <label className="text-xs font-medium text-muted-foreground block mb-1">Organisations at Risk <span className="opacity-60 font-normal">(comma-separated)</span></label>
          <Input value={f.orgsAtRisk} onChange={txt("orgsAtRisk")} className="h-8 text-xs"
            placeholder="Fortune 500, US Federal, NATO members..." />
        </div>
      </div>

    </div>
  );
}

/* ── Add Modal ──────────────────────────────────────────────────────────── */
function AddC2Modal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState<C2Form>(EMPTY_FORM);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.ip.trim()) { setErr("IP address is required"); return; }
    setLoading(true); setErr("");
    try {
      await apiFetch<any>(`${BASE}/api/threat-intel/c2-servers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "C2 server added", description: `${f.ip} added to C2 infrastructure database.` });
      onDone(); onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to add C2 server");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Plus className="w-4 h-4 text-primary" /> Add C2 Server
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <C2FormFields f={f} setF={setF} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}
              Add C2 Server
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── Edit Modal ─────────────────────────────────────────────────────────── */
function EditC2Modal({ server, onClose, onDone }: { server: any; onClose: () => void; onDone: (updated: any) => void }) {
  const [f, setF] = useState<C2Form>(() => c2ToForm(server));
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!f.ip.trim()) { setErr("IP address is required"); return; }
    setLoading(true); setErr("");
    try {
      const updated = await apiFetch<any>(`${BASE}/api/threat-intel/c2-servers/${server.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formToPayload(f)),
      });
      toast({ title: "C2 server updated" });
      onDone(updated); onClose();
    } catch (ex: any) {
      setErr(ex.message ?? "Failed to update C2 server");
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-start justify-center p-4 overflow-y-auto">
      <div className="bg-card border border-border rounded-2xl w-full max-w-2xl p-6 space-y-4 my-8">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold flex items-center gap-2">
            <Pencil className="w-4 h-4 text-primary" /> Edit C2 Server
          </h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-3 py-2 rounded-lg bg-muted/30 border border-border text-xs text-muted-foreground font-mono">
          ID #{server.id} — {server.ip}{server.port ? `:${server.port}` : ""}
        </div>
        <form onSubmit={submit} className="space-y-4">
          <C2FormFields f={f} setF={setF} />
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">
              {loading && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1.5" />}
              Save Changes
            </Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ── View Sheet ─────────────────────────────────────────────────────────── */
function ViewC2Sheet({ server, onClose, onEdit }: { server: any; onClose: () => void; onEdit: () => void }) {
  function Row({ label, value, mono = false }: { label: string; value: any; mono?: boolean }) {
    if (!value && value !== 0) return null;
    return (
      <div className="flex items-start gap-2">
        <span className="text-[10px] text-muted-foreground w-28 shrink-0 pt-0.5">{label}</span>
        <span className={cn("text-xs flex-1 break-all", mono && "font-mono")}>{String(value)}</span>
      </div>
    );
  }

  function TagRow({ label, items, cls }: { label: string; items: string[]; cls: string }) {
    if (!items?.length) return null;
    return (
      <div className="flex items-start gap-2">
        <span className="text-[10px] text-muted-foreground w-28 shrink-0 pt-1">{label}</span>
        <div className="flex flex-wrap gap-1">
          {items.map(t => <span key={t} className={cn("text-[10px] px-1.5 py-0.5 rounded border", cls)}>{t}</span>)}
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end">
      <div className="bg-card border-l border-border w-full max-w-lg h-full overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-card border-b border-border px-6 py-4 flex items-start justify-between gap-3 z-10">
          <div className="min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Radio className="w-4 h-4 text-red-400 shrink-0" />
              <h2 className="font-bold text-base font-mono truncate">{server.ip}{server.port ? `:${server.port}` : ""}</h2>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold",
                server.isActive ? "text-green-400 bg-green-500/10 border-green-500/20" : "text-muted-foreground bg-muted border-border")}>
                {server.isActive ? "Active" : "Inactive"}
              </span>
              {server.malwareFamily && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{server.malwareFamily}</span>
              )}
              {server.confidence != null && (
                <span className="text-[10px] text-muted-foreground">Confidence: {server.confidence}%</span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button size="sm" variant="outline" onClick={onEdit} className="h-7 text-xs">
              <Pencil className="w-3 h-3 mr-1" />Edit
            </Button>
            <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5">

          {/* Network */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Network</p>
            <div className="space-y-2">
              <Row label="IP Address" value={server.ip} mono />
              <Row label="Port" value={server.port} mono />
              <Row label="Domain" value={server.domain} mono />
              <Row label="Source" value={server.source} />
              <Row label="Confidence" value={server.confidence != null ? `${server.confidence}%` : null} />
            </div>
          </div>

          {/* Attribution */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Attribution</p>
            <div className="space-y-2">
              <Row label="Malware Family" value={server.malwareFamily} />
              <Row label="Threat Actor" value={server.actorName} />
              <TagRow label="Tags" items={server.tags ?? []} cls="bg-muted border-border text-muted-foreground" />
            </div>
          </div>

          {/* Geolocation */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Geolocation</p>
            <div className="space-y-2">
              <Row label="Country" value={[server.country, server.countryCode].filter(Boolean).join(" / ")} />
              <Row label="City" value={server.city} />
              <Row label="ISP" value={server.isp} />
              <Row label="ASN" value={server.asn} mono />
              <Row label="ASN Org" value={server.asnOrg} />
              {(server.lat != null && server.lng != null) && (
                <Row label="Coordinates" value={`${server.lat}, ${server.lng}`} mono />
              )}
            </div>
          </div>

          {/* Cloud */}
          {(server.cloudProvider || server.serviceCategory) && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Cloud & Service</p>
              <div className="space-y-2">
                <Row label="Cloud Provider" value={server.cloudProvider} />
                <Row label="Service Category" value={server.serviceCategory} />
              </div>
            </div>
          )}

          {/* Risk Impact */}
          {(server.sectorsAtRisk?.length > 0 || server.platformsAtRisk?.length > 0 || server.orgsAtRisk?.length > 0) && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Risk Impact</p>
              <div className="space-y-2">
                <TagRow label="Sectors at Risk" items={server.sectorsAtRisk ?? []} cls="bg-orange-500/10 border-orange-500/20 text-orange-400" />
                <TagRow label="Platforms at Risk" items={server.platformsAtRisk ?? []} cls="bg-blue-500/10 border-blue-500/20 text-blue-400" />
                <TagRow label="Orgs at Risk" items={server.orgsAtRisk ?? []} cls="bg-muted border-border text-muted-foreground" />
              </div>
            </div>
          )}

          {/* Timestamps */}
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 pb-1 border-b border-border/50">Timeline</p>
            <div className="space-y-2">
              <Row label="Discovered At" value={server.discoveredAt ? new Date(server.discoveredAt).toLocaleString() : null} />
              <Row label="Last Seen At" value={server.lastSeenAt ? new Date(server.lastSeenAt).toLocaleString() : null} />
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}

/* ── Main Page ──────────────────────────────────────────────────────────── */
export default function ThreatIntelC2Page() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();

  const [q, setQ] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const [editServer, setEditServer] = useState<any | null>(null);
  const [viewServer, setViewServer] = useState<any | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{ id: number; ip: string } | null>(null);
  const [overrides, setOverrides] = useState<Record<number, any>>({});
  const L = 50;

  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-c2", q, active, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q);
      if (active) p.set("active", active);
      return apiFetch<any>(`${BASE}/api/threat-intel/c2-servers?${p}`);
    },
    staleTime: 30_000,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiFetch<any>(`${BASE}/api/threat-intel/c2-servers/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["ti-c2"] });
      toast({ title: "C2 server deleted" });
      setConfirmDelete(null);
    },
    onError: () => toast({ title: "Failed to delete", variant: "destructive" }),
  });

  function afterEdit(updated: any) {
    setOverrides(o => ({ ...o, [updated.id]: updated }));
    qc.invalidateQueries({ queryKey: ["ti-c2"] });
    if (viewServer?.id === updated.id) setViewServer(updated);
  }

  function afterAdd() {
    setOverrides({});
    qc.invalidateQueries({ queryKey: ["ti-c2"] });
  }

  const rawServers: any[] = data?.c2Servers ?? [];
  const servers = rawServers.map(s => overrides[s.id] ? { ...s, ...overrides[s.id] } : s);
  const total = data?.total ?? 0;
  const hasFilters = !!(q || active);

  return (
    <div className="p-6 space-y-4">

      {/* ── Modals ── */}
      {showAdd && <AddC2Modal onClose={() => setShowAdd(false)} onDone={afterAdd} />}
      {editServer && (
        <EditC2Modal server={editServer} onClose={() => setEditServer(null)}
          onDone={updated => { afterEdit(updated); setEditServer(null); }} />
      )}
      {viewServer && (
        <ViewC2Sheet server={viewServer} onClose={() => setViewServer(null)}
          onEdit={() => { setEditServer(viewServer); setViewServer(null); }} />
      )}
      {confirmDelete && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-sm space-y-4">
            <h2 className="text-base font-semibold">Delete C2 Server?</h2>
            <p className="text-sm text-muted-foreground">
              Permanently remove <strong className="text-foreground font-mono">{confirmDelete.ip}</strong> from the C2 infrastructure database.
            </p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button size="sm" variant="destructive"
                onClick={() => deleteMutation.mutate(confirmDelete.id)}
                disabled={deleteMutation.isPending}>
                {deleteMutation.isPending && <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" />}
                Delete
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Radio className="w-5 h-5 text-red-400" />
          <div>
            <h1 className="text-xl font-bold">C2 Infrastructure</h1>
            <p className="text-xs text-muted-foreground">{total.toLocaleString()} C2 servers tracked</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button size="sm" onClick={() => setShowAdd(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" />Add C2 Server
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-wrap gap-2">
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <Input placeholder="Search IP, domain, actor…" value={q}
            onChange={e => { setQ(e.target.value); setPage(0); }}
            className="h-8 pl-8 text-xs" />
        </div>
        <Select value={active || "all"} onValueChange={v => { setActive(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-36 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All status</SelectItem>
            <SelectItem value="true">Active only</SelectItem>
          </SelectContent>
        </Select>
        {hasFilters && (
          <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
            onClick={() => { setQ(""); setActive(""); setPage(0); }}>
            <X className="w-3.5 h-3.5 mr-1" />Clear
          </Button>
        )}
      </div>

      {/* ── Table ── */}
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="text-left p-3 font-medium text-muted-foreground">IP : Port</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Malware Family</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">Country</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">Actor</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Discovered</th>
              {isAdmin && <th className="text-right p-3 font-medium text-muted-foreground">Actions</th>}
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({ length: 10 }).map((_, i) => (
                <tr key={i} className="border-b border-border/30">
                  <td colSpan={7} className="p-3"><Skeleton className="h-4 w-full" /></td>
                </tr>
              ))
              : servers.map((s: any) => (
                <tr key={s.id}
                  className="border-b border-border/30 hover:bg-muted/20 transition-colors cursor-pointer"
                  onClick={() => setViewServer(s)}>
                  <td className="p-3">
                    <div>
                      <span className="font-mono text-red-400">{s.ip}</span>
                      {s.port && <span className="font-mono text-muted-foreground">:{s.port}</span>}
                    </div>
                    {s.domain && <div className="text-[10px] text-muted-foreground font-mono truncate max-w-[160px]">{s.domain}</div>}
                  </td>
                  <td className="p-3 text-muted-foreground hidden sm:table-cell">
                    {s.malwareFamily
                      ? <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{s.malwareFamily}</span>
                      : <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="p-3 hidden md:table-cell">
                    {s.country
                      ? <span className="flex items-center gap-1 text-muted-foreground"><Globe className="w-3 h-3" />{s.country}</span>
                      : <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="p-3 text-muted-foreground/80 hidden lg:table-cell truncate max-w-[120px]">
                    {s.actorName ?? <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="p-3">
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold",
                      s.isActive ? "text-green-400 bg-green-500/10 border-green-500/20" : "text-muted-foreground bg-muted border-border")}>
                      {s.isActive ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="p-3 text-muted-foreground/60 hidden sm:table-cell">
                    {s.discoveredAt ? new Date(s.discoveredAt).toLocaleDateString() : "—"}
                  </td>
                  {isAdmin && (
                    <td className="p-3 text-right" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => setViewServer(s)}
                          className="p-1.5 rounded hover:bg-muted/40 text-muted-foreground hover:text-foreground transition-colors" title="View">
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setEditServer(s)}
                          className="p-1.5 rounded hover:bg-blue-500/10 text-muted-foreground hover:text-blue-400 transition-colors" title="Edit">
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button onClick={() => setConfirmDelete({ id: s.id, ip: s.ip })}
                          className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors" title="Delete">
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
          </tbody>
        </table>
        {!isLoading && servers.length === 0 && (
          <div className="p-8 text-center text-sm text-muted-foreground">
            {hasFilters
              ? "No C2 servers match your search."
              : "No C2 servers tracked yet. Add one manually or run an AbuseIPDB / ThreatFox feed refresh."}
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
