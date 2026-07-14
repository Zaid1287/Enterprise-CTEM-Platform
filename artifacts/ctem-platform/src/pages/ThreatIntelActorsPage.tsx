import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Users, Search, RefreshCw, ExternalLink, Plus, Trash2, X } from "lucide-react";
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
  "financial":      "text-green-400 bg-green-500/10 border-green-500/20",
  "espionage":      "text-blue-400 bg-blue-500/10 border-blue-500/20",
  "disruption":     "text-red-400 bg-red-500/10 border-red-500/20",
  "hacktivism":     "text-purple-400 bg-purple-500/10 border-purple-500/20",
  "state-sponsored":"text-orange-400 bg-orange-500/10 border-orange-500/20",
};

function CreateActorDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [name, setName] = useState("");
  const [country, setCountry] = useState("");
  const [motivation, setMotivation] = useState("");
  const [aliases, setAliases] = useState("");

  const create = useMutation({
    mutationFn: () => apiFetch<{ actor: any }>(`${BASE}/api/threat-intel/actors`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name,
        country: country || undefined,
        motivation: motivation || undefined,
        aliases: aliases ? aliases.split(",").map(s => s.trim()).filter(Boolean) : [],
        source: "manual",
        isActive: true,
      }),
    }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ["ti-actors"] });
      toast({ title: "Actor created", description: `${data.actor?.name ?? name} added to threat actor database.` });
      onClose();
    },
    onError: (err: any) => toast({ title: "Failed to create actor", description: err?.message ?? "Unknown error", variant: "destructive" }),
  });

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
      <div className="bg-card border border-border rounded-xl p-6 w-full max-w-md space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold">Add Threat Actor</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs font-medium text-muted-foreground">Name *</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. APT29" className="mt-1 h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Country</label>
            <Input value={country} onChange={e => setCountry(e.target.value)} placeholder="e.g. Russia" className="mt-1 h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Motivation</label>
            <Select value={motivation || "none"} onValueChange={v => setMotivation(v === "none" ? "" : v)}>
              <SelectTrigger className="mt-1 h-8 text-xs"><SelectValue placeholder="Select motivation" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Not specified</SelectItem>
                {["financial","espionage","disruption","hacktivism","state-sponsored"].map(m => (
                  <SelectItem key={m} value={m} className="capitalize">{m}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground">Aliases (comma-separated)</label>
            <Input value={aliases} onChange={e => setAliases(e.target.value)} placeholder="e.g. Cozy Bear, The Dukes" className="mt-1 h-8 text-xs" />
          </div>
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <Button size="sm" variant="outline" onClick={onClose}>Cancel</Button>
          <Button size="sm" onClick={() => create.mutate()} disabled={!name.trim() || create.isPending}>
            {create.isPending ? "Creating…" : "Create Actor"}
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function ThreatIntelActorsPage() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [country, setCountry] = useState("");
  const [motivation, setMotivation] = useState("");
  const [page, setPage] = useState(0);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<{ id: number; name: string } | null>(null);
  const L = 50;

  const isAdmin = user?.role === "admin" || user?.role === "super_admin";

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-actors", q, country, motivation, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q); if (country) p.set("country", country); if (motivation) p.set("motivation", motivation);
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

  const actors: any[] = data?.actors ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      {showCreate && <CreateActorDialog onClose={() => setShowCreate(false)} />}

      {confirmDelete && (
        <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
          <div className="bg-card border border-border rounded-xl p-6 w-full max-w-sm space-y-4">
            <h2 className="text-base font-semibold">Delete Threat Actor?</h2>
            <p className="text-sm text-muted-foreground">This will permanently remove <strong>{confirmDelete.name}</strong> and all associated data.</p>
            <div className="flex justify-end gap-2">
              <Button size="sm" variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
              <Button size="sm" variant="destructive" onClick={() => deleteActor.mutate(confirmDelete.id)} disabled={deleteActor.isPending}>
                {deleteActor.isPending ? "Deleting…" : "Delete"}
              </Button>
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Users className="w-5 h-5 text-purple-400" />
          <div><h1 className="text-xl font-bold">Threat Actors</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} known threat actors</p></div>
        </div>
        <div className="flex items-center gap-2">
          {isAdmin && (
            <Button size="sm" onClick={() => setShowCreate(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" />Add Actor
            </Button>
          )}
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        <div className="relative w-60"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" /><Input placeholder="Search actors…" value={q} onChange={e => { setQ(e.target.value); setPage(0); }} className="h-8 pl-8 text-xs" /></div>
        <Select value={motivation || "all"} onValueChange={v => { setMotivation(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-44 text-xs"><SelectValue placeholder="Motivation" /></SelectTrigger>
          <SelectContent><SelectItem value="all">All motivations</SelectItem>{["financial","espionage","disruption","hacktivism","state-sponsored"].map(m => <SelectItem key={m} value={m} className="capitalize">{m}</SelectItem>)}</SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading
          ? Array.from({length:9}).map((_,i) => <Skeleton key={i} className="h-36 rounded-xl" />)
          : actors.map((a: any) => (
            <div
              key={a.id}
              className="bg-card border border-border rounded-xl p-4 hover:border-primary/40 transition-all group space-y-2.5 relative"
            >
              {isAdmin && (
                <button
                  onClick={e => { e.stopPropagation(); setConfirmDelete({ id: a.id, name: a.name }); }}
                  className="absolute top-3 right-3 text-muted-foreground/30 hover:text-red-400 transition-colors"
                  title={`Delete ${a.name}`}
                  aria-label={`Delete actor ${a.name}`}
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
              <button
                onClick={() => navigate(`/threat-intel/actors/${a.id}`)}
                className="w-full text-left space-y-2"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-semibold text-sm group-hover:text-primary transition-colors truncate">{a.name}</p>
                    {a.aliases?.length > 0 && <p className="text-[10px] text-muted-foreground truncate">aka {(a.aliases as string[]).slice(0,2).join(", ")}</p>}
                  </div>
                  <div className={cn("text-lg font-bold tabular-nums shrink-0", Number(a.riskScore) >= 70 ? "text-red-400" : Number(a.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400")}>
                    {Math.round(Number(a.riskScore ?? 0))}
                  </div>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {a.country && <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{a.country}</span>}
                  {a.motivation && <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium capitalize", MOT_COLOR[a.motivation] ?? "text-muted-foreground bg-muted border-border")}>{a.motivation}</span>}
                  {a.isActive && <span className="text-[10px] px-1.5 py-0.5 rounded bg-green-500/10 border border-green-500/20 text-green-400">Active</span>}
                </div>
                {a.targetIndustries?.length > 0 && (
                  <p className="text-[10px] text-muted-foreground truncate">
                    Targets: {(a.targetIndustries as string[]).slice(0,3).join(", ")}
                    {(a.targetIndustries as string[]).length > 3 && ` +${(a.targetIndustries as string[]).length - 3}`}
                  </p>
                )}
                <p className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
                  <ExternalLink className="w-2.5 h-2.5" /> View full profile
                </p>
              </button>
            </div>
          ))
        }
      </div>
      {!isLoading && actors.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">No threat actors loaded. Run a MITRE ATT&CK feed refresh.</div>
      )}
      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Showing {page*L+1}–{Math.min((page+1)*L, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page===0} onClick={() => setPage(p=>p-1)}>Prev</Button>
            <Button size="sm" variant="outline" disabled={(page+1)*L>=total} onClick={() => setPage(p=>p+1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
