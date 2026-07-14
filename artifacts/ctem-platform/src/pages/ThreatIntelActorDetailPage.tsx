import { useQuery } from "@tanstack/react-query";
import { useRoute, useLocation } from "wouter";
import { Users, ChevronLeft, Globe, Activity, Target, Layers, Bug, AlertTriangle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function ThreatIntelActorDetailPage() {
  const [, navigate] = useLocation();
  const [match, params] = useRoute("/threat-intel/actors/:id");
  const actorId = params?.id ? parseInt(params.id) : null;

  const { data, isLoading, error } = useQuery({
    queryKey: ["ti-actor", actorId],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/actors/${actorId}`),
    enabled: actorId !== null,
    staleTime: 60_000,
  });

  if (!match || !actorId) return null;

  if (isLoading) return (
    <div className="p-6 space-y-4">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-24 w-full" />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4"><Skeleton className="h-48" /><Skeleton className="h-48" /></div>
    </div>
  );

  if (error || !data) return (
    <div className="p-6 text-center py-16">
      <p className="text-muted-foreground">Actor not found or TI module not enabled.</p>
      <Button variant="outline" size="sm" className="mt-3" onClick={() => navigate("/threat-intel/actors")}>← Back to Actors</Button>
    </div>
  );

  const a = data;
  const ttps: any[] = data.ttps ?? [];
  const campaigns: any[] = data.campaigns ?? [];
  const malware: any[] = data.malware ?? [];

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate("/threat-intel/actors")} className="text-muted-foreground hover:text-foreground transition-colors">
          <ChevronLeft className="w-5 h-5" />
        </button>
        <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20">
          <Users className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold">{a.name}</h1>
          {a.aliases?.length > 0 && <p className="text-xs text-muted-foreground">aka {(a.aliases as string[]).join(", ")}</p>}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <div className={cn("text-2xl font-bold tabular-nums", Number(a.riskScore) >= 70 ? "text-red-400" : Number(a.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400")}>
            {Math.round(Number(a.riskScore ?? 0))}
          </div>
          <span className="text-xs text-muted-foreground">risk</span>
        </div>
      </div>

      {/* Meta badges */}
      <div className="flex flex-wrap gap-2">
        {a.mitreId && <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono">{a.mitreId}</span>}
        {a.country && <span className="text-xs px-2 py-0.5 rounded-full bg-muted border border-border text-muted-foreground"><Globe className="w-3 h-3 inline mr-1" />{a.country}</span>}
        {a.motivation && <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-400 capitalize">{a.motivation}</span>}
        {a.isActive && <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-400"><Activity className="w-3 h-3 inline mr-1" />Active</span>}
        <span className="text-xs px-2 py-0.5 rounded-full bg-muted border border-border text-muted-foreground">Source: {a.source}</span>
      </div>

      {a.description && (
        <div className="bg-muted/20 border border-border/40 rounded-xl p-4">
          <p className="text-sm text-muted-foreground leading-relaxed">{a.description}</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Target info */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <h2 className="text-sm font-semibold flex items-center gap-2"><Target className="w-4 h-4 text-orange-400" />Targeting</h2>
          {a.targetIndustries?.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-1.5">Industries</p>
              <div className="flex flex-wrap gap-1.5">
                {(a.targetIndustries as string[]).map((ind: string) => (
                  <span key={ind} className="text-[11px] px-2 py-0.5 rounded-full bg-muted border border-border text-foreground">{ind}</span>
                ))}
              </div>
            </div>
          )}
          {a.targetCountries?.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-1.5">Countries</p>
              <div className="flex flex-wrap gap-1.5">
                {(a.targetCountries as string[]).map((c: string) => (
                  <span key={c} className="text-[11px] px-2 py-0.5 rounded-full bg-muted border border-border text-foreground">{c}</span>
                ))}
              </div>
            </div>
          )}
          {!a.targetIndustries?.length && !a.targetCountries?.length && (
            <p className="text-xs text-muted-foreground">No targeting data available</p>
          )}
        </div>

        {/* TTPs */}
        <div className="bg-card border border-border rounded-xl p-4 space-y-3">
          <h2 className="text-sm font-semibold flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" />TTPs ({ttps.length})</h2>
          {ttps.length === 0 ? (
            <p className="text-xs text-muted-foreground">No TTP data available</p>
          ) : (
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {ttps.slice(0,20).map((t: any) => (
                <div key={t.id} className="flex items-center justify-between text-xs py-1.5 border-b border-border/30">
                  <div>
                    <span className="font-mono text-blue-400 text-[10px] mr-2">{t.mitreId}</span>
                    <span className="text-foreground">{t.name}</span>
                  </div>
                  <span className="text-muted-foreground/60 text-[10px]">{t.tactic}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Linked campaigns */}
        {campaigns.length > 0 && (
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <h2 className="text-sm font-semibold flex items-center gap-2"><Layers className="w-4 h-4 text-blue-400" />Campaigns ({campaigns.length})</h2>
            <div className="space-y-1.5">
              {campaigns.map((c: any) => (
                <div key={c.id} className="flex items-center justify-between p-2 rounded-lg bg-blue-500/5 border border-blue-500/15">
                  <div>
                    <p className="text-xs font-medium">{c.name}</p>
                    {c.status && <p className="text-[10px] text-muted-foreground capitalize">{c.status}</p>}
                  </div>
                  {c.startDate && <p className="text-[10px] text-muted-foreground/60">{new Date(c.startDate).getFullYear()}</p>}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Linked malware */}
        {malware.length > 0 && (
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <h2 className="text-sm font-semibold flex items-center gap-2"><Bug className="w-4 h-4 text-yellow-400" />Malware ({malware.length})</h2>
            <div className="flex flex-wrap gap-1.5">
              {malware.map((m: any) => (
                <span key={m.id} className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">{m.name}</span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
