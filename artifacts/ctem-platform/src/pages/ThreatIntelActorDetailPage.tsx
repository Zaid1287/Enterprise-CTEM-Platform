import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRoute, useLocation } from "wouter";
import {
  Users, ChevronLeft, Globe, Activity, Target, Layers, Bug, AlertTriangle,
  Loader2, Shield, Clock, Info, Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const TABS = [
  { id: "overview",        label: "Overview",        icon: Info },
  { id: "ttps",            label: "TTPs",             icon: Target },
  { id: "malware",         label: "Malware",          icon: Bug },
  { id: "campaigns",       label: "Campaigns",        icon: Layers },
  { id: "infrastructure",  label: "Infrastructure",   icon: Globe },
  { id: "timeline",        label: "Timeline",         icon: Clock },
] as const;
type TabId = typeof TABS[number]["id"];

export default function ThreatIntelActorDetailPage() {
  const [, navigate] = useLocation();
  const [match, params] = useRoute("/threat-intel/actors/:id");
  const actorId = params?.id ? parseInt(params.id) : null;
  const [activeTab, setActiveTab] = useState<TabId>("overview");

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
      <Skeleton className="h-10 w-full" />
      <Skeleton className="h-64 w-full" />
    </div>
  );

  if (error || !data) return (
    <div className="p-6 text-center py-16">
      <p className="text-muted-foreground">Actor not found or TI module not enabled.</p>
      <Button variant="outline" size="sm" className="mt-3" onClick={() => navigate("/threat-intel/actors")}>← Back to Actors</Button>
    </div>
  );

  const a = data;
  const ttps: any[]      = data.ttps       ?? [];
  const campaigns: any[] = data.campaigns  ?? [];
  const malware: any[]   = data.malware    ?? [];
  const iocs: any[]      = data.iocs       ?? [];

  const tactics = [...new Set(ttps.map((t: any) => t.tactic).filter(Boolean))];

  return (
    <div className="p-6 space-y-5">
      {/* Back + header */}
      <div className="flex items-center gap-3">
        <button onClick={() => navigate("/threat-intel/actors")} className="text-muted-foreground hover:text-foreground transition-colors">
          <ChevronLeft className="w-5 h-5" />
        </button>
        <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20">
          <Users className="w-5 h-5 text-purple-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold">{a.name}</h1>
          {(a.aliases as string[] | undefined)?.length > 0 && (
            <p className="text-xs text-muted-foreground">aka {(a.aliases as string[]).join(", ")}</p>
          )}
        </div>
        <div className="ml-auto flex items-center gap-2 text-right">
          <div>
            <p className={cn("text-3xl font-black tabular-nums", Number(a.riskScore) >= 70 ? "text-red-400" : Number(a.riskScore) >= 40 ? "text-orange-400" : "text-yellow-400")}>
              {Math.round(Number(a.riskScore ?? 0))}
            </p>
            <p className="text-[10px] text-muted-foreground">risk score</p>
          </div>
        </div>
      </div>

      {/* Meta badges */}
      <div className="flex flex-wrap gap-2">
        {a.mitreId   && <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono">{a.mitreId}</span>}
        {a.country   && <span className="text-xs px-2 py-0.5 rounded-full bg-muted border border-border text-muted-foreground"><Globe className="w-3 h-3 inline mr-1" />{a.country}</span>}
        {a.motivation && <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-400 capitalize">{a.motivation}</span>}
        {a.isActive  && <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/10 border border-green-500/20 text-green-400"><Activity className="w-3 h-3 inline mr-1" />Active</span>}
        <span className="text-xs px-2 py-0.5 rounded-full bg-muted border border-border text-muted-foreground">Source: {a.source}</span>
        {ttps.length  > 0 && <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400">{ttps.length} TTPs</span>}
        {campaigns.length > 0 && <span className="text-xs px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400">{campaigns.length} campaigns</span>}
        {malware.length > 0 && <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-300">{malware.length} malware</span>}
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border overflow-x-auto no-scrollbar">
        {TABS.map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium transition-colors whitespace-nowrap border-b-2 -mb-px",
                activeTab === tab.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-border",
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Tab panels */}
      {activeTab === "overview" && (
        <div className="space-y-4">
          {a.description && (
            <div className="bg-muted/20 border border-border/40 rounded-xl p-4">
              <p className="text-sm text-muted-foreground leading-relaxed">{a.description}</p>
            </div>
          )}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Key stats */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
              <h2 className="text-sm font-semibold flex items-center gap-2"><Info className="w-4 h-4 text-blue-400" />Key Stats</h2>
              <div className="space-y-2 text-xs">
                {[
                  { label: "Country", value: a.country ?? "Unknown" },
                  { label: "Motivation", value: a.motivation ?? "Unknown" },
                  { label: "Status", value: a.isActive ? "Active" : "Inactive" },
                  { label: "First seen", value: a.firstSeen ? new Date(a.firstSeen).toLocaleDateString() : "Unknown" },
                  { label: "Last seen",  value: a.lastSeen  ? new Date(a.lastSeen).toLocaleDateString()  : "Unknown" },
                  { label: "Source", value: a.source ?? "—" },
                ].map(r => (
                  <div key={r.label} className="flex justify-between gap-2">
                    <span className="text-muted-foreground">{r.label}</span>
                    <span className="font-medium text-right">{r.value}</span>
                  </div>
                ))}
              </div>
            </div>
            {/* Targeting */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3 lg:col-span-2">
              <h2 className="text-sm font-semibold flex items-center gap-2"><Target className="w-4 h-4 text-orange-400" />Targeting</h2>
              {(a.targetIndustries as string[] | undefined)?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5">Industries</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(a.targetIndustries as string[]).map(ind => (
                      <span key={ind} className="text-[11px] px-2 py-0.5 rounded-full bg-muted border border-border text-foreground">{ind}</span>
                    ))}
                  </div>
                </div>
              )}
              {(a.targetCountries as string[] | undefined)?.length > 0 && (
                <div>
                  <p className="text-xs font-medium text-muted-foreground mb-1.5">Countries</p>
                  <div className="flex flex-wrap gap-1.5">
                    {(a.targetCountries as string[]).map(c => (
                      <span key={c} className="text-[11px] px-2 py-0.5 rounded-full bg-muted border border-border text-foreground">{c}</span>
                    ))}
                  </div>
                </div>
              )}
              {!(a.targetIndustries as string[] | undefined)?.length && !(a.targetCountries as string[] | undefined)?.length && (
                <p className="text-xs text-muted-foreground">No targeting data available</p>
              )}
            </div>
          </div>
          {/* Detection & mitigation summary */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-card border border-border rounded-xl p-4 space-y-2">
              <h2 className="text-sm font-semibold flex items-center gap-2"><Eye className="w-4 h-4 text-blue-400" />Detection Summary</h2>
              <div className="space-y-1.5 text-xs text-muted-foreground">
                <p>• {ttps.length > 0 ? `${ttps.length} MITRE ATT&CK techniques documented` : "No TTPs loaded yet"}</p>
                {tactics.length > 0 && <p>• Tactics: {tactics.slice(0, 4).join(", ")}{tactics.length > 4 ? ` +${tactics.length - 4} more` : ""}</p>}
                {malware.length > 0 && <p>• {malware.length} associated malware families tracked</p>}
                {iocs.length > 0 && <p>• {iocs.length} IOCs available for detection</p>}
              </div>
            </div>
            <div className="bg-card border border-border rounded-xl p-4 space-y-2">
              <h2 className="text-sm font-semibold flex items-center gap-2"><Shield className="w-4 h-4 text-green-400" />Mitigation Summary</h2>
              <div className="space-y-1.5 text-xs text-muted-foreground">
                <p>• Enforce MFA across all privileged accounts</p>
                <p>• Apply network segmentation to limit lateral movement</p>
                {(a.motivation as string | undefined)?.includes("financial") && <p>• Monitor for data exfiltration (ransomware group)</p>}
                {(a.country as string | undefined) && <p>• Geo-block traffic from known {a.country} exit nodes</p>}
                <p>• Deploy EDR with behavioral detection for known TTPs</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === "ttps" && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-sm font-semibold flex items-center gap-2"><Target className="w-4 h-4 text-yellow-400" />TTPs ({ttps.length})</h2>
          </div>
          {ttps.length === 0 ? (
            <p className="text-xs text-muted-foreground p-6 text-center">No TTP data available for this actor</p>
          ) : (
            <>
              {/* Tactic breakdown */}
              <div className="p-4 border-b border-border flex flex-wrap gap-2">
                {tactics.map(tactic => (
                  <span key={tactic} className="text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 capitalize">{tactic}</span>
                ))}
              </div>
              <table className="w-full text-xs">
                <thead className="bg-muted/30 border-b border-border">
                  <tr>
                    <th className="text-left p-3 font-medium text-muted-foreground">ID</th>
                    <th className="text-left p-3 font-medium text-muted-foreground">Name</th>
                    <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">Tactic</th>
                    <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">Platform</th>
                  </tr>
                </thead>
                <tbody>
                  {ttps.map((t: any) => (
                    <tr key={t.id} className="border-b border-border/30 hover:bg-muted/20">
                      <td className="p-3 font-mono text-blue-400 text-[10px]">{t.mitreId}</td>
                      <td className="p-3 font-medium">{t.name}</td>
                      <td className="p-3 text-muted-foreground capitalize hidden md:table-cell">{t.tactic}</td>
                      <td className="p-3 text-muted-foreground/60 text-[10px] hidden lg:table-cell">{(t.platforms as string[] | undefined)?.join(", ") ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {activeTab === "malware" && (
        <div className="space-y-3">
          {malware.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-8">No malware families associated with this actor</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {malware.map((m: any) => (
                <div key={m.id} className="bg-card border border-border rounded-xl p-4 space-y-2">
                  <div className="flex items-start justify-between">
                    <p className="text-sm font-semibold">{m.name}</p>
                    <span className={cn(
                      "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize",
                      m.malwareType === "ransomware" ? "text-red-400 bg-red-500/10 border-red-500/20" :
                      m.malwareType === "trojan" ? "text-orange-400 bg-orange-500/10 border-orange-500/20" :
                      "text-muted-foreground bg-muted border-border",
                    )}>
                      {m.malwareType ?? "malware"}
                    </span>
                  </div>
                  {m.description && <p className="text-[11px] text-muted-foreground line-clamp-3">{m.description}</p>}
                  {(m.aliases as string[] | undefined)?.length > 0 && (
                    <p className="text-[10px] text-muted-foreground">aka: {(m.aliases as string[]).join(", ")}</p>
                  )}
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-muted-foreground/60">Source: {m.source}</span>
                    <span className={cn("font-bold tabular-nums", Number(m.riskScore) >= 70 ? "text-red-400" : "text-orange-400")}>
                      Risk {Math.round(Number(m.riskScore ?? 0))}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "campaigns" && (
        <div className="space-y-3">
          {campaigns.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-8">No campaigns associated with this actor</p>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {campaigns.map((c: any) => (
                <div key={c.id} className="bg-card border border-border rounded-xl p-4 space-y-2">
                  <div className="flex items-start justify-between">
                    <p className="text-sm font-semibold">{c.name}</p>
                    {c.status && (
                      <span className={cn(
                        "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize",
                        c.status === "active" ? "text-red-400 bg-red-500/10 border-red-500/20" : "text-muted-foreground bg-muted border-border",
                      )}>
                        {c.status}
                      </span>
                    )}
                  </div>
                  {c.description && <p className="text-[11px] text-muted-foreground line-clamp-3">{c.description}</p>}
                  <div className="flex gap-4 text-[10px] text-muted-foreground/60">
                    {c.startDate && <span>Started: {new Date(c.startDate).toLocaleDateString()}</span>}
                    {c.endDate   && <span>Ended: {new Date(c.endDate).toLocaleDateString()}</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "infrastructure" && (
        <div className="space-y-3">
          {iocs.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-8">No infrastructure IOCs loaded for this actor</p>
          ) : (
            <div className="border border-border rounded-xl overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-muted/30 border-b border-border">
                  <tr>
                    <th className="text-left p-3 font-medium text-muted-foreground">Type</th>
                    <th className="text-left p-3 font-medium text-muted-foreground">Value</th>
                    <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Severity</th>
                    <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">First Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {iocs.map((ioc: any) => (
                    <tr key={ioc.id} className="border-b border-border/30 hover:bg-muted/20">
                      <td className="p-3"><span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted border border-border uppercase">{ioc.type}</span></td>
                      <td className="p-3 font-mono text-[11px] max-w-[180px] truncate">{ioc.value}</td>
                      <td className="p-3 hidden sm:table-cell">
                        <span className={cn(
                          "capitalize font-semibold text-[10px]",
                          ioc.severity === "critical" ? "text-red-400" : ioc.severity === "high" ? "text-orange-400" : "text-yellow-400",
                        )}>
                          {ioc.severity}
                        </span>
                      </td>
                      <td className="p-3 text-muted-foreground/60 hidden md:table-cell">
                        {ioc.firstSeen ? new Date(ioc.firstSeen).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === "timeline" && (
        <div className="space-y-3">
          {campaigns.length === 0 && ttps.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-8">No timeline events available</p>
          ) : (
            <div className="relative pl-6 border-l border-border space-y-4">
              {[
                ...campaigns.filter(c => c.startDate).map(c => ({ date: c.startDate, type: "campaign", label: `Campaign: ${c.name}`, status: c.status })),
                a.firstSeen ? [{ date: a.firstSeen, type: "actor", label: `Actor first observed`, status: "info" }] : [],
                a.lastSeen  ? [{ date: a.lastSeen,  type: "actor", label: `Actor last observed`,  status: "info" }] : [],
              ].flat().sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime())
               .map((ev: any, i: number) => (
                <div key={i} className="relative">
                  <div className={cn(
                    "absolute -left-[25px] w-3 h-3 rounded-full border-2 border-background",
                    ev.type === "campaign" ? "bg-blue-400" : "bg-purple-400",
                  )} />
                  <div className="bg-card border border-border rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <p className="text-xs font-medium">{ev.label}</p>
                      <p className="text-[10px] text-muted-foreground">{new Date(ev.date).toLocaleDateString()}</p>
                    </div>
                    {ev.status && <p className="text-[10px] text-muted-foreground capitalize mt-0.5">{ev.status}</p>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
