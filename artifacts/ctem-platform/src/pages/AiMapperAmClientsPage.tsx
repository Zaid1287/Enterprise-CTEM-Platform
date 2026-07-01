import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Users, ChevronRight, ShieldCheck, ShieldOff,
  Server, AlertTriangle, Activity, Radar,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";

const BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

interface ClientAiRow {
  id: number; name: string; slug: string; plan: string;
  isEnabled: boolean; endpoints: number; critical: number; high: number;
  noAuth: number; scans: number; activeScans: number; lastScanAt: string | null;
}

export default function AiMapperAmClientsPage() {
  const [, navigate] = useLocation();

  const { data: clients = [], isLoading } = useQuery<ClientAiRow[]>({
    queryKey: ["ai-mapper-am-clients"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/am-clients`),
  });

  const enabledCount   = clients.filter(c => c.isEnabled).length;
  const totalEndpoints = clients.reduce((s, c) => s + c.endpoints, 0);
  const totalCritical  = clients.reduce((s, c) => s + c.critical,  0);

  return (
    <div className="p-6 space-y-6 w-full">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
          <Users className="w-4.5 h-4.5 text-violet-400" />
        </div>
        <div>
          <h1 className="text-xl font-bold">AI Mapper — My Clients</h1>
          <p className="text-sm text-muted-foreground">
            AI exposure summary across all your assigned clients
          </p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Clients with AI Mapper", value: `${enabledCount} / ${clients.length}`, icon: ShieldCheck, color: "text-violet-400" },
          { label: "Total AI Endpoints",     value: totalEndpoints,                        icon: Server,       color: "text-blue-400"   },
          { label: "Critical Findings",      value: totalCritical,                         icon: AlertTriangle, color: "text-red-400"   },
        ].map(s => (
          <div key={s.label} className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <div className={cn("w-8 h-8 rounded-lg bg-card border border-border flex items-center justify-center", s.color)}>
              <s.icon className="w-4 h-4" />
            </div>
            <div>
              <p className="text-2xl font-bold">{s.value}</p>
              <p className="text-xs text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Client grid */}
      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {[...Array(6)].map((_, i) => <Skeleton key={i} className="h-44 rounded-xl" />)}
        </div>
      ) : clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
          <Users className="w-10 h-10 text-muted-foreground/30 mb-3" />
          <p className="text-muted-foreground">No clients assigned yet.</p>
          <p className="text-sm text-muted-foreground/60 mt-1">Ask your administrator to assign clients to you.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {clients.map(c => (
            <div
              key={c.id}
              className={cn(
                "bg-card border rounded-xl p-5 flex flex-col gap-4 transition-colors",
                c.isEnabled ? "border-border hover:border-violet-500/40" : "border-border/60 opacity-80"
              )}
            >
              {/* Client header */}
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="font-semibold truncate">{c.name}</p>
                  <p className="text-xs text-muted-foreground">{c.slug}</p>
                </div>
                <div className={cn(
                  "shrink-0 text-xs px-2 py-0.5 rounded-full font-medium border inline-flex items-center gap-1",
                  c.isEnabled
                    ? "bg-violet-500/10 text-violet-400 border-violet-500/25"
                    : "bg-muted/50 text-muted-foreground border-border"
                )}>
                  {c.isEnabled ? <ShieldCheck className="w-3 h-3" /> : <ShieldOff className="w-3 h-3" />}
                  {c.isEnabled ? "Active" : "Inactive"}
                </div>
              </div>

              {/* Stats */}
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className="bg-muted/30 rounded-lg py-2">
                  <p className="text-lg font-bold tabular-nums">{c.endpoints}</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Endpoints</p>
                </div>
                <div className="bg-muted/30 rounded-lg py-2">
                  <p className={cn("text-lg font-bold tabular-nums", c.critical > 0 ? "text-red-400" : "")}>{c.critical}</p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Critical</p>
                </div>
                <div className="bg-muted/30 rounded-lg py-2">
                  <p className="text-lg font-bold tabular-nums inline-flex items-center gap-1">
                    {c.activeScans > 0 && <Activity className="w-3 h-3 text-green-400 animate-pulse" />}
                    {c.scans}
                  </p>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Scans</p>
                </div>
              </div>

              {/* Last scan */}
              {c.lastScanAt && (
                <p className="text-xs text-muted-foreground inline-flex items-center gap-1">
                  <Radar className="w-3 h-3" />
                  Last scan {formatDistanceToNow(new Date(c.lastScanAt), { addSuffix: true })}
                </p>
              )}

              {/* Action */}
              <Button
                variant={c.isEnabled ? "default" : "outline"}
                size="sm"
                className="w-full mt-auto"
                onClick={() => navigate(`/ai-mapper/clients/${c.id}`)}
              >
                {c.isEnabled ? "View AI Mapper" : "View (Module Inactive)"}
                <ChevronRight className="w-3.5 h-3.5 ml-1" />
              </Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
