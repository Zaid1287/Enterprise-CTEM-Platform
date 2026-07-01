import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Globe2, Search, ChevronRight, Loader2,
  ShieldCheck, ShieldOff, Server, AlertTriangle, Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";

const BASE = import.meta.env.BASE_URL?.replace(/\/$/, "") ?? "";

interface TenantAiRow {
  id: number; name: string; slug: string; plan: string; isActive: boolean;
  isEnabled: boolean; endpoints: number; critical: number; high: number;
  noAuth: number; scans: number; activeScans: number; lastScanAt: string | null;
}

const RISK_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-green-400",
};

export default function AiMapperAdminPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [search, setSearch] = useState("");

  const { data: rows = [], isLoading } = useQuery<TenantAiRow[]>({
    queryKey: ["ai-mapper-admin-overview"],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/admin/overview`),
  });

  const toggleMutation = useMutation({
    mutationFn: ({ tenantId, isEnabled }: { tenantId: number; isEnabled: boolean }) =>
      apiFetch(`${BASE}/api/ai-mapper/client/${tenantId}/module`, {
        method: "PATCH",
        body: JSON.stringify({ isEnabled }),
      }),
    onSuccess: (_d, { isEnabled }) => {
      qc.invalidateQueries({ queryKey: ["ai-mapper-admin-overview"] });
      toast({ title: isEnabled ? "AI Mapper enabled" : "AI Mapper disabled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const filtered = rows.filter(r =>
    r.name.toLowerCase().includes(search.toLowerCase()) ||
    r.slug.toLowerCase().includes(search.toLowerCase())
  );

  const totalEnabled  = rows.filter(r => r.isEnabled).length;
  const totalEndpoints = rows.reduce((s, r) => s + r.endpoints, 0);
  const totalCritical  = rows.reduce((s, r) => s + r.critical,  0);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center">
            <Globe2 className="w-4.5 h-4.5 text-violet-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold">AI Mapper — Admin</h1>
            <p className="text-sm text-muted-foreground">Manage AI Mapper module across all tenants</p>
          </div>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Module Enabled",    value: `${totalEnabled} / ${rows.length}`, icon: ShieldCheck, color: "text-violet-400" },
          { label: "Total AI Endpoints", value: totalEndpoints,                    icon: Server,       color: "text-blue-400" },
          { label: "Critical Exposure",  value: totalCritical,                     icon: AlertTriangle, color: "text-red-400" },
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

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search tenants…"
          className="pl-9"
        />
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tenant</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">AI Mapper</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Endpoints</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Scans</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Scan</th>
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-10 text-center text-muted-foreground text-sm">No tenants found</td></tr>
              )}
              {filtered.map(t => (
                <tr key={t.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium">{t.name}</div>
                    <div className="text-xs text-muted-foreground">{t.slug}</div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMutation.mutate({ tenantId: t.id, isEnabled: !t.isEnabled })}
                      disabled={toggleMutation.isPending}
                      className={cn(
                        "text-xs px-2.5 py-1 rounded-full font-medium border transition-colors cursor-pointer inline-flex items-center gap-1.5",
                        t.isEnabled
                          ? "bg-violet-500/10 text-violet-400 border-violet-500/25 hover:bg-violet-500/20"
                          : "bg-muted/50 text-muted-foreground border-border hover:bg-muted"
                      )}
                    >
                      {t.isEnabled ? <><ShieldCheck className="w-3 h-3" />Enabled</> : <><ShieldOff className="w-3 h-3" />Disabled</>}
                    </button>
                  </td>
                  <td className="px-4 py-3 tabular-nums text-right">{t.endpoints}</td>
                  <td className="px-4 py-3 tabular-nums text-right">
                    {t.critical > 0
                      ? <span className="text-red-400 font-semibold">{t.critical}</span>
                      : <span className="text-muted-foreground/40">—</span>}
                  </td>
                  <td className="px-4 py-3 tabular-nums text-right">
                    <span className="inline-flex items-center gap-1">
                      {t.activeScans > 0 && <Activity className="w-3 h-3 text-green-400 animate-pulse" />}
                      {t.scans}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {t.lastScanAt ? formatDistanceToNow(new Date(t.lastScanAt), { addSuffix: true }) : "—"}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => navigate(`/ai-mapper/clients/${t.id}`)}
                      >
                        View <ChevronRight className="w-3.5 h-3.5 ml-1" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
