import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Eye, RefreshCw, AlertTriangle, Calendar, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const RISK_META: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/25",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/25",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  low:      "text-green-400 bg-green-500/10 border-green-500/25",
};

export default function ThreatIntelDarkWebPage() {
  const { user } = useAuth();
  const [page, setPage] = useState(0);
  const L = 20;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-dark-web", page],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/dark-web?limit=${L}&offset=${page * L}`),
    staleTime: 60_000,
  });

  const mentions: any[] = data?.mentions ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Eye className="w-5 h-5 text-purple-400" />
          <div>
            <h1 className="text-xl font-bold">Dark Web Monitoring</h1>
            <p className="text-xs text-muted-foreground">{total.toLocaleString()} mentions for your organization</p>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>

      {!isLoading && mentions.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 gap-4 text-center">
          <div className="p-4 rounded-2xl bg-green-500/10 border border-green-500/20">
            <Shield className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-green-400">No dark web mentions found</p>
            <p className="text-xs text-muted-foreground mt-1 max-w-xs">
              No references to your organization have been detected on dark web forums, paste sites, or data leak marketplaces.
            </p>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {isLoading
          ? Array.from({length:5}).map((_,i) => <Skeleton key={i} className="h-32 rounded-xl" />)
          : mentions.map((m: any) => (
            <div key={m.id} className={cn("border rounded-xl p-4 space-y-2", m.riskLevel === "critical" ? "border-red-500/30 bg-red-500/5" : m.riskLevel === "high" ? "border-orange-500/30 bg-orange-500/5" : "border-border bg-card")}>
              <div className="flex items-start justify-between gap-3">
                <div className="space-y-1 min-w-0">
                  <p className="font-semibold text-sm">{m.sourceType ?? "Unknown source"}</p>
                  {m.url && <p className="text-[10px] font-mono text-muted-foreground truncate max-w-xs">{m.url}</p>}
                </div>
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  {m.riskLevel && <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", RISK_META[m.riskLevel] ?? RISK_META.low)}>{m.riskLevel}</span>}
                  {m.detectedAt && (
                    <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
                      <Calendar className="w-2.5 h-2.5" />{new Date(m.detectedAt).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              {m.snippet && (
                <div className="bg-muted/30 border border-border/40 rounded-lg p-2.5">
                  <p className="text-xs text-muted-foreground italic">"{m.snippet}"</p>
                </div>
              )}
              {m.keywords?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {(m.keywords as string[]).map((k: string) => <span key={k} className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">{k}</span>)}
                </div>
              )}
              {m.isVerified && <p className="text-[10px] text-green-400/70 flex items-center gap-1"><AlertTriangle className="w-2.5 h-2.5" />Verified mention</p>}
            </div>
          ))
        }
      </div>

      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{page*L+1}–{Math.min((page+1)*L, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page===0} onClick={() => setPage(p=>p-1)}>Prev</Button>
            <Button size="sm" variant="outline" disabled={(page+1)*L>=total} onClick={() => setPage(p=>p+1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
