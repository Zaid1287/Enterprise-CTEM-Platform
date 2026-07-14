import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Activity, RefreshCw, Loader2, AlertTriangle, Link2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const EXPLOIT_META: Record<string, string> = {
  active:    "text-red-400 bg-red-500/10 border-red-500/20",
  confirmed: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  potential: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  unknown:   "text-muted-foreground bg-muted border-border",
};

export default function ThreatIntelCorrelationsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const { toast } = useToast();
  const [correlating, setCorrelating] = useState(false);
  const [page, setPage] = useState(0);
  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-correlations", page],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/correlations?limit=${L}&offset=${page * L}`),
    staleTime: 30_000,
  });

  async function triggerCorrelate() {
    if (!isAdmin) return;
    setCorrelating(true);
    try {
      await apiFetch(`${BASE}/api/threat-intel/correlate`, { method: "POST" });
      toast({ title: "Correlation triggered", description: "Running in background — refresh in a few seconds." });
      setTimeout(() => { setCorrelating(false); refetch(); }, 5000);
    } catch { toast({ title: "Failed to trigger", variant: "destructive" }); setCorrelating(false); }
  }

  const corrs: any[] = data?.correlations ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-green-400" />
          <div>
            <h1 className="text-xl font-bold">Asset Correlations</h1>
            <p className="text-xs text-muted-foreground">{total.toLocaleString()} findings correlated against TI database</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {isAdmin && (
            <Button size="sm" onClick={triggerCorrelate} disabled={correlating}>
              {correlating ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Correlating…</> : <><Activity className="w-3.5 h-3.5 mr-1.5" />Run Correlation</>}
            </Button>
          )}
        </div>
      </div>

      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="text-left p-3 font-medium text-muted-foreground">Finding</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Actors</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">IOCs</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">CVEs</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Exploitation</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Score</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden xl:table-cell">Correlated</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({length:8}).map((_,i) => (
                <tr key={i} className="border-b border-border/30"><td colSpan={7} className="p-3"><Skeleton className="h-4 w-full" /></td></tr>
              ))
              : corrs.map((c: any) => (
                <tr key={c.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                  <td className="p-3">
                    <a href={`/findings/${c.findingId}`} className="flex items-center gap-1 text-primary hover:underline">
                      <Link2 className="w-3 h-3 opacity-50" /> #{c.findingId}
                    </a>
                  </td>
                  <td className="p-3 hidden sm:table-cell text-muted-foreground">{(c.matchedActors as any[])?.length ?? 0}</td>
                  <td className="p-3 hidden md:table-cell text-muted-foreground">{(c.matchedIocs as any[])?.length ?? 0}</td>
                  <td className="p-3 hidden lg:table-cell text-muted-foreground">{(c.matchedCves as any[])?.length ?? 0}</td>
                  <td className="p-3">
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", EXPLOIT_META[c.exploitationStatus] ?? EXPLOIT_META.unknown)}>
                      {c.exploitationStatus ?? "unknown"}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={cn("text-sm font-bold tabular-nums", c.threatScore >= 70 ? "text-red-400" : c.threatScore >= 40 ? "text-orange-400" : "text-yellow-400")}>
                      {Math.round(c.threatScore ?? 0)}
                    </span>
                  </td>
                  <td className="p-3 text-muted-foreground/60 hidden xl:table-cell">
                    {c.correlatedAt ? new Date(c.correlatedAt).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))
            }
          </tbody>
        </table>
        {!isLoading && corrs.length === 0 && (
          <div className="p-8 text-center space-y-3">
            <Activity className="w-8 h-8 mx-auto opacity-20" />
            <p className="text-sm text-muted-foreground">No correlations yet.</p>
            {isAdmin && (
              <Button size="sm" onClick={triggerCorrelate} disabled={correlating}>
                {correlating ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : null}
                Run Correlation Now
              </Button>
            )}
          </div>
        )}
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
