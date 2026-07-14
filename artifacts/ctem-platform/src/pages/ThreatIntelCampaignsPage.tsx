import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Layers, Search, RefreshCw, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const STATUS_META: Record<string, string> = {
  active:   "text-green-400 bg-green-500/10 border-green-500/20",
  dormant:  "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  ended:    "text-muted-foreground bg-muted border-border",
};

export default function ThreatIntelCampaignsPage() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-campaigns", q, status, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q); if (status) p.set("status", status);
      return apiFetch<any>(`${BASE}/api/threat-intel/campaigns?${p}`);
    },
    staleTime: 30_000,
  });

  const campaigns: any[] = data?.campaigns ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Layers className="w-5 h-5 text-blue-400" />
          <div><h1 className="text-xl font-bold">Campaigns</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} tracked campaigns</p></div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" /><Input placeholder="Search campaigns…" value={q} onChange={e => { setQ(e.target.value); setPage(0); }} className="h-8 pl-8 text-xs" /></div>
        <Select value={status || "all"} onValueChange={v => { setStatus(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent><SelectItem value="all">All statuses</SelectItem>{["active","dormant","ended"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent>
        </Select>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {isLoading
          ? Array.from({length:6}).map((_,i) => <Skeleton key={i} className="h-40 rounded-xl" />)
          : campaigns.map((c: any) => (
            <div key={c.id} className="bg-card border border-border rounded-xl p-4 space-y-2.5 hover:border-blue-500/30 transition-colors">
              <div className="flex items-start justify-between gap-2">
                <p className="font-semibold text-sm leading-tight">{c.name}</p>
                <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize shrink-0", STATUS_META[c.status] ?? STATUS_META.ended)}>{c.status ?? "unknown"}</span>
              </div>
              {c.actorName && <p className="text-xs text-muted-foreground">Actor: <span className="text-foreground">{c.actorName}</span></p>}
              {c.description && <p className="text-xs text-muted-foreground line-clamp-2">{c.description}</p>}
              {(c.targetIndustries?.length > 0) && (
                <div className="flex flex-wrap gap-1">
                  {(c.targetIndustries as string[]).slice(0,3).map((ind: string) => (
                    <span key={ind} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{ind}</span>
                  ))}
                </div>
              )}
              {(c.startDate || c.endDate) && (
                <p className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
                  <Calendar className="w-3 h-3" />
                  {c.startDate ? new Date(c.startDate).getFullYear() : "?"} {c.endDate ? `→ ${new Date(c.endDate).getFullYear()}` : "→ present"}
                </p>
              )}
              {c.mitreId && <p className="text-[10px] font-mono text-blue-400/70">{c.mitreId}</p>}
            </div>
          ))
        }
      </div>
      {!isLoading && campaigns.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">No campaigns loaded. Run a MITRE ATT&CK feed refresh.</div>
      )}
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
