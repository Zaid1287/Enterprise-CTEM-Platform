import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Newspaper, Search, RefreshCw, ExternalLink, Calendar } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const SEV: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/25",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/25",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  low:      "text-green-400 bg-green-500/10 border-green-500/25",
};

export default function ThreatIntelNewsPage() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const L = 20;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-news", q, severity, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q); if (severity) p.set("severity", severity);
      return apiFetch<any>(`${BASE}/api/threat-intel/news?${p}`);
    },
    staleTime: 60_000,
  });

  const news: any[] = data?.news ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Newspaper className="w-5 h-5 text-blue-400" />
          <div><h1 className="text-xl font-bold">Threat News</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} intel articles</p></div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" /><Input placeholder="Search news…" value={q} onChange={e => { setQ(e.target.value); setPage(0); }} className="h-8 pl-8 text-xs" /></div>
        <Select value={severity || "all"} onValueChange={v => { setSeverity(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem>{["critical","high","medium","low"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select>
      </div>
      <div className="space-y-3">
        {isLoading
          ? Array.from({length:5}).map((_,i) => <Skeleton key={i} className="h-28 rounded-xl" />)
          : news.map((n: any) => (
            <div key={n.id} className="bg-card border border-border rounded-xl p-4 space-y-2 hover:border-blue-500/30 transition-colors">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0 space-y-1">
                  <p className="font-semibold text-sm leading-snug">{n.title}</p>
                  {n.source && <p className="text-[10px] text-muted-foreground/60">{n.source}</p>}
                </div>
                <div className="flex flex-col items-end gap-1.5 shrink-0">
                  {n.severity && <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", SEV[n.severity] ?? SEV.low)}>{n.severity}</span>}
                  {n.createdAt && (
                    <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
                      <Calendar className="w-2.5 h-2.5" />
                      {new Date(n.createdAt).toLocaleDateString()}
                    </span>
                  )}
                </div>
              </div>
              {n.summary && <p className="text-xs text-muted-foreground line-clamp-2">{n.summary}</p>}
              {n.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {(n.tags as string[]).slice(0,5).map((t: string) => <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">{t}</span>)}
                </div>
              )}
              {n.url && (
                <a href={n.url} target="_blank" rel="noopener noreferrer" className="text-[11px] text-primary hover:underline flex items-center gap-1">
                  Read full article <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          ))
        }
      </div>
      {!isLoading && news.length === 0 && (
        <div className="text-center py-12 text-sm text-muted-foreground">No threat news available. Data is populated via the TI news feed sources.</div>
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
