import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Radio, Search, RefreshCw, Globe, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function ThreatIntelC2Page() {
  const [country, setCountry] = useState("");
  const [active, setActive] = useState("");
  const [page, setPage] = useState(0);
  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-c2", country, active, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (country) p.set("country", country); if (active) p.set("active", active);
      return apiFetch<any>(`${BASE}/api/threat-intel/c2-servers?${p}`);
    },
    staleTime: 30_000,
  });

  const servers: any[] = data?.c2Servers ?? [];
  const total = data?.total ?? 0;
  const countries = [...new Set(servers.map((s: any) => s.country).filter(Boolean))] as string[];

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Radio className="w-5 h-5 text-red-400" />
          <div><h1 className="text-xl font-bold">C2 Infrastructure</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} C2 servers tracked</p></div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <Select value={active || "all"} onValueChange={v => { setActive(v === "all" ? "" : v); setPage(0); }}>
          <SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
          <SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="true">Active only</SelectItem></SelectContent>
        </Select>
      </div>
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="text-left p-3 font-medium text-muted-foreground">IP Address</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Malware Family</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">Country</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">Port</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Status</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Discovered</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({length:10}).map((_,i) => (
                <tr key={i} className="border-b border-border/30">
                  <td colSpan={6} className="p-3"><Skeleton className="h-4 w-full" /></td>
                </tr>
              ))
              : servers.map((s: any) => (
                <tr key={s.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                  <td className="p-3 font-mono text-red-400">{s.ip}</td>
                  <td className="p-3 text-muted-foreground hidden sm:table-cell">{s.malwareFamily ?? "Unknown"}</td>
                  <td className="p-3 hidden md:table-cell">
                    {s.country && <span className="flex items-center gap-1 text-muted-foreground"><Globe className="w-3 h-3" />{s.country}</span>}
                  </td>
                  <td className="p-3 font-mono text-muted-foreground hidden lg:table-cell">{s.port ?? "—"}</td>
                  <td className="p-3">
                    <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold", s.isActive ? "text-green-400 bg-green-500/10 border-green-500/20" : "text-muted-foreground bg-muted border-border")}>
                      {s.isActive ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="p-3 text-muted-foreground/60 hidden sm:table-cell">
                    {s.discoveredAt ? new Date(s.discoveredAt).toLocaleDateString() : "—"}
                  </td>
                </tr>
              ))
            }
          </tbody>
        </table>
        {!isLoading && servers.length === 0 && (
          <div className="p-8 text-center text-sm text-muted-foreground">No C2 servers loaded. Run an AbuseIPDB or ThreatFox feed refresh.</div>
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
