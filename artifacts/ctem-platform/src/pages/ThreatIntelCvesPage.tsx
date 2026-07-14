import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Search, RefreshCw, ExternalLink, X } from "lucide-react";
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
  none:     "text-muted-foreground bg-muted border-border",
};
const EXPLOIT: Record<string, string> = {
  active:    "text-red-400 bg-red-500/10 border-red-500/20",
  confirmed: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  potential: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  unknown:   "text-muted-foreground bg-muted border-border",
};

export default function ThreatIntelCvesPage() {
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [kev, setKev] = useState("");
  const [exploited, setExploited] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [page, setPage] = useState(0);
  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-cves", q, severity, kev, exploited, dateFrom, dateTo, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q)        p.set("q", q);
      if (severity) p.set("severity", severity);
      if (kev)      p.set("kev", kev);
      if (exploited) p.set("exploited", exploited);
      if (dateFrom) p.set("dateFrom", dateFrom);
      if (dateTo)   p.set("dateTo", dateTo);
      return apiFetch<any>(`${BASE}/api/threat-intel/cves?${p}`);
    },
    staleTime: 30_000,
  });

  const cves: any[] = data?.cves ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400" />
          <div><h1 className="text-xl font-bold">CVE Intelligence</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} CVEs in database</p></div>
        </div>
        <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" /><Input placeholder="CVE-2024-XXXX or keyword…" value={q} onChange={e => { setQ(e.target.value); setPage(0); }} className="h-8 pl-8 text-xs font-mono" /></div>
        <Select value={severity || "all"} onValueChange={v => { setSeverity(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem>{["critical","high","medium","low"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select>
        <Select value={kev || "all"} onValueChange={v => { setKev(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-28 text-xs"><SelectValue placeholder="KEV" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="true">KEV only</SelectItem></SelectContent></Select>
        <Select value={exploited || "all"} onValueChange={v => { setExploited(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-36 text-xs"><SelectValue placeholder="Exploitation" /></SelectTrigger><SelectContent><SelectItem value="all">All</SelectItem><SelectItem value="true">Actively exploited</SelectItem></SelectContent></Select>
        <div className="flex items-center gap-1">
          <Input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(0); }} className="h-8 w-36 text-xs" title="Updated from" />
          <span className="text-xs text-muted-foreground">–</span>
          <Input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(0); }} className="h-8 w-36 text-xs" title="Updated to" />
          {(dateFrom || dateTo) && (
            <button onClick={() => { setDateFrom(""); setDateTo(""); setPage(0); }} className="text-muted-foreground hover:text-foreground ml-0.5 shrink-0"><X className="w-3.5 h-3.5" /></button>
          )}
        </div>
      </div>
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="text-left p-3 font-medium text-muted-foreground">CVE ID</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Severity</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">CVSS</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">EPSS</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Exploitation</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">KEV</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden xl:table-cell">Description</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({length:10}).map((_,i) => (
                <tr key={i} className="border-b border-border/30"><td colSpan={7} className="p-3"><Skeleton className="h-4 w-full" /></td></tr>
              ))
              : cves.map((c: any) => (
                <tr key={c.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                  <td className="p-3">
                    <a href={`https://nvd.nist.gov/vuln/detail/${c.cveId}`} target="_blank" rel="noopener noreferrer" className="font-mono text-amber-400 hover:underline flex items-center gap-1">
                      {c.cveId} <ExternalLink className="w-3 h-3 opacity-50" />
                    </a>
                  </td>
                  <td className="p-3"><span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", SEV[c.severity] ?? SEV.none)}>{c.severity ?? "N/A"}</span></td>
                  <td className="p-3 font-mono text-muted-foreground hidden sm:table-cell">{c.cvss != null ? Number(c.cvss).toFixed(1) : "—"}</td>
                  <td className="p-3 font-mono text-muted-foreground hidden md:table-cell">{c.epss != null ? `${(Number(c.epss)*100).toFixed(2)}%` : "—"}</td>
                  <td className="p-3"><span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", EXPLOIT[c.exploitationStatus ?? "unknown"] ?? EXPLOIT.unknown)}>{c.exploitationStatus ?? "unknown"}</span></td>
                  <td className="p-3 hidden lg:table-cell">
                    {c.isKev && <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-400 font-bold">KEV</span>}
                  </td>
                  <td className="p-3 text-muted-foreground max-w-xs truncate hidden xl:table-cell">{c.description?.slice(0,100) ?? "—"}</td>
                </tr>
              ))
            }
          </tbody>
        </table>
        {!isLoading && cves.length === 0 && (
          <div className="p-8 text-center text-sm text-muted-foreground">No CVEs found. Run an NVD feed refresh to load CVE intelligence.</div>
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
