import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Plus, Trash2, Search, Loader2, X, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const SEV: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/25",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/25",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/25",
  low:      "text-green-400 bg-green-500/10 border-green-500/25",
};

function AddModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [f, setF] = useState({ type: "ip", value: "", source: "manual", severity: "medium", description: "" });
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const { toast } = useToast();
  async function submit(e: React.FormEvent) {
    e.preventDefault(); setLoading(true); setErr("");
    try {
      await apiFetch(`${BASE}/api/threat-intel/iocs`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(f) });
      toast({ title: "IOC added" }); onDone(); onClose();
    } catch (e: any) { setErr(e.message ?? "Error"); } finally { setLoading(false); }
  }
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl p-5 w-full max-w-md shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2"><Crosshair className="w-4 h-4 text-orange-400" />Add IOC</h2>
          <button onClick={onClose}><X className="w-4 h-4 text-muted-foreground" /></button>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground block mb-1">Type</label>
              <Select value={f.type} onValueChange={v => setF(x => ({ ...x, type: v }))}>
                <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>{["ip","domain","url","hash","email","cidr"].map(t => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground block mb-1">Severity</label>
              <Select value={f.severity} onValueChange={v => setF(x => ({ ...x, severity: v }))}>
                <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>{["critical","high","medium","low"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Value *</label>
            <Input value={f.value} onChange={e => setF(x => ({ ...x, value: e.target.value }))} placeholder="1.2.3.4 or malicious.com" className="h-8 text-xs font-mono" required />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Source</label>
            <Input value={f.source} onChange={e => setF(x => ({ ...x, source: e.target.value }))} className="h-8 text-xs" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground block mb-1">Description</label>
            <Input value={f.description} onChange={e => setF(x => ({ ...x, description: e.target.value }))} className="h-8 text-xs" />
          </div>
          {err && <p className="text-xs text-destructive">{err}</p>}
          <div className="flex gap-2 pt-1">
            <Button type="submit" size="sm" disabled={loading} className="flex-1">{loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "Add IOC"}</Button>
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default function ThreatIntelIocsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const qc = useQueryClient();
  const { toast } = useToast();
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [sev, setSev] = useState("");
  const [page, setPage] = useState(0);
  const [showAdd, setShowAdd] = useState(false);
  const L = 50;

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-iocs", q, type, sev, page],
    queryFn: () => {
      const p = new URLSearchParams({ limit: String(L), offset: String(page * L) });
      if (q) p.set("q", q); if (type) p.set("type", type); if (sev) p.set("severity", sev);
      return apiFetch<any>(`${BASE}/api/threat-intel/iocs?${p}`);
    },
    staleTime: 30_000,
  });

  async function del(id: number) {
    try { await apiFetch(`${BASE}/api/threat-intel/iocs/${id}`, { method: "DELETE" }); toast({ title: "IOC deleted" }); qc.invalidateQueries({ queryKey: ["ti-iocs"] }); }
    catch { toast({ title: "Delete failed", variant: "destructive" }); }
  }

  const iocs: any[] = data?.iocs ?? [];
  const total = data?.total ?? 0;

  return (
    <div className="p-6 space-y-4">
      {showAdd && <AddModal onClose={() => setShowAdd(false)} onDone={() => refetch()} />}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Crosshair className="w-5 h-5 text-orange-400" />
          <div><h1 className="text-xl font-bold">IOC Database</h1><p className="text-xs text-muted-foreground">{total.toLocaleString()} indicators</p></div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {isAdmin && <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="w-3.5 h-3.5 mr-1" />Add IOC</Button>}
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <div className="relative w-60"><Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" /><Input placeholder="Search…" value={q} onChange={e => { setQ(e.target.value); setPage(0); }} className="h-8 pl-8 text-xs" /></div>
        <Select value={type || "all"} onValueChange={v => { setType(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-28 text-xs"><SelectValue placeholder="Type" /></SelectTrigger><SelectContent><SelectItem value="all">All types</SelectItem>{["ip","domain","url","hash","email","cidr"].map(t => <SelectItem key={t} value={t}>{t.toUpperCase()}</SelectItem>)}</SelectContent></Select>
        <Select value={sev || "all"} onValueChange={v => { setSev(v === "all" ? "" : v); setPage(0); }}><SelectTrigger className="h-8 w-32 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger><SelectContent><SelectItem value="all">All severities</SelectItem>{["critical","high","medium","low"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select>
      </div>
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>{["Type","Value","Source","Severity","Score","TLP",""].map((h,i) => <th key={i} className={cn("text-left p-3 font-medium text-muted-foreground", i >= 2 && i <= 2 ? "hidden md:table-cell" : i >= 4 ? "hidden sm:table-cell" : "")}>{h}</th>)}</tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({length:8}).map((_,i) => <tr key={i} className="border-b border-border/30"><td colSpan={7} className="p-3"><Skeleton className="h-4 w-full" /></td></tr>)
              : iocs.map((ioc: any) => (
                <tr key={ioc.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                  <td className="p-3"><span className="text-[10px] px-1.5 py-0.5 rounded font-mono border border-border bg-muted/40 uppercase">{ioc.type}</span></td>
                  <td className="p-3 font-mono text-[11px] max-w-[200px] truncate">{ioc.value}</td>
                  <td className="p-3 text-muted-foreground hidden md:table-cell">{ioc.source}</td>
                  <td className="p-3"><span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize", SEV[ioc.severity] ?? SEV.low)}>{ioc.severity}</span></td>
                  <td className="p-3 font-mono text-muted-foreground hidden sm:table-cell">{Math.round(ioc.threatScore ?? 0)}</td>
                  <td className="p-3 hidden sm:table-cell"><span className="text-[9px] px-1 py-0.5 rounded bg-muted border border-border text-muted-foreground uppercase font-mono">{ioc.tlp ?? "white"}</span></td>
                  <td className="p-3 text-right">{isAdmin && <button onClick={() => del(ioc.id)} className="text-muted-foreground/40 hover:text-destructive transition-colors p-1"><Trash2 className="w-3.5 h-3.5" /></button>}</td>
                </tr>
              ))
            }
          </tbody>
        </table>
        {!isLoading && iocs.length === 0 && <div className="p-8 text-center text-sm text-muted-foreground">No IOCs found. Run a feed refresh or adjust filters.</div>}
      </div>
      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Showing {page*L+1}–{Math.min((page+1)*L, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page===0} onClick={() => setPage(p=>p-1)}>Prev</Button>
            <Button size="sm" variant="outline" disabled={(page+1)*L>=total} onClick={() => setPage(p=>p+1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
