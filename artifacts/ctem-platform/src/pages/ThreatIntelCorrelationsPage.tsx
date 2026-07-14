import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, RefreshCw, Loader2, Link2, ChevronDown, ChevronUp,
  Users, Bug, Crosshair, Search, Sparkles, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const EXPLOIT_STYLE: Record<string, string> = {
  active:    "text-red-400 bg-red-500/10 border-red-500/20",
  confirmed: "text-orange-400 bg-orange-500/10 border-orange-500/20",
  potential: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
  unknown:   "text-muted-foreground bg-muted border-border",
};

const SEV_STYLE: Record<string, string> = {
  critical: "text-red-400",
  high:     "text-orange-400",
  medium:   "text-yellow-400",
  low:      "text-green-400",
  info:     "text-muted-foreground",
};

/* ── AI explanation panel (shown inside expanded row) ───────────────────── */
function AiExplanation({ correlation }: { correlation: any }) {
  const [loading, setLoading] = useState(false);
  const [explanation, setExplanation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const getExplanation = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await apiFetch<{ explanation?: string; error?: string }>(
        `${BASE}/api/ai/explain-finding`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            findingId: correlation.findingId,
            context: {
              correlatedActors: (correlation.matchedActors as any[])?.map((a: any) => a.name),
              exploitationStatus: correlation.exploitationStatus,
              threatScore: correlation.threatScore,
              correlationBasis: correlation.correlationBasis,
            },
          }),
        }
      );
      setExplanation(res.explanation ?? res.error ?? "No explanation available.");
    } catch {
      setError("AI service unavailable — configure OPENAI_API_KEY to enable.");
    } finally {
      setLoading(false);
    }
  }, [correlation]);

  if (explanation) {
    return (
      <div className="mt-2 p-3 bg-purple-500/5 border border-purple-500/20 rounded-lg text-[11px] text-muted-foreground leading-relaxed relative">
        <div className="flex items-center gap-1.5 text-purple-400 font-semibold mb-1.5">
          <Sparkles className="w-3 h-3" /> AI Analysis
        </div>
        <p>{explanation}</p>
        <button onClick={() => setExplanation(null)} className="absolute top-2 right-2 text-muted-foreground/40 hover:text-muted-foreground"><X className="w-3 h-3" /></button>
      </div>
    );
  }
  if (error) return <p className="mt-1 text-[10px] text-destructive/70">{error}</p>;
  return (
    <Button size="sm" variant="ghost" className="mt-1 h-6 text-[10px] text-purple-400 hover:text-purple-300 px-2" onClick={getExplanation} disabled={loading}>
      {loading ? <Loader2 className="w-3 h-3 mr-1 animate-spin" /> : <Sparkles className="w-3 h-3 mr-1" />}
      {loading ? "Analysing…" : "AI Explanation"}
    </Button>
  );
}

/* ── Expand panel ───────────────────────────────────────────────────────── */
function ExpandedRow({ c }: { c: any }) {
  const actors   = (c.matchedActors   as any[]) ?? [];
  const iocs     = (c.matchedIocs     as any[]) ?? [];
  const cves     = (c.matchedCves     as any[]) ?? [];
  const malware  = (c.matchedMalware  as any[]) ?? [];
  const basis    = (c.correlationBasis as string[]) ?? [];

  return (
    <tr className="border-b border-border/30 bg-muted/10">
      <td colSpan={8} className="px-4 py-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-[11px]">
          {actors.length > 0 && (
            <div>
              <p className="font-semibold text-purple-400 flex items-center gap-1 mb-1.5">
                <Users className="w-3 h-3" />Actors ({actors.length})
              </p>
              <div className="space-y-1">
                {actors.slice(0, 3).map((a: any, i: number) => (
                  <div key={i} className="flex items-center justify-between">
                    <a href={`/threat-intel/actors/${a.id}`} className="text-primary hover:underline truncate max-w-[120px]">{a.name}</a>
                    <span className="text-muted-foreground ml-2 shrink-0">{a.country ?? "—"}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {iocs.length > 0 && (
            <div>
              <p className="font-semibold text-orange-400 flex items-center gap-1 mb-1.5">
                <Crosshair className="w-3 h-3" />IOCs ({iocs.length})
              </p>
              <div className="space-y-1">
                {iocs.slice(0, 3).map((ioc: any, i: number) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="text-muted-foreground capitalize">{ioc.type}</span>
                    <span className="font-mono text-[10px] truncate max-w-[120px]">{ioc.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {cves.length > 0 && (
            <div>
              <p className="font-semibold text-red-400 flex items-center gap-1 mb-1.5">CVEs ({cves.length})</p>
              <div className="space-y-1">
                {cves.slice(0, 3).map((cv: any, i: number) => (
                  <div key={i} className="flex items-center gap-2">
                    <span className="font-mono">{cv.cveId}</span>
                    {cv.isKev && <span className="text-[9px] px-1 rounded bg-red-500/20 text-red-400 border border-red-500/30">KEV</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {malware.length > 0 && (
            <div>
              <p className="font-semibold text-yellow-400 flex items-center gap-1 mb-1.5">
                <Bug className="w-3 h-3" />Malware ({malware.length})
              </p>
              <div className="space-y-1">
                {malware.slice(0, 3).map((m: any, i: number) => (
                  <p key={i} className="truncate">{m.name}</p>
                ))}
              </div>
            </div>
          )}
          {basis.length > 0 && (
            <div className="sm:col-span-2 lg:col-span-4">
              <p className="font-semibold text-muted-foreground mb-1">Correlation basis</p>
              <div className="flex flex-wrap gap-1">
                {basis.map((b: string) => (
                  <span key={b} className="text-[10px] px-1.5 py-0.5 rounded bg-muted border border-border text-muted-foreground">
                    {b.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>
          )}
          {/* AI explanation preview */}
          <div className="sm:col-span-2 lg:col-span-4">
            <AiExplanation correlation={c} />
          </div>
        </div>
      </td>
    </tr>
  );
}

/* ── Main page ─────────────────────────────────────────────────────────── */
export default function ThreatIntelCorrelationsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const { toast } = useToast();
  const [correlating, setCorrelating] = useState(false);
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  /* Filters */
  const [exploitFilter, setExploitFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [actorSearch, setActorSearch] = useState("");
  const [assetSearch, setAssetSearch] = useState("");
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

  const allCorrs: any[] = data?.correlations ?? [];
  const total = data?.total ?? 0;

  /* Client-side multi-filter */
  const filtered = allCorrs.filter(c => {
    if (exploitFilter !== "all"  && c.exploitationStatus !== exploitFilter) return false;
    if (severityFilter !== "all" && c.findingSeverity    !== severityFilter) return false;
    if (assetSearch && !String(c.assetName ?? "").toLowerCase().includes(assetSearch.toLowerCase())) return false;
    if (actorSearch) {
      const actors: string[] = (c.matchedActors as any[])?.map((a: any) => (a.name as string).toLowerCase()) ?? [];
      if (!actors.some(n => n.includes(actorSearch.toLowerCase()))) return false;
    }
    return true;
  });

  const hasFilters = exploitFilter !== "all" || severityFilter !== "all" || actorSearch || assetSearch;

  return (
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-green-400" />
          <div>
            <h1 className="text-xl font-bold">Asset Correlations</h1>
            <p className="text-xs text-muted-foreground">
              {total.toLocaleString()} findings correlated against TI database
              {hasFilters && filtered.length !== allCorrs.length && ` · ${filtered.length} shown after filters`}
            </p>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button size="sm" variant="outline" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
          {isAdmin && (
            <Button size="sm" onClick={triggerCorrelate} disabled={correlating}>
              {correlating
                ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Correlating…</>
                : <><Activity className="w-3.5 h-3.5 mr-1.5" />Run Correlation</>}
            </Button>
          )}
        </div>
      </div>

      {/* Filter row */}
      <div className="flex flex-wrap gap-2">
        <Select value={exploitFilter} onValueChange={v => { setExploitFilter(v); setPage(0); }}>
          <SelectTrigger className="h-8 text-xs w-40">
            <SelectValue placeholder="Exploitation" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="confirmed">Confirmed</SelectItem>
            <SelectItem value="potential">Potential</SelectItem>
            <SelectItem value="unknown">Unknown</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={v => { setSeverityFilter(v); setPage(0); }}>
          <SelectTrigger className="h-8 text-xs w-32">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative">
          <Users className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
          <Input
            placeholder="Filter by actor…"
            value={actorSearch}
            onChange={e => { setActorSearch(e.target.value); setPage(0); }}
            className="h-8 pl-7 text-xs w-40"
          />
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
          <Input
            placeholder="Filter by asset…"
            value={assetSearch}
            onChange={e => { setAssetSearch(e.target.value); setPage(0); }}
            className="h-8 pl-7 text-xs w-40"
          />
        </div>
        {hasFilters && (
          <Button size="sm" variant="ghost" className="h-8 text-xs text-muted-foreground"
            onClick={() => { setExploitFilter("all"); setSeverityFilter("all"); setActorSearch(""); setAssetSearch(""); }}>
            <X className="w-3 h-3 mr-1" />Clear
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="border border-border rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-muted/30 border-b border-border">
            <tr>
              <th className="w-6 p-3" />
              <th className="text-left p-3 font-medium text-muted-foreground">Finding</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden md:table-cell">Asset</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden sm:table-cell">Severity</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden lg:table-cell">Actors</th>
              <th className="text-left p-3 font-medium text-muted-foreground hidden xl:table-cell">IOCs</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Exploitation</th>
              <th className="text-left p-3 font-medium text-muted-foreground">Score</th>
            </tr>
          </thead>
          <tbody>
            {isLoading
              ? Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i} className="border-b border-border/30">
                    <td colSpan={8} className="p-3"><Skeleton className="h-4 w-full" /></td>
                  </tr>
                ))
              : filtered.map((c: any) => (
                  <>
                    <tr
                      key={c.id}
                      className={cn(
                        "border-b border-border/30 transition-colors",
                        expandedId === c.id && "bg-muted/10",
                      )}
                    >
                      <td className="p-3 text-muted-foreground">
                        <button
                          onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}
                          className="text-muted-foreground hover:text-foreground transition-colors p-0.5 rounded"
                          title={expandedId === c.id ? "Collapse" : "Expand"}
                        >
                          {expandedId === c.id
                            ? <ChevronUp className="w-3 h-3" />
                            : <ChevronDown className="w-3 h-3" />}
                        </button>
                      </td>
                      <td className="p-3">
                        <a
                          href={`/findings/${c.findingId}`}
                          className="flex items-start gap-1 text-primary hover:underline"
                        >
                          <Link2 className="w-3 h-3 opacity-50 mt-0.5 shrink-0" />
                          <span className="line-clamp-2">{c.findingTitle ?? `#${c.findingId}`}</span>
                        </a>
                      </td>
                      <td className="p-3 text-muted-foreground hidden md:table-cell truncate max-w-[120px]">
                        {c.assetName ?? "—"}
                      </td>
                      <td className="p-3 hidden sm:table-cell">
                        <span className={cn("font-semibold capitalize", SEV_STYLE[c.findingSeverity] ?? "text-muted-foreground")}>
                          {c.findingSeverity ?? "—"}
                        </span>
                      </td>
                      <td className="p-3 text-muted-foreground hidden lg:table-cell">
                        {(c.matchedActors as any[])?.length ?? 0}
                      </td>
                      <td className="p-3 text-muted-foreground hidden xl:table-cell">
                        {(c.matchedIocs as any[])?.length ?? 0}
                      </td>
                      <td className="p-3">
                        <span className={cn(
                          "text-[10px] px-1.5 py-0.5 rounded border font-semibold capitalize",
                          EXPLOIT_STYLE[c.exploitationStatus] ?? EXPLOIT_STYLE.unknown,
                        )}>
                          {c.exploitationStatus ?? "unknown"}
                        </span>
                      </td>
                      <td className="p-3">
                        <span className={cn(
                          "text-sm font-bold tabular-nums",
                          c.threatScore >= 70 ? "text-red-400" : c.threatScore >= 40 ? "text-orange-400" : "text-yellow-400",
                        )}>
                          {Math.round(c.threatScore ?? 0)}
                        </span>
                      </td>
                    </tr>
                    {expandedId === c.id && <ExpandedRow key={`exp-${c.id}`} c={c} />}
                  </>
                ))
            }
          </tbody>
        </table>
        {!isLoading && filtered.length === 0 && (
          <div className="p-8 text-center space-y-3">
            <Activity className="w-8 h-8 mx-auto opacity-20" />
            <p className="text-sm text-muted-foreground">
              {allCorrs.length > 0 ? "No correlations match the active filters." : "No correlations yet."}
            </p>
            {isAdmin && allCorrs.length === 0 && (
              <Button size="sm" onClick={triggerCorrelate} disabled={correlating}>
                {correlating && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
                Run Correlation Now
              </Button>
            )}
          </div>
        )}
      </div>

      {/* Pagination */}
      {total > L && (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>{page * L + 1}–{Math.min((page + 1) * L, total)} of {total.toLocaleString()}</span>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={page === 0} onClick={() => setPage(p => p - 1)}>Prev</Button>
            <Button size="sm" variant="outline" disabled={(page + 1) * L >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}
    </div>
  );
}
