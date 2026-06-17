import { useState } from "react";
import { useParams, useLocation } from "wouter";
import { useGetBrandThreatScan, getGetBrandThreatScanQueryKey } from "@workspace/api-client-react";
import {
  ArrowLeft, Globe, Shield, AlertTriangle, CheckCircle2, XCircle, Clock,
  Loader2, Mail, Server, Filter, ChevronDown, ChevronUp, RefreshCw,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";

const RISK_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

const SCORE_COLOR = (s: number) =>
  s >= 75 ? "text-red-400" : s >= 50 ? "text-orange-400" : s >= 25 ? "text-yellow-400" : "text-green-400";

const FUZZER_LABEL: Record<string, string> = {
  "omission":      "Omission",
  "repetition":    "Repetition",
  "transposition": "Transposition",
  "replacement":   "Keyboard Sub",
  "insertion":     "Insertion",
  "vowel-swap":    "Vowel Swap",
  "hyphenation":   "Hyphenation",
  "homoglyph":     "Homoglyph",
  "subdomain":     "Subdomain",
  "addition":      "Addition",
  "tld-swap":      "TLD Swap",
};

const FUZZER_COLOR: Record<string, string> = {
  "omission":      "bg-blue-500/10 text-blue-400",
  "repetition":    "bg-purple-500/10 text-purple-400",
  "transposition": "bg-indigo-500/10 text-indigo-400",
  "replacement":   "bg-cyan-500/10 text-cyan-400",
  "insertion":     "bg-teal-500/10 text-teal-400",
  "vowel-swap":    "bg-sky-500/10 text-sky-400",
  "hyphenation":   "bg-violet-500/10 text-violet-400",
  "homoglyph":     "bg-rose-500/10 text-rose-400",
  "subdomain":     "bg-amber-500/10 text-amber-400",
  "addition":      "bg-lime-500/10 text-lime-400",
  "tld-swap":      "bg-pink-500/10 text-pink-400",
};

type FilterMode = "all" | "live" | "mx" | "suspicious";

export default function BrandThreatDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [fuzzerFilter, setFuzzerFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const PAGE_SIZE = 25;

  const { data: scan, isLoading, refetch } = useGetBrandThreatScan(id, {
    query: {
      enabled: !!id,
      queryKey: getGetBrandThreatScanQueryKey(id),
      refetchInterval: (data: any) =>
        (data?.status === "running" || data?.status === "pending") ? 3000 : false,
    },
  });

  const s = scan as any;
  const results: any[] = s?.results ?? [];

  const fuzzers = Array.from(new Set(results.map((r: any) => r.fuzzer))).sort();

  const filtered = results.filter((r: any) => {
    if (filter === "live" && !(r.dnsA?.length > 0)) return false;
    if (filter === "mx" && !(r.dnsMx?.length > 0)) return false;
    if (filter === "suspicious" && !r.isSuspicious) return false;
    if (fuzzerFilter !== "all" && r.fuzzer !== fuzzerFilter) return false;
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!s) {
    return (
      <div className="p-6">
        <p className="text-muted-foreground">Scan not found.</p>
        <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="mt-2">
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" />
          Back
        </Button>
      </div>
    );
  }

  const fuzzerBreakdown: Record<string, number> = s.fuzzerBreakdown ?? {};
  const liveResults   = results.filter((r: any) => r.dnsA?.length > 0);
  const mxResults     = results.filter((r: any) => r.dnsMx?.length > 0);
  const suspResults   = results.filter((r: any) => r.isSuspicious);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="mt-0.5 shrink-0">
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" />
          Back
        </Button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-lg font-semibold font-mono">{s.domain}</h1>
            {s.status === "running" && (
              <span className="flex items-center gap-1.5 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full">
                <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
              </span>
            )}
            {s.status === "done" && s.phishingRisk && (
              <span className={cn("text-xs px-2 py-0.5 rounded-md border font-medium capitalize", RISK_COLOR[s.phishingRisk])}>
                {s.phishingRisk} phishing risk
              </span>
            )}
            {s.status === "error" && (
              <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded">
                <XCircle className="w-3 h-3" /> Error
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground mt-1">
            Started {formatDate(s.createdAt)}
            {s.completedAt && ` · Completed ${formatDate(s.completedAt)}`}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => refetch()} className="shrink-0">
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
          Refresh
        </Button>
      </div>

      {/* Summary stats */}
      {s.status === "done" && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Permutations</p>
            <p className="text-2xl font-bold">{s.totalPermutations}</p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Live (DNS resolves)</p>
            <p className={cn("text-2xl font-bold", liveResults.length > 0 ? "text-red-400" : "text-green-400")}>
              {liveResults.length}
            </p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Has MX (phishing)</p>
            <p className={cn("text-2xl font-bold", mxResults.length > 0 ? "text-orange-400" : "text-green-400")}>
              {mxResults.length}
            </p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Suspicious</p>
            <p className={cn("text-2xl font-bold", suspResults.length > 0 ? "text-yellow-400" : "text-green-400")}>
              {suspResults.length}
            </p>
          </div>
        </div>
      )}

      {/* Running state */}
      {(s.status === "running" || s.status === "pending") && (
        <div className="bg-card border border-border rounded-xl p-6 flex items-center gap-4">
          <Loader2 className="w-6 h-6 animate-spin text-blue-400 shrink-0" />
          <div>
            <p className="text-sm font-medium">Scan in progress</p>
            <p className="text-xs text-muted-foreground">
              {s.totalPermutations > 0
                ? `Checking ${s.totalPermutations} domain permutations via DNS…`
                : "Generating domain permutations…"}
            </p>
          </div>
        </div>
      )}

      {/* Error state */}
      {s.status === "error" && (
        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-red-400">Scan failed</p>
            <p className="text-xs text-muted-foreground">{s.error ?? "Unknown error"}</p>
          </div>
        </div>
      )}

      {/* Results section */}
      {results.length > 0 && (
        <>
          {/* Fuzzer breakdown */}
          {Object.keys(fuzzerBreakdown).length > 0 && (
            <div className="bg-card border border-border rounded-xl p-4">
              <h3 className="text-sm font-medium mb-3">Permutation Breakdown by Fuzzer</h3>
              <div className="flex flex-wrap gap-2">
                {Object.entries(fuzzerBreakdown)
                  .sort(([, a], [, b]) => (b as number) - (a as number))
                  .map(([fuzzer, count]) => (
                    <div key={fuzzer} className={cn(
                      "flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg font-medium",
                      FUZZER_COLOR[fuzzer] ?? "bg-muted text-muted-foreground"
                    )}>
                      <span>{FUZZER_LABEL[fuzzer] ?? fuzzer}</span>
                      <span className="opacity-70">({count as number})</span>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {/* Domain results table */}
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="p-4 border-b border-border flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
              <h3 className="text-sm font-medium">
                Domain Permutations
                <span className="text-muted-foreground font-normal text-xs ml-2">({filtered.length} of {results.length})</span>
              </h3>
              <div className="flex items-center gap-2 flex-wrap">
                {/* Status filter */}
                <div className="flex rounded-lg border border-border overflow-hidden text-xs">
                  {(["all", "live", "mx", "suspicious"] as FilterMode[]).map(f => (
                    <button
                      key={f}
                      onClick={() => { setFilter(f); setPage(0); }}
                      className={cn(
                        "px-2.5 py-1.5 capitalize transition-colors",
                        filter === f ? "bg-primary text-primary-foreground" : "hover:bg-muted"
                      )}
                    >
                      {f === "all" ? "All" : f === "live" ? `Live (${liveResults.length})` : f === "mx" ? `MX (${mxResults.length})` : `Suspicious (${suspResults.length})`}
                    </button>
                  ))}
                </div>
                {/* Fuzzer filter */}
                <select
                  value={fuzzerFilter}
                  onChange={e => { setFuzzerFilter(e.target.value); setPage(0); }}
                  className="bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none"
                >
                  <option value="all">All fuzzers</option>
                  {fuzzers.map(f => (
                    <option key={f} value={f}>{FUZZER_LABEL[f] ?? f}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* Table header */}
            <div className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-0 text-xs text-muted-foreground uppercase tracking-wider px-4 py-2 border-b border-border bg-muted/20">
              <span>Domain</span>
              <span className="w-28 text-center">Fuzzer</span>
              <span className="w-24 text-center">DNS A</span>
              <span className="w-24 text-center">MX</span>
              <span className="w-20 text-center">Risk</span>
            </div>

            <div className="divide-y divide-border">
              {paged.map((r: any) => (
                <div key={r.id}>
                  <div
                    className="grid grid-cols-[1fr_auto_auto_auto_auto] gap-0 px-4 py-2.5 hover:bg-muted/20 transition-colors cursor-pointer items-center"
                    onClick={() => setExpandedId(expandedId === r.id ? null : r.id)}
                  >
                    {/* Domain */}
                    <div className="flex items-center gap-2 min-w-0">
                      {r.isSuspicious ? (
                        <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5 text-muted-foreground/30 shrink-0" />
                      )}
                      <span className="text-sm font-mono truncate">{r.permutation}</span>
                    </div>

                    {/* Fuzzer badge */}
                    <div className="w-28 flex justify-center">
                      <span className={cn("text-[10px] px-1.5 py-0.5 rounded font-medium", FUZZER_COLOR[r.fuzzer] ?? "bg-muted text-muted-foreground")}>
                        {FUZZER_LABEL[r.fuzzer] ?? r.fuzzer}
                      </span>
                    </div>

                    {/* DNS A */}
                    <div className="w-24 flex justify-center">
                      {r.dnsA?.length > 0 ? (
                        <span className="flex items-center gap-1 text-xs text-red-400 font-mono">
                          <Server className="w-3 h-3" />
                          {r.dnsA[0]}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground/40">—</span>
                      )}
                    </div>

                    {/* MX */}
                    <div className="w-24 flex justify-center">
                      {r.dnsMx?.length > 0 ? (
                        <span className="flex items-center gap-1 text-xs text-orange-400">
                          <Mail className="w-3 h-3" />
                          MX
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground/40">—</span>
                      )}
                    </div>

                    {/* Risk score */}
                    <div className="w-20 flex items-center justify-center gap-1">
                      <span className={cn("text-sm font-bold tabular-nums", SCORE_COLOR(r.riskScore))}>
                        {r.riskScore}
                      </span>
                      {expandedId === r.id
                        ? <ChevronUp className="w-3 h-3 text-muted-foreground/50" />
                        : <ChevronDown className="w-3 h-3 text-muted-foreground/50" />}
                    </div>
                  </div>

                  {/* Expanded row */}
                  {expandedId === r.id && (
                    <div className="px-10 pb-3 pt-1 bg-muted/10 border-t border-border/50">
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
                        <div>
                          <p className="text-muted-foreground mb-1 uppercase tracking-wider text-[10px]">DNS A Records</p>
                          {r.dnsA?.length > 0
                            ? r.dnsA.map((ip: string) => <p key={ip} className="font-mono text-foreground">{ip}</p>)
                            : <p className="text-muted-foreground/50">None</p>}
                        </div>
                        <div>
                          <p className="text-muted-foreground mb-1 uppercase tracking-wider text-[10px]">MX Records</p>
                          {r.dnsMx?.length > 0
                            ? r.dnsMx.map((mx: string) => <p key={mx} className="font-mono text-foreground">{mx}</p>)
                            : <p className="text-muted-foreground/50">None</p>}
                        </div>
                        <div>
                          <p className="text-muted-foreground mb-1 uppercase tracking-wider text-[10px]">SPF/MX Info</p>
                          <p className="text-foreground">{r.mxSpf ?? "—"}</p>
                        </div>
                        <div>
                          <p className="text-muted-foreground mb-1 uppercase tracking-wider text-[10px]">WHOIS</p>
                          {r.whoisRegistrar || r.whoisCreated || r.whoisCountry ? (
                            <div className="space-y-0.5">
                              {r.whoisRegistrar && <p><span className="text-muted-foreground">Registrar:</span> {r.whoisRegistrar}</p>}
                              {r.whoisCreated && <p><span className="text-muted-foreground">Created:</span> {r.whoisCreated}</p>}
                              {r.whoisCountry && <p><span className="text-muted-foreground">Country:</span> {r.whoisCountry}</p>}
                            </div>
                          ) : (
                            <p className="text-muted-foreground/50">Not queried</p>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}

              {filtered.length === 0 && (
                <div className="flex items-center justify-center h-20 text-sm text-muted-foreground">
                  No results match the current filters
                </div>
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-border">
                <span className="text-xs text-muted-foreground">
                  Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
                </span>
                <div className="flex items-center gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(p => Math.max(0, p - 1))}
                    disabled={page === 0}
                    className="h-7 text-xs"
                  >
                    Previous
                  </Button>
                  <span className="text-xs text-muted-foreground px-2">{page + 1} / {totalPages}</span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                    className="h-7 text-xs"
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
