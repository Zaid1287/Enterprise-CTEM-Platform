import { useState } from "react";
import { useParams, useLocation } from "wouter";
import { useGetBrandThreatScan, getGetBrandThreatScanQueryKey } from "@workspace/api-client-react";
import {
  ArrowLeft, Globe, AlertTriangle, CheckCircle2, XCircle,
  Loader2, Mail, Server, ChevronDown, ChevronUp, RefreshCw,
  ShieldAlert, Eye, Activity, Zap, Fingerprint, ExternalLink,
  Hash, Search, ChevronRight,
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";

const RISK_META: Record<string, { label: string; color: string; bg: string; border: string; bar: string }> = {
  critical: { label: "Critical",  color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/30",    bar: "#f87171" },
  high:     { label: "High",      color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", bar: "#fb923c" },
  medium:   { label: "Medium",    color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", bar: "#facc15" },
  low:      { label: "Low",       color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/30",  bar: "#4ade80" },
};

const SCORE_COLOR = (s: number) =>
  s >= 75 ? "#f87171" : s >= 50 ? "#fb923c" : s >= 25 ? "#facc15" : "#4ade80";

const FUZZER_META: Record<string, { label: string; color: string; bg: string; chartColor: string }> = {
  "omission":      { label: "Omission",     color: "text-blue-400",   bg: "bg-blue-500/10",   chartColor: "#60a5fa" },
  "repetition":    { label: "Repetition",   color: "text-purple-400", bg: "bg-purple-500/10", chartColor: "#c084fc" },
  "transposition": { label: "Transposition",color: "text-indigo-400", bg: "bg-indigo-500/10", chartColor: "#818cf8" },
  "replacement":   { label: "Keyboard Sub", color: "text-cyan-400",   bg: "bg-cyan-500/10",   chartColor: "#22d3ee" },
  "insertion":     { label: "Insertion",    color: "text-teal-400",   bg: "bg-teal-500/10",   chartColor: "#2dd4bf" },
  "vowel-swap":    { label: "Vowel Swap",   color: "text-sky-400",    bg: "bg-sky-500/10",    chartColor: "#38bdf8" },
  "hyphenation":   { label: "Hyphenation",  color: "text-violet-400", bg: "bg-violet-500/10", chartColor: "#a78bfa" },
  "homoglyph":     { label: "Homoglyph",    color: "text-rose-400",   bg: "bg-rose-500/10",   chartColor: "#fb7185" },
  "subdomain":     { label: "Subdomain",    color: "text-amber-400",  bg: "bg-amber-500/10",  chartColor: "#fbbf24" },
  "addition":      { label: "Addition",     color: "text-lime-400",   bg: "bg-lime-500/10",   chartColor: "#a3e635" },
  "tld-swap":      { label: "TLD Swap",     color: "text-pink-400",   bg: "bg-pink-500/10",   chartColor: "#f472b6" },
  "bitsquatting":  { label: "Bitsquatting", color: "text-orange-400", bg: "bg-orange-500/10", chartColor: "#fb923c" },
};

const ENGINE_META: Record<string, { color: string; bg: string; border: string }> = {
  "Shodan":       { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25" },
  "Censys":       { color: "text-blue-400",   bg: "bg-blue-500/10",   border: "border-blue-500/25" },
  "FOFA":         { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25" },
  "Netlas":       { color: "text-teal-400",   bg: "bg-teal-500/10",   border: "border-teal-500/25" },
  "Hunter-How":   { color: "text-amber-400",  bg: "bg-amber-500/10",  border: "border-amber-500/25" },
  "Criminal IP":  { color: "text-rose-400",   bg: "bg-rose-500/10",   border: "border-rose-500/25" },
  "Zoomeye":      { color: "text-purple-400", bg: "bg-purple-500/10", border: "border-purple-500/25" },
  "Silent Push":  { color: "text-cyan-400",   bg: "bg-cyan-500/10",   border: "border-cyan-500/25" },
  "ODIN":         { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/25" },
  "Validin":      { color: "text-violet-400", bg: "bg-violet-500/10", border: "border-violet-500/25" },
};

type FilterMode = "all" | "live" | "mx" | "suspicious";

function RiskScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${score}%`, backgroundColor: SCORE_COLOR(score) }}
        />
      </div>
      <span className="text-xs font-bold tabular-nums w-6 text-right" style={{ color: SCORE_COLOR(score) }}>
        {score}
      </span>
    </div>
  );
}

function HashChip({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button
      onClick={copy}
      title="Click to copy"
      className="flex flex-col gap-0.5 text-left group hover:bg-muted/60 rounded-lg px-2.5 py-2 transition-colors w-full"
    >
      <span className="text-[9px] uppercase tracking-widest text-muted-foreground font-semibold">{label}</span>
      <span className="font-mono text-[11px] text-foreground/80 break-all leading-snug group-hover:text-foreground transition-colors">
        {copied ? <span className="text-green-400">Copied!</span> : value}
      </span>
    </button>
  );
}

function FaviconIntelPanel({ scan }: { scan: any }) {
  const [collapsed, setCollapsed] = useState(false);
  const status: string = scan.favihunterStatus ?? "pending";
  const searchUrls: Record<string, { url: string; hash_type: string }> = scan.faviconSearchUrls ?? {};

  if (status === "pending" || status === "running") {
    return (
      <div className="mx-6 mt-4 bg-violet-500/5 border border-violet-500/20 rounded-xl p-4 flex items-center gap-3">
        <Loader2 className="w-4 h-4 animate-spin text-violet-400 shrink-0" />
        <div>
          <p className="text-sm font-medium text-violet-400">Favicon intelligence scan in progress</p>
          <p className="text-xs text-muted-foreground">
            favihunter is computing favicon hashes and generating search engine pivot URLs…
          </p>
        </div>
      </div>
    );
  }

  if (status === "skipped" || status === "error" || !scan.faviconMd5) {
    return (
      <div className="mx-6 mt-4 bg-muted/30 border border-border rounded-xl p-4 flex items-center gap-3">
        <Fingerprint className="w-4 h-4 text-muted-foreground/40 shrink-0" />
        <p className="text-xs text-muted-foreground">
          {status === "error"
            ? `Favicon intelligence unavailable: ${scan.favihunterError ?? "unknown error"}`
            : "No favicon found for this domain — skipping favicon intelligence."}
        </p>
      </div>
    );
  }

  const engines = Object.entries(searchUrls).filter(([k]) => k !== "_error");

  return (
    <div className="mx-6 mt-4 border border-violet-500/20 rounded-xl overflow-hidden bg-violet-500/3">
      {/* Header */}
      <button
        className="w-full flex items-center gap-3 px-5 py-3.5 hover:bg-violet-500/5 transition-colors"
        onClick={() => setCollapsed(c => !c)}
      >
        <Fingerprint className="w-4 h-4 text-violet-400 shrink-0" />
        <span className="text-sm font-semibold text-violet-300">Favicon Intelligence</span>
        <span className="text-[10px] text-violet-400/60 bg-violet-500/10 border border-violet-500/20 px-1.5 py-0.5 rounded-full font-mono ml-1">
          powered by favihunter
        </span>
        <div className="flex-1" />
        <span className="text-xs text-muted-foreground mr-1">{engines.length} search engines</span>
        {collapsed
          ? <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
          : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
        }
      </button>

      {!collapsed && (
        <div className="border-t border-violet-500/15 px-5 py-4">
          <div className="flex gap-6 flex-wrap">
            {/* Favicon preview */}
            <div className="flex flex-col items-center gap-2 shrink-0">
              <div className="w-12 h-12 rounded-xl border border-border bg-background flex items-center justify-center overflow-hidden">
                <img
                  src={scan.faviconUrl}
                  alt="favicon"
                  className="w-10 h-10 object-contain"
                  onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
                />
              </div>
              <p className="text-[9px] text-muted-foreground text-center max-w-[60px] break-all leading-tight font-mono">
                favicon.ico
              </p>
            </div>

            {/* Hash values */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-2">
                <Hash className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                  Favicon Hashes
                </span>
                <span className="text-[9px] text-muted-foreground/50">(click to copy)</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-0.5">
                <HashChip label="MMH3 (Shodan / FOFA)" value={String(scan.faviconMmh3)} />
                <HashChip label="MMH3-HEX (Criminal IP)" value={scan.faviconMmh3Hex} />
                <HashChip label="MD5 (Censys / Hunter-How / ODIN / Validin)" value={scan.faviconMd5} />
                <HashChip label="SHA256 (Netlas)" value={scan.faviconSha256} />
              </div>
            </div>
          </div>

          {/* Search engine pivot links */}
          {engines.length > 0 && (
            <div className="mt-4">
              <div className="flex items-center gap-1.5 mb-2">
                <Search className="w-3 h-3 text-muted-foreground" />
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">
                  Search Engine Pivots
                </span>
                <span className="text-[9px] text-muted-foreground/50 ml-1">
                  — click to find hosts using the same favicon
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {engines.map(([name, { url, hash_type }]) => {
                  const meta = ENGINE_META[name] ?? { color: "text-muted-foreground", bg: "bg-muted/50", border: "border-border" };
                  return (
                    <a
                      key={name}
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={cn(
                        "flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-all",
                        "hover:scale-105 hover:shadow-sm",
                        meta.color, meta.bg, meta.border,
                      )}
                      title={`Search ${name} using ${hash_type} hash`}
                    >
                      {name}
                      <ExternalLink className="w-3 h-3 opacity-60" />
                    </a>
                  );
                })}
              </div>
              <p className="text-[10px] text-muted-foreground/40 mt-2">
                These links pivot on the domain's actual favicon fingerprint to find clones, phishing infrastructure, or related assets across internet scan databases.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function BrandThreatDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [fuzzerFilter, setFuzzerFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const PAGE_SIZE = 50;

  const { data: scan, isLoading, refetch } = useGetBrandThreatScan(id, {
    query: {
      enabled: !!id,
      queryKey: getGetBrandThreatScanQueryKey(id),
      refetchInterval: (query: any) => {
        const d = query?.state?.data as any;
        if (d?.status === "running" || d?.status === "pending") return 3000;
        if (d?.favihunterStatus === "running" || d?.favihunterStatus === "pending") return 4000;
        return false;
      },
    },
  });

  const s = scan as any;
  const results: any[] = s?.results ?? [];

  const filtered = results.filter((r: any) => {
    if (filter === "live"       && !(r.dnsA?.length > 0)) return false;
    if (filter === "mx"         && !(r.dnsMx?.length > 0)) return false;
    if (filter === "suspicious" && !r.isSuspicious) return false;
    if (fuzzerFilter !== "all"  && r.fuzzer !== fuzzerFilter) return false;
    if (search && !r.permutation.includes(search.toLowerCase())) return false;
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
      <div className="p-6 flex flex-col gap-3">
        <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="w-fit">
          <ArrowLeft className="w-3.5 h-3.5 mr-1.5" /> Back
        </Button>
        <p className="text-muted-foreground text-sm">Scan not found.</p>
      </div>
    );
  }

  const fuzzerBreakdown: Record<string, number> = s.fuzzerBreakdown ?? {};
  const liveResults = results.filter((r: any) => r.dnsA?.length > 0);
  const mxResults   = results.filter((r: any) => r.dnsMx?.length > 0);
  const suspResults = results.filter((r: any) => r.isSuspicious);
  const risk        = RISK_META[s.phishingRisk] ?? RISK_META.low;

  const chartData = Object.entries(fuzzerBreakdown)
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .map(([fuzzer, count]) => ({
      fuzzer,
      label: FUZZER_META[fuzzer]?.label ?? fuzzer,
      count: count as number,
      color: FUZZER_META[fuzzer]?.chartColor ?? "#94a3b8",
    }));

  const showFaviPanel = s.status !== "pending" && (
    s.favihunterStatus === "running" ||
    s.favihunterStatus === "done" ||
    s.favihunterStatus === "skipped" ||
    s.favihunterStatus === "error"
  );

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Hero header ──────────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-card via-card to-background border-b border-border px-6 py-5">
        <div className="flex items-center gap-3 mb-1">
          <Button variant="ghost" size="sm" onClick={() => navigate("/brand-threats")} className="h-8 shrink-0">
            <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Back
          </Button>
          <div className="w-px h-4 bg-border" />
          <ShieldAlert className="w-4 h-4 text-primary shrink-0" />
          <h1 className="text-lg font-bold font-mono truncate">{s.domain}</h1>
          {s.status === "running" && (
            <span className="flex items-center gap-1.5 text-xs text-blue-400 bg-blue-500/10 border border-blue-500/20 px-2 py-0.5 rounded-full shrink-0">
              <Loader2 className="w-3 h-3 animate-spin" /> Scanning…
            </span>
          )}
          {s.status === "done" && s.phishingRisk && (
            <span className={cn("text-xs px-2.5 py-0.5 rounded-full border font-semibold capitalize shrink-0", risk.color, risk.bg, risk.border)}>
              {risk.label} Risk
            </span>
          )}
          {s.status === "error" && (
            <span className="flex items-center gap-1 text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-2 py-0.5 rounded-full shrink-0">
              <XCircle className="w-3 h-3" /> Error
            </span>
          )}
          <div className="flex-1" />
          <Button variant="outline" size="sm" onClick={() => refetch()} className="h-8 shrink-0">
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" /> Refresh
          </Button>
        </div>

        <p className="text-xs text-muted-foreground mt-2 ml-[72px]">
          Started {formatDate(s.createdAt)}
          {s.completedAt && ` · Completed ${formatDate(s.completedAt)}`}
          {s.pipelineScanId && (
            <span className="ml-2 inline-flex items-center gap-0.5 text-violet-400">
              <Zap className="w-2.5 h-2.5" /> Auto-triggered from pipeline scan #{s.pipelineScanId}
            </span>
          )}
        </p>

        {/* Stat strip */}
        {s.status === "done" && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
            <div className="bg-background/60 border border-border rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Total Permutations</p>
              <p className="text-2xl font-bold tabular-nums">{(s.totalPermutations ?? 0).toLocaleString()}</p>
            </div>
            <div className="bg-background/60 border border-red-500/20 rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Live Domains</p>
              <p className={cn("text-2xl font-bold tabular-nums", liveResults.length > 0 ? "text-red-400" : "text-green-400")}>
                {liveResults.length}
              </p>
              <p className="text-[10px] text-muted-foreground">DNS A record resolves</p>
            </div>
            <div className="bg-background/60 border border-orange-500/20 rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Phishing Ready</p>
              <p className={cn("text-2xl font-bold tabular-nums", mxResults.length > 0 ? "text-orange-400" : "text-green-400")}>
                {mxResults.length}
              </p>
              <p className="text-[10px] text-muted-foreground">Has MX records</p>
            </div>
            <div className="bg-background/60 border border-yellow-500/20 rounded-xl px-4 py-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-0.5">Suspicious</p>
              <p className={cn("text-2xl font-bold tabular-nums", suspResults.length > 0 ? "text-yellow-400" : "text-green-400")}>
                {suspResults.length}
              </p>
              <p className="text-[10px] text-muted-foreground">Risk score ≥ 40</p>
            </div>
          </div>
        )}
      </div>

      {/* ── Running / error banner ────────────────────────────────────── */}
      {(s.status === "running" || s.status === "pending") && (
        <div className="mx-6 mt-4 bg-blue-500/5 border border-blue-500/20 rounded-xl p-4 flex items-center gap-4">
          <Loader2 className="w-5 h-5 animate-spin text-blue-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-blue-400">Scan in progress</p>
            <p className="text-xs text-muted-foreground">
              {s.totalPermutations > 0
                ? `Resolving DNS for ${s.totalPermutations} domain permutations…`
                : "Generating permutations via dnstwist + running favihunter favicon analysis…"}
            </p>
          </div>
        </div>
      )}
      {s.status === "error" && (
        <div className="mx-6 mt-4 bg-red-500/5 border border-red-500/20 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <div>
            <p className="text-sm font-medium text-red-400">Scan failed</p>
            <p className="text-xs text-muted-foreground">{s.error ?? "Unknown error"}</p>
          </div>
        </div>
      )}

      {/* ── Favicon Intelligence panel (favihunter) ───────────────────── */}
      {showFaviPanel && <FaviconIntelPanel scan={s} />}

      {/* ── Main two-column layout ────────────────────────────────────── */}
      {results.length > 0 && (
        <div className="flex-1 min-h-0 flex gap-0 overflow-hidden mt-4">
          {/* ── Left sidebar ── */}
          <div className="w-64 shrink-0 border-r border-border overflow-y-auto p-4 space-y-4 bg-card/50">
            {/* Fuzzer breakdown chart */}
            {chartData.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
                  Permutation Types
                </p>
                <div style={{ height: Math.max(200, chartData.length * 28) }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
                      <XAxis type="number" hide />
                      <YAxis
                        type="category"
                        dataKey="label"
                        width={80}
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip
                        cursor={{ fill: "rgba(255,255,255,0.03)" }}
                        contentStyle={{
                          background: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: 8,
                          fontSize: 11,
                        }}
                        formatter={(value: any) => [value, "permutations"]}
                        labelFormatter={(label: string) => label}
                      />
                      <Bar dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={14}>
                        {chartData.map((entry) => (
                          <Cell key={entry.fuzzer} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}

            {/* Divider */}
            <div className="border-t border-border" />

            {/* Filters */}
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Filters</p>

              <div className="space-y-1">
                {([
                  { key: "all",        label: "All results",         count: results.length,        icon: <Eye className="w-3.5 h-3.5" /> },
                  { key: "live",       label: "Live (DNS resolves)", count: liveResults.length,    icon: <Server className="w-3.5 h-3.5" /> },
                  { key: "mx",         label: "Has MX (phishing)",   count: mxResults.length,      icon: <Mail className="w-3.5 h-3.5" /> },
                  { key: "suspicious", label: "Suspicious",          count: suspResults.length,    icon: <AlertTriangle className="w-3.5 h-3.5" /> },
                ] as const).map(({ key, label, count, icon }) => (
                  <button
                    key={key}
                    onClick={() => { setFilter(key as FilterMode); setPage(0); }}
                    className={cn(
                      "w-full flex items-center justify-between gap-2 px-3 py-2 rounded-lg text-xs transition-colors",
                      filter === key
                        ? "bg-primary/10 text-primary font-medium"
                        : "hover:bg-muted/50 text-muted-foreground",
                    )}
                  >
                    <span className="flex items-center gap-2">{icon}{label}</span>
                    <span className={cn(
                      "text-[10px] font-semibold px-1.5 py-0.5 rounded-full",
                      filter === key ? "bg-primary/15 text-primary" : "bg-muted text-muted-foreground",
                    )}>
                      {count}
                    </span>
                  </button>
                ))}
              </div>

              <div className="mt-3 border-t border-border pt-3">
                <p className="text-[10px] text-muted-foreground mb-2">Permutation type</p>
                <select
                  value={fuzzerFilter}
                  onChange={e => { setFuzzerFilter(e.target.value); setPage(0); }}
                  className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none"
                >
                  <option value="all">All types</option>
                  {Array.from(new Set(results.map((r: any) => r.fuzzer))).sort().map((f: string) => (
                    <option key={f} value={f}>{FUZZER_META[f]?.label ?? f}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>

          {/* ── Results table ── */}
          <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
            {/* Table toolbar */}
            <div className="px-5 py-3 border-b border-border flex items-center gap-3 bg-card/30">
              <Activity className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <span className="text-sm font-medium">
                Domain Permutations
                <span className="text-muted-foreground font-normal text-xs ml-2">
                  {filtered.length} of {results.length}
                </span>
              </span>
              <div className="flex-1" />
              <input
                type="text"
                placeholder="Search domains…"
                value={search}
                onChange={e => { setSearch(e.target.value); setPage(0); }}
                className="bg-background border border-border rounded-lg px-3 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40 w-44"
              />
            </div>

            {/* Table header */}
            <div className="grid grid-cols-[28px_1fr_120px_80px_80px_100px] items-center px-5 py-2 border-b border-border bg-muted/20 text-[10px] text-muted-foreground uppercase tracking-wider">
              <span />
              <span>Domain</span>
              <span className="text-center">Type</span>
              <span className="text-center">DNS A</span>
              <span className="text-center">MX</span>
              <span className="text-center">Risk Score</span>
            </div>

            {/* Rows */}
            <div className="flex-1 overflow-y-auto divide-y divide-border">
              {paged.map((r: any) => {
                const fm = FUZZER_META[r.fuzzer];
                const isExpanded = expandedId === r.id;
                return (
                  <div key={r.id}>
                    <div
                      className={cn(
                        "grid grid-cols-[28px_1fr_120px_80px_80px_100px] items-center px-5 py-2.5 hover:bg-muted/20 transition-colors cursor-pointer",
                        r.isSuspicious && "bg-orange-500/3",
                      )}
                      onClick={() => setExpandedId(isExpanded ? null : r.id)}
                    >
                      <div className="flex items-center justify-center">
                        {r.isSuspicious
                          ? <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
                          : <CheckCircle2 className="w-3.5 h-3.5 text-muted-foreground/20" />
                        }
                      </div>
                      <div className="flex items-center gap-2 min-w-0 pr-2">
                        <span className="text-sm font-mono truncate">{r.permutation}</span>
                        {isExpanded
                          ? <ChevronUp className="w-3 h-3 text-muted-foreground/40 shrink-0" />
                          : <ChevronDown className="w-3 h-3 text-muted-foreground/40 shrink-0" />
                        }
                      </div>
                      <div className="flex justify-center">
                        <span className={cn(
                          "text-[10px] px-2 py-0.5 rounded-full font-medium",
                          fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted",
                        )}>
                          {fm?.label ?? r.fuzzer}
                        </span>
                      </div>
                      <div className="flex justify-center">
                        {r.dnsA?.length > 0 ? (
                          <span className="flex items-center gap-1 text-[11px] text-red-400 font-mono font-medium">
                            <Server className="w-2.5 h-2.5 shrink-0" />
                            {r.dnsA[0].length > 11 ? r.dnsA[0].slice(0, 11) + "…" : r.dnsA[0]}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground/30">—</span>
                        )}
                      </div>
                      <div className="flex justify-center">
                        {r.dnsMx?.length > 0 ? (
                          <span className="flex items-center gap-1 text-[11px] text-orange-400 font-medium">
                            <Mail className="w-2.5 h-2.5" /> MX
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground/30">—</span>
                        )}
                      </div>
                      <div className="px-2">
                        <RiskScoreBar score={r.riskScore} />
                      </div>
                    </div>

                    {/* Expanded detail */}
                    {isExpanded && (
                      <div className="bg-muted/10 border-t border-border/50 px-12 py-4">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-5 text-xs">
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">DNS A Records</p>
                            {r.dnsA?.length > 0 ? (
                              <div className="space-y-1">
                                {r.dnsA.map((ip: string) => (
                                  <div key={ip} className="flex items-center gap-1.5">
                                    <Server className="w-3 h-3 text-red-400 shrink-0" />
                                    <span className="font-mono text-foreground">{ip}</span>
                                  </div>
                                ))}
                              </div>
                            ) : <p className="text-muted-foreground/50 italic">No A records</p>}
                          </div>
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">MX Records</p>
                            {r.dnsMx?.length > 0 ? (
                              <div className="space-y-1">
                                {r.dnsMx.map((mx: string) => (
                                  <div key={mx} className="flex items-center gap-1.5">
                                    <Mail className="w-3 h-3 text-orange-400 shrink-0" />
                                    <span className="font-mono text-foreground">{mx}</span>
                                  </div>
                                ))}
                              </div>
                            ) : <p className="text-muted-foreground/50 italic">No MX records</p>}
                          </div>
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">Permutation Type</p>
                            <span className={cn(
                              "inline-flex items-center gap-1 text-xs px-2 py-1 rounded-lg font-medium",
                              fm ? `${fm.color} ${fm.bg}` : "text-muted-foreground bg-muted",
                            )}>
                              {fm?.label ?? r.fuzzer}
                            </span>
                            <p className="text-muted-foreground/50 mt-1 text-[10px]">
                              {r.isSuspicious ? "⚠ Flagged suspicious" : "No threat indicators"}
                            </p>
                          </div>
                          <div>
                            <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">WHOIS Info</p>
                            {r.whoisRegistrar || r.whoisCreated || r.whoisCountry ? (
                              <div className="space-y-0.5">
                                {r.whoisRegistrar && <p><span className="text-muted-foreground">Registrar: </span>{r.whoisRegistrar}</p>}
                                {r.whoisCreated && <p><span className="text-muted-foreground">Created: </span>{r.whoisCreated}</p>}
                                {r.whoisCountry && <p><span className="text-muted-foreground">Country: </span>{r.whoisCountry}</p>}
                              </div>
                            ) : (
                              <p className="text-muted-foreground/50 italic">Not queried</p>
                            )}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}

              {filtered.length === 0 && (
                <div className="flex flex-col items-center justify-center h-32 text-center">
                  <Globe className="w-6 h-6 text-muted-foreground/20 mb-2" />
                  <p className="text-sm text-muted-foreground">No results match the current filters</p>
                </div>
              )}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-5 py-3 border-t border-border bg-card/30">
                <span className="text-xs text-muted-foreground">
                  Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
                </span>
                <div className="flex items-center gap-1">
                  <Button variant="outline" size="sm" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} className="h-7 text-xs">
                    Previous
                  </Button>
                  <span className="text-xs text-muted-foreground px-3">{page + 1} / {totalPages}</span>
                  <Button variant="outline" size="sm" onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="h-7 text-xs">
                    Next
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
