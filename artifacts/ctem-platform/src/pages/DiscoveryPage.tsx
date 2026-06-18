import { useState } from "react";
import {
  useListAssets,
  useTriggerPassiveDiscovery,
  useListDiscoveryLatest,
  useListDiscoveryHistory,
  getListDiscoveryLatestQueryKey,
  getListDiscoveryHistoryQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Radar, Play, Loader2, CheckCircle2, XCircle, MinusCircle,
  ChevronDown, RefreshCw, Clock, Globe, Search, Database,
  Key, Shield, Github, Wifi, Server, BookOpen, AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const MODULE_META: Record<string, { label: string; icon: React.ElementType; description: string; color: string }> = {
  ctLogs:       { label: "CT Logs",          icon: BookOpen,  description: "Certificate Transparency logs via crt.sh",         color: "text-blue-400" },
  reverseWhois: { label: "Reverse WHOIS",    icon: Globe,     description: "Reverse WHOIS via HackerTarget",                   color: "text-violet-400" },
  asnLookup:    { label: "ASN Lookup",       icon: Wifi,      description: "Autonomous System Number & BGP route data",        color: "text-cyan-400" },
  dkimCheck:    { label: "DKIM Check",       icon: Key,       description: "DKIM selector probe across 25 common selectors",   color: "text-yellow-400" },
  githubExposure:{ label: "GitHub Exposure", icon: Github,    description: "GitHub code search for leaked secrets/config",     color: "text-white" },
  shodan:       { label: "Shodan",           icon: Search,    description: "Shodan internet-wide port & banner scan",          color: "text-orange-400" },
  fofa:         { label: "FOFA",             icon: Radar,     description: "FOFA cyberspace search engine",                    color: "text-pink-400" },
  censys:       { label: "Censys",           icon: Server,    description: "Censys internet-wide certificate & host data",     color: "text-indigo-400" },
  intelx:       { label: "IntelX",           icon: Database,  description: "Intelligence X OSINT data lake",                  color: "text-emerald-400" },
  criminalIp:   { label: "Criminal IP",      icon: Shield,    description: "Criminal IP threat intelligence search",           color: "text-red-400" },
};

const STATUS_ICON = {
  ok:      <CheckCircle2 className="w-4 h-4 text-green-400" />,
  skipped: <MinusCircle  className="w-4 h-4 text-muted-foreground" />,
  error:   <XCircle      className="w-4 h-4 text-red-400" />,
};

const STATUS_BADGE: Record<string, string> = {
  ok:      "bg-green-500/10 text-green-400 border-green-500/25",
  skipped: "bg-muted/30 text-muted-foreground border-border",
  error:   "bg-red-500/10 text-red-400 border-red-500/25",
};

type TabKey = "latest" | "history";

function ModuleCard({ result }: { result: Record<string, unknown> }) {
  const [expanded, setExpanded] = useState(false);
  const source  = result.source as string;
  const status  = result.status as string;
  const summary = result.summary as string | undefined;
  const data    = result.data as Record<string, unknown> | null | undefined;
  const meta    = MODULE_META[source] ?? { label: source, icon: Radar, description: "", color: "text-muted-foreground" };
  const Icon    = meta.icon;
  const hasData = data && Object.keys(data).length > 0;

  return (
    <div className={cn(
      "bg-card border rounded-xl overflow-hidden transition-all",
      status === "ok" ? "border-border" : status === "error" ? "border-red-500/20" : "border-border/50 opacity-60"
    )}>
      <div
        className="flex items-start gap-3 p-4 cursor-pointer hover:bg-muted/10 transition-colors"
        onClick={() => hasData && setExpanded(v => !v)}
      >
        <div className={cn("mt-0.5 p-2 rounded-lg bg-muted/20", meta.color.replace("text-", "border-").replace("-400", "-500/20"))}>
          <Icon className={cn("w-4 h-4", meta.color)} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <span className="text-sm font-medium">{meta.label}</span>
            <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-full border uppercase tracking-wider", STATUS_BADGE[status] ?? STATUS_BADGE.skipped)}>
              {status}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">{summary ?? meta.description}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {STATUS_ICON[status as keyof typeof STATUS_ICON] ?? STATUS_ICON.skipped}
          {hasData && (
            <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform", expanded && "rotate-180")} />
          )}
        </div>
      </div>

      {expanded && hasData && (
        <div className="border-t border-border bg-muted/5 p-4">
          <pre className="text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap max-h-64 overflow-y-auto">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function HistoryRow({ row }: { row: Record<string, unknown> }) {
  const [expanded, setExpanded] = useState(false);
  const source  = row.source  as string;
  const status  = row.status  as string;
  const summary = row.summary as string | undefined;
  const data    = row.data    as Record<string, unknown> | null | undefined;
  const createdAt = row.createdAt as string | undefined;
  const meta    = MODULE_META[source] ?? { label: source, icon: Radar, description: "", color: "text-muted-foreground" };
  const Icon    = meta.icon;
  const hasData = data && Object.keys(data).length > 0;

  return (
    <div className="border-b border-border/50 last:border-0">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-muted/10 transition-colors"
        onClick={() => hasData && setExpanded(v => !v)}
      >
        <Icon className={cn("w-3.5 h-3.5 shrink-0", meta.color)} />
        <span className="text-sm font-medium w-36 shrink-0">{meta.label}</span>
        <span className={cn("text-[10px] font-semibold px-1.5 py-0.5 rounded-full border uppercase tracking-wider shrink-0", STATUS_BADGE[status] ?? STATUS_BADGE.skipped)}>
          {status}
        </span>
        <span className="text-xs text-muted-foreground flex-1 truncate">{summary}</span>
        {createdAt && (
          <span className="text-xs text-muted-foreground shrink-0 flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {formatDate(createdAt)}
          </span>
        )}
        {hasData && (
          <ChevronDown className={cn("w-3.5 h-3.5 text-muted-foreground transition-transform shrink-0", expanded && "rotate-180")} />
        )}
      </div>
      {expanded && hasData && (
        <div className="bg-muted/5 px-4 pb-3">
          <pre className="text-xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap max-h-48 overflow-y-auto">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

export default function DiscoveryPage() {
  const [selectedAssetId, setSelectedAssetId] = useState<number | null>(null);
  const [tab, setTab] = useState<TabKey>("latest");
  const [running, setRunning] = useState(false);
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: assetsData } = useListAssets();
  const assets = assetsData?.assets ?? [];

  const { data: latestData, isLoading: loadingLatest } = useListDiscoveryLatest(
    selectedAssetId ?? 0,
    { query: { enabled: selectedAssetId !== null, queryKey: getListDiscoveryLatestQueryKey(selectedAssetId ?? 0) } }
  );

  const { data: historyData, isLoading: loadingHistory } = useListDiscoveryHistory(
    selectedAssetId ?? 0,
    { query: { enabled: selectedAssetId !== null && tab === "history", queryKey: getListDiscoveryHistoryQueryKey(selectedAssetId ?? 0) } }
  );

  const { mutateAsync: triggerDiscovery } = useTriggerPassiveDiscovery();

  const latestSources = (latestData?.sources ?? []) as Record<string, unknown>[];
  const historyRows   = (historyData?.results ?? []) as Record<string, unknown>[];

  const okCount      = latestSources.filter(s => s.status === "ok").length;
  const errorCount   = latestSources.filter(s => s.status === "error").length;
  const skippedCount = latestSources.filter(s => s.status === "skipped").length;

  async function handleRun() {
    if (!selectedAssetId) return;
    setRunning(true);
    try {
      await triggerDiscovery({ assetId: selectedAssetId });
      toast({ title: "Discovery complete", description: "All passive discovery modules finished." });
      qc.invalidateQueries({ queryKey: getListDiscoveryLatestQueryKey(selectedAssetId) });
      qc.invalidateQueries({ queryKey: getListDiscoveryHistoryQueryKey(selectedAssetId) });
    } catch {
      toast({ title: "Discovery failed", variant: "destructive" });
    } finally {
      setRunning(false);
    }
  }

  const selectedAsset = assets.find(a => a.id === selectedAssetId);

  return (
    <div className="p-6 space-y-6 max-w-5xl mx-auto">
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Radar className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Passive Discovery</h1>
            <p className="text-xs text-muted-foreground mt-0.5">CT logs, WHOIS, ASN, DKIM, GitHub exposure, and commercial intel sources</p>
          </div>
        </div>
      </div>

      <div className="bg-card border border-border rounded-xl p-5 flex flex-col sm:flex-row gap-4 items-end">
        <div className="flex-1">
          <label className="text-xs text-muted-foreground uppercase tracking-wider mb-2 block">Target Asset</label>
          <select
            className="w-full bg-background border border-border rounded-lg px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40 appearance-none"
            value={selectedAssetId ?? ""}
            onChange={e => setSelectedAssetId(e.target.value ? parseInt(e.target.value) : null)}
          >
            <option value="">— Select an asset —</option>
            {assets.map(a => (
              <option key={a.id} value={a.id}>
                {a.name} ({a.value})
              </option>
            ))}
          </select>
        </div>
        <Button
          className="shrink-0 gap-2"
          disabled={!selectedAssetId || running}
          onClick={handleRun}
        >
          {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
          {running ? "Running…" : "Run Discovery"}
        </Button>
      </div>

      {selectedAsset && latestSources.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-card border border-border rounded-xl p-4 text-center">
            <div className="text-2xl font-bold text-green-400">{okCount}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Sources OK</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 text-center">
            <div className="text-2xl font-bold text-muted-foreground">{skippedCount}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Skipped</div>
          </div>
          <div className="bg-card border border-border rounded-xl p-4 text-center">
            <div className="text-2xl font-bold text-red-400">{errorCount}</div>
            <div className="text-xs text-muted-foreground mt-0.5">Errors</div>
          </div>
        </div>
      )}

      {selectedAssetId && (
        <>
          <div className="flex gap-1 p-1 bg-muted/20 border border-border rounded-lg w-fit">
            {(["latest", "history"] as TabKey[]).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={cn(
                  "px-4 py-1.5 text-xs font-medium rounded-md transition-colors capitalize",
                  tab === t ? "bg-card shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground"
                )}
              >
                {t === "latest" ? "Latest Results" : "History"}
              </button>
            ))}
          </div>

          {tab === "latest" && (
            <div>
              {loadingLatest ? (
                <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading…</span>
                </div>
              ) : latestSources.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-muted/20 flex items-center justify-center">
                    <AlertCircle className="w-6 h-6 text-muted-foreground" />
                  </div>
                  <div>
                    <p className="text-sm font-medium">No discovery data yet</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Select an asset and click Run Discovery to collect OSINT data.</p>
                  </div>
                </div>
              ) : (
                <div className="grid gap-3 sm:grid-cols-2">
                  {latestSources.map((s, i) => (
                    <ModuleCard key={`${s.source as string}-${i}`} result={s} />
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === "history" && (
            <div className="bg-card border border-border rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <span className="text-sm font-medium">Discovery History</span>
                <button
                  className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors"
                  onClick={() => qc.invalidateQueries({ queryKey: getListDiscoveryHistoryQueryKey(selectedAssetId) })}
                >
                  <RefreshCw className="w-3 h-3" /> Refresh
                </button>
              </div>
              {loadingHistory ? (
                <div className="flex items-center justify-center py-12 text-muted-foreground gap-2">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span className="text-sm">Loading…</span>
                </div>
              ) : historyRows.length === 0 ? (
                <div className="py-12 text-center text-sm text-muted-foreground">No history records yet.</div>
              ) : (
                historyRows.map((row, i) => (
                  <HistoryRow key={i} row={row} />
                ))
              )}
            </div>
          )}
        </>
      )}

      {!selectedAssetId && (
        <div className="flex flex-col items-center justify-center py-20 text-center gap-3">
          <div className="w-14 h-14 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center">
            <Radar className="w-7 h-7 text-primary/60" />
          </div>
          <div>
            <p className="text-sm font-medium">Select an asset to begin</p>
            <p className="text-xs text-muted-foreground mt-1 max-w-sm">
              Choose a target asset above to view existing discovery results or kick off a new passive discovery run across all configured OSINT and intelligence sources.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
