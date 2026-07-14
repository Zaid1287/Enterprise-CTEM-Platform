import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Database, RefreshCw, Loader2, CheckCircle2, XCircle, Clock, PlayCircle, Key, AlertCircle, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const FEED_META: Record<string, { name: string; desc: string }> = {
  alienvault_otx: { name: "AlienVault OTX", desc: "Open threat exchange — IOCs, malware, actors" },
  abuseipdb:      { name: "AbuseIPDB", desc: "Malicious IP database (API key required)" },
  greynoise:      { name: "GreyNoise", desc: "Internet noise scanner (API key required)" },
  threatfox:      { name: "ThreatFox", desc: "IOC sharing platform — malware IOCs and C2" },
  malwarebazaar:  { name: "MalwareBazaar", desc: "Malware sample database" },
  urlhaus:        { name: "URLhaus", desc: "Malicious URL database" },
  phishtank:      { name: "PhishTank", desc: "Phishing site database" },
  cisa_kev:       { name: "CISA KEV", desc: "Known Exploited Vulnerabilities catalog" },
  mitre_attack:   { name: "MITRE ATT&CK", desc: "Threat actor, campaign, and TTP database" },
  nvd_cve:        { name: "NVD CVE", desc: "National Vulnerability Database (CVE intel)" },
};

export default function ThreatIntelFeedsPage() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin" || user?.role === "super_admin";
  const { toast } = useToast();
  const qc = useQueryClient();
  const [runningFeeds, setRunningFeeds] = useState<Set<string>>(new Set());

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["ti-feeds-status"],
    queryFn: () => apiFetch<any>(`${BASE}/api/threat-intel/feeds/status`),
    staleTime: 30_000,
    refetchInterval: (q) => {
      const d = q.state.data as any;
      if (!d) return 30_000;
      const hasRunning = d.feeds?.some((f: any) => f.status === "running");
      return hasRunning ? 5_000 : 30_000;
    },
  });

  async function refreshFeed(source?: string) {
    if (!isAdmin) return;
    const key = source ?? "__all__";
    setRunningFeeds(s => new Set([...s, key]));
    try {
      await apiFetch(`${BASE}/api/threat-intel/feeds/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(source ? { source } : {}),
      });
      toast({ title: source ? `${FEED_META[source]?.name ?? source} refresh triggered` : "Full feed refresh triggered" });
      setTimeout(() => {
        setRunningFeeds(s => { const n = new Set(s); n.delete(key); return n; });
        refetch();
      }, 3000);
    } catch {
      toast({ title: "Refresh failed", variant: "destructive" });
      setRunningFeeds(s => { const n = new Set(s); n.delete(key); return n; });
    }
  }

  const feeds: any[] = data?.feeds ?? [];

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Database className="w-5 h-5 text-blue-400" />
          <div>
            <h1 className="text-xl font-bold">Feed Management</h1>
            <p className="text-xs text-muted-foreground">Manage and monitor threat intelligence feed sources</p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => refetch()}><RefreshCw className="w-3.5 h-3.5" /></Button>
          {isAdmin && (
            <Button size="sm" onClick={() => refreshFeed()} disabled={runningFeeds.has("__all__")}>
              {runningFeeds.has("__all__") ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Refreshing…</> : <><RefreshCw className="w-3.5 h-3.5 mr-1.5" />Refresh All</>}
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {isLoading
          ? Array.from({length:10}).map((_,i) => <Skeleton key={i} className="h-28 rounded-xl" />)
          : feeds.map((f: any) => {
            const meta = FEED_META[f.source] ?? { name: f.source, desc: "" };
            const ok = f.status === "completed";
            const running = f.status === "running" || runningFeeds.has(f.source);
            const never = f.status === "never";
            const failed = !ok && !running && !never;
            return (
              <div key={f.source} className={cn(
                "bg-card border rounded-xl p-4 space-y-2.5",
                ok ? "border-green-500/20" : running ? "border-blue-500/20" : failed ? "border-red-500/20" : "border-border",
              )}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      {ok ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                          : running ? <Loader2 className="w-3.5 h-3.5 text-blue-400 shrink-0 animate-spin" />
                          : failed ? <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                          : <Clock className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                      <p className="font-semibold text-sm">{meta.name}</p>
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{meta.desc}</p>
                  </div>
                  {isAdmin && (
                    <Button
                      size="sm" variant="outline"
                      className="h-7 px-2 text-[11px] shrink-0"
                      disabled={running}
                      onClick={() => refreshFeed(f.source)}
                    >
                      {running ? <Loader2 className="w-3 h-3 animate-spin" /> : <PlayCircle className="w-3 h-3 mr-1" />}
                      {running ? "" : "Run"}
                    </Button>
                  )}
                </div>
                <div className="flex flex-wrap gap-3 text-[10px] text-muted-foreground">
                  {f.recordsAdded > 0 && <span className="text-green-400">+{Number(f.recordsAdded).toLocaleString()} records</span>}
                  {never && <span>Never run</span>}
                  {f.completedAt && <span>Last: {new Date(f.completedAt).toLocaleDateString()}</span>}
                  {f.error && <span className="text-red-400 truncate max-w-[200px]">{f.error}</span>}
                </div>
                {f.apiKeyRequired && (
                  <div className={cn(
                    "flex items-center gap-1.5 text-[10px] px-2 py-1 rounded-md border w-fit",
                    f.apiKeyConfigured
                      ? "text-green-400 bg-green-500/10 border-green-500/20"
                      : "text-amber-400 bg-amber-500/10 border-amber-500/20",
                  )}>
                    {f.apiKeyConfigured
                      ? <><Key className="w-3 h-3" />API key configured</>
                      : <><AlertCircle className="w-3 h-3" />API key missing —{" "}
                          <a href="/settings/platform" className="underline hover:text-amber-300 inline-flex items-center gap-0.5">
                            Platform Settings<ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </>
                    }
                  </div>
                )}
              </div>
            );
          })
        }
      </div>
    </div>
  );
}
