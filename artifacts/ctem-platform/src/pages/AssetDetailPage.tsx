import { useState } from "react";
import { useParams, useLocation } from "wouter";
import {
  useGetAsset, useListFindings, useGetAssetRiskScore, useCheckAssetVerification,
  useListAssetTechnologies, useRunTechScan,
  getGetAssetQueryKey, getListFindingsQueryKey, getGetAssetRiskScoreQueryKey,
  getListAssetTechnologiesQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink, ShieldCheck, Cpu, Loader2, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import { cn, severityBgColor, statusBadgeClass, riskLevelBg, capitalize, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const CATEGORY_COLOR: Record<string, string> = {
  "Web Server":           "bg-blue-500/10 text-blue-400 border-blue-500/20",
  "CMS":                  "bg-purple-500/10 text-purple-400 border-purple-500/20",
  "E-commerce":           "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  "JavaScript Framework": "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  "JavaScript Library":   "bg-sky-500/10 text-sky-400 border-sky-500/20",
  "UI Framework":         "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  "CSS Framework":        "bg-violet-500/10 text-violet-400 border-violet-500/20",
  "Programming Language": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  "Web Framework":        "bg-amber-500/10 text-amber-400 border-amber-500/20",
  "CDN":                  "bg-slate-500/10 text-slate-400 border-slate-500/20",
  "Analytics":            "bg-rose-500/10 text-rose-400 border-rose-500/20",
  "Tag Manager":          "bg-pink-500/10 text-pink-400 border-pink-500/20",
  "Security":             "bg-red-500/10 text-red-400 border-red-500/20",
  "Payment":              "bg-green-500/10 text-green-400 border-green-500/20",
  "PaaS":                 "bg-teal-500/10 text-teal-400 border-teal-500/20",
  "Caching":              "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
};

function categoryColor(cat: string) {
  return CATEGORY_COLOR[cat] ?? "bg-muted text-muted-foreground border-border";
}

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [verifying, setVerifying] = useState(false);
  const [scanning, setScanning] = useState(false);

  const { data: asset, isLoading } = useGetAsset(id, {
    query: { enabled: !!id, queryKey: getGetAssetQueryKey(id) },
  });
  const { data: findings } = useListFindings({ assetId: id } as any, {
    query: { enabled: !!id, queryKey: getListFindingsQueryKey({ assetId: id }) },
  });
  const { data: riskScore } = useGetAssetRiskScore(id, {
    query: { enabled: !!id, queryKey: getGetAssetRiskScoreQueryKey(id) },
  });
  const { data: technologies, refetch: refetchTechs } = useListAssetTechnologies(id, {
    query: { enabled: !!id, queryKey: getListAssetTechnologiesQueryKey(id) },
  });
  const verifyAsset = useCheckAssetVerification();
  const runTechScan = useRunTechScan();

  const handleVerify = async () => {
    setVerifying(true);
    try {
      await verifyAsset.mutateAsync({ assetId: id });
      queryClient.invalidateQueries({ queryKey: getGetAssetQueryKey(id) });
    } finally {
      setVerifying(false);
    }
  };

  const handleTechScan = async () => {
    setScanning(true);
    try {
      const res = await runTechScan.mutateAsync({ assetId: id });
      await refetchTechs();
      const count = (res as any)?.technologies?.length ?? 0;
      toast({ title: `Technology scan complete`, description: `${count} technolog${count === 1 ? "y" : "ies"} detected.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Tech scan failed", variant: "destructive" });
    } finally {
      setScanning(false);
    }
  };

  const a = asset as any;
  const rs = riskScore as any;
  const techs = (technologies as any[]) ?? [];

  // Group by category
  const grouped: Record<string, any[]> = {};
  for (const t of techs) {
    if (!grouped[t.category]) grouped[t.category] = [];
    grouped[t.category].push(t);
  }

  const webTypes = ["domain", "subdomain", "url", "ip"];
  const canScan = a && webTypes.includes(a.type);

  if (isLoading) return <div className="space-y-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}</div>;
  if (!a) return <div className="text-muted-foreground">Asset not found</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/assets")}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Assets
        </Button>
      </div>

      {/* Header */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs bg-accent/50 px-2 py-0.5 rounded">{a.type}</span>
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", statusBadgeClass(a.verificationStatus))}>{a.verificationStatus}</span>
              {a.verificationStatus !== "verified" && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-6 px-2 text-xs border-green-500/40 text-green-500 hover:bg-green-500/10 hover:text-green-400"
                  disabled={verifying}
                  onClick={handleVerify}
                >
                  <ShieldCheck className="w-3.5 h-3.5 mr-1" />
                  {verifying ? "Verifying…" : "Mark Verified"}
                </Button>
              )}
            </div>
            <h1 className="text-base font-semibold">{a.name}</h1>
            <p className="text-sm font-mono text-muted-foreground mt-0.5">{a.value}</p>
          </div>
          {rs && (
            <div className="text-right">
              <p className="text-3xl font-bold tabular-nums" style={{ color: rs.level === "critical" ? "#ef4444" : rs.level === "high" ? "#f97316" : rs.level === "medium" ? "#eab308" : "#22c55e" }}>
                {Math.round(rs.score)}
              </p>
              <p className="text-xs text-muted-foreground">risk score</p>
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium", riskLevelBg(rs.level))}>{rs.level}</span>
            </div>
          )}
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4">
          {[
            { label: "IP Address", value: a.ipAddress ?? "—" },
            { label: "Port", value: a.port ?? "—" },
            { label: "Last Scanned", value: formatDate(a.lastScannedAt) },
            { label: "Added", value: formatDate(a.createdAt) },
          ].map(m => (
            <div key={m.label} className="bg-accent/40 rounded-lg p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{m.label}</p>
              <p className="text-xs font-medium font-mono mt-0.5">{m.value}</p>
            </div>
          ))}
        </div>

        {/* Assignment info */}
        {(a.assignedClientName || a.assignedAccountManagerName) && (
          <div className="grid grid-cols-2 gap-3 mt-3">
            {a.assignedClientName && (
              <div className="bg-accent/40 rounded-lg p-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Client</p>
                <p className="text-xs font-medium mt-0.5">{a.assignedClientName}</p>
              </div>
            )}
            {a.assignedAccountManagerName && (
              <div className="bg-accent/40 rounded-lg p-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Account Manager</p>
                <p className="text-xs font-medium mt-0.5">{a.assignedAccountManagerName}</p>
              </div>
            )}
          </div>
        )}

        {a.tags?.length > 0 && (
          <div className="flex gap-1.5 flex-wrap mt-3">
            {a.tags.map((tag: string) => (
              <span key={tag} className="text-xs bg-primary/10 text-primary border border-primary/20 px-2 py-0.5 rounded-full">{tag}</span>
            ))}
          </div>
        )}
      </div>

      {/* Findings */}
      <div className="bg-card border border-border rounded-xl p-4">
        <h3 className="text-sm font-medium mb-3">Findings ({(findings as any[])?.length ?? 0})</h3>
        <div className="space-y-2">
          {(findings as any[] ?? []).map((f: any) => (
            <div key={f.id} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", severityBgColor(f.severity))}>{f.severity}</span>
              <Link href={`/findings/${f.id}`}>
                <span className="text-sm text-primary hover:underline cursor-pointer flex-1 line-clamp-1">{f.title}</span>
              </Link>
              {f.isKev && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold">KEV</span>}
              <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", statusBadgeClass(f.status))}>{capitalize(f.status)}</span>
            </div>
          ))}
          {(findings as any[] ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">No findings for this asset.</p>
          )}
        </div>
      </div>

      {/* Technology Detection */}
      <div className="bg-card border border-border rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-muted-foreground" />
            <h3 className="text-sm font-medium">Detected Technologies</h3>
            {techs.length > 0 && (
              <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{techs.length}</span>
            )}
          </div>
          {canScan && (
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-3 text-xs gap-1.5"
              disabled={scanning}
              onClick={handleTechScan}
            >
              {scanning
                ? <><Loader2 className="w-3 h-3 animate-spin" /> Scanning…</>
                : <><RefreshCw className="w-3 h-3" /> {techs.length > 0 ? "Re-scan" : "Detect Technologies"}</>}
            </Button>
          )}
        </div>

        {scanning && (
          <div className="py-6 flex flex-col items-center gap-2 text-muted-foreground">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
            <p className="text-xs">Fingerprinting {a.value}…</p>
            <p className="text-[10px] text-muted-foreground/60">Fetching HTTP headers, HTML patterns, and scripts</p>
          </div>
        )}

        {!scanning && techs.length === 0 && (
          <div className="py-6 text-center text-sm text-muted-foreground">
            {canScan
              ? "No technologies detected yet. Click \"Detect Technologies\" to run a real-time fingerprint scan."
              : "Technology detection is only available for domain, subdomain, URL, and IP assets."}
          </div>
        )}

        {!scanning && techs.length > 0 && (
          <div className="space-y-4">
            {Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([category, items]) => (
              <div key={category}>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">{category}</p>
                <div className="flex flex-wrap gap-2">
                  {items.map((t: any) => (
                    <div key={t.id} className={cn("flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium", categoryColor(t.category))}>
                      {t.icon && <span>{t.icon}</span>}
                      <span>{t.technology}</span>
                      {t.version && (
                        <span className="text-[10px] opacity-70 font-mono bg-black/10 px-1 rounded">{t.version}</span>
                      )}
                      {t.confidence < 100 && (
                        <span className="text-[10px] opacity-50">{t.confidence}%</span>
                      )}
                      {t.website && (
                        <a href={t.website} target="_blank" rel="noopener noreferrer" className="opacity-50 hover:opacity-100 transition-opacity" onClick={e => e.stopPropagation()}>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
            <p className="text-[10px] text-muted-foreground/50 mt-2">
              Last scanned: {formatDate(techs[0]?.detectedAt)}
              {techs[0]?.cpe && <span className="ml-2 font-mono">{techs[0].cpe}</span>}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
