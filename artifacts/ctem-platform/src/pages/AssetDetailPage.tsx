import { useState } from "react";
import { useParams, useLocation } from "wouter";
import {
  useGetAsset, useListFindings, useGetAssetRiskScore, useCheckAssetVerification,
  useListAssetTechnologies, useRunTechScan, useListAssetScreenshots, useRunScreenshotScan,
  getGetAssetQueryKey, getListFindingsQueryKey, getGetAssetRiskScoreQueryKey,
  getListAssetTechnologiesQueryKey, getListAssetScreenshotsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ArrowLeft, ExternalLink, ShieldCheck, Cpu, Loader2, RefreshCw, Camera, AlertTriangle, X,
  ChevronLeft, ChevronRight, Download,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import { cn, severityBgColor, statusBadgeClass, riskLevelBg, capitalize, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { downloadAssetPdf } from "@/lib/pdfReport";
import { getToken } from "@/lib/auth";

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

const PAGE_TYPE_BADGE: Record<string, string> = {
  index:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  login:     "bg-amber-500/15 text-amber-400 border-amber-500/30",
  signup:    "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  admin:     "bg-red-500/15 text-red-400 border-red-500/30",
  api:       "bg-purple-500/15 text-purple-400 border-purple-500/30",
  sensitive: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  error:     "bg-slate-500/15 text-slate-400 border-slate-500/30",
};

const FINDING_SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high:     "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium:   "text-yellow-400 bg-yellow-500/10 border-yellow-500/30",
  low:      "text-blue-400 bg-blue-500/10 border-blue-500/30",
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
  const [verifying, setVerifying]             = useState(false);
  const [scanning, setScanning]               = useState(false);
  const [screenshotting, setScreenshotting]   = useState(false);
  const [downloading, setDownloading]         = useState(false);
  const [expandedShot, setExpandedShot]       = useState<any | null>(null);
  const [findingsPage, setFindingsPage]       = useState(0);

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
  const { data: screenshots, refetch: refetchScreenshots } = useListAssetScreenshots(id, {
    query: { enabled: !!id, queryKey: getListAssetScreenshotsQueryKey(id) },
  });

  const verifyAsset  = useCheckAssetVerification();
  const runTechScan  = useRunTechScan();
  const runShotScan  = useRunScreenshotScan();

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

  const handleScreenshotScan = async () => {
    setScreenshotting(true);
    try {
      const res = await runShotScan.mutateAsync({ assetId: id });
      await refetchScreenshots();
      const count = (res as any)?.screenshots?.length ?? 0;
      toast({ title: `Screenshot scan complete`, description: `${count} page${count === 1 ? "" : "s"} captured.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Screenshot scan failed", variant: "destructive" });
    } finally {
      setScreenshotting(false);
    }
  };

  const a     = asset as any;
  const rs    = riskScore as any;
  const techs = (technologies as any[]) ?? [];
  const shots = (screenshots as any[]) ?? [];

  const grouped: Record<string, any[]> = {};
  for (const t of techs) {
    if (!grouped[t.category]) grouped[t.category] = [];
    grouped[t.category].push(t);
  }

  const webTypes = ["domain", "subdomain", "url", "ip"];
  const canScan  = a && webTypes.includes(a.type);

  const totalFindings = shots.reduce((n: number, s: any) => n + ((s.findings as any[])?.length ?? 0), 0);

  if (isLoading) return <div className="space-y-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}</div>;
  if (!a) return <div className="text-muted-foreground">Asset not found</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <Button variant="ghost" size="sm" onClick={() => navigate("/assets")}>
          <ArrowLeft className="w-4 h-4 mr-1" /> Assets
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="gap-1.5"
          disabled={downloading || isLoading || !a}
          onClick={async () => {
            setDownloading(true);
            try { await downloadAssetPdf(id, getToken()); }
            catch { /* ignore */ }
            finally { setDownloading(false); }
          }}
        >
          {downloading
            ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
            : <Download className="w-3.5 h-3.5" />}
          {downloading ? "Generating…" : "Download PDF"}
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
            { label: "IP Address",   value: a.ipAddress ?? "—" },
            { label: "Port",         value: a.port ?? "—" },
            { label: "Last Scanned", value: formatDate(a.lastScannedAt) },
            { label: "Added",        value: formatDate(a.createdAt) },
          ].map(m => (
            <div key={m.label} className="bg-accent/40 rounded-lg p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{m.label}</p>
              <p className="text-xs font-medium font-mono mt-0.5">{m.value}</p>
            </div>
          ))}
        </div>

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
      {(() => {
        const FINDINGS_PER_PAGE = 10;
        const allF = (findings as any[]) ?? [];
        const totalPages = Math.max(1, Math.ceil(allF.length / FINDINGS_PER_PAGE));
        const paged = allF.slice(findingsPage * FINDINGS_PER_PAGE, (findingsPage + 1) * FINDINGS_PER_PAGE);
        return (
          <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium">
                Findings
                {allF.length > 0 && <span className="ml-1.5 text-xs text-muted-foreground font-normal">({allF.length})</span>}
              </h3>
              {totalPages > 1 && (
                <div className="flex items-center gap-0.5">
                  <button
                    onClick={() => setFindingsPage(p => Math.max(0, p - 1))}
                    disabled={findingsPage === 0}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30 transition-colors"
                  >
                    <ChevronLeft className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-xs text-muted-foreground px-1.5 tabular-nums">
                    {findingsPage + 1} / {totalPages}
                  </span>
                  <button
                    onClick={() => setFindingsPage(p => Math.min(totalPages - 1, p + 1))}
                    disabled={findingsPage >= totalPages - 1}
                    className="p-1 rounded hover:bg-muted disabled:opacity-30 transition-colors"
                  >
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
            <div className="space-y-2">
              {paged.map((f: any) => (
                <div key={f.id} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", severityBgColor(f.severity))}>{f.severity}</span>
                  <Link href={`/findings/${f.id}`}>
                    <span className="text-sm text-primary hover:underline cursor-pointer flex-1 line-clamp-1">{f.title}</span>
                  </Link>
                  {f.isKev && <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-bold">KEV</span>}
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium shrink-0", statusBadgeClass(f.status))}>{capitalize(f.status)}</span>
                </div>
              ))}
              {allF.length === 0 && (
                <p className="text-sm text-muted-foreground">No findings for this asset.</p>
              )}
            </div>
          </div>
        );
      })()}

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

      {/* ── Screenshot Gallery ──────────────────────────────────────────────── */}
      {canScan && (
        <div className="bg-card border border-border rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Camera className="w-4 h-4 text-muted-foreground" />
              <h3 className="text-sm font-medium">Visual Screenshot Gallery</h3>
              {shots.length > 0 && (
                <span className="text-[10px] bg-primary/10 text-primary border border-primary/20 px-1.5 py-0.5 rounded font-medium">{shots.length}</span>
              )}
              {totalFindings > 0 && (
                <span className="text-[10px] bg-red-500/10 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-medium flex items-center gap-1">
                  <AlertTriangle className="w-2.5 h-2.5" />{totalFindings} sensitive
                </span>
              )}
            </div>
            <Button
              size="sm"
              variant="outline"
              className="h-7 px-3 text-xs gap-1.5"
              disabled={screenshotting}
              onClick={handleScreenshotScan}
            >
              {screenshotting
                ? <><Loader2 className="w-3 h-3 animate-spin" /> Capturing…</>
                : <><Camera className="w-3 h-3" /> {shots.length > 0 ? "Re-capture" : "Capture Screenshots"}</>}
            </Button>
          </div>

          {screenshotting && (
            <div className="py-10 flex flex-col items-center gap-3 text-muted-foreground">
              <Loader2 className="w-8 h-8 animate-spin text-primary" />
              <p className="text-sm font-medium">Capturing pages on {a.value}…</p>
              <p className="text-xs text-muted-foreground/60">Visiting index, login, signup, admin, and API paths via headless Chromium</p>
            </div>
          )}

          {!screenshotting && shots.length === 0 && (
            <div className="py-8 text-center">
              <Camera className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No screenshots captured yet.</p>
              <p className="text-xs text-muted-foreground/60 mt-1">Click "Capture Screenshots" to visit and photograph pages via headless Chromium.</p>
            </div>
          )}

          {!screenshotting && shots.length > 0 && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {shots.map((shot: any) => {
                const shotFindings: any[] = shot.findings ?? [];
                const criticalOrHigh = shotFindings.filter((f: any) => f.severity === "critical" || f.severity === "high");
                return (
                  <div
                    key={shot.id}
                    className="group border border-border rounded-lg overflow-hidden cursor-pointer hover:border-primary/50 transition-colors bg-accent/20"
                    onClick={() => setExpandedShot(shot)}
                  >
                    {/* Screenshot image */}
                    <div className="relative w-full aspect-video bg-background overflow-hidden">
                      {shot.screenshotData && shot.screenshotData.startsWith("data:image") ? (
                        <img
                          src={shot.screenshotData}
                          alt={`${shot.pageType} screenshot`}
                          className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-300"
                        />
                      ) : shot.screenshotData && shot.screenshotData.length > 100 ? (
                        <img
                          src={`data:image/png;base64,${shot.screenshotData}`}
                          alt={`${shot.pageType} screenshot`}
                          className="w-full h-full object-cover object-top group-hover:scale-[1.02] transition-transform duration-300"
                        />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center text-muted-foreground/30">
                          <Camera className="w-8 h-8" />
                        </div>
                      )}
                      {/* Page type badge overlay */}
                      <span className={cn(
                        "absolute top-2 left-2 text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase tracking-wider",
                        PAGE_TYPE_BADGE[shot.pageType] ?? "bg-muted text-muted-foreground border-border"
                      )}>
                        {shot.pageType}
                      </span>
                      {/* Status code */}
                      {shot.statusCode && (
                        <span className={cn(
                          "absolute top-2 right-2 text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold",
                          shot.statusCode < 300 ? "bg-green-500/20 text-green-400" :
                          shot.statusCode < 400 ? "bg-blue-500/20 text-blue-400" :
                          shot.statusCode < 500 ? "bg-yellow-500/20 text-yellow-400" :
                          "bg-red-500/20 text-red-400"
                        )}>
                          {shot.statusCode}
                        </span>
                      )}
                      {/* Sensitive findings badge */}
                      {criticalOrHigh.length > 0 && (
                        <div className="absolute bottom-2 right-2 flex items-center gap-1 bg-red-500/90 text-white text-[10px] px-1.5 py-0.5 rounded font-semibold">
                          <AlertTriangle className="w-2.5 h-2.5" />
                          {criticalOrHigh.length} critical
                        </div>
                      )}
                    </div>

                    {/* Card footer */}
                    <div className="p-2.5">
                      <p className="text-xs font-medium line-clamp-1 mb-0.5">{shot.title || shot.url}</p>
                      <p className="text-[10px] text-muted-foreground font-mono line-clamp-1">{shot.url}</p>
                      {shotFindings.length > 0 && (
                        <div className="flex gap-1 flex-wrap mt-1.5">
                          {shotFindings.slice(0, 3).map((f: any, i: number) => (
                            <span key={i} className={cn("text-[9px] px-1.5 py-0.5 rounded border font-medium", FINDING_SEVERITY_COLOR[f.severity])}>
                              {f.type}
                            </span>
                          ))}
                          {shotFindings.length > 3 && (
                            <span className="text-[9px] text-muted-foreground px-1 py-0.5">+{shotFindings.length - 3} more</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {!screenshotting && shots.length > 0 && (
            <p className="text-[10px] text-muted-foreground/50 mt-3">
              Last captured: {formatDate(shots[0]?.capturedAt)} · {shots.length} page{shots.length === 1 ? "" : "s"} · Chromium headless
            </p>
          )}
        </div>
      )}

      {/* ── Expanded Screenshot Lightbox ───────────────────────────────────── */}
      {expandedShot && (
        <div
          className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
          onClick={() => setExpandedShot(null)}
        >
          <div
            className="bg-card border border-border rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div className="flex items-center gap-2">
                <span className={cn(
                  "text-xs px-2 py-0.5 rounded border font-semibold uppercase tracking-wider",
                  PAGE_TYPE_BADGE[expandedShot.pageType] ?? "bg-muted text-muted-foreground border-border"
                )}>
                  {expandedShot.pageType}
                </span>
                <span className="text-sm font-medium line-clamp-1">{expandedShot.title || expandedShot.url}</span>
                {expandedShot.statusCode && (
                  <span className={cn(
                    "text-xs px-1.5 py-0.5 rounded font-mono",
                    expandedShot.statusCode < 300 ? "text-green-400" :
                    expandedShot.statusCode < 400 ? "text-blue-400" :
                    expandedShot.statusCode < 500 ? "text-yellow-400" : "text-red-400"
                  )}>
                    {expandedShot.statusCode}
                  </span>
                )}
              </div>
              <Button size="sm" variant="ghost" onClick={() => setExpandedShot(null)}><X className="w-4 h-4" /></Button>
            </div>

            <div className="p-4 space-y-4">
              {/* Full screenshot */}
              <div className="rounded-lg overflow-hidden border border-border bg-background">
                {expandedShot.screenshotData && (
                  <img
                    src={expandedShot.screenshotData.startsWith("data:") ? expandedShot.screenshotData : `data:image/png;base64,${expandedShot.screenshotData}`}
                    alt="Full page screenshot"
                    className="w-full object-contain"
                  />
                )}
              </div>

              {/* URL */}
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">URL</p>
                <a href={expandedShot.url} target="_blank" rel="noopener noreferrer"
                   className="text-sm font-mono text-primary hover:underline flex items-center gap-1">
                  {expandedShot.url} <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              {/* Sensitive findings */}
              {(expandedShot.findings?.length ?? 0) > 0 && (
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wider mb-2">
                    Sensitive Disclosures ({expandedShot.findings.length})
                  </p>
                  <div className="space-y-2">
                    {expandedShot.findings.map((f: any, i: number) => (
                      <div key={i} className={cn("rounded-lg border p-3", FINDING_SEVERITY_COLOR[f.severity])}>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-[10px] font-semibold uppercase tracking-wider">{f.severity}</span>
                          <span className="text-xs font-medium">{f.type}</span>
                        </div>
                        <p className="text-xs font-mono break-all opacity-80">{f.value}</p>
                        {f.context && (
                          <p className="text-[10px] opacity-60 mt-1 break-all">{f.context}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {(expandedShot.findings?.length ?? 0) === 0 && (
                <div className="flex items-center gap-2 text-emerald-400 text-sm">
                  <ShieldCheck className="w-4 h-4" />
                  No sensitive disclosures detected on this page.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
