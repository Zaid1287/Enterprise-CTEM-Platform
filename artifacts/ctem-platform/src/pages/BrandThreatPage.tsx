import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import {
  useListBrandThreats, useCreateBrandThreatScan, useDeleteBrandThreatScan,
  getListBrandThreatsQueryKey, useListAssets,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert, Plus, Trash2, Loader2, Globe, AlertTriangle,
  CheckCircle2, Clock, XCircle, RefreshCw, Eye, Zap, Shield,
  TrendingUp, Activity, Search, ChevronRight, Fish, Database, Target,
  BookmarkCheck, Tag, Mail, Smartphone, AtSign, Link, CalendarClock,
  RotateCw, Edit2, Check, X, LockKeyhole, Megaphone, Image,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { getToken } from "@/lib/auth";

const RISK_META: Record<string, { color: string; bg: string; border: string; dot: string }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10",    border: "border-red-500/25",    dot: "bg-red-400" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/25", dot: "bg-orange-400" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/25", dot: "bg-yellow-400" },
  low:      { color: "text-green-400",  bg: "bg-green-500/10",  border: "border-green-500/25",  dot: "bg-green-400" },
};

const STATUS_CONFIG: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  pending: { icon: <Clock className="w-3.5 h-3.5" />,                          label: "Queued",   color: "text-muted-foreground" },
  running: { icon: <Loader2 className="w-3.5 h-3.5 animate-spin" />,           label: "Scanning", color: "text-blue-400" },
  done:    { icon: <CheckCircle2 className="w-3.5 h-3.5" />,                   label: "Complete", color: "text-green-400" },
  error:   { icon: <XCircle className="w-3.5 h-3.5" />,                        label: "Error",    color: "text-red-400" },
};

const SCANNABLE_TYPES = ["keyword","logo_url","domain","email","social_handle","mobile_app","subdomain","url"] as const;
const TYPE_LABEL: Record<string, string> = { domain: "Domain", subdomain: "Subdomain", url: "URL" };

function normalizeDomainPreview(value: string): string {
  return value.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!;
}

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [selectedAsset, setSelectedAsset] = useState<any | null>(null);
  const [search, setSearch] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const { mutateAsync } = useCreateBrandThreatScan();
  const { toast } = useToast();

  const { data: allAssets = [], isLoading: assetsLoading } = useListAssets(
    {},
    { query: { queryKey: ["assets", "brand-threat-modal"], staleTime: 30_000 } },
  );

  const eligibleAssets = (allAssets as any[]).filter(
    (a: any) => SCANNABLE_TYPES.includes(a.type) && a.value,
  );

  // Verified = selectable; unverified = shown but disabled
  const verifiedAssets   = eligibleAssets.filter((a: any) => a.verificationStatus === "verified");
  const unverifiedAssets = eligibleAssets.filter((a: any) => a.verificationStatus !== "verified");

  const allSorted = [...verifiedAssets, ...unverifiedAssets];

  const filtered = search.trim()
    ? allSorted.filter((a: any) =>
        a.name?.toLowerCase().includes(search.toLowerCase()) ||
        a.value?.toLowerCase().includes(search.toLowerCase()),
      )
    : allSorted;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedAsset) return;
    setSubmitting(true);
    try {
      await mutateAsync({ data: { assetId: selectedAsset.id } });
      toast({
        title: "Scan started",
        description: `Running brand threat scan for ${normalizeDomainPreview(selectedAsset.value)}`,
      });
      onSuccess();
    } catch (err: any) {
      const msg = err?.response?.data?.error ?? "Failed to start scan";
      toast({ title: msg, variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-card border border-border rounded-2xl w-full max-w-lg shadow-2xl flex flex-col max-h-[90vh]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-border shrink-0">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-primary" />
            </div>
            <h2 className="text-base font-semibold">New Brand Threat Scan</h2>
          </div>
          <p className="text-xs text-muted-foreground mt-2 ml-11 leading-relaxed">
            Select an asset from your inventory to scan for typosquatting, phishing, and brand abuse.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col flex-1 overflow-hidden">
          <div className="p-6 space-y-4 flex-1 overflow-hidden flex flex-col">
            {/* Search */}
            <div className="relative shrink-0">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <input
                ref={searchRef}
                type="text"
                placeholder="Search assets by name or domain…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="w-full bg-background border border-border rounded-lg pl-8 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                autoFocus
              />
            </div>

            {/* Asset list */}
            <div className="flex-1 overflow-y-auto space-y-1 min-h-0 pr-0.5">
              {assetsLoading ? (
                <div className="flex items-center justify-center py-10 text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                  <span className="text-sm">Loading assets…</span>
                </div>
              ) : filtered.length === 0 ? (
                <div className="text-center py-10 text-muted-foreground">
                  <Globe className="w-6 h-6 mx-auto mb-2 opacity-30" />
                  <p className="text-sm font-medium">No domain assets found</p>
                  <p className="text-xs mt-1 opacity-60">
                    {eligibleAssets.length === 0
                      ? "Add domain, subdomain, or URL assets to your inventory first."
                      : "No assets match your search."}
                  </p>
                </div>
              ) : (
                filtered.map((asset: any) => {
                  const isSelected = selectedAsset?.id === asset.id;
                  const isVerified = asset.verificationStatus === "verified";
                  const preview = normalizeDomainPreview(asset.value);
                  return (
                    <button
                      key={asset.id}
                      type="button"
                      disabled={!isVerified}
                      onClick={() => isVerified ? setSelectedAsset(isSelected ? null : asset) : undefined}
                      title={!isVerified ? "Verify asset ownership first to enable brand threat scanning" : undefined}
                      className={cn(
                        "w-full text-left px-3 py-2.5 rounded-xl border transition-all flex items-center gap-3",
                        !isVerified
                          ? "opacity-45 cursor-not-allowed border-border/40 bg-background/30"
                          : isSelected
                            ? "border-primary/60 bg-primary/8 ring-1 ring-primary/30"
                            : "border-border bg-background/50 hover:border-border/80 hover:bg-muted/30",
                      )}
                    >
                      <div className={cn(
                        "w-7 h-7 rounded-lg flex items-center justify-center shrink-0",
                        isSelected && isVerified ? "bg-primary/15" : "bg-muted/40",
                      )}>
                        {isVerified
                          ? <Globe className={cn("w-3.5 h-3.5", isSelected ? "text-primary" : "text-muted-foreground")} />
                          : <LockKeyhole className="w-3.5 h-3.5 text-muted-foreground/60" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={cn("text-sm font-medium truncate", !isVerified && "text-muted-foreground")}>
                            {asset.name || preview}
                          </span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded border bg-muted/50 border-border text-muted-foreground shrink-0">
                            {TYPE_LABEL[asset.type] ?? asset.type}
                          </span>
                          {!isVerified && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded border bg-yellow-500/10 border-yellow-500/25 text-yellow-500/80 shrink-0">
                              Unverified
                            </span>
                          )}
                          {asset.tenantName && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded border bg-blue-500/10 border-blue-500/25 text-blue-400 shrink-0 hidden sm:inline">
                              {asset.tenantName}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-muted-foreground font-mono truncate mt-0.5">{preview}</p>
                      </div>
                      {isSelected && isVerified && (
                        <div className="w-4 h-4 rounded-full bg-primary flex items-center justify-center shrink-0">
                          <Check className="w-2.5 h-2.5 text-primary-foreground" />
                        </div>
                      )}
                    </button>
                  );
                })
              )}
            </div>

            {/* Selected preview */}
            {selectedAsset && (
              <div className="shrink-0 bg-primary/5 border border-primary/20 rounded-xl px-3 py-2.5 flex items-center gap-2.5">
                <Target className="w-3.5 h-3.5 text-primary shrink-0" />
                <div className="flex-1 min-w-0">
                  <span className="text-xs text-muted-foreground">Scanning: </span>
                  <span className="text-xs font-mono font-semibold text-foreground">{normalizeDomainPreview(selectedAsset.value)}</span>
                </div>
                <button type="button" onClick={() => setSelectedAsset(null)} className="text-muted-foreground hover:text-foreground">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {/* Pipeline info */}
            <div className="grid grid-cols-3 gap-2 shrink-0">
              {[
                { icon: <Globe className="w-3 h-3" />,    label: "Typosquatting",  sub: "dnstwist + DNS" },
                { icon: <Fish className="w-3 h-3" />,     label: "Phishing feeds", sub: "PhishTank · OpenPhish" },
                { icon: <Database className="w-3 h-3" />, label: "Data leaks",     sub: "HIBP breach lookup" },
              ].map(item => (
                <div key={item.label} className="bg-background/80 border border-border/50 rounded-xl p-2.5 text-center">
                  <div className="flex justify-center mb-1 text-muted-foreground">{item.icon}</div>
                  <p className="text-[10px] font-semibold">{item.label}</p>
                  <p className="text-[9px] text-muted-foreground/60 leading-tight mt-0.5">{item.sub}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Footer */}
          <div className="px-6 pb-6 shrink-0 flex gap-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose} className="flex-1">Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting || !selectedAsset} className="flex-1">
              {submitting ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Shield className="w-3.5 h-3.5 mr-1.5" />}
              Start Scan
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ScanCard({ scan, onDelete, onView, onRetry, deleting, retrying }: {
  scan: any; onDelete: (id: number) => void; onView: (id: number) => void; onRetry: (id: number) => void; deleting: boolean; retrying: boolean;
}) {
  const status     = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const risk       = RISK_META[scan.phishingRisk] ?? RISK_META.low;
  const liveCount  = scan.liveCount ?? 0;
  const isActive   = scan.status === "running" || scan.status === "pending";
  const isDone     = scan.status === "done";
  const isCritical = isDone && scan.phishingRisk === "critical";
  const isHigh     = isDone && scan.phishingRisk === "high";
  const isMedium   = isDone && scan.phishingRisk === "medium";
  const hasStats   = isDone || (scan.status === "error" && (liveCount > 0 || (scan.phishingCount ?? 0) > 0 || (scan.dataLeakCount ?? 0) > 0 || (scan.brandAbuseCount ?? 0) > 0));

  return (
    <div className={cn(
      "bg-card border rounded-2xl overflow-hidden transition-all hover:shadow-lg hover:-translate-y-0.5 flex flex-col",
      isActive   ? "border-blue-500/30" :
      isCritical ? "border-red-500/40 shadow-[0_0_20px_-4px_rgba(239,68,68,0.15)]" :
      isHigh     ? "border-orange-500/30" :
      "border-border",
    )}>
      {/* Accent bar — thicker gradient for critical, solid for others */}
      <div className={cn(
        "h-1.5 w-full shrink-0",
        isDone ? (
          isCritical ? "bg-gradient-to-r from-red-600 via-red-500 to-orange-500" :
          isHigh     ? "bg-orange-500" :
          isMedium   ? "bg-yellow-500" : "bg-green-500"
        ) : isActive ? "bg-blue-500 animate-pulse" : "bg-muted"
      )} />

      <div className="p-5 flex flex-col flex-1 gap-3">

        {/* ── Header ── */}
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              {scan.watchlistItemType && scan.watchlistItemType !== "domain" && scan.watchlistItemType !== "subdomain" && scan.watchlistItemType !== "url" ? (
                <>
                  {(() => {
                    const typeIcon: Record<string, React.ReactNode> = {
                      keyword: <Tag className="w-3.5 h-3.5 text-violet-400 shrink-0" />,
                      email: <AtSign className="w-3.5 h-3.5 text-orange-400 shrink-0" />,
                      social_handle: <AtSign className="w-3.5 h-3.5 text-pink-400 shrink-0" />,
                      mobile_app: <Smartphone className="w-3.5 h-3.5 text-blue-400 shrink-0" />,
                      logo_url: <Image className="w-3.5 h-3.5 text-cyan-400 shrink-0" />,
                    };
                    const typeLabel: Record<string, string> = {
                      keyword: "Keyword",
                      email: "Email",
                      social_handle: "Social",
                      mobile_app: "Mobile App",
                      logo_url: "Logo",
                      ip: "IP",
                    };
                    return (
                      <>
                        {typeIcon[scan.watchlistItemType] ?? <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />}
                        <span className="text-sm font-semibold font-mono truncate">{scan.watchlistItemValue ?? scan.domain}</span>
                        <span className="text-[10px] bg-muted/60 text-muted-foreground border border-border px-1.5 py-0.5 rounded-full shrink-0">
                          {typeLabel[scan.watchlistItemType] ?? scan.watchlistItemType} scan
                        </span>
                      </>
                    );
                  })()}
                </>
              ) : (
                <>
                  <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  <span className="text-sm font-semibold font-mono truncate">{scan.domain}</span>
                </>
              )}
              {scan.pipelineScanId && (
                <span className="text-[10px] bg-violet-500/10 text-violet-400 border border-violet-500/20 px-1.5 py-0.5 rounded-full flex items-center gap-0.5 shrink-0">
                  <Zap className="w-2.5 h-2.5" /> Auto
                </span>
              )}
              {(scan.scanCount ?? 1) > 1 && (
                <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 rounded-full shrink-0">
                  #{scan.scanCount} scan
                </span>
              )}
            </div>
            <p className="text-[11px] text-muted-foreground mt-1 leading-relaxed">
              {scan.lastScannedAt
                ? <>Last scanned {formatDate(scan.lastScannedAt)} · First seen {formatDate(scan.createdAt)}</>
                : formatDate(scan.createdAt)
              }
            </p>
          </div>
          <span className={cn("flex items-center gap-1 text-[11px] font-medium shrink-0", status.color)}>
            {status.icon}
            {status.label}
          </span>
        </div>

        {/* ── Critical / High threat banner ── */}
        {(isCritical || isHigh) && (
          <div className={cn(
            "rounded-xl px-3.5 py-2.5 flex items-center gap-2.5 border",
            isCritical
              ? "bg-red-500/8 border-red-500/30"
              : "bg-orange-500/8 border-orange-500/25",
          )}>
            <div className={cn(
              "w-2 h-2 rounded-full shrink-0",
              isCritical ? "bg-red-500 animate-pulse" : "bg-orange-500",
            )} />
            <div className="flex-1 min-w-0">
              <p className={cn("text-xs font-semibold leading-tight", isCritical ? "text-red-400" : "text-orange-400")}>
                {isCritical ? "Critical Phishing Threat Detected" : "High Phishing Risk Identified"}
              </p>
              <p className="text-[10px] text-muted-foreground mt-0.5 leading-relaxed">
                {isCritical
                  ? `${liveCount > 0 ? `${liveCount} live domain${liveCount !== 1 ? "s" : ""} actively impersonating` : "Active threat actors targeting"} this brand`
                  : `${liveCount > 0 ? `${liveCount} live suspicious domain${liveCount !== 1 ? "s" : ""} detected` : "Elevated threat indicators found"}`
                }
              </p>
            </div>
            <ShieldAlert className={cn("w-4 h-4 shrink-0", isCritical ? "text-red-400" : "text-orange-400")} />
          </div>
        )}

        {/* ── Stats grid ── */}
        {hasStats && (
          <div className="grid grid-cols-3 gap-2">
            {[
              {
                icon: <Activity className="w-2.5 h-2.5" />,
                label: "Live",
                value: liveCount,
                positive: liveCount > 0,
                activeColor: "text-red-400",
                activeBg: "bg-red-500/8 border-red-500/20",
              },
              {
                icon: <Fish className="w-2.5 h-2.5" />,
                label: "Phishing",
                value: scan.phishingCount ?? 0,
                positive: (scan.phishingCount ?? 0) > 0,
                activeColor: "text-red-500",
                activeBg: "bg-red-500/10 border-red-500/25",
              },
              {
                icon: <Globe className="w-2.5 h-2.5" />,
                label: "Registered",
                value: scan.registeredCount ?? 0,
                positive: (scan.registeredCount ?? 0) > 0,
                activeColor: "text-orange-400",
                activeBg: "bg-orange-500/8 border-orange-500/20",
              },
              {
                icon: <Database className="w-2.5 h-2.5" />,
                label: "Leaks",
                value: scan.dataLeakCount ?? 0,
                positive: (scan.dataLeakCount ?? 0) > 0,
                activeColor: "text-yellow-400",
                activeBg: "bg-yellow-500/8 border-yellow-500/20",
              },
              {
                icon: <Target className="w-2.5 h-2.5" />,
                label: "Abuse",
                value: scan.brandAbuseCount ?? 0,
                positive: (scan.brandAbuseCount ?? 0) > 0,
                activeColor: "text-yellow-500",
                activeBg: "bg-yellow-500/10 border-yellow-500/25",
              },
              {
                icon: <Megaphone className="w-2.5 h-2.5" />,
                label: "Mal. Ads",
                value: scan.adMonitoringCount ?? 0,
                positive: (scan.adMonitoringCount ?? 0) > 0,
                activeColor: "text-violet-400",
                activeBg: "bg-violet-500/10 border-violet-500/25",
              },
            ].map(item => (
              <div key={item.label} className={cn(
                "rounded-xl p-2.5 text-center border transition-colors",
                item.positive ? item.activeBg : "bg-background/60 border-border/50",
              )}>
                <p className={cn(
                  "text-[10px] mb-0.5 flex items-center justify-center gap-0.5",
                  item.positive ? "text-muted-foreground" : "text-muted-foreground/60",
                )}>
                  {item.icon} {item.label}
                </p>
                <p className={cn(
                  "text-base font-bold tabular-nums",
                  item.positive ? item.activeColor : "text-muted-foreground/40",
                )}>
                  {item.value}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* ── Running progress ── */}
        {isActive && (
          <div className="bg-blue-500/5 border border-blue-500/20 rounded-xl p-3">
            <div className="flex items-center gap-2.5 mb-2">
              <Loader2 className="w-4 h-4 animate-spin text-blue-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-blue-400">Intelligence scan in progress</p>
                <p className="text-[10px] text-muted-foreground truncate">
                  {scan.totalPermutations > 0
                    ? `${scan.totalPermutations} permutations · RDAP + GeoIP + VT + phishing feeds + HIBP…`
                    : "Generating permutations + running intelligence engines…"}
                </p>
              </div>
              <span className="text-[11px] font-bold text-blue-400 shrink-0 tabular-nums">{scan.progress ?? 0}%</span>
            </div>
            <div className="w-full bg-blue-500/10 rounded-full h-1.5 overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-700 ease-in-out"
                style={{ width: `${Math.max(3, scan.progress ?? 0)}%` }}
              />
            </div>
          </div>
        )}

        {/* ── Error ── */}
        {scan.status === "error" && (() => {
          const isTimeout = scan.error?.toLowerCase().includes("timed out");
          return (
            <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-3">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-semibold text-red-400">
                    {isTimeout ? "Scan timed out" : "Scan failed"}
                  </p>
                  <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed font-mono line-clamp-2">
                    {scan.error ?? "An unexpected error occurred."}
                  </p>
                  {isTimeout && (
                    <p className="text-[11px] text-muted-foreground/70 mt-1">
                      Click Retry Scan to start a fresh scan.
                    </p>
                  )}
                </div>
              </div>
            </div>
          );
        })()}

        {/* ── Footer ── */}
        <div className="flex items-center justify-between gap-2 mt-auto pt-1 border-t border-border/40">
          {isDone && scan.phishingRisk ? (
            <div className={cn(
              "flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border",
              risk.bg, risk.border,
            )}>
              {isCritical ? (
                <ShieldAlert className={cn("w-3.5 h-3.5 shrink-0", risk.color)} />
              ) : (
                <Shield className={cn("w-3 h-3 shrink-0", risk.color)} />
              )}
              <span className={cn("text-[11px] font-semibold capitalize", risk.color)}>
                {scan.phishingRisk} phishing risk
              </span>
            </div>
          ) : <div />}

          <div className="flex items-center gap-1">
            {(isDone || scan.status === "error") && (
              <Button size="sm" variant="ghost" onClick={() => onView(scan.id)} className="h-7 text-xs gap-1">
                View <ChevronRight className="w-3 h-3" />
              </Button>
            )}
            {scan.status === "error" && (
              <Button
                size="sm" variant="ghost"
                onClick={() => onRetry(scan.id)}
                disabled={retrying}
                className="h-7 text-xs gap-1 text-red-400 hover:text-red-300"
              >
                {retrying ? <Loader2 className="w-3 h-3 animate-spin" /> : <RotateCw className="w-3 h-3" />}
                Retry
              </Button>
            )}
            <Button
              size="sm" variant="ghost"
              onClick={() => onDelete(scan.id)}
              disabled={deleting}
              className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
            >
              {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
            </Button>
          </div>
        </div>

      </div>
    </div>
  );
}

const WATCHLIST_TYPE_ICONS: Record<string, React.ReactNode> = {
  keyword:       <Tag className="w-3.5 h-3.5" />,
  logo_url:      <Link className="w-3.5 h-3.5" />,
  domain:        <Globe className="w-3.5 h-3.5" />,
  ip:            <Target className="w-3.5 h-3.5" />,
  email:         <Mail className="w-3.5 h-3.5" />,
  social_handle: <AtSign className="w-3.5 h-3.5" />,
  mobile_app:    <Smartphone className="w-3.5 h-3.5" />,
};

const WATCHLIST_TYPES = ["keyword","logo_url","domain","ip","email","social_handle","mobile_app"] as const;

const FREQ_LABELS: Record<string, string> = {
  none:    "No schedule",
  daily:   "Daily",
  weekly:  "Weekly",
  monthly: "Monthly",
};

const DAYS_FULL = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

interface WatchlistSchedule {
  frequency: string;
  scanTime: string;
  dayOfWeek: number | null;
  dayOfMonth: number | null;
}

function scheduleLabel(item: any): string {
  const freq = item.frequency ?? "none";
  if (freq === "none") return "";
  const time = item.scanTime ?? "03:00";
  if (freq === "daily") return `Daily at ${time} UTC`;
  if (freq === "weekly") {
    const day = DAYS_FULL[item.dayOfWeek ?? 1] ?? "Monday";
    return `Weekly · ${day} at ${time} UTC`;
  }
  if (freq === "monthly") {
    const dom = item.dayOfMonth ?? 1;
    const suffix = dom === 1 ? "st" : dom === 2 ? "nd" : dom === 3 ? "rd" : "th";
    return `Monthly · ${dom}${suffix} at ${time} UTC`;
  }
  return FREQ_LABELS[freq] ?? freq;
}

function WatchlistItem({
  item, onDelete, onScheduleChange, onEdit, deleting, latestScan, onViewScan, onRunScan, onView, runningScan, allAssets = [],
}: {
  item: any;
  onDelete: (id: number) => void;
  onScheduleChange: (id: number, schedule: WatchlistSchedule) => void;
  onEdit: (id: number, updates: { value: string; type: string; notes: string; assetId?: number | null }) => Promise<void>;
  allAssets?: any[];
  deleting: boolean;
  latestScan?: any;
  onViewScan?: (id: number) => void;
  onRunScan?: (item: any) => void;
  onView?: (item: any) => void;
  runningScan?: boolean;
}) {
  const [editingFreq, setEditingFreq] = useState(false);
  const [pendingFreq, setPendingFreq] = useState<string>(item.frequency ?? "none");
  const [pendingTime, setPendingTime] = useState<string>(item.scanTime ?? "03:00");
  const [pendingDow, setPendingDow] = useState<number>(item.dayOfWeek ?? 1);
  const [pendingDom, setPendingDom] = useState<number>(item.dayOfMonth ?? 1);
  const isSchedulable = item.type !== "ip";

  // Inline item edit state
  const [editingItem, setEditingItem] = useState(false);
  const [editValue, setEditValue] = useState(item.value ?? "");
  const [editType, setEditType] = useState(item.type ?? "domain");
  const [editNotes, setEditNotes] = useState(item.notes ?? "");
  const [editAssetId, setEditAssetId] = useState<number | null>(item.assetId ?? null);
  const [savingEdit, setSavingEdit] = useState(false);

  // Derive linked asset name for display badge
  const linkedAsset = item.assetId ? (allAssets as any[]).find((a: any) => a.id === item.assetId) : null;

  function openItemEdit() {
    setEditValue(item.value ?? "");
    setEditType(item.type ?? "domain");
    setEditNotes(item.notes ?? "");
    setEditAssetId(item.assetId ?? null);
    setEditingFreq(false); // close schedule editor if open
    setEditingItem(true);
  }

  async function saveItemEdit() {
    if (!editValue.trim()) return;
    setSavingEdit(true);
    try {
      await onEdit(item.id, { value: editValue.trim(), type: editType, notes: editNotes, assetId: editAssetId });
      setEditingItem(false);
    } finally {
      setSavingEdit(false);
    }
  }

  function openEditor() {
    setPendingFreq(item.frequency ?? "none");
    setPendingTime(item.scanTime ?? "03:00");
    setPendingDow(item.dayOfWeek ?? 1);
    setPendingDom(item.dayOfMonth ?? 1);
    setEditingItem(false); // close item editor if open
    setEditingFreq(true);
  }

  function saveSchedule() {
    onScheduleChange(item.id, {
      frequency: pendingFreq,
      scanTime: pendingTime,
      dayOfWeek: pendingFreq === "weekly" ? pendingDow : null,
      dayOfMonth: pendingFreq === "monthly" ? pendingDom : null,
    });
    setEditingFreq(false);
  }

  const label = scheduleLabel(item);
  // Live preview of derived scan domain while editing
  const editPreview = editingItem ? extractScanDomain({ type: editType, value: editValue }) : null;

  return (
    <div className="bg-muted/10 border border-border rounded-xl px-4 py-3 space-y-2">
      <div className="flex items-center gap-3">
        <span className="text-muted-foreground shrink-0">
          {WATCHLIST_TYPE_ICONS[item.type] ?? <Tag className="w-3.5 h-3.5" />}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-mono font-medium truncate">{item.value}</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-muted border border-border text-muted-foreground capitalize shrink-0">
              {item.type?.replace(/_/g, " ")}
            </span>
            {isSchedulable && label && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 flex items-center gap-1 shrink-0">
                <RotateCw className="w-2.5 h-2.5" />
                {label}
              </span>
            )}
            {linkedAsset && (
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center gap-1 shrink-0" title={`Linked to asset: ${linkedAsset.name ?? linkedAsset.domain ?? `#${linkedAsset.id}`}`}>
                <CheckCircle2 className="w-2.5 h-2.5" />
                {linkedAsset.name ?? linkedAsset.domain ?? `Asset #${linkedAsset.id}`}
              </span>
            )}
          </div>
          {item.notes && (
            <p className="text-xs text-muted-foreground/70 mt-0.5 truncate">{item.notes}</p>
          )}
          {/* For non-domain types, show the derived domain that will be scanned */}
          {!["domain","subdomain","url"].includes(item.type) && (() => {
            const { domain } = extractScanDomain(item);
            if (!domain) return null;
            return (
              <p className="text-[10px] text-muted-foreground/50 mt-0.5 flex items-center gap-1">
                <Globe className="w-2.5 h-2.5 shrink-0" />
                Scans: <span className="font-mono">{domain}</span>
              </p>
            );
          })()}
        </div>
        <span className="text-[10px] text-muted-foreground/50 shrink-0 hidden sm:block">{formatDate(item.createdAt)}</span>
        {/* Scan status badge — shown when a scan exists */}
        {latestScan && (
          <span className={cn(
            "text-[10px] px-2 py-0.5 rounded-full border flex items-center gap-1 shrink-0",
            latestScan.status === "done"    ? "bg-green-500/10 border-green-500/20 text-green-400" :
            latestScan.status === "running" ? "bg-blue-500/10 border-blue-500/20 text-blue-400" :
            latestScan.status === "failed"  ? "bg-red-500/10 border-red-500/20 text-red-400" :
                                              "bg-muted border-border text-muted-foreground"
          )}>
            {latestScan.status === "running" && <Loader2 className="w-2.5 h-2.5 animate-spin" />}
            {latestScan.status === "done" && <CheckCircle2 className="w-2.5 h-2.5" />}
            {latestScan.status === "failed" && <XCircle className="w-2.5 h-2.5" />}
            {latestScan.status === "done" ? "Scanned" : latestScan.status === "running" ? "Scanning…" : latestScan.status === "failed" ? "Failed" : latestScan.status}
          </span>
        )}
        {/* View Intel — always visible; routes to scan detail or triggers new scan */}
        {onView && (
          <Button
            variant="ghost" size="sm"
            onClick={() => onView(item)}
            disabled={runningScan}
            className="h-7 text-[11px] px-2.5 text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 shrink-0 gap-1 font-medium"
            title={latestScan ? "View brand threat intelligence for this item" : "Start a scan to view intelligence"}
          >
            {runningScan
              ? <Loader2 className="w-3 h-3 animate-spin" />
              : latestScan ? <Eye className="w-3 h-3" /> : <Zap className="w-3 h-3" />}
            {runningScan ? "Starting…" : latestScan ? "View Intel" : "Scan Now"}
          </Button>
        )}
        {/* Re-scan button — shown for all types that can produce a scan domain */}
        {latestScan && item.type !== "ip" && onRunScan && (
          <Button
            variant="ghost" size="sm"
            onClick={() => onRunScan(item)}
            disabled={runningScan}
            className="h-7 text-[11px] px-2 text-emerald-400 hover:text-emerald-300 shrink-0 gap-1"
            title="Run a fresh brand threat scan"
          >
            <RefreshCw className="w-3 h-3" />
            Re-scan
          </Button>
        )}
        {isSchedulable && (
          <Button
            variant="ghost" size="sm"
            onClick={() => editingFreq ? setEditingFreq(false) : openEditor()}
            className={cn("h-7 w-7 p-0 shrink-0", editingFreq ? "text-blue-400" : "text-muted-foreground hover:text-blue-400")}
            title="Set scan schedule"
          >
            <CalendarClock className="w-3.5 h-3.5" />
          </Button>
        )}
        <Button
          variant="ghost" size="sm"
          onClick={() => editingItem ? setEditingItem(false) : openItemEdit()}
          className={cn("h-7 w-7 p-0 shrink-0", editingItem ? "text-amber-400" : "text-muted-foreground hover:text-amber-400")}
          title="Edit watchlist item"
        >
          <Edit2 className="w-3.5 h-3.5" />
        </Button>
        <Button
          variant="ghost" size="sm"
          onClick={() => onDelete(item.id)}
          disabled={deleting}
          className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 shrink-0"
        >
          {deleting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
        </Button>
      </div>

      {/* Scheduling meta row */}
      {isSchedulable && !editingFreq && (item.lastScanAt || item.nextScanAt) && (
        <div className="flex items-center gap-4 pl-7 flex-wrap">
          {item.lastScanAt && (
            <span className="text-[10px] text-muted-foreground/60 flex items-center gap-1">
              <Clock className="w-3 h-3" /> Last scan: {formatDate(item.lastScanAt)}
            </span>
          )}
          {item.nextScanAt && (
            <span className="text-[10px] text-blue-400/70 flex items-center gap-1">
              <CalendarClock className="w-3 h-3" /> Next: {formatDate(item.nextScanAt)}
            </span>
          )}
        </div>
      )}

      {/* Inline item editor */}
      {editingItem && (
        <div className="space-y-2.5 pt-2 border-t border-amber-500/20 mt-1">
          <p className="text-[10px] font-semibold text-amber-400/80 uppercase tracking-wider">Edit Watchlist Item</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="space-y-1">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Type</span>
              <select
                value={editType}
                onChange={e => { setEditType(e.target.value); setEditValue(""); }}
                className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-amber-500/40"
              >
                {WATCHLIST_TYPES.map(t => (
                  <option key={t} value={t}>{t.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
                {editType === "keyword" ? "Brand Keyword" :
                 editType === "email" ? "Email Address" :
                 editType === "social_handle" ? "Social Handle" :
                 editType === "mobile_app" ? "App Name" :
                 editType === "logo_url" ? "Logo URL" :
                 editType === "ip" ? "IP Address" : "Domain"}
              </span>
              <input
                value={editValue}
                onChange={e => setEditValue(e.target.value)}
                placeholder={TYPE_HINTS[editType]?.placeholder ?? "Enter value"}
                className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-amber-500/40"
                autoFocus
              />
            </div>
          </div>
          {/* Live scan preview */}
          {editValue.trim() && editType !== "ip" && editPreview?.domain && (
            <p className="text-[10px] text-emerald-400/80 flex items-center gap-1.5">
              <Zap className="w-3 h-3 shrink-0" />
              Will scan: <span className="font-mono font-medium">{editPreview.domain}</span>
            </p>
          )}
          {editValue.trim() && editType !== "ip" && !editPreview?.domain && editPreview?.osintLabel && (
            <p className="text-[10px] text-blue-400/80 flex items-center gap-1.5">
              <Zap className="w-3 h-3 shrink-0" />
              {editPreview.osintLabel}
            </p>
          )}
          {editValue.trim() && editType !== "ip" && !editPreview?.domain && !editPreview?.osintLabel && editPreview?.error && (
            <p className="text-[10px] text-muted-foreground/60 flex items-center gap-1.5">
              <AlertTriangle className="w-3 h-3 shrink-0" />
              {editPreview.error}
            </p>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <div className="space-y-1">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Notes (optional)</span>
              <input
                value={editNotes}
                onChange={e => setEditNotes(e.target.value)}
                placeholder="Optional context or description"
                className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-amber-500/40"
              />
            </div>
            <div className="space-y-1">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Link to Asset <span className="opacity-50">(verified only)</span></span>
              <select
                value={editAssetId ?? ""}
                onChange={e => setEditAssetId(e.target.value ? parseInt(e.target.value, 10) : null)}
                className="w-full bg-background border border-border rounded-lg px-2 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-amber-500/40"
              >
                <option value="">— None —</option>
                {(allAssets as any[])
                  .filter((a: any) => a.verificationStatus === "verified")
                  .map((a: any) => (
                    <option key={a.id} value={a.id}>
                      {a.name ?? a.domain ?? `Asset #${a.id}`} ({a.type})
                    </option>
                  ))}
              </select>
            </div>
          </div>
          <div className="flex gap-1.5 justify-end">
            <Button
              size="sm" variant="ghost"
              onClick={() => setEditingItem(false)}
              className="h-7 px-2.5 text-xs text-muted-foreground"
            >
              <X className="w-3 h-3 mr-1" /> Cancel
            </Button>
            <Button
              size="sm" variant="ghost"
              onClick={saveItemEdit}
              disabled={savingEdit || !editValue.trim()}
              className="h-7 px-2.5 text-xs text-amber-400 hover:text-amber-300 hover:bg-amber-500/10"
            >
              {savingEdit ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Check className="w-3 h-3 mr-1" />}
              Save Changes
            </Button>
          </div>
        </div>
      )}

      {/* Inline schedule editor */}
      {editingFreq && (
        <div className="pl-7 space-y-2.5 pt-1 border-t border-border/40 mt-2">
          <div className="flex flex-wrap items-end gap-2">
            {/* Frequency */}
            <div className="space-y-1">
              <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Frequency</span>
              <select
                value={pendingFreq}
                onChange={e => setPendingFreq(e.target.value)}
                className="bg-background border border-border rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40"
              >
                {Object.entries(FREQ_LABELS).map(([v, l]) => (
                  <option key={v} value={v}>{l}</option>
                ))}
              </select>
            </div>

            {/* Time picker — shown for all non-none frequencies */}
            {pendingFreq !== "none" && (
              <div className="space-y-1">
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Time (UTC)</span>
                <input
                  type="time"
                  value={pendingTime}
                  onChange={e => setPendingTime(e.target.value)}
                  className="bg-background border border-border rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40"
                />
              </div>
            )}

            {/* Day of week — weekly only */}
            {pendingFreq === "weekly" && (
              <div className="space-y-1">
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Day</span>
                <select
                  value={pendingDow}
                  onChange={e => setPendingDow(Number(e.target.value))}
                  className="bg-background border border-border rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40"
                >
                  {DAYS_FULL.map((d, i) => <option key={i} value={i}>{d}</option>)}
                </select>
              </div>
            )}

            {/* Day of month — monthly only */}
            {pendingFreq === "monthly" && (
              <div className="space-y-1">
                <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Day of month</span>
                <select
                  value={pendingDom}
                  onChange={e => setPendingDom(Number(e.target.value))}
                  className="bg-background border border-border rounded-lg px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-primary/40"
                >
                  {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              </div>
            )}

            <div className="flex gap-1">
              <Button size="sm" variant="ghost" onClick={saveSchedule} className="h-7 px-2 text-green-400 hover:text-green-300 hover:bg-green-500/10">
                <Check className="w-3.5 h-3.5 mr-1" /> Save
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setEditingFreq(false)} className="h-7 px-2 text-muted-foreground">
                <X className="w-3.5 h-3.5" />
              </Button>
            </div>
          </div>

          {pendingFreq !== "none" && (
            <p className="text-[10px] text-muted-foreground/60">
              {pendingFreq === "daily" && `Runs every day at ${pendingTime} UTC`}
              {pendingFreq === "weekly" && `Runs every ${DAYS_FULL[pendingDow]} at ${pendingTime} UTC`}
              {pendingFreq === "monthly" && `Runs on day ${pendingDom} of every month at ${pendingTime} UTC`}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function normalizeDomain(v: string): string {
  return (v ?? "").toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0]!.split("?")[0]!.trim();
}

/** Per-type: extract the domain (domain/url types) or describe the OSINT scan target */
function extractScanDomain(item: { type: string; value: string }): { domain: string | null; osintLabel?: string; error?: string } {
  const v = (item.value ?? "").trim();
  switch (item.type) {
    case "domain":
    case "subdomain": {
      const d = normalizeDomain(v);
      return d && /\.[a-z]{2,}$/i.test(d) ? { domain: d } : { domain: null, error: "Invalid domain — expected format: example.com" };
    }
    case "url": {
      const d = normalizeDomain(v);
      return d && /\.[a-z]{2,}$/i.test(d) ? { domain: d } : { domain: null, error: "Could not extract a valid domain from this URL" };
    }
    case "logo_url": {
      if (!v.startsWith("http")) return { domain: null, error: "Logo URL must start with http:// or https://" };
      return { domain: null, osintLabel: `Logo OSINT: ad library search, reverse image search, cert transparency` };
    }
    case "email": {
      if (!v.includes("@")) return { domain: null, error: "Invalid email — expected format: user@example.com" };
      return { domain: null, osintLabel: `Email OSINT: breach lookup (HIBP), paste search, MX validation` };
    }
    case "social_handle": {
      const handle = v.replace(/^@+/, "").trim();
      if (!handle) return { domain: null, error: "Enter the handle without @ prefix (e.g. mybrand)" };
      return { domain: null, osintLabel: `Social OSINT: check @${handle} across 10+ platforms + impersonation variants` };
    }
    case "keyword": {
      if (!v) return { domain: null, error: "Keyword cannot be empty" };
      return { domain: null, osintLabel: `Keyword OSINT: Reddit, ads library, cert transparency, DNS lookalikes` };
    }
    case "mobile_app": {
      if (!v) return { domain: null, error: "Enter package ID or app name" };
      return { domain: null, osintLabel: `App OSINT: Google Play direct lookup + app store abuse search` };
    }
    case "ip":
      return { domain: null, error: "IP addresses are correlated against scan results — add the associated domain to run a brand threat scan" };
    default:
      return { domain: null, error: "Unknown watchlist item type" };
  }
}

/** Per-type input guidance for the Add Item form */
const TYPE_HINTS: Record<string, { placeholder: string; hint: string }> = {
  domain:        { placeholder: "e.g. sentinelwares.com",                    hint: "Root domain — typosquatting, phishing detection, cert monitoring" },
  subdomain:     { placeholder: "e.g. app.sentinelwares.com",                hint: "Subdomain — root domain extracted and scanned for threats" },
  url:           { placeholder: "e.g. https://sentinelwares.com/login",      hint: "Any URL — host domain scanned for typosquatting & phishing" },
  keyword:       { placeholder: "e.g. sentinelware",                         hint: "Brand keyword — OSINT: Reddit, ad libraries, DNS lookalikes, cert transparency" },
  email:         { placeholder: "e.g. support@sentinelwares.com",            hint: "Email — OSINT: breach lookup (HIBP), paste search, MX validation" },
  social_handle: { placeholder: "e.g. @sentinelwares or sentinelwares",      hint: "Social handle — OSINT: platform existence check + impersonation variants" },
  mobile_app:    { placeholder: "e.g. com.sentinelware.app or app name",     hint: "Package ID or app name — OSINT: Google Play/App Store abuse search" },
  logo_url:      { placeholder: "e.g. https://sentinelwares.com/logo.png",   hint: "Logo URL — OSINT: ad library search, reverse image search, cert transparency" },
  ip:            { placeholder: "e.g. 1.2.3.4",                              hint: "IP — correlated with typosquatting A records (no direct scan)" },
};

function WatchlistSection() {
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const { data: allScans } = useListBrandThreats({});
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningScanItemId, setRunningScanItemId] = useState<number | null>(null);

  function latestScanForItem(item: any) {
    const scans = (allScans as any[]) ?? [];
    // Primary: match by watchlistItemId (most reliable — set by the new /scan endpoint)
    const byId = scans.find((s: any) => s.watchlistItemId === item.id);
    if (byId) return byId;
    // Secondary: match by watchlistItemType + watchlistItemValue
    const byTypeVal = scans.find((s: any) =>
      s.watchlistItemType === item.type && s.watchlistItemValue === item.value,
    );
    if (byTypeVal) return byTypeVal;
    // Fallback: derive domain and match (legacy domain scans without watchlist metadata)
    const { domain: derivedDomain } = extractScanDomain(item);
    const normalizedVal = normalizeDomain(item.value ?? "");
    const matches = scans.filter((s: any) => {
      const d = normalizeDomain(s.domain ?? "");
      if (derivedDomain && d === normalizeDomain(derivedDomain)) return true;
      if (d && d === normalizedVal) return true;
      return false;
    });
    return matches[0] ?? null;
  }
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [form, setForm] = useState({ value: "", type: "domain", notes: "", frequency: "none", scanTime: "03:00", dayOfWeek: 1, dayOfMonth: 1, assetId: null as number | null });
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const { data: watchlistAssets = [] } = useListAssets({}, { query: { queryKey: ["assets", "watchlist-form"], staleTime: 60_000 } });

  async function fetchItems() {
    setLoading(true);
    try {
      const res = await fetch("/api/brand-watchlist", {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (res.ok) setItems(await res.json());
    } catch { /* ignore */ } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void fetchItems(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.value.trim()) return;
    setSubmitting(true);
    try {
      const res = await fetch("/api/brand-watchlist", {
        method: "POST",
        headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          value: form.value.trim(),
          type: form.type,
          notes: form.notes,
          frequency: form.frequency,
          scanTime: form.frequency !== "none" ? form.scanTime : null,
          dayOfWeek: form.frequency === "weekly" ? form.dayOfWeek : null,
          dayOfMonth: form.frequency === "monthly" ? form.dayOfMonth : null,
          assetId: form.assetId ?? null,
        }),
      });
      if (!res.ok) throw new Error("Failed");
      toast({ title: "Watchlist item added" });
      setShowForm(false);
      setForm({ value: "", type: "domain", notes: "", frequency: "none", scanTime: "03:00", dayOfWeek: 1, dayOfMonth: 1, assetId: null });
      void fetchItems();
    } catch {
      toast({ title: "Failed to add watchlist item", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Remove this watchlist item?")) return;
    setDeletingId(id);
    try {
      await fetch(`/api/brand-watchlist/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      void fetchItems();
    } catch {
      toast({ title: "Failed to remove item", variant: "destructive" });
    } finally {
      setDeletingId(null);
    }
  }

  async function handleRunScan(item: any) {
    setRunningScanItemId(item.id);
    try {
      const res = await fetch(`/api/brand-watchlist/${item.id}/scan`, {
        method: "POST",
        headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error((err as any)?.error ?? "Failed to start scan");
      }
      const scan = await res.json();
      navigate(`/brand-threats/${scan.id}`);
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to start brand threat scan", variant: "destructive" });
    } finally {
      setRunningScanItemId(null);
    }
  }

  async function handleViewItem(item: any) {
    const latest = latestScanForItem(item);
    if (latest) {
      navigate(`/brand-threats/${latest.id}`);
      return;
    }
    const { error } = extractScanDomain(item);
    if (error) {
      toast({ title: error, variant: "destructive" });
      return;
    }
    await handleRunScan(item);
  }

  async function handleScheduleChange(id: number, schedule: WatchlistSchedule) {
    try {
      const res = await fetch(`/api/brand-watchlist/${id}`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          frequency: schedule.frequency,
          scanTime: schedule.scanTime,
          dayOfWeek: schedule.dayOfWeek,
          dayOfMonth: schedule.dayOfMonth,
        }),
      });
      if (!res.ok) throw new Error("Failed");
      const updated = await res.json();
      setItems(prev => prev.map(i => i.id === id ? updated : i));
      toast({
        title: schedule.frequency === "none"
          ? "Auto-scan disabled"
          : `Schedule saved — ${scheduleLabel({ ...schedule, dayOfWeek: schedule.dayOfWeek ?? undefined, dayOfMonth: schedule.dayOfMonth ?? undefined })}`,
      });
    } catch {
      toast({ title: "Failed to update schedule", variant: "destructive" });
    }
  }

  async function handleEditItem(id: number, updates: { value: string; type: string; notes: string; assetId?: number | null }) {
    const res = await fetch(`/api/brand-watchlist/${id}`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
      body: JSON.stringify(updates),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      toast({ title: err.error ?? "Failed to update watchlist item", variant: "destructive" });
      throw new Error(err.error ?? "Failed");
    }
    const updated = await res.json();
    setItems(prev => prev.map(i => i.id === id ? updated : i));
    toast({ title: "Watchlist item updated" });
  }

  const scheduledCount = items.filter((i: any) => i.frequency && i.frequency !== "none").length;

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5">
      <div className="w-full">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-sm font-semibold">Brand Asset Watchlist</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Monitor keywords, domains, emails, social handles, and mobile apps. All items can be auto-scanned on a schedule.
            </p>
            {scheduledCount > 0 && (
              <p className="text-[11px] text-blue-400 mt-1 flex items-center gap-1">
                <RotateCw className="w-3 h-3" />
                {scheduledCount} item{scheduledCount !== 1 ? "s" : ""} scheduled for automatic monitoring
              </p>
            )}
          </div>
          <Button size="sm" onClick={() => setShowForm(v => !v)} className="h-8 gap-1.5">
            <Plus className="w-3.5 h-3.5" /> Add Item
          </Button>
        </div>

        {showForm && (
          <form onSubmit={handleCreate} className="bg-muted/20 border border-border rounded-xl p-4 space-y-3 mb-5">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">New Watchlist Item</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Type</label>
                <select
                  value={form.type}
                  onChange={e => setForm(v => ({ ...v, type: e.target.value, value: "" }))}
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                >
                  {WATCHLIST_TYPES.map(t => (
                    <option key={t} value={t}>{t.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">
                  {form.type === "keyword" ? "Brand Keyword *" :
                   form.type === "email" ? "Email Address *" :
                   form.type === "social_handle" ? "Social Handle *" :
                   form.type === "mobile_app" ? "App Name *" :
                   form.type === "logo_url" ? "Logo URL *" :
                   form.type === "ip" ? "IP Address *" :
                   "Domain *"}
                </label>
                <input
                  value={form.value}
                  onChange={e => setForm(v => ({ ...v, value: e.target.value }))}
                  placeholder={TYPE_HINTS[form.type]?.placeholder ?? "Enter value"}
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                />
              </div>
            </div>
            {/* Per-type hint + scan preview */}
            {form.value.trim() && (() => {
              if (form.type === "ip") {
                return (
                  <p className="text-[11px] text-muted-foreground/70 flex items-center gap-1.5 -mt-1">
                    <Target className="w-3 h-3 shrink-0" />
                    {TYPE_HINTS[form.type]?.hint}
                  </p>
                );
              }
              const { domain, osintLabel, error } = extractScanDomain({ type: form.type, value: form.value });
              if (domain) {
                return (
                  <p className="text-[11px] text-emerald-400/80 flex items-center gap-1.5 -mt-1">
                    <Zap className="w-3 h-3 shrink-0" />
                    Will scan: <span className="font-mono font-medium">{domain}</span>
                  </p>
                );
              }
              if (osintLabel) {
                return (
                  <p className="text-[11px] text-blue-400/80 flex items-center gap-1.5 -mt-1">
                    <Zap className="w-3 h-3 shrink-0" />
                    {osintLabel}
                  </p>
                );
              }
              if (error) {
                return (
                  <p className="text-[11px] text-muted-foreground/60 flex items-center gap-1.5 -mt-1">
                    <AlertTriangle className="w-3 h-3 shrink-0" />
                    {error}
                  </p>
                );
              }
              return null;
            })()}
            {!form.value.trim() && TYPE_HINTS[form.type] && (
              <p className="text-[11px] text-muted-foreground/60 -mt-1">{TYPE_HINTS[form.type]!.hint}</p>
            )}
            {form.type !== "ip" && (
              <div className="space-y-2">
                <label className="text-xs text-muted-foreground block mb-1">
                  <span className="flex items-center gap-1"><CalendarClock className="w-3 h-3" /> Auto-scan Schedule</span>
                </label>
                <div className="flex flex-wrap gap-2">
                  <select
                    value={form.frequency}
                    onChange={e => setForm(v => ({ ...v, frequency: e.target.value }))}
                    className="bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                  >
                    {Object.entries(FREQ_LABELS).map(([val, label]) => (
                      <option key={val} value={val}>{label}</option>
                    ))}
                  </select>
                  {form.frequency !== "none" && (
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-muted-foreground">at</span>
                      <input
                        type="time"
                        value={form.scanTime}
                        onChange={e => setForm(v => ({ ...v, scanTime: e.target.value }))}
                        className="bg-background border border-border rounded-lg px-2 py-1.5 text-sm focus:outline-none"
                      />
                      <span className="text-xs text-muted-foreground">UTC</span>
                    </div>
                  )}
                  {form.frequency === "weekly" && (
                    <select
                      value={form.dayOfWeek}
                      onChange={e => setForm(v => ({ ...v, dayOfWeek: Number(e.target.value) }))}
                      className="bg-background border border-border rounded-lg px-2 py-1.5 text-sm focus:outline-none"
                    >
                      {DAYS_FULL.map((d, i) => <option key={i} value={i}>{d}</option>)}
                    </select>
                  )}
                  {form.frequency === "monthly" && (
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs text-muted-foreground">on day</span>
                      <select
                        value={form.dayOfMonth}
                        onChange={e => setForm(v => ({ ...v, dayOfMonth: Number(e.target.value) }))}
                        className="bg-background border border-border rounded-lg px-2 py-1.5 text-sm focus:outline-none"
                      >
                        {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                          <option key={d} value={d}>{d}</option>
                        ))}
                      </select>
                    </div>
                  )}
                </div>
              </div>
            )}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Description</label>
                <input
                  value={form.notes}
                  onChange={e => setForm(v => ({ ...v, notes: e.target.value }))}
                  placeholder="Optional context for this watchlist item"
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Link to Asset <span className="text-muted-foreground/50">(optional)</span></label>
                <select
                  value={form.assetId ?? ""}
                  onChange={e => setForm(v => ({ ...v, assetId: e.target.value ? parseInt(e.target.value, 10) : null }))}
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                >
                  <option value="">— None —</option>
                  {(watchlistAssets as any[])
                    .filter((a: any) => a.verificationStatus === "verified")
                    .map((a: any) => (
                      <option key={a.id} value={a.id}>{a.name ?? a.domain ?? `Asset #${a.id}`} ({a.type})</option>
                    ))}
                </select>
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <Button type="button" variant="outline" size="sm" onClick={() => setShowForm(false)}>Cancel</Button>
              <Button type="submit" size="sm" disabled={submitting || !form.value.trim()}>
                {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                Add to Watchlist
              </Button>
            </div>
          </form>
        )}

        {loading ? (
          <div className="flex items-center justify-center h-24">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : items.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center">
            <div className="w-14 h-14 rounded-2xl bg-primary/5 border border-primary/10 flex items-center justify-center mb-4">
              <BookmarkCheck className="w-6 h-6 text-primary/30" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No watchlist items yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1 max-w-xs">
              Add domains, emails, keywords, social handles, or mobile apps to monitor for brand impersonation, typosquatting, phishing, and fake accounts.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map((item: any) => (
              <WatchlistItem
                key={item.id}
                item={item}
                onDelete={handleDelete}
                onScheduleChange={handleScheduleChange}
                onEdit={handleEditItem}
                deleting={deletingId === item.id}
                latestScan={latestScanForItem(item)}
                onViewScan={id => navigate(`/brand-threats/${id}`)}
                onRunScan={handleRunScan}
                onView={handleViewItem}
                runningScan={runningScanItemId === item.id}
                allAssets={watchlistAssets as any[]}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const SCHEDULE_FREQ_LABELS: Record<string, string> = {
  daily:   "Daily",
  weekly:  "Weekly",
  monthly: "Monthly",
};

function SchedulesSection() {
  const { toast } = useToast();
  const [schedules, setSchedules] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [editId, setEditId] = useState<number | null>(null);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [form, setForm] = useState({
    name: "",
    domain: "",
    frequency: "weekly",
    runTime: "03:00",
    dayOfWeek: 1,
    dayOfMonth: 1,
  });

  const { data: assetsData } = useListAssets({}, { query: { queryKey: ["assets", "brand-schedule-assets"], staleTime: 60_000 } });
  const verifiedDomainAssets = (assetsData ?? []).filter(
    (a: any) => a.verificationStatus === "verified" && (a.type === "domain" || a.type === "subdomain"),
  );

  async function load() {
    setLoading(true);
    try {
      const res = await fetch("/api/brand-threat-schedules", {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (res.ok) setSchedules(await res.json());
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  function resetForm() {
    setForm({ name: "", domain: "", frequency: "weekly", runTime: "03:00", dayOfWeek: 1, dayOfMonth: 1 });
    setEditId(null);
    setShowForm(false);
  }

  function startEdit(s: any) {
    setForm({
      name: s.name ?? "",
      domain: s.domain ?? "",
      frequency: s.frequency ?? "weekly",
      runTime: s.runTime ?? "03:00",
      dayOfWeek: s.dayOfWeek ?? 1,
      dayOfMonth: s.dayOfMonth ?? 1,
    });
    setEditId(s.id);
    setShowForm(true);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name.trim() || !form.domain.trim()) return;
    setSubmitting(true);
    try {
      const url = editId ? `/api/brand-threat-schedules/${editId}` : "/api/brand-threat-schedules";
      const method = editId ? "PATCH" : "POST";
      const res = await fetch(url, {
        method,
        headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      if (!res.ok) throw new Error("Failed");
      toast({ title: editId ? "Schedule updated" : "Schedule created" });
      resetForm();
      load();
    } catch {
      toast({ title: "Failed to save schedule", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(id: number) {
    if (!confirm("Delete this schedule?")) return;
    setDeletingId(id);
    try {
      const res = await fetch(`/api/brand-threat-schedules/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      if (!res.ok) throw new Error("Failed");
      setSchedules(prev => prev.filter(s => s.id !== id));
      toast({ title: "Schedule deleted" });
    } catch {
      toast({ title: "Failed to delete schedule", variant: "destructive" });
    } finally {
      setDeletingId(null);
    }
  }

  async function handleToggle(s: any) {
    try {
      const res = await fetch(`/api/brand-threat-schedules/${s.id}`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" },
        body: JSON.stringify({ status: s.status === "active" ? "paused" : "active" }),
      });
      if (!res.ok) throw new Error("Failed");
      const updated = await res.json();
      setSchedules(prev => prev.map(x => x.id === s.id ? updated : x));
    } catch {
      toast({ title: "Failed to update schedule", variant: "destructive" });
    }
  }

  const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  return (
    <div className="flex-1 overflow-y-auto px-6 py-5">
      <div className="w-full">
        <div className="flex items-center justify-between mb-5">
          <div>
            <h2 className="text-sm font-semibold">Brand Threat Schedules</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              Automated brand threat scans that run on a fixed schedule, independent of the watchlist.
            </p>
          </div>
          <Button size="sm" onClick={() => { resetForm(); setShowForm(v => !v); }} className="h-8 gap-1.5">
            <Plus className="w-3.5 h-3.5" /> New Schedule
          </Button>
        </div>

        {showForm && (
          <form onSubmit={handleSubmit} className="bg-muted/20 border border-border rounded-xl p-4 space-y-3 mb-5">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
              {editId ? "Edit Schedule" : "New Schedule"}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Schedule Name *</label>
                <input
                  value={form.name}
                  onChange={e => setForm(v => ({ ...v, name: e.target.value }))}
                  placeholder="e.g. Weekly ACME Brand Check"
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                />
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Domain *</label>
                {verifiedDomainAssets.length > 0 ? (
                  <select
                    value={form.domain}
                    onChange={e => setForm(v => ({ ...v, domain: e.target.value }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  >
                    <option value="">Select a verified domain…</option>
                    {verifiedDomainAssets.map((a: any) => {
                      const domain = (a.value ?? "").toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
                      return (
                        <option key={a.id} value={domain}>
                          {a.name} — {domain}
                        </option>
                      );
                    })}
                  </select>
                ) : (
                  <input
                    value={form.domain}
                    onChange={e => setForm(v => ({ ...v, domain: e.target.value }))}
                    placeholder="e.g. acme.com"
                    className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                  />
                )}
                <p className="text-[10px] text-muted-foreground mt-1">Only verified assets are eligible for brand threat monitoring.</p>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Frequency</label>
                <select
                  value={form.frequency}
                  onChange={e => setForm(v => ({ ...v, frequency: e.target.value }))}
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                >
                  {Object.entries(SCHEDULE_FREQ_LABELS).map(([val, label]) => (
                    <option key={val} value={val}>{label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-muted-foreground block mb-1">Scan Time (UTC)</label>
                <input
                  type="time"
                  value={form.runTime}
                  onChange={e => setForm(v => ({ ...v, runTime: e.target.value }))}
                  className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                />
              </div>
              {form.frequency === "weekly" && (
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Day of Week</label>
                  <select
                    value={form.dayOfWeek}
                    onChange={e => setForm(v => ({ ...v, dayOfWeek: parseInt(e.target.value) }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                  >
                    {dayNames.map((d, i) => <option key={i} value={i}>{d}</option>)}
                  </select>
                </div>
              )}
              {form.frequency === "monthly" && (
                <div>
                  <label className="text-xs text-muted-foreground block mb-1">Day of Month</label>
                  <select
                    value={form.dayOfMonth}
                    onChange={e => setForm(v => ({ ...v, dayOfMonth: parseInt(e.target.value) }))}
                    className="w-full bg-background border border-border rounded-lg px-3 py-1.5 text-sm focus:outline-none"
                  >
                    {Array.from({ length: 28 }, (_, i) => i + 1).map(d => (
                      <option key={d} value={d}>{d}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
            <div className="flex gap-2 justify-end">
              <Button type="button" variant="outline" size="sm" onClick={resetForm}>Cancel</Button>
              <Button type="submit" size="sm" disabled={submitting || !form.name.trim() || !form.domain.trim()}>
                {submitting ? <Loader2 className="w-3.5 h-3.5 animate-spin mr-1" /> : null}
                {editId ? "Save Changes" : "Create Schedule"}
              </Button>
            </div>
          </form>
        )}

        {loading ? (
          <div className="flex items-center justify-center h-24">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : schedules.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-center">
            <div className="w-14 h-14 rounded-2xl bg-primary/5 border border-primary/10 flex items-center justify-center mb-4">
              <CalendarClock className="w-6 h-6 text-primary/30" />
            </div>
            <p className="text-sm font-medium text-muted-foreground">No schedules yet</p>
            <p className="text-xs text-muted-foreground/60 mt-1 max-w-xs">
              Create a schedule to run brand threat scans automatically on a daily, weekly, or monthly basis.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {schedules.map((s: any) => (
              <div
                key={s.id}
                className={cn(
                  "rounded-xl border p-4 transition-colors",
                  s.status === "active" ? "bg-card border-border" : "bg-muted/10 border-border/50 opacity-60"
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-medium truncate">{s.name}</span>
                      <span className={cn(
                        "text-[10px] px-2 py-0.5 rounded-full font-medium shrink-0",
                        s.status === "active" ? "text-green-400 bg-green-500/10" : "text-muted-foreground bg-muted"
                      )}>
                        {s.status === "active" ? "Active" : "Paused"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Domain: <span className="text-foreground font-mono">{s.domain}</span>
                    </p>
                    <div className="flex items-center gap-3 mt-1.5 text-[11px] text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <CalendarClock className="w-3 h-3" />
                        {SCHEDULE_FREQ_LABELS[s.frequency] ?? s.frequency}
                        {s.frequency === "weekly" && s.dayOfWeek != null && ` · ${dayNames[s.dayOfWeek]}`}
                        {s.frequency === "monthly" && s.dayOfMonth != null && ` · day ${s.dayOfMonth}`}
                        {s.runTime && ` @ ${s.runTime} UTC`}
                      </span>
                      {s.nextRunAt && (
                        <span className="flex items-center gap-1 text-blue-400/70">
                          <Clock className="w-3 h-3" />
                          Next: {new Date(s.nextRunAt).toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => handleToggle(s)}
                      className="p-1.5 rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                      title={s.status === "active" ? "Pause schedule" : "Enable schedule"}
                    >
                      {s.status === "active" ? <XCircle className="w-3.5 h-3.5" /> : <Check className="w-3.5 h-3.5" />}
                    </button>
                    <button
                      onClick={() => startEdit(s)}
                      className="p-1.5 rounded-md hover:bg-muted transition-colors text-muted-foreground hover:text-foreground"
                      title="Edit schedule"
                    >
                      <Edit2 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDelete(s.id)}
                      disabled={deletingId === s.id}
                      className="p-1.5 rounded-md hover:bg-red-500/10 transition-colors text-muted-foreground hover:text-red-400"
                      title="Delete schedule"
                    >
                      {deletingId === s.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function BrandThreatPage() {
  const [, navigate] = useLocation();
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showModal, setShowModal] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);
  const [retryingId, setRetryingId] = useState<number | null>(null);
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<"scans" | "watchlist" | "schedules">("scans");

  const { data: scans, isLoading, refetch } = useListBrandThreats({
    query: { queryKey: getListBrandThreatsQueryKey(), staleTime: 0, refetchInterval: (query: any) => {
      const list = (query?.state?.data as any[]) ?? [];
      return list.some((s: any) => s.status === "running" || s.status === "pending") ? 4000 : 30_000;
    }},
  });
  const { mutateAsync: deleteScan } = useDeleteBrandThreatScan();

  async function handleDelete(id: number) {
    if (!confirm("Delete this brand threat scan and all its results?")) return;
    setDeletingId(id);
    try {
      await deleteScan({ id });
      queryClient.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
      toast({ title: "Scan deleted" });
    } catch {
      toast({ title: "Failed to delete scan", variant: "destructive" });
    } finally {
      setDeletingId(null);
    }
  }

  async function handleRetry(id: number) {
    setRetryingId(id);
    try {
      const res = await fetch(`/api/brand-threats/${id}/rescan`, {
        method: "POST",
        headers: { Authorization: `Bearer ${getToken() ?? ""}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        toast({ title: body?.error ?? "Failed to start retry scan", variant: "destructive" });
        return;
      }
      const newScan = await res.json();
      queryClient.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
      toast({ title: "Scan restarted", description: `A fresh scan has been queued for ${newScan.domain ?? "this domain"}.` });
      if (newScan.id && newScan.id !== id) {
        navigate(`/brand-threats/${newScan.id}`);
      }
    } catch {
      toast({ title: "Failed to retry scan", variant: "destructive" });
    } finally {
      setRetryingId(null);
    }
  }

  const scanList = (scans as any[]) ?? [];
  const filtered = search.trim()
    ? scanList.filter((s: any) => s.domain.includes(search.trim().toLowerCase()))
    : scanList;

  const totalLive     = scanList.reduce((n: number, s: any) => n + (s.liveCount ?? 0), 0);
  const totalPhishing = scanList.reduce((n: number, s: any) => n + (s.phishingCount ?? 0), 0);
  const totalLeaks    = scanList.reduce((n: number, s: any) => n + (s.dataLeakCount ?? 0), 0);
  const activeScans   = scanList.filter((s: any) => s.status === "running" || s.status === "pending").length;

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* ── Top hero bar ──────────────────────────────────────────────── */}
      <div className="bg-gradient-to-r from-card via-card to-background border-b border-border px-6 py-5">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">Brand Threat Intelligence</h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                Typosquatting · Phishing detection · Data leaks · Brand abuse · CT monitoring
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Tab switcher */}
            <div className="flex items-center gap-1 bg-muted/30 rounded-lg p-1 mr-1">
              <button
                onClick={() => setActiveTab("scans")}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === "scans" ? "bg-card shadow-sm text-foreground border border-border" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <ShieldAlert className="w-3.5 h-3.5" /> Scans
              </button>
              <button
                onClick={() => setActiveTab("watchlist")}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === "watchlist" ? "bg-card shadow-sm text-foreground border border-border" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <BookmarkCheck className="w-3.5 h-3.5" /> Watchlist
              </button>
              <button
                onClick={() => setActiveTab("schedules")}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all",
                  activeTab === "schedules" ? "bg-card shadow-sm text-foreground border border-border" : "text-muted-foreground hover:text-foreground",
                )}
              >
                <CalendarClock className="w-3.5 h-3.5" /> Schedules
              </button>
            </div>
            <Button variant="outline" size="sm" onClick={() => refetch()} className="h-8">
              <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
              Refresh
            </Button>
            {activeTab === "scans" && (
              <Button size="sm" onClick={() => setShowModal(true)} className="h-8">
                <Plus className="w-3.5 h-3.5 mr-1.5" />
                New Scan
              </Button>
            )}
          </div>
        </div>

        {/* Stat strip */}
        {scanList.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5">
            <div className="flex items-center gap-3 bg-background/60 border border-border rounded-xl px-4 py-3">
              <Globe className="w-4 h-4 text-muted-foreground shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Domains Scanned</p>
                <p className="text-xl font-bold leading-tight">{new Set(scanList.map((s: any) => s.domain)).size}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-red-500/20 rounded-xl px-4 py-3">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Live Threats</p>
                <p className={cn("text-xl font-bold leading-tight", totalLive > 0 ? "text-red-400" : "")}>{totalLive}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-orange-500/20 rounded-xl px-4 py-3">
              <Fish className="w-4 h-4 text-orange-400 shrink-0" />
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Phishing Detected</p>
                <p className={cn("text-xl font-bold leading-tight", totalPhishing > 0 ? "text-orange-400" : "")}>{totalPhishing}</p>
              </div>
            </div>
            <div className="flex items-center gap-3 bg-background/60 border border-border rounded-xl px-4 py-3">
              {activeScans > 0
                ? <Activity className="w-4 h-4 text-blue-400 shrink-0" />
                : <Database className="w-4 h-4 text-muted-foreground shrink-0" />}
              <div>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">
                  {activeScans > 0 ? "Active Scans" : "Data Leaks"}
                </p>
                <p className={cn("text-xl font-bold leading-tight", activeScans > 0 ? "text-blue-400" : totalLeaks > 0 ? "text-yellow-400" : "")}>
                  {activeScans > 0 ? activeScans : totalLeaks}
                </p>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Watchlist tab content ──────────────────────────────────────── */}
      {activeTab === "watchlist" && <WatchlistSection />}

      {/* ── Schedules tab content ──────────────────────────────────────── */}
      {activeTab === "schedules" && <SchedulesSection />}

      {/* ── Scans tab content ──────────────────────────────────────────── */}
      {activeTab === "scans" && (
      <div className="flex-1 overflow-y-auto px-6 py-5">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : scanList.length === 0 ? (
          /* ── Empty state ── */
          <div className="flex flex-col items-center justify-center h-96 text-center">
            <div className="relative mb-6">
              <div className="w-20 h-20 rounded-2xl bg-primary/5 border border-primary/10 flex items-center justify-center">
                <ShieldAlert className="w-9 h-9 text-primary/40" />
              </div>
              <div className="absolute -bottom-1 -right-1 w-6 h-6 rounded-full bg-card border border-border flex items-center justify-center">
                <Plus className="w-3.5 h-3.5 text-muted-foreground" />
              </div>
            </div>
            <h2 className="text-base font-semibold mb-1">No brand threat scans yet</h2>
            <p className="text-sm text-muted-foreground max-w-md mb-6">
              Start a scan to detect domains impersonating your brand via typosquatting, homoglyph substitution,
              TLD swaps, and other deception techniques.
            </p>
            <Button onClick={() => setShowModal(true)}>
              <Shield className="w-4 h-4 mr-2" />
              Run First Scan
            </Button>
            <p className="text-xs text-muted-foreground/50 mt-3">
              Scans also auto-trigger when you run an Asset or Domain Scan
            </p>
          </div>
        ) : (
          <>
            {/* Search bar */}
            <div className="flex items-center gap-3 mb-5">
              <div className="relative flex-1 max-w-xs">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Filter by domain…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="w-full bg-background border border-border rounded-lg pl-8 pr-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-primary/40"
                />
              </div>
              <span className="text-xs text-muted-foreground">
                {filtered.length} scan{filtered.length !== 1 ? "s" : ""}
              </span>
            </div>

            {/* Cards grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
              {filtered.map((scan: any) => (
                <ScanCard
                  key={scan.id}
                  scan={scan}
                  onDelete={handleDelete}
                  onView={id => navigate(`/brand-threats/${id}`)}
                  onRetry={handleRetry}
                  deleting={deletingId === scan.id}
                  retrying={retryingId === scan.id}
                />
              ))}
            </div>

            {filtered.length === 0 && (
              <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
                No scans match "{search}"
              </div>
            )}
          </>
        )}
      </div>
      )}

      {showModal && (
        <NewScanModal
          onClose={() => setShowModal(false)}
          onSuccess={() => {
            setShowModal(false);
            queryClient.invalidateQueries({ queryKey: getListBrandThreatsQueryKey() });
          }}
        />
      )}
    </div>
  );
}
