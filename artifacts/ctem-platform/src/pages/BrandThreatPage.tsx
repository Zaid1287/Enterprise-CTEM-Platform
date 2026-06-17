import { useState } from "react";
import { useLocation } from "wouter";
import {
  useListBrandThreats, useCreateBrandThreatScan, useDeleteBrandThreatScan,
  getListBrandThreatsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import {
  ShieldAlert, Plus, Trash2, Loader2, Globe, AlertTriangle,
  CheckCircle2, Clock, XCircle, RefreshCw, Eye,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

const RISK_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

const STATUS_ICON: Record<string, React.ReactNode> = {
  pending: <Clock className="w-3.5 h-3.5 text-muted-foreground" />,
  running: <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />,
  done:    <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />,
  error:   <XCircle className="w-3.5 h-3.5 text-red-400" />,
};

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [domain, setDomain] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const { mutateAsync } = useCreateBrandThreatScan();
  const { toast } = useToast();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setSubmitting(true);
    try {
      await mutateAsync({ data: { domain: domain.trim() } });
      toast({ title: "Brand threat scan started", description: `Scanning permutations of ${domain.trim()}…` });
      onSuccess();
    } catch {
      toast({ title: "Failed to start scan", variant: "destructive" });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-card border border-border rounded-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <ShieldAlert className="w-5 h-5 text-primary" />
          <h2 className="text-base font-semibold">New Brand Threat Scan</h2>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          Enter a domain to scan for lookalike, typosquat, and brand-impersonation permutations. The engine will check DNS/MX records for all generated variants.
        </p>
        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider mb-1.5 block">Target Domain</label>
            <input
              type="text"
              placeholder="example.com"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 font-mono"
              autoFocus
            />
          </div>
          <div className="flex gap-2 pt-1">
            <Button type="button" variant="outline" size="sm" onClick={onClose} className="flex-1">Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting || !domain.trim()} className="flex-1">
              {submitting ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Plus className="w-3.5 h-3.5 mr-1.5" />}
              Start Scan
            </Button>
          </div>
        </form>
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

  const { data: scans, isLoading, refetch } = useListBrandThreats({
    query: { queryKey: getListBrandThreatsQueryKey() },
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

  const scanList = (scans as any[]) ?? [];

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">Brand Threat Monitor</h1>
            <p className="text-xs text-muted-foreground">
              Domain permutation scanning — detect typosquatting, homoglyph, and brand impersonation domains
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
            Refresh
          </Button>
          <Button size="sm" onClick={() => setShowModal(true)}>
            <Plus className="w-3.5 h-3.5 mr-1.5" />
            New Scan
          </Button>
        </div>
      </div>

      {/* Info cards */}
      {scanList.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Total Scans</p>
            <p className="text-2xl font-bold">{scanList.length}</p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Domains Monitored</p>
            <p className="text-2xl font-bold">{new Set(scanList.map((s: any) => s.domain)).size}</p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Live Threats Found</p>
            <p className="text-2xl font-bold text-red-400">
              {scanList.reduce((n: number, s: any) => n + (s.liveCount ?? 0), 0)}
            </p>
          </div>
          <div className="bg-card border border-border rounded-xl p-4">
            <p className="text-xs text-muted-foreground mb-1">Active Scans</p>
            <p className="text-2xl font-bold text-blue-400">
              {scanList.filter((s: any) => s.status === "running" || s.status === "pending").length}
            </p>
          </div>
        </div>
      )}

      {/* Scans table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-medium">Scan History</h2>
          <span className="text-xs text-muted-foreground">{scanList.length} scan{scanList.length !== 1 ? "s" : ""}</span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : scanList.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-center px-4">
            <ShieldAlert className="w-8 h-8 text-muted-foreground/30 mb-3" />
            <p className="text-sm text-muted-foreground mb-1">No brand threat scans yet</p>
            <p className="text-xs text-muted-foreground/60 mb-4">
              Start a scan to detect lookalike domains targeting your brand
            </p>
            <Button size="sm" onClick={() => setShowModal(true)}>
              <Plus className="w-3.5 h-3.5 mr-1.5" />
              New Scan
            </Button>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {scanList.map((scan: any) => (
              <div key={scan.id} className="flex items-center gap-4 p-4 hover:bg-muted/30 transition-colors">
                {/* Status icon */}
                <div className="shrink-0">{STATUS_ICON[scan.status] ?? STATUS_ICON.pending}</div>

                {/* Domain + info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <Globe className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                    <span className="text-sm font-medium font-mono truncate">{scan.domain}</span>
                    {scan.status === "done" && scan.liveCount > 0 && (
                      <span className="text-[10px] bg-red-500/15 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded font-semibold shrink-0">
                        {scan.liveCount} LIVE
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>{formatDate(scan.createdAt)}</span>
                    {scan.status === "done" && (
                      <>
                        <span>·</span>
                        <span>{scan.totalPermutations} permutations</span>
                        <span>·</span>
                        <span>{scan.registeredCount} registered</span>
                      </>
                    )}
                    {scan.status === "running" && (
                      <span className="text-blue-400">Scanning…</span>
                    )}
                    {scan.status === "error" && (
                      <span className="text-red-400 flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> {scan.error ?? "Scan failed"}
                      </span>
                    )}
                  </div>
                </div>

                {/* Phishing risk badge */}
                {scan.status === "done" && scan.phishingRisk && (
                  <span className={cn(
                    "text-xs px-2 py-0.5 rounded-md border font-medium capitalize shrink-0",
                    RISK_COLOR[scan.phishingRisk] ?? RISK_COLOR.low,
                  )}>
                    {scan.phishingRisk} risk
                  </span>
                )}

                {/* Actions */}
                <div className="flex items-center gap-1 shrink-0">
                  {scan.status === "done" && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => navigate(`/brand-threats/${scan.id}`)}
                      className="h-7 text-xs"
                    >
                      <Eye className="w-3.5 h-3.5 mr-1" />
                      View
                    </Button>
                  )}
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleDelete(scan.id)}
                    disabled={deletingId === scan.id}
                    className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400"
                  >
                    {deletingId === scan.id ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Trash2 className="w-3.5 h-3.5" />
                    )}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

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
