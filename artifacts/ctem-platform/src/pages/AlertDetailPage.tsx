import { useParams, useLocation } from "wouter";
import {
  useGetAlert, useUpdateAlert,
  getGetAlertQueryKey, getListAlertsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import {
  ArrowLeft, Bell, BellOff, AlertTriangle, ShieldAlert,
  Link2, Tag, Info, CheckCircle, DatabaseZap, Crosshair,
  ScanSearch, Activity, Shield, Eye, Calendar, Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { cn, severityBgColor, formatDateTime } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { Link } from "wouter";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const TYPE_LABEL: Record<string, string> = {
  new_vulnerability:  "New Vulnerability",
  critical_exposure:  "Critical Exposure",
  ssl_expiry:         "SSL Certificate Expiry",
  new_asset:          "New Asset Discovered",
  compliance_failure: "Compliance Failure",
  scan_complete:      "Scan Completed",
  phishing_detected:  "Phishing Detected",
  data_leak_found:    "Data Leak Found",
  brand_abuse_found:  "Brand Abuse Found",
  brand_threat:       "Brand Threat",
  new_finding:        "New Finding",
  critical_finding:   "Critical Finding",
  high_finding:       "High Finding",
};

const TYPE_COLOR: Record<string, string> = {
  new_vulnerability:  "bg-red-500/10 text-red-400 border-red-500/30",
  critical_exposure:  "bg-orange-500/10 text-orange-400 border-orange-500/30",
  ssl_expiry:         "bg-amber-500/10 text-amber-400 border-amber-500/30",
  new_asset:          "bg-blue-500/10 text-blue-400 border-blue-500/30",
  compliance_failure: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  scan_complete:      "bg-green-500/10 text-green-400 border-green-500/30",
  phishing_detected:  "bg-red-500/10 text-red-400 border-red-500/30",
  data_leak_found:    "bg-orange-500/10 text-orange-400 border-orange-500/30",
  brand_abuse_found:  "bg-purple-500/10 text-purple-400 border-purple-500/30",
  brand_threat:       "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const SEV_GRADIENT: Record<string, string> = {
  critical: "from-red-500/20 via-red-500/5 to-transparent border-red-500/30",
  high:     "from-orange-500/20 via-orange-500/5 to-transparent border-orange-500/30",
  medium:   "from-yellow-500/20 via-yellow-500/5 to-transparent border-yellow-500/30",
  low:      "from-blue-500/20 via-blue-500/5 to-transparent border-blue-500/30",
};

function TypeIcon({ type, className }: { type: string; className?: string }) {
  const cls = className ?? "w-6 h-6";
  switch (type) {
    case "phishing_detected":  return <ShieldAlert className={cn(cls, "text-red-400")} />;
    case "data_leak_found":    return <DatabaseZap className={cn(cls, "text-orange-400")} />;
    case "brand_abuse_found":  return <Crosshair className={cn(cls, "text-purple-400")} />;
    case "brand_threat":       return <AlertTriangle className={cn(cls, "text-yellow-400")} />;
    case "scan_complete":      return <ScanSearch className={cn(cls, "text-blue-400")} />;
    case "critical_finding":
    case "high_finding":
    case "new_finding":        return <Activity className={cn(cls, "text-muted-foreground")} />;
    case "compliance_failure": return <Shield className={cn(cls, "text-purple-400")} />;
    case "ssl_expiry":         return <Shield className={cn(cls, "text-amber-400")} />;
    default:                   return <Bell className={cn(cls, "text-muted-foreground")} />;
  }
}

export default function AlertDetailPage() {
  const params = useParams<{ id: string }>();
  const alertId = Number(params.id);
  const [, navigate] = useLocation();
  const qc = useQueryClient();

  const { data: alert, isLoading } = useGetAlert(alertId, {
    query: { queryKey: getGetAlertQueryKey(alertId), enabled: !isNaN(alertId) },
  });

  const updateAlert = useUpdateAlert();
  const a = alert as any;
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await apiFetch(`${BASE}/api/alerts/${alertId}`, { method: "DELETE" });
      qc.invalidateQueries({ queryKey: getListAlertsQueryKey() });
      navigate("/alerts");
    } finally {
      setDeleting(false);
      setConfirmDelete(false);
    }
  };

  useEffect(() => {
    if (a && !a.isRead) {
      updateAlert.mutateAsync({ alertId, data: { isRead: true } }).then(() => {
        qc.invalidateQueries({ queryKey: getListAlertsQueryKey() });
        qc.invalidateQueries({ queryKey: getGetAlertQueryKey(alertId) });
      });
    }
  }, [a?.id, a?.isRead]);

  if (isLoading) {
    return (
      <div className="space-y-5">
        <Skeleton className="h-7 w-40" />
        <Skeleton className="h-28 rounded-xl" />
        <div className="grid grid-cols-3 gap-4">
          <Skeleton className="col-span-2 h-36 rounded-xl" />
          <Skeleton className="h-36 rounded-xl" />
        </div>
        <Skeleton className="h-24 rounded-xl" />
      </div>
    );
  }

  if (!a) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" className="h-7 px-2 gap-1.5" onClick={() => navigate("/alerts")}>
          <ArrowLeft className="w-3.5 h-3.5" /> Back to Alerts
        </Button>
        <div className="bg-card border border-border rounded-xl p-16 text-center text-muted-foreground">
          <Bell className="w-8 h-8 mx-auto mb-3 opacity-30" />
          <p className="font-medium">Alert not found</p>
          <p className="text-sm mt-1">This alert may have been deleted.</p>
        </div>
      </div>
    );
  }

  const typeLabel = TYPE_LABEL[a.type] ?? (a.type ?? "").replace(/_/g, " ");
  const typeCls = TYPE_COLOR[a.type] ?? "bg-muted text-muted-foreground border-border";
  const sevGradient = SEV_GRADIENT[a.severity] ?? SEV_GRADIENT.low;

  const markRead = async () => {
    await updateAlert.mutateAsync({ alertId, data: { isRead: true } });
    qc.invalidateQueries({ queryKey: getListAlertsQueryKey() });
    qc.invalidateQueries({ queryKey: getGetAlertQueryKey(alertId) });
  };

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" className="h-7 px-2 gap-1.5" onClick={() => navigate("/alerts")}>
          <ArrowLeft className="w-3.5 h-3.5" /> Alerts
        </Button>
        <span className="text-muted-foreground/40 text-xs">/</span>
        <span className="text-xs text-muted-foreground truncate">{a.title}</span>
      </div>

      {/* Hero banner — full width with severity gradient */}
      <div className={cn("relative bg-gradient-to-r border rounded-xl overflow-hidden", sevGradient)}>
        <div className="p-6 flex items-start justify-between gap-4">
          <div className="flex items-start gap-4 flex-1 min-w-0">
            <div className="w-14 h-14 rounded-xl bg-card/80 border border-border flex items-center justify-center shrink-0 shadow-sm">
              <TypeIcon type={a.type} className="w-7 h-7" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap mb-2.5">
                {!a.isRead && (
                  <span className="inline-flex items-center gap-1.5 text-[10px] font-bold bg-primary/20 text-primary border border-primary/30 px-2.5 py-0.5 rounded-full uppercase tracking-wide">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
                    UNREAD
                  </span>
                )}
                {a.isRead && (
                  <span className="inline-flex items-center gap-1 text-[10px] text-muted-foreground border border-border px-2 py-0.5 rounded-full">
                    <CheckCircle className="w-3 h-3" /> Read
                  </span>
                )}
                <span className={cn("text-[10px] font-bold px-2.5 py-0.5 rounded-md border uppercase tracking-wide", severityBgColor(a.severity))}>
                  {a.severity}
                </span>
                <span className={cn("text-[10px] px-2 py-0.5 rounded border font-medium capitalize", typeCls)}>
                  {typeLabel}
                </span>
              </div>
              <h1 className="text-2xl font-bold text-foreground leading-snug">{a.title}</h1>
              <p className="text-xs text-muted-foreground mt-1">{formatDateTime(a.createdAt)}</p>
            </div>
          </div>
          {!a.isRead && (
            <Button
              variant="outline" size="sm" className="h-9 gap-1.5 bg-card/80 shrink-0"
              onClick={markRead}
              disabled={updateAlert.isPending}
            >
              <BellOff className="w-4 h-4" /> Mark as Read
            </Button>
          )}
        </div>
      </div>

      {/* Two-column body */}
      <div className="grid grid-cols-3 gap-5">
        {/* Message — takes 2/3 width */}
        <div className="col-span-2 space-y-4">
          <div className="bg-card border border-border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-4 h-4 text-primary" />
              <h2 className="text-sm font-semibold">Alert Message</h2>
            </div>
            <p className="text-sm text-foreground leading-relaxed whitespace-pre-wrap">
              {a.message ?? "No additional message."}
            </p>
          </div>

          {/* Related context — in the left column */}
          {(a.relatedAssetId || a.relatedFindingId) && (
            <div className="bg-card border border-border rounded-xl p-6">
              <div className="flex items-center gap-2 mb-4">
                <Link2 className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-semibold">Related Context</h2>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {a.relatedAssetId && (
                  <div className="flex items-center justify-between bg-muted/30 border border-border rounded-xl px-4 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                        <ShieldAlert className="w-4 h-4 text-primary" />
                      </div>
                      <div>
                        <p className="text-xs font-semibold">Related Asset</p>
                        <p className="text-[11px] text-muted-foreground">ID #{a.relatedAssetId}</p>
                      </div>
                    </div>
                    <Link href={`/assets/${a.relatedAssetId}`}>
                      <Button variant="outline" size="sm" className="h-7 text-xs">View →</Button>
                    </Link>
                  </div>
                )}
                {a.relatedFindingId && (
                  <div className="flex items-center justify-between bg-muted/30 border border-border rounded-xl px-4 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-orange-500/10 flex items-center justify-center shrink-0">
                        <Info className="w-4 h-4 text-orange-400" />
                      </div>
                      <div>
                        <p className="text-xs font-semibold">Related Finding</p>
                        <p className="text-[11px] text-muted-foreground">ID #{a.relatedFindingId}</p>
                      </div>
                    </div>
                    <Link href={`/findings/${a.relatedFindingId}`}>
                      <Button variant="outline" size="sm" className="h-7 text-xs">View →</Button>
                    </Link>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Sidebar metadata — 1/3 width */}
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-xl p-5">
            <h2 className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide mb-4">Alert Details</h2>
            <div className="space-y-4">
              <div>
                <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide mb-1">Type</p>
                <div className="flex items-center gap-1.5">
                  <Tag className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  <p className="text-sm text-foreground capitalize">{typeLabel}</p>
                </div>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide mb-1">Severity</p>
                <div className="flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  <p className={cn("text-sm font-semibold capitalize",
                    a.severity === "critical" ? "text-red-400"
                    : a.severity === "high" ? "text-orange-400"
                    : a.severity === "medium" ? "text-yellow-400"
                    : "text-blue-400"
                  )}>{a.severity}</p>
                </div>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide mb-1">Received</p>
                <div className="flex items-start gap-1.5">
                  <Calendar className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
                  <p className="text-sm text-foreground leading-snug">{formatDateTime(a.createdAt)}</p>
                </div>
              </div>
              {a.seenAt && (
                <div>
                  <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide mb-1">Seen At</p>
                  <div className="flex items-start gap-1.5">
                    <Eye className="w-3.5 h-3.5 text-muted-foreground shrink-0 mt-0.5" />
                    <p className="text-sm text-foreground leading-snug">{formatDateTime(a.seenAt)}</p>
                  </div>
                </div>
              )}
              <div>
                <p className="text-[10px] text-muted-foreground font-medium uppercase tracking-wide mb-1">Status</p>
                <div className="flex items-center gap-1.5">
                  <Bell className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                  <p className={cn("text-sm font-medium", a.isRead ? "text-muted-foreground" : "text-primary")}>
                    {a.isRead ? "Read" : "Unread"}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Quick actions */}
          <div className="flex flex-col gap-2">
            {!a.isRead && (
              <Button size="sm" className="w-full h-9 gap-1.5" onClick={markRead} disabled={updateAlert.isPending}>
                <BellOff className="w-4 h-4" /> Mark as Read
              </Button>
            )}
            <Button variant="outline" size="sm" className="w-full h-9 gap-1.5" onClick={() => navigate("/alerts")}>
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Alerts
            </Button>
            <Button
              variant="outline" size="sm"
              className="w-full h-9 gap-1.5 text-destructive hover:text-destructive border-destructive/30 hover:bg-destructive/10"
              onClick={() => setConfirmDelete(true)}
            >
              <Trash2 className="w-4 h-4" /> Delete Alert
            </Button>
          </div>

          <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" /> Delete Alert
                </DialogTitle>
              </DialogHeader>
              <p className="text-sm text-muted-foreground">
                Permanently delete this alert? This cannot be undone.
              </p>
              <DialogFooter className="mt-2">
                <Button variant="outline" onClick={() => setConfirmDelete(false)} disabled={deleting}>Cancel</Button>
                <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
                  {deleting ? "Deleting…" : "Delete"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>
    </div>
  );
}
