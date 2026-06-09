import { useParams, useLocation } from "wouter";
import {
  useGetAlert, useUpdateAlert,
  getGetAlertQueryKey, getListAlertsQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import {
  ArrowLeft, Bell, BellOff, AlertTriangle, ShieldAlert,
  Link2, Clock, Tag, Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, formatDateTime } from "@/lib/utils";
import { Link } from "wouter";

const TYPE_LABEL: Record<string, string> = {
  new_vulnerability: "New Vulnerability",
  critical_exposure: "Critical Exposure",
  ssl_expiry: "SSL Certificate Expiry",
  new_asset: "New Asset Discovered",
  compliance_failure: "Compliance Failure",
  scan_complete: "Scan Completed",
};

const TYPE_COLOR: Record<string, string> = {
  new_vulnerability: "bg-red-500/10 text-red-400 border-red-500/30",
  critical_exposure: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  ssl_expiry: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  new_asset: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  compliance_failure: "bg-purple-500/10 text-purple-400 border-purple-500/30",
  scan_complete: "bg-green-500/10 text-green-400 border-green-500/30",
};

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
      <div className="space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-32 rounded-xl" />
        <Skeleton className="h-24 rounded-xl" />
      </div>
    );
  }

  if (!a) {
    return (
      <div className="space-y-4">
        <Button variant="ghost" size="sm" onClick={() => navigate("/alerts")}>
          <ArrowLeft className="w-4 h-4 mr-1.5" /> Back to Alerts
        </Button>
        <div className="bg-card border border-border rounded-xl p-10 text-center text-muted-foreground">
          Alert not found.
        </div>
      </div>
    );
  }

  const typeLabel = TYPE_LABEL[a.type] ?? a.type;
  const typeCls = TYPE_COLOR[a.type] ?? "bg-muted text-muted-foreground border-border";

  return (
    <div className="space-y-5 max-w-2xl">
      {/* Back */}
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" className="h-7 px-2" onClick={() => navigate("/alerts")}>
          <ArrowLeft className="w-3.5 h-3.5 mr-1" /> Alerts
        </Button>
        <span className="text-muted-foreground/40 text-xs">/</span>
        <span className="text-xs text-muted-foreground truncate max-w-xs">{a.title}</span>
      </div>

      {/* Hero */}
      <div className="bg-card border border-border rounded-xl p-5 space-y-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              {!a.isRead && (
                <span className="w-2 h-2 rounded-full bg-primary shrink-0" />
              )}
              <span className={cn("text-xs px-2 py-0.5 rounded border font-semibold", severityBgColor(a.severity))}>
                {a.severity?.toUpperCase()}
              </span>
              <span className={cn("text-xs px-2 py-0.5 rounded border font-medium", typeCls)}>
                {typeLabel}
              </span>
              {a.isRead && (
                <span className="text-xs px-2 py-0.5 rounded border bg-muted text-muted-foreground border-border">
                  Read
                </span>
              )}
            </div>
            <h1 className="text-base font-semibold">{a.title}</h1>
          </div>

          {!a.isRead && (
            <Button
              variant="outline" size="sm" className="shrink-0 h-8"
              onClick={async () => {
                await updateAlert.mutateAsync({ alertId, data: { isRead: true } });
                qc.invalidateQueries({ queryKey: getListAlertsQueryKey() });
                qc.invalidateQueries({ queryKey: getGetAlertQueryKey(alertId) });
              }}
            >
              <BellOff className="w-3.5 h-3.5 mr-1.5" /> Mark Read
            </Button>
          )}
        </div>

        {/* Message */}
        <div className="bg-muted/30 border border-border rounded-lg p-4">
          <p className="text-sm text-foreground leading-relaxed">{a.message}</p>
        </div>

        {/* Meta grid */}
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="space-y-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Type</p>
            <div className="flex items-center gap-1.5">
              <Tag className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-foreground">{typeLabel}</span>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Severity</p>
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-muted-foreground" />
              <span className={cn("font-semibold capitalize", a.severity === "critical" ? "text-red-400" : a.severity === "high" ? "text-orange-400" : a.severity === "medium" ? "text-yellow-400" : "text-blue-400")}>
                {a.severity}
              </span>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Received</p>
            <div className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-foreground">{formatDateTime(a.createdAt)}</span>
            </div>
          </div>
          <div className="space-y-1">
            <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Status</p>
            <div className="flex items-center gap-1.5">
              <Bell className="w-3.5 h-3.5 text-muted-foreground" />
              <span className="text-foreground">{a.isRead ? "Read" : "Unread"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Related links */}
      {(a.relatedAssetId || a.relatedFindingId) && (
        <div className="bg-card border border-border rounded-xl p-5 space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <Link2 className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Related Context</h2>
          </div>

          {a.relatedAssetId && (
            <div className="flex items-center justify-between bg-accent/30 rounded-lg px-4 py-3 border border-border">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                <div>
                  <p className="text-xs font-medium">Related Asset</p>
                  <p className="text-[10px] text-muted-foreground">Asset ID #{a.relatedAssetId}</p>
                </div>
              </div>
              <Link href={`/assets/${a.relatedAssetId}`}>
                <Button variant="ghost" size="sm" className="h-7 text-xs text-primary">
                  View Asset →
                </Button>
              </Link>
            </div>
          )}

          {a.relatedFindingId && (
            <div className="flex items-center justify-between bg-accent/30 rounded-lg px-4 py-3 border border-border">
              <div className="flex items-center gap-2">
                <Info className="w-4 h-4 text-muted-foreground" />
                <div>
                  <p className="text-xs font-medium">Related Finding</p>
                  <p className="text-[10px] text-muted-foreground">Finding ID #{a.relatedFindingId}</p>
                </div>
              </div>
              <Link href={`/findings/${a.relatedFindingId}`}>
                <Button variant="ghost" size="sm" className="h-7 text-xs text-primary">
                  View Finding →
                </Button>
              </Link>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
