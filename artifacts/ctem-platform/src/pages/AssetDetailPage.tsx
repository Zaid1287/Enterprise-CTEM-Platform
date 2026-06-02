import { useState } from "react";
import { useParams, useLocation } from "wouter";
import {
  useGetAsset, useListFindings, useGetAssetRiskScore, useCheckAssetVerification,
  getGetAssetQueryKey, getListFindingsQueryKey, getGetAssetRiskScoreQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Link } from "wouter";
import { cn, severityBgColor, statusBadgeClass, riskLevelBg, capitalize, formatDate } from "@/lib/utils";

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const [, navigate] = useLocation();
  const id = parseInt(params.id ?? "0", 10);
  const queryClient = useQueryClient();
  const [verifying, setVerifying] = useState(false);

  const { data: asset, isLoading } = useGetAsset(id, {
    query: { enabled: !!id, queryKey: getGetAssetQueryKey(id) },
  });
  const { data: findings } = useListFindings({ assetId: id } as any, {
    query: { enabled: !!id, queryKey: getListFindingsQueryKey({ assetId: id }) },
  });
  const { data: riskScore } = useGetAssetRiskScore(id, {
    query: { enabled: !!id, queryKey: getGetAssetRiskScoreQueryKey(id) },
  });
  const verifyAsset = useCheckAssetVerification();

  const handleVerify = async () => {
    setVerifying(true);
    try {
      await verifyAsset.mutateAsync({ assetId: id });
      queryClient.invalidateQueries({ queryKey: getGetAssetQueryKey(id) });
    } finally {
      setVerifying(false);
    }
  };

  const a = asset as any;
  const rs = riskScore as any;

  if (isLoading) return <div className="space-y-4">{[...Array(3)].map((_, i) => <Skeleton key={i} className="h-32 rounded-xl" />)}</div>;
  if (!a) return <div className="text-muted-foreground">Asset not found</div>;

  return (
    <div className="space-y-4 max-w-4xl">
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
    </div>
  );
}
