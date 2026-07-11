import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { RefreshCw, Building2, Shield, Loader2 } from "lucide-react";

interface TenantRow {
  tenantId: number;
  tenantName: string;
  plan: string;
  isEnabled: boolean;
  vendorCount: number;
  avgRiskScore: number;
}

export default function TprmAdminPage() {
  const { user } = useAuth();
  const [data, setData]       = useState<{ tenants: TenantRow[]; stats: any } | null>(null);
  const [loading, setLoading] = useState(true);
  const [toggling, setToggling] = useState<number | null>(null);

  const load = () => {
    setLoading(true);
    apiFetch<any>("/api/tprm/admin/overview")
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const toggle = async (tenantId: number, current: boolean) => {
    setToggling(tenantId);
    try {
      await apiFetch("/api/tprm/module", { method: "PATCH", body: JSON.stringify({ tenantId, isEnabled: !current }) });
      load();
    } catch { /* ignore */ }
    setToggling(null);
  };

  const isSA = user?.role === "super_admin";

  return (
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">TPRM Module Administration</h1>
          <p className="text-muted-foreground text-sm">Enable or disable Third Party Risk Management per tenant</p>
        </div>
        <Button variant="outline" size="sm" onClick={load}><RefreshCw className="w-4 h-4" /></Button>
      </div>

      {/* Stats */}
      {data && (
        <div className="grid grid-cols-3 gap-3">
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">Total Tenants</p><p className="text-xl font-bold mt-0.5">{data.stats.total}</p></CardContent></Card>
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">TPRM Enabled</p><p className="text-xl font-bold mt-0.5 text-green-400">{data.stats.enabled}</p></CardContent></Card>
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">TPRM Disabled</p><p className="text-xl font-bold mt-0.5 text-muted-foreground">{data.stats.disabled}</p></CardContent></Card>
        </div>
      )}

      {/* Own tenant toggle for admins */}
      {user?.role === "admin" && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">Your Organization</CardTitle></CardHeader>
          <CardContent className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium">Enable TPRM Module</p>
              <p className="text-xs text-muted-foreground">Enable Third Party Risk Management for your organization</p>
            </div>
            {loading ? <Skeleton className="h-6 w-12" /> : (
              <div className="flex items-center gap-2">
                {toggling === user.tenantId && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
                <Switch
                  checked={data?.tenants.find(t => t.tenantId === user.tenantId)?.isEnabled ?? false}
                  onCheckedChange={() => toggle(user.tenantId, data?.tenants.find(t => t.tenantId === user.tenantId)?.isEnabled ?? false)}
                  disabled={toggling !== null}
                />
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Super admin tenant table */}
      {isSA && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm">All Tenants</CardTitle></CardHeader>
          <CardContent className="p-0">
            {loading ? (
              <div className="p-4 space-y-2">{Array(5).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Tenant</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Plan</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Vendors</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Avg Risk</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">TPRM</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.tenants ?? []).map(t => (
                    <tr key={t.tenantId} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <Building2 className="w-4 h-4 text-muted-foreground" />
                          <span className="font-medium">{t.tenantName}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5"><Badge variant="outline" className="text-[10px] capitalize">{t.plan}</Badge></td>
                      <td className="px-4 py-2.5 text-muted-foreground">{t.vendorCount}</td>
                      <td className="px-4 py-2.5">
                        {t.vendorCount > 0 ? (
                          <span className={t.avgRiskScore >= 70 ? "text-green-400" : t.avgRiskScore >= 50 ? "text-yellow-400" : "text-red-400"}>{t.avgRiskScore}/100</span>
                        ) : <span className="text-muted-foreground">—</span>}
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          {toggling === t.tenantId && <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />}
                          <Switch
                            checked={t.isEnabled}
                            onCheckedChange={() => toggle(t.tenantId, t.isEnabled)}
                            disabled={toggling !== null}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
