import { useAuth } from "@/hooks/useAuth";
import {
  useGetTenant, useUpdateTenant, getGetTenantQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Building2, Save } from "lucide-react";
import { capitalize, formatDate } from "@/lib/utils";

export default function TenantSettingsPage() {
  const { user } = useAuth();
  const tenantId = user?.tenantId ?? 0;
  const queryClient = useQueryClient();

  const { data: tenant, isLoading } = useGetTenant(tenantId, {
    query: { enabled: !!tenantId, queryKey: getGetTenantQueryKey(tenantId) },
  });
  const updateTenant = useUpdateTenant();
  const [form, setForm] = useState({ name: "", plan: "" });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (tenant) {
      const t = tenant as any;
      setForm({ name: t.name, plan: t.plan });
    }
  }, [tenant]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    await updateTenant.mutateAsync({ tenantId, data: form });
    queryClient.invalidateQueries({ queryKey: getGetTenantQueryKey(tenantId) });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const t = tenant as any;

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center gap-2">
        <Building2 className="w-5 h-5 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">Tenant Settings</h1>
          <p className="text-sm text-muted-foreground">Manage your organization configuration</p>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}
        </div>
      ) : (
        <>
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-medium mb-4">Organization Details</h3>
            <form onSubmit={handleSave} className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs">Organization Name</Label>
                <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} required className="h-9 max-w-sm" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Slug</Label>
                <Input value={t?.slug ?? ""} disabled className="h-9 max-w-sm opacity-50 font-mono text-sm" />
                <p className="text-xs text-muted-foreground">The slug is automatically generated and cannot be changed.</p>
              </div>
              <Button type="submit" size="sm" disabled={updateTenant.isPending}>
                <Save className="w-3.5 h-3.5 mr-1.5" />
                {saved ? "Saved!" : updateTenant.isPending ? "Saving..." : "Save Changes"}
              </Button>
            </form>
          </div>

          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-medium mb-4">Plan & Limits</h3>
            <div className="grid grid-cols-2 gap-4">
              {[
                { label: "Current Plan", value: capitalize(t?.plan ?? "") },
                { label: "Max Assets", value: t?.maxAssets ?? "Unlimited" },
                { label: "Max Users", value: t?.maxUsers ?? "Unlimited" },
                { label: "Member Since", value: formatDate(t?.createdAt) },
              ].map(({ label, value }) => (
                <div key={label} className="bg-accent/30 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="text-sm font-medium mt-0.5">{value}</p>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
