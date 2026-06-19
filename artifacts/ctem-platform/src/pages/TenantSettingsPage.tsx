import { useAuth } from "@/hooks/useAuth";
import { useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Building2, Save, Loader2, CheckCircle2 } from "lucide-react";
import { capitalize, formatDate } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PLANS = ["starter", "professional", "enterprise"];

export default function TenantSettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const tenantId = user?.tenantId ?? 0;
  const queryClient = useQueryClient();

  const { data: tenant, isLoading } = useQuery<any>({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const updateMutation = useMutation({
    mutationFn: (body: { name: string; plan: string }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenant", tenantId] });
      toast({ title: "Settings saved successfully" });
    },
    onError: (e: any) => toast({ title: "Failed to save", description: e.message, variant: "destructive" }),
  });

  const [form, setForm] = useState({ name: "", plan: "starter" });

  useEffect(() => {
    if (tenant) {
      setForm({ name: tenant.name ?? "", plan: tenant.plan ?? "starter" });
    }
  }, [tenant]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast({ title: "Organization name is required", variant: "destructive" });
      return;
    }
    updateMutation.mutate(form);
  };

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
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : (
        <>
          {/* Organization Details */}
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-4">Organization Details</h3>
            <form onSubmit={handleSave} className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-xs">Organization Name *</Label>
                <Input
                  value={form.name}
                  onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                  placeholder="Acme Corp"
                  required className="h-9 max-w-sm"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs">Slug (read-only)</Label>
                <Input
                  value={tenant?.slug ?? ""}
                  disabled
                  className="h-9 max-w-sm opacity-50 font-mono text-sm"
                />
                <p className="text-xs text-muted-foreground">Auto-generated. Cannot be changed.</p>
              </div>

              {user?.role === "super_admin" && (
                <div className="space-y-1.5">
                  <Label className="text-xs">Plan</Label>
                  <Select value={form.plan} onValueChange={v => setForm(p => ({ ...p, plan: v }))}>
                    <SelectTrigger className="h-9 max-w-sm"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {PLANS.map(pl => (
                        <SelectItem key={pl} value={pl} className="capitalize">
                          {pl.charAt(0).toUpperCase() + pl.slice(1)}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}

              <Button type="submit" size="sm" disabled={updateMutation.isPending} className="flex items-center gap-1.5">
                {updateMutation.isPending
                  ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  : updateMutation.isSuccess
                  ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                  : <Save className="w-3.5 h-3.5" />}
                {updateMutation.isPending ? "Saving…" : "Save Changes"}
              </Button>
            </form>
          </div>

          {/* Plan & Limits */}
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-4">Plan & Limits</h3>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Current Plan",  value: capitalize(tenant?.plan ?? "—") },
                { label: "Max Assets",    value: tenant?.maxAssets  ?? "Unlimited" },
                { label: "Max Users",     value: tenant?.maxUsers   ?? "Unlimited" },
                { label: "Member Since",  value: tenant?.createdAt ? formatDate(tenant.createdAt) : "—" },
              ].map(({ label, value }) => (
                <div key={label} className="bg-accent/30 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="text-sm font-medium mt-0.5">{String(value)}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Tenant ID info */}
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-3">System Info</h3>
            <div className="space-y-2 text-xs text-muted-foreground font-mono">
              <div className="flex items-center gap-3">
                <span className="text-muted-foreground/50 w-24">Tenant ID</span>
                <span className="text-foreground">{tenant?.id ?? "—"}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-muted-foreground/50 w-24">Status</span>
                <span className={tenant?.isActive ? "text-green-400" : "text-red-400"}>
                  {tenant?.isActive ? "Active" : "Inactive"}
                </span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
