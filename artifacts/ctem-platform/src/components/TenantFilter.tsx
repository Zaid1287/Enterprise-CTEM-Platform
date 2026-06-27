import { useListTenants } from "@workspace/api-client-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useAuth } from "@/hooks/useAuth";

interface TenantFilterProps {
  value: number | null;
  onChange: (tenantId: number | null) => void;
}

export function TenantFilter({ value, onChange }: TenantFilterProps) {
  const { user } = useAuth();
  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";
  const { data: tenants } = useListTenants({ query: { enabled: isPrivileged } } as any);

  if (!isPrivileged) return null;

  const tenantList = ((tenants as any[]) ?? []).filter(
    (t: any) => !t.isPlatform && t.id !== user?.tenantId
  );

  return (
    <Select
      value={value ? String(value) : "_all_"}
      onValueChange={(v) => onChange(v === "_all_" ? null : parseInt(v, 10))}
    >
      <SelectTrigger className="h-8 text-xs w-44">
        <SelectValue placeholder="All Clients" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="_all_">All Clients</SelectItem>
        {tenantList.map((t: any) => (
          <SelectItem key={t.id} value={String(t.id)}>
            {t.name ?? `Tenant #${t.id}`}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
