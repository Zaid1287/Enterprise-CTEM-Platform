import { useState } from "react";
import {
  useListUsers, useCreateUser, useUpdateUser, useDeleteUser,
  getListUsersQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { Plus, Trash2, UserCheck, UserX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { cn, formatDateTime, capitalize } from "@/lib/utils";

const ROLE_OPTIONS: Record<string, string[]> = {
  super_admin: ["super_admin", "admin", "account_manager", "client"],
  admin: ["admin", "client"],
  account_manager: ["client"],
  client: [],
};

export default function UsersPage() {
  const { user: me } = useAuth();
  const role = me?.role ?? "client";
  const allowedRoles = ROLE_OPTIONS[role] ?? [];

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({
    email: "", firstName: "", lastName: "",
    role: allowedRoles[allowedRoles.length - 1] ?? "client",
    password: "", tenantId: "",
  });
  const queryClient = useQueryClient();

  const { data: users, isLoading } = useListUsers({
    query: { queryKey: getListUsersQueryKey() },
  });
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();

  const needsTenantId = (role === "super_admin" || role === "account_manager") &&
    (form.role === "admin" || form.role === "client");

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const body: any = {
      email: form.email, firstName: form.firstName,
      lastName: form.lastName, role: form.role, password: form.password,
    };
    if (needsTenantId && form.tenantId) body.tenantId = Number(form.tenantId);
    await createUser.mutateAsync({ data: body } as any);
    queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
    setShowCreate(false);
    setForm({ email: "", firstName: "", lastName: "", role: allowedRoles[allowedRoles.length - 1] ?? "client", password: "", tenantId: "" });
  };

  const handleToggleActive = async (user: any) => {
    await updateUser.mutateAsync({ userId: user.id, data: { isActive: !user.isActive } });
    queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
  };

  const handleDelete = async (id: number) => {
    if (!confirm("Delete this user? This cannot be undone.")) return;
    await deleteUser.mutateAsync({ userId: id });
    queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
  };

  const userList = Array.isArray(users) ? users as any[] : [];
  const showTenantCol = role === "super_admin" || role === "account_manager";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">User Management</h1>
          <p className="text-sm text-muted-foreground">
            {userList.length} {role === "super_admin" ? "users across all tenants" : role === "account_manager" ? "users across your assigned clients" : "users in your organization"}
          </p>
        </div>
        {allowedRoles.length > 0 && (
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> Invite User
          </Button>
        )}
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Email</th>
              {showTenantCol && <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tenant</th>}
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Role</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Login</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(3)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(showTenantCol ? 7 : 6)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && userList.map((u: any) => (
              <tr key={u.id} className="border-b border-border/50 hover:bg-accent/30">
                <td className="px-4 py-2.5 font-medium">{u.firstName} {u.lastName}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{u.email}</td>
                {showTenantCol && (
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{u.tenantName ?? `#${u.tenantId}`}</td>
                )}
                <td className="px-4 py-2.5">
                  <Badge variant="outline" className={cn("text-xs capitalize",
                    u.role === "super_admin" ? "border-purple-500/40 text-purple-400" :
                    u.role === "account_manager" ? "border-blue-500/40 text-blue-400" :
                    u.role === "admin" ? "border-green-500/40 text-green-400" : "")}>
                    {u.role.replace(/_/g, " ")}
                  </Badge>
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                    u.isActive ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border")}>
                    {u.isActive ? "Active" : "Inactive"}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{formatDateTime(u.lastLoginAt)}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleToggleActive(u)}
                      title={u.isActive ? "Deactivate" : "Activate"}>
                      {u.isActive ? <UserX className="w-3.5 h-3.5 text-muted-foreground" /> : <UserCheck className="w-3.5 h-3.5 text-green-400" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                      onClick={() => handleDelete(u.id)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Invite User</DialogTitle></DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">First Name</Label>
                <Input value={form.firstName} onChange={e => setForm(p => ({ ...p, firstName: e.target.value }))} required className="h-9" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Last Name</Label>
                <Input value={form.lastName} onChange={e => setForm(p => ({ ...p, lastName: e.target.value }))} required className="h-9" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Email</Label>
              <Input type="email" value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Role</Label>
              <Select value={form.role} onValueChange={v => setForm(p => ({ ...p, role: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {allowedRoles.map(r => (
                    <SelectItem key={r} value={r}>
                      <span className="capitalize">{r.replace(/_/g, " ")}</span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {needsTenantId && (
              <div className="space-y-1.5">
                <Label className="text-xs">Tenant ID <span className="text-muted-foreground">(for admin/client users)</span></Label>
                <Input type="number" value={form.tenantId} onChange={e => setForm(p => ({ ...p, tenantId: e.target.value }))} min="1" className="h-9" placeholder="Leave blank for platform tenant" />
              </div>
            )}
            <div className="space-y-1.5">
              <Label className="text-xs">Temporary Password</Label>
              <Input type="password" value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))} required minLength={8} className="h-9" />
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createUser.isPending}>{createUser.isPending ? "Creating..." : "Create User"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
