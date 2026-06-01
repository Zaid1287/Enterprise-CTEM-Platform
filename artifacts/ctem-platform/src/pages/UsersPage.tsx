import { useState } from "react";
import {
  useListUsers, useCreateUser, useUpdateUser, useDeleteUser,
  getListUsersQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, UserCheck, UserX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, formatDateTime, capitalize } from "@/lib/utils";

const ROLES = ["admin", "account_manager", "client"];

export default function UsersPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ email: "", firstName: "", lastName: "", role: "client", password: "" });
  const queryClient = useQueryClient();

  const { data: users, isLoading } = useListUsers({
    query: { queryKey: getListUsersQueryKey() },
  });
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const deleteUser = useDeleteUser();

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await createUser.mutateAsync(form as any);
    queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
    setShowCreate(false);
    setForm({ email: "", firstName: "", lastName: "", role: "client", password: "" });
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

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">User Management</h1>
          <p className="text-sm text-muted-foreground">{Array.isArray(users) ? users.length : 0} users in this workspace</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> Invite User
        </Button>
      </div>

      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Email</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Role</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Login</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(3)].map((_, i) => (
              <tr key={i} className="border-b border-border/50">
                {[...Array(6)].map((_, j) => <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>)}
              </tr>
            ))}
            {!isLoading && (users as any[] ?? []).map((u: any) => (
              <tr key={u.id} className="border-b border-border/50 hover:bg-accent/30">
                <td className="px-4 py-2.5 font-medium">{u.firstName} {u.lastName}</td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{u.email}</td>
                <td className="px-4 py-2.5">
                  <span className="text-xs bg-accent/50 px-2 py-0.5 rounded capitalize">{u.role.replace("_", " ")}</span>
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border", u.isActive ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border")}>
                    {u.isActive ? "Active" : "Inactive"}
                  </span>
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">{formatDateTime(u.lastLoginAt)}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => handleToggleActive(u)} title={u.isActive ? "Deactivate" : "Activate"}>
                      {u.isActive ? <UserX className="w-3.5 h-3.5 text-muted-foreground" /> : <UserCheck className="w-3.5 h-3.5 text-green-400" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => handleDelete(u.id)}>
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
                  {ROLES.map(r => <SelectItem key={r} value={r}>{capitalize(r)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
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
