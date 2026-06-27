import { useState, useEffect } from "react";
import {
  useListUsers, useCreateUser, useDeleteUser,
  getListUsersQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import {
  Plus, Trash2, Pencil, Shield, UserCheck, UserX, Key,
  Mail, User, Building2, Clock, ShieldCheck, ShieldOff,
  RotateCcw, Eye, EyeOff, CheckCircle2, AlertCircle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { cn, formatDateTime } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const ROLE_OPTIONS: Record<string, string[]> = {
  super_admin: ["super_admin", "admin", "account_manager", "client"],
  admin: ["admin", "client"],
  account_manager: ["client"],
  client: [],
};

const ROLE_META: Record<string, { label: string; color: string; bg: string }> = {
  super_admin:     { label: "Super Admin",     color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/30" },
  admin:           { label: "Admin",           color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/30" },
  account_manager: { label: "Account Manager", color: "text-cyan-400",   bg: "bg-cyan-500/10 border-cyan-500/30" },
  client:          { label: "Client",          color: "text-green-400",  bg: "bg-green-500/10 border-green-500/30" },
};

function RoleBadge({ role }: { role: string }) {
  const m = ROLE_META[role] ?? { label: role, color: "text-muted-foreground", bg: "bg-muted border-border" };
  return (
    <span className={cn("text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border", m.color, m.bg)}>
      {m.label}
    </span>
  );
}

function Avatar({ name, avatarUrl }: { name: string; avatarUrl?: string | null }) {
  if (avatarUrl) return <img src={avatarUrl} className="w-8 h-8 rounded-full object-cover" alt={name} />;
  const initials = name.split(" ").map(p => p[0]).join("").slice(0, 2).toUpperCase();
  const colors = ["bg-purple-500", "bg-blue-500", "bg-green-500", "bg-cyan-500", "bg-orange-500", "bg-pink-500"];
  const idx = name.charCodeAt(0) % colors.length;
  return (
    <div className={cn("w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white", colors[idx])}>
      {initials}
    </div>
  );
}

interface EditState {
  firstName: string;
  lastName: string;
  email: string;
  role: string;
  isActive: boolean;
  newPassword: string;
  tenantId: string;
  twoFactorEnabled: boolean;
}

export default function UsersPage() {
  const { user: me } = useAuth();
  const role = me?.role ?? "client";
  const allowedRoles = ROLE_OPTIONS[role] ?? [];
  const isSuperAdmin = role === "super_admin";
  const { toast } = useToast();

  const [showCreate, setShowCreate] = useState(false);
  const [editUser, setEditUser] = useState<any | null>(null);
  const [editState, setEditState] = useState<EditState>({
    firstName: "", lastName: "", email: "", role: "client",
    isActive: true, newPassword: "", tenantId: "", twoFactorEnabled: false,
  });
  const [showPassword, setShowPassword] = useState(false);
  const [saving, setSaving] = useState(false);

  const [form, setForm] = useState({
    email: "", firstName: "", lastName: "",
    role: allowedRoles[allowedRoles.length - 1] ?? "client",
    password: "", tenantId: "",
  });
  const queryClient = useQueryClient();

  const [invitations, setInvitations] = useState<any[]>([]);
  const [showInvite, setShowInvite] = useState(false);
  const [inviteSending, setInviteSending] = useState(false);
  const [inviteForm, setInviteForm] = useState({ name: "", email: "", role: "vendor" });
  const [inviteAssetIds, setInviteAssetIds] = useState<number[]>([]);
  const [availableAssets, setAvailableAssets] = useState<{ id: number; name: string }[]>([]);

  const EXTERNAL_ROLES = ["vendor", "employee", "third_party"];
  const isExternalInviteRole = EXTERNAL_ROLES.includes(inviteForm.role);

  const { data: users, isLoading } = useListUsers({
    query: { queryKey: getListUsersQueryKey() },
  });
  const createUser = useCreateUser();
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
    toast({ title: "User created successfully" });
  };

  const openEdit = (u: any) => {
    setEditUser(u);
    setEditState({
      firstName: u.firstName, lastName: u.lastName, email: u.email,
      role: u.role, isActive: u.isActive, newPassword: "",
      tenantId: String(u.tenantId ?? ""), twoFactorEnabled: u.twoFactorEnabled ?? false,
    });
    setShowPassword(false);
  };

  const handleSave = async () => {
    if (!editUser) return;
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        firstName: editState.firstName,
        lastName: editState.lastName,
        role: editState.role,
        isActive: editState.isActive,
      };
      if (isSuperAdmin) {
        body.email = editState.email;
        body.tenantId = editState.tenantId;
        if (!editState.twoFactorEnabled && editUser.twoFactorEnabled) {
          body.twoFactorEnabled = false;
        }
        if (editState.newPassword.length >= 8) {
          body.newPassword = editState.newPassword;
        }
      }
      await apiFetch(`${BASE}/api/users/${editUser.id}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      });
      queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
      setEditUser(null);
      toast({ title: "User updated", description: `${editState.firstName} ${editState.lastName} updated successfully.` });
    } catch (e: any) {
      toast({ title: "Update failed", description: e.message, variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number, name: string) => {
    if (!confirm(`Delete ${name}? This cannot be undone.`)) return;
    await deleteUser.mutateAsync({ userId: id });
    queryClient.invalidateQueries({ queryKey: getListUsersQueryKey() });
    toast({ title: "User deleted" });
  };

  const fetchInvitations = async () => {
    try {
      const data = await apiFetch(`${BASE}/api/invitations`);
      setInvitations(Array.isArray(data) ? data : []);
    } catch { setInvitations([]); }
  };

  useEffect(() => { fetchInvitations(); }, []);

  // Fetch assets for the invite asset picker
  useEffect(() => {
    if (!showInvite) return;
    apiFetch(`${BASE}/api/assets`)
      .then((data: any) => setAvailableAssets(Array.isArray(data) ? data.map((a: any) => ({ id: a.id, name: a.name })) : []))
      .catch(() => setAvailableAssets([]));
  }, [showInvite]);

  const handleSendInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (EXTERNAL_ROLES.includes(inviteForm.role) && inviteAssetIds.length === 0) {
      toast({ title: "Assets required", description: "Select at least one asset for external member roles.", variant: "destructive" });
      return;
    }
    setInviteSending(true);
    try {
      await apiFetch(`${BASE}/api/invitations`, {
        method: "POST",
        body: JSON.stringify({ ...inviteForm, assetIds: inviteAssetIds }),
      });
      await fetchInvitations();
      setShowInvite(false);
      setInviteForm({ name: "", email: "", role: "vendor" });
      setInviteAssetIds([]);
      toast({ title: "Invitation sent", description: `${inviteForm.email} has been invited.` });
    } catch (err: any) {
      toast({ title: "Failed to send invitation", description: err?.error ?? err?.message ?? "Unknown error", variant: "destructive" });
    } finally {
      setInviteSending(false);
    }
  };

  const handleCancelInvite = async (id: number) => {
    if (!confirm("Cancel this invitation?")) return;
    try {
      await apiFetch(`${BASE}/api/invitations/${id}`, { method: "DELETE" });
      await fetchInvitations();
      toast({ title: "Invitation cancelled" });
    } catch {
      toast({ title: "Failed to cancel invitation", variant: "destructive" });
    }
  };

  const userList = Array.isArray(users) ? users as any[] : [];
  const showTenantCol = role === "super_admin" || role === "account_manager";

  const stats = {
    total: userList.length,
    active: userList.filter((u: any) => u.isActive).length,
    superAdmins: userList.filter((u: any) => u.role === "super_admin").length,
    twoFaEnabled: userList.filter((u: any) => u.twoFactorEnabled).length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold">User Management</h1>
          <p className="text-sm text-muted-foreground">
            {isSuperAdmin ? "All users across every tenant" :
              role === "account_manager" ? "Users in your assigned client tenants" :
              "Users in your organization"}
          </p>
        </div>
        {allowedRoles.length > 0 && (
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-3.5 h-3.5 mr-1.5" /> Add User
          </Button>
        )}
      </div>

      {/* Stats row */}
      {!isLoading && userList.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Total Users", value: stats.total, icon: User, color: "text-blue-400 bg-blue-500/10" },
            { label: "Active", value: stats.active, icon: UserCheck, color: "text-green-400 bg-green-500/10" },
            { label: "Super Admins", value: stats.superAdmins, icon: Shield, color: "text-purple-400 bg-purple-500/10" },
            { label: "2FA Enabled", value: stats.twoFaEnabled, icon: ShieldCheck, color: "text-cyan-400 bg-cyan-500/10" },
          ].map(s => (
            <div key={s.label} className="bg-card border border-border rounded-xl p-3.5 flex items-center gap-3">
              <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center", s.color)}>
                <s.icon className="w-4 h-4" />
              </div>
              <div>
                <p className="text-xl font-bold leading-none">{s.value}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{s.label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Table */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">User</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Email</th>
              {showTenantCol && <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tenant</th>}
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Role</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">2FA</th>
              <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Last Login</th>
              <th className="px-4 py-2.5" />
            </tr>
          </thead>
          <tbody>
            {isLoading && [...Array(4)].map((_, i) => (
              <tr key={i} className="border-b border-border/40">
                {[...Array(showTenantCol ? 8 : 7)].map((_, j) => (
                  <td key={j} className="px-4 py-3"><Skeleton className="h-4" /></td>
                ))}
              </tr>
            ))}
            {!isLoading && userList.map((u: any) => (
              <tr key={u.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors group">
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-2.5">
                    <Avatar name={`${u.firstName} ${u.lastName}`} avatarUrl={u.avatarUrl} />
                    <div>
                      <p className="font-medium text-sm leading-none">{u.firstName} {u.lastName}</p>
                      <p className="text-[10px] text-muted-foreground mt-0.5">ID #{u.id}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <span className="text-xs text-muted-foreground font-mono">{u.email}</span>
                </td>
                {showTenantCol && (
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Building2 className="w-3 h-3 shrink-0" />
                      {u.tenantName ?? `#${u.tenantId}`}
                    </div>
                  </td>
                )}
                <td className="px-4 py-2.5">
                  <RoleBadge role={u.role} />
                </td>
                <td className="px-4 py-2.5">
                  <span className={cn(
                    "text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border",
                    u.isActive
                      ? "text-green-400 bg-green-500/10 border-green-500/30"
                      : "text-muted-foreground bg-muted border-border",
                  )}>
                    {u.isActive ? "Active" : "Inactive"}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  {u.twoFactorEnabled
                    ? <ShieldCheck className="w-4 h-4 text-green-400" />
                    : <ShieldOff className="w-4 h-4 text-muted-foreground/40" />}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Clock className="w-3 h-3 shrink-0" />
                    {u.lastLoginAt ? formatDateTime(u.lastLoginAt) : "Never"}
                  </div>
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      variant="ghost" size="icon" className="h-7 w-7"
                      onClick={() => openEdit(u)}
                      title="Edit user"
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </Button>
                    {u.id !== me?.id && (
                      <Button
                        variant="ghost" size="icon"
                        className="h-7 w-7 text-destructive hover:text-destructive"
                        onClick={() => handleDelete(u.id, `${u.firstName} ${u.lastName}`)}
                        title="Delete user"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </Button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {!isLoading && userList.length === 0 && (
              <tr>
                <td colSpan={showTenantCol ? 8 : 7} className="px-4 py-12 text-center text-muted-foreground text-sm">
                  No users found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* ── Invitations Panel ── */}
      {(role === "admin" || role === "super_admin" || role === "account_manager") && (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="flex items-center gap-2">
              <Mail className="w-4 h-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold">Invitations</h2>
              {invitations.length > 0 && (
                <span className="text-[10px] font-semibold bg-primary/10 text-primary px-1.5 py-0.5 rounded-full">
                  {invitations.length}
                </span>
              )}
            </div>
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => setShowInvite(true)}>
              <Plus className="w-3.5 h-3.5 mr-1" /> Send Invitation
            </Button>
          </div>
          {invitations.length === 0 ? (
            <div className="px-4 py-8 text-center text-muted-foreground text-sm">No invitations sent yet</div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Name</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Email</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Role</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Expires</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {invitations.map((inv: any) => (
                  <tr key={inv.id} className="border-b border-border/40 hover:bg-accent/10 transition-colors">
                    <td className="px-4 py-2.5 font-medium">{inv.name}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{inv.email}</td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border text-cyan-400 bg-cyan-500/10 border-cyan-500/30">
                        {inv.role?.replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={cn(
                        "text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full border",
                        inv.status === "pending"  ? "text-amber-400 bg-amber-500/10 border-amber-500/30" :
                        inv.status === "accepted" ? "text-green-400 bg-green-500/10 border-green-500/30" :
                        "text-muted-foreground bg-muted border-border"
                      )}>
                        {inv.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      {inv.expiresAt ? new Date(inv.expiresAt).toLocaleDateString() : "—"}
                    </td>
                    <td className="px-4 py-2.5">
                      {inv.status === "pending" && (
                        <Button
                          variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => handleCancelInvite(inv.id)}
                          title="Cancel invitation"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Send Invitation Dialog ── */}
      <Dialog open={showInvite} onOpenChange={setShowInvite}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Mail className="w-4 h-4" /> Send Invitation
            </DialogTitle>
            <DialogDescription>Invite an external contact — they'll receive a welcome email.</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSendInvite} className="space-y-3 mt-1">
            <div className="space-y-1.5">
              <Label className="text-xs">Full Name</Label>
              <Input
                value={inviteForm.name}
                onChange={e => setInviteForm(p => ({ ...p, name: e.target.value }))}
                required placeholder="Jane Smith" className="h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Email Address</Label>
              <Input
                type="email"
                value={inviteForm.email}
                onChange={e => setInviteForm(p => ({ ...p, email: e.target.value }))}
                required placeholder="jane@vendor.com" className="h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Role</Label>
              <Select value={inviteForm.role} onValueChange={v => {
                setInviteForm(p => ({ ...p, role: v }));
                setInviteAssetIds([]);
              }}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="vendor">Vendor</SelectItem>
                  <SelectItem value="employee">Employee</SelectItem>
                  <SelectItem value="third_party">Third Party</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {isExternalInviteRole && (
              <div className="space-y-1.5">
                <Label className="text-xs">Asset Access <span className="text-destructive">*</span></Label>
                <p className="text-[11px] text-muted-foreground">Select the assets this member can view.</p>
                <div className="max-h-36 overflow-y-auto rounded-md border border-border bg-background p-2 space-y-1">
                  {availableAssets.length === 0 ? (
                    <p className="text-xs text-muted-foreground text-center py-2">No assets available</p>
                  ) : availableAssets.map(asset => {
                    const checked = inviteAssetIds.includes(asset.id);
                    return (
                      <label key={asset.id} className="flex items-center gap-2 text-xs px-1 py-0.5 rounded cursor-pointer hover:bg-muted/50">
                        <input
                          type="checkbox"
                          className="accent-primary"
                          checked={checked}
                          onChange={() => setInviteAssetIds(prev =>
                            checked ? prev.filter(id => id !== asset.id) : [...prev, asset.id]
                          )}
                        />
                        <span className="truncate">{asset.name}</span>
                      </label>
                    );
                  })}
                </div>
                {inviteAssetIds.length > 0 && (
                  <p className="text-[11px] text-primary">{inviteAssetIds.length} asset{inviteAssetIds.length > 1 ? "s" : ""} selected</p>
                )}
              </div>
            )}
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => { setShowInvite(false); setInviteAssetIds([]); }}>Cancel</Button>
              <Button type="submit" disabled={inviteSending}>
                {inviteSending ? "Sending…" : "Send Invitation"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Create User Dialog ── */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="w-4 h-4" /> Add User
            </DialogTitle>
            <DialogDescription>Create a new user account.</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreate} className="space-y-3 mt-1">
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
              <Label className="text-xs">Email Address</Label>
              <Input type="email" value={form.email} onChange={e => setForm(p => ({ ...p, email: e.target.value }))} required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Role</Label>
              <Select value={form.role} onValueChange={v => setForm(p => ({ ...p, role: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {allowedRoles.map(r => (
                    <SelectItem key={r} value={r}>{ROLE_META[r]?.label ?? r}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {needsTenantId && (
              <div className="space-y-1.5">
                <Label className="text-xs">Tenant ID <span className="text-muted-foreground">(optional)</span></Label>
                <Input type="number" value={form.tenantId} onChange={e => setForm(p => ({ ...p, tenantId: e.target.value }))} min="1" className="h-9" placeholder="Leave blank for platform tenant" />
              </div>
            )}
            <div className="space-y-1.5">
              <Label className="text-xs">Temporary Password</Label>
              <Input type="password" value={form.password} onChange={e => setForm(p => ({ ...p, password: e.target.value }))} required minLength={8} className="h-9" />
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createUser.isPending}>
                {createUser.isPending ? "Creating…" : "Create User"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Edit User Dialog ── */}
      <Dialog open={!!editUser} onOpenChange={open => { if (!open) setEditUser(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2.5">
              {editUser && <Avatar name={`${editUser.firstName} ${editUser.lastName}`} avatarUrl={editUser.avatarUrl} />}
              Edit User
            </DialogTitle>
            <DialogDescription>Update user profile, role, and security settings.</DialogDescription>
          </DialogHeader>

          {editUser && (
            <div className="space-y-5 mt-1">
              {/* Basic Info */}
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5" /> Basic Information
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs">First Name</Label>
                    <Input value={editState.firstName} onChange={e => setEditState(p => ({ ...p, firstName: e.target.value }))} className="h-9" />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Last Name</Label>
                    <Input value={editState.lastName} onChange={e => setEditState(p => ({ ...p, lastName: e.target.value }))} className="h-9" />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs flex items-center gap-1">
                    <Mail className="w-3 h-3" /> Email Address
                    {!isSuperAdmin && <span className="text-muted-foreground">(read-only)</span>}
                  </Label>
                  <Input
                    type="email"
                    value={editState.email}
                    onChange={e => setEditState(p => ({ ...p, email: e.target.value }))}
                    className="h-9"
                    readOnly={!isSuperAdmin}
                    disabled={!isSuperAdmin}
                  />
                </div>
              </div>

              {/* Role & Access */}
              <div className="space-y-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5" /> Role & Access
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <Label className="text-xs">Role</Label>
                    <Select value={editState.role} onValueChange={v => setEditState(p => ({ ...p, role: v }))}>
                      <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {allowedRoles.map(r => (
                          <SelectItem key={r} value={r}>{ROLE_META[r]?.label ?? r}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  {isSuperAdmin && (
                    <div className="space-y-1.5">
                      <Label className="text-xs flex items-center gap-1">
                        <Building2 className="w-3 h-3" /> Tenant ID
                      </Label>
                      <Input
                        type="number"
                        value={editState.tenantId}
                        onChange={e => setEditState(p => ({ ...p, tenantId: e.target.value }))}
                        className="h-9"
                        min="1"
                      />
                    </div>
                  )}
                </div>
                <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg border border-border/50">
                  <div className="flex items-center gap-2">
                    {editState.isActive
                      ? <CheckCircle2 className="w-4 h-4 text-green-400" />
                      : <AlertCircle className="w-4 h-4 text-muted-foreground" />}
                    <div>
                      <p className="text-sm font-medium">Account {editState.isActive ? "Active" : "Inactive"}</p>
                      <p className="text-xs text-muted-foreground">
                        {editState.isActive ? "User can sign in" : "Sign-in is blocked"}
                      </p>
                    </div>
                  </div>
                  <Switch
                    checked={editState.isActive}
                    onCheckedChange={v => setEditState(p => ({ ...p, isActive: v }))}
                  />
                </div>
              </div>

              {/* Security — super_admin only */}
              {isSuperAdmin && (
                <div className="space-y-3">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                    <Key className="w-3.5 h-3.5" /> Security
                  </p>

                  {/* Password reset */}
                  <div className="space-y-1.5">
                    <Label className="text-xs flex items-center gap-1">
                      <RotateCcw className="w-3 h-3" /> Reset Password
                      <span className="text-muted-foreground">(leave blank to keep current)</span>
                    </Label>
                    <div className="relative">
                      <Input
                        type={showPassword ? "text" : "password"}
                        value={editState.newPassword}
                        onChange={e => setEditState(p => ({ ...p, newPassword: e.target.value }))}
                        className="h-9 pr-10"
                        placeholder="New password (min 8 chars)"
                        minLength={8}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(p => !p)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                    {editState.newPassword.length > 0 && editState.newPassword.length < 8 && (
                      <p className="text-xs text-red-400">Password must be at least 8 characters</p>
                    )}
                  </div>

                  {/* 2FA disable */}
                  {editUser.twoFactorEnabled && (
                    <div className="flex items-center justify-between p-3 bg-amber-500/5 rounded-lg border border-amber-500/20">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4 text-amber-400" />
                        <div>
                          <p className="text-sm font-medium">Two-Factor Auth</p>
                          <p className="text-xs text-muted-foreground">Disable to allow sign-in without OTP</p>
                        </div>
                      </div>
                      <Switch
                        checked={editState.twoFactorEnabled}
                        onCheckedChange={v => setEditState(p => ({ ...p, twoFactorEnabled: v }))}
                      />
                    </div>
                  )}

                  {/* Meta info */}
                  <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                    <div className="bg-muted/30 rounded-lg p-2.5">
                      <p className="font-medium text-foreground/70 mb-0.5">Member Since</p>
                      <p>{editUser.createdAt ? new Date(editUser.createdAt).toLocaleDateString() : "—"}</p>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-2.5">
                      <p className="font-medium text-foreground/70 mb-0.5">Last Login</p>
                      <p>{editUser.lastLoginAt ? formatDateTime(editUser.lastLoginAt) : "Never"}</p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setEditUser(null)}>Cancel</Button>
            <Button onClick={handleSave} disabled={saving}>
              {saving ? "Saving…" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
