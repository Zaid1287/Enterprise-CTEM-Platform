import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  User, Lock, Users, CreditCard, Eye, EyeOff, Loader2,
  CheckCircle2, Mail, Copy, Sparkles, ArrowUpRight, Shield,
  Building2, UserPlus, X, KeyRound, Trash2, ExternalLink,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

type Tab = "profile" | "password" | "team" | "billing" | "aikeys";

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: "profile",  label: "Profile",       icon: User },
  { id: "password", label: "Password",      icon: Lock },
  { id: "team",     label: "Team Members",  icon: Users },
  { id: "billing",  label: "Billing Plans", icon: CreditCard },
  { id: "aikeys",   label: "AI Keys",       icon: KeyRound },
];

const PLAN_TIERS = [
  {
    name: "Starter",
    slug: "starter",
    price: "$49",
    period: "/month",
    description: "For small teams getting started with threat exposure management.",
    maxAssets: 25,
    maxUsers: 5,
    features: ["25 assets", "5 users", "Core vulnerability scanning", "Basic compliance reports", "Email alerts", "7-day data retention"],
    highlight: false,
  },
  {
    name: "Pro",
    slug: "pro",
    price: "$199",
    period: "/month",
    description: "Full CTEM capabilities for growing security teams.",
    maxAssets: 200,
    maxUsers: 25,
    features: ["200 assets", "25 users", "All scanning tools", "Full compliance suite", "AI Copilot", "Takedown requests", "API access", "30-day data retention"],
    highlight: true,
  },
  {
    name: "Enterprise",
    slug: "enterprise",
    price: "Custom",
    period: "",
    description: "Unlimited scale with dedicated support and custom integrations.",
    maxAssets: null,
    maxUsers: null,
    features: ["Unlimited assets", "Unlimited users", "Custom integrations", "Dedicated account manager", "SLA guarantee", "On-prem option", "Unlimited retention"],
    highlight: false,
  },
];

export default function AccountSettingsPage() {
  const [tab, setTab] = useState<Tab>("profile");
  const { user, setUser } = useAuth();

  return (
    <div className="max-w-3xl space-y-5">
      <div>
        <h1 className="text-lg font-semibold">Account Settings</h1>
        <p className="text-sm text-muted-foreground">Manage your profile, security, and team</p>
      </div>

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-border">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(
                "flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors",
                tab === t.id
                  ? "border-primary text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground hover:border-border",
              )}
            >
              <Icon className="w-4 h-4" />
              {t.label}
            </button>
          );
        })}
      </div>

      {tab === "profile"  && <ProfileTab user={user} setUser={setUser} />}
      {tab === "password" && <PasswordTab />}
      {tab === "team"     && <TeamTab />}
      {tab === "billing"  && <BillingTab user={user} />}
      {tab === "aikeys"   && <AiKeysTab />}
    </div>
  );
}

// ── Profile Tab ────────────────────────────────────────────────────

const ROLE_STYLE: Record<string, string> = {
  super_admin:     "bg-purple-500/20 text-purple-400 border-purple-500/30",
  account_manager: "bg-blue-500/20   text-blue-400   border-blue-500/30",
  admin:           "bg-green-500/20  text-green-400  border-green-500/30",
  client:          "bg-muted text-muted-foreground border-border",
};

function ProfileTab({ user, setUser }: { user: any; setUser: (u: any) => void }) {
  const { toast } = useToast();
  const [form, setForm] = useState({
    firstName: user?.firstName ?? "",
    lastName:  user?.lastName  ?? "",
  });
  const [saving, setSaving] = useState(false);
  const [editMode, setEditMode] = useState(false);

  const initials = `${user?.firstName?.[0] ?? ""}${user?.lastName?.[0] ?? ""}`.toUpperCase();
  const fullName  = `${user?.firstName ?? ""} ${user?.lastName ?? ""}`.trim();
  const roleCls   = ROLE_STYLE[user?.role] ?? ROLE_STYLE.client;

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.firstName.trim() || !form.lastName.trim()) {
      toast({ title: "Name fields cannot be empty", variant: "destructive" }); return;
    }
    setSaving(true);
    try {
      const updated = await apiFetch(`${BASE}/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ firstName: form.firstName.trim(), lastName: form.lastName.trim() }),
      });
      setUser({ ...user, ...(updated as any) });
      setEditMode(false);
      toast({ title: "Profile updated" });
    } catch {
      toast({ title: "Failed to update profile", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  const handleCancel = () => {
    setForm({ firstName: user?.firstName ?? "", lastName: user?.lastName ?? "" });
    setEditMode(false);
  };

  return (
    <div className="space-y-4">
      {/* Identity card */}
      <div className="bg-card border border-border rounded-xl p-6">
        <div className="flex items-start gap-5">
          {/* Avatar */}
          <div className="relative shrink-0">
            <div className="w-20 h-20 rounded-2xl bg-primary/15 border-2 border-primary/25 flex items-center justify-center text-2xl font-bold text-primary select-none">
              {initials || "?"}
            </div>
            <span className={cn(
              "absolute -bottom-2 left-1/2 -translate-x-1/2 text-[9px] px-2 py-0.5 rounded-full font-bold uppercase tracking-wider border whitespace-nowrap",
              roleCls
            )}>
              {user?.role?.replace(/_/g, " ")}
            </span>
          </div>

          {/* Info block */}
          <div className="flex-1 min-w-0 pt-1">
            {editMode ? (
              <form onSubmit={handleSave} className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs">First Name</Label>
                    <Input
                      value={form.firstName}
                      onChange={e => setForm(p => ({ ...p, firstName: e.target.value }))}
                      placeholder="First name"
                      autoFocus
                      className="h-9"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Last Name</Label>
                    <Input
                      value={form.lastName}
                      onChange={e => setForm(p => ({ ...p, lastName: e.target.value }))}
                      placeholder="Last name"
                      className="h-9"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button type="submit" size="sm" disabled={saving}>
                    {saving && <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />}
                    Save Changes
                  </Button>
                  <Button type="button" size="sm" variant="outline" onClick={handleCancel}>Cancel</Button>
                </div>
              </form>
            ) : (
              <div className="space-y-0.5">
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-bold leading-tight">{fullName || "—"}</h2>
                  <button
                    onClick={() => setEditMode(true)}
                    className="text-xs text-muted-foreground hover:text-foreground border border-border hover:border-primary/40 rounded-md px-2.5 py-1 transition-colors"
                  >
                    Edit
                  </button>
                </div>
                <p className="text-sm text-muted-foreground">{user?.email}</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Account details grid */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-card border border-border rounded-xl p-4">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Email</p>
          <p className="text-sm font-medium truncate">{user?.email ?? "—"}</p>
          <p className="text-[10px] text-muted-foreground mt-0.5">Cannot be changed · contact support</p>
        </div>
        <div className="bg-card border border-border rounded-xl p-4">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Role</p>
          <p className="text-sm font-medium capitalize">{user?.role?.replace(/_/g, " ") ?? "—"}</p>
          <p className="text-[10px] text-muted-foreground mt-0.5">Assigned by your administrator</p>
        </div>
        <div className="bg-card border border-border rounded-xl p-4">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Member Since</p>
          <p className="text-sm font-medium">
            {user?.createdAt ? new Date(user.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" }) : "—"}
          </p>
        </div>
        <div className="bg-card border border-border rounded-xl p-4">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-1">Workspace ID</p>
          <p className="text-sm font-mono font-medium">tenant-{user?.tenantId ?? "?"}</p>
        </div>
      </div>
    </div>
  );
}

// ── Password Tab ────────────────────────────────────────────────────

function PasswordTab() {
  const { toast } = useToast();
  const [form, setForm] = useState({ currentPassword: "", newPassword: "", confirmPassword: "" });
  const [show, setShow] = useState({ current: false, new: false, confirm: false });
  const [saving, setSaving] = useState(false);
  const [strength, setStrength] = useState(0);

  function calcStrength(p: string): number {
    let s = 0;
    if (p.length >= 8)  s++;
    if (p.length >= 12) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[0-9]/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return s;
  }

  const strengthLabel = ["", "Weak", "Fair", "Good", "Strong", "Very Strong"][strength];
  const strengthColor = ["", "bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-green-500", "bg-emerald-500"][strength];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.newPassword !== form.confirmPassword) {
      toast({ title: "Passwords do not match", variant: "destructive" }); return;
    }
    if (form.newPassword.length < 8) {
      toast({ title: "Password must be at least 8 characters", variant: "destructive" }); return;
    }
    setSaving(true);
    try {
      await apiFetch(`${BASE}/api/auth/change-password`, {
        method: "POST",
        body: JSON.stringify({ currentPassword: form.currentPassword, newPassword: form.newPassword }),
      });
      setForm({ currentPassword: "", newPassword: "", confirmPassword: "" });
      setStrength(0);
      toast({ title: "Password changed successfully" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to change password", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-card border border-border rounded-xl p-6 space-y-5">
      <div className="flex items-center gap-2 text-sm text-muted-foreground bg-accent/30 rounded-lg px-3 py-2.5">
        <Shield className="w-4 h-4 text-primary shrink-0" />
        Use a strong, unique password. We recommend at least 12 characters with a mix of letters, numbers, and symbols.
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1.5">
          <Label>Current Password</Label>
          <div className="relative">
            <Input
              type={show.current ? "text" : "password"}
              value={form.currentPassword}
              onChange={e => setForm(p => ({ ...p, currentPassword: e.target.value }))}
              placeholder="Enter current password"
              required
            />
            <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => setShow(p => ({ ...p, current: !p.current }))}>
              {show.current ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
        </div>

        <div className="space-y-1.5">
          <Label>New Password</Label>
          <div className="relative">
            <Input
              type={show.new ? "text" : "password"}
              value={form.newPassword}
              onChange={e => { setForm(p => ({ ...p, newPassword: e.target.value })); setStrength(calcStrength(e.target.value)); }}
              placeholder="Enter new password"
              required
            />
            <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => setShow(p => ({ ...p, new: !p.new }))}>
              {show.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          {form.newPassword && (
            <div className="space-y-1">
              <div className="flex gap-1">
                {[1, 2, 3, 4, 5].map(i => (
                  <div key={i} className={cn("h-1 flex-1 rounded-full transition-all", i <= strength ? strengthColor : "bg-border")} />
                ))}
              </div>
              <p className="text-xs text-muted-foreground">{strengthLabel}</p>
            </div>
          )}
        </div>

        <div className="space-y-1.5">
          <Label>Confirm New Password</Label>
          <div className="relative">
            <Input
              type={show.confirm ? "text" : "password"}
              value={form.confirmPassword}
              onChange={e => setForm(p => ({ ...p, confirmPassword: e.target.value }))}
              placeholder="Confirm new password"
              required
            />
            <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => setShow(p => ({ ...p, confirm: !p.confirm }))}>
              {show.confirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          {form.confirmPassword && form.confirmPassword !== form.newPassword && (
            <p className="text-xs text-red-400">Passwords do not match</p>
          )}
          {form.confirmPassword && form.confirmPassword === form.newPassword && form.newPassword && (
            <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> Passwords match</p>
          )}
        </div>

        <div className="flex justify-end pt-1">
          <Button type="submit" disabled={saving || !form.currentPassword || !form.newPassword || form.newPassword !== form.confirmPassword}>
            {saving ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : <Lock className="w-4 h-4 mr-1.5" />}
            Change Password
          </Button>
        </div>
      </form>
    </div>
  );
}

// ── Team Tab ────────────────────────────────────────────────────────

function TeamTab() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("client");
  const [sending, setSending] = useState(false);
  const [showInvite, setShowInvite] = useState(false);

  const { data: members = [], isLoading } = useQuery<any[]>({
    queryKey: ["team-members"],
    queryFn: () => apiFetch(`${BASE}/api/users`),
  });

  const deactivateMutation = useMutation({
    mutationFn: (userId: number) =>
      apiFetch(`${BASE}/api/users/${userId}`, { method: "PATCH", body: JSON.stringify({ isActive: false }) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["team-members"] }); toast({ title: "User deactivated" }); },
  });

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setSending(true);
    try {
      await apiFetch(`${BASE}/api/users`, {
        method: "POST",
        body: JSON.stringify({
          email: inviteEmail,
          password: `Invite${Math.random().toString(36).slice(2, 10)}!`,
          firstName: inviteEmail.split("@")[0],
          lastName: "",
          role: inviteRole,
        }),
      });
      qc.invalidateQueries({ queryKey: ["team-members"] });
      setInviteEmail("");
      setShowInvite(false);
      toast({ title: "Team member added", description: `${inviteEmail} has been added to your workspace.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to add member", variant: "destructive" });
    } finally {
      setSending(false);
    }
  };

  const roleColor: Record<string, string> = {
    super_admin:     "bg-purple-500/20 text-purple-400 border-purple-500/30",
    account_manager: "bg-blue-500/20   text-blue-400   border-blue-500/30",
    admin:           "bg-green-500/20  text-green-400  border-green-500/30",
    client:          "bg-muted text-muted-foreground border-border",
  };

  const canInvite = user?.role === "admin" || user?.role === "super_admin" || user?.role === "account_manager";
  const invitableRoles = user?.role === "super_admin"
    ? ["admin", "account_manager", "client"]
    : user?.role === "admin"
    ? ["client"]
    : ["client"];

  return (
    <div className="space-y-4">
      {/* Invite panel */}
      {canInvite && (
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-3">
            <div>
              <p className="font-medium text-sm">Invite Team Member</p>
              <p className="text-xs text-muted-foreground mt-0.5">Add a new user to your workspace</p>
            </div>
            <Button size="sm" onClick={() => setShowInvite(v => !v)}>
              <UserPlus className="w-4 h-4 mr-1.5" />
              {showInvite ? "Cancel" : "Invite"}
            </Button>
          </div>

          {showInvite && (
            <form onSubmit={handleInvite} className="space-y-3 pt-3 border-t border-border">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Email Address</Label>
                  <Input
                    type="email"
                    value={inviteEmail}
                    onChange={e => setInviteEmail(e.target.value)}
                    placeholder="colleague@company.com"
                    required
                    className="h-9"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Role</Label>
                  <select
                    value={inviteRole}
                    onChange={e => setInviteRole(e.target.value)}
                    className="w-full h-9 rounded-md border border-border bg-background text-sm px-3 focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    {invitableRoles.map(r => (
                      <option key={r} value={r}>{r.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="flex justify-end">
                <Button type="submit" size="sm" disabled={sending}>
                  {sending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Mail className="w-3.5 h-3.5 mr-1.5" />}
                  Add Member
                </Button>
              </div>
            </form>
          )}
        </div>
      )}

      {/* Members list */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <p className="text-sm font-medium">Team Members</p>
          <span className="text-xs text-muted-foreground">{(members as any[]).filter((m: any) => m.isActive).length} active</span>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : (members as any[]).length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">No team members yet</div>
        ) : (
          <div className="divide-y divide-border">
            {(members as any[]).map((m: any) => (
              <div key={m.id} className={cn("flex items-center gap-3 px-5 py-3.5", !m.isActive && "opacity-50")}>
                <div className="w-9 h-9 rounded-full bg-accent flex items-center justify-center text-sm font-semibold shrink-0">
                  {m.firstName?.[0]}{m.lastName?.[0]}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{m.firstName} {m.lastName} {m.id === user?.id && <span className="text-xs text-muted-foreground">(you)</span>}</p>
                  <p className="text-xs text-muted-foreground truncate">{m.email}</p>
                </div>
                <span className={cn("text-[10px] px-2 py-0.5 rounded font-semibold uppercase tracking-wider border shrink-0", roleColor[m.role] ?? roleColor.client)}>
                  {m.role?.replace(/_/g, " ")}
                </span>
                {!m.isActive && <span className="text-xs text-muted-foreground">(inactive)</span>}
                {m.isActive && m.id !== user?.id && canInvite && (
                  <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive shrink-0"
                    onClick={() => deactivateMutation.mutate(m.id)} title="Deactivate user">
                    <X className="w-3.5 h-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Billing Tab ────────────────────────────────────────────────────

function BillingTab({ user }: { user: any }) {
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const { data: tenantData } = useQuery<any>({
    queryKey: ["tenant-billing"],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${user?.tenantId}`).catch(() => null),
    enabled: !!user?.tenantId,
  });

  const currentPlan = tenantData?.plan ?? "starter";
  const adminEmail = "admin@ctemplatform.com";

  function copyEmail() {
    navigator.clipboard.writeText(adminEmail).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="space-y-5">
      {/* Current plan banner */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between">
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Current Plan</p>
            <p className="text-2xl font-bold capitalize">{currentPlan}</p>
            <p className="text-sm text-muted-foreground mt-1">
              {tenantData?.name ?? "Your workspace"} · {tenantData?.maxAssets ?? "—"} max assets · {tenantData?.maxUsers ?? "—"} max users
            </p>
          </div>
          <div className="bg-primary/10 border border-primary/20 rounded-lg px-3 py-1.5">
            <p className="text-xs font-semibold text-primary uppercase tracking-wide">Active</p>
          </div>
        </div>
      </div>

      {/* Upgrade notice */}
      <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 px-4 py-3.5 flex items-start gap-3">
        <Sparkles className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-amber-300">Want to upgrade your plan?</p>
          <p className="text-xs text-amber-400/80 mt-0.5">
            Contact our admin team to upgrade, downgrade, or discuss enterprise pricing.
          </p>
          <div className="flex items-center gap-2 mt-2">
            <span className="text-xs font-mono text-amber-300">{adminEmail}</span>
            <button onClick={copyEmail} className="text-amber-400 hover:text-amber-300">
              {copied ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
        <a href={`mailto:${adminEmail}?subject=Plan Upgrade Request`}>
          <Button size="sm" variant="outline" className="shrink-0 border-amber-500/40 text-amber-400 hover:bg-amber-500/10">
            <Mail className="w-3.5 h-3.5 mr-1.5" /> Contact Admin
          </Button>
        </a>
      </div>

      {/* Plan tiers */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {PLAN_TIERS.map(plan => {
          const isCurrent = plan.slug === currentPlan;
          return (
            <div
              key={plan.slug}
              className={cn(
                "rounded-xl border p-5 space-y-4 relative",
                plan.highlight ? "border-primary/50 bg-primary/5" : "border-border bg-card",
                isCurrent && "ring-2 ring-primary/40",
              )}
            >
              {plan.highlight && (
                <div className="absolute -top-2.5 left-1/2 -translate-x-1/2">
                  <span className="bg-primary text-primary-foreground text-[10px] font-bold px-3 py-0.5 rounded-full uppercase tracking-wider">Most Popular</span>
                </div>
              )}
              {isCurrent && (
                <div className="absolute top-3 right-3">
                  <span className="bg-green-500/20 text-green-400 border border-green-500/30 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase">Current</span>
                </div>
              )}

              <div>
                <p className="font-semibold text-base">{plan.name}</p>
                <div className="flex items-baseline gap-1 mt-1">
                  <span className="text-2xl font-bold">{plan.price}</span>
                  <span className="text-sm text-muted-foreground">{plan.period}</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{plan.description}</p>
              </div>

              <ul className="space-y-1.5">
                {plan.features.map(f => (
                  <li key={f} className="flex items-center gap-2 text-xs text-muted-foreground">
                    <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                    {f}
                  </li>
                ))}
              </ul>

              {!isCurrent && (
                <a href={`mailto:${adminEmail}?subject=Upgrade to ${plan.name} Plan`} className="block">
                  <Button size="sm" variant={plan.highlight ? "default" : "outline"} className="w-full">
                    <ArrowUpRight className="w-3.5 h-3.5 mr-1.5" />
                    {currentPlan === "enterprise" || (PLAN_TIERS.findIndex(p => p.slug === currentPlan) > PLAN_TIERS.findIndex(p => p.slug === plan.slug))
                      ? "Downgrade" : "Upgrade"}
                  </Button>
                </a>
              )}
              {isCurrent && (
                <Button size="sm" variant="outline" disabled className="w-full">
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1.5 text-green-400" /> Active Plan
                </Button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── AI Keys Tab ────────────────────────────────────────────────────

const AI_PROVIDERS = [
  {
    id: "openai",
    name: "OpenAI",
    description: "GPT-4, GPT-4o and other OpenAI models",
    placeholder: "sk-...",
    docsUrl: "https://platform.openai.com/api-keys",
    color: "text-green-400",
    bg: "bg-green-500/10 border-green-500/20",
  },
  {
    id: "gemini",
    name: "Google Gemini",
    description: "Gemini 1.5 Pro, Gemini Flash",
    placeholder: "AIza...",
    docsUrl: "https://aistudio.google.com/app/apikey",
    color: "text-blue-400",
    bg: "bg-blue-500/10 border-blue-500/20",
  },
  {
    id: "anthropic",
    name: "Anthropic",
    description: "Claude 3.5 Sonnet, Claude 3 Haiku",
    placeholder: "sk-ant-...",
    docsUrl: "https://console.anthropic.com/settings/keys",
    color: "text-orange-400",
    bg: "bg-orange-500/10 border-orange-500/20",
  },
  {
    id: "openrouter",
    name: "OpenRouter",
    description: "Unified access to 100+ AI models",
    placeholder: "sk-or-...",
    docsUrl: "https://openrouter.ai/keys",
    color: "text-purple-400",
    bg: "bg-purple-500/10 border-purple-500/20",
  },
  {
    id: "ollama",
    name: "Ollama",
    description: "Local models (Llama, Mistral, etc.)",
    placeholder: "Leave blank if using default local URL",
    docsUrl: "https://ollama.ai",
    color: "text-cyan-400",
    bg: "bg-cyan-500/10 border-cyan-500/20",
    hasBaseUrl: true,
  },
] as const;

type ProviderId = typeof AI_PROVIDERS[number]["id"];

function AiKeysTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [editing, setEditing] = useState<ProviderId | null>(null);
  const [inputs, setInputs] = useState<Record<string, { apiKey: string; baseUrl: string }>>({});
  const [show, setShow] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState<ProviderId | null>(null);
  const [deleting, setDeleting] = useState<ProviderId | null>(null);

  const { data: settings = [], isLoading } = useQuery<any[]>({
    queryKey: ["ai-settings"],
    queryFn: () => apiFetch(`${BASE}/api/me/ai-settings`),
  });

  const savedByProvider = new Map<string, any>((settings as any[]).map((s: any) => [s.provider, s]));

  function startEdit(providerId: ProviderId) {
    const existing = savedByProvider.get(providerId);
    setInputs(p => ({
      ...p,
      [providerId]: { apiKey: "", baseUrl: existing?.baseUrl ?? "" },
    }));
    setEditing(providerId);
  }

  function cancelEdit() {
    setEditing(null);
  }

  async function handleSave(providerId: ProviderId) {
    const { apiKey, baseUrl } = inputs[providerId] ?? { apiKey: "", baseUrl: "" };
    if (!apiKey.trim() && providerId !== "ollama") {
      toast({ title: "API key cannot be empty", variant: "destructive" }); return;
    }
    setSaving(providerId);
    try {
      await apiFetch(`${BASE}/api/me/ai-settings/${providerId}`, {
        method: "PUT",
        body: JSON.stringify({ apiKey: apiKey.trim(), baseUrl: baseUrl.trim() || undefined }),
      });
      qc.invalidateQueries({ queryKey: ["ai-settings"] });
      setEditing(null);
      toast({ title: `${AI_PROVIDERS.find(p => p.id === providerId)?.name} key saved` });
    } catch {
      toast({ title: "Failed to save key", variant: "destructive" });
    } finally {
      setSaving(null);
    }
  }

  async function handleDelete(providerId: ProviderId) {
    setDeleting(providerId);
    try {
      await apiFetch(`${BASE}/api/me/ai-settings/${providerId}`, { method: "DELETE" });
      qc.invalidateQueries({ queryKey: ["ai-settings"] });
      toast({ title: "API key removed" });
    } catch {
      toast({ title: "Failed to remove key", variant: "destructive" });
    } finally {
      setDeleting(null);
    }
  }

  return (
    <div className="space-y-4">
      {/* Header info */}
      <div className="rounded-xl border border-border bg-card px-5 py-4">
        <div className="flex items-start gap-3">
          <KeyRound className="w-5 h-5 text-primary shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sm">Your AI API Keys</p>
            <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
              Add your own API keys to power the AI Copilot with real AI models. Keys are stored securely and
              used only for your AI Copilot requests. Your keys are never shared with other users.
            </p>
          </div>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-10">
          <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="space-y-3">
          {AI_PROVIDERS.map(provider => {
            const saved = savedByProvider.get(provider.id);
            const isEditingThis = editing === provider.id;
            const inp = inputs[provider.id] ?? { apiKey: "", baseUrl: "" };
            const showKey = show[provider.id] ?? false;

            return (
              <div
                key={provider.id}
                className={cn(
                  "rounded-xl border p-5 transition-colors",
                  saved ? "border-border bg-card" : "border-border/50 bg-card/50",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3 min-w-0">
                    <div className={cn("w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 text-xs font-bold", provider.bg, provider.color)}>
                      {provider.name[0]}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium">{provider.name}</p>
                        {saved?.hasKey && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 font-semibold">
                            ✓ Configured
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground mt-0.5">{provider.description}</p>
                      {saved?.hasKey && !isEditingThis && (
                        <p className="text-xs font-mono text-muted-foreground mt-1 truncate max-w-[220px]">
                          {saved.apiKey}
                        </p>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <a href={provider.docsUrl} target="_blank" rel="noreferrer">
                      <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-foreground">
                        <ExternalLink className="w-3.5 h-3.5" />
                      </Button>
                    </a>
                    {!isEditingThis && (
                      <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => startEdit(provider.id)}>
                        {saved?.hasKey ? "Update" : "Add Key"}
                      </Button>
                    )}
                    {saved?.hasKey && !isEditingThis && (
                      <Button
                        size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        disabled={deleting === provider.id}
                        onClick={() => handleDelete(provider.id)}
                      >
                        {deleting === provider.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                      </Button>
                    )}
                  </div>
                </div>

                {/* Edit form */}
                {isEditingThis && (
                  <div className="mt-4 space-y-3 pt-4 border-t border-border">
                    <div className="space-y-1.5">
                      <Label className="text-xs">API Key</Label>
                      <div className="relative">
                        <Input
                          type={showKey ? "text" : "password"}
                          value={inp.apiKey}
                          onChange={e => setInputs(p => ({ ...p, [provider.id]: { ...inp, apiKey: e.target.value } }))}
                          placeholder={provider.placeholder}
                          className="h-9 font-mono text-xs pr-9"
                          autoFocus
                        />
                        <button
                          type="button"
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                          onClick={() => setShow(p => ({ ...p, [provider.id]: !showKey }))}
                        >
                          {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>

                    {"hasBaseUrl" in provider && provider.hasBaseUrl && (
                      <div className="space-y-1.5">
                        <Label className="text-xs">Base URL <span className="text-muted-foreground">(optional, default: http://localhost:11434)</span></Label>
                        <Input
                          type="text"
                          value={inp.baseUrl}
                          onChange={e => setInputs(p => ({ ...p, [provider.id]: { ...inp, baseUrl: e.target.value } }))}
                          placeholder="http://localhost:11434"
                          className="h-9 font-mono text-xs"
                        />
                      </div>
                    )}

                    <div className="flex gap-2 justify-end">
                      <Button size="sm" variant="outline" onClick={cancelEdit}>Cancel</Button>
                      <Button size="sm" disabled={saving === provider.id} onClick={() => handleSave(provider.id)}>
                        {saving === provider.id ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <KeyRound className="w-3.5 h-3.5 mr-1.5" />}
                        Save Key
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 flex items-start gap-3">
        <Shield className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <p className="text-xs text-amber-400/90 leading-relaxed">
          API keys are stored encrypted and are only used for your AI Copilot requests. We never log or share your keys.
          Revoke access by removing the key at any time.
        </p>
      </div>
    </div>
  );
}
