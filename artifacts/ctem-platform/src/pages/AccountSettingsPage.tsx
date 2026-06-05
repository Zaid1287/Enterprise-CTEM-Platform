import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  User, Lock, Users, CreditCard, Eye, EyeOff, Loader2,
  CheckCircle2, Mail, Copy, Sparkles, ArrowUpRight, Shield,
  Building2, UserPlus, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

type Tab = "profile" | "password" | "team" | "billing";

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: "profile",  label: "Profile",       icon: User },
  { id: "password", label: "Password",      icon: Lock },
  { id: "team",     label: "Team Members",  icon: Users },
  { id: "billing",  label: "Billing Plans", icon: CreditCard },
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
    </div>
  );
}

// ── Profile Tab ────────────────────────────────────────────────────

function ProfileTab({ user, setUser }: { user: any; setUser: (u: any) => void }) {
  const { toast } = useToast();
  const [form, setForm] = useState({
    firstName: user?.firstName ?? "",
    lastName: user?.lastName ?? "",
    email: user?.email ?? "",
  });
  const [saving, setSaving] = useState(false);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const updated = await apiFetch(`${BASE}/api/users/${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ firstName: form.firstName, lastName: form.lastName }),
      });
      setUser({ ...user, ...(updated as any) });
      toast({ title: "Profile updated successfully" });
    } catch {
      toast({ title: "Failed to update profile", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-card border border-border rounded-xl p-6 space-y-5">
      {/* Avatar */}
      <div className="flex items-center gap-4">
        <div className="w-16 h-16 rounded-full bg-primary/15 border border-primary/30 flex items-center justify-center text-xl font-bold text-primary">
          {user?.firstName?.[0]}{user?.lastName?.[0]}
        </div>
        <div>
          <p className="font-semibold">{user?.firstName} {user?.lastName}</p>
          <p className="text-sm text-muted-foreground">{user?.email}</p>
          <span className={cn(
            "text-[10px] px-2 py-0.5 rounded font-semibold uppercase tracking-wider mt-1 inline-block",
            user?.role === "super_admin"     ? "bg-purple-500/20 text-purple-400 border border-purple-500/30" :
            user?.role === "account_manager" ? "bg-blue-500/20   text-blue-400   border border-blue-500/30"   :
            user?.role === "admin"           ? "bg-green-500/20  text-green-400  border border-green-500/30"   :
                                               "bg-muted text-muted-foreground border border-border",
          )}>
            {user?.role?.replace(/_/g, " ")}
          </span>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label>First Name</Label>
            <Input value={form.firstName} onChange={e => setForm(p => ({ ...p, firstName: e.target.value }))} placeholder="First name" />
          </div>
          <div className="space-y-1.5">
            <Label>Last Name</Label>
            <Input value={form.lastName} onChange={e => setForm(p => ({ ...p, lastName: e.target.value }))} placeholder="Last name" />
          </div>
        </div>
        <div className="space-y-1.5">
          <Label>Email Address</Label>
          <Input value={form.email} disabled className="bg-muted/30 text-muted-foreground cursor-not-allowed" />
          <p className="text-xs text-muted-foreground">Email cannot be changed. Contact support if needed.</p>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label>Tenant</Label>
            <Input value={`Tenant #${user?.tenantId}`} disabled className="bg-muted/30 text-muted-foreground cursor-not-allowed" />
          </div>
          <div className="space-y-1.5">
            <Label>Member Since</Label>
            <Input value={user?.createdAt ? new Date(user.createdAt).toLocaleDateString() : "—"} disabled className="bg-muted/30 text-muted-foreground cursor-not-allowed" />
          </div>
        </div>
        <div className="flex justify-end pt-1">
          <Button type="submit" disabled={saving}>
            {saving ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
            Save Changes
          </Button>
        </div>
      </form>
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
