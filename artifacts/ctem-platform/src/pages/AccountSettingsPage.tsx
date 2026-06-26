import { useState, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import {
  User, Lock, Users, CreditCard, Eye, EyeOff, Loader2,
  CheckCircle2, Mail, Copy, Sparkles, ArrowUpRight, Shield, ShieldCheck,
  Building2, UserPlus, X, KeyRound, Trash2, ExternalLink,
  Camera, SmartphoneNfc, Send, Clock, Check, Ticket,
  Monitor, Globe, LogOut, Bell, Hash, MessageSquare,
  Webhook, ToggleLeft, ToggleRight, TestTube, AlertCircle, Save,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

type Tab = "profile" | "password" | "team" | "billing" | "aikeys" | "sessions" | "notifications";

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: "profile",       label: "Profile",       icon: User },
  { id: "password",      label: "Password",      icon: Lock },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "team",          label: "Team Members",  icon: Users },
  { id: "billing",       label: "Billing Plans", icon: CreditCard },
  { id: "sessions",      label: "Sessions",      icon: Monitor },
  { id: "aikeys",        label: "AI Keys",       icon: KeyRound },
];


export default function AccountSettingsPage() {
  const [tab, setTab] = useState<Tab>("profile");
  const { user, setUser } = useAuth();

  return (
    <div className="space-y-5">
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

      {tab === "profile"       && <ProfileTab user={user} setUser={setUser} />}
      {tab === "password"      && <div className="space-y-5"><PasswordTab /><TwoFactorSection user={user} setUser={setUser} /></div>}
      {tab === "notifications" && <NotificationsTab />}
      {tab === "team"          && <TeamTab />}
      {tab === "billing"       && <BillingTab user={user} />}
      {tab === "sessions"      && <SessionsTab />}
      {tab === "aikeys"        && <AiKeysTab />}
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
  const [uploadingAvatar, setUploadingAvatar] = useState(false);
  const avatarInputRef = useRef<HTMLInputElement>(null);

  const initials = `${user?.firstName?.[0] ?? ""}${user?.lastName?.[0] ?? ""}`.toUpperCase();
  const fullName  = `${user?.firstName ?? ""} ${user?.lastName ?? ""}`.trim();
  const roleCls   = ROLE_STYLE[user?.role] ?? ROLE_STYLE.client;

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadingAvatar(true);
    try {
      const formData = new FormData();
      formData.append("avatar", file);
      const result = await apiFetch(`${BASE}/api/auth/avatar`, {
        method: "POST",
        body: formData,
        headers: {}, // Don't set Content-Type — browser will set multipart boundary
      });
      setUser({ ...user, avatarUrl: (result as any).avatarUrl });
      toast({ title: "Profile picture updated" });
    } catch {
      toast({ title: "Failed to upload picture", variant: "destructive" });
    } finally {
      setUploadingAvatar(false);
      if (avatarInputRef.current) avatarInputRef.current.value = "";
    }
  };

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
    <div className="space-y-5">
      {/* Hero identity card — full width, side-by-side layout */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {/* Top accent strip */}
        <div className="h-1.5 w-full bg-gradient-to-r from-primary/80 via-primary/40 to-transparent" />

        <div className="p-6 flex flex-col sm:flex-row gap-8">
          {/* Left: avatar + name block */}
          <div className="flex items-center gap-5 shrink-0">
            <div className="relative group">
              {user?.avatarUrl ? (
                <img
                  src={`${BASE}${user.avatarUrl}`}
                  alt={fullName}
                  className="w-24 h-24 rounded-2xl border-2 border-primary/25 object-cover"
                />
              ) : (
                <div className="w-24 h-24 rounded-2xl bg-primary/15 border-2 border-primary/25 flex items-center justify-center text-3xl font-bold text-primary select-none shadow-inner">
                  {initials || "?"}
                </div>
              )}
              {/* Upload overlay */}
              <button
                type="button"
                onClick={() => avatarInputRef.current?.click()}
                disabled={uploadingAvatar}
                className="absolute inset-0 rounded-2xl bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center"
              >
                {uploadingAvatar
                  ? <Loader2 className="w-6 h-6 text-white animate-spin" />
                  : <Camera className="w-6 h-6 text-white" />
                }
              </button>
              <input
                ref={avatarInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={handleAvatarUpload}
              />
              <span className={cn(
                "absolute -bottom-2.5 left-1/2 -translate-x-1/2 text-[9px] px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider border whitespace-nowrap shadow",
                roleCls,
              )}>
                {user?.role?.replace(/_/g, " ")}
              </span>
            </div>

            <div className="space-y-0.5">
              {editMode ? null : (
                <>
                  <h2 className="text-2xl font-bold leading-tight">{fullName || "—"}</h2>
                  <p className="text-sm text-muted-foreground">{user?.email}</p>
                  <button
                    type="button"
                    onClick={() => avatarInputRef.current?.click()}
                    className="text-[11px] text-muted-foreground hover:text-primary flex items-center gap-1 mt-1"
                  >
                    <Camera className="w-3 h-3" /> Change photo
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Divider */}
          <div className="hidden sm:block w-px bg-border self-stretch mx-2" />

          {/* Right: edit form or info grid — takes remaining width */}
          <div className="flex-1 min-w-0">
            {editMode ? (
              <form onSubmit={handleSave} className="space-y-4">
                <div>
                  <h3 className="text-sm font-semibold mb-3">Edit Profile</h3>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="space-y-1.5">
                      <Label className="text-xs">First Name</Label>
                      <Input
                        value={form.firstName}
                        onChange={e => setForm(p => ({ ...p, firstName: e.target.value }))}
                        placeholder="First name"
                        autoFocus
                        className="h-9"
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs">Last Name</Label>
                      <Input
                        value={form.lastName}
                        onChange={e => setForm(p => ({ ...p, lastName: e.target.value }))}
                        placeholder="Last name"
                        className="h-9"
                      />
                    </div>
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
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">Account Details</h3>
                  <button
                    onClick={() => setEditMode(true)}
                    className="text-xs text-muted-foreground hover:text-foreground border border-border hover:border-primary/40 rounded-md px-3 py-1.5 transition-colors"
                  >
                    Edit Profile
                  </button>
                </div>
                <div className="grid grid-cols-2 gap-x-8 gap-y-4">
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-0.5">Email Address</p>
                    <p className="text-sm font-medium truncate">{user?.email ?? "—"}</p>
                    <p className="text-[10px] text-muted-foreground/70 mt-0.5">Contact support to change</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-0.5">Role</p>
                    <span className={cn("inline-block text-xs px-2 py-0.5 rounded-md font-semibold border", roleCls)}>
                      {user?.role?.replace(/_/g, " ") ?? "—"}
                    </span>
                    <p className="text-[10px] text-muted-foreground/70 mt-1">Assigned by administrator</p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-0.5">Member Since</p>
                    <p className="text-sm font-medium">
                      {user?.createdAt
                        ? new Date(user.createdAt).toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })
                        : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-[10px] text-muted-foreground uppercase tracking-wide font-semibold mb-0.5">Workspace ID</p>
                    <p className="text-sm font-mono font-medium text-primary">tenant-{user?.tenantId ?? "?"}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick stats row */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-card border border-border rounded-xl p-4 text-center">
          <p className="text-2xl font-bold text-primary">—</p>
          <p className="text-xs text-muted-foreground mt-1">Assets Assigned</p>
        </div>
        <div className="bg-card border border-border rounded-xl p-4 text-center">
          <p className="text-2xl font-bold text-orange-400">—</p>
          <p className="text-xs text-muted-foreground mt-1">Open Findings</p>
        </div>
        <div className="bg-card border border-border rounded-xl p-4 text-center">
          <p className="text-2xl font-bold text-green-400">—</p>
          <p className="text-xs text-muted-foreground mt-1">Scans Completed</p>
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

// ── Two-Factor Auth component ────────────────────────────────────────

function TwoFactorSection({ user, setUser }: { user: any; setUser: (u: any) => void }) {
  const { toast } = useToast();
  const [step, setStep] = useState<"idle" | "pending_otp">("idle");
  const [otp, setOtp] = useState("");
  const [loading, setLoading] = useState(false);
  const [disablePassword, setDisablePassword] = useState("");
  const [showDisable, setShowDisable] = useState(false);
  const enabled = user?.twoFactorEnabled ?? false;

  const handleEnable = async () => {
    setLoading(true);
    try {
      await apiFetch(`${BASE}/api/auth/2fa/enable`, { method: "POST", body: JSON.stringify({}) });
      setStep("pending_otp");
      toast({ title: "Check your email for a verification code" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to send code", variant: "destructive" });
    } finally { setLoading(false); }
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await apiFetch(`${BASE}/api/auth/2fa/confirm`, { method: "POST", body: JSON.stringify({ otp }) });
      setUser({ ...user, twoFactorEnabled: true });
      setStep("idle"); setOtp("");
      toast({ title: "Two-factor authentication enabled" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Invalid code", variant: "destructive" });
    } finally { setLoading(false); }
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await apiFetch(`${BASE}/api/auth/2fa/disable`, { method: "POST", body: JSON.stringify({ password: disablePassword }) });
      setUser({ ...user, twoFactorEnabled: false });
      setShowDisable(false); setDisablePassword("");
      toast({ title: "Two-factor authentication disabled" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to disable 2FA", variant: "destructive" });
    } finally { setLoading(false); }
  };

  return (
    <div className="bg-card border border-border rounded-xl p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className={cn("w-9 h-9 rounded-lg flex items-center justify-center border", enabled ? "bg-green-500/10 border-green-500/30" : "bg-muted border-border")}>
            <SmartphoneNfc className={cn("w-4 h-4", enabled ? "text-green-400" : "text-muted-foreground")} />
          </div>
          <div>
            <p className="font-medium text-sm">Two-factor authentication</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              {enabled ? "Enabled — you'll need an email code to sign in" : "Not enabled — add extra protection to your account"}
            </p>
          </div>
        </div>
        <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-bold uppercase border", enabled ? "bg-green-500/10 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border")}>
          {enabled ? "On" : "Off"}
        </span>
      </div>

      {!enabled && step === "idle" && (
        <Button size="sm" onClick={handleEnable} disabled={loading} className="w-full">
          {loading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <SmartphoneNfc className="w-3.5 h-3.5 mr-1.5" />}
          Enable 2FA via Email
        </Button>
      )}

      {step === "pending_otp" && (
        <form onSubmit={handleConfirm} className="space-y-3 pt-3 border-t border-border">
          <p className="text-xs text-muted-foreground">Enter the 6-digit code sent to <span className="text-foreground">{user?.email}</span></p>
          <Input
            type="text" inputMode="numeric" maxLength={6} value={otp}
            onChange={e => setOtp(e.target.value.replace(/\D/g, ""))}
            placeholder="000000" autoFocus className="text-center text-lg tracking-[0.5em] font-mono h-10"
          />
          <div className="flex gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => { setStep("idle"); setOtp(""); }} className="flex-1">Cancel</Button>
            <Button type="submit" size="sm" disabled={loading || otp.length < 6} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Check className="w-3.5 h-3.5 mr-1.5" />}
              Verify & Enable
            </Button>
          </div>
        </form>
      )}

      {enabled && !showDisable && (
        <button type="button" onClick={() => setShowDisable(true)} className="text-xs text-destructive/70 hover:text-destructive">
          Disable 2FA
        </button>
      )}

      {enabled && showDisable && (
        <form onSubmit={handleDisable} className="space-y-3 pt-3 border-t border-border">
          <p className="text-xs text-muted-foreground">Enter your password to confirm disabling 2FA</p>
          <Input type="password" value={disablePassword} onChange={e => setDisablePassword(e.target.value)} placeholder="Your password" className="h-9" />
          <div className="flex gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => { setShowDisable(false); setDisablePassword(""); }} className="flex-1">Cancel</Button>
            <Button type="submit" size="sm" variant="destructive" disabled={loading || !disablePassword} className="flex-1">
              {loading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : null}
              Disable 2FA
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

// ── Team Tab ────────────────────────────────────────────────────────

const INVITE_ROLES = [
  { value: "vendor",      label: "Vendor",                    color: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
  { value: "employee",    label: "Employee",                  color: "bg-sky-500/20 text-sky-400 border-sky-500/30" },
  { value: "third_party", label: "Third Party Management",   color: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30" },
];

const PERSONAL_EMAIL_DOMAINS = [
  "gmail.com","yahoo.com","hotmail.com","outlook.com","icloud.com",
  "live.com","aol.com","protonmail.com","ymail.com","mail.com",
  "googlemail.com","msn.com","me.com","mac.com",
];

function isBusinessEmail(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return !PERSONAL_EMAIL_DOMAINS.includes(domain);
}

const INV_STATUS_COLOR: Record<string, string> = {
  pending:  "bg-amber-500/10 text-amber-400 border-amber-500/25",
  accepted: "bg-green-500/10 text-green-400 border-green-500/25",
  rejected: "bg-red-500/10   text-red-400   border-red-500/25",
};

function TeamTab() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showInvite, setShowInvite] = useState(false);
  const [inviteForm, setInviteForm] = useState({ name: "", email: "", role: "employee" });
  const [sending, setSending] = useState(false);

  const { data: membersRaw = [], isLoading } = useQuery<any[]>({
    queryKey: ["team-members"],
    queryFn: () => apiFetch(`${BASE}/api/users`),
  });

  const { data: invitations = [], isLoading: invLoading } = useQuery<any[]>({
    queryKey: ["invitations"],
    queryFn: () => apiFetch(`${BASE}/api/invitations`),
  });

  // Fetch account managers actually assigned to this tenant (cross-tenant lookup via dedicated endpoint)
  const { data: accountManagers = [], isLoading: amLoading } = useQuery<any[]>({
    queryKey: ["my-account-managers"],
    queryFn: () => apiFetch(`${BASE}/api/account-manager/my-manager`),
  });

  // Build a set of emails that have an accepted invitation
  const acceptedEmails = new Set(
    (invitations as any[])
      .filter((inv: any) => inv.status === "accepted")
      .map((inv: any) => (inv.email ?? "").toLowerCase()),
  );

  // Team members = only users whose email appears in an accepted invitation
  // (excludes super_admin, admin, and account_manager — they are staff, not invitees)
  const STAFF_ROLES = new Set(["super_admin", "admin", "account_manager"]);
  const members = (membersRaw as any[]).filter((m: any) =>
    !STAFF_ROLES.has(m.role) && acceptedEmails.has((m.email ?? "").toLowerCase()),
  );

  const deactivateMutation = useMutation({
    mutationFn: (userId: number) =>
      apiFetch(`${BASE}/api/users/${userId}`, { method: "PATCH", body: JSON.stringify({ isActive: false }) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["team-members"] });
      toast({ title: "User deactivated" });
    },
  });

  const deleteInvMutation = useMutation({
    mutationFn: (id: number) => apiFetch(`${BASE}/api/invitations/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["invitations"] });
      toast({ title: "Invitation removed" });
    },
  });

  const canInvite = !!user;

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isBusinessEmail(inviteForm.email)) {
      toast({ title: "Business email required", description: "Please use a company email address, not a personal email provider.", variant: "destructive" });
      return;
    }
    setSending(true);
    try {
      await apiFetch(`${BASE}/api/invitations`, {
        method: "POST",
        body: JSON.stringify(inviteForm),
      });
      qc.invalidateQueries({ queryKey: ["invitations"] });
      setInviteForm({ name: "", email: "", role: "employee" });
      setShowInvite(false);
      toast({ title: "Invitation sent", description: `${inviteForm.email} has been invited.` });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to send invitation", variant: "destructive" });
    } finally {
      setSending(false);
    }
  };

  const roleColor: Record<string, string> = {
    client:      "bg-muted text-muted-foreground border-border",
    vendor:      "bg-amber-500/20 text-amber-400 border-amber-500/30",
    employee:    "bg-sky-500/20 text-sky-400 border-sky-500/30",
    third_party: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
  };

  return (
    <div className="space-y-5">
      {/* Invite panel */}
      {canInvite && (
        <div className="bg-card border border-border rounded-xl p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="font-medium text-sm">Invite External Member</p>
              <p className="text-xs text-muted-foreground mt-0.5">Send an invitation to a vendor, employee, or third party</p>
            </div>
            <Button size="sm" onClick={() => setShowInvite(v => !v)} variant={showInvite ? "outline" : "default"}>
              <UserPlus className="w-4 h-4 mr-1.5" />
              {showInvite ? "Cancel" : "Send Invite"}
            </Button>
          </div>

          {showInvite && (
            <form onSubmit={handleInvite} className="space-y-3 pt-4 mt-4 border-t border-border">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">Invitee Name</Label>
                  <Input
                    value={inviteForm.name}
                    onChange={e => setInviteForm(p => ({ ...p, name: e.target.value }))}
                    placeholder="Jane Smith"
                    required className="h-9"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">Business Email ID</Label>
                  <Input
                    type="email"
                    value={inviteForm.email}
                    onChange={e => setInviteForm(p => ({ ...p, email: e.target.value }))}
                    placeholder="jane@company.com"
                    required className="h-9"
                  />
                  {inviteForm.email && !isBusinessEmail(inviteForm.email) && (
                    <p className="text-[10px] text-destructive">Personal email providers are not allowed. Use a business email.</p>
                  )}
                </div>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Role</Label>
                <div className="flex gap-2">
                  {INVITE_ROLES.map(r => (
                    <button
                      key={r.value}
                      type="button"
                      onClick={() => setInviteForm(p => ({ ...p, role: r.value }))}
                      className={cn(
                        "flex-1 py-2 rounded-lg border text-xs font-medium transition-all",
                        inviteForm.role === r.value ? r.color : "border-border text-muted-foreground hover:border-border/80",
                      )}
                    >
                      {r.label}
                    </button>
                  ))}
                </div>
              </div>
              <div className="flex justify-end">
                <Button type="submit" size="sm" disabled={sending}>
                  {sending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Send className="w-3.5 h-3.5 mr-1.5" />}
                  Send Invitation
                </Button>
              </div>
            </form>
          )}
        </div>
      )}

      {/* Assigned Account Manager — always shown; empty state when none assigned */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-primary" />
          <p className="text-sm font-medium">Assigned Account Manager</p>
        </div>
        {amLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
          </div>
        ) : accountManagers.length === 0 ? (
          <div className="py-8 text-center text-sm text-muted-foreground">
            <ShieldCheck className="w-6 h-6 mx-auto mb-2 opacity-25" />
            <p className="font-medium">Account Manager Not Assigned</p>
            <p className="text-xs mt-1 text-muted-foreground/60">Contact your platform administrator to get an account manager assigned.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {accountManagers.map((m: any) => (
              <div key={m.id} className="flex items-center gap-3 px-5 py-3.5">
                <div className="w-9 h-9 rounded-full bg-primary/10 border border-primary/20 flex items-center justify-center text-sm font-semibold shrink-0 overflow-hidden">
                  {m.avatarUrl
                    ? <img src={`${BASE}${m.avatarUrl}`} alt="" className="w-full h-full object-cover" />
                    : `${m.firstName?.[0] ?? ""}${m.lastName?.[0] ?? ""}`
                  }
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{m.firstName} {m.lastName}</p>
                  <p className="text-xs text-muted-foreground truncate">{m.email}</p>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded font-semibold uppercase tracking-wider border bg-primary/10 text-primary border-primary/30 shrink-0">
                  Account Manager
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Team members — only invitation-accepted users */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Team Members</p>
            <p className="text-[11px] text-muted-foreground mt-0.5">Only members who accepted their invitation</p>
          </div>
          <span className="text-xs text-muted-foreground">{members.filter((m: any) => m.isActive).length} active</span>
        </div>
        {isLoading || invLoading ? (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : members.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted-foreground">
            <Users className="w-6 h-6 mx-auto mb-2 opacity-30" />
            <p>No accepted team members yet.</p>
            <p className="text-xs mt-1 text-muted-foreground/60">Members appear here after they accept their invitation.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {members.map((m: any) => (
              <div key={m.id} className={cn("flex items-center gap-3 px-5 py-3.5", !m.isActive && "opacity-50")}>
                <div className="w-9 h-9 rounded-full bg-accent flex items-center justify-center text-sm font-semibold shrink-0 overflow-hidden">
                  {m.avatarUrl
                    ? <img src={`${BASE}${m.avatarUrl}`} alt="" className="w-full h-full object-cover" />
                    : `${m.firstName?.[0] ?? ""}${m.lastName?.[0] ?? ""}`
                  }
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">
                    {m.firstName} {m.lastName}
                    {m.id === user?.id && <span className="text-xs text-muted-foreground ml-1">(you)</span>}
                  </p>
                  <p className="text-xs text-muted-foreground truncate">{m.email}</p>
                </div>
                <span className={cn("text-[10px] px-2 py-0.5 rounded font-semibold uppercase tracking-wider border shrink-0", roleColor[m.role] ?? roleColor.client)}>
                  {m.role?.replace(/_/g, " ")}
                </span>
                {!m.isActive && <span className="text-xs text-muted-foreground">(inactive)</span>}
                {m.isActive && m.id !== user?.id && canInvite && (
                  <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive shrink-0"
                    onClick={() => deactivateMutation.mutate(m.id)} title="Deactivate">
                    <X className="w-3.5 h-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Invitations tracking — all statuses */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Ticket className="w-4 h-4 text-muted-foreground" />
            <p className="text-sm font-medium">Invitations</p>
          </div>
          <span className="text-xs text-muted-foreground">
            {(invitations as any[]).filter((i: any) => i.status === "pending").length} pending
          </span>
        </div>
        {invLoading ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : (invitations as any[]).length === 0 ? (
          <div className="py-8 text-center text-sm text-muted-foreground">No invitations sent yet</div>
        ) : (
          <div className="divide-y divide-border">
            {(invitations as any[]).map((inv: any) => (
              <div key={inv.id} className="flex items-center gap-3 px-5 py-3.5">
                <div className="w-8 h-8 rounded-full bg-accent flex items-center justify-center text-xs font-semibold shrink-0">
                  {inv.name?.[0]?.toUpperCase() ?? "?"}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{inv.name}</p>
                  <p className="text-xs text-muted-foreground truncate">{inv.email}</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium", roleColor[inv.role] ?? roleColor.client)}>
                    {inv.role?.replace(/_/g, " ")}
                  </span>
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border font-medium flex items-center gap-1", INV_STATUS_COLOR[inv.status])}>
                    {inv.status === "pending" ? <Clock className="w-2.5 h-2.5" /> : inv.status === "accepted" ? <CheckCircle2 className="w-2.5 h-2.5" /> : <X className="w-2.5 h-2.5" />}
                    {inv.status}
                  </span>
                </div>
                {canInvite && (
                  <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive shrink-0"
                    onClick={() => deleteInvMutation.mutate(inv.id)} title="Remove invitation">
                    <Trash2 className="w-3.5 h-3.5" />
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
  const [checkoutLoading, setCheckoutLoading] = useState<string | null>(null);
  const [portalLoading, setPortalLoading] = useState(false);

  const { data: tenantData } = useQuery<any>({
    queryKey: ["tenant-billing"],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${user?.tenantId}`).catch(() => null),
    enabled: !!user?.tenantId,
  });

  // Real packages created by super admin
  const { data: packages = [], isLoading: pkgsLoading } = useQuery<any[]>({
    queryKey: ["packages"],
    queryFn: () => (apiFetch(`${BASE}/api/packages`) as Promise<any[]>).catch(() => []),
    staleTime: 60_000,
  });

  const { data: stripeData } = useQuery({
    queryKey: ["stripe-products"],
    queryFn: (): Promise<{ products: any[] }> =>
      (apiFetch(`${BASE}/api/stripe/products`) as Promise<{ products: any[] }>).catch(() => ({ products: [] })),
    staleTime: 5 * 60 * 1000,
  });

  const { data: subData } = useQuery({
    queryKey: ["stripe-subscription"],
    queryFn: (): Promise<{ subscription: any }> =>
      (apiFetch(`${BASE}/api/stripe/subscription`) as Promise<{ subscription: any }>).catch(() => ({ subscription: null })),
    enabled: !!user,
  });

  // Current plan string from tenant record (e.g. "starter", "professional")
  const currentPlan = (tenantData?.plan ?? "").toLowerCase();
  const hasStripeProducts = (stripeData?.products?.length ?? 0) > 0;
  const activeSub = subData?.subscription;

  async function handleCheckout(priceId: string, planKey: string) {
    setCheckoutLoading(planKey);
    try {
      const { url } = await apiFetch(`${BASE}/api/stripe/checkout`, {
        method: "POST",
        body: JSON.stringify({ priceId }),
      }) as any;
      if (url) window.location.href = url;
    } catch (err: any) {
      toast({ title: err?.message ?? "Checkout failed", variant: "destructive" });
    } finally {
      setCheckoutLoading(null);
    }
  }

  async function handlePortal() {
    setPortalLoading(true);
    try {
      const { url } = await apiFetch(`${BASE}/api/stripe/portal`, { method: "POST" }) as any;
      if (url) window.location.href = url;
    } catch (err: any) {
      toast({ title: err?.message ?? "Could not open billing portal", variant: "destructive" });
    } finally {
      setPortalLoading(false);
    }
  }

  // Build display plan list from real packages (DB), enriched with Stripe pricing if available.
  // Derive a slug from the package name to match against tenantData.plan.
  const displayPlans = packages
    .filter((pkg: any) => pkg.isActive)
    .map((pkg: any, idx: number) => {
      const slug = pkg.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
      const stripeProduct = hasStripeProducts
        ? stripeData!.products.find((p: any) =>
            p.metadata?.packageId === String(pkg.id) ||
            p.metadata?.slug === slug ||
            p.name.toLowerCase() === pkg.name.toLowerCase()
          )
        : null;
      const monthlyPrice = stripeProduct?.prices?.find((p: any) => p.recurring?.interval === "month");
      const priceDisplay = monthlyPrice
        ? `$${(monthlyPrice.unitAmount / 100).toFixed(0)}`
        : pkg.price > 0 ? `$${Number(pkg.price).toFixed(0)}` : "Free";
      return {
        id: pkg.id,
        slug,
        name: pkg.name,
        description: pkg.description ?? "",
        price: priceDisplay,
        priceRaw: Number(pkg.price),
        maxAssets: pkg.maxAssets,
        maxUsers: pkg.maxUsers,
        features: Array.isArray(pkg.features) ? pkg.features : [],
        highlight: idx === 1 && packages.length >= 2, // middle package is "most popular"
        isEnterprise: pkg.price === 0 && pkg.maxAssets === null,
        stripeProductId: stripeProduct?.id ?? null,
        stripePriceId: monthlyPrice?.id ?? null,
      };
    });

  return (
    <div className="space-y-5">
      {/* Current plan banner */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-1">Current Plan</p>
            <p className="text-2xl font-bold capitalize">{currentPlan}</p>
            <p className="text-sm text-muted-foreground mt-1">
              {tenantData?.name ?? "Your workspace"}
              {tenantData?.maxAssets && ` · ${tenantData.maxAssets} max assets`}
              {tenantData?.maxUsers && ` · ${tenantData.maxUsers} max users`}
            </p>
            {activeSub && (
              <p className="text-xs text-green-400 mt-1.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3 h-3" />
                Active subscription · renews {new Date((activeSub.current_period_end ?? 0) * 1000).toLocaleDateString()}
              </p>
            )}
          </div>
          <div className="flex flex-col gap-2 items-end shrink-0">
            <div className="bg-primary/10 border border-primary/20 rounded-lg px-3 py-1.5">
              <p className="text-xs font-semibold text-primary uppercase tracking-wide">Active</p>
            </div>
            {activeSub && (
              <Button
                size="sm" variant="outline"
                className="text-xs"
                onClick={handlePortal}
                disabled={portalLoading}
              >
                {portalLoading ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <ExternalLink className="w-3 h-3 mr-1.5" />}
                Manage Billing
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Plan tiers — from real packages created by super admin */}
      {pkgsLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="rounded-xl border border-border bg-card p-5 space-y-3 animate-pulse">
              <div className="h-4 w-24 bg-muted rounded" />
              <div className="h-8 w-16 bg-muted rounded" />
              <div className="space-y-2">{[...Array(4)].map((_, j) => <div key={j} className="h-3 bg-muted rounded" />)}</div>
            </div>
          ))}
        </div>
      ) : displayPlans.length === 0 ? (
        <div className="rounded-xl border border-dashed border-border p-8 text-center text-muted-foreground">
          <p className="text-sm">No plans available. Contact your administrator.</p>
        </div>
      ) : (
      <div className={`grid grid-cols-1 gap-4 ${displayPlans.length <= 2 ? "md:grid-cols-2" : "md:grid-cols-3"}`}>
        {displayPlans.map((plan, idx) => {
          const isCurrent = plan.slug === currentPlan ||
            plan.name.toLowerCase() === currentPlan ||
            plan.name.toLowerCase().replace(/\s+/g, "") === currentPlan.replace(/\s+/g, "");
          const loading = checkoutLoading === plan.slug;

          return (
            <div
              key={plan.id}
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
                  {plan.priceRaw > 0 && <span className="text-sm text-muted-foreground">/month</span>}
                </div>
                {(plan.maxAssets !== null || plan.maxUsers !== null) && (
                  <p className="text-xs text-muted-foreground mt-1">
                    {plan.maxAssets !== null ? `${plan.maxAssets} assets` : "Unlimited assets"}
                    {plan.maxUsers !== null ? ` · ${plan.maxUsers} users` : " · Unlimited users"}
                  </p>
                )}
                {plan.description && (
                  <p className="text-xs text-muted-foreground mt-1.5 leading-relaxed">{plan.description}</p>
                )}
              </div>

              {plan.features.length > 0 && (
                <ul className="space-y-1.5">
                  {plan.features.map((f: string) => (
                    <li key={f} className="flex items-center gap-2 text-xs text-muted-foreground">
                      <CheckCircle2 className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      {f}
                    </li>
                  ))}
                </ul>
              )}

              {isCurrent ? (
                <Button size="sm" variant="outline" disabled className="w-full">
                  <CheckCircle2 className="w-3.5 h-3.5 mr-1.5 text-green-400" /> Active Plan
                </Button>
              ) : plan.isEnterprise || plan.priceRaw === 0 ? (
                <a href="mailto:sales@sentinelware.io?subject=Plan Enquiry" className="block">
                  <Button size="sm" variant="outline" className="w-full">
                    <Mail className="w-3.5 h-3.5 mr-1.5" /> Contact Sales
                  </Button>
                </a>
              ) : plan.stripePriceId ? (
                <Button
                  size="sm"
                  variant={plan.highlight ? "default" : "outline"}
                  className="w-full"
                  disabled={loading}
                  onClick={() => handleCheckout(plan.stripePriceId!, plan.slug)}
                >
                  {loading
                    ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Processing…</>
                    : <><ArrowUpRight className="w-3.5 h-3.5 mr-1.5" />{idx > displayPlans.findIndex(p => p.slug === currentPlan || p.name.toLowerCase() === currentPlan) ? "Upgrade" : "Switch"}</>
                  }
                </Button>
              ) : (
                <a href="mailto:sales@sentinelware.io?subject=Plan Change Request" className="block">
                  <Button size="sm" variant={plan.highlight ? "default" : "outline"} className="w-full">
                    <ArrowUpRight className="w-3.5 h-3.5 mr-1.5" />
                    Contact Sales
                  </Button>
                </a>
              )}
            </div>
          );
        })}
      </div>
      )}

      {/* Billing portal shortcut if subscribed */}
      {activeSub && (
        <div className="rounded-xl border border-border bg-card px-5 py-4 flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium">Billing Portal</p>
            <p className="text-xs text-muted-foreground mt-0.5">Manage payment methods, invoices, and subscription details via Stripe.</p>
          </div>
          <Button size="sm" variant="outline" onClick={handlePortal} disabled={portalLoading}>
            {portalLoading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <ExternalLink className="w-3.5 h-3.5 mr-1.5" />}
            Open Portal
          </Button>
        </div>
      )}
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

// ── Sessions Tab ────────────────────────────────────────────────────

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function SessionsTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [revoking, setRevoking] = useState<number | null>(null);
  const [revokingAll, setRevokingAll] = useState(false);

  const { data: sessions = [], isLoading } = useQuery<any[]>({
    queryKey: ["auth-sessions"],
    queryFn: () => apiFetch(`${BASE}/api/auth/sessions`),
    refetchInterval: 30_000,
  });

  async function handleRevoke(sessionId: number) {
    setRevoking(sessionId);
    try {
      await apiFetch(`${BASE}/api/auth/sessions/${sessionId}`, { method: "DELETE" });
      qc.invalidateQueries({ queryKey: ["auth-sessions"] });
      toast({ title: "Session revoked" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to revoke session", variant: "destructive" });
    } finally {
      setRevoking(null);
    }
  }

  async function handleRevokeAll() {
    setRevokingAll(true);
    try {
      await apiFetch(`${BASE}/api/auth/sessions`, { method: "DELETE" });
      qc.invalidateQueries({ queryKey: ["auth-sessions"] });
      toast({ title: "All other sessions revoked" });
    } catch (err: any) {
      toast({ title: err?.message ?? "Failed to revoke sessions", variant: "destructive" });
    } finally {
      setRevokingAll(false);
    }
  }

  const mostRecent = sessions[0];

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="bg-card border border-border rounded-xl p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0">
              <Monitor className="w-4 h-4 text-primary" />
            </div>
            <div>
              <p className="font-medium text-sm">Active Sessions</p>
              <p className="text-xs text-muted-foreground mt-0.5">
                {isLoading ? "Loading…" : `${sessions.length} active session${sessions.length !== 1 ? "s" : ""}`}
              </p>
            </div>
          </div>
          {sessions.length > 1 && (
            <Button
              size="sm" variant="outline"
              className="text-destructive border-destructive/30 hover:bg-destructive/10 shrink-0"
              onClick={handleRevokeAll}
              disabled={revokingAll}
            >
              {revokingAll ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <LogOut className="w-3.5 h-3.5 mr-1.5" />}
              Revoke All Others
            </Button>
          )}
        </div>
      </div>

      {/* Session list */}
      <div className="bg-card border border-border rounded-xl overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
          </div>
        ) : sessions.length === 0 ? (
          <div className="py-10 text-center space-y-2">
            <Monitor className="w-8 h-8 text-muted-foreground/40 mx-auto" />
            <p className="text-sm text-muted-foreground">No active sessions found</p>
            <p className="text-xs text-muted-foreground/60">Sessions are recorded on login. Sign out and back in to see this tab populate.</p>
          </div>
        ) : (
          <div className="divide-y divide-border">
            {sessions.map((s: any, i: number) => {
              const isMostRecent = s.id === mostRecent?.id;
              return (
                <div key={s.id} className="flex items-center gap-4 px-5 py-4">
                  {/* Device icon */}
                  <div className={cn(
                    "w-9 h-9 rounded-lg border flex items-center justify-center shrink-0",
                    isMostRecent ? "bg-primary/10 border-primary/20" : "bg-muted border-border",
                  )}>
                    <Monitor className={cn("w-4 h-4", isMostRecent ? "text-primary" : "text-muted-foreground")} />
                  </div>

                  {/* Details */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-medium truncate">
                        {s.device ?? s.browser ?? "Unknown device"}
                      </p>
                      {isMostRecent && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 font-semibold shrink-0">
                          Most Recent
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                      {s.ipAddress && (
                        <span className="flex items-center gap-1 text-xs text-muted-foreground">
                          <Globe className="w-3 h-3" />
                          {s.ipAddress}
                        </span>
                      )}
                      {s.os && (
                        <span className="text-xs text-muted-foreground">{s.os}</span>
                      )}
                      <span className="text-xs text-muted-foreground">
                        <Clock className="w-3 h-3 inline mr-0.5" />
                        {formatRelativeTime(s.lastActiveAt)}
                      </span>
                      <span className="text-xs text-muted-foreground/60">
                        Created {new Date(s.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                    {s.userAgent && (
                      <p className="text-[10px] text-muted-foreground/50 mt-0.5 truncate max-w-xs">
                        {s.userAgent}
                      </p>
                    )}
                  </div>

                  {/* Revoke */}
                  <Button
                    size="sm" variant="ghost"
                    className="h-8 px-3 text-xs text-muted-foreground hover:text-destructive shrink-0"
                    onClick={() => handleRevoke(s.id)}
                    disabled={revoking === s.id}
                  >
                    {revoking === s.id
                      ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      : <><X className="w-3.5 h-3.5 mr-1" />Revoke</>
                    }
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Security tip */}
      <div className="rounded-xl border border-border bg-card/50 px-4 py-3 flex items-start gap-3">
        <Shield className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
        <p className="text-xs text-muted-foreground leading-relaxed">
          If you see a session you don't recognise, revoke it immediately and change your password.
          Sessions expire automatically after 30 days of inactivity.
        </p>
      </div>
    </div>
  );
}

// ── Notifications Tab ─────────────────────────────────────────────────────────

type ChannelKey = "email" | "slack" | "discord" | "telegram" | "webhook";
interface ChannelConfig { enabled: boolean; destination: string; ruleId?: number }
type ChannelMap = Record<ChannelKey, ChannelConfig>;

const CHANNEL_META_ACCT: Record<ChannelKey, {
  label: string; icon: React.ElementType; placeholder: string; hint: string; color: string;
}> = {
  email:    { label: "Email",    icon: Mail,          placeholder: "alerts@yourcompany.com",                         hint: "Alerts will be sent to this email address.",                                  color: "text-blue-400" },
  slack:    { label: "Slack",    icon: Hash,          placeholder: "https://hooks.slack.com/services/T.../B.../...", hint: "Create an Incoming Webhook in your Slack workspace settings.",                 color: "text-purple-400" },
  discord:  { label: "Discord",  icon: MessageSquare, placeholder: "https://discord.com/api/webhooks/123.../abc...", hint: "Go to Discord channel settings → Integrations → Webhooks.",                  color: "text-indigo-400" },
  telegram: { label: "Telegram", icon: Send,          placeholder: "BotToken:ChatID  (e.g. 123456:ABCdef:-100123456)", hint: "Format: BotToken:ChatID — get your token from @BotFather.",               color: "text-sky-400" },
  webhook:  { label: "Webhook",  icon: Webhook,       placeholder: "https://your-server.com/webhook",               hint: "Receives a JSON POST with the full alert payload on every event.",            color: "text-orange-400" },
};

const DEFAULT_CH: ChannelMap = {
  email: { enabled: false, destination: "" }, slack: { enabled: false, destination: "" },
  discord: { enabled: false, destination: "" }, telegram: { enabled: false, destination: "" },
  webhook: { enabled: false, destination: "" },
};

function NotificationsTab() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [channels, setChannels] = useState<ChannelMap>({ ...DEFAULT_CH });
  const [testingChannel, setTestingChannel] = useState<ChannelKey | null>(null);
  const [testResults, setTestResults] = useState<Partial<Record<ChannelKey, "ok" | "fail">>>({});

  const { isLoading } = useQuery<ChannelMap>({
    queryKey: ["notification-channels"],
    queryFn: () => apiFetch(`${BASE}/api/notification-channels`),
    onSuccess: (data: ChannelMap) => setChannels(data),
  } as any);

  const saveMutation = useMutation({
    mutationFn: (body: ChannelMap) =>
      apiFetch(`${BASE}/api/notification-channels`, { method: "PUT", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notification-channels"] });
      toast({ title: "Notification channels saved" });
    },
    onError: (e: any) => toast({ title: "Failed to save", description: e.message, variant: "destructive" }),
  });

  const toggle = (ch: ChannelKey) =>
    setChannels(p => ({ ...p, [ch]: { ...p[ch], enabled: !p[ch].enabled } }));
  const setDest = (ch: ChannelKey, v: string) =>
    setChannels(p => ({ ...p, [ch]: { ...p[ch], destination: v } }));

  const test = async (ch: ChannelKey) => {
    const dest = channels[ch].destination;
    if (!dest) { toast({ title: "Enter a destination first", variant: "destructive" }); return; }
    setTestingChannel(ch);
    setTestResults(p => ({ ...p, [ch]: undefined }));
    try {
      await apiFetch(`${BASE}/api/notification-channels/${ch}/test`, {
        method: "POST", body: JSON.stringify({ destination: dest }),
      });
      setTestResults(p => ({ ...p, [ch]: "ok" }));
      toast({ title: `${CHANNEL_META_ACCT[ch].label} test sent!`, description: "Check your destination." });
    } catch (e: any) {
      setTestResults(p => ({ ...p, [ch]: "fail" }));
      toast({ title: `Test failed`, description: e.message, variant: "destructive" });
    } finally {
      setTestingChannel(null);
    }
  };

  const active = Object.values(channels).filter(c => c.enabled).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <Bell className="w-4 h-4 text-muted-foreground" /> Notification Channels
            {active > 0 && <Badge variant="secondary" className="text-xs h-5 px-1.5">{active} active</Badge>}
          </h2>
          <p className="text-xs text-muted-foreground mt-0.5">
            Where your organization receives all security alerts — scans, findings, brand threats.
          </p>
        </div>
        <Button size="sm" onClick={() => saveMutation.mutate(channels)} disabled={saveMutation.isPending} className="gap-1.5">
          {saveMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
          Save All
        </Button>
      </div>

      {isLoading
        ? <div className="space-y-2">{[...Array(5)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>
        : (
          <div className="space-y-2">
            {(Object.keys(CHANNEL_META_ACCT) as ChannelKey[]).map(ch => {
              const m = CHANNEL_META_ACCT[ch];
              const Icon = m.icon;
              const cfg = channels[ch];
              return (
                <div key={ch} className={cn(
                  "border rounded-xl p-4 transition-colors",
                  cfg.enabled ? "border-primary/40 bg-primary/5" : "border-border bg-card",
                )}>
                  <div className="flex items-start gap-3">
                    <button onClick={() => toggle(ch)} className="mt-0.5 shrink-0">
                      {cfg.enabled
                        ? <ToggleRight className="w-5 h-5 text-primary" />
                        : <ToggleLeft className="w-5 h-5 text-muted-foreground" />}
                    </button>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <Icon className={cn("w-4 h-4", m.color)} />
                        <span className="text-sm font-medium">{m.label}</span>
                        {cfg.enabled && <Badge className="text-[10px] h-4 px-1 bg-green-500/20 text-green-400 border-green-500/30">Active</Badge>}
                        {testResults[ch] === "ok"   && <Badge className="text-[10px] h-4 px-1 bg-green-500/20 text-green-400 border-green-500/30">✓ Sent</Badge>}
                        {testResults[ch] === "fail" && <Badge className="text-[10px] h-4 px-1 bg-red-500/20 text-red-400 border-red-500/30">✗ Failed</Badge>}
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={cfg.destination} onChange={e => setDest(ch, e.target.value)}
                          placeholder={m.placeholder} className="h-7 text-xs font-mono flex-1"
                          type={ch === "email" ? "email" : "text"}
                        />
                        <Button
                          size="sm" variant="outline" className="h-7 text-xs gap-1 shrink-0"
                          disabled={!cfg.destination || testingChannel === ch}
                          onClick={() => test(ch)}
                        >
                          {testingChannel === ch
                            ? <Loader2 className="w-3 h-3 animate-spin" />
                            : <TestTube className="w-3 h-3" />}
                          Test
                        </Button>
                      </div>
                      <p className="text-[11px] text-muted-foreground mt-1.5">{m.hint}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

      <div className="flex items-start gap-2 p-3 bg-accent/30 rounded-lg">
        <AlertCircle className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <p className="text-[11px] text-muted-foreground">
          These channels fire for <strong className="text-foreground">all</strong> your org's alerts.
          For per-event rules (e.g. only on critical findings), use <strong className="text-foreground">Alerts → Alert Rules</strong>.
        </p>
      </div>
    </div>
  );
}
