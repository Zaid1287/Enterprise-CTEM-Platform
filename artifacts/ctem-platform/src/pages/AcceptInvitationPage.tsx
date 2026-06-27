import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/hooks/useAuth";
import { apiFetch } from "@/lib/apiFetch";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, Eye, EyeOff, CheckCircle2, AlertCircle, Loader2 } from "lucide-react";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

interface InvitationInfo {
  email: string;
  name: string;
  role: string;
  tenantName: string;
  assetNames: string[];
}

export default function AcceptInvitationPage() {
  const [, navigate] = useLocation();
  const { login } = useAuth();

  const token = new URLSearchParams(window.location.search).get("token") ?? "";

  const [info, setInfo] = useState<InvitationInfo | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!token) { setLoadError("No invitation token found in the URL."); setLoading(false); return; }
    apiFetch(`/api/auth/invitation-info?token=${encodeURIComponent(token)}`)
      .then((data: InvitationInfo) => {
        setInfo(data);
        // Pre-fill name parts from the invitation name if possible
        const parts = (data.name ?? "").trim().split(/\s+/);
        if (parts.length >= 2) {
          setFirstName(parts[0]);
          setLastName(parts.slice(1).join(" "));
        } else if (parts.length === 1) {
          setFirstName(parts[0]);
        }
      })
      .catch(err => setLoadError(err?.message ?? "Invalid or expired invitation link."))
      .finally(() => setLoading(false));
  }, [token]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitError(null);
    if (password !== confirmPassword) { setSubmitError("Passwords do not match"); return; }
    if (password.length < 8) { setSubmitError("Password must be at least 8 characters"); return; }
    setSubmitting(true);
    try {
      const data = await apiFetch("/api/auth/accept-invitation", {
        method: "POST",
        body: JSON.stringify({ token, firstName, lastName, password }),
      }) as { accessToken: string; refreshToken: string; user: any };
      login(data.accessToken, data.refreshToken, data.user);
      sessionStorage.setItem("ctem_token", data.accessToken);
      setDone(true);
      setTimeout(() => navigate("/assets"), 1200);
    } catch (err: any) {
      setSubmitError(err?.message ?? "Failed to create account. Please try again.");
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a]">
        <Loader2 className="w-6 h-6 animate-spin text-primary" />
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a] px-4">
        <div className="max-w-md w-full bg-[#111] border border-[#222] rounded-xl p-8 text-center">
          <AlertCircle className="w-10 h-10 text-destructive mx-auto mb-4" />
          <h1 className="text-lg font-semibold text-white mb-2">Invitation Error</h1>
          <p className="text-sm text-muted-foreground mb-6">{loadError}</p>
          <Button variant="outline" onClick={() => navigate("/login")}>Go to Login</Button>
        </div>
      </div>
    );
  }

  if (done) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a] px-4">
        <div className="max-w-md w-full bg-[#111] border border-[#222] rounded-xl p-8 text-center">
          <CheckCircle2 className="w-10 h-10 text-green-500 mx-auto mb-4" />
          <h1 className="text-lg font-semibold text-white mb-2">Account Created!</h1>
          <p className="text-sm text-muted-foreground">Taking you to your assets…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0a0a] px-4 py-10">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-4">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="Sentinelware"
              className="h-7 w-auto object-contain"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>
          <h1 className="text-2xl font-bold text-white">Accept Your Invitation</h1>
          <p className="text-sm text-muted-foreground mt-1">
            You've been invited to join <strong className="text-foreground">{info?.tenantName}</strong> as a{" "}
            <strong className="text-foreground">{info?.role?.replace(/_/g, " ")}</strong>.
          </p>
        </div>

        <div className="bg-[#111] border border-[#222] rounded-xl p-6">
          {/* Asset access preview */}
          {info?.assetNames && info.assetNames.length > 0 && (
            <div className="mb-5 p-3 rounded-lg bg-primary/5 border border-primary/20">
              <p className="text-xs font-medium text-primary mb-2 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" /> You will have access to:
              </p>
              <ul className="space-y-1">
                {info.assetNames.map(name => (
                  <li key={name} className="text-xs text-muted-foreground">• {name}</li>
                ))}
              </ul>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email — read-only */}
            <div className="space-y-1.5">
              <Label className="text-xs">Email Address</Label>
              <Input value={info?.email ?? ""} readOnly className="h-9 bg-muted/30 text-muted-foreground cursor-not-allowed" />
            </div>

            {/* Name */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">First Name</Label>
                <Input
                  value={firstName}
                  onChange={e => setFirstName(e.target.value)}
                  required placeholder="Jane" className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Last Name</Label>
                <Input
                  value={lastName}
                  onChange={e => setLastName(e.target.value)}
                  required placeholder="Smith" className="h-9"
                />
              </div>
            </div>

            {/* Password */}
            <div className="space-y-1.5">
              <Label className="text-xs">Password</Label>
              <div className="relative">
                <Input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required minLength={8}
                  placeholder="At least 8 characters"
                  className="h-9 pr-9"
                />
                <button type="button" onClick={() => setShowPassword(v => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Confirm Password</Label>
              <Input
                type={showPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                required minLength={8}
                placeholder="Re-enter your password"
                className="h-9"
              />
            </div>

            {submitError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-sm text-destructive">
                <AlertCircle className="w-4 h-4 shrink-0" /> {submitError}
              </div>
            )}

            <Button type="submit" className="w-full h-9 mt-1" disabled={submitting}>
              {submitting ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating account…</> : "Create Account & Sign In"}
            </Button>
          </form>
        </div>

        <p className="text-center text-xs text-muted-foreground mt-4">
          Already have an account?{" "}
          <button onClick={() => navigate("/login")} className="text-primary hover:underline">Sign in</button>
        </p>
      </div>
    </div>
  );
}
