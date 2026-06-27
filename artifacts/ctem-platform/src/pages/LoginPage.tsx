import { useState } from "react";
import { useLocation } from "wouter";
import { useLogin } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { Eye, EyeOff, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function LoginPage() {
  const [, navigate] = useLocation();
  const { login } = useAuth();
  const loginMutation = useLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  // 2FA state
  const [twoFaRequired, setTwoFaRequired] = useState(false);
  const [twoFaCode, setTwoFaCode] = useState("");
  const [twoFaLoading, setTwoFaLoading] = useState(false);
  const [pendingTokens, setPendingTokens] = useState<{ accessToken: string; refreshToken: string; user: any } | null>(null);

  // Force password reset state
  const [resetRequired, setResetRequired] = useState(false);
  const [resetUserId, setResetUserId] = useState<number | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [resetLoading, setResetLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const result = await loginMutation.mutateAsync({ data: { email, password } });
      const r = result as any;
      if (r.requiresPasswordReset) {
        setResetUserId(r.userId);
        setResetRequired(true);
      } else if (r.twoFactorRequired) {
        setPendingTokens(r);
        setTwoFaRequired(true);
      } else {
        login(r.accessToken, r.refreshToken, r.user as any);
        navigate("/dashboard");
      }
    } catch (err: any) {
      setError(err?.data?.error ?? "Invalid email or password");
    }
  };

  const handlePasswordReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (newPassword !== confirmPassword) { setError("Passwords do not match"); return; }
    if (newPassword.length < 8) { setError("Password must be at least 8 characters"); return; }
    setResetLoading(true);
    try {
      const res = await fetch(`${BASE}/api/auth/set-initial-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId: resetUserId, currentPassword: password, newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw data;
      login(data.accessToken, data.refreshToken, data.user);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.error ?? "Failed to set new password");
    } finally {
      setResetLoading(false);
    }
  };

  const handleTwoFa = async (e: React.FormEvent) => {
    e.preventDefault();
    setTwoFaLoading(true);
    setError("");
    try {
      const res = await fetch(`${BASE}/api/auth/2fa/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${pendingTokens?.accessToken}` },
        body: JSON.stringify({ otp: twoFaCode }),
      });
      const data = await res.json();
      if (!res.ok) throw data;
      login(pendingTokens!.accessToken, pendingTokens!.refreshToken, pendingTokens!.user);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.error ?? "Invalid verification code");
    } finally {
      setTwoFaLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex bg-background">
      {/* Left panel — branding */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-2/5 bg-card border-r border-border flex-col justify-between p-12 relative overflow-hidden">
        {/* Background decoration */}
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />
        <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -top-20 -right-20 w-72 h-72 bg-primary/3 rounded-full blur-3xl pointer-events-none" />

        {/* Logo */}
        <div className="relative">
          <img
            src={`${BASE}/sentinelware-logo.png`}
            alt="Sentinelware"
            className="h-9 w-auto object-contain"
            onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
          />
        </div>

        {/* Middle content */}
        <div className="relative space-y-6">
          <div className="space-y-3">
            <h2 className="text-3xl font-bold leading-tight tracking-tight">
              Continuous Threat<br />Exposure Management
            </h2>
            <p className="text-muted-foreground text-base leading-relaxed">
              Monitor, detect, and respond to your organization's security exposure in real time.
            </p>
          </div>

          <div className="space-y-3">
            {[
              "15 integrated security modules",
              "Real-time asset & vulnerability tracking",
              "AI-powered risk scoring & copilot",
              "Enterprise-grade multi-tenant architecture",
            ].map(item => (
              <div key={item} className="flex items-center gap-2.5 text-sm text-muted-foreground">
                <div className="w-1.5 h-1.5 rounded-full bg-primary shrink-0" />
                {item}
              </div>
            ))}
          </div>
        </div>

        {/* Bottom quote */}
        <div className="relative border border-border/50 rounded-xl p-4 bg-background/30 backdrop-blur-sm">
          <p className="text-xs text-muted-foreground leading-relaxed italic">
            "Sentinelware has transformed how we approach threat exposure — from reactive to fully proactive."
          </p>
          <p className="text-xs font-medium mt-2 text-foreground/70">— Enterprise Security Team</p>
        </div>
      </div>

      {/* Right panel — form */}
      <div className="flex-1 flex flex-col items-center justify-center p-8">
        <div className="w-full max-w-sm space-y-7">
          {/* Mobile logo */}
          <div className="lg:hidden flex justify-center">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="Sentinelware"
              className="h-8 w-auto object-contain"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>

          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              {resetRequired ? "Set new password" : twoFaRequired ? "Two-factor authentication" : "Sign in"}
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              {resetRequired
                ? "Your account requires a new password before you can continue."
                : twoFaRequired
                ? "Enter the 6-digit code sent to your email"
                : "Enter your work email and password to continue"}
            </p>
          </div>

          {resetRequired ? (
            <form onSubmit={handlePasswordReset} className="space-y-4">
              <div className="space-y-1.5">
                <Label className="text-sm font-medium">New password</Label>
                <Input
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  required
                  autoFocus
                  className="h-10"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-sm font-medium">Confirm new password</Label>
                <Input
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder="Repeat your password"
                  required
                  className="h-10"
                />
              </div>
              {error && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">{error}</div>
              )}
              <Button type="submit" className="w-full h-10" disabled={resetLoading}>
                {resetLoading ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" />Setting password…</> : "Set new password & sign in"}
              </Button>
            </form>
          ) : !twoFaRequired ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-sm font-medium">Work email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  required
                  autoFocus
                  className="h-10"
                />
              </div>
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label htmlFor="password" className="text-sm font-medium">Password</Label>
                  <button
                    type="button"
                    onClick={() => navigate("/forgot-password")}
                    className="text-xs text-primary hover:underline"
                  >
                    Forgot password?
                  </button>
                </div>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    required
                    className="h-10 pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {error && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                  {error}
                </div>
              )}

              <Button type="submit" className="w-full h-10" disabled={loginMutation.isPending}>
                {loginMutation.isPending
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Signing in…</>
                  : <><span>Sign in</span><ArrowRight className="w-4 h-4 ml-2" /></>
                }
              </Button>
            </form>
          ) : (
            <form onSubmit={handleTwoFa} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="otp" className="text-sm font-medium">Verification code</Label>
                <Input
                  id="otp"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={twoFaCode}
                  onChange={e => setTwoFaCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  required
                  autoFocus
                  className="h-10 text-center text-lg tracking-[0.5em] font-mono"
                />
              </div>

              {error && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                  {error}
                </div>
              )}

              <Button type="submit" className="w-full h-10" disabled={twoFaLoading || twoFaCode.length < 6}>
                {twoFaLoading
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Verifying…</>
                  : "Verify & Sign in"
                }
              </Button>
              <button
                type="button"
                onClick={() => { setTwoFaRequired(false); setPendingTokens(null); setTwoFaCode(""); setError(""); }}
                className="w-full text-xs text-muted-foreground hover:text-foreground text-center"
              >
                ← Back to login
              </button>
            </form>
          )}

          <p className="text-center text-sm text-muted-foreground">
            No account?{" "}
            <button onClick={() => navigate("/register")} className="text-primary hover:underline font-medium">
              Create workspace
            </button>
          </p>
        </div>
      </div>
    </div>
  );
}
