import { useState } from "react";
import { useLocation } from "wouter";
import { ArrowLeft, ArrowRight, Loader2, CheckCircle2, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

type Step = "email" | "otp" | "done";

export default function ForgotPasswordPage() {
  const [, navigate] = useLocation();
  const [step, setStep] = useState<Step>("email");
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSendOtp = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) throw data;
      setStep("otp");
    } catch (err: any) {
      setError(err?.error ?? "Failed to send reset email. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }
    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp, newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw data;
      setStep("done");
    } catch (err: any) {
      setError(err?.error ?? "Failed to reset password. Check the code and try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background p-8">
      <div className="w-full max-w-sm space-y-7">
        {/* Logo */}
        <div className="flex justify-center">
          <img
            src={`${BASE}/sentinelware-logo.png`}
            alt="Sentinelware"
            className="h-8 w-auto object-contain"
            onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
          />
        </div>

        {step === "done" ? (
          <div className="text-center space-y-4">
            <div className="flex justify-center">
              <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center">
                <CheckCircle2 className="w-8 h-8 text-green-400" />
              </div>
            </div>
            <div>
              <h1 className="text-xl font-bold">Password reset!</h1>
              <p className="text-sm text-muted-foreground mt-1">Your password has been successfully updated.</p>
            </div>
            <Button className="w-full h-10" onClick={() => navigate("/login")}>
              Sign in with new password
            </Button>
          </div>
        ) : step === "email" ? (
          <>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Forgot password</h1>
              <p className="text-sm text-muted-foreground mt-1">
                Enter your work email and we'll send you a reset code
              </p>
            </div>

            <form onSubmit={handleSendOtp} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="email" className="text-sm font-medium">Work email</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  required
                  autoFocus
                  className="h-10"
                />
              </div>

              {error && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                  {error}
                </div>
              )}

              <Button type="submit" className="w-full h-10" disabled={loading}>
                {loading
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Sending…</>
                  : <><Mail className="w-4 h-4 mr-2" /> Send reset code</>
                }
              </Button>
            </form>
          </>
        ) : (
          <>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Check your email</h1>
              <p className="text-sm text-muted-foreground mt-1">
                We sent a 6-digit code to <span className="text-foreground font-medium">{email}</span>
              </p>
            </div>

            <form onSubmit={handleResetPassword} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="otp" className="text-sm font-medium">Reset code</Label>
                <Input
                  id="otp"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={otp}
                  onChange={e => setOtp(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  required
                  autoFocus
                  className="h-10 text-center text-lg tracking-[0.5em] font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="newPassword" className="text-sm font-medium">New password</Label>
                <Input
                  id="newPassword"
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  placeholder="Min. 8 characters"
                  required
                  minLength={8}
                  className="h-10"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="confirmPassword" className="text-sm font-medium">Confirm password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  placeholder="Repeat new password"
                  required
                  className="h-10"
                />
                {confirmPassword && confirmPassword !== newPassword && (
                  <p className="text-xs text-red-400">Passwords do not match</p>
                )}
              </div>

              {error && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                  {error}
                </div>
              )}

              <Button type="submit" className="w-full h-10" disabled={loading || otp.length < 6 || !newPassword || newPassword !== confirmPassword}>
                {loading
                  ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Resetting…</>
                  : <><ArrowRight className="w-4 h-4 mr-2" /> Reset password</>
                }
              </Button>
            </form>

            <button
              onClick={() => { setStep("email"); setError(""); setOtp(""); }}
              className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground mx-auto"
            >
              <ArrowLeft className="w-4 h-4" /> Back
            </button>
          </>
        )}

        {step !== "done" && (
          <p className="text-center text-sm text-muted-foreground">
            Remember your password?{" "}
            <button onClick={() => navigate("/login")} className="text-primary hover:underline font-medium">Sign in</button>
          </p>
        )}
      </div>
    </div>
  );
}
