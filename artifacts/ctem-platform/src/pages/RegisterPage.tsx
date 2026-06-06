import { useState } from "react";
import { useLocation } from "wouter";
import { useRegister } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { Eye, EyeOff, ArrowRight, Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const FREE_DOMAINS = [
  "gmail.com","yahoo.com","hotmail.com","outlook.com","live.com","icloud.com",
  "aol.com","protonmail.com","mail.com","yandex.com","zoho.com","gmx.com",
  "inbox.com","msn.com","me.com","mac.com","comcast.net","verizon.net",
];

function isBusinessEmail(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return !FREE_DOMAINS.includes(domain);
}

function calcStrength(p: string): number {
  let s = 0;
  if (p.length >= 8)  s++;
  if (p.length >= 12) s++;
  if (/[A-Z]/.test(p)) s++;
  if (/[0-9]/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return s;
}

export default function RegisterPage() {
  const [, navigate] = useLocation();
  const { login } = useAuth();
  const registerMutation = useRegister();
  const [form, setForm] = useState({
    email: "", password: "", firstName: "", lastName: "", tenantName: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [strength, setStrength] = useState(0);

  const emailValid = !form.email || isBusinessEmail(form.email);
  const emailError = form.email && !emailValid
    ? "Please use a business email address (not Gmail, Yahoo, etc.)"
    : null;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
    if (name === "password") setStrength(calcStrength(value));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isBusinessEmail(form.email)) {
      setError("Please use a business email address.");
      return;
    }
    setError("");
    try {
      const result = await registerMutation.mutateAsync({ data: form });
      login((result as any).accessToken, (result as any).refreshToken, (result as any).user as any);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.data?.error ?? "Registration failed. Please try again.");
    }
  };

  const strengthLabel = ["", "Weak", "Fair", "Good", "Strong", "Very Strong"][strength];
  const strengthColor = ["", "bg-red-500", "bg-orange-500", "bg-yellow-500", "bg-green-500", "bg-emerald-500"][strength];

  return (
    <div className="min-h-screen flex bg-background">
      {/* Left panel */}
      <div className="hidden lg:flex lg:w-1/2 xl:w-2/5 bg-card border-r border-border flex-col justify-between p-12 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent pointer-events-none" />
        <div className="absolute -bottom-32 -left-32 w-96 h-96 bg-primary/5 rounded-full blur-3xl pointer-events-none" />

        <div className="relative">
          <img
            src={`${BASE}/sentinelware-logo.png`}
            alt="Sentinelware"
            className="h-9 w-auto object-contain"
            onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
          />
        </div>

        <div className="relative space-y-6">
          <div className="space-y-3">
            <h2 className="text-3xl font-bold leading-tight tracking-tight">
              Start securing your<br />attack surface today
            </h2>
            <p className="text-muted-foreground text-base leading-relaxed">
              Set up your workspace in minutes and get full visibility into your organization's threat exposure.
            </p>
          </div>

          <div className="space-y-3">
            {[
              "Free 14-day trial, no credit card required",
              "Auto-discovery across all asset types",
              "Compliance frameworks: ISO 27001, SOC 2, PCI DSS",
              "Dedicated account manager on Enterprise",
            ].map(item => (
              <div key={item} className="flex items-center gap-2.5 text-sm text-muted-foreground">
                <CheckCircle2 className="w-4 h-4 text-primary shrink-0" />
                {item}
              </div>
            ))}
          </div>
        </div>

        <div className="relative border border-border/50 rounded-xl p-4 bg-background/30 backdrop-blur-sm">
          <p className="text-xs text-muted-foreground leading-relaxed italic">
            "We reduced our mean time to detect by 73% within the first month of using Sentinelware."
          </p>
          <p className="text-xs font-medium mt-2 text-foreground/70">— CISO, Fortune 500 Company</p>
        </div>
      </div>

      {/* Right panel */}
      <div className="flex-1 flex flex-col items-center justify-center p-8">
        <div className="w-full max-w-sm space-y-7">
          <div className="lg:hidden flex justify-center">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="Sentinelware"
              className="h-8 w-auto object-contain"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>

          <div>
            <h1 className="text-2xl font-bold tracking-tight">Create your workspace</h1>
            <p className="text-sm text-muted-foreground mt-1">Set up your CTEM environment in under a minute</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="firstName" className="text-sm font-medium">First name</Label>
                <Input id="firstName" name="firstName" value={form.firstName} onChange={handleChange} placeholder="John" required className="h-10" autoFocus />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lastName" className="text-sm font-medium">Last name</Label>
                <Input id="lastName" name="lastName" value={form.lastName} onChange={handleChange} placeholder="Smith" required className="h-10" />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="tenantName" className="text-sm font-medium">Organization name</Label>
              <Input id="tenantName" name="tenantName" value={form.tenantName} onChange={handleChange} placeholder="Acme Corp" required className="h-10" />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-sm font-medium">
                Work email
              </Label>
              <div className="relative">
                <Input
                  id="email"
                  name="email"
                  type="email"
                  value={form.email}
                  onChange={handleChange}
                  placeholder="you@company.com"
                  required
                  className={cn("h-10 pr-9", emailError && "border-red-500/50 focus-visible:ring-red-500/30")}
                />
                {form.email && (
                  <div className="absolute right-3 top-1/2 -translate-y-1/2">
                    {emailValid
                      ? <CheckCircle2 className="w-4 h-4 text-green-400" />
                      : <XCircle className="w-4 h-4 text-red-400" />
                    }
                  </div>
                )}
              </div>
              {emailError && <p className="text-xs text-red-400">{emailError}</p>}
              <p className="text-[11px] text-muted-foreground/70">Business emails only — no Gmail, Yahoo, etc.</p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-sm font-medium">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  value={form.password}
                  onChange={handleChange}
                  placeholder="Min. 8 characters"
                  required
                  minLength={8}
                  className="h-10 pr-10"
                />
                <button type="button" onClick={() => setShowPassword(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors">
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {form.password && (
                <div className="space-y-1">
                  <div className="flex gap-1">
                    {[1, 2, 3, 4, 5].map(i => (
                      <div key={i} className={cn("h-1 flex-1 rounded-full transition-all", i <= strength ? strengthColor : "bg-border")} />
                    ))}
                  </div>
                  <p className="text-[11px] text-muted-foreground">{strengthLabel}</p>
                </div>
              )}
            </div>

            {error && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                {error}
              </div>
            )}

            <Button
              type="submit"
              className="w-full h-10 mt-1"
              disabled={registerMutation.isPending || !!emailError}
            >
              {registerMutation.isPending
                ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Creating workspace…</>
                : <><span>Create workspace</span><ArrowRight className="w-4 h-4 ml-2" /></>
              }
            </Button>
          </form>

          <p className="text-center text-sm text-muted-foreground">
            Already have an account?{" "}
            <button onClick={() => navigate("/login")} className="text-primary hover:underline font-medium">Sign in</button>
          </p>
        </div>
      </div>
    </div>
  );
}
