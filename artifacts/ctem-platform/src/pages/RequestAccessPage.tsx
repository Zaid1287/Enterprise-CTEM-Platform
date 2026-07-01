import { useState } from "react";
import { useLocation } from "wouter";
import { CheckCircle2, XCircle, ArrowRight, Loader2, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

const FREE_DOMAINS = [
  "gmail.com","yahoo.com","hotmail.com","outlook.com","live.com","icloud.com",
  "aol.com","protonmail.com","mail.com","yandex.com","zoho.com","gmx.com",
  "inbox.com","msn.com","me.com","mac.com","comcast.net","verizon.net",
  "mailinator.com","guerrillamail.com","tempmail.com","throwam.com","sharklasers.com",
  "dispostable.com","yopmail.com","trashmail.com","fakeinbox.com","maildrop.cc",
];

function isBusinessEmail(email: string): boolean {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return false;
  return !FREE_DOMAINS.includes(domain);
}

const TEAM_SIZES = ["1–10", "11–50", "51–200", "201–500", "500+"];

export default function RequestAccessPage() {
  const [, navigate] = useLocation();
  const [form, setForm] = useState({
    fullName: "", companyName: "", email: "",
    jobTitle: "", teamSize: "", phone: "", message: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const emailValid = !form.email || isBusinessEmail(form.email);
  const emailError = form.email && !emailValid
    ? "Please use a business email address (not Gmail, Yahoo, etc.)"
    : null;

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isBusinessEmail(form.email)) {
      setError("Please use a business email address.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${BASE}/api/auth/request-access`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? "Submission failed");
      setSubmitted(true);
    } catch (err: any) {
      setError(err.message ?? "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  if (submitted) {
    return (
      <div className="min-h-screen flex bg-background items-center justify-center p-8">
        <div className="w-full max-w-md text-center space-y-5">
          <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center mx-auto">
            <CheckCircle2 className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Request submitted!</h1>
            <p className="text-muted-foreground text-sm mt-2 leading-relaxed">
              Thank you, <strong>{form.fullName}</strong>. Our team will review your request and reach out to <strong>{form.email}</strong> within 1–2 business days.
            </p>
          </div>
          <Button variant="outline" onClick={() => navigate("/login")} className="w-full">
            Back to sign in
          </Button>
        </div>
      </div>
    );
  }

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
              Enterprise-grade CTEM<br />for your organization
            </h2>
            <p className="text-muted-foreground text-base leading-relaxed">
              Get full visibility into your attack surface. Our team will review your request and set up your workspace.
            </p>
          </div>
          <div className="space-y-3">
            {[
              "Continuous threat exposure management",
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
        <div className="w-full max-w-md space-y-6">
          <div className="lg:hidden flex justify-center">
            <img
              src={`${BASE}/sentinelware-logo.png`}
              alt="Sentinelware"
              className="h-8 w-auto object-contain"
              onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
            />
          </div>

          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldCheck className="w-4 h-4 text-primary" />
              <span className="text-xs font-medium text-primary uppercase tracking-wider">Access by application only</span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight">Request access</h1>
            <p className="text-sm text-muted-foreground mt-1">Tell us about your organization. We'll get back to you within 1–2 business days.</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5 col-span-2">
                <Label htmlFor="fullName" className="text-sm font-medium">Full name *</Label>
                <Input id="fullName" name="fullName" value={form.fullName} onChange={handleChange} placeholder="Jane Smith" required className="h-10" autoFocus />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="companyName" className="text-sm font-medium">Company name *</Label>
              <Input id="companyName" name="companyName" value={form.companyName} onChange={handleChange} placeholder="Acme Corp" required className="h-10" />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-sm font-medium">Work email *</Label>
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

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="jobTitle" className="text-sm font-medium">Job title</Label>
                <Input id="jobTitle" name="jobTitle" value={form.jobTitle} onChange={handleChange} placeholder="CISO" className="h-10" />
              </div>
              <div className="space-y-1.5">
                <Label className="text-sm font-medium">Team size</Label>
                <Select value={form.teamSize} onValueChange={v => setForm(p => ({ ...p, teamSize: v }))}>
                  <SelectTrigger className="h-10">
                    <SelectValue placeholder="Select…" />
                  </SelectTrigger>
                  <SelectContent>
                    {TEAM_SIZES.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="phone" className="text-sm font-medium">Phone number</Label>
              <Input id="phone" name="phone" type="tel" value={form.phone} onChange={handleChange} placeholder="+1 555 000 0000" className="h-10" />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="message" className="text-sm font-medium">What are you looking to solve?</Label>
              <Textarea
                id="message"
                name="message"
                value={form.message}
                onChange={handleChange}
                placeholder="Tell us about your security challenges or use case…"
                rows={3}
                className="resize-none text-sm"
              />
            </div>

            {error && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2.5">
                {error}
              </div>
            )}

            <Button
              type="submit"
              className="w-full h-10 mt-1"
              disabled={loading || !!emailError || !form.fullName || !form.companyName || !form.email}
            >
              {loading
                ? <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Submitting…</>
                : <><span>Submit request</span><ArrowRight className="w-4 h-4 ml-2" /></>
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
