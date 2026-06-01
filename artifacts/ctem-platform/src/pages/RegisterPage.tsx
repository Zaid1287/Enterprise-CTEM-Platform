import { useState } from "react";
import { useLocation } from "wouter";
import { useRegister } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function RegisterPage() {
  const [, navigate] = useLocation();
  const { login } = useAuth();
  const registerMutation = useRegister();
  const [form, setForm] = useState({
    email: "", password: "", firstName: "", lastName: "", tenantName: "",
  });
  const [error, setError] = useState("");

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm(prev => ({ ...prev, [e.target.name]: e.target.value }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const result = await registerMutation.mutateAsync({ data: form });
      login(result.accessToken, result.refreshToken, result.user as any);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.data?.error ?? "Registration failed. Please try again.");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-primary/15 border border-primary/30">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold tracking-tight">Create Workspace</h1>
            <p className="text-sm text-muted-foreground mt-1">Set up your CTEM environment</p>
          </div>
        </div>

        <div className="bg-card border border-border rounded-xl p-6 shadow-lg shadow-black/20">
          <form onSubmit={handleSubmit} className="space-y-3.5">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="firstName" className="text-xs text-muted-foreground">First name</Label>
                <Input id="firstName" name="firstName" value={form.firstName} onChange={handleChange} placeholder="John" required className="h-9 text-sm" />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="lastName" className="text-xs text-muted-foreground">Last name</Label>
                <Input id="lastName" name="lastName" value={form.lastName} onChange={handleChange} placeholder="Smith" required className="h-9 text-sm" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="tenantName" className="text-xs text-muted-foreground">Organization name</Label>
              <Input id="tenantName" name="tenantName" value={form.tenantName} onChange={handleChange} placeholder="Acme Corp" required className="h-9 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-xs text-muted-foreground">Work email</Label>
              <Input id="email" name="email" type="email" value={form.email} onChange={handleChange} placeholder="you@company.com" required className="h-9 text-sm" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-xs text-muted-foreground">Password</Label>
              <Input id="password" name="password" type="password" value={form.password} onChange={handleChange} placeholder="Min. 8 characters" required minLength={8} className="h-9 text-sm" />
            </div>

            {error && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">{error}</div>
            )}

            <Button type="submit" className="w-full h-9 text-sm mt-1" disabled={registerMutation.isPending}>
              {registerMutation.isPending ? "Creating workspace..." : "Create workspace"}
            </Button>
          </form>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          Already have an account?{" "}
          <button onClick={() => navigate("/login")} className="text-primary hover:underline font-medium">Sign in</button>
        </p>
      </div>
    </div>
  );
}
