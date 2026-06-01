import { useState } from "react";
import { useLocation } from "wouter";
import { useLogin } from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { Shield, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

export default function LoginPage() {
  const [, navigate] = useLocation();
  const { login } = useAuth();
  const loginMutation = useLogin();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    try {
      const result = await loginMutation.mutateAsync({ data: { email, password } });
      login(result.accessToken, result.refreshToken, result.user as any);
      navigate("/dashboard");
    } catch (err: any) {
      setError(err?.data?.error ?? "Invalid email or password");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-sm space-y-6">
        {/* Logo */}
        <div className="flex flex-col items-center gap-3">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-primary/15 border border-primary/30">
            <Shield className="w-6 h-6 text-primary" />
          </div>
          <div className="text-center">
            <h1 className="text-xl font-semibold tracking-tight">CTEM Platform</h1>
            <p className="text-sm text-muted-foreground mt-1">Continuous Threat Exposure Management</p>
          </div>
        </div>

        {/* Form */}
        <div className="bg-card border border-border rounded-xl p-6 shadow-lg shadow-black/20">
          <h2 className="text-sm font-medium text-foreground mb-4">Sign in to your workspace</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-xs text-muted-foreground">Email address</Label>
              <Input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                required
                autoFocus
                className="h-9 text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-xs text-muted-foreground">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  className="h-9 text-sm pr-9"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            {error && (
              <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
                {error}
              </div>
            )}

            <Button
              type="submit"
              className="w-full h-9 text-sm"
              disabled={loginMutation.isPending}
            >
              {loginMutation.isPending ? "Signing in..." : "Sign in"}
            </Button>
          </form>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          No account?{" "}
          <button
            onClick={() => navigate("/register")}
            className="text-primary hover:underline font-medium"
          >
            Create workspace
          </button>
        </p>
      </div>
    </div>
  );
}
