import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Save, Loader2, RefreshCw, Info, ShieldOff } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Tooltip, TooltipContent, TooltipTrigger,
} from "@/components/ui/tooltip";
import { useToast } from "@/hooks/use-toast";
import { getToken } from "@/lib/auth";

/* ─── API ────────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs(), ...opts });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error((e as any).error ?? "Failed"); }
  return r.json();
}

/* ─── Config knob meta ────────────────────────────────────────────────── */
interface KnobDef {
  key: string; label: string; description: string;
  type: "boolean" | "integer" | "select";
  options?: string[];
  min?: number; max?: number;
}

const KNOBS: KnobDef[] = [
  /* ── Master switches ─────────────────────────────────────────────────── */
  { key: "enabled",                    type: "boolean", label: "Enable Orchestration Engine",    description: "Master switch. When off, orchestratedFetch falls back to direct fetch." },
  { key: "use_proxies",                type: "boolean", label: "Use Proxy Pool",                 description: "Route outbound scan requests through the configured proxy/IP pool." },
  { key: "rotate_fingerprints",        type: "boolean", label: "Rotate Browser Fingerprints",    description: "Cycle through active fingerprint profiles on each request." },
  { key: "dns_rotation_enabled",       type: "boolean", label: "Rotate DNS Resolvers",           description: "Use the DNS resolver pool instead of the system default resolver." },
  { key: "cookie_persistence_enabled", type: "boolean", label: "Cookie Persistence",             description: "Maintain cookies across requests to the same host (session simulation)." },
  { key: "circuit_breaker_enabled",    type: "boolean", label: "Enable Circuit Breakers",        description: "Open the circuit for a host after repeated rate-limit or block responses." },
  { key: "log_all_requests",           type: "boolean", label: "Log All Requests to Telemetry",  description: "Write every HTTP request to the telemetry table. Disable to reduce DB writes." },
  /* ── Rotation strategies ─────────────────────────────────────────────── */
  { key: "proxy_rotation_strategy",
    type: "select",
    label: "Proxy Rotation Strategy",
    description: "Algorithm used to pick the next proxy from the pool.",
    options: ["round-robin", "weighted-health", "least-429", "random"] },
  { key: "resolver_rotation_strategy",
    type: "select",
    label: "DNS Resolver Rotation",
    description: "Algorithm used to select a DNS resolver from the pool.",
    options: ["round-robin", "random", "sticky"] },
  { key: "fingerprint_rotation_strategy",
    type: "select",
    label: "Fingerprint Rotation Strategy",
    description: "How browser fingerprint profiles are cycled across requests.",
    options: ["random", "round-robin", "per-target"] },
  /* ── Scan delay & throttle ───────────────────────────────────────────── */
  { key: "scan_delay_intensity",
    type: "select",
    label: "Scan Delay Intensity",
    description: "Controls inter-request delay to reduce detection probability.",
    options: ["low", "medium", "high", "adaptive"] },
  /* ── Proxy management ────────────────────────────────────────────────── */
  { key: "max_requests_per_proxy",     type: "integer", label: "Max Requests per Proxy",          description: "Maximum requests routed through one proxy before rotating to the next.", min: 1, max: 10000 },
  { key: "proxy_cooldown_minutes",     type: "integer", label: "Proxy Cooldown (min)",            description: "Minutes a proxy stays in cooldown after exceeding its error threshold.", min: 1, max: 1440 },
  { key: "proxy_health_threshold",     type: "integer", label: "Proxy Health Score Threshold",    description: "Minimum health score (0-100) required for a proxy to remain active.", min: 0, max: 100 },
  /* ── Retry & backoff ─────────────────────────────────────────────────── */
  { key: "max_retries",                type: "integer", label: "Max Retries per Request",         description: "Number of retry attempts before giving up on a request.", min: 0, max: 10 },
  { key: "backoff_base_ms",            type: "integer", label: "Retry Base Backoff (ms)",         description: "Base delay for exponential backoff on retries.", min: 100, max: 30000 },
  { key: "request_timeout_ms",         type: "integer", label: "Request Timeout (ms)",            description: "Hard timeout for each HTTP attempt.", min: 1000, max: 120000 },
  /* ── Concurrency & circuit breakers ─────────────────────────────────── */
  { key: "max_concurrent_per_host",    type: "integer", label: "Max Concurrent Requests / Host",  description: "Concurrency cap per target hostname.", min: 1, max: 50 },
  { key: "circuit_breaker_threshold",  type: "integer", label: "Circuit Breaker Threshold",       description: "Consecutive failures before a circuit opens.", min: 1, max: 20 },
  { key: "circuit_breaker_cooldown_ms",type: "integer", label: "Circuit Breaker Cooldown (ms)",   description: "How long a circuit stays open before switching to half-open.", min: 10000, max: 3600000 },
  /* ── Rate limiting ───────────────────────────────────────────────────── */
  { key: "rate_limit_window_ms",       type: "integer", label: "Rate Limit Window (ms)",          description: "Token bucket refill window for adaptive rate limiting.", min: 100, max: 60000 },
  { key: "rate_limit_max_tokens",      type: "integer", label: "Rate Limit Max Tokens",           description: "Max requests per window before throttling.", min: 1, max: 1000 },
];

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function OrchestratorConfigPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [values, setValues] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);

  const isSuperAdmin = user?.role === "super_admin";

  if (user && !isSuperAdmin) {
    return (
      <div className="p-12 flex flex-col items-center gap-4 text-center max-w-md mx-auto mt-16">
        <div className="p-4 rounded-full bg-destructive/10">
          <ShieldOff className="w-10 h-10 text-destructive" />
        </div>
        <h1 className="text-2xl font-bold tracking-tight">Access Restricted</h1>
        <p className="text-muted-foreground text-sm">
          Orchestrator configuration is limited to super administrators.
          Contact your platform admin if you need to make changes.
        </p>
      </div>
    );
  }

  const { data, isLoading } = useQuery<{ config: Record<string, string> }>({
    queryKey: ["orchestrator-config"],
    queryFn: () => api("/api/orchestrator-config"),
    enabled: isSuperAdmin,
  });

  useEffect(() => {
    if (data?.config) {
      setValues(data.config);
      setDirty(false);
    }
  }, [data]);

  const saveMut = useMutation({
    mutationFn: (updates: Record<string, string>) =>
      api("/api/orchestrator-config", { method: "PATCH", body: JSON.stringify(updates) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["orchestrator-config"] });
      toast({ title: "Configuration saved", description: "Orchestrator will pick up changes within 60 seconds." });
      setDirty(false);
    },
    onError: (e: Error) => toast({ title: "Save failed", description: e.message, variant: "destructive" }),
  });

  const set = (key: string, val: string) => {
    setValues(v => ({ ...v, [key]: val }));
    setDirty(true);
  };

  const renderKnob = (k: KnobDef) => {
    const val = values[k.key] ?? "";
    if (k.type === "boolean") {
      const checked = val !== "false";
      return (
        <Switch
          checked={checked}
          onCheckedChange={v => set(k.key, v ? "true" : "false")}
        />
      );
    }
    if (k.type === "select") {
      return (
        <Select value={val} onValueChange={v => set(k.key, v)}>
          <SelectTrigger className="w-44"><SelectValue placeholder="Select…" /></SelectTrigger>
          <SelectContent>
            {k.options!.map(o => <SelectItem key={o} value={o}>{o}</SelectItem>)}
          </SelectContent>
        </Select>
      );
    }
    return (
      <Input
        type="number"
        className="w-36 h-8 text-sm"
        value={val}
        min={k.min}
        max={k.max}
        onChange={e => set(k.key, e.target.value)}
      />
    );
  };

  const boolKnobs = KNOBS.filter(k => k.type === "boolean");
  const numKnobs  = KNOBS.filter(k => k.type !== "boolean");

  return (
    <div className="p-6 space-y-6 max-w-3xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Orchestrator Configuration</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            All configuration knobs for the scan orchestration engine
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["orchestrator-config"] })} className="gap-1.5">
            <RefreshCw className="w-3.5 h-3.5" />
            Reload
          </Button>
          <Button
            size="sm"
            onClick={() => saveMut.mutate(values)}
            disabled={!dirty || saveMut.isPending}
            className="gap-1.5"
          >
            {saveMut.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />}
            Save Changes
          </Button>
        </div>
      </div>

      {dirty && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          You have unsaved changes. Click "Save Changes" to apply.
        </div>
      )}

      {/* Toggles section */}
      <div className="rounded-xl border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold">Feature Toggles</h2>
        {isLoading ? (
          Array.from({ length: 7 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-6 w-10 rounded-full" />
            </div>
          ))
        ) : boolKnobs.map(k => (
          <div key={k.key} className="flex items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <Label className="text-sm font-medium">{k.label}</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="w-3.5 h-3.5 text-muted-foreground cursor-help shrink-0" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">{k.description}</TooltipContent>
                </Tooltip>
              </div>
              <p className="text-xs text-muted-foreground font-mono mt-0.5">{k.key}</p>
            </div>
            {renderKnob(k)}
          </div>
        ))}
      </div>

      {/* Numeric settings */}
      <div className="rounded-xl border bg-card p-5 space-y-4">
        <h2 className="text-sm font-semibold">Numeric Parameters</h2>
        {isLoading ? (
          Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-52" />
              <Skeleton className="h-8 w-36 rounded" />
            </div>
          ))
        ) : numKnobs.map(k => (
          <div key={k.key} className="flex items-center justify-between gap-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <Label className="text-sm font-medium">{k.label}</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="w-3.5 h-3.5 text-muted-foreground cursor-help shrink-0" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs text-xs">{k.description}</TooltipContent>
                </Tooltip>
              </div>
              <p className="text-xs text-muted-foreground font-mono mt-0.5">
                {k.key}{k.min != null ? ` (${k.min}–${k.max})` : ""}
              </p>
            </div>
            {renderKnob(k)}
          </div>
        ))}
      </div>

      {/* Config note */}
      <div className="rounded-lg border bg-blue-500/5 border-blue-500/20 px-4 py-3 text-xs text-muted-foreground">
        <strong className="text-foreground">Note:</strong> Changes are written immediately to the database.
        The orchestrator reloads its config cache every 60 seconds, so new settings take effect within one minute.
      </div>
    </div>
  );
}
