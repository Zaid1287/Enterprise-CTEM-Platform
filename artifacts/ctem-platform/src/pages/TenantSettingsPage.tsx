import { useAuth } from "@/hooks/useAuth";
import { useQueryClient } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Building2, Save, Loader2, CheckCircle2, Bell, Mail, Hash,
  MessageSquare, Webhook, Zap, Send, TestTube, AlertCircle,
  ToggleLeft, ToggleRight,
} from "lucide-react";
import { capitalize, formatDate } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

interface PkgData { id: number; name: string }

type ChannelKey = "email" | "slack" | "discord" | "telegram" | "webhook";
interface ChannelConfig { enabled: boolean; destination: string; ruleId?: number }
type ChannelMap = Record<ChannelKey, ChannelConfig>;

const CHANNEL_META: Record<ChannelKey, {
  label: string;
  icon: React.ElementType;
  placeholder: string;
  hint: string;
  color: string;
}> = {
  email: {
    label: "Email",
    icon: Mail,
    placeholder: "alerts@yourcompany.com",
    hint: "Alerts will be sent to this email address.",
    color: "text-blue-400",
  },
  slack: {
    label: "Slack",
    icon: Hash,
    placeholder: "https://hooks.slack.com/services/T.../B.../...",
    hint: "Create an Incoming Webhook in your Slack workspace settings.",
    color: "text-[#4A154B]",
  },
  discord: {
    label: "Discord",
    icon: MessageSquare,
    placeholder: "https://discord.com/api/webhooks/123.../abc...",
    hint: "Go to Discord channel settings → Integrations → Webhooks.",
    color: "text-[#5865F2]",
  },
  telegram: {
    label: "Telegram",
    icon: Send,
    placeholder: "1234567890:ABCdef...TOKEN:CHAT_ID",
    hint: "Format: BotToken:ChatID — get your bot token from @BotFather.",
    color: "text-[#2CA5E0]",
  },
  webhook: {
    label: "Webhook",
    icon: Webhook,
    placeholder: "https://your-server.com/webhook",
    hint: "Receives a JSON POST with the alert payload.",
    color: "text-orange-400",
  },
};

const DEFAULT_CHANNELS: ChannelMap = {
  email:    { enabled: false, destination: "" },
  slack:    { enabled: false, destination: "" },
  discord:  { enabled: false, destination: "" },
  telegram: { enabled: false, destination: "" },
  webhook:  { enabled: false, destination: "" },
};

function AiMapperModuleCard({ tenantId, userRole }: { tenantId: number; userRole: string }) {
  const { toast } = useToast();
  const { aiMapperEnabled, setAiMapperEnabled } = useAuth();
  const qc = useQueryClient();

  const { data, isLoading } = useQuery<{ isEnabled: boolean }>({
    queryKey: ["ai-mapper-module", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/ai-mapper/module`),
    enabled: !!tenantId,
  });

  const toggle = useMutation({
    mutationFn: (enable: boolean) =>
      apiFetch(`${BASE}/api/ai-mapper/module`, {
        method: "PATCH",
        body: JSON.stringify({ isEnabled: enable }),
      }),
    onSuccess: (_data, enable) => {
      setAiMapperEnabled(enable);
      qc.invalidateQueries({ queryKey: ["ai-mapper-module", tenantId] });
      toast({ title: enable ? "AI Mapper enabled" : "AI Mapper disabled" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const canToggle = userRole === "super_admin" || userRole === "admin";
  const enabled = data?.isEnabled ?? aiMapperEnabled;

  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold">AI Mapper Module</h3>
          <p className="text-xs text-muted-foreground mt-0.5">
            Discover and assess exposed AI infrastructure — Ollama, MCP servers, vLLM, Gradio, and more.
          </p>
          {enabled && (
            <Badge className="mt-2 text-xs bg-green-500/20 text-green-400 border-green-500/30">Active</Badge>
          )}
        </div>
        {canToggle && (
          <Button
            variant={enabled ? "outline" : "default"}
            size="sm"
            onClick={() => toggle.mutate(!enabled)}
            disabled={toggle.isPending || isLoading}
            className="shrink-0"
          >
            {toggle.isPending
              ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
              : enabled ? <ToggleRight className="w-3.5 h-3.5 mr-1.5 text-green-400" /> : <ToggleLeft className="w-3.5 h-3.5 mr-1.5" />
            }
            {enabled ? "Disable" : "Enable"}
          </Button>
        )}
      </div>
    </div>
  );
}

export default function TenantSettingsPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const tenantId = user?.tenantId ?? 0;
  const queryClient = useQueryClient();

  const { data: tenant, isLoading } = useQuery<any>({
    queryKey: ["tenant", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${tenantId}`),
    enabled: !!tenantId,
  });

  const { data: packages = [] } = useQuery<PkgData[]>({
    queryKey: ["packages"],
    queryFn: () => apiFetch(`${BASE}/api/packages`),
  });
  const planOptions = packages.length > 0
    ? packages.map(p => p.name.toLowerCase())
    : ["starter", "professional", "enterprise"];

  const updateMutation = useMutation({
    mutationFn: (body: { name: string; plan: string }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}`, {
        method: "PATCH",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenant", tenantId] });
      toast({ title: "Settings saved successfully" });
    },
    onError: (e: any) => toast({ title: "Failed to save", description: e.message, variant: "destructive" }),
  });

  const [form, setForm] = useState({ name: "", plan: "starter" });

  useEffect(() => {
    if (tenant) {
      setForm({ name: tenant.name ?? "", plan: tenant.plan ?? "starter" });
    }
  }, [tenant]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast({ title: "Organization name is required", variant: "destructive" });
      return;
    }
    updateMutation.mutate(form);
  };

  return (
    <div className="space-y-5 max-w-2xl">
      <div className="flex items-center gap-2">
        <Building2 className="w-5 h-5 text-muted-foreground" />
        <div>
          <h1 className="text-lg font-semibold">Org Settings</h1>
          <p className="text-sm text-muted-foreground">Organization configuration and notification channels</p>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : (
        <>
          {/* Organization Details — only editable by admin+ */}
          {(user?.role === "admin" || user?.role === "super_admin") && (
            <div className="bg-card border border-border rounded-xl p-5">
              <h3 className="text-sm font-semibold mb-4">Organization Details</h3>
              <form onSubmit={handleSave} className="space-y-4">
                <div className="space-y-1.5">
                  <Label className="text-xs">Organization Name *</Label>
                  <Input
                    value={form.name}
                    onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                    placeholder="Acme Corp"
                    required className="h-9 max-w-sm"
                  />
                </div>

                <div className="space-y-1.5">
                  <Label className="text-xs">Slug (read-only)</Label>
                  <Input
                    value={tenant?.slug ?? ""}
                    disabled
                    className="h-9 max-w-sm opacity-50 font-mono text-sm"
                  />
                  <p className="text-xs text-muted-foreground">Auto-generated. Cannot be changed.</p>
                </div>

                {user?.role === "super_admin" && (
                  <div className="space-y-1.5">
                    <Label className="text-xs">Plan</Label>
                    <Select value={form.plan} onValueChange={v => setForm(p => ({ ...p, plan: v }))}>
                      <SelectTrigger className="h-9 max-w-sm"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        {planOptions.map(pl => (
                          <SelectItem key={pl} value={pl} className="capitalize">
                            {pl.charAt(0).toUpperCase() + pl.slice(1)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                <Button type="submit" size="sm" disabled={updateMutation.isPending} className="flex items-center gap-1.5">
                  {updateMutation.isPending
                    ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    : updateMutation.isSuccess
                    ? <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                    : <Save className="w-3.5 h-3.5" />}
                  {updateMutation.isPending ? "Saving…" : "Save Changes"}
                </Button>
              </form>
            </div>
          )}

          {/* Plan & Limits */}
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-4">Plan & Limits</h3>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Current Plan",  value: capitalize(tenant?.plan ?? "—") },
                { label: "Max Assets",    value: tenant?.maxAssets  ?? "Unlimited" },
                { label: "Max Users",     value: tenant?.maxUsers   ?? "Unlimited" },
                { label: "Member Since",  value: tenant?.createdAt ? formatDate(tenant.createdAt) : "—" },
              ].map(({ label, value }) => (
                <div key={label} className="bg-accent/30 rounded-lg p-3">
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="text-sm font-medium mt-0.5">{String(value)}</p>
                </div>
              ))}
            </div>
          </div>

          {/* AI Mapper Module */}
          <AiMapperModuleCard tenantId={tenantId} userRole={user?.role ?? ""} />

          {/* Notification Channels — all roles */}
          <NotificationChannelsSection />

          {/* System Info */}
          <div className="bg-card border border-border rounded-xl p-5">
            <h3 className="text-sm font-semibold mb-3">System Info</h3>
            <div className="space-y-2 text-xs text-muted-foreground font-mono">
              <div className="flex items-center gap-3">
                <span className="text-muted-foreground/50 w-24">Tenant ID</span>
                <span className="text-foreground">{tenant?.id ?? "—"}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-muted-foreground/50 w-24">Status</span>
                <span className={tenant?.isActive ? "text-green-400" : "text-red-400"}>
                  {tenant?.isActive ? "Active" : "Inactive"}
                </span>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Notification Channels Component ───────────────────────────────────────────

function NotificationChannelsSection() {
  const { toast } = useToast();
  const [channels, setChannels] = useState<ChannelMap>({ ...DEFAULT_CHANNELS });
  const [testingChannel, setTestingChannel] = useState<ChannelKey | null>(null);
  const [testResults, setTestResults] = useState<Record<ChannelKey, "ok" | "fail" | null>>({
    email: null, slack: null, discord: null, telegram: null, webhook: null,
  });

  const { isLoading, refetch } = useQuery<ChannelMap>({
    queryKey: ["notification-channels"],
    queryFn: () => apiFetch(`${BASE}/api/notification-channels`),
    onSuccess: (data: ChannelMap) => setChannels(data),
  } as any);

  const saveMutation = useMutation({
    mutationFn: (body: ChannelMap) =>
      apiFetch(`${BASE}/api/notification-channels`, {
        method: "PUT",
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      refetch();
      toast({ title: "Notification channels saved" });
    },
    onError: (e: any) => toast({ title: "Failed to save", description: e.message, variant: "destructive" }),
  });

  const handleToggle = (ch: ChannelKey) => {
    setChannels(prev => ({ ...prev, [ch]: { ...prev[ch], enabled: !prev[ch].enabled } }));
  };

  const handleDestChange = (ch: ChannelKey, destination: string) => {
    setChannels(prev => ({ ...prev, [ch]: { ...prev[ch], destination } }));
  };

  const handleSave = () => saveMutation.mutate(channels);

  const handleTest = async (ch: ChannelKey) => {
    const dest = channels[ch].destination;
    if (!dest) {
      toast({ title: "Enter a destination first", variant: "destructive" }); return;
    }
    setTestingChannel(ch);
    setTestResults(prev => ({ ...prev, [ch]: null }));
    try {
      await apiFetch(`${BASE}/api/notification-channels/${ch}/test`, {
        method: "POST",
        body: JSON.stringify({ destination: dest }),
      });
      setTestResults(prev => ({ ...prev, [ch]: "ok" }));
      toast({ title: `${CHANNEL_META[ch].label} test sent!`, description: "Check your destination for the test message." });
    } catch (e: any) {
      setTestResults(prev => ({ ...prev, [ch]: "fail" }));
      toast({ title: `${CHANNEL_META[ch].label} test failed`, description: e.message, variant: "destructive" });
    } finally {
      setTestingChannel(null);
    }
  };

  const activeCount = Object.values(channels).filter(c => c.enabled).length;

  return (
    <div className="bg-card border border-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-muted-foreground" />
          <h3 className="text-sm font-semibold">Notification Channels</h3>
          {activeCount > 0 && (
            <Badge variant="secondary" className="text-xs h-5 px-1.5">
              {activeCount} active
            </Badge>
          )}
        </div>
        <Button
          size="sm"
          onClick={handleSave}
          disabled={saveMutation.isPending}
          className="h-7 text-xs gap-1.5"
        >
          {saveMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Save className="w-3 h-3" />}
          Save All
        </Button>
      </div>
      <p className="text-xs text-muted-foreground mb-4">
        Org-level channels receive <span className="text-foreground font-medium">all alerts</span> for your organization — scans, findings, brand threats. Enable any channel and set its destination.
      </p>

      {isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-16 rounded-lg" />)}
        </div>
      ) : (
        <div className="space-y-2">
          {(Object.keys(CHANNEL_META) as ChannelKey[]).map(ch => {
            const meta = CHANNEL_META[ch];
            const Icon = meta.icon;
            const cfg = channels[ch];
            const testResult = testResults[ch];
            const isTesting = testingChannel === ch;

            return (
              <div
                key={ch}
                className={cn(
                  "border rounded-lg p-3.5 transition-colors",
                  cfg.enabled ? "border-primary/40 bg-primary/5" : "border-border bg-accent/10",
                )}
              >
                <div className="flex items-start gap-3">
                  {/* Toggle */}
                  <button
                    onClick={() => handleToggle(ch)}
                    className="mt-0.5 shrink-0"
                    title={cfg.enabled ? "Disable channel" : "Enable channel"}
                  >
                    {cfg.enabled
                      ? <ToggleRight className="w-5 h-5 text-primary" />
                      : <ToggleLeft className="w-5 h-5 text-muted-foreground" />}
                  </button>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className={cn("w-4 h-4", meta.color)} />
                      <span className="text-sm font-medium">{meta.label}</span>
                      {cfg.enabled && (
                        <Badge className="text-[10px] h-4 px-1 bg-green-500/20 text-green-400 border-green-500/30">
                          Active
                        </Badge>
                      )}
                      {testResult === "ok" && (
                        <Badge className="text-[10px] h-4 px-1 bg-green-500/20 text-green-400 border-green-500/30">
                          ✓ Sent
                        </Badge>
                      )}
                      {testResult === "fail" && (
                        <Badge className="text-[10px] h-4 px-1 bg-red-500/20 text-red-400 border-red-500/30">
                          ✗ Failed
                        </Badge>
                      )}
                    </div>

                    <div className="flex gap-2">
                      <Input
                        value={cfg.destination}
                        onChange={e => handleDestChange(ch, e.target.value)}
                        placeholder={meta.placeholder}
                        className="h-7 text-xs font-mono flex-1"
                        type={ch === "email" ? "email" : "text"}
                      />
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs gap-1 shrink-0"
                        disabled={!cfg.destination || isTesting}
                        onClick={() => handleTest(ch)}
                      >
                        {isTesting
                          ? <Loader2 className="w-3 h-3 animate-spin" />
                          : <TestTube className="w-3 h-3" />}
                        Test
                      </Button>
                    </div>

                    <p className="text-[11px] text-muted-foreground mt-1.5">{meta.hint}</p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="mt-3 flex items-start gap-2 p-2.5 bg-accent/30 rounded-lg">
        <AlertCircle className="w-3.5 h-3.5 text-muted-foreground mt-0.5 shrink-0" />
        <p className="text-[11px] text-muted-foreground">
          Use the <span className="text-foreground font-medium">Alerts → Alert Rules</span> tab to create granular rules that fire only for specific event types (e.g., only critical findings) or specific assets.
        </p>
      </div>
    </div>
  );
}
