import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  Bell, Plus, Trash2, Play, EyeOff, CheckCircle2, XCircle,
  Loader2, RefreshCw, AlertTriangle, Mail, Globe, MessageSquare,
  Info, Zap, Shield, Settings,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface AlertRule {
  id: number;
  name: string;
  triggerType: string;
  channel: string;
  destination: string | null;
  isActive: boolean;
  createdAt: string;
}

interface RuleForm {
  name: string;
  channel: string;
  destination: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const BLANK_FORM: RuleForm = { name: "", channel: "email", destination: "" };

const CHANNEL_META: Record<string, {
  label: string; placeholder: string; hint: string;
  icon: React.ReactNode; bg: string; text: string; border: string;
}> = {
  email: {
    label: "Email",
    placeholder: "alerts@yourcompany.com",
    hint: "Requires Resend API key or SMTP configured in Platform Settings → Email.",
    icon: <Mail className="h-4 w-4" />,
    bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/20",
  },
  slack: {
    label: "Slack",
    placeholder: "https://hooks.slack.com/services/…",
    hint: "Create an Incoming Webhook in your Slack workspace and paste the URL here.",
    icon: <MessageSquare className="h-4 w-4" />,
    bg: "bg-green-500/10", text: "text-green-400", border: "border-green-500/20",
  },
  discord: {
    label: "Discord",
    placeholder: "https://discord.com/api/webhooks/…",
    hint: "Server Settings → Integrations → Webhooks → Copy Webhook URL.",
    icon: <MessageSquare className="h-4 w-4" />,
    bg: "bg-indigo-500/10", text: "text-indigo-400", border: "border-indigo-500/20",
  },
  telegram: {
    label: "Telegram",
    placeholder: "BOT_TOKEN:CHAT_ID",
    hint: "Format: BOT_TOKEN:CHAT_ID — get a token from @BotFather, chat ID from @userinfobot.",
    icon: <MessageSquare className="h-4 w-4" />,
    bg: "bg-sky-500/10", text: "text-sky-400", border: "border-sky-500/20",
  },
  webhook: {
    label: "Webhook",
    placeholder: "https://your-server.com/webhook",
    hint: "Sentinelware will POST a JSON payload to this URL for every Shadow IT discovery event.",
    icon: <Globe className="h-4 w-4" />,
    bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/20",
  },
};

type TestState = { status: "idle" | "loading" | "ok" | "err"; msg?: string };

// ── Helper components ──────────────────────────────────────────────────────────

function ChannelPill({ channel }: { channel: string }) {
  const meta = CHANNEL_META[channel] ?? { label: channel, bg: "bg-muted/50", text: "text-muted-foreground", border: "border-border", icon: <Globe className="h-3.5 w-3.5" /> };
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold border capitalize", meta.bg, meta.text, meta.border)}>
      {meta.icon}
      {meta.label}
    </span>
  );
}

function KpiCard({ label, value, icon, accent, sub }: { label: string; value: number | string; icon: React.ReactNode; accent: string; sub?: string }) {
  return (
    <div className="rounded-xl border bg-card p-4 flex items-center gap-3">
      <div className={cn("p-2.5 rounded-lg flex-shrink-0", accent)}>{icon}</div>
      <div className="min-w-0">
        <p className="text-2xl font-bold leading-none">{value}</p>
        <p className="text-xs text-muted-foreground mt-1 truncate">{label}</p>
        {sub && <p className="text-xs text-muted-foreground/60 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function ShadowItAlertsPage() {
  const qc = useQueryClient();
  const { toast } = useToast();

  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit] = useState<AlertRule | null>(null);
  const [form, setForm] = useState<RuleForm>(BLANK_FORM);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [testStates, setTestStates] = useState<Record<number, TestState>>({});
  const [toggling, setToggling] = useState<number | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  // ── Data ────────────────────────────────────────────────────────────────────

  const { data: allRules, isLoading, refetch, isFetching } = useQuery<AlertRule[]>({
    queryKey: ["shadow-it-alert-rules"],
    queryFn: () => apiFetch<AlertRule[]>("/api/alerts/rules"),
    select: (rows) => rows.filter((r) => r.triggerType === "shadow_it_discovered"),
    staleTime: 0,
  });

  const rules = allRules ?? [];
  const activeCount = rules.filter(r => r.isActive).length;
  const channelsInUse = [...new Set(rules.map(r => r.channel))].length;

  // ── Handlers ────────────────────────────────────────────────────────────────

  const openCreate = () => { setForm(BLANK_FORM); setFormError(null); setShowCreate(true); };
  const openEdit = (rule: AlertRule) => {
    setForm({ name: rule.name, channel: rule.channel, destination: rule.destination ?? "" });
    setFormError(null);
    setShowEdit(rule);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) { setFormError("Rule name is required."); return; }
    setSaving(true); setFormError(null);
    try {
      await apiFetch("/api/alerts/rules", {
        method: "POST",
        body: JSON.stringify({
          name: form.name.trim(),
          triggerType: "shadow_it_discovered",
          channel: form.channel,
          destination: form.destination.trim() || null,
          isActive: true,
        }),
      });
      await refetch();
      setShowCreate(false);
      toast({ title: "Alert rule created", description: `"${form.name.trim()}" will notify via ${CHANNEL_META[form.channel]?.label ?? form.channel}.` });
    } catch (err: any) {
      setFormError(err?.message ?? "Failed to create rule.");
    }
    setSaving(false);
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!showEdit) return;
    if (!form.name.trim()) { setFormError("Rule name is required."); return; }
    setSaving(true); setFormError(null);
    try {
      await apiFetch(`/api/alerts/rules/${showEdit.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: form.name.trim(),
          channel: form.channel,
          destination: form.destination.trim() || null,
        }),
      });
      await refetch();
      setShowEdit(null);
      toast({ title: "Alert rule updated" });
    } catch (err: any) {
      setFormError(err?.message ?? "Failed to update rule.");
    }
    setSaving(false);
  };

  const handleDelete = async (rule: AlertRule) => {
    if (!confirm(`Delete alert rule "${rule.name}"?`)) return;
    setDeleting(rule.id);
    try {
      await apiFetch(`/api/alerts/rules/${rule.id}`, { method: "DELETE" });
      await refetch();
      toast({ title: "Rule deleted", description: `"${rule.name}" has been removed.` });
    } catch (err: any) {
      toast({ title: "Delete failed", description: err?.message, variant: "destructive" });
    }
    setDeleting(null);
  };

  const handleToggle = async (rule: AlertRule) => {
    setToggling(rule.id);
    try {
      await apiFetch(`/api/alerts/rules/${rule.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isActive: !rule.isActive }),
      });
      await refetch();
      toast({ title: rule.isActive ? "Rule disabled" : "Rule enabled", description: `"${rule.name}" is now ${rule.isActive ? "inactive" : "active"}.` });
    } catch (err: any) {
      toast({ title: "Toggle failed", description: err?.message, variant: "destructive" });
    }
    setToggling(null);
  };

  const handleTest = async (rule: AlertRule) => {
    setTestStates(p => ({ ...p, [rule.id]: { status: "loading" } }));
    try {
      const res = await apiFetch<{ success: boolean; channel: string; destination: string }>(
        `/api/alerts/rules/${rule.id}/test`, { method: "POST" }
      );
      setTestStates(p => ({ ...p, [rule.id]: { status: "ok", msg: `Sent to ${res.destination}` } }));
      toast({ title: "Test sent", description: `Test notification delivered to ${res.destination}` });
    } catch (err: any) {
      setTestStates(p => ({ ...p, [rule.id]: { status: "err", msg: err?.message ?? "Delivery failed" } }));
      toast({ title: "Test failed", description: err?.message, variant: "destructive" });
    }
    setTimeout(() => setTestStates(p => ({ ...p, [rule.id]: { status: "idle" } })), 6000);
  };

  // ── Form fields (shared between create/edit dialogs) ──────────────────────

  const RuleFormFields = () => (
    <>
      <div className="space-y-1.5">
        <Label className="text-sm font-medium">Rule Name <span className="text-destructive">*</span></Label>
        <Input
          value={form.name}
          onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
          placeholder="e.g. Slack — Shadow IT Critical"
          className="h-9"
          required
        />
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium">Trigger Event</Label>
        <div className="flex items-center gap-2 rounded-lg border border-purple-500/30 bg-purple-500/8 px-3 py-2">
          <Zap className="h-4 w-4 text-purple-400 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium text-purple-300">Shadow IT Discovery</p>
            <p className="text-xs text-muted-foreground mt-0.5">Fires when a new unsanctioned asset, OAuth app, or network device is found.</p>
          </div>
        </div>
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium">Notification Channel</Label>
        <div className="grid grid-cols-5 gap-2">
          {Object.entries(CHANNEL_META).map(([key, meta]) => (
            <button
              key={key}
              type="button"
              onClick={() => setForm(p => ({ ...p, channel: key, destination: "" }))}
              className={cn(
                "flex flex-col items-center gap-1.5 p-2.5 rounded-xl border text-xs font-medium transition-all",
                form.channel === key
                  ? `${meta.bg} ${meta.text} ${meta.border} shadow-sm`
                  : "border-border bg-muted/30 text-muted-foreground hover:bg-muted/50"
              )}
            >
              {meta.icon}
              {meta.label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-1.5">
        <Label className="text-sm font-medium">Destination</Label>
        <Input
          value={form.destination}
          onChange={e => setForm(p => ({ ...p, destination: e.target.value }))}
          placeholder={CHANNEL_META[form.channel]?.placeholder ?? ""}
          className="h-9"
        />
        <p className="text-xs text-muted-foreground leading-relaxed">
          {CHANNEL_META[form.channel]?.hint}
        </p>
      </div>
    </>
  );

  // ── Render ──────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5">

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-card border border-border/50 overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-purple-500 via-violet-500 to-fuchsia-500" />
        <div className="px-6 py-5 flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-purple-500/10 border border-purple-500/20">
              <Bell className="h-6 w-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">Shadow IT — Alert Configuration</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Configure who gets notified when Shadow IT discovers new unsanctioned assets, OAuth apps, or network devices.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={isFetching}
              onClick={() => refetch()}
              className="h-9 gap-1.5"
            >
              <RefreshCw className={cn("h-4 w-4", isFetching && "animate-spin")} />
              Refresh
            </Button>
            <Button
              onClick={openCreate}
              className="h-9 bg-purple-600 hover:bg-purple-700 text-white gap-2"
            >
              <Plus className="h-4 w-4" /> New Rule
            </Button>
          </div>
        </div>
      </div>

      {/* ── KPI Strip ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
        <KpiCard
          label="Alert Rules"
          value={rules.length}
          accent="bg-purple-500/10"
          icon={<Bell className="h-4 w-4 text-purple-400" />}
          sub="Shadow IT scoped"
        />
        <KpiCard
          label="Active Rules"
          value={activeCount}
          accent="bg-green-500/10"
          icon={<CheckCircle2 className="h-4 w-4 text-green-400" />}
          sub={`${rules.length - activeCount} disabled`}
        />
        <KpiCard
          label="Channels in Use"
          value={channelsInUse}
          accent="bg-blue-500/10"
          icon={<Globe className="h-4 w-4 text-blue-400" />}
          sub="Email · Slack · Webhook…"
        />
      </div>

      {/* ── How Shadow IT Alerts Work ─────────────────────────────────────── */}
      <div className="rounded-xl border border-purple-500/20 bg-purple-500/5 overflow-hidden">
        <div className="px-5 py-4 flex items-start gap-4">
          <div className="p-2 rounded-lg bg-purple-500/15 flex-shrink-0 mt-0.5">
            <Info className="h-4 w-4 text-purple-400" />
          </div>
          <div>
            <p className="text-sm font-semibold text-purple-300 mb-2">How Shadow IT Alerts Work</p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              Each rule fires when the correlation engine detects a new shadow asset — unsanctioned subdomains,
              exposed cloud buckets, admin panels found by Nuclei, shadow services on dangerous ports,
              unauthorized tech stacks, new OAuth apps from IdP sync, or unmanaged network devices.
              Rules run immediately after each scan and on the daily discovery job.
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {[
                { icon: <Shield className="h-3 w-3" />, label: "Unsanctioned assets" },
                { icon: <EyeOff className="h-3 w-3" />, label: "OAuth apps" },
                { icon: <Settings className="h-3 w-3" />, label: "Network devices" },
                { icon: <Zap className="h-3 w-3" />, label: "Runs post-scan + daily" },
              ].map(item => (
                <span key={item.label} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full bg-purple-500/10 border border-purple-500/20 text-purple-300">
                  {item.icon}
                  {item.label}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Alert Rules Grid ──────────────────────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">Alert Rules</h2>
            <span className="inline-flex items-center justify-center h-5 min-w-5 px-1.5 rounded-full bg-purple-500/15 text-purple-400 text-xs font-bold">
              {rules.length}
            </span>
          </div>
          <p className="text-xs text-muted-foreground">
            Scoped to <code className="bg-muted px-1.5 py-0.5 rounded text-xs">shadow_it_discovered</code> event type
          </p>
        </div>

        {/* Loading */}
        {isLoading && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {[0, 1, 2].map(i => (
              <div key={i} className="rounded-xl border bg-card h-44 animate-pulse" />
            ))}
          </div>
        )}

        {/* Empty state */}
        {!isLoading && rules.length === 0 && (
          <div className="rounded-xl border-2 border-dashed border-border bg-card/50 py-16 text-center">
            <div className="mx-auto w-14 h-14 rounded-full bg-purple-500/10 flex items-center justify-center mb-4">
              <Bell className="h-7 w-7 text-purple-400 opacity-60" />
            </div>
            <h3 className="font-semibold text-base mb-2">No alert rules configured</h3>
            <p className="text-sm text-muted-foreground max-w-sm mx-auto mb-5">
              Shadow IT discoveries are being logged but <strong>no notifications will be sent</strong>.
              Create a rule to get alerted immediately when new shadow assets are found.
            </p>
            <Button onClick={openCreate} className="bg-purple-600 hover:bg-purple-700 text-white gap-2">
              <Plus className="h-4 w-4" /> Create First Alert Rule
            </Button>
          </div>
        )}

        {/* Rule card grid */}
        {!isLoading && rules.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {rules.map(rule => {
              const ts = testStates[rule.id] ?? { status: "idle" };
              const chanMeta = CHANNEL_META[rule.channel];
              const isBeingDeleted = deleting === rule.id;
              const isBeingToggled = toggling === rule.id;

              return (
                <div
                  key={rule.id}
                  className={cn(
                    "rounded-xl border bg-card overflow-hidden flex flex-col transition-all",
                    rule.isActive ? "border-border/60" : "border-border/30 opacity-70",
                  )}
                >
                  {/* Channel color accent strip */}
                  <div className={cn("h-1", chanMeta?.bg.replace("/10", ""))} style={{
                    background: rule.channel === "email" ? "#3b82f6"
                      : rule.channel === "slack" ? "#22c55e"
                      : rule.channel === "discord" ? "#6366f1"
                      : rule.channel === "telegram" ? "#0ea5e9"
                      : "#f97316"
                  }} />

                  <div className="p-5 flex-1 flex flex-col gap-4">
                    {/* Header */}
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={cn("h-10 w-10 rounded-xl flex items-center justify-center flex-shrink-0 border", chanMeta?.bg, chanMeta?.text, chanMeta?.border)}>
                          {chanMeta?.icon ?? <Globe className="h-4 w-4" />}
                        </div>
                        <div className="min-w-0">
                          <p className="font-semibold text-sm leading-tight truncate">{rule.name}</p>
                          <ChannelPill channel={rule.channel} />
                        </div>
                      </div>

                      {/* Active toggle */}
                      <div className="flex flex-col items-end gap-1 flex-shrink-0">
                        {isBeingToggled
                          ? <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                          : (
                            <Switch
                              checked={rule.isActive}
                              onCheckedChange={() => handleToggle(rule)}
                            />
                          )
                        }
                        <span className={cn("text-xs font-medium", rule.isActive ? "text-green-400" : "text-muted-foreground")}>
                          {rule.isActive ? "Active" : "Disabled"}
                        </span>
                      </div>
                    </div>

                    {/* Destination */}
                    <div className="rounded-lg bg-muted/40 px-3 py-2">
                      <p className="text-xs text-muted-foreground mb-1">Destination</p>
                      <p className="font-mono text-xs truncate" title={rule.destination ?? undefined}>
                        {rule.destination
                          ? rule.destination
                          : <span className="italic text-muted-foreground/60 not-italic font-sans">platform default</span>
                        }
                      </p>
                    </div>

                    {/* Test result feedback */}
                    {ts.status === "ok" && (
                      <div className="flex items-center gap-1.5 text-xs text-green-500 bg-green-500/8 border border-green-500/20 rounded-lg px-3 py-2">
                        <CheckCircle2 className="h-3.5 w-3.5 flex-shrink-0" />
                        <span className="truncate">{ts.msg}</span>
                      </div>
                    )}
                    {ts.status === "err" && (
                      <div className="flex items-center gap-1.5 text-xs text-red-500 bg-red-500/8 border border-red-500/20 rounded-lg px-3 py-2">
                        <XCircle className="h-3.5 w-3.5 flex-shrink-0" />
                        <span className="truncate">{ts.msg}</span>
                      </div>
                    )}

                    {/* Created at */}
                    <p className="text-xs text-muted-foreground/60 mt-auto">
                      Created {new Date(rule.createdAt).toLocaleDateString()}
                    </p>
                  </div>

                  {/* Card footer actions */}
                  <div className="px-5 py-3 border-t border-border/50 bg-muted/20 flex items-center justify-between gap-2">
                    {/* Test button */}
                    {ts.status === "loading" ? (
                      <Button size="sm" variant="outline" disabled className="h-8 text-xs gap-1.5">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" /> Testing…
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => handleTest(rule)}
                        disabled={ts.status !== "idle"}
                        className="h-8 text-xs gap-1.5"
                        title="Send a test notification"
                      >
                        <Play className="h-3.5 w-3.5" /> Test
                      </Button>
                    )}

                    <div className="flex items-center gap-1.5">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openEdit(rule)}
                        className="h-8 text-xs"
                      >
                        Edit
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDelete(rule)}
                        disabled={isBeingDeleted}
                        className="h-8 w-8 p-0 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                      >
                        {isBeingDeleted
                          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          : <Trash2 className="h-3.5 w-3.5" />
                        }
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })}

            {/* Add another rule card */}
            <button
              onClick={openCreate}
              className="rounded-xl border-2 border-dashed border-border/60 bg-card/30 hover:border-purple-500/40 hover:bg-purple-500/5 transition-all flex flex-col items-center justify-center gap-2 py-10 text-sm text-muted-foreground hover:text-purple-400 min-h-[200px]"
            >
              <Plus className="h-7 w-7 opacity-50" />
              <span>Add another rule</span>
            </button>
          </div>
        )}
      </div>

      {/* ── Create Dialog ─────────────────────────────────────────────────── */}
      <Dialog open={showCreate} onOpenChange={o => { if (!saving) setShowCreate(o); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bell className="h-5 w-5 text-purple-400" />
              Create Shadow IT Alert Rule
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleCreate} className="space-y-4 mt-1">
            <RuleFormFields />
            {formError && (
              <div className="flex items-center gap-2 text-xs text-destructive bg-destructive/8 border border-destructive/20 rounded-lg px-3 py-2">
                <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
                {formError}
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowCreate(false)} disabled={saving}>
                Cancel
              </Button>
              <Button type="submit" disabled={saving} className="bg-purple-600 hover:bg-purple-700 text-white gap-2">
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                Create Rule
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Edit Dialog ───────────────────────────────────────────────────── */}
      <Dialog open={!!showEdit} onOpenChange={o => { if (!saving && !o) setShowEdit(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Settings className="h-5 w-5 text-purple-400" />
              Edit Alert Rule
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEdit} className="space-y-4 mt-1">
            <RuleFormFields />
            {formError && (
              <div className="flex items-center gap-2 text-xs text-destructive bg-destructive/8 border border-destructive/20 rounded-lg px-3 py-2">
                <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0" />
                {formError}
              </div>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowEdit(null)} disabled={saving}>
                Cancel
              </Button>
              <Button type="submit" disabled={saving} className="bg-purple-600 hover:bg-purple-700 text-white gap-2">
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                Save Changes
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
