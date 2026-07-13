import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import {
  Card, CardContent, CardHeader, CardTitle, CardDescription,
} from "@/components/ui/card";
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
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Bell, Plus, Trash2, Play, EyeOff, CheckCircle2, XCircle,
  Loader2, RefreshCw, AlertTriangle, Mail, Globe, MessageSquare,
} from "lucide-react";

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

const BLANK_FORM: RuleForm = { name: "", channel: "email", destination: "" };

const CHANNEL_PLACEHOLDER: Record<string, string> = {
  email:   "alerts@yourcompany.com",
  slack:   "https://hooks.slack.com/services/…",
  discord: "https://discord.com/api/webhooks/…",
  telegram: "BOT_TOKEN:CHAT_ID",
  webhook: "https://your-server.com/webhook",
};

const CHANNEL_HINT: Record<string, string> = {
  email:   "Requires Resend API key or SMTP configured in Platform Settings.",
  slack:   "Create an Incoming Webhook in your Slack workspace and paste the URL here.",
  discord: "Server Settings → Integrations → Webhooks → Copy Webhook URL.",
  telegram:"Format: BOT_TOKEN:CHAT_ID — get a token from @BotFather, chat ID from @userinfobot.",
  webhook: "Sentinelware will POST a JSON payload to this URL for every Shadow IT discovery event.",
};

const CHANNEL_ICONS: Record<string, React.ReactNode> = {
  email:   <Mail className="h-3.5 w-3.5" />,
  slack:   <MessageSquare className="h-3.5 w-3.5" />,
  discord: <MessageSquare className="h-3.5 w-3.5" />,
  telegram:<MessageSquare className="h-3.5 w-3.5" />,
  webhook: <Globe className="h-3.5 w-3.5" />,
};

type TestState = { status: "idle" | "loading" | "ok" | "err"; msg?: string };

export default function ShadowItAlertsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit] = useState<AlertRule | null>(null);
  const [form, setForm] = useState<RuleForm>(BLANK_FORM);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<number | null>(null);
  const [testStates, setTestStates] = useState<Record<number, TestState>>({});
  const [toggling, setToggling] = useState<number | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const { data: allRules, isLoading, refetch } = useQuery<AlertRule[]>({
    queryKey: ["shadow-it-alert-rules"],
    queryFn: () => apiFetch<AlertRule[]>("/api/alerts/rules"),
    select: (rows) => rows.filter((r) => r.triggerType === "shadow_it_discovered"),
  });

  const rules = allRules ?? [];

  const openCreate = () => {
    setForm(BLANK_FORM);
    setFormError(null);
    setShowCreate(true);
  };

  const openEdit = (rule: AlertRule) => {
    setForm({ name: rule.name, channel: rule.channel, destination: rule.destination ?? "" });
    setFormError(null);
    setShowEdit(rule);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) { setFormError("Rule name is required."); return; }
    setSaving(true);
    setFormError(null);
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
    } catch (err: any) {
      setFormError(err?.message ?? "Failed to create rule.");
    }
    setSaving(false);
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!showEdit) return;
    if (!form.name.trim()) { setFormError("Rule name is required."); return; }
    setSaving(true);
    setFormError(null);
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
    } catch (err: any) {
      setFormError(err?.message ?? "Failed to update rule.");
    }
    setSaving(false);
  };

  const handleDelete = async (id: number) => {
    setDeleting(id);
    try {
      await apiFetch(`/api/alerts/rules/${id}`, { method: "DELETE" });
      await refetch();
    } catch { /* toast via apiFetch */ }
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
    } catch { /* toast via apiFetch */ }
    setToggling(null);
  };

  const handleTest = async (rule: AlertRule) => {
    setTestStates((p) => ({ ...p, [rule.id]: { status: "loading" } }));
    try {
      const res = await apiFetch<{ success: boolean; channel: string; destination: string }>(
        `/api/alerts/rules/${rule.id}/test`,
        { method: "POST" }
      );
      setTestStates((p) => ({
        ...p,
        [rule.id]: { status: "ok", msg: `Sent to ${res.destination}` },
      }));
    } catch (err: any) {
      setTestStates((p) => ({
        ...p,
        [rule.id]: { status: "err", msg: err?.message ?? "Delivery failed" },
      }));
    }
    setTimeout(
      () => setTestStates((p) => ({ ...p, [rule.id]: { status: "idle" } })),
      6000
    );
  };

  const RuleFormFields = () => (
    <>
      <div className="space-y-1.5">
        <Label className="text-xs">Rule Name *</Label>
        <Input
          value={form.name}
          onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
          placeholder="e.g. Slack — Shadow IT Critical"
          className="h-9"
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label className="text-xs">Trigger</Label>
        <Input
          value="Shadow IT Discovery"
          disabled
          className="h-9 bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 font-medium"
        />
        <p className="text-[11px] text-muted-foreground">
          Fires whenever Sentinelware finds a new unsanctioned asset, OAuth app, or network device.
        </p>
      </div>
      <div className="space-y-1.5">
        <Label className="text-xs">Notification Channel</Label>
        <Select
          value={form.channel}
          onValueChange={(v) => setForm((p) => ({ ...p, channel: v, destination: "" }))}
        >
          <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="email">📧 Email</SelectItem>
            <SelectItem value="slack">💬 Slack</SelectItem>
            <SelectItem value="discord">🎮 Discord</SelectItem>
            <SelectItem value="telegram">✈️ Telegram</SelectItem>
            <SelectItem value="webhook">🔗 Webhook</SelectItem>
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1.5">
        <Label className="text-xs">Destination</Label>
        <Input
          value={form.destination}
          onChange={(e) => setForm((p) => ({ ...p, destination: e.target.value }))}
          placeholder={CHANNEL_PLACEHOLDER[form.channel] ?? ""}
          className="h-9"
        />
        <p className="text-[11px] text-muted-foreground">{CHANNEL_HINT[form.channel]}</p>
      </div>
    </>
  );

  return (
    <AppLayout>
      <div className="p-6 space-y-6 max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <EyeOff className="h-6 w-6 text-purple-500" />
              Shadow IT — Alert Configuration
            </h1>
            <p className="text-muted-foreground mt-1 text-sm">
              Configure who gets notified when Shadow IT discovers a new unsanctioned asset, OAuth app, or internal network device.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refetch()}>
              <RefreshCw className="h-4 w-4 mr-2" />
              Refresh
            </Button>
            <Button size="sm" onClick={openCreate}>
              <Plus className="h-4 w-4 mr-2" />
              New Rule
            </Button>
          </div>
        </div>

        {/* Info banner */}
        <Card className="border-purple-200 bg-purple-50/50 dark:bg-purple-900/10">
          <CardContent className="p-4">
            <div className="flex items-start gap-3">
              <Bell className="h-5 w-5 text-purple-500 mt-0.5 shrink-0" />
              <div className="text-sm">
                <p className="font-medium text-purple-900 dark:text-purple-200">How Shadow IT alerts work</p>
                <p className="text-muted-foreground mt-1">
                  Each rule below fires when the correlation engine detects a new shadow asset — unsanctioned subdomains,
                  exposed cloud buckets, admin panels found by Nuclei, shadow services on dangerous ports,
                  unauthorized tech stacks, new OAuth apps from IdP sync, or unmanaged network devices.
                  Rules run immediately after each scan and on the daily discovery job.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Rules table */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Bell className="h-4 w-4" />
              Alert Rules for Shadow IT Discovery
              <Badge variant="secondary" className="ml-1">{rules.length}</Badge>
            </CardTitle>
            <CardDescription>
              All rules below are scoped exclusively to the <code className="bg-muted px-1 rounded text-xs">shadow_it_discovered</code> event type.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : rules.length === 0 ? (
              <div className="text-center py-12 space-y-3">
                <AlertTriangle className="h-10 w-10 text-muted-foreground mx-auto" />
                <p className="font-medium text-sm">No alert rules configured</p>
                <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                  Shadow IT discoveries are being logged but no notifications will be sent.
                  Create a rule to get alerted immediately when new shadow assets are found.
                </p>
                <Button size="sm" onClick={openCreate} className="mt-2">
                  <Plus className="h-4 w-4 mr-2" /> Create First Rule
                </Button>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[220px]">Rule Name</TableHead>
                    <TableHead>Channel</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead className="w-[90px] text-center">Active</TableHead>
                    <TableHead className="w-[200px] text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.map((rule) => {
                    const ts = testStates[rule.id] ?? { status: "idle" };
                    return (
                      <TableRow key={rule.id}>
                        <TableCell className="font-medium text-sm py-3">{rule.name}</TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5 text-sm capitalize">
                            {CHANNEL_ICONS[rule.channel]}
                            {rule.channel}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground max-w-[200px] truncate">
                          {rule.destination
                            ? (rule.destination.length > 50 ? rule.destination.slice(0, 47) + "…" : rule.destination)
                            : <span className="italic text-muted-foreground/50">platform default</span>}
                        </TableCell>
                        <TableCell className="text-center">
                          {toggling === rule.id ? (
                            <Loader2 className="h-4 w-4 animate-spin mx-auto text-muted-foreground" />
                          ) : (
                            <Switch
                              checked={rule.isActive}
                              onCheckedChange={() => handleToggle(rule)}
                            />
                          )}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-1.5">
                            {/* Test button */}
                            {ts.status === "loading" ? (
                              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                            ) : ts.status === "ok" ? (
                              <span className="flex items-center gap-1 text-xs text-green-600">
                                <CheckCircle2 className="h-3.5 w-3.5" /> {ts.msg}
                              </span>
                            ) : ts.status === "err" ? (
                              <span className="flex items-center gap-1 text-xs text-red-600">
                                <XCircle className="h-3.5 w-3.5" /> {ts.msg}
                              </span>
                            ) : (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleTest(rule)}
                                title="Send a test notification"
                              >
                                <Play className="h-3.5 w-3.5 mr-1" /> Test
                              </Button>
                            )}
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => openEdit(rule)}
                            >
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDelete(rule.id)}
                              disabled={deleting === rule.id}
                              className="text-destructive hover:text-destructive"
                            >
                              {deleting === rule.id
                                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                                : <Trash2 className="h-3.5 w-3.5" />}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        {/* Create dialog */}
        <Dialog open={showCreate} onOpenChange={(o) => { if (!saving) setShowCreate(o); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Shadow IT Alert Rule</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleCreate} className="space-y-4 mt-1">
              <RuleFormFields />
              {formError && (
                <p className="text-xs text-destructive">{formError}</p>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setShowCreate(false)} disabled={saving}>
                  Cancel
                </Button>
                <Button type="submit" disabled={saving}>
                  {saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Create Rule
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>

        {/* Edit dialog */}
        <Dialog open={!!showEdit} onOpenChange={(o) => { if (!saving && !o) setShowEdit(null); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Edit Alert Rule</DialogTitle>
            </DialogHeader>
            <form onSubmit={handleEdit} className="space-y-4 mt-1">
              <RuleFormFields />
              {formError && (
                <p className="text-xs text-destructive">{formError}</p>
              )}
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setShowEdit(null)} disabled={saving}>
                  Cancel
                </Button>
                <Button type="submit" disabled={saving}>
                  {saving && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  Save Changes
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>
    </AppLayout>
  );
}
