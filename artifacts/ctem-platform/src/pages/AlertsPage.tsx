import { useState, useEffect, useRef } from "react";
import { useLocation } from "wouter";
import {
  useListAlerts, useUpdateAlert, useListAlertRules, useCreateAlertRule,
  useUpdateAlertRule, useDeleteAlertRule,
  getListAlertsQueryKey, getListAlertRulesQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Bell, BellOff, ChevronRight, Trash2, Power, FlaskConical, CheckCircle2, XCircle, Loader2, ShieldAlert, DatabaseZap, Crosshair, ScanSearch, AlertTriangle, Activity, Archive, Inbox } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, capitalize, formatDateTime } from "@/lib/utils";
import { apiFetch } from "@/lib/apiFetch";
import { getToken } from "@/lib/auth";
import { useToast } from "@/hooks/use-toast";

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const ARCHIVE_PAGE_SIZE = 20;

function AlertTypeIcon({ type, className }: { type: string; className?: string }) {
  const cls = className ?? "w-4 h-4 shrink-0";
  switch (type) {
    case "phishing_detected":  return <ShieldAlert className={cn(cls, "text-red-400")} />;
    case "data_leak_found":    return <DatabaseZap className={cn(cls, "text-orange-400")} />;
    case "brand_abuse_found":  return <Crosshair className={cn(cls, "text-purple-400")} />;
    case "brand_threat":       return <AlertTriangle className={cn(cls, "text-yellow-400")} />;
    case "scan_complete":      return <ScanSearch className={cn(cls, "text-blue-400")} />;
    case "critical_finding":
    case "high_finding":
    case "new_finding":        return <Activity className={cn(cls, "text-muted-foreground")} />;
    default:                   return <Bell className={cn(cls, "text-muted-foreground")} />;
  }
}

const CHANNEL_PLACEHOLDER: Record<string, string> = {
  email:    "alerts@company.com",
  slack:    "https://hooks.slack.com/services/…",
  discord:  "https://discord.com/api/webhooks/…",
  telegram: "BOT_TOKEN:CHAT_ID  (e.g. 123456:AAH…:-1001234567)",
  webhook:  "https://your-server.com/webhook",
};

type TestState = { status: "idle" } | { status: "testing" } | { status: "ok"; dest: string } | { status: "error"; msg: string };

export default function AlertsPage() {
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [severityFilter, setSeverityFilter] = useState("");
  const [archivePage, setArchivePage] = useState(0);
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [ruleForm, setRuleForm] = useState({ name: "", triggerType: "new_finding", channel: "email", destination: "" });
  const [testStates, setTestStates] = useState<Record<number, TestState>>({});
  const queryClient = useQueryClient();

  const sseRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const token = getToken();
    if (!token) return;
    const url = `${BASE}/api/alerts/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);
    sseRef.current = es;
    es.onmessage = () => {
      queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
    };
    es.onerror = () => {
      es.close();
      sseRef.current = null;
    };
    return () => {
      es.close();
      sseRef.current = null;
    };
  }, []);

  const alertParams = { severity: severityFilter || undefined };
  const { data: alerts, isLoading } = useListAlerts(alertParams as any, {
    query: {
      queryKey: getListAlertsQueryKey(alertParams as any),
      refetchInterval: 60_000,
      staleTime: 0,
    },
  });
  const { data: rules } = useListAlertRules({
    query: { queryKey: getListAlertRulesQueryKey() },
  });
  const updateAlert = useUpdateAlert();
  const createRule = useCreateAlertRule();
  const updateRule = useUpdateAlertRule();
  const deleteRule = useDeleteAlertRule();

  const markRead = async (id: number) => {
    await updateAlert.mutateAsync({ alertId: id, data: { isRead: true } });
    queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
  };

  const markAllRead = async () => {
    for (const a of unreadAlerts) {
      await updateAlert.mutateAsync({ alertId: a.id, data: { isRead: true } });
    }
    queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    await createRule.mutateAsync({ data: ruleForm } as any);
    queryClient.invalidateQueries({ queryKey: getListAlertRulesQueryKey() });
    setShowCreateRule(false);
    setRuleForm({ name: "", triggerType: "new_finding", channel: "email", destination: "" });
  };

  const handleToggleRule = async (rule: any) => {
    await updateRule.mutateAsync({ ruleId: rule.id, data: { isActive: !rule.isActive } });
    queryClient.invalidateQueries({ queryKey: getListAlertRulesQueryKey() });
  };

  const handleDeleteRule = async (ruleId: number) => {
    if (!confirm("Delete this alert rule?")) return;
    await deleteRule.mutateAsync({ ruleId });
    queryClient.invalidateQueries({ queryKey: getListAlertRulesQueryKey() });
  };

  const handleTestRule = async (rule: any) => {
    setTestStates(prev => ({ ...prev, [rule.id]: { status: "testing" } }));
    try {
      const result = await apiFetch<{ success: boolean; channel: string; destination: string }>(
        `${BASE}/api/alerts/rules/${rule.id}/test`,
        { method: "POST" },
      );
      if (result.success) {
        setTestStates(prev => ({ ...prev, [rule.id]: { status: "ok", dest: result.destination } }));
        toast({ title: "Test sent!", description: `${capitalize(result.channel)} notification delivered successfully.` });
        setTimeout(() => setTestStates(prev => ({ ...prev, [rule.id]: { status: "idle" } })), 4000);
      }
    } catch (err: any) {
      const msg = err?.message ?? "Delivery failed. Check your destination URL or credentials.";
      setTestStates(prev => ({ ...prev, [rule.id]: { status: "error", msg } }));
      toast({ title: "Test failed", description: msg, variant: "destructive" });
      setTimeout(() => setTestStates(prev => ({ ...prev, [rule.id]: { status: "idle" } })), 6000);
    }
  };

  const alertList = alerts as any[] ?? [];
  const unreadAlerts = alertList.filter((a: any) => !a.isRead);
  const archivedAlerts = alertList.filter((a: any) => a.isRead);
  const unreadCount = unreadAlerts.length;

  const filteredUnread = severityFilter
    ? unreadAlerts.filter((a: any) => a.severity === severityFilter)
    : unreadAlerts;
  const filteredArchive = severityFilter
    ? archivedAlerts.filter((a: any) => a.severity === severityFilter)
    : archivedAlerts;

  const archiveTotalPages = Math.max(1, Math.ceil(filteredArchive.length / ARCHIVE_PAGE_SIZE));
  const archivePaged = filteredArchive.slice(archivePage * ARCHIVE_PAGE_SIZE, (archivePage + 1) * ARCHIVE_PAGE_SIZE);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Alerts</h1>
          <p className="text-sm text-muted-foreground">
            {unreadCount} unread · {archivedAlerts.length} archived
          </p>
        </div>
      </div>

      <Tabs defaultValue="inbox">
        <TabsList className="h-8">
          <TabsTrigger value="inbox" className="text-xs gap-1.5">
            <Inbox className="w-3 h-3" />
            Inbox
            {unreadCount > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-primary text-primary-foreground text-[10px] font-semibold leading-none">
                {unreadCount}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="archive" className="text-xs gap-1.5">
            <Archive className="w-3 h-3" />
            Archive
            {archivedAlerts.length > 0 && (
              <span className="ml-1 px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground text-[10px] font-semibold leading-none">
                {archivedAlerts.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="rules" className="text-xs">Alert Rules</TabsTrigger>
        </TabsList>

        {/* ── Inbox — unread alerts ─────────────────────────────── */}
        <TabsContent value="inbox" className="space-y-3 mt-3">
          <div className="flex gap-2 items-center">
            <Select value={severityFilter || "_all_"} onValueChange={(v) => setSeverityFilter(v === "_all_" ? "" : v)}>
              <SelectTrigger className="w-32 h-7 text-xs"><SelectValue placeholder="All severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="_all_">All</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            {unreadCount > 0 && (
              <Button
                variant="outline" size="sm" className="h-7 text-xs"
                onClick={markAllRead}
                disabled={updateAlert.isPending}
              >
                <BellOff className="w-3 h-3 mr-1" /> Mark all read
              </Button>
            )}
          </div>

          {isLoading && [...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}

          {!isLoading && filteredUnread.map((alert: any) => (
            <div
              key={alert.id}
              className="bg-card border border-primary/30 rounded-xl p-4 transition-all cursor-pointer hover:border-primary/50 hover:bg-accent/10 group"
              onClick={() => { markRead(alert.id); navigate(`/alerts/${alert.id}`); }}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5 flex-1 min-w-0">
                  <AlertTypeIcon type={alert.type} className="w-4 h-4 shrink-0 mt-0.5" />
                  <div className="w-2 h-2 rounded-full bg-primary mt-1.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium shrink-0", severityBgColor(alert.severity))}>{alert.severity}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{alert.message}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">{formatDateTime(alert.createdAt)}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <Button
                    variant="ghost" size="icon" className="h-7 w-7"
                    onClick={(e) => { e.stopPropagation(); markRead(alert.id); }}
                    title="Archive (mark as read)"
                  >
                    <Archive className="w-3.5 h-3.5" />
                  </Button>
                  <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors" />
                </div>
              </div>
            </div>
          ))}

          {!isLoading && filteredUnread.length === 0 && (
            <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
              <CheckCircle2 className="w-8 h-8 text-green-400 mx-auto mb-2" />
              Inbox is clear — no unread alerts.
            </div>
          )}
        </TabsContent>

        {/* ── Archive — read alerts with pagination ────────────── */}
        <TabsContent value="archive" className="space-y-3 mt-3">
          <div className="flex gap-2 items-center justify-between">
            <Select value={severityFilter || "_all_"} onValueChange={(v) => { setSeverityFilter(v === "_all_" ? "" : v); setArchivePage(0); }}>
              <SelectTrigger className="w-32 h-7 text-xs"><SelectValue placeholder="All severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="_all_">All</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              {filteredArchive.length} archived alert{filteredArchive.length !== 1 ? "s" : ""}
            </p>
          </div>

          {isLoading && [...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}

          {!isLoading && archivePaged.map((alert: any) => (
            <div
              key={alert.id}
              className="bg-card border border-border rounded-xl p-4 transition-all cursor-pointer hover:border-primary/30 hover:bg-accent/10 group opacity-75 hover:opacity-100"
              onClick={() => navigate(`/alerts/${alert.id}`)}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5 flex-1 min-w-0">
                  <AlertTypeIcon type={alert.type} className="w-4 h-4 shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium shrink-0", severityBgColor(alert.severity))}>{alert.severity}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{alert.message}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">{formatDateTime(alert.createdAt)}</p>
                  </div>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors shrink-0" />
              </div>
            </div>
          ))}

          {!isLoading && filteredArchive.length === 0 && (
            <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">
              <Archive className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
              No archived alerts yet.
            </div>
          )}

          {archiveTotalPages > 1 && (
            <div className="flex items-center justify-between pt-1">
              <p className="text-xs text-muted-foreground">
                Page {archivePage + 1} of {archiveTotalPages}
              </p>
              <div className="flex gap-1">
                <Button
                  variant="outline" size="sm" className="h-7 text-xs"
                  disabled={archivePage === 0}
                  onClick={() => setArchivePage(p => p - 1)}
                >← Prev</Button>
                <Button
                  variant="outline" size="sm" className="h-7 text-xs"
                  disabled={archivePage >= archiveTotalPages - 1}
                  onClick={() => setArchivePage(p => p + 1)}
                >Next →</Button>
              </div>
            </div>
          )}
        </TabsContent>

        {/* ── Alert Rules ──────────────────────────────────────── */}
        <TabsContent value="rules" className="space-y-3 mt-3">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">Alert rules fire on matching scan events and deliver notifications to your configured channel.</p>
            <Button size="sm" onClick={() => setShowCreateRule(true)}>
              <Plus className="w-4 h-4 mr-1.5" /> New Rule
            </Button>
          </div>
          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Name</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Trigger</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Channel</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Destination</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                  <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(rules as any[] ?? []).map((rule: any) => {
                  const ts: TestState = testStates[rule.id] ?? { status: "idle" };
                  return (
                    <tr key={rule.id} className="border-b border-border/50 hover:bg-accent/20 transition-colors">
                      <td className="px-4 py-2.5 text-sm font-medium">{rule.name}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{capitalize(rule.triggerType.replace(/_/g, " "))}</td>
                      <td className="px-4 py-2.5 text-xs">
                        <span className="flex items-center gap-1">
                          {rule.channel === "email" && "📧"}
                          {rule.channel === "slack" && "💬"}
                          {rule.channel === "discord" && "🎮"}
                          {rule.channel === "telegram" && "✈️"}
                          {rule.channel === "webhook" && "🔗"}
                          {capitalize(rule.channel)}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono truncate max-w-[160px]" title={rule.destination ?? ""}>
                        {rule.destination ?? <span className="italic text-muted-foreground/50">platform default</span>}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className={cn(
                          "text-xs px-2 py-0.5 rounded-md border",
                          rule.isActive
                            ? "bg-green-500/15 text-green-400 border-green-500/30"
                            : "bg-muted text-muted-foreground border-border"
                        )}>
                          {rule.isActive ? "Active" : "Paused"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost" size="sm"
                            className={cn(
                              "h-7 px-2 text-xs gap-1",
                              ts.status === "ok" && "text-green-400 hover:text-green-400",
                              ts.status === "error" && "text-destructive hover:text-destructive",
                            )}
                            title="Send a test notification"
                            onClick={() => handleTestRule(rule)}
                            disabled={ts.status === "testing"}
                          >
                            {ts.status === "testing" && <Loader2 className="w-3 h-3 animate-spin" />}
                            {ts.status === "ok" && <CheckCircle2 className="w-3 h-3" />}
                            {ts.status === "error" && <XCircle className="w-3 h-3" />}
                            {ts.status === "idle" && <FlaskConical className="w-3 h-3" />}
                            {ts.status === "testing" ? "Sending…" : ts.status === "ok" ? "Sent!" : ts.status === "error" ? "Failed" : "Test"}
                          </Button>
                          <Button
                            variant="ghost" size="icon" className="h-7 w-7"
                            title={rule.isActive ? "Pause rule" : "Activate rule"}
                            onClick={() => handleToggleRule(rule)}
                            disabled={updateRule.isPending}
                          >
                            <Power className={cn("w-3.5 h-3.5", rule.isActive ? "text-green-400" : "text-muted-foreground")} />
                          </Button>
                          <Button
                            variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                            title="Delete rule"
                            onClick={() => handleDeleteRule(rule.id)}
                            disabled={deleteRule.isPending}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
                {(rules as any[] ?? []).length === 0 && (
                  <tr><td colSpan={6} className="px-4 py-8 text-center text-sm text-muted-foreground">No alert rules configured. Create one to start receiving notifications.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </TabsContent>
      </Tabs>

      <Dialog open={showCreateRule} onOpenChange={setShowCreateRule}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Alert Rule</DialogTitle></DialogHeader>
          <form onSubmit={handleCreateRule} className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Rule Name</Label>
              <Input value={ruleForm.name} onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))} required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Trigger Type</Label>
              <Select value={ruleForm.triggerType} onValueChange={v => setRuleForm(p => ({ ...p, triggerType: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="any">Any Event</SelectItem>
                  <SelectItem value="new_finding">New Finding</SelectItem>
                  <SelectItem value="critical_finding">Critical Finding</SelectItem>
                  <SelectItem value="high_finding">High Finding</SelectItem>
                  <SelectItem value="scan_complete">Scan Complete</SelectItem>
                  <SelectItem value="brand_threat">Any Brand Threat</SelectItem>
                  <SelectItem value="phishing_detected">🎣 Phishing Detected</SelectItem>
                  <SelectItem value="data_leak_found">💧 Data Leak Found</SelectItem>
                  <SelectItem value="brand_abuse_found">🎯 Brand Abuse Found</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Notification Channel</Label>
              <Select value={ruleForm.channel} onValueChange={v => setRuleForm(p => ({ ...p, channel: v, destination: "" }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="email">📧 Email</SelectItem>
                  <SelectItem value="slack">💬 Slack</SelectItem>
                  <SelectItem value="discord">🎮 Discord</SelectItem>
                  <SelectItem value="telegram">✈️ Telegram</SelectItem>
                  <SelectItem value="webhook">🔗 Webhook (Generic HTTP)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Destination</Label>
              <Input
                value={ruleForm.destination}
                onChange={e => setRuleForm(p => ({ ...p, destination: e.target.value }))}
                placeholder={CHANNEL_PLACEHOLDER[ruleForm.channel] ?? ""}
                className="h-9"
              />
              {ruleForm.channel === "telegram" && (
                <p className="text-[11px] text-muted-foreground">Format: <code className="bg-muted px-1 rounded">BOT_TOKEN:CHAT_ID</code>. Get a token from @BotFather and find your chat ID from @userinfobot.</p>
              )}
              {ruleForm.channel === "webhook" && (
                <p className="text-[11px] text-muted-foreground">Sentinelware will POST a JSON payload to this URL on every matching event.</p>
              )}
              {ruleForm.channel === "slack" && (
                <p className="text-[11px] text-muted-foreground">Create an Incoming Webhook in your Slack workspace and paste the URL here.</p>
              )}
              {ruleForm.channel === "email" && (
                <p className="text-[11px] text-muted-foreground">Requires Resend API key or SMTP configured in Platform Settings.</p>
              )}
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreateRule(false)}>Cancel</Button>
              <Button type="submit" disabled={createRule.isPending}>
                {createRule.isPending ? "Creating…" : "Create Rule"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
