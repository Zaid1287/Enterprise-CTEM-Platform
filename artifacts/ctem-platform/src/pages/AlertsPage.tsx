import { useState, useEffect, useRef, useCallback } from "react";
import { useLocation } from "wouter";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  useListAlerts, useUpdateAlert, useListAlertRules, useCreateAlertRule,
  useUpdateAlertRule, useDeleteAlertRule, useListAssetGroups,
  getListAlertsQueryKey, getListAlertRulesQueryKey, getListAssetGroupsQueryKey,
} from "@workspace/api-client-react";
import { useAuth } from "@/hooks/useAuth";
import { TenantFilter } from "@/components/TenantFilter";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Bell, BellOff, ChevronRight, Trash2, Power, FlaskConical, CheckCircle2, XCircle, Loader2, ShieldAlert, DatabaseZap, Crosshair, ScanSearch, AlertTriangle, Activity, Archive, Inbox, Brain, Sparkles, RefreshCw, X } from "lucide-react";
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
  const [tenantFilter, setTenantFilter] = useState<number | null>(null);
  const [archivePage, setArchivePage] = useState(0);
  const { user } = useAuth();
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [ruleForm, setRuleForm] = useState<{ name: string; triggerType: string; channel: string; destination: string; groupId: number | null }>({ name: "", triggerType: "new_finding", channel: "email", destination: "", groupId: null });
  const [testStates, setTestStates] = useState<Record<number, TestState>>({});
  const queryClient = useQueryClient();

  // ── AI explain-alert state (per alert) ───────────────────────────────────
  const [aiAlertOpen, setAiAlertOpen] = useState<Record<number, boolean>>({});
  const [aiAlertText, setAiAlertText] = useState<Record<number, string>>({});
  const [aiAlertLoading, setAiAlertLoading] = useState<Record<number, boolean>>({});
  const [aiAlertNoKey, setAiAlertNoKey] = useState<Record<number, boolean>>({});

  const triggerAlertExplain = useCallback(async (alertId: number) => {
    if (aiAlertLoading[alertId]) return;
    setAiAlertText(p => ({ ...p, [alertId]: "" }));
    setAiAlertLoading(p => ({ ...p, [alertId]: true }));
    setAiAlertNoKey(p => ({ ...p, [alertId]: false }));
    const token = sessionStorage.getItem("ctem_token") ?? "";
    let accumulated = "";
    try {
      const resp = await fetch(`${BASE}/api/ai/stream`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ action: "explain-alert", alertId }),
      });
      if (!resp.body) throw new Error("No stream");
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n"); buf = lines.pop() ?? "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const d = JSON.parse(line.slice(6));
            if (d.noKey) setAiAlertNoKey(p => ({ ...p, [alertId]: true }));
            if (d.text) { accumulated += d.text; setAiAlertText(p => ({ ...p, [alertId]: accumulated })); }
          } catch { /* ignore */ }
        }
      }
    } catch { setAiAlertText(p => ({ ...p, [alertId]: accumulated || "Failed to generate analysis. Please try again." })); }
    setAiAlertLoading(p => ({ ...p, [alertId]: false }));
  }, [aiAlertLoading, BASE]);

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

  const isPrivileged = user?.role === "super_admin" || user?.role === "admin";
  const alertParams = {
    severity: severityFilter || undefined,
    ...(isPrivileged && tenantFilter ? { tenantId: tenantFilter } : {}),
  };
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
  const { data: groups } = useListAssetGroups({
    query: { queryKey: getListAssetGroupsQueryKey() },
  });
  const groupList = (groups as any[]) ?? [];
  const updateAlert = useUpdateAlert();
  const createRule = useCreateAlertRule();
  const updateRule = useUpdateAlertRule();
  const deleteRule = useDeleteAlertRule();

  const invalidateDashboards = () => {
    queryClient.invalidateQueries({ queryKey: ["platform-overview"] });
    queryClient.invalidateQueries({ queryKey: ["admin-overview"] });
    queryClient.invalidateQueries({ queryKey: ["am-overview"] });
    queryClient.invalidateQueries({ queryKey: ["dash-overview"] });
  };

  const markRead = async (id: number) => {
    await updateAlert.mutateAsync({ alertId: id, data: { isRead: true } });
    queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
    invalidateDashboards();
  };

  const markAllRead = async () => {
    for (const a of unreadAlerts) {
      await updateAlert.mutateAsync({ alertId: a.id, data: { isRead: true } });
    }
    queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
    invalidateDashboards();
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    await createRule.mutateAsync({ data: ruleForm } as any);
    queryClient.invalidateQueries({ queryKey: getListAlertRulesQueryKey() });
    setShowCreateRule(false);
    setRuleForm({ name: "", triggerType: "new_finding", channel: "email", destination: "", groupId: null });
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
        {isPrivileged && <TenantFilter value={tenantFilter} onChange={(t) => { setTenantFilter(t); setArchivePage(0); }} />}
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
              className="bg-card border border-primary/30 rounded-xl p-4 transition-all hover:border-primary/50 hover:bg-accent/10 group"
            >
              <div
                className="flex items-start justify-between gap-3 cursor-pointer"
                onClick={() => { markRead(alert.id); navigate(`/alerts/${alert.id}`); }}
              >
                <div className="flex items-start gap-2.5 flex-1 min-w-0">
                  <AlertTypeIcon type={alert.type} className="w-4 h-4 shrink-0 mt-0.5" />
                  <div className="w-2 h-2 rounded-full bg-primary mt-1.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium shrink-0", severityBgColor(alert.severity))}>{alert.severity}</span>
                      {isPrivileged && !tenantFilter && alert.tenantName && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-medium shrink-0">{alert.tenantName}</span>
                      )}
                      {isPrivileged && !tenantFilter && (alert.tenantCount ?? 1) > 1 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 font-medium shrink-0">{alert.tenantCount} tenants</span>
                      )}
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
                  <Button
                    variant="ghost" size="icon" className="h-7 w-7"
                    onClick={(e) => {
                      e.stopPropagation();
                      const isOpen = !aiAlertOpen[alert.id];
                      setAiAlertOpen(p => ({ ...p, [alert.id]: isOpen }));
                      if (isOpen && !aiAlertText[alert.id]) triggerAlertExplain(alert.id);
                    }}
                    title="AI Explain Alert"
                  >
                    <Brain className={cn("w-3.5 h-3.5", aiAlertOpen[alert.id] ? "text-primary" : "text-muted-foreground/60")} />
                  </Button>
                  <ChevronRight className="w-4 h-4 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors cursor-pointer" onClick={() => { markRead(alert.id); navigate(`/alerts/${alert.id}`); }} />
                </div>
              </div>
              {/* AI Explain Panel */}
              {aiAlertOpen[alert.id] && (
                <div className="mt-3 bg-muted/20 border border-primary/20 rounded-lg p-3 space-y-2" onClick={e => e.stopPropagation()}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <Brain className="w-3.5 h-3.5 text-primary" />
                      <span className="text-xs font-semibold">AI Alert Analysis</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        className="text-muted-foreground hover:text-foreground transition-colors"
                        onClick={() => { setAiAlertText(p => ({ ...p, [alert.id]: "" })); triggerAlertExplain(alert.id); }}
                        disabled={aiAlertLoading[alert.id]}
                        title="Regenerate"
                      >
                        <RefreshCw className={cn("w-3 h-3", aiAlertLoading[alert.id] && "animate-spin")} />
                      </button>
                      <button
                        className="text-muted-foreground hover:text-foreground transition-colors"
                        onClick={() => setAiAlertOpen(p => ({ ...p, [alert.id]: false }))}
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                  {aiAlertNoKey[alert.id] && (
                    <div className="flex items-center gap-1.5 text-[10px] text-amber-400/80 bg-amber-500/10 border border-amber-500/20 rounded px-2 py-1">
                      <AlertTriangle className="w-3 h-3 shrink-0" />
                      Template response — <a href="/settings/account" className="underline ml-0.5">add an API key</a> for real AI analysis.
                    </div>
                  )}
                  <div className="text-xs text-muted-foreground">
                    {aiAlertLoading[alert.id] && !aiAlertText[alert.id] ? (
                      <div className="space-y-1.5">
                        <Skeleton className="h-2.5 w-3/4" />
                        <Skeleton className="h-2.5 w-full" />
                        <Skeleton className="h-2.5 w-5/6" />
                        <div className="flex items-center gap-1 text-[10px] text-muted-foreground/50 mt-2">
                          <Sparkles className="w-3 h-3 animate-pulse text-primary" />
                          Analysing alert…
                        </div>
                      </div>
                    ) : (
                      <>
                        <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
                          h2: ({ children }) => <h2 className="text-xs font-bold mt-2 mb-1 text-foreground">{children}</h2>,
                          h3: ({ children }) => <h3 className="text-[11px] font-semibold mt-1.5 mb-0.5 text-foreground/90">{children}</h3>,
                          p: ({ children }) => <p className="text-[11px] text-muted-foreground mb-1.5 leading-relaxed">{children}</p>,
                          ul: ({ children }) => <ul className="list-disc pl-4 space-y-0.5 mb-1.5">{children}</ul>,
                          li: ({ children }) => <li className="text-[11px] text-muted-foreground">{children}</li>,
                          strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
                        }}>{aiAlertText[alert.id]}</ReactMarkdown>
                        {aiAlertLoading[alert.id] && <span className="inline-block w-1.5 h-3 bg-primary/70 animate-pulse ml-0.5 rounded-sm" />}
                      </>
                    )}
                  </div>
                </div>
              )}
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
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium shrink-0", severityBgColor(alert.severity))}>{alert.severity}</span>
                      {isPrivileged && !tenantFilter && alert.tenantName && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-medium shrink-0">{alert.tenantName}</span>
                      )}
                      {isPrivileged && !tenantFilter && (alert.tenantCount ?? 1) > 1 && (
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 font-medium shrink-0">{alert.tenantCount} tenants</span>
                      )}
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
            {/* Group scope filter */}
            {groupList.length > 0 && (
              <div className="space-y-1.5">
                <Label className="text-xs">Scope to Group (optional)</Label>
                <Select value={ruleForm.groupId ? String(ruleForm.groupId) : ""} onValueChange={v => setRuleForm(p => ({ ...p, groupId: v ? Number(v) : null }))}>
                  <SelectTrigger className="h-9"><SelectValue placeholder="All assets (no group filter)" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">All assets</SelectItem>
                    {groupList.map((g: any) => (
                      <SelectItem key={g.id} value={String(g.id)}>{g.name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {ruleForm.groupId && (
                  <p className="text-[10px] text-muted-foreground">Rule will only fire for assets in the selected group.</p>
                )}
              </div>
            )}

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
