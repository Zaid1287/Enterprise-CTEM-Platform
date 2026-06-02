import { useState } from "react";
import {
  useListAlerts, useUpdateAlert, useListAlertRules, useCreateAlertRule,
  getListAlertsQueryKey, getListAlertRulesQueryKey,
} from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Bell, BellOff, Settings2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { cn, severityBgColor, capitalize, formatDateTime } from "@/lib/utils";

export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState("");
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [ruleForm, setRuleForm] = useState({ name: "", triggerType: "new_vulnerability", channel: "email", destination: "" });
  const queryClient = useQueryClient();

  const alertParams = { severity: severityFilter || undefined };
  const { data: alerts, isLoading } = useListAlerts(alertParams as any, {
    query: { queryKey: getListAlertsQueryKey(alertParams as any) },
  });
  const { data: rules } = useListAlertRules({
    query: { queryKey: getListAlertRulesQueryKey() },
  });
  const updateAlert = useUpdateAlert();
  const createRule = useCreateAlertRule();

  const markRead = async (id: number) => {
    await updateAlert.mutateAsync({ alertId: id, data: { isRead: true } });
    queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    await createRule.mutateAsync({ data: ruleForm } as any);
    queryClient.invalidateQueries({ queryKey: getListAlertRulesQueryKey() });
    setShowCreateRule(false);
    setRuleForm({ name: "", triggerType: "new_vulnerability", channel: "email", destination: "" });
  };

  const alertList = alerts as any[] ?? [];
  const unread = alertList.filter((a: any) => !a.isRead).length;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">Alerts</h1>
          <p className="text-sm text-muted-foreground">{unread} unread of {alertList.length} total</p>
        </div>
      </div>

      <Tabs defaultValue="inbox">
        <TabsList className="h-8">
          <TabsTrigger value="inbox" className="text-xs">Inbox</TabsTrigger>
          <TabsTrigger value="rules" className="text-xs">Alert Rules</TabsTrigger>
        </TabsList>

        <TabsContent value="inbox" className="space-y-3 mt-3">
          <div className="flex gap-2">
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
            <Button
              variant="outline" size="sm" className="h-7 text-xs"
              onClick={async () => {
                for (const a of alertList.filter((x: any) => !x.isRead)) {
                  await updateAlert.mutateAsync({ alertId: a.id, data: { isRead: true } });
                }
                queryClient.invalidateQueries({ queryKey: getListAlertsQueryKey() });
              }}
            >
              <BellOff className="w-3 h-3 mr-1" /> Mark all read
            </Button>
          </div>

          {isLoading && [...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}
          {!isLoading && alertList.map((alert: any) => (
            <div
              key={alert.id}
              className={cn(
                "bg-card border rounded-xl p-4 transition-all",
                !alert.isRead ? "border-primary/30" : "border-border opacity-60"
              )}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-2.5 flex-1 min-w-0">
                  {!alert.isRead && <div className="w-2 h-2 rounded-full bg-primary mt-1.5 shrink-0" />}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-0.5">
                      <p className="text-sm font-medium truncate">{alert.title}</p>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded font-medium shrink-0", severityBgColor(alert.severity))}>{alert.severity}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{alert.message}</p>
                    <p className="text-[10px] text-muted-foreground mt-1">{formatDateTime(alert.createdAt)}</p>
                  </div>
                </div>
                {!alert.isRead && (
                  <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={() => markRead(alert.id)}>
                    <Bell className="w-3.5 h-3.5" />
                  </Button>
                )}
              </div>
            </div>
          ))}
          {!isLoading && alertList.length === 0 && (
            <div className="bg-card border border-border rounded-xl p-8 text-center text-sm text-muted-foreground">No alerts.</div>
          )}
        </TabsContent>

        <TabsContent value="rules" className="space-y-3 mt-3">
          <div className="flex justify-end">
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
                </tr>
              </thead>
              <tbody>
                {(rules as any[] ?? []).map((rule: any) => (
                  <tr key={rule.id} className="border-b border-border/50">
                    <td className="px-4 py-2.5 text-sm font-medium">{rule.name}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{capitalize(rule.triggerType)}</td>
                    <td className="px-4 py-2.5 text-xs">{capitalize(rule.channel)}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{rule.destination ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <span className={cn("text-xs px-2 py-0.5 rounded-md", rule.isActive ? "bg-green-500/15 text-green-400 border border-green-500/30" : "bg-muted text-muted-foreground border border-border")}>
                        {rule.isActive ? "Active" : "Inactive"}
                      </span>
                    </td>
                  </tr>
                ))}
                {(rules as any[] ?? []).length === 0 && (
                  <tr><td colSpan={5} className="px-4 py-8 text-center text-sm text-muted-foreground">No alert rules configured.</td></tr>
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
                  <SelectItem value="new_vulnerability">New Vulnerability</SelectItem>
                  <SelectItem value="critical_exposure">Critical Exposure</SelectItem>
                  <SelectItem value="ssl_expiry">SSL Expiry</SelectItem>
                  <SelectItem value="new_asset">New Asset</SelectItem>
                  <SelectItem value="compliance_failure">Compliance Failure</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Notification Channel</Label>
              <Select value={ruleForm.channel} onValueChange={v => setRuleForm(p => ({ ...p, channel: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="email">Email</SelectItem>
                  <SelectItem value="slack">Slack</SelectItem>
                  <SelectItem value="discord">Discord</SelectItem>
                  <SelectItem value="webhook">Webhook</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Destination</Label>
              <Input value={ruleForm.destination} onChange={e => setRuleForm(p => ({ ...p, destination: e.target.value }))} placeholder="Email address or webhook URL" className="h-9" />
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreateRule(false)}>Cancel</Button>
              <Button type="submit" disabled={createRule.isPending}>Create Rule</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
