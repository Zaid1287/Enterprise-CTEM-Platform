import { useState, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Building2, Users, Server, Bug, ChevronDown, ChevronUp, UserCheck, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface TenantRow {
  id: number;
  name: string;
  slug: string;
  plan: string;
  isActive: boolean;
  createdAt: string;
  userCount: number;
  assetCount: number;
  findingCount: number;
  criticalCount: number;
  openFindingCount: number;
  assignedManagers: Array<{ id: number; name: string; email: string }>;
}

interface UserRow {
  id: number;
  firstName: string | null;
  lastName: string | null;
  email: string;
  role: string;
}

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PLANS = ["starter", "professional", "enterprise"];
const emptyForm = { name: "", slug: "", plan: "starter" };

export default function TenantsPage() {
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [assignTarget, setAssignTarget] = useState<{ tenantId: number; tenantName: string } | null>(null);
  const [selectedAmId, setSelectedAmId] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: tenants = [], isLoading } = useQuery<TenantRow[]>({
    queryKey: ["platform-tenants"],
    queryFn: () => apiFetch(`${BASE}/api/tenants`),
  });

  const { data: allUsers = [] } = useQuery<UserRow[]>({
    queryKey: ["platform-users"],
    queryFn: () => apiFetch(`${BASE}/api/users`),
  });

  const amUsers = allUsers.filter(u => u.role === "account_manager");

  const createMutation = useMutation({
    mutationFn: (body: object) => apiFetch(`${BASE}/api/tenants`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setShowCreate(false);
      setForm(emptyForm);
      toast({ title: "Tenant created" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const assignMutation = useMutation({
    mutationFn: ({ tenantId, accountManagerUserId }: { tenantId: number; accountManagerUserId: number }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}/managers`, {
        method: "POST",
        body: JSON.stringify({ accountManagerUserId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setAssignTarget(null);
      setSelectedAmId("");
      toast({ title: "Account manager assigned" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const unassignMutation = useMutation({
    mutationFn: ({ tenantId, amUserId }: { tenantId: number; amUserId: number }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}/managers/${amUserId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      toast({ title: "Account manager unassigned" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const totalAssets = tenants.reduce((s, t) => s + t.assetCount, 0);
  const totalFindings = tenants.reduce((s, t) => s + t.findingCount, 0);
  const activeTenants = tenants.filter(t => t.isActive).length;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">All Tenants</h1>
          <p className="text-sm text-muted-foreground">{tenants.length} client organizations · {activeTenants} active</p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> New Tenant
        </Button>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total Tenants", value: tenants.length, icon: Building2, color: "text-purple-400" },
          { label: "Total Assets", value: totalAssets, icon: Server, color: "text-blue-400" },
          { label: "Total Findings", value: totalFindings, icon: Bug, color: "text-amber-400" },
        ].map(k => (
          <div key={k.label} className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
            <k.icon className={cn("w-6 h-6 shrink-0", k.color)} />
            <div>
              <p className="text-xl font-bold">{k.value}</p>
              <p className="text-xs text-muted-foreground">{k.label}</p>
            </div>
          </div>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Tenant</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Users</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Findings</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {tenants.map(t => (
                <Fragment key={t.id}>
                  <tr
                    className={cn("border-b border-border/50 hover:bg-accent/30 cursor-pointer", expandedId === t.id && "bg-accent/20")}
                    onClick={() => setExpandedId(expandedId === t.id ? null : t.id)}
                  >
                    <td className="px-4 py-2.5">
                      <div className="font-medium">{t.name}</div>
                      <div className="text-xs text-muted-foreground">ID: {t.id} · {t.slug}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                    </td>
                    <td className="px-4 py-2.5">{t.userCount}</td>
                    <td className="px-4 py-2.5">{t.assetCount}</td>
                    <td className="px-4 py-2.5">{t.openFindingCount ?? t.findingCount}</td>
                    <td className="px-4 py-2.5">
                      {t.criticalCount > 0
                        ? <span className="text-red-400 font-semibold">{t.criticalCount}</span>
                        : <span className="text-muted-foreground">0</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                        t.isActive
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : "bg-muted text-muted-foreground border-border")}>
                        {t.isActive ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">
                      {expandedId === t.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </td>
                  </tr>

                  {expandedId === t.id && (
                    <tr className="border-b border-border/50 bg-accent/10">
                      <td colSpan={8} className="px-6 py-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 flex items-center gap-1.5">
                              <UserCheck className="w-3.5 h-3.5" /> Account Managers
                            </p>
                            {t.assignedManagers.length === 0 ? (
                              <p className="text-xs text-muted-foreground/70 italic">No account managers assigned to this tenant.</p>
                            ) : (
                              <div className="space-y-1.5">
                                {t.assignedManagers.map((m: any) => (
                                  <div key={m.id} className="flex items-center gap-2 text-xs">
                                    <div className="w-6 h-6 rounded-full bg-blue-500/15 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                                      <span className="text-[10px] font-bold text-blue-400">{(m.name || m.email).charAt(0).toUpperCase()}</span>
                                    </div>
                                    <span className="font-medium">{m.name}</span>
                                    <span className="text-muted-foreground">·</span>
                                    <span className="text-muted-foreground">{m.email}</span>
                                    <button
                                      onClick={e => { e.stopPropagation(); unassignMutation.mutate({ tenantId: t.id, amUserId: m.id }); }}
                                      className="ml-auto p-0.5 rounded hover:bg-red-500/15 text-muted-foreground hover:text-red-400 transition-colors"
                                      title="Unassign"
                                    >
                                      <X className="w-3.5 h-3.5" />
                                    </button>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            className="text-xs h-7 shrink-0"
                            onClick={e => { e.stopPropagation(); setAssignTarget({ tenantId: t.id, tenantName: t.name }); setSelectedAmId(""); }}
                          >
                            <Plus className="w-3.5 h-3.5 mr-1" /> Assign Manager
                          </Button>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {tenants.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-8 text-center text-muted-foreground text-sm">No client tenants yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Create Tenant Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Client Tenant</DialogTitle></DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => { e.preventDefault(); createMutation.mutate(form); }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Organization Name</Label>
              <Input value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} required className="h-9" />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Slug (unique identifier)</Label>
              <Input
                value={form.slug}
                onChange={e => setForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/\s+/g, "-") }))}
                required className="h-9" placeholder="acme-corp"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Plan</Label>
              <Select value={form.plan} onValueChange={v => setForm(p => ({ ...p, plan: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PLANS.map(pl => <SelectItem key={pl} value={pl} className="capitalize">{pl}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createMutation.isPending}>{createMutation.isPending ? "Creating..." : "Create Tenant"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Assign Account Manager Dialog */}
      <Dialog open={!!assignTarget} onOpenChange={open => { if (!open) { setAssignTarget(null); setSelectedAmId(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Account Manager</DialogTitle>
            <p className="text-sm text-muted-foreground">Select an account manager to assign to <span className="font-medium text-foreground">{assignTarget?.tenantName}</span></p>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {amUsers.length === 0 ? (
              <p className="text-sm text-muted-foreground italic">No account manager users found. Create a user with the account_manager role first.</p>
            ) : (
              <div className="space-y-1.5">
                <Label className="text-xs">Account Manager</Label>
                <Select value={selectedAmId} onValueChange={setSelectedAmId}>
                  <SelectTrigger className="h-9">
                    <SelectValue placeholder="Select account manager..." />
                  </SelectTrigger>
                  <SelectContent>
                    {amUsers.map(u => (
                      <SelectItem key={u.id} value={String(u.id)}>
                        {u.firstName || u.lastName ? `${u.firstName ?? ""} ${u.lastName ?? ""}`.trim() : u.email} — {u.email}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => { setAssignTarget(null); setSelectedAmId(""); }}>Cancel</Button>
            <Button
              disabled={!selectedAmId || assignMutation.isPending}
              onClick={() => {
                if (!assignTarget || !selectedAmId) return;
                assignMutation.mutate({ tenantId: assignTarget.tenantId, accountManagerUserId: Number(selectedAmId) });
              }}
            >
              {assignMutation.isPending ? "Assigning..." : "Assign"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
