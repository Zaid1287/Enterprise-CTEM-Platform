import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { Plus, Trash2, AlertTriangle, Shield, Server, Bug, Activity } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

interface ClientMetric {
  tenantId: number;
  tenantName: string;
  plan: string;
  isActive: boolean;
  assetCount: number;
  findingCount: number;
  criticalCount: number;
  openFindingCount: number;
  activeScans: number;
  assignedAt: string | null;
}

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

export default function MyClientsPage() {
  const { user } = useAuth();
  const [showAssign, setShowAssign] = useState(false);
  const [tenantId, setTenantId] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: clients = [], isLoading } = useQuery<ClientMetric[]>({
    queryKey: ["am-clients"],
    queryFn: () => apiFetch(`${BASE}/api/account-manager/clients`),
  });

  const assignMutation = useMutation({
    mutationFn: (clientTenantId: number) =>
      apiFetch(`${BASE}/api/account-manager/clients`, { method: "POST", body: JSON.stringify({ clientTenantId }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["am-clients"] });
      setShowAssign(false);
      setTenantId("");
      toast({ title: "Client assigned" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const unassignMutation = useMutation({
    mutationFn: (clientTenantId: number) =>
      apiFetch(`${BASE}/api/account-manager/clients/${clientTenantId}`, { method: "DELETE" }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ["am-clients"] }); toast({ title: "Client unassigned" }); },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const totalAssets = clients.reduce((s, c) => s + c.assetCount, 0);
  const totalFindings = clients.reduce((s, c) => s + c.findingCount, 0);
  const totalCritical = clients.reduce((s, c) => s + c.criticalCount, 0);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">My Clients</h1>
          <p className="text-sm text-muted-foreground">{clients.length} assigned client tenant{clients.length !== 1 ? "s" : ""}</p>
        </div>
        <Button size="sm" onClick={() => setShowAssign(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> Assign Client
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total Assets", value: totalAssets, icon: Server, color: "text-blue-400" },
          { label: "Open Findings", value: totalFindings, icon: Bug, color: "text-amber-400" },
          { label: "Critical", value: totalCritical, icon: AlertTriangle, color: "text-red-400" },
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
          {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}
        </div>
      ) : clients.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
          <Shield className="w-10 h-10 mb-2 opacity-30" />
          <p className="text-sm">No clients assigned yet.</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Findings</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Active Scans</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {clients.map(c => (
                <tr key={c.tenantId} className="border-b border-border/50 hover:bg-accent/30">
                  <td className="px-4 py-2.5 font-medium">{c.tenantName}</td>
                  <td className="px-4 py-2.5">
                    <Badge variant="outline" className="text-xs capitalize">{c.plan}</Badge>
                  </td>
                  <td className="px-4 py-2.5">{c.assetCount}</td>
                  <td className="px-4 py-2.5">{c.openFindingCount}</td>
                  <td className="px-4 py-2.5">
                    {c.criticalCount > 0
                      ? <span className="text-red-400 font-semibold">{c.criticalCount}</span>
                      : <span className="text-muted-foreground">0</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    {c.activeScans > 0
                      ? <span className="flex items-center gap-1 text-blue-400"><Activity className="w-3 h-3" />{c.activeScans}</span>
                      : <span className="text-muted-foreground">—</span>}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn("text-xs px-2 py-0.5 rounded-md font-medium border",
                      c.isActive ? "bg-green-500/15 text-green-400 border-green-500/30" : "bg-muted text-muted-foreground border-border")}>
                      {c.isActive ? "Active" : "Inactive"}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                      onClick={() => confirm(`Unassign ${c.tenantName}?`) && unassignMutation.mutate(c.tenantId)}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={showAssign} onOpenChange={setShowAssign}>
        <DialogContent>
          <DialogHeader><DialogTitle>Assign Client Tenant</DialogTitle></DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => { e.preventDefault(); assignMutation.mutate(Number(tenantId)); }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Tenant ID</Label>
              <Input type="number" value={tenantId} onChange={e => setTenantId(e.target.value)} required min="1" className="h-9" placeholder="Enter the client tenant ID" />
              <p className="text-xs text-muted-foreground">Ask your Super Admin for the tenant ID of the client organization.</p>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowAssign(false)}>Cancel</Button>
              <Button type="submit" disabled={assignMutation.isPending}>{assignMutation.isPending ? "Assigning..." : "Assign"}</Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
