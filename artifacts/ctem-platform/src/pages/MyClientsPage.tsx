import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import {
  Plus, Trash2, AlertTriangle, Shield, Server, Bug, Activity,
  ChevronDown, ChevronRight, Globe, Cpu, Network, Link2, Key,
  Cloud, Smartphone, Lock, Database, Box,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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

interface AvailableTenant {
  id: number;
  name: string;
  plan: string;
  isActive: boolean;
}

interface AssetRow {
  id: number;
  name: string;
  type: string;
  value: string;
  riskLevel: string;
  verificationStatus: string;
  lastScannedAt: string | null;
  scanFrequency: string;
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  domain: Globe,
  subdomain: Network,
  ip: Cpu,
  url: Link2,
  api: Key,
  cloud_asset: Cloud,
  mobile_application: Smartphone,
  ssl_certificate: Lock,
  host: Database,
  cidr: Box,
};

const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border border-red-500/30",
  high: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
  medium: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30",
  low: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
  info: "bg-muted/60 text-muted-foreground border border-border/40",
};

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

function ClientAssetPanel({ tenantId }: { tenantId: number }) {
  const { data: list = [], isLoading: loading } = useQuery<AssetRow[]>({
    queryKey: ["tenant-assets", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${tenantId}/assets`),
    staleTime: 30_000,
  });

  if (loading) {
    return (
      <div className="space-y-1.5 py-2 px-4">
        {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-8 rounded" />)}
      </div>
    );
  }

  if (list.length === 0) {
    return (
      <div className="px-4 py-4 text-center text-muted-foreground text-xs">
        No assets in this client's inventory yet.
      </div>
    );
  }

  return (
    <div className="border-t border-border/40 bg-muted/10">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border/30">
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Asset</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Type</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Value</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Risk</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Verified</th>
            <th className="text-left px-4 py-2 text-muted-foreground font-medium">Frequency</th>
          </tr>
        </thead>
        <tbody>
          {list.map(a => {
            const Icon = TYPE_ICONS[a.type] ?? Globe;
            return (
              <tr key={a.id} className="border-b border-border/20 hover:bg-accent/10 transition-colors">
                <td className="px-4 py-2 font-medium flex items-center gap-1.5">
                  <Icon className="w-3 h-3 text-muted-foreground shrink-0" />
                  {a.name}
                </td>
                <td className="px-4 py-2 text-muted-foreground capitalize">{a.type.replace(/_/g, " ")}</td>
                <td className="px-4 py-2 font-mono text-muted-foreground max-w-[180px] truncate">{a.value}</td>
                <td className="px-4 py-2">
                  <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-medium capitalize", RISK_COLORS[a.riskLevel] ?? RISK_COLORS.info)}>
                    {a.riskLevel}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <span className={cn("text-[10px] font-medium", a.verificationStatus === "verified" ? "text-green-400" : "text-muted-foreground/50")}>
                    {a.verificationStatus === "verified" ? "✓ Verified" : "Unverified"}
                  </span>
                </td>
                <td className="px-4 py-2 capitalize text-muted-foreground">{a.scanFrequency}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function MyClientsPage() {
  const { user } = useAuth();
  const [showAssign, setShowAssign] = useState(false);
  const [selectedTenantId, setSelectedTenantId] = useState<string>("");
  const [unassignTarget, setUnassignTarget] = useState<{ id: number; name: string } | null>(null);
  const [expandedClients, setExpandedClients] = useState<Set<number>>(new Set());
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: clients = [], isLoading } = useQuery<ClientMetric[]>({
    queryKey: ["am-clients"],
    queryFn: () => apiFetch(`${BASE}/api/account-manager/clients`),
  });

  const { data: availableTenants = [], isLoading: loadingAvailable } = useQuery<AvailableTenant[]>({
    queryKey: ["am-available-tenants"],
    queryFn: () => apiFetch(`${BASE}/api/account-manager/available-tenants`),
    enabled: showAssign,
    staleTime: 0,
  });

  const assignMutation = useMutation({
    mutationFn: (clientTenantId: number) =>
      apiFetch(`${BASE}/api/account-manager/clients`, { method: "POST", body: JSON.stringify({ clientTenantId }) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["am-clients"] });
      queryClient.invalidateQueries({ queryKey: ["am-available-tenants"] });
      setShowAssign(false);
      setSelectedTenantId("");
      toast({ title: "Client assigned successfully" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const unassignMutation = useMutation({
    mutationFn: (clientTenantId: number) =>
      apiFetch(`${BASE}/api/account-manager/clients/${clientTenantId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["am-clients"] });
      queryClient.invalidateQueries({ queryKey: ["am-available-tenants"] });
      toast({ title: "Client unassigned" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const toggleExpand = (tenantId: number) => {
    setExpandedClients(prev => {
      const next = new Set(prev);
      if (next.has(tenantId)) next.delete(tenantId);
      else next.add(tenantId);
      return next;
    });
  };

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
          <p className="text-xs mt-1 opacity-60">Click "Assign Client" to link a client tenant to your account.</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="w-8 px-2 py-2.5" />
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Client</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Open Findings</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Active Scans</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {clients.map(c => {
                const expanded = expandedClients.has(c.tenantId);
                return (
                  <>
                    <tr
                      key={c.tenantId}
                      className={cn(
                        "border-b border-border/50 hover:bg-accent/20 transition-colors cursor-pointer",
                        expanded && "bg-accent/10",
                      )}
                      onClick={() => toggleExpand(c.tenantId)}
                    >
                      <td className="px-2 py-2.5 text-muted-foreground">
                        {expanded
                          ? <ChevronDown className="w-4 h-4" />
                          : <ChevronRight className="w-4 h-4" />}
                      </td>
                      <td className="px-4 py-2.5 font-medium">{c.tenantName}</td>
                      <td className="px-4 py-2.5">
                        <Badge variant="outline" className="text-xs capitalize">{c.plan}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="flex items-center gap-1">
                          <Server className="w-3 h-3 text-blue-400" />
                          {c.assetCount}
                        </span>
                      </td>
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
                          c.isActive
                            ? "bg-green-500/15 text-green-400 border-green-500/30"
                            : "bg-muted text-muted-foreground border-border")}>
                          {c.isActive ? "Active" : "Inactive"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                        <Button
                          variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => setUnassignTarget({ id: c.tenantId, name: c.tenantName })}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </td>
                    </tr>
                    {expanded && (
                      <tr key={`${c.tenantId}-assets`} className="border-b border-border/50">
                        <td colSpan={9} className="p-0">
                          <ClientAssetPanel tenantId={c.tenantId} />
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Unassign confirmation Dialog */}
      <Dialog open={!!unassignTarget} onOpenChange={v => { if (!v) setUnassignTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Unassign Client</DialogTitle>
            <DialogDescription>
              Remove <span className="font-semibold text-foreground">{unassignTarget?.name}</span> from your client list?
              You can reassign them later.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setUnassignTarget(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={unassignMutation.isPending}
              onClick={() => {
                if (unassignTarget) {
                  unassignMutation.mutate(unassignTarget.id, {
                    onSettled: () => setUnassignTarget(null),
                  });
                }
              }}
            >
              {unassignMutation.isPending ? "Removing…" : "Unassign"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Assign Client Dialog — real tenant picker */}
      <Dialog open={showAssign} onOpenChange={v => { if (!v) { setShowAssign(false); setSelectedTenantId(""); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Assign Client Tenant</DialogTitle>
            <DialogDescription>
              Select a tenant to assign as your client. You will be able to monitor their assets and findings.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {loadingAvailable ? (
              <Skeleton className="h-9 w-full rounded" />
            ) : availableTenants.length === 0 ? (
              <div className="text-sm text-muted-foreground text-center py-4">
                All tenants are already assigned, or no tenants are available.
              </div>
            ) : (
              <div className="space-y-1.5">
                <p className="text-xs text-muted-foreground font-medium">Select client tenant</p>
                <Select value={selectedTenantId} onValueChange={setSelectedTenantId}>
                  <SelectTrigger className="h-9">
                    <SelectValue placeholder="Choose a tenant…" />
                  </SelectTrigger>
                  <SelectContent>
                    {availableTenants.map(t => (
                      <SelectItem key={t.id} value={String(t.id)}>
                        <span className="flex items-center gap-2">
                          {t.name}
                          <Badge variant="outline" className="text-[10px] capitalize ml-1">{t.plan}</Badge>
                          {!t.isActive && <span className="text-[10px] text-muted-foreground">(inactive)</span>}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => { setShowAssign(false); setSelectedTenantId(""); }}>Cancel</Button>
            <Button
              disabled={!selectedTenantId || assignMutation.isPending || availableTenants.length === 0}
              onClick={() => selectedTenantId && assignMutation.mutate(Number(selectedTenantId))}
            >
              {assignMutation.isPending ? "Assigning…" : "Assign Client"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
