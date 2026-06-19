import { useState, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Building2, Users, Server, Bug, ChevronDown, ChevronUp,
  UserCheck, X, Globe, Cpu, Network, ShieldCheck, Cloud, Smartphone,
  Link2, FileKey, Layers, Trash2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
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

interface AssetRow {
  id: number;
  name: string;
  type: string;
  value: string;
  verificationStatus: string;
  scanFrequency: string;
  riskLevel: string;
  lastScannedAt: string | null;
}

const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PLANS = ["starter", "professional", "enterprise"];
const emptyForm = { name: "", slug: "", plan: "starter" };

const ASSET_TYPES = [
  { value: "domain", label: "Domain", icon: Globe, placeholder: "example.com" },
  { value: "subdomain", label: "Subdomain", icon: Layers, placeholder: "sub.example.com" },
  { value: "ip", label: "IP Address", icon: Cpu, placeholder: "192.168.1.1" },
  { value: "cidr", label: "CIDR Range", icon: Network, placeholder: "192.168.1.0/24" },
  { value: "url", label: "URL", icon: Link2, placeholder: "https://example.com/app" },
  { value: "api", label: "API Endpoint", icon: FileKey, placeholder: "https://api.example.com" },
  { value: "cloud_asset", label: "Cloud Asset", icon: Cloud, placeholder: "my-s3-bucket" },
  { value: "ssl_certificate", label: "SSL Certificate", icon: ShieldCheck, placeholder: "example.com" },
  { value: "host", label: "Host", icon: Server, placeholder: "host.example.com" },
  { value: "mobile_application", label: "Mobile App", icon: Smartphone, placeholder: "com.example.app" },
];

const SCAN_FREQS = [
  { value: "manual", label: "Manual only" },
  { value: "hourly", label: "Hourly" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];

const emptyAssetForm = { name: "", type: "domain", value: "", scanFrequency: "daily", businessImpact: 5 };

type ActiveTab = "managers" | "assets";

export default function TenantsPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<Record<number, ActiveTab>>({});

  // AM assignment dialog
  const [assignTarget, setAssignTarget] = useState<{ tenantId: number; tenantName: string } | null>(null);
  const [selectedAmId, setSelectedAmId] = useState("");

  // Asset add dialog
  const [assetTarget, setAssetTarget] = useState<{ tenantId: number; tenantName: string } | null>(null);
  const [assetForm, setAssetForm] = useState(emptyAssetForm);

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

  // Assets per expanded tenant — fetched on-demand
  const { data: tenantAssets = [], isLoading: assetsLoading, refetch: refetchAssets } = useQuery<AssetRow[]>({
    queryKey: ["tenant-assets", expandedId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${expandedId}/assets`),
    enabled: expandedId !== null && (activeTab[expandedId ?? -1] === "assets" || false),
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
        method: "POST", body: JSON.stringify({ accountManagerUserId }),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setAssignTarget(null); setSelectedAmId("");
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

  const addAssetMutation = useMutation({
    mutationFn: ({ tenantId, body }: { tenantId: number; body: object }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}/assets`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenant-assets", assetTarget?.tenantId ?? expandedId] });
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setAssetTarget(null); setAssetForm(emptyAssetForm);
      toast({ title: "Asset added successfully" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteAssetMutation = useMutation({
    mutationFn: ({ tenantId, assetId }: { tenantId: number; assetId: number }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}/assets/${assetId}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenant-assets", expandedId] });
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      toast({ title: "Asset removed" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  function getTab(id: number): ActiveTab {
    return activeTab[id] ?? "managers";
  }

  function setTab(id: number, tab: ActiveTab) {
    setActiveTab(prev => ({ ...prev, [id]: tab }));
  }

  const totalAssets = tenants.reduce((s, t) => s + t.assetCount, 0);
  const totalFindings = tenants.reduce((s, t) => s + t.findingCount, 0);
  const activeTenants = tenants.filter(t => t.isActive).length;

  const selectedAssetType = ASSET_TYPES.find(t => t.value === assetForm.type);

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{isSuperAdmin ? "All Tenants" : "Tenant Management"}</h1>
          <p className="text-sm text-muted-foreground">
            {isSuperAdmin
              ? `${tenants.length} client organizations · ${activeTenants} active`
              : "Manage your tenant's account managers and assets"}
          </p>
        </div>
        {isSuperAdmin && (
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1.5" /> New Tenant
          </Button>
        )}
      </div>

      {/* Summary KPIs */}
      {isSuperAdmin && (
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
      )}

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
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Open Findings</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {tenants.map(t => (
                <Fragment key={t.id}>
                  <tr
                    className={cn(
                      "border-b border-border/50 hover:bg-accent/30 cursor-pointer",
                      expandedId === t.id && "bg-accent/20"
                    )}
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
                      <span className={cn(
                        "text-xs px-2 py-0.5 rounded-md font-medium border",
                        t.isActive
                          ? "bg-green-500/15 text-green-400 border-green-500/30"
                          : "bg-muted text-muted-foreground border-border"
                      )}>
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
                        {/* Tab bar */}
                        <div className="flex items-center gap-1 mb-4 border-b border-border pb-2">
                          <button
                            onClick={e => { e.stopPropagation(); setTab(t.id, "managers"); }}
                            className={cn(
                              "px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                              getTab(t.id) === "managers"
                                ? "bg-primary/10 text-primary"
                                : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <UserCheck className="w-3.5 h-3.5 inline mr-1.5" />
                            Account Managers ({t.assignedManagers.length})
                          </button>
                          <button
                            onClick={e => { e.stopPropagation(); setTab(t.id, "assets"); }}
                            className={cn(
                              "px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                              getTab(t.id) === "assets"
                                ? "bg-primary/10 text-primary"
                                : "text-muted-foreground hover:text-foreground"
                            )}
                          >
                            <Server className="w-3.5 h-3.5 inline mr-1.5" />
                            Assets ({t.assetCount})
                          </button>
                        </div>

                        {/* Account Managers tab */}
                        {getTab(t.id) === "managers" && (
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1">
                              {t.assignedManagers.length === 0 ? (
                                <p className="text-xs text-muted-foreground/70 italic">No account managers assigned.</p>
                              ) : (
                                <div className="space-y-1.5">
                                  {t.assignedManagers.map((m: any) => (
                                    <div key={m.id} className="flex items-center gap-2 text-xs">
                                      <div className="w-6 h-6 rounded-full bg-blue-500/15 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                                        <span className="text-[10px] font-bold text-blue-400">
                                          {(m.name || m.email).charAt(0).toUpperCase()}
                                        </span>
                                      </div>
                                      <span className="font-medium">{m.name}</span>
                                      <span className="text-muted-foreground">·</span>
                                      <span className="text-muted-foreground">{m.email}</span>
                                      <button
                                        onClick={e => {
                                          e.stopPropagation();
                                          unassignMutation.mutate({ tenantId: t.id, amUserId: m.id });
                                        }}
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
                              size="sm" variant="outline" className="text-xs h-7 shrink-0"
                              onClick={e => {
                                e.stopPropagation();
                                setAssignTarget({ tenantId: t.id, tenantName: t.name });
                                setSelectedAmId("");
                              }}
                            >
                              <Plus className="w-3.5 h-3.5 mr-1" /> Assign Manager
                            </Button>
                          </div>
                        )}

                        {/* Assets tab */}
                        {getTab(t.id) === "assets" && (
                          <div className="space-y-3">
                            <div className="flex items-center justify-between">
                              <p className="text-xs text-muted-foreground">
                                Assets added here are immediately available for scanning.
                              </p>
                              <Button
                                size="sm" variant="outline" className="text-xs h-7"
                                onClick={e => {
                                  e.stopPropagation();
                                  setAssetTarget({ tenantId: t.id, tenantName: t.name });
                                  setAssetForm(emptyAssetForm);
                                }}
                              >
                                <Plus className="w-3.5 h-3.5 mr-1" /> Add Asset
                              </Button>
                            </div>

                            {assetsLoading ? (
                              <div className="space-y-1">
                                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-8 rounded" />)}
                              </div>
                            ) : tenantAssets.length === 0 ? (
                              <div className="text-center py-6 border border-dashed border-border rounded-lg">
                                <Server className="w-8 h-8 mx-auto text-muted-foreground/30 mb-2" />
                                <p className="text-xs text-muted-foreground">No assets yet.</p>
                                <p className="text-xs text-muted-foreground/70 mt-1">Add a domain, IP, or URL to start scanning.</p>
                              </div>
                            ) : (
                              <div className="rounded-lg border border-border overflow-hidden">
                                <table className="w-full text-xs">
                                  <thead>
                                    <tr className="border-b border-border bg-muted/30">
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Name</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Type</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Value</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Scan</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Risk</th>
                                      <th className="px-3 py-2" />
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {tenantAssets.map(a => {
                                      const at = ASSET_TYPES.find(x => x.value === a.type);
                                      const Icon = at?.icon ?? Globe;
                                      return (
                                        <tr key={a.id} className="border-b border-border/40 hover:bg-accent/20">
                                          <td className="px-3 py-2 font-medium">{a.name}</td>
                                          <td className="px-3 py-2">
                                            <span className="flex items-center gap-1 text-muted-foreground">
                                              <Icon className="w-3 h-3" />
                                              {at?.label ?? a.type}
                                            </span>
                                          </td>
                                          <td className="px-3 py-2 font-mono text-muted-foreground">{a.value}</td>
                                          <td className="px-3 py-2 capitalize text-muted-foreground">{a.scanFrequency}</td>
                                          <td className="px-3 py-2">
                                            <span className={cn(
                                              "px-1.5 py-0.5 rounded text-[10px] font-medium capitalize",
                                              a.riskLevel === "critical" && "bg-red-500/15 text-red-400",
                                              a.riskLevel === "high" && "bg-orange-500/15 text-orange-400",
                                              a.riskLevel === "medium" && "bg-yellow-500/15 text-yellow-400",
                                              a.riskLevel === "low" && "bg-blue-500/15 text-blue-400",
                                              a.riskLevel === "info" && "bg-muted text-muted-foreground",
                                            )}>{a.riskLevel}</span>
                                          </td>
                                          <td className="px-3 py-2">
                                            <button
                                              onClick={e => {
                                                e.stopPropagation();
                                                deleteAssetMutation.mutate({ tenantId: t.id, assetId: a.id });
                                              }}
                                              className="p-1 rounded hover:bg-red-500/15 text-muted-foreground hover:text-red-400 transition-colors"
                                              title="Delete asset"
                                            >
                                              <Trash2 className="w-3.5 h-3.5" />
                                            </button>
                                          </td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                              </div>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
              {tenants.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-muted-foreground text-sm">
                    No client tenants yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Create Tenant Dialog ─────────────────────────────────────────── */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader><DialogTitle>Create Client Tenant</DialogTitle></DialogHeader>
          <form
            className="space-y-3 mt-2"
            onSubmit={e => { e.preventDefault(); createMutation.mutate(form); }}
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Organization Name</Label>
              <Input
                value={form.name}
                onChange={e => setForm(p => ({ ...p, name: e.target.value }))}
                required className="h-9" placeholder="Acme Corp"
              />
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
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? "Creating..." : "Create Tenant"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Assign Account Manager Dialog ────────────────────────────────── */}
      <Dialog open={!!assignTarget} onOpenChange={open => { if (!open) { setAssignTarget(null); setSelectedAmId(""); } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Account Manager</DialogTitle>
            <p className="text-sm text-muted-foreground mt-1">
              Assign a manager to <span className="font-medium text-foreground">{assignTarget?.tenantName}</span>.
              They will immediately see this tenant's data in their portal.
            </p>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {amUsers.length === 0 ? (
              <p className="text-sm text-muted-foreground italic">
                No account manager users found. Go to Settings → Users and create a user with the <strong>account_manager</strong> role first.
              </p>
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
                        {u.firstName || u.lastName
                          ? `${u.firstName ?? ""} ${u.lastName ?? ""}`.trim()
                          : u.email} — {u.email}
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
              disabled={!selectedAmId || assignMutation.isPending || amUsers.length === 0}
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

      {/* ── Add Asset Dialog ──────────────────────────────────────────────── */}
      <Dialog open={!!assetTarget} onOpenChange={open => { if (!open) { setAssetTarget(null); setAssetForm(emptyAssetForm); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Asset to {assetTarget?.tenantName}</DialogTitle>
            <p className="text-sm text-muted-foreground mt-1">
              This asset will be immediately available for scanning under this tenant.
            </p>
          </DialogHeader>
          <form
            className="space-y-3 mt-2"
            onSubmit={e => {
              e.preventDefault();
              if (!assetTarget) return;
              addAssetMutation.mutate({ tenantId: assetTarget.tenantId, body: assetForm });
            }}
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Type</Label>
              <Select
                value={assetForm.type}
                onValueChange={v => setAssetForm(p => ({ ...p, type: v, value: "" }))}
              >
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {ASSET_TYPES.map(at => (
                    <SelectItem key={at.value} value={at.value}>
                      <span className="flex items-center gap-2">
                        <at.icon className="w-3.5 h-3.5" />
                        {at.label}
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Display Name</Label>
              <Input
                value={assetForm.name}
                onChange={e => setAssetForm(p => ({ ...p, name: e.target.value }))}
                required className="h-9"
                placeholder={`e.g. ${selectedAssetType?.label ?? "My Asset"}`}
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">
                Value{" "}
                <span className="text-muted-foreground font-normal">
                  ({selectedAssetType?.label ?? "asset"} — {selectedAssetType?.placeholder ?? ""})
                </span>
              </Label>
              <Input
                value={assetForm.value}
                onChange={e => setAssetForm(p => ({ ...p, value: e.target.value }))}
                required className="h-9 font-mono"
                placeholder={selectedAssetType?.placeholder ?? ""}
              />
              <p className="text-[11px] text-muted-foreground">
                {assetForm.type === "domain" && "Root domain only (e.g. example.com — not https://)."}
                {assetForm.type === "ip" && "IPv4 or IPv6 address."}
                {assetForm.type === "cidr" && "CIDR notation (e.g. 10.0.0.0/24)."}
                {assetForm.type === "url" && "Full URL including https://."}
                {assetForm.type === "subdomain" && "Full subdomain (e.g. api.example.com)."}
                {assetForm.type === "api" && "Full API base URL including https://."}
                {assetForm.type === "cloud_asset" && "Bucket name, storage account, or cloud resource ID."}
                {assetForm.type === "ssl_certificate" && "Domain the certificate is issued for."}
                {assetForm.type === "host" && "Hostname or FQDN."}
                {assetForm.type === "mobile_application" && "App bundle ID or package name."}
              </p>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={assetForm.scanFrequency} onValueChange={v => setAssetForm(p => ({ ...p, scanFrequency: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_FREQS.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Business Impact (1–10)</Label>
                <Input
                  type="number" min={1} max={10}
                  value={assetForm.businessImpact}
                  onChange={e => setAssetForm(p => ({ ...p, businessImpact: Number(e.target.value) }))}
                  className="h-9"
                />
              </div>
            </div>

            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => { setAssetTarget(null); setAssetForm(emptyAssetForm); }}>
                Cancel
              </Button>
              <Button type="submit" disabled={addAssetMutation.isPending}>
                {addAssetMutation.isPending ? "Adding..." : "Add Asset"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
