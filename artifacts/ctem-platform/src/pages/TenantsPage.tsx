import { useState, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Building2, Users, Server, Bug, ChevronDown, ChevronUp,
  UserCheck, X, Globe, Shield, Cpu, Network, Code2, Cloud, Smartphone,
  Lock, Trash2, Loader2, Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter, DialogDescription,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { cn, formatDate } from "@/lib/utils";

// ── Types ─────────────────────────────────────────────────────────────────────
interface TenantRow {
  id: number; name: string; slug: string; plan: string; isActive: boolean;
  createdAt: string; userCount: number; assetCount: number;
  findingCount: number; criticalCount: number; openFindingCount: number;
  assignedManagers: Array<{ id: number; name: string; email: string }>;
}
interface UserRow {
  id: number; firstName: string | null; lastName: string | null; email: string; role: string;
}
interface AssetRow {
  id: number; name: string; type: string; value: string;
  verificationStatus: string; scanFrequency: string; riskLevel: string; lastScannedAt: string | null;
}

// ── Constants (matching AssetsPage exactly) ───────────────────────────────────
const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");
const PLANS = ["starter", "professional", "enterprise"];

const TYPE_CONFIG: Record<string, { label: string; valueLabel: string; valuePlaceholder: string }> = {
  domain:       { label: "Domain",           valueLabel: "Domain",             valuePlaceholder: "example.com"                },
  subdomain:    { label: "Subdomain",         valueLabel: "Subdomain",          valuePlaceholder: "app.example.com"            },
  url:          { label: "URL",               valueLabel: "URL",                valuePlaceholder: "https://example.com"         },
  ip:           { label: "IP Address",        valueLabel: "IP Address",         valuePlaceholder: "203.0.113.10"               },
  cidr:         { label: "CIDR / IP Range",   valueLabel: "CIDR Range",         valuePlaceholder: "10.0.0.0/8"                 },
  api:          { label: "API Endpoint",      valueLabel: "Base URL",           valuePlaceholder: "https://api.example.com/v1" },
  ssl_cert:     { label: "SSL Certificate",   valueLabel: "Hostname",           valuePlaceholder: "example.com"                },
  cloud_asset:  { label: "Cloud Asset",       valueLabel: "Resource ID / ARN",  valuePlaceholder: "arn:aws:ec2:us-east-1:…"    },
  host:         { label: "Host",              valueLabel: "Hostname / IP",      valuePlaceholder: "server01.internal"          },
  mobile_app:   { label: "Mobile App",        valueLabel: "Bundle ID / App ID", valuePlaceholder: "com.example.app"            },
};
const ASSET_TYPES = Object.keys(TYPE_CONFIG);
const SCAN_FREQUENCIES = [
  { value: "manual",  label: "Manual only" },
  { value: "daily",   label: "Daily" },
  { value: "weekly",  label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];
const TYPE_ICONS: Record<string, React.ElementType> = {
  domain: Globe, subdomain: Globe, url: Code2, ip: Cpu, cidr: Network,
  api: Code2, ssl_cert: Lock, cloud_asset: Cloud, host: Server, mobile_app: Smartphone,
};

function typeLabel(t: string) { return TYPE_CONFIG[t]?.label ?? t; }
function typeValueLabel(t: string) { return TYPE_CONFIG[t]?.valueLabel ?? "Value"; }
function typeValuePlaceholder(t: string) { return TYPE_CONFIG[t]?.valuePlaceholder ?? ""; }

const emptyTenantForm = { name: "", slug: "", plan: "starter" };
const emptyAssetForm = { name: "", type: "domain", value: "", description: "", scanFrequency: "daily" };

type ActiveTab = "managers" | "assets";

// ── Main Component ─────────────────────────────────────────────────────────────
export default function TenantsPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const queryClient = useQueryClient();
  const { toast } = useToast();

  // Row expansion
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<Record<number, ActiveTab>>({});

  // Create tenant dialog
  const [showCreate, setShowCreate] = useState(false);
  const [tenantForm, setTenantForm] = useState(emptyTenantForm);

  // AM assignment dialog
  const [assignTarget, setAssignTarget] = useState<{ tenantId: number; tenantName: string } | null>(null);
  const [selectedAmId, setSelectedAmId] = useState("");

  // Add asset dialog
  const [assetTarget, setAssetTarget] = useState<{ tenantId: number; tenantName: string } | null>(null);
  const [assetForm, setAssetForm] = useState({ ...emptyAssetForm });

  // ── Queries ──────────────────────────────────────────────────────────────────
  const { data: tenants = [], isLoading } = useQuery<TenantRow[]>({
    queryKey: ["platform-tenants"],
    queryFn: () => apiFetch(`${BASE}/api/tenants`),
  });

  const { data: allUsers = [] } = useQuery<UserRow[]>({
    queryKey: ["platform-users"],
    queryFn: () => apiFetch(`${BASE}/api/users`),
  });

  // Fetch assets whenever a tenant row is expanded (regardless of tab)
  const { data: tenantAssets = [], isLoading: assetsLoading } = useQuery<AssetRow[]>({
    queryKey: ["tenant-assets", expandedId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${expandedId}/assets`),
    enabled: expandedId !== null,
  });

  const amUsers = allUsers.filter(u => u.role === "account_manager");

  // ── Mutations ────────────────────────────────────────────────────────────────
  const createTenantMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch(`${BASE}/api/tenants`, { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setShowCreate(false); setTenantForm(emptyTenantForm);
      toast({ title: "Tenant created successfully" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const assignMutation = useMutation({
    mutationFn: ({ tenantId, amId }: { tenantId: number; amId: number }) =>
      apiFetch(`${BASE}/api/tenants/${tenantId}/managers`, {
        method: "POST", body: JSON.stringify({ accountManagerUserId: amId }),
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
      apiFetch(`${BASE}/api/tenants/${tenantId}/assets`, {
        method: "POST", body: JSON.stringify(body),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tenant-assets", assetTarget?.tenantId] });
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setAssetTarget(null); setAssetForm({ ...emptyAssetForm });
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

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function getTab(id: number): ActiveTab { return activeTab[id] ?? "managers"; }
  function setTab(id: number, tab: ActiveTab) { setActiveTab(p => ({ ...p, [id]: tab })); }
  function toggleRow(id: number) { setExpandedId(prev => prev === id ? null : id); }

  const totalAssets = tenants.reduce((s, t) => s + t.assetCount, 0);
  const totalFindings = tenants.reduce((s, t) => s + t.findingCount, 0);

  // ── Render ────────────────────────────────────────────────────────────────────
  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold">{isSuperAdmin ? "All Tenants" : "Tenant Management"}</h1>
          <p className="text-sm text-muted-foreground">
            Manage client organizations, account managers, and assets
          </p>
        </div>
        <Button size="sm" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4 mr-1.5" /> New Tenant
        </Button>
      </div>

      {/* KPI cards — super admin only */}
      {isSuperAdmin && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total Tenants", value: tenants.length, icon: Building2, color: "text-purple-400" },
            { label: "Total Assets",  value: totalAssets,    icon: Server,    color: "text-blue-400"   },
            { label: "Total Findings",value: totalFindings,  icon: Bug,       color: "text-amber-400"  },
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

      {/* Tenant table */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-14 rounded-xl" />)}
        </div>
      ) : (
        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Organization</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Plan</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Users</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Assets</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Open Findings</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Critical</th>
                <th className="text-left px-4 py-2.5 text-xs font-medium text-muted-foreground">Status</th>
                <th className="w-8 px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {tenants.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-10 text-center text-muted-foreground text-sm">
                  No tenants yet. Click <strong>New Tenant</strong> to create one.
                </td></tr>
              )}
              {tenants.map(t => (
                <Fragment key={t.id}>
                  <tr
                    className={cn(
                      "border-b border-border/50 hover:bg-accent/30 cursor-pointer select-none transition-colors",
                      expandedId === t.id && "bg-accent/20"
                    )}
                    onClick={() => toggleRow(t.id)}
                  >
                    <td className="px-4 py-2.5">
                      <div className="font-medium">{t.name}</div>
                      <div className="text-xs text-muted-foreground">{t.slug}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <Badge variant="outline" className="text-xs capitalize">{t.plan}</Badge>
                    </td>
                    <td className="px-4 py-2.5 tabular-nums">{t.userCount}</td>
                    <td className="px-4 py-2.5 tabular-nums">{t.assetCount}</td>
                    <td className="px-4 py-2.5 tabular-nums">{t.openFindingCount}</td>
                    <td className="px-4 py-2.5 tabular-nums">
                      {t.criticalCount > 0
                        ? <span className="text-red-400 font-semibold">{t.criticalCount}</span>
                        : <span className="text-muted-foreground/40">—</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={cn(
                        "text-xs px-2 py-0.5 rounded-full font-medium border",
                        t.isActive
                          ? "bg-green-500/10 text-green-400 border-green-500/25"
                          : "bg-muted/50 text-muted-foreground border-border"
                      )}>
                        {t.isActive ? "Active" : "Inactive"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">
                      {expandedId === t.id
                        ? <ChevronUp className="w-4 h-4" />
                        : <ChevronDown className="w-4 h-4" />}
                    </td>
                  </tr>

                  {/* Expanded panel */}
                  {expandedId === t.id && (
                    <tr className="border-b border-border/50">
                      <td colSpan={8} className="bg-muted/10 px-6 py-4">
                        {/* Tabs */}
                        <div className="flex gap-1 mb-4 border-b border-border pb-3">
                          {(["managers", "assets"] as ActiveTab[]).map(tab => (
                            <button
                              key={tab}
                              onClick={e => { e.stopPropagation(); setTab(t.id, tab); }}
                              className={cn(
                                "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors",
                                getTab(t.id) === tab
                                  ? "bg-primary text-primary-foreground"
                                  : "text-muted-foreground hover:text-foreground hover:bg-accent"
                              )}
                            >
                              {tab === "managers"
                                ? <><UserCheck className="w-3.5 h-3.5" /> Account Managers ({t.assignedManagers.length})</>
                                : <><Server className="w-3.5 h-3.5" /> Assets ({t.assetCount})</>}
                            </button>
                          ))}
                        </div>

                        {/* Account Managers tab */}
                        {getTab(t.id) === "managers" && (
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-h-[40px]">
                              {t.assignedManagers.length === 0 ? (
                                <p className="text-xs text-muted-foreground italic">
                                  No account managers assigned. Click "Assign Manager" to add one.
                                </p>
                              ) : (
                                <div className="space-y-2">
                                  {t.assignedManagers.map((m: any) => (
                                    <div key={m.id} className="flex items-center gap-2.5 text-sm">
                                      <div className="w-7 h-7 rounded-full bg-blue-500/15 border border-blue-500/20 flex items-center justify-center shrink-0">
                                        <span className="text-xs font-bold text-blue-400">
                                          {(m.name || m.email)[0].toUpperCase()}
                                        </span>
                                      </div>
                                      <div className="flex-1 min-w-0">
                                        <span className="font-medium text-xs">{m.name}</span>
                                        <span className="text-muted-foreground text-xs ml-2">{m.email}</span>
                                      </div>
                                      <button
                                        onClick={e => { e.stopPropagation(); unassignMutation.mutate({ tenantId: t.id, amUserId: m.id }); }}
                                        className="p-1 rounded hover:bg-red-500/15 text-muted-foreground hover:text-red-400 transition-colors ml-auto"
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
                              size="sm" variant="outline" className="text-xs h-8 shrink-0"
                              onClick={e => { e.stopPropagation(); setAssignTarget({ tenantId: t.id, tenantName: t.name }); setSelectedAmId(""); }}
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
                                Assets listed here are scanned for vulnerabilities. Add domains, IPs, URLs, and more.
                              </p>
                              <Button
                                size="sm" variant="outline" className="text-xs h-8 shrink-0"
                                onClick={e => { e.stopPropagation(); setAssetTarget({ tenantId: t.id, tenantName: t.name }); setAssetForm({ ...emptyAssetForm }); }}
                              >
                                <Plus className="w-3.5 h-3.5 mr-1" /> Add Asset
                              </Button>
                            </div>

                            {assetsLoading ? (
                              <div className="space-y-1.5">
                                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-9 rounded-lg" />)}
                              </div>
                            ) : tenantAssets.length === 0 ? (
                              <div
                                className="flex flex-col items-center justify-center py-8 border-2 border-dashed border-border rounded-xl cursor-pointer hover:border-primary/40 hover:bg-accent/10 transition-colors"
                                onClick={e => { e.stopPropagation(); setAssetTarget({ tenantId: t.id, tenantName: t.name }); setAssetForm({ ...emptyAssetForm }); }}
                              >
                                <Server className="w-8 h-8 text-muted-foreground/30 mb-2" />
                                <p className="text-sm font-medium text-muted-foreground">No assets yet</p>
                                <p className="text-xs text-muted-foreground/60 mt-1">Click to add a domain, IP, URL, or other target</p>
                              </div>
                            ) : (
                              <div className="rounded-lg border border-border overflow-hidden">
                                <table className="w-full text-xs">
                                  <thead>
                                    <tr className="bg-muted/30 border-b border-border">
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Name</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Type</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Value</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Frequency</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Risk</th>
                                      <th className="text-left px-3 py-2 text-muted-foreground font-medium">Last Scan</th>
                                      <th className="w-8 px-3 py-2" />
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {tenantAssets.map(a => {
                                      const Icon = TYPE_ICONS[a.type] ?? Globe;
                                      return (
                                        <tr key={a.id} className="border-b border-border/40 hover:bg-accent/20 transition-colors">
                                          <td className="px-3 py-2 font-medium">{a.name}</td>
                                          <td className="px-3 py-2">
                                            <span className="flex items-center gap-1 text-muted-foreground">
                                              <Icon className="w-3 h-3 shrink-0" />
                                              {typeLabel(a.type)}
                                            </span>
                                          </td>
                                          <td className="px-3 py-2 font-mono text-muted-foreground max-w-[160px] truncate">{a.value}</td>
                                          <td className="px-3 py-2 capitalize text-muted-foreground">{a.scanFrequency}</td>
                                          <td className="px-3 py-2">
                                            <span className={cn(
                                              "px-1.5 py-0.5 rounded text-[10px] font-medium capitalize",
                                              a.riskLevel === "critical" && "bg-red-500/15 text-red-400",
                                              a.riskLevel === "high"     && "bg-orange-500/15 text-orange-400",
                                              a.riskLevel === "medium"   && "bg-yellow-500/15 text-yellow-400",
                                              a.riskLevel === "low"      && "bg-blue-500/15 text-blue-400",
                                              a.riskLevel === "info"     && "bg-muted text-muted-foreground",
                                            )}>{a.riskLevel}</span>
                                          </td>
                                          <td className="px-3 py-2 text-muted-foreground">
                                            {a.lastScannedAt ? formatDate(a.lastScannedAt) : <span className="text-muted-foreground/40">Never</span>}
                                          </td>
                                          <td className="px-3 py-2">
                                            <button
                                              onClick={e => { e.stopPropagation(); deleteAssetMutation.mutate({ tenantId: t.id, assetId: a.id }); }}
                                              className="p-1 rounded hover:bg-red-500/15 text-muted-foreground hover:text-red-400 transition-colors"
                                              title="Delete"
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
            </tbody>
          </table>
        </div>
      )}

      {/* ════════════════════════════ Dialogs ════════════════════════════════ */}

      {/* Create Tenant */}
      <Dialog open={showCreate} onOpenChange={v => { if (!v) { setShowCreate(false); setTenantForm(emptyTenantForm); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create New Tenant</DialogTitle>
            <DialogDescription>Set up a new client organization on the platform.</DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4 mt-1"
            onSubmit={e => { e.preventDefault(); createTenantMutation.mutate(tenantForm); }}
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Organization Name *</Label>
              <Input
                value={tenantForm.name}
                onChange={e => setTenantForm(p => ({ ...p, name: e.target.value }))}
                placeholder="Acme Corp"
                required className="h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Slug *</Label>
              <Input
                value={tenantForm.slug}
                onChange={e => setTenantForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-") }))}
                placeholder="acme-corp"
                required className="h-9 font-mono"
              />
              <p className="text-[11px] text-muted-foreground">Unique URL-safe identifier. Used internally.</p>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Plan</Label>
              <Select value={tenantForm.plan} onValueChange={v => setTenantForm(p => ({ ...p, plan: v }))}>
                <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {PLANS.map(pl => <SelectItem key={pl} value={pl} className="capitalize">{pl.charAt(0).toUpperCase() + pl.slice(1)}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <DialogFooter>
              <Button variant="outline" type="button" onClick={() => { setShowCreate(false); setTenantForm(emptyTenantForm); }}>Cancel</Button>
              <Button type="submit" disabled={createTenantMutation.isPending}>
                {createTenantMutation.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
                Create Tenant
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Assign Account Manager */}
      <Dialog open={!!assignTarget} onOpenChange={v => { if (!v) { setAssignTarget(null); setSelectedAmId(""); } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Assign Account Manager</DialogTitle>
            <DialogDescription>
              Assign a manager to <strong>{assignTarget?.tenantName}</strong>. They will see this tenant's data in their dashboard immediately.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            {amUsers.length === 0 ? (
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-xs text-amber-400">
                No account manager users found. Go to <strong>Admin → Users</strong> and create a user with the <strong>account_manager</strong> role first, then come back here.
              </div>
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
                        {u.firstName || u.lastName ? `${u.firstName ?? ""} ${u.lastName ?? ""}`.trim() : u.email}
                        {" · "}{u.email}
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
                assignMutation.mutate({ tenantId: assignTarget.tenantId, amId: Number(selectedAmId) });
              }}
            >
              {assignMutation.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
              Assign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Asset — matches AssetsPage design exactly */}
      <Dialog open={!!assetTarget} onOpenChange={v => { if (!v) { setAssetTarget(null); setAssetForm({ ...emptyAssetForm }); } }}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Add Asset</DialogTitle>
            <DialogDescription>
              Adding to <strong>{assetTarget?.tenantName}</strong>. Asset will be immediately available for scanning.
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-4 mt-1"
            onSubmit={e => {
              e.preventDefault();
              if (!assetTarget) return;
              addAssetMutation.mutate({ tenantId: assetTarget.tenantId, body: assetForm });
            }}
          >
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name *</Label>
              <Input
                value={assetForm.name}
                onChange={e => setAssetForm(p => ({ ...p, name: e.target.value }))}
                placeholder="e.g. Main Website, Production API"
                required className="h-9"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Type *</Label>
                <Select value={assetForm.type} onValueChange={v => setAssetForm(p => ({ ...p, type: v, value: "" }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {ASSET_TYPES.map(t => <SelectItem key={t} value={t}>{typeLabel(t)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">{typeValueLabel(assetForm.type)} *</Label>
                <Input
                  value={assetForm.value}
                  onChange={e => setAssetForm(p => ({ ...p, value: e.target.value }))}
                  placeholder={typeValuePlaceholder(assetForm.type)}
                  required className="h-9 font-mono text-sm"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Description (optional)</Label>
              <Input
                value={assetForm.description}
                onChange={e => setAssetForm(p => ({ ...p, description: e.target.value }))}
                placeholder="e.g. Main production website"
                className="h-9"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">Scan Frequency</Label>
              <Select value={assetForm.scanFrequency} onValueChange={v => setAssetForm(p => ({ ...p, scanFrequency: v }))}>
                <SelectTrigger className="h-9 text-xs"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SCAN_FREQUENCIES.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                </SelectContent>
              </Select>
              {assetForm.scanFrequency !== "manual" && (
                <p className="text-xs text-muted-foreground">
                  This asset will be scanned automatically on a <strong>{assetForm.scanFrequency}</strong> schedule.
                </p>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => { setAssetTarget(null); setAssetForm({ ...emptyAssetForm }); }}>
                Cancel
              </Button>
              <Button type="submit" disabled={addAssetMutation.isPending}>
                {addAssetMutation.isPending ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
                Add Asset
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
