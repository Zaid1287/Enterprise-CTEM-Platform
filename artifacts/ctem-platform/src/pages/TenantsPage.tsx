import { useState, Fragment } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Building2, Users, Server, Bug, ChevronDown, ChevronUp,
  UserCheck, X, Globe, Shield, Cpu, Network, Code2, Cloud, Smartphone,
  Lock, Trash2, Loader2, Pencil, MoreHorizontal,
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
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Slider } from "@/components/ui/slider";
import { apiFetch } from "@/lib/apiFetch";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { cn, formatDate } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────────
interface TenantRow {
  id: number; name: string; slug: string; plan: string; isActive: boolean;
  parentTenantId: number | null; createdAt: string;
  userCount: number; assetCount: number;
  findingCount: number; criticalCount: number; openFindingCount: number;
  assignedManagers: Array<{ id: number; name: string; email: string }>;
}
interface UserRow {
  id: number; firstName: string | null; lastName: string | null; email: string; role: string;
}
interface AssetRow {
  id: number; name: string; type: string; value: string;
  verificationStatus: string; isActive: boolean;
  scanFrequency: string; riskLevel: string; businessImpact: number | null;
  lastScannedAt: string | null;
}
interface PkgData {
  id: number; name: string; price: number;
  maxAssets: number | null; maxUsers: number | null; isActive: boolean;
}

// ── Constants ────────────────────────────────────────────────────────────────
const BASE = import.meta.env.BASE_URL.replace(/\/$/, "");

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
const RISK_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400",
  high:     "bg-orange-500/15 text-orange-400",
  medium:   "bg-yellow-500/15 text-yellow-400",
  low:      "bg-blue-500/15 text-blue-400",
  info:     "bg-muted/40 text-muted-foreground",
};

function typeLabel(t: string) { return TYPE_CONFIG[t]?.label ?? t; }
function typeValueLabel(t: string) { return TYPE_CONFIG[t]?.valueLabel ?? "Value"; }
function typeValuePlaceholder(t: string) { return TYPE_CONFIG[t]?.valuePlaceholder ?? ""; }

const emptyTenantForm = { name: "", slug: "", plan: "" };
const emptyEditForm   = { name: "", plan: "", isActive: true, maxAssets: "", maxUsers: "" };
const emptyAssetForm  = { name: "", type: "domain", value: "", description: "", scanFrequency: "daily", businessImpact: 5 };

type ActiveTab = "managers" | "assets";

// ── TenantAssetsPanel ─────────────────────────────────────────────────────────
// Isolated component so each tenant's assets have their own query/cache.
function TenantAssetsPanel({
  tenantId, tenantName,
  onAddAsset, onDeleteAsset,
}: {
  tenantId: number; tenantName: string;
  onAddAsset: () => void;
  onDeleteAsset: (assetId: number) => void;
}) {
  const { data: assets = [], isLoading } = useQuery<AssetRow[]>({
    queryKey: ["tenant-assets", tenantId],
    queryFn: () => apiFetch(`${BASE}/api/tenants/${tenantId}/assets`),
    staleTime: 30_000,
  });

  if (isLoading) {
    return (
      <div className="space-y-1.5">
        {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-9 rounded-lg" />)}
      </div>
    );
  }

  if (assets.length === 0) {
    return (
      <div
        className="flex flex-col items-center justify-center py-8 border-2 border-dashed border-border rounded-xl cursor-pointer hover:border-primary/40 hover:bg-accent/10 transition-colors"
        onClick={e => { e.stopPropagation(); onAddAsset(); }}
      >
        <Server className="w-8 h-8 text-muted-foreground/30 mb-2" />
        <p className="text-sm font-medium text-muted-foreground">No assets yet</p>
        <p className="text-xs text-muted-foreground/60 mt-1">Click to add a domain, IP, URL, or other target</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-muted/30 border-b border-border">
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Name</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Type</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Value</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Frequency</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Risk</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Verified</th>
            <th className="text-left px-3 py-2 text-muted-foreground font-medium">Last Scan</th>
            <th className="w-8 px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {assets.map(a => {
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
                  <span className={cn("px-1.5 py-0.5 rounded text-[10px] font-medium capitalize", RISK_COLORS[a.riskLevel] ?? RISK_COLORS.info)}>
                    {a.riskLevel}
                  </span>
                </td>
                <td className="px-3 py-2">
                  <span className={cn("text-[10px] font-medium", a.verificationStatus === "verified" ? "text-green-400" : "text-muted-foreground/50")}>
                    {a.verificationStatus === "verified" ? "✓ Verified" : "Unverified"}
                  </span>
                </td>
                <td className="px-3 py-2 text-muted-foreground">
                  {a.lastScannedAt ? formatDate(a.lastScannedAt) : <span className="opacity-40">Never</span>}
                </td>
                <td className="px-3 py-2">
                  <button
                    onClick={e => { e.stopPropagation(); onDeleteAsset(a.id); }}
                    className="p-1 rounded hover:bg-red-500/15 text-muted-foreground hover:text-red-400 transition-colors"
                    title="Remove asset"
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
  );
}

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

  // Edit tenant dialog
  const [editTarget, setEditTarget] = useState<TenantRow | null>(null);
  const [editForm, setEditForm] = useState(emptyEditForm);

  // Delete confirmation
  const [deleteTarget, setDeleteTarget] = useState<TenantRow | null>(null);

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

  // Packages — used for Plan dropdown
  const { data: packages = [] } = useQuery<PkgData[]>({
    queryKey: ["packages"],
    queryFn: () => apiFetch(`${BASE}/api/packages`),
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

  const updateTenantMutation = useMutation({
    mutationFn: ({ id, ...body }: { id: number } & object) =>
      apiFetch(`${BASE}/api/tenants/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setEditTarget(null);
      toast({ title: "Tenant updated" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  const deleteTenantMutation = useMutation({
    mutationFn: (id: number) =>
      apiFetch(`${BASE}/api/tenants/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      setDeleteTarget(null);
      if (expandedId === deleteTarget?.id) setExpandedId(null);
      toast({ title: "Tenant deleted" });
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
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ["tenant-assets", tenantId] });
      queryClient.invalidateQueries({ queryKey: ["platform-tenants"] });
      toast({ title: "Asset removed" });
    },
    onError: (e: any) => toast({ title: "Error", description: e.message, variant: "destructive" }),
  });

  // ── Helpers ──────────────────────────────────────────────────────────────────
  function getTab(id: number): ActiveTab { return activeTab[id] ?? "managers"; }
  function setTab(id: number, tab: ActiveTab) { setActiveTab(p => ({ ...p, [id]: tab })); }
  function toggleRow(id: number) { setExpandedId(prev => prev === id ? null : id); }

  function openEdit(t: TenantRow, e: React.MouseEvent) {
    e.stopPropagation();
    setEditTarget(t);
    setEditForm({
      name: t.name,
      plan: t.plan,
      isActive: t.isActive,
      maxAssets: "",
      maxUsers: "",
    });
  }

  function openDelete(t: TenantRow, e: React.MouseEvent) {
    e.stopPropagation();
    setDeleteTarget(t);
  }

  // Plan options: packages from DB + free-text fallback if none
  const planOptions = packages.length > 0
    ? packages.filter(p => p.isActive).map(p => p.name.toLowerCase().replace(/\s+/g, "-"))
    : ["starter", "professional", "enterprise"];

  const totalAssets   = tenants.reduce((s, t) => s + t.assetCount, 0);
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
        <Button size="sm" onClick={() => { setTenantForm(emptyTenantForm); setShowCreate(true); }}>
          <Plus className="w-4 h-4 mr-1.5" /> New Tenant
        </Button>
      </div>

      {/* KPI cards — super admin only */}
      {isSuperAdmin && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total Tenants",  value: tenants.length, icon: Building2, color: "text-purple-400" },
            { label: "Total Assets",   value: totalAssets,    icon: Server,    color: "text-blue-400"   },
            { label: "Total Findings", value: totalFindings,  icon: Bug,       color: "text-amber-400"  },
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
                <th className="text-right px-4 py-2.5 text-xs font-medium text-muted-foreground">Actions</th>
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
                    <td className="px-4 py-2.5" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        {/* Expand/collapse */}
                        <button
                          onClick={e => { e.stopPropagation(); toggleRow(t.id); }}
                          className="p-1 rounded hover:bg-accent text-muted-foreground transition-colors"
                          title="View details"
                        >
                          {expandedId === t.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>

                        {/* Actions dropdown */}
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <button className="p-1 rounded hover:bg-accent text-muted-foreground transition-colors">
                              <MoreHorizontal className="w-4 h-4" />
                            </button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-40">
                            <DropdownMenuItem onClick={e => openEdit(t, e)}>
                              <Pencil className="w-3.5 h-3.5 mr-2" /> Edit Tenant
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={e => { e.stopPropagation(); setAssetTarget({ tenantId: t.id, tenantName: t.name }); setAssetForm({ ...emptyAssetForm }); }}
                            >
                              <Plus className="w-3.5 h-3.5 mr-2" /> Add Asset
                            </DropdownMenuItem>
                            {/* Don't show Delete for the user's own tenant */}
                            {t.id !== user?.tenantId && (
                              <>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  className="text-destructive focus:text-destructive"
                                  onClick={e => openDelete(t, e)}
                                >
                                  <Trash2 className="w-3.5 h-3.5 mr-2" /> Delete
                                </DropdownMenuItem>
                              </>
                            )}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
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
                                Assets from this tenant's inventory — same as their Asset Inventory page.
                              </p>
                              <Button
                                size="sm" variant="outline" className="text-xs h-8 shrink-0"
                                onClick={e => { e.stopPropagation(); setAssetTarget({ tenantId: t.id, tenantName: t.name }); setAssetForm({ ...emptyAssetForm }); }}
                              >
                                <Plus className="w-3.5 h-3.5 mr-1" /> Add Asset
                              </Button>
                            </div>
                            <TenantAssetsPanel
                              tenantId={t.id}
                              tenantName={t.name}
                              onAddAsset={() => { setAssetTarget({ tenantId: t.id, tenantName: t.name }); setAssetForm({ ...emptyAssetForm }); }}
                              onDeleteAsset={assetId => deleteAssetMutation.mutate({ tenantId: t.id, assetId })}
                            />
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

      {/* ── Create Tenant Dialog ───────────────────────────────────────────── */}
      <Dialog open={showCreate} onOpenChange={v => { if (!v) setShowCreate(false); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New Tenant</DialogTitle>
            <DialogDescription>Add a new client organization to the platform.</DialogDescription>
          </DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => {
            e.preventDefault();
            if (!tenantForm.name.trim()) return;
            const slug = tenantForm.slug.trim() || tenantForm.name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
            createTenantMutation.mutate({ name: tenantForm.name.trim(), slug, plan: tenantForm.plan || "starter" });
          }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Organization Name *</Label>
              <Input
                value={tenantForm.name}
                onChange={e => setTenantForm(p => ({ ...p, name: e.target.value }))}
                placeholder="Acme Corp" required className="h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Slug <span className="text-muted-foreground">(auto-generated if blank)</span></Label>
              <Input
                value={tenantForm.slug}
                onChange={e => setTenantForm(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "") }))}
                placeholder="acme-corp" className="h-9 font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Plan</Label>
              {packages.length > 0 ? (
                <Select value={tenantForm.plan || packages[0]?.name.toLowerCase().replace(/\s+/g, "-") || "starter"} onValueChange={v => setTenantForm(p => ({ ...p, plan: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {packages.filter(pk => pk.isActive).map(pk => {
                      const slug = pk.name.toLowerCase().replace(/\s+/g, "-");
                      return (
                        <SelectItem key={pk.id} value={slug}>
                          {pk.name} {pk.price > 0 ? `· $${pk.price}/mo` : "· Free"} {pk.maxAssets ? `· ${pk.maxAssets} assets` : ""}
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
              ) : (
                <Select value={tenantForm.plan || "starter"} onValueChange={v => setTenantForm(p => ({ ...p, plan: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["starter", "professional", "enterprise"].map(pl => (
                      <SelectItem key={pl} value={pl} className="capitalize">{pl.charAt(0).toUpperCase() + pl.slice(1)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
              <Button type="submit" disabled={createTenantMutation.isPending}>
                {createTenantMutation.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Creating…</> : "Create Tenant"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Edit Tenant Dialog ─────────────────────────────────────────────── */}
      <Dialog open={!!editTarget} onOpenChange={v => { if (!v) setEditTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Tenant</DialogTitle>
            <DialogDescription>Update organization settings for {editTarget?.name}.</DialogDescription>
          </DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => {
            e.preventDefault();
            if (!editTarget) return;
            const body: Record<string, unknown> = { name: editForm.name, plan: editForm.plan, isActive: editForm.isActive };
            if (editForm.maxAssets) body.maxAssets = parseInt(editForm.maxAssets);
            if (editForm.maxUsers) body.maxUsers = parseInt(editForm.maxUsers);
            updateTenantMutation.mutate({ id: editTarget.id, ...body });
          }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Organization Name *</Label>
              <Input
                value={editForm.name}
                onChange={e => setEditForm(p => ({ ...p, name: e.target.value }))}
                required className="h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Plan</Label>
              {packages.length > 0 ? (
                <Select value={editForm.plan} onValueChange={v => setEditForm(p => ({ ...p, plan: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {packages.filter(pk => pk.isActive).map(pk => {
                      const slug = pk.name.toLowerCase().replace(/\s+/g, "-");
                      return (
                        <SelectItem key={pk.id} value={slug}>
                          {pk.name} {pk.price > 0 ? `· $${pk.price}/mo` : "· Free"} {pk.maxAssets ? `· ${pk.maxAssets} assets` : ""}
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
              ) : (
                <Select value={editForm.plan} onValueChange={v => setEditForm(p => ({ ...p, plan: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["starter", "professional", "enterprise"].map(pl => (
                      <SelectItem key={pl} value={pl} className="capitalize">{pl.charAt(0).toUpperCase() + pl.slice(1)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">Max Assets <span className="text-muted-foreground">(blank = unlimited)</span></Label>
                <Input
                  type="number" min="1"
                  value={editForm.maxAssets}
                  onChange={e => setEditForm(p => ({ ...p, maxAssets: e.target.value }))}
                  placeholder="unlimited" className="h-9"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Max Users <span className="text-muted-foreground">(blank = unlimited)</span></Label>
                <Input
                  type="number" min="1"
                  value={editForm.maxUsers}
                  onChange={e => setEditForm(p => ({ ...p, maxUsers: e.target.value }))}
                  placeholder="unlimited" className="h-9"
                />
              </div>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="checkbox" id="isActive" checked={editForm.isActive}
                onChange={e => setEditForm(p => ({ ...p, isActive: e.target.checked }))}
                className="w-4 h-4 rounded"
              />
              <Label htmlFor="isActive" className="text-xs cursor-pointer">Tenant is active</Label>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setEditTarget(null)}>Cancel</Button>
              <Button type="submit" disabled={updateTenantMutation.isPending}>
                {updateTenantMutation.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Saving…</> : "Save Changes"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* ── Delete Confirmation Dialog ─────────────────────────────────────── */}
      <Dialog open={!!deleteTarget} onOpenChange={v => { if (!v) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete Tenant</DialogTitle>
            <DialogDescription>
              This will permanently delete <strong>{deleteTarget?.name}</strong> and all their assets,
              users, and findings. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="mt-2">
            <Button variant="outline" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={deleteTenantMutation.isPending}
              onClick={() => deleteTarget && deleteTenantMutation.mutate(deleteTarget.id)}
            >
              {deleteTenantMutation.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Deleting…</> : "Delete Tenant"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Assign Account Manager Dialog ─────────────────────────────────── */}
      <Dialog open={!!assignTarget} onOpenChange={v => { if (!v) setAssignTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Assign Account Manager</DialogTitle>
            <DialogDescription>Select an account manager for {assignTarget?.tenantName}.</DialogDescription>
          </DialogHeader>
          <div className="space-y-3 mt-2">
            <div className="space-y-1.5">
              <Label className="text-xs">Account Manager</Label>
              <Select value={selectedAmId} onValueChange={setSelectedAmId}>
                <SelectTrigger className="h-9">
                  <SelectValue placeholder="Select account manager" />
                </SelectTrigger>
                <SelectContent>
                  {amUsers.length === 0
                    ? <SelectItem value="-1" disabled>No account managers available</SelectItem>
                    : amUsers.map(u => (
                        <SelectItem key={u.id} value={String(u.id)}>
                          {u.firstName && u.lastName ? `${u.firstName} ${u.lastName}` : u.email}
                        </SelectItem>
                      ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter className="mt-4">
            <Button variant="outline" onClick={() => setAssignTarget(null)}>Cancel</Button>
            <Button
              disabled={!selectedAmId || assignMutation.isPending}
              onClick={() => assignTarget && assignMutation.mutate({ tenantId: assignTarget.tenantId, amId: Number(selectedAmId) })}
            >
              {assignMutation.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Assigning…</> : "Assign"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Add Asset Dialog ───────────────────────────────────────────────── */}
      <Dialog open={!!assetTarget} onOpenChange={v => { if (!v) setAssetTarget(null); }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Add Asset to {assetTarget?.tenantName}</DialogTitle>
            <DialogDescription>
              Assets are added to this tenant's inventory and will appear in their Asset Inventory page.
            </DialogDescription>
          </DialogHeader>
          <form className="space-y-3 mt-2" onSubmit={e => {
            e.preventDefault();
            if (!assetTarget) return;
            addAssetMutation.mutate({
              tenantId: assetTarget.tenantId,
              body: {
                name: assetForm.name.trim(),
                type: assetForm.type,
                value: assetForm.value.trim(),
                description: assetForm.description.trim() || undefined,
                scanFrequency: assetForm.scanFrequency,
                businessImpact: assetForm.businessImpact,
              },
            });
          }}>
            <div className="space-y-1.5">
              <Label className="text-xs">Asset Name *</Label>
              <Input
                value={assetForm.name}
                onChange={e => setAssetForm(p => ({ ...p, name: e.target.value }))}
                placeholder="e.g. Main Website" required className="h-9"
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
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={assetForm.scanFrequency} onValueChange={v => setAssetForm(p => ({ ...p, scanFrequency: v }))}>
                  <SelectTrigger className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_FREQUENCIES.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
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
            <div className="space-y-1.5">
              <Label className="text-xs">Business Impact: <strong>{assetForm.businessImpact}</strong>/10</Label>
              <Slider
                min={1} max={10} step={1}
                value={[assetForm.businessImpact]}
                onValueChange={([v]) => setAssetForm(p => ({ ...p, businessImpact: v }))}
                className="my-1"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground"><span>Low (1)</span><span>Critical (10)</span></div>
            </div>
            <DialogFooter className="mt-4">
              <Button variant="outline" type="button" onClick={() => setAssetTarget(null)}>Cancel</Button>
              <Button type="submit" disabled={addAssetMutation.isPending}>
                {addAssetMutation.isPending ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />Adding…</> : "Add Asset"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
