import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import {
  Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  RefreshCw, Building2, Shield, Loader2, Plus, Trash2, Globe, LayoutList,
  ChevronFirst, ChevronLast, ChevronLeft, ChevronRight, Search, PackageCheck,
  Lock, CheckCircle2, AlertCircle,
} from "lucide-react";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const PAGE_SIZE = 20;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface TenantRow {
  tenantId:     number;
  tenantName:   string;
  plan:         string;
  isEnabled:    boolean;
  vendorCount:  number;
  avgRiskScore: number;
}

interface AssetRow {
  id:                 number;
  tenantId:           number | null;
  tenantName:         string | null;
  name:               string;
  type:               string;
  value:              string;
  verificationStatus: string;
  isTprmEnabled:      boolean;
  riskLevel:          string | null;
  isActive:           boolean;
  createdAt:          string;
}

interface GlobalVendor {
  id:          number;
  companyName: string;
  domain:      string;
  type:        string;
  status:      string;
  riskScore:   number | null;
  riskGrade:   string | null;
}

interface AllVendor extends GlobalVendor {
  tenantId:     number;
  tenantName:   string | null;
  isGlobal:     boolean;
  lastScannedAt: string | null;
}

type Tab = "module" | "global_library" | "all_vendors";

const RISK_GRADE_COLOR: Record<string, string> = {
  A: "text-green-400", B: "text-green-300", C: "text-yellow-400",
  D: "text-orange-400", F: "text-red-500",
};

const VERIFICATION_BADGE: Record<string, { label: string; className: string; icon: React.ReactNode }> = {
  verified:   { label: "Verified",   className: "bg-green-500/15 text-green-400 border-green-500/30",  icon: <CheckCircle2 className="w-3 h-3" /> },
  pending:    { label: "Pending",    className: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", icon: <AlertCircle className="w-3 h-3" /> },
  unverified: { label: "Unverified", className: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",    icon: <Lock className="w-3 h-3" /> },
  failed:     { label: "Failed",     className: "bg-red-500/15 text-red-400 border-red-500/30",       icon: <AlertCircle className="w-3 h-3" /> },
};

// ─────────────────────────────────────────────────────────────────────────────
// Smart Pagination helpers
// ─────────────────────────────────────────────────────────────────────────────

function getPageNumbers(current: number, total: number): (number | "...")[] {
  if (total <= 9) return Array.from({ length: total }, (_, i) => i + 1);
  const always = new Set([1, total - 2, total - 1, total].filter(p => p >= 1));
  const near   = new Set(
    [current - 2, current - 1, current, current + 1, current + 2].filter(p => p >= 1 && p <= total),
  );
  const all = [...new Set([...always, ...near])].sort((a, b) => a - b);
  const result: (number | "...")[] = [];
  for (let i = 0; i < all.length; i++) {
    result.push(all[i]);
    if (i + 1 < all.length && (all[i + 1] as number) - (all[i] as number) > 1) result.push("...");
  }
  return result;
}

function SmartPagination({
  page, totalPages, total, pageSize, onPage,
}: { page: number; totalPages: number; total: number; pageSize: number; onPage: (p: number) => void }) {
  if (totalPages <= 1) return null;
  const safe = Math.min(page, totalPages);
  const nums = getPageNumbers(safe, totalPages);
  return (
    <div className="flex items-center justify-between px-4 py-3 border-t border-border/40">
      <p className="text-xs text-muted-foreground">
        Showing {(safe - 1) * pageSize + 1}–{Math.min(safe * pageSize, total)} of {total}
      </p>
      <div className="flex items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(1)} title="First page">
          <ChevronFirst className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === 1} onClick={() => onPage(safe - 1)}>
          <ChevronLeft className="w-3.5 h-3.5" />
        </Button>
        {nums.map((p, i) =>
          p === "..." ? (
            <span key={`e-${i}`} className="text-xs text-muted-foreground px-1 select-none">…</span>
          ) : (
            <Button
              key={p}
              variant={p === safe ? "default" : "ghost"}
              size="icon"
              className="h-7 w-7 text-xs"
              onClick={() => onPage(p as number)}
            >
              {p}
            </Button>
          )
        )}
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(safe + 1)}>
          <ChevronRight className="w-3.5 h-3.5" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7" disabled={safe === totalPages} onClick={() => onPage(totalPages)} title="Last page">
          <ChevronLast className="w-3.5 h-3.5" />
        </Button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────

export default function TprmAdminPage() {
  const { user } = useAuth();
  const { toast } = useToast();
  const isAdminOrSA = user?.role === "super_admin" || user?.role === "admin";

  const [tab, setTab] = useState<Tab>("module");

  // ── Overview stats (always loaded) ────────────────────────────────────────
  const [overview, setOverview]   = useState<{ tenants: TenantRow[]; stats: any } | null>(null);
  const [loadingOv, setLoadingOv] = useState(true);

  // ── Module: Asset Inventory state ─────────────────────────────────────────
  const [assets, setAssets]         = useState<AssetRow[]>([]);
  const [assetTotal, setAssetTotal] = useState(0);
  const [assetPage, setAssetPage]   = useState(1);
  const [assetSearch, setAssetSearch] = useState("");
  const [assetVerified, setAssetVerified] = useState(""); // "" | "true" | "false"
  const [loadingAssets, setLoadingAssets] = useState(false);
  const [toggling, setToggling]     = useState<number | null>(null);
  const assetSearchDebounce = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // ── Global library state ───────────────────────────────────────────────────
  const [globals, setGlobals]         = useState<GlobalVendor[]>([]);
  const [globalTotal, setGlobalTotal] = useState(0);
  const [globalPage, setGlobalPage]   = useState(1);
  const [globalSearch, setGlobalSearch] = useState("");
  const [loadingGl, setLoadingGl]     = useState(false);
  const [showAdd, setShowAdd]         = useState(false);
  const [addForm, setAddForm]         = useState({ companyName: "", domain: "", type: "service_provider", industry: "" });
  const [addSaving, setAddSaving]     = useState(false);
  const [deleting, setDeleting]       = useState<number | null>(null);
  const glSearchDebounce = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // ── All vendors state ──────────────────────────────────────────────────────
  const [allVendors, setAllVendors]   = useState<AllVendor[]>([]);
  const [avTotal, setAvTotal]         = useState(0);
  const [avPage, setAvPage]           = useState(1);
  const [avSearch, setAvSearch]       = useState("");
  const [loadingAv, setLoadingAv]     = useState(false);
  const avSearchDebounce = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // ─────────────────────────────────────────────────────────────────────────
  // Loaders
  // ─────────────────────────────────────────────────────────────────────────

  const loadOverview = () => {
    setLoadingOv(true);
    apiFetch<any>("/api/tprm/admin/overview")
      .then(setOverview)
      .catch(() => {})
      .finally(() => setLoadingOv(false));
  };

  const loadAssets = (page = assetPage, search = assetSearch, verified = assetVerified) => {
    setLoadingAssets(true);
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    if (search)   p.set("search", search);
    if (verified) p.set("verified", verified);
    apiFetch<{ assets: AssetRow[]; total: number }>(`/api/tprm/admin/assets?${p}`)
      .then(r => { setAssets(r.assets); setAssetTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoadingAssets(false));
  };

  const loadGlobals = (page = globalPage, search = globalSearch) => {
    setLoadingGl(true);
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    if (search) p.set("search", search);
    apiFetch<{ vendors: GlobalVendor[]; total: number }>(`/api/tprm/admin/global-vendors?${p}`)
      .then(r => { setGlobals(r.vendors); setGlobalTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoadingGl(false));
  };

  const loadAllVendors = (page = avPage, search = avSearch) => {
    setLoadingAv(true);
    const p = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    if (search) p.set("search", search);
    apiFetch<{ vendors: AllVendor[]; total: number }>(`/api/tprm/admin/all-vendors?${p}`)
      .then(r => { setAllVendors(r.vendors); setAvTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoadingAv(false));
  };

  // Initial loads
  useEffect(() => { loadOverview(); }, []);
  useEffect(() => { if (tab === "module")         loadAssets(1, assetSearch, assetVerified); }, [tab]);
  useEffect(() => { if (tab === "global_library") loadGlobals(1, globalSearch); }, [tab]);
  useEffect(() => { if (tab === "all_vendors")    loadAllVendors(1, avSearch); }, [tab]);

  // ─────────────────────────────────────────────────────────────────────────
  // Search debouncing
  // ─────────────────────────────────────────────────────────────────────────

  const handleAssetSearch = (v: string) => {
    setAssetSearch(v); setAssetPage(1);
    clearTimeout(assetSearchDebounce.current);
    assetSearchDebounce.current = setTimeout(() => loadAssets(1, v, assetVerified), 350);
  };

  const handleAssetVerified = (v: string) => {
    setAssetVerified(v); setAssetPage(1);
    loadAssets(1, assetSearch, v);
  };

  const handleGlSearch = (v: string) => {
    setGlobalSearch(v); setGlobalPage(1);
    clearTimeout(glSearchDebounce.current);
    glSearchDebounce.current = setTimeout(() => loadGlobals(1, v), 350);
  };

  const handleAvSearch = (v: string) => {
    setAvSearch(v); setAvPage(1);
    clearTimeout(avSearchDebounce.current);
    avSearchDebounce.current = setTimeout(() => loadAllVendors(1, v), 350);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Actions
  // ─────────────────────────────────────────────────────────────────────────

  const toggleAssetTprm = async (asset: AssetRow) => {
    if (asset.verificationStatus !== "verified" && !asset.isTprmEnabled) {
      toast({ title: "Asset not verified", description: "Verify the asset first to enable TPRM.", variant: "destructive" });
      return;
    }
    setToggling(asset.id);
    try {
      await apiFetch(`/api/tprm/admin/assets/${asset.id}`, {
        method: "PATCH",
        body: JSON.stringify({ isTprmEnabled: !asset.isTprmEnabled }),
      });
      setAssets(prev => prev.map(a => a.id === asset.id ? { ...a, isTprmEnabled: !a.isTprmEnabled } : a));
      toast({ title: !asset.isTprmEnabled ? "TPRM enabled" : "TPRM disabled" });
    } catch (err: any) {
      toast({ title: "Failed to toggle TPRM", description: err?.message ?? "", variant: "destructive" });
    }
    setToggling(null);
  };

  const handleAddGlobal = async () => {
    if (!addForm.companyName || !addForm.domain) return;
    setAddSaving(true);
    try {
      await apiFetch("/api/tprm/admin/global-vendors", {
        method: "POST",
        body: JSON.stringify(addForm),
      });
      setShowAdd(false);
      setAddForm({ companyName: "", domain: "", type: "service_provider", industry: "" });
      setGlobalPage(1);
      loadGlobals(1, globalSearch);
      toast({ title: "Global vendor added" });
    } catch { /* ignore */ }
    setAddSaving(false);
  };

  const handleDeleteGlobal = async (id: number) => {
    setDeleting(id);
    try {
      await apiFetch(`/api/tprm/admin/global-vendors/${id}`, { method: "DELETE" });
      setGlobals(prev => prev.filter(v => v.id !== id));
      setGlobalTotal(t => t - 1);
      toast({ title: "Global vendor deleted" });
    } catch { /* ignore */ }
    setDeleting(null);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Pagination pages
  // ─────────────────────────────────────────────────────────────────────────

  const assetTotalPages  = Math.max(1, Math.ceil(assetTotal / PAGE_SIZE));
  const globalTotalPages = Math.max(1, Math.ceil(globalTotal / PAGE_SIZE));
  const avTotalPages     = Math.max(1, Math.ceil(avTotal / PAGE_SIZE));

  // ─────────────────────────────────────────────────────────────────────────
  // Render helpers
  // ─────────────────────────────────────────────────────────────────────────

  const tabClass = (t: Tab) =>
    `px-4 py-2 text-sm font-medium rounded-md transition-colors cursor-pointer ${
      tab === t
        ? "bg-accent text-accent-foreground"
        : "text-muted-foreground hover:text-foreground hover:bg-accent/50"
    }`;

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">TPRM Module Administration</h1>
          <p className="text-muted-foreground text-sm">Manage Third Party Risk Management across the platform</p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            if (tab === "module")         { loadOverview(); loadAssets(); }
            if (tab === "global_library") loadGlobals();
            if (tab === "all_vendors")    loadAllVendors();
          }}
        >
          <RefreshCw className="w-4 h-4" />
        </Button>
      </div>

      {/* Stats (always visible) */}
      {overview && (
        <div className="grid grid-cols-3 gap-3">
          <Card className="bg-card/60">
            <CardContent className="pt-3 pb-3">
              <p className="text-xs text-muted-foreground">Total Tenants</p>
              <p className="text-xl font-bold mt-0.5">{overview.stats.total}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/60">
            <CardContent className="pt-3 pb-3">
              <p className="text-xs text-muted-foreground">TPRM Enabled</p>
              <p className="text-xl font-bold mt-0.5 text-green-400">{overview.stats.enabled}</p>
            </CardContent>
          </Card>
          <Card className="bg-card/60">
            <CardContent className="pt-3 pb-3">
              <p className="text-xs text-muted-foreground">TPRM Disabled</p>
              <p className="text-xl font-bold mt-0.5 text-muted-foreground">{overview.stats.disabled}</p>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border/50 pb-1">
        <button className={tabClass("module")} onClick={() => setTab("module")}>
          <span className="flex items-center gap-1.5"><Shield className="w-4 h-4" />Module Settings</span>
        </button>
        {isAdminOrSA && (
          <button className={tabClass("global_library")} onClick={() => setTab("global_library")}>
            <span className="flex items-center gap-1.5"><Globe className="w-4 h-4" />Global Vendor Library</span>
          </button>
        )}
        {isAdminOrSA && (
          <button className={tabClass("all_vendors")} onClick={() => setTab("all_vendors")}>
            <span className="flex items-center gap-1.5"><LayoutList className="w-4 h-4" />All Vendors</span>
          </button>
        )}
      </div>

      {/* ── Tab: Module Settings — Asset Inventory ── */}
      {tab === "module" && (
        <div className="space-y-4">
          {/* Description */}
          <div className="flex items-start gap-3 p-3 rounded-lg bg-blue-500/5 border border-blue-500/20">
            <PackageCheck className="w-5 h-5 text-blue-400 mt-0.5 shrink-0" />
            <div className="text-sm text-muted-foreground">
              Enable the TPRM module for individual assets. Only <span className="text-green-400 font-medium">verified</span> assets can have TPRM activated. Unverified assets must be verified in Asset Inventory first.
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                className="pl-8 h-8 text-sm"
                placeholder="Search assets…"
                value={assetSearch}
                onChange={e => handleAssetSearch(e.target.value)}
              />
            </div>
            <Select value={assetVerified || "all"} onValueChange={v => handleAssetVerified(v === "all" ? "" : v)}>
              <SelectTrigger className="h-8 w-[160px] text-sm">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All statuses</SelectItem>
                <SelectItem value="true">Verified only</SelectItem>
                <SelectItem value="false">Unverified only</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-xs text-muted-foreground ml-auto">
              {assetTotal} asset{assetTotal !== 1 ? "s" : ""}
            </span>
          </div>

          {/* Asset table */}
          <Card>
            <CardContent className="p-0">
              {loadingAssets ? (
                <div className="p-4 space-y-2">
                  {Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}
                </div>
              ) : assets.length === 0 ? (
                <div className="p-10 text-center text-muted-foreground text-sm">
                  {assetSearch || assetVerified ? "No assets match your filters." : "No assets found."}
                </div>
              ) : (
                <>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Asset</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Type</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Tenant</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Verification</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Risk</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">TPRM</th>
                      </tr>
                    </thead>
                    <tbody>
                      {assets.map(a => {
                        const vs = VERIFICATION_BADGE[a.verificationStatus] ?? VERIFICATION_BADGE.unverified;
                        const isVerified = a.verificationStatus === "verified";
                        const isDisabled = !isVerified && !a.isTprmEnabled;
                        return (
                          <tr key={a.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                            <td className="px-4 py-2.5">
                              <p className="font-medium truncate max-w-[200px]">{a.name}</p>
                              <p className="text-[11px] text-muted-foreground font-mono truncate max-w-[200px]">{a.value}</p>
                            </td>
                            <td className="px-4 py-2.5">
                              <Badge variant="secondary" className="text-[10px] capitalize">{a.type.replace(/_/g, " ")}</Badge>
                            </td>
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-1.5">
                                <Building2 className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                                <span className="text-xs">{a.tenantName ?? `#${a.tenantId}`}</span>
                              </div>
                            </td>
                            <td className="px-4 py-2.5">
                              <span className={`inline-flex items-center gap-1 text-[11px] font-medium px-2 py-0.5 rounded-full border ${vs.className}`}>
                                {vs.icon}{vs.label}
                              </span>
                            </td>
                            <td className="px-4 py-2.5">
                              {a.riskLevel
                                ? <Badge variant="outline" className="text-[10px] capitalize">{a.riskLevel}</Badge>
                                : <span className="text-muted-foreground text-xs">—</span>}
                            </td>
                            <td className="px-4 py-2.5">
                              <div className="flex items-center gap-2">
                                {toggling === a.id && <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />}
                                <Switch
                                  checked={a.isTprmEnabled}
                                  onCheckedChange={() => toggleAssetTprm(a)}
                                  disabled={toggling !== null || isDisabled}
                                  title={isDisabled ? "Asset must be verified first" : undefined}
                                />
                                {isDisabled && (
                                  <span className="text-[10px] text-muted-foreground">Verify first</span>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  <SmartPagination
                    page={assetPage}
                    totalPages={assetTotalPages}
                    total={assetTotal}
                    pageSize={PAGE_SIZE}
                    onPage={p => { setAssetPage(p); loadAssets(p, assetSearch, assetVerified); }}
                  />
                </>
              )}
            </CardContent>
          </Card>

          {/* Tenant overview accordion (secondary) */}
          {isAdminOrSA && overview && (
            <Card className="border-dashed">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Building2 className="w-4 h-4" />Tenant-level TPRM Toggles
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {loadingOv ? (
                  <div className="p-4 space-y-2">{Array(4).fill(0).map((_, i) => <Skeleton key={i} className="h-11" />)}</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2">Tenant</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2">Plan</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2">Vendors</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2">TPRM</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(overview.tenants ?? []).map(t => (
                        <tr key={t.tenantId} className="border-b border-border/20 hover:bg-accent/20 transition-colors">
                          <td className="px-4 py-2">
                            <div className="flex items-center gap-2">
                              <Building2 className="w-3.5 h-3.5 text-muted-foreground" />
                              <span className="font-medium text-sm">{t.tenantName}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2">
                            <Badge variant="outline" className="text-[10px] capitalize">{t.plan}</Badge>
                          </td>
                          <td className="px-4 py-2 text-muted-foreground text-sm">{t.vendorCount}</td>
                          <td className="px-4 py-2">
                            <Badge
                              variant="outline"
                              className={t.isEnabled ? "bg-green-500/15 text-green-400 border-green-500/30 text-[10px]" : "text-[10px] text-muted-foreground"}
                            >
                              {t.isEnabled ? "Enabled" : "Disabled"}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* ── Tab: Global Vendor Library ── */}
      {tab === "global_library" && isAdminOrSA && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                className="pl-8 h-8 text-sm"
                placeholder="Search global vendors…"
                value={globalSearch}
                onChange={e => handleGlSearch(e.target.value)}
              />
            </div>
            <span className="text-xs text-muted-foreground">{globalTotal} vendor{globalTotal !== 1 ? "s" : ""}</span>
            <Button size="sm" onClick={() => setShowAdd(true)} className="gap-1.5 ml-auto">
              <Plus className="w-4 h-4" />Add Global Vendor
            </Button>
          </div>
          <p className="text-xs text-muted-foreground -mt-2">
            Global vendors are shared across all tenants. All tenants can view and scan them.
          </p>

          <Card>
            <CardContent className="p-0">
              {loadingGl ? (
                <div className="p-4 space-y-2">{Array(6).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
              ) : globals.length === 0 ? (
                <div className="p-10 text-center text-muted-foreground text-sm">
                  {globalSearch ? "No vendors match your search." : "No global vendors yet."}
                </div>
              ) : (
                <>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Company</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Domain</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Type</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Status</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Risk</th>
                        <th className="px-4 py-2.5" />
                      </tr>
                    </thead>
                    <tbody>
                      {globals.map(v => (
                        <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                          <td className="px-4 py-2.5 font-medium">{v.companyName}</td>
                          <td className="px-4 py-2.5 text-muted-foreground font-mono text-xs">{v.domain}</td>
                          <td className="px-4 py-2.5">
                            <Badge variant="secondary" className="text-[10px] capitalize">{v.type.replace(/_/g, " ")}</Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge variant="outline" className="text-[10px] capitalize">{v.status}</Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            {v.riskGrade
                              ? <span className={`font-bold ${RISK_GRADE_COLOR[v.riskGrade] ?? ""}`}>{v.riskGrade} ({v.riskScore}/100)</span>
                              : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="text-destructive hover:text-destructive"
                              disabled={deleting === v.id}
                              onClick={() => handleDeleteGlobal(v.id)}
                            >
                              {deleting === v.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <SmartPagination
                    page={globalPage}
                    totalPages={globalTotalPages}
                    total={globalTotal}
                    pageSize={PAGE_SIZE}
                    onPage={p => { setGlobalPage(p); loadGlobals(p, globalSearch); }}
                  />
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Tab: All Vendors (cross-tenant) ── */}
      {tab === "all_vendors" && isAdminOrSA && (
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-[200px] max-w-xs">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                className="pl-8 h-8 text-sm"
                placeholder="Search by name or domain…"
                value={avSearch}
                onChange={e => handleAvSearch(e.target.value)}
              />
            </div>
            <span className="text-xs text-muted-foreground">{avTotal} vendor{avTotal !== 1 ? "s" : ""}</span>
          </div>

          <Card>
            <CardContent className="p-0">
              {loadingAv ? (
                <div className="p-4 space-y-2">{Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-11" />)}</div>
              ) : allVendors.length === 0 ? (
                <div className="p-10 text-center text-muted-foreground text-sm">
                  {avSearch ? "No vendors match your search." : "No vendors found."}
                </div>
              ) : (
                <>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Company</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Domain</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Tenant</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Type</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Risk</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Global</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Last Scan</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allVendors.map(v => (
                        <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                          <td className="px-4 py-2.5 font-medium">{v.companyName}</td>
                          <td className="px-4 py-2.5 text-muted-foreground font-mono text-xs">{v.domain}</td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-1.5">
                              <Building2 className="w-3.5 h-3.5 text-muted-foreground" />
                              <span className="text-xs">{v.tenantName ?? `#${v.tenantId}`}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge variant="secondary" className="text-[10px] capitalize">{v.type.replace(/_/g, " ")}</Badge>
                          </td>
                          <td className="px-4 py-2.5">
                            {v.riskGrade
                              ? <span className={`font-bold ${RISK_GRADE_COLOR[v.riskGrade] ?? ""}`}>{v.riskGrade}</span>
                              : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="px-4 py-2.5">
                            {v.isGlobal
                              ? <Badge className="bg-blue-500/20 text-blue-400 text-[10px]">Global</Badge>
                              : <span className="text-muted-foreground text-xs">—</span>}
                          </td>
                          <td className="px-4 py-2.5 text-xs text-muted-foreground">
                            {v.lastScannedAt ? new Date(v.lastScannedAt).toLocaleDateString() : "Never"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <SmartPagination
                    page={avPage}
                    totalPages={avTotalPages}
                    total={avTotal}
                    pageSize={PAGE_SIZE}
                    onPage={p => { setAvPage(p); loadAllVendors(p, avSearch); }}
                  />
                </>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Add Global Vendor dialog ── */}
      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Add Global Vendor</DialogTitle>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Company Name *</label>
              <Input
                placeholder="Acme Corp"
                value={addForm.companyName}
                onChange={e => setAddForm(f => ({ ...f, companyName: e.target.value }))}
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Domain *</label>
              <Input
                placeholder="acme.com"
                value={addForm.domain}
                onChange={e => setAddForm(f => ({ ...f, domain: e.target.value }))}
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Type</label>
              <Select value={addForm.type} onValueChange={v => setAddForm(f => ({ ...f, type: v }))}>
                <SelectTrigger className="h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="service_provider">Service Provider</SelectItem>
                  <SelectItem value="software_vendor">Software Vendor</SelectItem>
                  <SelectItem value="cloud_provider">Cloud Provider</SelectItem>
                  <SelectItem value="partner">Partner</SelectItem>
                  <SelectItem value="subsidiary">Subsidiary</SelectItem>
                  <SelectItem value="sister_concern">Sister Concern</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground">Industry</label>
              <Input
                placeholder="Technology"
                value={addForm.industry}
                onChange={e => setAddForm(f => ({ ...f, industry: e.target.value }))}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={handleAddGlobal} disabled={addSaving || !addForm.companyName || !addForm.domain}>
              {addSaving ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Plus className="w-4 h-4 mr-2" />}
              Add Vendor
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
