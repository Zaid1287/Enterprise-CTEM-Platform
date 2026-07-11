import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useAuth } from "@/hooks/useAuth";
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
} from "lucide-react";

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

// ─────────────────────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────────────────────

export default function TprmAdminPage() {
  const { user } = useAuth();
  const isSA = user?.role === "super_admin";

  const [tab, setTab] = useState<Tab>("module");

  // ── Module settings state ──────────────────────────────────────────────────
  const [overview, setOverview]     = useState<{ tenants: TenantRow[]; stats: any } | null>(null);
  const [loadingOv, setLoadingOv]   = useState(true);
  const [toggling, setToggling]     = useState<number | null>(null);

  // ── Global library state ───────────────────────────────────────────────────
  const [globals, setGlobals]       = useState<GlobalVendor[]>([]);
  const [loadingGl, setLoadingGl]   = useState(false);
  const [showAdd, setShowAdd]       = useState(false);
  const [addForm, setAddForm]       = useState({ companyName: "", domain: "", type: "service_provider", industry: "" });
  const [addSaving, setAddSaving]   = useState(false);
  const [deleting, setDeleting]     = useState<number | null>(null);

  // ── All vendors state ──────────────────────────────────────────────────────
  const [allVendors, setAllVendors] = useState<AllVendor[]>([]);
  const [loadingAv, setLoadingAv]   = useState(false);
  const [avSearch, setAvSearch]     = useState("");

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

  const loadGlobals = () => {
    setLoadingGl(true);
    apiFetch<GlobalVendor[]>("/api/tprm/admin/global-vendors")
      .then(setGlobals)
      .catch(() => {})
      .finally(() => setLoadingGl(false));
  };

  const loadAllVendors = () => {
    setLoadingAv(true);
    apiFetch<AllVendor[]>("/api/tprm/admin/all-vendors")
      .then(setAllVendors)
      .catch(() => {})
      .finally(() => setLoadingAv(false));
  };

  useEffect(() => { loadOverview(); }, []);
  useEffect(() => {
    if (tab === "global_library" && globals.length === 0) loadGlobals();
    if (tab === "all_vendors"    && allVendors.length === 0) loadAllVendors();
  }, [tab]);

  // ─────────────────────────────────────────────────────────────────────────
  // Actions
  // ─────────────────────────────────────────────────────────────────────────

  const toggle = async (tenantId: number, current: boolean) => {
    setToggling(tenantId);
    try {
      await apiFetch("/api/tprm/module", { method: "PATCH", body: JSON.stringify({ tenantId, isEnabled: !current }) });
      loadOverview();
    } catch { /* ignore */ }
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
      loadGlobals();
    } catch { /* ignore */ }
    setAddSaving(false);
  };

  const handleDeleteGlobal = async (id: number) => {
    setDeleting(id);
    try {
      await apiFetch(`/api/tprm/admin/global-vendors/${id}`, { method: "DELETE" });
      setGlobals(prev => prev.filter(v => v.id !== id));
    } catch { /* ignore */ }
    setDeleting(null);
  };

  // ─────────────────────────────────────────────────────────────────────────
  // Filtered all-vendors list
  // ─────────────────────────────────────────────────────────────────────────

  const filteredAv = allVendors.filter(v =>
    !avSearch ||
    v.companyName.toLowerCase().includes(avSearch.toLowerCase()) ||
    v.domain.toLowerCase().includes(avSearch.toLowerCase()) ||
    (v.tenantName ?? "").toLowerCase().includes(avSearch.toLowerCase())
  );

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
    <div className="p-6 space-y-5 max-w-[1200px] mx-auto">
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
            if (tab === "module")         loadOverview();
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
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">Total Tenants</p><p className="text-xl font-bold mt-0.5">{overview.stats.total}</p></CardContent></Card>
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">TPRM Enabled</p><p className="text-xl font-bold mt-0.5 text-green-400">{overview.stats.enabled}</p></CardContent></Card>
          <Card className="bg-card/60"><CardContent className="pt-3 pb-3"><p className="text-xs text-muted-foreground">TPRM Disabled</p><p className="text-xl font-bold mt-0.5 text-muted-foreground">{overview.stats.disabled}</p></CardContent></Card>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border/50 pb-1">
        <button className={tabClass("module")} onClick={() => setTab("module")}>
          <span className="flex items-center gap-1.5"><Shield className="w-4 h-4" />Module Settings</span>
        </button>
        {isSA && (
          <button className={tabClass("global_library")} onClick={() => setTab("global_library")}>
            <span className="flex items-center gap-1.5"><Globe className="w-4 h-4" />Global Vendor Library</span>
          </button>
        )}
        {isSA && (
          <button className={tabClass("all_vendors")} onClick={() => setTab("all_vendors")}>
            <span className="flex items-center gap-1.5"><LayoutList className="w-4 h-4" />All Vendors</span>
          </button>
        )}
      </div>

      {/* ── Tab: Module Settings ── */}
      {tab === "module" && (
        <div className="space-y-4">
          {/* Own tenant toggle for admins */}
          {user?.role === "admin" && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">Your Organization</CardTitle></CardHeader>
              <CardContent className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">Enable TPRM Module</p>
                  <p className="text-xs text-muted-foreground">Enable Third Party Risk Management for your organization</p>
                </div>
                {loadingOv ? <Skeleton className="h-6 w-12" /> : (
                  <div className="flex items-center gap-2">
                    {toggling === user.tenantId && <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />}
                    <Switch
                      checked={overview?.tenants.find(t => t.tenantId === user.tenantId)?.isEnabled ?? false}
                      onCheckedChange={() => toggle(user.tenantId, overview?.tenants.find(t => t.tenantId === user.tenantId)?.isEnabled ?? false)}
                      disabled={toggling !== null}
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Super admin tenant table */}
          {isSA && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-sm">All Tenants — TPRM Toggle</CardTitle></CardHeader>
              <CardContent className="p-0">
                {loadingOv ? (
                  <div className="p-4 space-y-2">{Array(5).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
                ) : (
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Tenant</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Plan</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Vendors</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Avg Risk</th>
                        <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">TPRM</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(overview?.tenants ?? []).map(t => (
                        <tr key={t.tenantId} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              <Building2 className="w-4 h-4 text-muted-foreground" />
                              <span className="font-medium">{t.tenantName}</span>
                            </div>
                          </td>
                          <td className="px-4 py-2.5"><Badge variant="outline" className="text-[10px] capitalize">{t.plan}</Badge></td>
                          <td className="px-4 py-2.5 text-muted-foreground">{t.vendorCount}</td>
                          <td className="px-4 py-2.5">
                            {t.vendorCount > 0
                              ? <span className={t.avgRiskScore >= 70 ? "text-green-400" : t.avgRiskScore >= 50 ? "text-yellow-400" : "text-red-400"}>{t.avgRiskScore}/100</span>
                              : <span className="text-muted-foreground">—</span>}
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              {toggling === t.tenantId && <Loader2 className="w-3.5 h-3.5 animate-spin text-muted-foreground" />}
                              <Switch
                                checked={t.isEnabled}
                                onCheckedChange={() => toggle(t.tenantId, t.isEnabled)}
                                disabled={toggling !== null}
                              />
                            </div>
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
      {tab === "global_library" && isSA && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Global vendors are shared across all tenants. All tenants can view and scan them, but only super_admins can create or delete them.
            </p>
            <Button size="sm" onClick={() => setShowAdd(true)} className="gap-1.5">
              <Plus className="w-4 h-4" />Add Global Vendor
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              {loadingGl ? (
                <div className="p-4 space-y-2">{Array(5).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
              ) : globals.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground text-sm">No global vendors yet.</div>
              ) : (
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
                        <td className="px-4 py-2.5"><Badge variant="secondary" className="text-[10px] capitalize">{v.type.replace(/_/g, " ")}</Badge></td>
                        <td className="px-4 py-2.5"><Badge variant="outline" className="text-[10px] capitalize">{v.status}</Badge></td>
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
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ── Tab: All Vendors (cross-tenant) ── */}
      {tab === "all_vendors" && isSA && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <Input
              className="max-w-xs h-8 text-sm"
              placeholder="Search by name, domain, tenant…"
              value={avSearch}
              onChange={e => setAvSearch(e.target.value)}
            />
            <span className="text-xs text-muted-foreground">{filteredAv.length} vendor{filteredAv.length !== 1 ? "s" : ""}</span>
          </div>

          <Card>
            <CardContent className="p-0">
              {loadingAv ? (
                <div className="p-4 space-y-2">{Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-11" />)}</div>
              ) : filteredAv.length === 0 ? (
                <div className="p-8 text-center text-muted-foreground text-sm">No vendors found.</div>
              ) : (
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
                    {filteredAv.map(v => (
                      <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                        <td className="px-4 py-2.5 font-medium">{v.companyName}</td>
                        <td className="px-4 py-2.5 text-muted-foreground font-mono text-xs">{v.domain}</td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <Building2 className="w-3.5 h-3.5 text-muted-foreground" />
                            <span className="text-xs">{v.tenantName ?? `#${v.tenantId}`}</span>
                          </div>
                        </td>
                        <td className="px-4 py-2.5"><Badge variant="secondary" className="text-[10px] capitalize">{v.type.replace(/_/g, " ")}</Badge></td>
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
            <Button
              disabled={!addForm.companyName || !addForm.domain || addSaving}
              onClick={handleAddGlobal}
            >
              {addSaving ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Add Vendor
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
