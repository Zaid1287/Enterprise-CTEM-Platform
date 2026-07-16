import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Plus, Search, RefreshCw, Building2, Loader2, Globe, LayoutGrid, LayoutList, ExternalLink, TrendingUp, Play, ScanLine, Pencil, Trash2 } from "lucide-react";
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip as RechartsTooltip, CartesianGrid, Legend, BarChart, Bar, Cell } from "recharts";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";

const VENDOR_TYPES = [
  { value: "service_provider",  label: "Service Provider" },
  { value: "software_vendor",   label: "Software Vendor" },
  { value: "cloud_provider",    label: "Cloud Provider" },
  { value: "hardware_vendor",   label: "Hardware Vendor" },
  { value: "data_processor",    label: "Data Processor" },
  { value: "consultant",        label: "Consultant" },
  { value: "partner",           label: "Partner" },
  { value: "subsidiary",        label: "Subsidiary" },
  { value: "prospecting",       label: "Prospecting" },
];

const SCAN_FREQUENCIES = [
  { value: "manual",     label: "Manual",              desc: "Only scan when you trigger it manually" },
  { value: "daily",      label: "Daily (Continuous)",  desc: "Scan every day — recommended for critical vendors" },
  { value: "weekly",     label: "Weekly",              desc: "Scan once per week — good for high-risk vendors" },
  { value: "monthly",    label: "Monthly",             desc: "Scan once per month — suitable for low-risk vendors" },
];

interface Vendor {
  id: number;
  companyName: string;
  domain: string;
  type: string;
  industry: string | null;
  riskScore: number;
  riskGrade: string;
  status: string;
  logoUrl: string | null;
  website: string | null;
  lastScannedAt: string | null;
  assetCount: number;
  inherentRisk: string | null;
  scanFrequency: string | null;
  assessmentType: string | null;
}

function gradeBadge(grade: string) {
  const c = grade === "A+" || grade === "A" ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B"  ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C"  ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D"  ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-bold border ${c}`}>{grade}</span>;
}

function riskBar(score: number) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 h-1.5 rounded bg-muted overflow-hidden"><div className={`h-full rounded ${color}`} style={{ width: `${score}%` }} /></div>
      <span className="text-xs font-medium w-8 text-right">{score}</span>
    </div>
  );
}

interface EnrichPreview {
  companyName: string; domain: string; logoUrl: string | null; industry: string | null;
  description: string | null; location: string | null; companyType: string | null;
  source: string; existingVendor?: { id: number; companyName: string } | null;
}

export default function TprmVendorsPage() {
  const [, navigate] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const role = user?.role ?? "client";
  const canManage = role === "super_admin" || role === "admin" || role === "account_manager";

  const [vendors, setVendors]   = useState<Vendor[]>([]);
  const [total, setTotal]       = useState(0);
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState("");
  const [type, setType]         = useState("all");
  const [riskGrade, setRiskGrade] = useState("all");
  const [page, setPage]         = useState(1);
  const [view, setView]         = useState<"table" | "grid">("table");

  // Per-vendor scanning state (problems 3 & 8)
  const [scanningIds, setScanningIds] = useState<Set<number>>(new Set());
  const [bulkScanning, setBulkScanning] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [showAdd, setShowAdd]   = useState(false);
  const [domain, setDomain]     = useState("");
  const [enriching, setEnriching] = useState(false);
  const [preview, setPreview]   = useState<EnrichPreview | null>(null);
  const [form, setForm]         = useState({ companyName: "", type: "service_provider", industry: "", description: "", inherentRisk: "medium", businessImpact: "5", scanFrequency: "weekly" });
  const [saving, setSaving]     = useState(false);

  // Edit / Delete state
  const [showEdit, setShowEdit]           = useState(false);
  const [editingVendor, setEditingVendor] = useState<Vendor | null>(null);
  const [editForm, setEditForm]           = useState({ companyName: "", domain: "", type: "service_provider", industry: "", description: "", inherentRisk: "medium", scanFrequency: "weekly", status: "active", website: "" });
  const [editSaving, setEditSaving]       = useState(false);
  const [deletingId, setDeletingId]       = useState<number | null>(null);

  const [assetsSummary, setAssetsSummary] = useState<{ domains: number; subdomains: number; ipAddresses: number; webApps: number; mobileApps: number } | null>(null);
  const [timeline, setTimeline] = useState<{ weeks: { label: string; assetCount: number; issueCount: number; vendorCount: number }[]; topAssetTypes: { type: string; count: number }[] } | null>(null);

  const load = () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: "30" });
    if (search)    params.set("search", search);
    if (type !== "all") params.set("type", type);
    if (riskGrade !== "all") params.set("riskGrade", riskGrade);
    apiFetch<{ vendors: Vendor[]; total: number }>(`/api/tprm/vendors?${params}`)
      .then(r => { setVendors(r.vendors); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, [search, type, riskGrade, page]);

  // Auto-poll every 5 s when any vendor is scanning (problems 3)
  useEffect(() => {
    const hasPending = vendors.some(v => v.status === "pending" || v.status === "scanning") || scanningIds.size > 0 || bulkScanning;
    if (hasPending && !pollRef.current) {
      pollRef.current = setInterval(() => {
        const params = new URLSearchParams({ page: String(page), limit: "30" });
        if (search) params.set("search", search);
        if (type !== "all") params.set("type", type);
        if (riskGrade !== "all") params.set("riskGrade", riskGrade);
        apiFetch<{ vendors: Vendor[]; total: number }>(`/api/tprm/vendors?${params}`)
          .then(r => {
            setVendors(r.vendors);
            setTotal(r.total);
            const stillPending = r.vendors.some(v => v.status === "pending" || v.status === "scanning");
            if (!stillPending) {
              setScanningIds(new Set());
              setBulkScanning(false);
              if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
            }
          })
          .catch(() => {});
      }, 5000);
    } else if (!hasPending && pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current && !hasPending) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, [vendors, scanningIds, bulkScanning]);

  const [comparison, setComparison] = useState<any[] | null>(null);

  useEffect(() => {
    apiFetch<any>("/api/tprm/vendors/assets-summary").then(setAssetsSummary).catch(() => {});
    apiFetch<any>("/api/tprm/vendors/timeline").then(setTimeline).catch(() => {});
    apiFetch<any[]>("/api/tprm/vendors/compare").then(setComparison).catch(() => {});
  }, []);

  // Problem 8: Per-row individual scan trigger (all roles can use this)
  const handleScan = async (e: React.MouseEvent, vendorId: number) => {
    e.stopPropagation();
    if (scanningIds.has(vendorId)) return;
    setScanningIds(prev => new Set([...prev, vendorId]));
    try {
      await apiFetch(`/api/tprm/vendors/${vendorId}/scan`, { method: "POST" });
    } catch { /* ignore */ }
  };

  // Problem 1: Bulk Rescan All button
  const handleBulkScan = async () => {
    if (bulkScanning) return;
    setBulkScanning(true);
    try {
      await apiFetch("/api/tprm/vendors/bulk-scan", { method: "POST" });
    } catch {
      setBulkScanning(false);
    }
  };

  const handleEnrich = async () => {
    if (!domain.trim()) return;
    setEnriching(true); setPreview(null);
    try {
      const d = await apiFetch<EnrichPreview>("/api/tprm/enrich", { method: "POST", body: JSON.stringify({ domain: domain.trim() }) });
      setPreview(d);
      setForm(f => ({ ...f, companyName: d.companyName, industry: d.industry ?? "", description: d.description ?? "" }));
    } catch { /* ignore */ }
    setEnriching(false);
  };

  const handleAdd = async () => {
    if (!form.companyName || !domain) return;
    setSaving(true);
    try {
      const v = await apiFetch<{ id: number }>("/api/tprm/vendors", {
        method: "POST",
        body: JSON.stringify({ ...form, domain: domain.trim(), logoUrl: preview?.logoUrl ?? null, location: preview?.location ?? null, companyType: preview?.companyType ?? null }),
      });
      setShowAdd(false); setDomain(""); setPreview(null);
      setForm({ companyName: "", type: "service_provider", industry: "", description: "", inherentRisk: "medium", businessImpact: "5", scanFrequency: "weekly" });
      navigate(`/tprm/vendors/${v.id}`);
    } catch { /* ignore */ }
    setSaving(false);
  };

  const openEdit = (e: React.MouseEvent, v: Vendor) => {
    e.stopPropagation();
    setEditingVendor(v);
    setEditForm({
      companyName:   v.companyName,
      domain:        v.domain ?? "",
      type:          v.type,
      industry:      v.industry ?? "",
      description:   (v as any).description ?? "",
      inherentRisk:  v.inherentRisk ?? "medium",
      scanFrequency: v.scanFrequency ?? "weekly",
      status:        v.status ?? "active",
      website:       v.website ?? "",
    });
    setShowEdit(true);
  };

  const handleEditSave = async () => {
    if (!editingVendor) return;
    setEditSaving(true);
    try {
      await apiFetch(`/api/tprm/vendors/${editingVendor.id}`, {
        method: "PATCH",
        body: JSON.stringify(editForm),
      });
      setShowEdit(false);
      setEditingVendor(null);
      load();
      toast({ title: "Vendor updated", description: `${editForm.companyName} has been updated.` });
    } catch (err: any) {
      toast({ title: "Update failed", description: err?.error ?? err?.message ?? "Unknown error", variant: "destructive" });
    }
    setEditSaving(false);
  };

  const handleDelete = async (e: React.MouseEvent, v: Vendor) => {
    e.stopPropagation();
    if (!confirm(`Delete "${v.companyName}"? This will remove all associated scan data and findings.`)) return;
    setDeletingId(v.id);
    try {
      await apiFetch(`/api/tprm/vendors/${v.id}`, { method: "DELETE" });
      load();
      toast({ title: "Vendor deleted", description: `${v.companyName} has been removed.` });
    } catch (err: any) {
      toast({ title: "Delete failed", description: err?.error ?? err?.message ?? "Unknown error", variant: "destructive" });
    }
    setDeletingId(null);
  };

  const typeLabel = (t: string) => VENDOR_TYPES.find(v => v.value === t)?.label ?? t.replace(/_/g, " ");
  const fmtDate   = (d: string | null) => d ? new Date(d).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) : "—";

  // Count by type for the header KPIs
  const serviceProvidersCount = vendors.filter(v => v.type === "service_provider").length;
  const prospectingCount      = vendors.filter(v => v.type === "prospecting").length;
  const subsidiaryCount       = vendors.filter(v => v.type === "subsidiary").length;

  // Determine if a vendor row is actively scanning
  const isScanning = (v: Vendor) => scanningIds.has(v.id) || v.status === "pending" || v.status === "scanning";

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">3rd Party Companies</h1>
          <p className="text-muted-foreground text-sm">{total} vendor{total !== 1 ? "s" : ""} tracked</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Problem 1: Rescan All button */}
          <Button size="sm" variant="outline" onClick={handleBulkScan} disabled={bulkScanning || vendors.length === 0}>
            {bulkScanning
              ? <><Loader2 className="w-4 h-4 mr-1.5 animate-spin" />Scanning…</>
              : <><ScanLine className="w-4 h-4 mr-1.5" />Rescan All</>
            }
          </Button>
          <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="w-4 h-4 mr-1.5" />Add Organization</Button>
        </div>
      </div>

      {/* Header KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: "Total 3rd Party Companies", value: total,               color: "text-blue-400" },
          { label: "Total Service Providers",   value: serviceProvidersCount, color: "text-purple-400" },
          { label: "Total Prospecting",         value: prospectingCount,    color: "text-cyan-400" },
          { label: "Total Subsidiaries",        value: subsidiaryCount,     color: "text-indigo-400" },
        ].map(k => (
          <Card key={k.label} className="bg-card/60">
            <CardContent className="pt-3 pb-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{k.label}</p>
              {loading ? <Skeleton className="h-7 w-12 mt-1" /> : <p className={`text-2xl font-bold mt-0.5 ${k.color}`}>{k.value}</p>}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Digital Assets Count */}
      <div>
        <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Digital Assets Count</h2>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label: "Domains",     value: assetsSummary?.domains     ?? 0, color: "text-blue-400" },
            { label: "Subdomains",  value: assetsSummary?.subdomains  ?? 0, color: "text-cyan-400" },
            { label: "IP Addresses",value: assetsSummary?.ipAddresses ?? 0, color: "text-purple-400" },
            { label: "Mobile Apps", value: assetsSummary?.mobileApps  ?? 0, color: "text-green-400" },
            { label: "Web Apps",    value: assetsSummary?.webApps     ?? 0, color: "text-orange-400" },
          ].map(k => (
            <Card key={k.label} className="bg-card/60">
              <CardContent className="pt-3 pb-3">
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{k.label}</p>
                {!assetsSummary ? <Skeleton className="h-7 w-12 mt-1" /> : <p className={`text-2xl font-bold mt-0.5 ${k.color}`}>{k.value}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Attack Surface Timeline */}
      <div className="grid md:grid-cols-3 gap-4">
        <Card className="md:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-muted-foreground" />Attack Surface Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!timeline ? <Skeleton className="h-40" /> : (timeline.weeks.length < 2 || (timeline.weeks.every(w => w.assetCount === 0 && w.issueCount === 0))) ? (
              <p className="text-xs text-muted-foreground py-8 text-center">No scan history yet — run vendor scans to populate the timeline</p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <LineChart data={timeline.weeks} margin={{ left: -10 }}>
                  <CartesianGrid strokeDasharray="3 3" opacity={0.08} />
                  <XAxis dataKey="label" tick={{ fontSize: 10 }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 10 }} width={30} />
                  <RechartsTooltip contentStyle={{ fontSize: 11 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="assetCount" name="Assets" stroke="#3b82f6" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="issueCount" name="Open Issues" stroke="#ef4444" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="vendorCount" name="Vendors" stroke="#a855f7" strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Top Asset Types Discovered</CardTitle></CardHeader>
          <CardContent>
            {!timeline ? <Skeleton className="h-40" /> : !timeline.topAssetTypes?.length ? (
              <p className="text-xs text-muted-foreground py-8 text-center">No assets discovered yet</p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={timeline.topAssetTypes} layout="vertical" barSize={14} margin={{ left: 30 }}>
                  <XAxis type="number" allowDecimals={false} tick={{ fontSize: 10 }} />
                  <YAxis type="category" dataKey="type" tick={{ fontSize: 10 }} width={70} />
                  <RechartsTooltip contentStyle={{ fontSize: 11 }} />
                  <Bar dataKey="count" name="Count" fill="#3b82f6" radius={[0, 3, 3, 0]}>
                    {(timeline.topAssetTypes ?? []).map((_: any, i: number) => (
                      <Cell key={i} fill={["#3b82f6","#a855f7","#06b6d4","#22c55e","#f97316"][i % 5]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Risk Comparison */}
      {comparison && comparison.length > 1 && (
        <div>
          <h2 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Vendor Risk Comparison</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left py-2 px-3 font-medium text-muted-foreground">Vendor</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">Risk Score</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">Critical</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">High</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">Open Findings</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">Compliance</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">4th Parties</th>
                  <th className="text-center py-2 px-3 font-medium text-muted-foreground">Inherited Risk</th>
                </tr>
              </thead>
              <tbody>
                {comparison.slice(0, 10).map((v: any) => (
                  <tr key={v.id} className="border-b border-border/30 hover:bg-muted/20 cursor-pointer" onClick={() => window.location.href = `/tprm/vendors/${v.id}`}>
                    <td className="py-2 px-3">
                      <div className="flex items-center gap-2">
                        {v.logoUrl && <img src={v.logoUrl} alt="" className="w-5 h-5 rounded object-contain" />}
                        <span className="font-medium">{v.companyName}</span>
                      </div>
                    </td>
                    <td className="py-2 px-3 text-center">
                      <span className={`font-bold ${v.riskScore >= 75 ? "text-red-400" : v.riskScore >= 50 ? "text-orange-400" : v.riskScore >= 25 ? "text-yellow-400" : "text-green-400"}`}>
                        {v.riskScore ?? "—"}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">
                      {v.criticalFindings > 0 ? <span className="text-red-400 font-bold">{v.criticalFindings}</span> : <span className="text-muted-foreground">0</span>}
                    </td>
                    <td className="py-2 px-3 text-center">
                      {v.highFindings > 0 ? <span className="text-orange-400 font-semibold">{v.highFindings}</span> : <span className="text-muted-foreground">0</span>}
                    </td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{v.openFindings}</td>
                    <td className="py-2 px-3 text-center">
                      {v.complianceScore != null ? (
                        <span className={`font-medium ${v.complianceScore >= 80 ? "text-green-400" : v.complianceScore >= 50 ? "text-yellow-400" : "text-red-400"}`}>{v.complianceScore}%</span>
                      ) : <span className="text-muted-foreground">—</span>}
                    </td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{v.fourthPartyCount}</td>
                    <td className="py-2 px-3 text-center">
                      <span className={`capitalize px-1.5 py-0.5 rounded text-[10px] font-medium ${v.inherentRisk === "critical" ? "bg-red-500/20 text-red-400" : v.inherentRisk === "high" ? "bg-orange-500/20 text-orange-400" : v.inherentRisk === "medium" ? "bg-yellow-500/20 text-yellow-400" : "bg-green-500/20 text-green-400"}`}>{v.inherentRisk ?? "low"}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search vendors…" className="pl-8 h-8 text-sm" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} />
        </div>
        <Select value={type} onValueChange={v => { setType(v); setPage(1); }}>
          <SelectTrigger className="w-44 h-8 text-sm"><SelectValue placeholder="Type" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            {VENDOR_TYPES.map(t => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={riskGrade} onValueChange={v => { setRiskGrade(v); setPage(1); }}>
          <SelectTrigger className="w-36 h-8 text-sm"><SelectValue placeholder="Grade" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Grades</SelectItem>
            {["A+", "A", "B", "C", "D", "F"].map(g => <SelectItem key={g} value={g}>Grade {g}</SelectItem>)}
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" className="h-8" onClick={() => { setPage(1); load(); }}><RefreshCw className="w-3.5 h-3.5" /></Button>
        <div className="flex border rounded-md overflow-hidden h-8">
          <button onClick={() => setView("table")} className={`px-2.5 flex items-center ${view === "table" ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"}`}><LayoutList className="w-3.5 h-3.5" /></button>
          <button onClick={() => setView("grid")}  className={`px-2.5 flex items-center border-l ${view === "grid"  ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"}`}><LayoutGrid className="w-3.5 h-3.5" /></button>
        </div>
      </div>

      {/* Table view */}
      {loading ? (
        <div className="space-y-2">{Array(8).fill(0).map((_, i) => <Skeleton key={i} className="h-12" />)}</div>
      ) : vendors.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-16 text-center">
            <Building2 className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm font-medium">No vendors found</p>
            <p className="text-xs text-muted-foreground mt-1">Add your first vendor to start monitoring</p>
            <Button size="sm" className="mt-4" onClick={() => setShowAdd(true)}><Plus className="w-4 h-4 mr-1.5" />Add Vendor</Button>
          </CardContent>
        </Card>
      ) : view === "table" ? (
        <Card>
          <CardContent className="p-0 overflow-x-auto">
            <table className="w-full text-sm min-w-[1280px]">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Vendor</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Domain</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Type</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Industry</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Inherent Risk</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Scan Freq</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Grade</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Risk Score</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Assets</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Last Scanned</th>
                  <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5 whitespace-nowrap">Status</th>
                  <th className="px-4 py-2.5 whitespace-nowrap text-right text-xs text-muted-foreground font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {vendors.map(v => (
                  <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors cursor-pointer" onClick={() => navigate(`/tprm/vendors/${v.id}`)}>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-2.5">
                        {v.logoUrl
                          ? <img src={v.logoUrl} alt="" className="w-7 h-7 rounded bg-white/10 object-contain p-0.5 shrink-0" />
                          : <div className="w-7 h-7 rounded bg-muted flex items-center justify-center text-xs font-bold shrink-0">{v.companyName[0]?.toUpperCase()}</div>
                        }
                        <span className="font-medium truncate max-w-[160px]">{v.companyName}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><Globe className="w-3 h-3" />{v.domain}</span>
                    </td>
                    <td className="px-4 py-2.5"><Badge variant="outline" className="text-[10px]">{typeLabel(v.type)}</Badge></td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{v.industry ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      {v.inherentRisk ? (
                        <Badge variant="outline" className={`text-[10px] ${v.inherentRisk === "critical" ? "border-red-500/40 text-red-400" : v.inherentRisk === "high" ? "border-orange-500/40 text-orange-400" : v.inherentRisk === "medium" ? "border-yellow-500/40 text-yellow-400" : "border-green-500/40 text-green-400"}`}>{v.inherentRisk}</Badge>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground capitalize">{v.scanFrequency === "daily" ? "Daily" : v.scanFrequency ?? "—"}</td>
                    <td className="px-4 py-2.5">{gradeBadge(v.riskGrade)}</td>
                    <td className="px-4 py-2.5">{riskBar(v.riskScore)}</td>
                    <td className="px-4 py-2.5 text-xs text-center">{v.assetCount}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground whitespace-nowrap">{fmtDate(v.lastScannedAt)}</td>
                    {/* Problem 3: Show scanning indicator inline */}
                    <td className="px-4 py-2.5">
                      {isScanning(v)
                        ? <Badge className="text-[10px] bg-blue-500/20 text-blue-400 border border-blue-500/30 animate-pulse">
                            <Loader2 className="w-2.5 h-2.5 mr-1 animate-spin inline" />Scanning
                          </Badge>
                        : <Badge variant={v.status === "active" ? "default" : "secondary"} className="text-[10px]">{v.status}</Badge>
                      }
                    </td>
                    {/* Actions */}
                    <td className="px-4 py-2.5 whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1">
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost" size="icon" className="h-7 w-7"
                                disabled={isScanning(v)}
                                onClick={e => handleScan(e, v.id)}
                              >
                                {isScanning(v)
                                  ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                  : <Play className="w-3.5 h-3.5" />
                                }
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent side="left" className="text-xs">
                              {isScanning(v) ? "Scanning in progress…" : "Run security scan"}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={e => { e.stopPropagation(); navigate(`/tprm/vendors/${v.id}`); }}>
                          <ExternalLink className="w-3.5 h-3.5" />
                        </Button>
                        {canManage && (
                          <>
                            <Button variant="ghost" size="icon" className="h-7 w-7" onClick={e => openEdit(e, v)} title="Edit vendor">
                              <Pencil className="w-3.5 h-3.5" />
                            </Button>
                            <Button
                              variant="ghost" size="icon"
                              className="h-7 w-7 text-destructive hover:text-destructive"
                              disabled={deletingId === v.id}
                              onClick={e => handleDelete(e, v)}
                              title="Delete vendor"
                            >
                              {deletingId === v.id
                                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                : <Trash2 className="w-3.5 h-3.5" />
                              }
                            </Button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {vendors.map(v => (
            <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
              <Card className="hover:bg-accent/30 cursor-pointer transition-colors h-full">
                <CardContent className="pt-4 pb-3">
                  <div className="flex items-start gap-3">
                    {v.logoUrl
                      ? <img src={v.logoUrl} alt={v.companyName} className="w-9 h-9 rounded bg-white/10 object-contain p-0.5 shrink-0" />
                      : <div className="w-9 h-9 rounded bg-muted flex items-center justify-center text-sm font-bold shrink-0">{v.companyName[0]?.toUpperCase()}</div>
                    }
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <p className="text-sm font-semibold truncate">{v.companyName}</p>
                        {gradeBadge(v.riskGrade)}
                      </div>
                      <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5"><Globe className="w-3 h-3" />{v.domain}</p>
                    </div>
                    {/* Scan button on grid card */}
                    <Button
                      variant="ghost" size="icon" className="h-7 w-7 shrink-0"
                      disabled={isScanning(v)}
                      onClick={e => { e.preventDefault(); handleScan(e, v.id); }}
                    >
                      {isScanning(v) ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    </Button>
                    {canManage && (
                      <>
                        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0" onClick={e => { e.preventDefault(); openEdit(e, v); }} title="Edit">
                          <Pencil className="w-3.5 h-3.5" />
                        </Button>
                        <Button variant="ghost" size="icon" className="h-7 w-7 shrink-0 text-destructive hover:text-destructive" disabled={deletingId === v.id} onClick={e => { e.preventDefault(); handleDelete(e, v); }} title="Delete">
                          {deletingId === v.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                        </Button>
                      </>
                    )}
                  </div>
                  <div className="mt-3 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Risk Score</span>
                      <span className="font-medium">{v.riskScore}/100</span>
                    </div>
                    <Progress value={v.riskScore} className="h-1.5" />
                  </div>
                  {isScanning(v) && (
                    <div className="mt-2">
                      <Badge className="text-[10px] bg-blue-500/20 text-blue-400 border border-blue-500/30 animate-pulse w-full justify-center">
                        <Loader2 className="w-2.5 h-2.5 mr-1 animate-spin" />Scanning…
                      </Badge>
                    </div>
                  )}
                  <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                    <Badge variant="outline" className="text-[10px] py-0">{typeLabel(v.type)}</Badge>
                    {v.industry && <Badge variant="outline" className="text-[10px] py-0">{v.industry}</Badge>}
                    <span className="ml-auto text-[10px] text-muted-foreground">{v.assetCount} assets</span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}

      {/* Pagination */}
      {total > 30 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Showing {Math.min((page - 1) * 30 + 1, total)}–{Math.min(page * 30, total)} of {total}</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>Previous</Button>
            <Button variant="outline" size="sm" disabled={page * 30 >= total} onClick={() => setPage(p => p + 1)}>Next</Button>
          </div>
        </div>
      )}

      {/* ── Edit Vendor Dialog ────────────────────────────────────────────────────────── */}
      <Dialog open={showEdit} onOpenChange={o => { if (!o) { setShowEdit(false); setEditingVendor(null); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Edit Vendor</DialogTitle>
            <DialogDescription>
              Update details for <span className="font-semibold text-foreground">{editingVendor?.companyName}</span>
              {editingVendor?.domain && <span className="text-muted-foreground"> · {editingVendor.domain}</span>}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            {/* Row 1: Company Name */}
            <div>
              <Label className="text-xs">Company Name <span className="text-red-400">*</span></Label>
              <Input className="mt-1 h-8 text-sm" value={editForm.companyName} onChange={e => setEditForm(f => ({ ...f, companyName: e.target.value }))} />
            </div>

            {/* Row 2: Domain (scan target) + Website URL */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs flex items-center gap-1">
                  Domain <span className="text-red-400">*</span>
                  <span className="text-muted-foreground font-normal">(scan target)</span>
                </Label>
                <Input
                  className="mt-1 h-8 text-sm font-mono"
                  placeholder="example.com"
                  value={editForm.domain}
                  onChange={e => {
                    let v = e.target.value.trim();
                    v = v.replace(/^https?:\/\//i, "").replace(/^www\./i, "").split("/")[0];
                    setEditForm(f => ({ ...f, domain: v }));
                  }}
                />
                {editForm.domain && editForm.domain !== editingVendor?.domain && (
                  <p className="text-xs text-amber-400 mt-0.5">⚠ Scans will target the new domain</p>
                )}
              </div>
              <div>
                <Label className="text-xs flex items-center gap-1">
                  <Globe className="w-3 h-3" /> Website URL
                </Label>
                <Input
                  className="mt-1 h-8 text-sm"
                  placeholder="https://vendor.com"
                  value={editForm.website}
                  onChange={e => setEditForm(f => ({ ...f, website: e.target.value }))}
                />
              </div>
            </div>

            {/* Row 3: Type + Industry */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label className="text-xs">Vendor Type</Label>
                <Select value={editForm.type} onValueChange={v => setEditForm(f => ({ ...f, type: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {VENDOR_TYPES.map(t => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Industry</Label>
                <Input className="mt-1 h-8 text-sm" placeholder="e.g. FinTech, Healthcare" value={editForm.industry} onChange={e => setEditForm(f => ({ ...f, industry: e.target.value }))} />
              </div>
            </div>

            {/* Row 4: Inherent Risk + Scan Frequency + Status */}
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label className="text-xs">Inherent Risk</Label>
                <Select value={editForm.inherentRisk} onValueChange={v => setEditForm(f => ({ ...f, inherentRisk: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["low","medium","high","critical"].map(r => <SelectItem key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={editForm.scanFrequency} onValueChange={v => setEditForm(f => ({ ...f, scanFrequency: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_FREQUENCIES.map(f => <SelectItem key={f.value} value={f.value}>{f.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Status</Label>
                <Select value={editForm.status} onValueChange={v => setEditForm(f => ({ ...f, status: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="inactive">Inactive</SelectItem>
                    <SelectItem value="under_review">Under Review</SelectItem>
                    <SelectItem value="offboarding">Offboarding</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Row 5: Description */}
            <div>
              <Label className="text-xs">Description</Label>
              <Textarea className="mt-1 text-sm resize-none" rows={2} placeholder="Brief description of this vendor…" value={editForm.description} onChange={e => setEditForm(f => ({ ...f, description: e.target.value }))} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setShowEdit(false); setEditingVendor(null); }}>Cancel</Button>
            <Button onClick={handleEditSave} disabled={editSaving || !editForm.companyName.trim()}>
              {editSaving && <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />}Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Vendor Dialog */}
      <Dialog open={showAdd} onOpenChange={v => { setShowAdd(v); if (!v) { setPreview(null); setDomain(""); } }}>
        <DialogContent className="max-w-lg">
          <DialogHeader><DialogTitle>Add Vendor</DialogTitle></DialogHeader>
          <div className="space-y-4">
            <div className="flex gap-2">
              <Input placeholder="vendor-domain.com" value={domain} onChange={e => setDomain(e.target.value)} onKeyDown={e => e.key === "Enter" && handleEnrich()} />
              <Button variant="outline" size="sm" onClick={handleEnrich} disabled={enriching || !domain.trim()}>
                {enriching ? <Loader2 className="w-4 h-4 animate-spin" /> : "Lookup"}
              </Button>
            </div>

            {preview && (
              <>
                {preview.existingVendor && (
                  <div className="flex items-start gap-2 p-3 rounded-lg border border-yellow-500/40 bg-yellow-500/10 text-sm">
                    <span className="text-yellow-400 font-bold shrink-0">⚠</span>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-yellow-300">Domain already tracked</p>
                      <p className="text-xs text-yellow-400/80 mt-0.5">Associated with <span className="font-semibold">{preview.existingVendor.companyName}</span>.</p>
                      <div className="flex gap-2 mt-2">
                        <Button size="sm" variant="outline" className="h-6 text-xs border-yellow-500/40 text-yellow-300 hover:bg-yellow-500/20" onClick={() => { setShowAdd(false); navigate(`/tprm/vendors/${preview.existingVendor!.id}`); }}>Go to existing vendor</Button>
                        <Button size="sm" variant="ghost" className="h-6 text-xs text-muted-foreground" onClick={() => {}}>Add separately</Button>
                      </div>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border">
                  {preview.logoUrl && <img src={preview.logoUrl} alt="" className="w-10 h-10 rounded object-contain bg-white/10 p-0.5" />}
                  <div>
                    <p className="text-sm font-semibold">{preview.companyName}</p>
                    {preview.industry && <p className="text-xs text-muted-foreground">{preview.industry}</p>}
                    {preview.location && <p className="text-xs text-muted-foreground">{preview.location}</p>}
                    <Badge variant="outline" className="text-[10px] mt-0.5">
                      via {preview.source === "homepage" ? "website" : preview.source}
                    </Badge>
                  </div>
                </div>
                {preview.source === "dns" && (
                  <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                    <span className="text-yellow-400">⚠</span>
                    Company info not found in public databases — you can edit the name and details below.
                  </p>
                )}
              </>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div className="col-span-2">
                <Label className="text-xs">Company Name *</Label>
                <Input className="mt-1" value={form.companyName} onChange={e => setForm(f => ({ ...f, companyName: e.target.value }))} />
              </div>
              <div>
                <Label className="text-xs">Vendor Type</Label>
                <Select value={form.type} onValueChange={v => setForm(f => ({ ...f, type: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {VENDOR_TYPES.map(t => <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              {/* Problem 4: Scan frequency with all options + tooltips */}
              <div>
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={form.scanFrequency} onValueChange={v => setForm(f => ({ ...f, scanFrequency: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCAN_FREQUENCIES.map(f => (
                      <SelectItem key={f.value} value={f.value}>
                        <div>
                          <div className="font-medium text-sm">{f.label}</div>
                          <div className="text-xs text-muted-foreground">{f.desc}</div>
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Inherent Risk</Label>
                <Select value={form.inherentRisk} onValueChange={v => setForm(f => ({ ...f, inherentRisk: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["low","medium","high","critical"].map(r => <SelectItem key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Business Impact (1–10)</Label>
                <Input type="number" min="1" max="10" className="mt-1 h-8 text-sm" value={form.businessImpact} onChange={e => setForm(f => ({ ...f, businessImpact: e.target.value }))} />
              </div>
            </div>
            {(preview?.description || form.description) && (
              <div>
                <Label className="text-xs">Description</Label>
                <Textarea className="mt-1 text-sm" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={handleAdd} disabled={saving || !form.companyName || !domain.trim()}>
              {saving && <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />}Add & Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
