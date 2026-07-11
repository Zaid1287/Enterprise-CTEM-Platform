import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Plus, Search, RefreshCw, Building2, Loader2, Globe, ChevronRight } from "lucide-react";
import { Progress } from "@/components/ui/progress";

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
  lastScannedAt: string | null;
  assetCount: number;
}

function gradeBadge(grade: string) {
  const c = grade === "A+" || grade === "A" ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-bold border ${c}`}>{grade}</span>;
}

interface EnrichPreview {
  companyName: string;
  domain: string;
  logoUrl: string | null;
  industry: string | null;
  description: string | null;
  location: string | null;
  companyType: string | null;
  source: string;
}

export default function TprmVendorsPage() {
  const [, navigate] = useLocation();
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [total, setTotal]     = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch]   = useState("");
  const [type, setType]       = useState("all");
  const [riskGrade, setRiskGrade] = useState("all");
  const [page, setPage]       = useState(1);

  const [showAdd, setShowAdd]         = useState(false);
  const [domain, setDomain]           = useState("");
  const [enriching, setEnriching]     = useState(false);
  const [preview, setPreview]         = useState<EnrichPreview | null>(null);
  const [form, setForm]               = useState({ companyName: "", type: "service_provider", industry: "", description: "", inherentRisk: "medium", businessImpact: "5", scanFrequency: "weekly" });
  const [saving, setSaving]           = useState(false);

  const load = () => {
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: "30" });
    if (search) params.set("search", search);
    if (type !== "all") params.set("type", type);
    if (riskGrade !== "all") params.set("riskGrade", riskGrade);
    apiFetch<{ vendors: Vendor[]; total: number }>(`/api/tprm/vendors?${params}`)
      .then(r => { setVendors(r.vendors); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [search, type, riskGrade, page]);

  const handleEnrich = async () => {
    if (!domain.trim()) return;
    setEnriching(true);
    setPreview(null);
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
      setShowAdd(false);
      setDomain("");
      setPreview(null);
      setForm({ companyName: "", type: "service_provider", industry: "", description: "", inherentRisk: "medium", businessImpact: "5", scanFrequency: "weekly" });
      navigate(`/tprm/vendors/${v.id}`);
    } catch { /* ignore */ }
    setSaving(false);
  };

  return (
    <div className="p-6 space-y-5 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Vendor Inventory</h1>
          <p className="text-muted-foreground text-sm">{total} vendor{total !== 1 ? "s" : ""} tracked</p>
        </div>
        <Button size="sm" onClick={() => setShowAdd(true)}><Plus className="w-4 h-4 mr-1.5" />Add Vendor</Button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search vendors…" className="pl-8 h-8 text-sm" value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} />
        </div>
        <Select value={type} onValueChange={v => { setType(v); setPage(1); }}>
          <SelectTrigger className="w-40 h-8 text-sm"><SelectValue placeholder="Type" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="service_provider">Service Provider</SelectItem>
            <SelectItem value="software_vendor">Software Vendor</SelectItem>
            <SelectItem value="cloud_provider">Cloud Provider</SelectItem>
            <SelectItem value="prospecting">Prospecting</SelectItem>
            <SelectItem value="subsidiary">Subsidiary</SelectItem>
            <SelectItem value="partner">Partner</SelectItem>
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
      </div>

      {/* Vendor grid */}
      {loading ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Array(6).fill(0).map((_, i) => <Skeleton key={i} className="h-32" />)}
        </div>
      ) : vendors.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="py-16 text-center">
            <Building2 className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm font-medium">No vendors found</p>
            <p className="text-xs text-muted-foreground mt-1">Add your first vendor to start monitoring</p>
            <Button size="sm" className="mt-4" onClick={() => setShowAdd(true)}><Plus className="w-4 h-4 mr-1.5" />Add Vendor</Button>
          </CardContent>
        </Card>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {vendors.map(v => (
            <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
              <Card className="hover:bg-accent/30 cursor-pointer transition-colors h-full">
                <CardContent className="pt-4 pb-3">
                  <div className="flex items-start gap-3">
                    {v.logoUrl ? (
                      <img src={v.logoUrl} alt={v.companyName} className="w-9 h-9 rounded bg-white/10 object-contain p-0.5 shrink-0" />
                    ) : (
                      <div className="w-9 h-9 rounded bg-muted flex items-center justify-center text-sm font-bold shrink-0">{v.companyName[0]?.toUpperCase()}</div>
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        <p className="text-sm font-semibold truncate">{v.companyName}</p>
                        {gradeBadge(v.riskGrade)}
                      </div>
                      <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5"><Globe className="w-3 h-3" />{v.domain}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
                  </div>
                  <div className="mt-3 space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground">Risk Score</span>
                      <span className="font-medium">{v.riskScore}/100</span>
                    </div>
                    <Progress value={v.riskScore} className="h-1.5" />
                  </div>
                  <div className="flex items-center gap-2 mt-2.5 flex-wrap">
                    <Badge variant="outline" className="text-[10px] py-0">{v.type.replace(/_/g, " ")}</Badge>
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
              <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/50 border">
                {preview.logoUrl && <img src={preview.logoUrl} alt="" className="w-10 h-10 rounded object-contain bg-white/10 p-0.5" />}
                <div>
                  <p className="text-sm font-semibold">{preview.companyName}</p>
                  {preview.industry && <p className="text-xs text-muted-foreground">{preview.industry}</p>}
                  {preview.location && <p className="text-xs text-muted-foreground">{preview.location}</p>}
                  <Badge variant="outline" className="text-[10px] mt-0.5">via {preview.source}</Badge>
                </div>
              </div>
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
                    <SelectItem value="service_provider">Service Provider</SelectItem>
                    <SelectItem value="software_vendor">Software Vendor</SelectItem>
                    <SelectItem value="cloud_provider">Cloud Provider</SelectItem>
                    <SelectItem value="partner">Partner</SelectItem>
                    <SelectItem value="prospecting">Prospecting</SelectItem>
                    <SelectItem value="subsidiary">Subsidiary</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Scan Frequency</Label>
                <Select value={form.scanFrequency} onValueChange={v => setForm(f => ({ ...f, scanFrequency: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">Manual</SelectItem>
                    <SelectItem value="weekly">Weekly</SelectItem>
                    <SelectItem value="monthly">Monthly</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Inherent Risk</Label>
                <Select value={form.inherentRisk} onValueChange={v => setForm(f => ({ ...f, inherentRisk: v }))}>
                  <SelectTrigger className="mt-1 h-8 text-sm"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label className="text-xs">Business Impact (1–10)</Label>
                <Input type="number" min="1" max="10" className="mt-1 h-8 text-sm" value={form.businessImpact} onChange={e => setForm(f => ({ ...f, businessImpact: e.target.value }))} />
              </div>
            </div>
            {preview?.description && (
              <div>
                <Label className="text-xs">Description</Label>
                <Textarea className="mt-1 text-sm" rows={2} value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)}>Cancel</Button>
            <Button onClick={handleAdd} disabled={saving || !form.companyName || !domain.trim()}>
              {saving ? <Loader2 className="w-4 h-4 mr-1.5 animate-spin" /> : null}
              Add & Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
