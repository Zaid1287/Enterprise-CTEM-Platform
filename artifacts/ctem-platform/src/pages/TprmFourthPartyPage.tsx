import { useEffect, useState, useMemo, useCallback } from "react";
import { SmartPagination } from "@/components/ui/SmartPagination";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import {
  Building2, AlertTriangle, Shield, Globe, RefreshCw,
  Search, TrendingUp, Users, Layers, Loader2,
} from "lucide-react";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useToast } from "@/hooks/use-toast";

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
};

const CAT_COLORS: Record<string, string> = {
  payments:       "#ef4444",
  auth:           "#f97316",
  cdn:            "#3b82f6",
  waf:            "#8b5cf6",
  analytics:      "#22c55e",
  advertising:    "#eab308",
  monitoring:     "#06b6d4",
  communication:  "#6366f1",
  marketing:      "#ec4899",
  infrastructure: "#64748b",
  security:       "#10b981",
  media:          "#7c3aed",
  devtools:       "#f59e0b",
  cms:            "#14b8a6",
  ca:             "#94a3b8",
};

const PAGE_SIZE = 10;

function riskBadge(level: string) {
  const cls = level === "critical" ? "bg-red-500/20 text-red-400 border-red-500/30"
    : level === "high"     ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : level === "medium"   ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : "bg-green-500/20 text-green-400 border-green-500/30";
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] font-semibold ${cls}`}>
      {level}
    </span>
  );
}

function catBadge(cat: string) {
  const col = CAT_COLORS[cat] ?? CAT_COLORS.infrastructure;
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold"
      style={{ color: col, background: col + "20" }}
    >{cat}</span>
  );
}


// Custom pie tooltip — uses solid hex colours so it's always readable in dark mode
function PieTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const { name, value } = payload[0];
  const col = CAT_COLORS[name] ?? "#64748b";
  return (
    <div
      style={{
        background: "#1e293b",
        border: "1px solid #334155",
        borderRadius: 8,
        padding: "8px 14px",
        boxShadow: "0 4px 16px rgba(0,0,0,0.5)",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ width: 10, height: 10, borderRadius: "50%", background: col, display: "inline-block", flexShrink: 0 }} />
        <span style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 13 }}>{name}</span>
      </div>
      <div style={{ color: "#94a3b8", fontSize: 12, marginTop: 3, paddingLeft: 18 }}>
        {value} {value === 1 ? "provider" : "providers"}
      </div>
    </div>
  );
}

export default function TprmFourthPartyPage() {
  const { toast } = useToast();
  const [data, setData]           = useState<any>(null);
  const [loading, setLoading]     = useState(true);
  const [search, setSearch]       = useState("");
  const [filterRisk, setFilterRisk]   = useState("all");
  const [filterCat, setFilterCat]     = useState("all");
  const [sortBy, setSortBy]           = useState<"concentration" | "risk" | "vendors">("concentration");
  const [page, setPage]               = useState(1);

  // Track in-progress risk level saves (key = domain||name)
  const [saving, setSaving] = useState<Record<string, boolean>>({});
  // Local risk level overrides (optimistic updates while save is in flight)
  const [riskOverrides, setRiskOverrides] = useState<Record<string, string>>({});

  const load = useCallback(() => {
    setLoading(true);
    apiFetch<any>("/api/tprm/fourth-parties/concentration-risk")
      .then(d => { setData(d); setRiskOverrides({}); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const filtered = useMemo(() => {
    if (!data?.concentrationRisk) return [];
    return (data.concentrationRisk as any[])
      .filter(e => {
        const rl = riskOverrides[e.domain || e.name] ?? e.riskLevel;
        if (filterRisk !== "all" && rl !== filterRisk) return false;
        if (filterCat !== "all" && e.category !== filterCat) return false;
        if (search) {
          const q = search.toLowerCase();
          if (!e.name.toLowerCase().includes(q) && !e.domain?.toLowerCase().includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortBy === "concentration") return b.concentrationScore - a.concentrationScore;
        if (sortBy === "vendors") return b.vendorCount - a.vendorCount;
        const rOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
        const ra = riskOverrides[a.domain || a.name] ?? a.riskLevel;
        const rb = riskOverrides[b.domain || b.name] ?? b.riskLevel;
        return (rOrder[rb] ?? 0) - (rOrder[ra] ?? 0);
      });
  }, [data, search, filterRisk, filterCat, sortBy, riskOverrides]);

  // Reset to page 1 whenever filters change
  useEffect(() => { setPage(1); }, [search, filterRisk, filterCat, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage   = Math.min(page, totalPages);
  const pageItems  = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  // Category breakdown for pie chart
  const catData = useMemo(() => {
    if (!data?.concentrationRisk) return [];
    const counts: Record<string, number> = {};
    for (const e of data.concentrationRisk as any[]) {
      counts[e.category] = (counts[e.category] ?? 0) + 1;
    }
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10);
  }, [data]);

  // Risk breakdown for bar chart
  const riskData = useMemo(() => {
    if (!data?.concentrationRisk) return [];
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const e of data.concentrationRisk as any[]) {
      const r = (riskOverrides[e.domain || e.name] ?? e.riskLevel) as string;
      if (r in counts) counts[r]++;
    }
    return Object.entries(counts).map(([name, count]) => ({ name, count }));
  }, [data, riskOverrides]);

  const allCategories = useMemo(() => {
    if (!data?.concentrationRisk) return [];
    return [...new Set((data.concentrationRisk as any[]).map((e: any) => e.category))];
  }, [data]);

  async function handleRiskChange(entry: any, newRisk: string) {
    const key = entry.domain || entry.name;
    setSaving(s => ({ ...s, [key]: true }));
    setRiskOverrides(o => ({ ...o, [key]: newRisk }));
    try {
      await apiFetch("/api/tprm/fourth-parties/risk-level", {
        method: "PATCH",
        body: JSON.stringify({ domain: entry.domain || undefined, name: entry.name, riskLevel: newRisk }),
      });
      toast({ title: "Risk level updated", description: `${entry.name} → ${newRisk}` });
      // Re-fetch in background to sync DB state
      apiFetch<any>("/api/tprm/fourth-parties/concentration-risk")
        .then(d => setData(d))
        .catch(() => {});
    } catch {
      // Revert optimistic update on failure
      setRiskOverrides(o => { const n = { ...o }; delete n[key]; return n; });
      toast({ title: "Update failed", description: "Could not update risk level", variant: "destructive" });
    } finally {
      setSaving(s => { const n = { ...s }; delete n[key]; return n; });
    }
  }

  if (loading) {
    return (
      <div className="p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <Skeleton key={i} className="h-24" />)}
        </div>
        <Skeleton className="h-72" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 max-w-[1400px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Layers className="w-6 h-6 text-primary" />
            4th Party Intelligence
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Cross-vendor concentration risk — shared infrastructure dependencies across your entire vendor portfolio
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link href="/tprm/supply-chain">
            <Button variant="outline" size="sm"><Globe className="w-4 h-4 mr-1.5" />Supply Chain Graph</Button>
          </Link>
          <Button variant="outline" size="sm" onClick={load}><RefreshCw className="w-4 h-4 mr-1.5" />Refresh</Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-blue-500/15 flex items-center justify-center">
                <Building2 className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{data?.totalFourthParties ?? 0}</p>
                <p className="text-xs text-muted-foreground">Total 4th Parties</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-orange-500/15 flex items-center justify-center">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{data?.highRiskFourthParties ?? 0}</p>
                <p className="text-xs text-muted-foreground">High / Critical Risk</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-purple-500/15 flex items-center justify-center">
                <Users className="w-4 h-4 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{data?.sharedFourthParties ?? 0}</p>
                <p className="text-xs text-muted-foreground">Shared Across Vendors</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-red-500/15 flex items-center justify-center">
                <TrendingUp className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">
                  {data?.concentrationRisk?.[0]?.concentrationScore ?? 0}
                </p>
                <p className="text-xs text-muted-foreground">Peak Concentration Score</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* ── Dependencies by Category ── */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Dependencies by Category</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            {catData.length === 0 ? (
              <div className="h-[220px] flex items-center justify-center text-xs text-muted-foreground">
                No data yet
              </div>
            ) : (
              <div className="flex items-center gap-4">
                {/* Donut chart — no built-in legend */}
                <div className="flex-shrink-0" style={{ width: 200, height: 200 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={catData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={82}
                        dataKey="value"
                        nameKey="name"
                        paddingAngle={2}
                        strokeWidth={0}
                      >
                        {catData.map((entry, i) => (
                          <Cell key={i} fill={CAT_COLORS[entry.name] ?? "#64748b"} />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>

                {/* Custom legend — scrollable, never clips */}
                <div className="flex-1 min-w-0 space-y-1.5 max-h-[200px] overflow-y-auto pr-1">
                  {catData.map((entry) => {
                    const col = CAT_COLORS[entry.name] ?? "#64748b";
                    const total = catData.reduce((s, c) => s + c.value, 0);
                    const pct = total > 0 ? Math.round((entry.value / total) * 100) : 0;
                    return (
                      <div key={entry.name} className="flex items-center gap-2">
                        <span
                          className="flex-shrink-0 w-2.5 h-2.5 rounded-full"
                          style={{ background: col }}
                        />
                        <span className="text-xs text-muted-foreground capitalize truncate flex-1 min-w-0">
                          {entry.name}
                        </span>
                        <span className="text-xs font-semibold text-foreground flex-shrink-0">
                          {entry.value}
                        </span>
                        <span className="text-[10px] text-muted-foreground flex-shrink-0 w-8 text-right">
                          {pct}%
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* ── Risk Level Distribution ── */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Risk Level Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={riskData} barCategoryGap="30%">
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: "rgba(255,255,255,0.04)" }}
                  contentStyle={{
                    background: "#1e293b",
                    border: "1px solid #334155",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  itemStyle={{ color: "#e2e8f0" }}
                  labelStyle={{ color: "#94a3b8" }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskData.map((entry, i) => (
                    <Cell key={i} fill={RISK_COLORS[entry.name] ?? "#64748b"} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Concentration Risk Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Concentration Risk Analysis
              {filtered.length !== (data?.concentrationRisk?.length ?? 0) && (
                <span className="text-xs text-muted-foreground font-normal">
                  ({filtered.length} of {data?.concentrationRisk?.length ?? 0})
                </span>
              )}
            </CardTitle>
            <div className="flex items-center gap-2 flex-wrap">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search providers…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="pl-8 h-7 text-xs w-44"
                />
              </div>
              <select
                value={filterRisk}
                onChange={e => setFilterRisk(e.target.value)}
                className="h-7 text-xs px-2 rounded border border-input bg-background text-foreground"
              >
                <option value="all">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={filterCat}
                onChange={e => setFilterCat(e.target.value)}
                className="h-7 text-xs px-2 rounded border border-input bg-background text-foreground"
              >
                <option value="all">All Categories</option>
                {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value as any)}
                className="h-7 text-xs px-2 rounded border border-input bg-background text-foreground"
              >
                <option value="concentration">Sort: Concentration</option>
                <option value="vendors">Sort: Vendor Count</option>
                <option value="risk">Sort: Risk Level</option>
              </select>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-0">
          {filtered.length === 0 ? (
            <div className="py-16 text-center text-sm text-muted-foreground">
              {data?.totalFourthParties === 0
                ? "No 4th party dependencies discovered yet. Run vendor scans to populate this view."
                : "No results match your current filters."}
            </div>
          ) : (
            <>
              <div className="overflow-auto">
                <table className="w-full text-sm min-w-[900px]">
                  <thead>
                    <tr className="border-b border-border/50 text-xs text-muted-foreground">
                      <th className="text-left px-4 py-2.5 font-medium whitespace-nowrap">Provider</th>
                      <th className="text-left px-4 py-2.5 font-medium whitespace-nowrap">Category</th>
                      <th className="text-left px-4 py-2.5 font-medium whitespace-nowrap">Risk Level</th>
                      <th className="text-center px-4 py-2.5 font-medium whitespace-nowrap">Vendors</th>
                      <th className="text-center px-4 py-2.5 font-medium whitespace-nowrap">Conc. Score</th>
                      <th className="text-left px-4 py-2.5 font-medium whitespace-nowrap">Vendor Dependencies</th>
                      <th className="px-4 py-2.5 whitespace-nowrap" />
                    </tr>
                  </thead>
                  <tbody>
                    {pageItems.map((entry: any, i: number) => {
                      const key = entry.domain || entry.name;
                      const currentRisk = riskOverrides[key] ?? entry.riskLevel;
                      const isSaving = saving[key] ?? false;
                      return (
                        <tr key={i} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                          <td className="px-4 py-3">
                            <div className="font-medium">{entry.name}</div>
                            {entry.domain && <div className="text-xs text-muted-foreground">{entry.domain}</div>}
                          </td>
                          <td className="px-4 py-3">{catBadge(entry.category)}</td>

                          {/* ── Inline Risk Level Editor ── */}
                          <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                            {isSaving ? (
                              <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
                                <Loader2 className="w-3 h-3 animate-spin" />
                                Saving…
                              </span>
                            ) : (
                              <select
                                value={currentRisk}
                                onChange={e => handleRiskChange(entry, e.target.value)}
                                className={`h-6 text-[11px] font-semibold px-1.5 rounded border cursor-pointer
                                  ${currentRisk === "critical" ? "bg-red-500/15 text-red-400 border-red-500/30" :
                                    currentRisk === "high"     ? "bg-orange-500/15 text-orange-400 border-orange-500/30" :
                                    currentRisk === "medium"   ? "bg-yellow-500/15 text-yellow-400 border-yellow-500/30" :
                                    "bg-green-500/15 text-green-400 border-green-500/30"}`}
                              >
                                <option value="critical">Critical</option>
                                <option value="high">High</option>
                                <option value="medium">Medium</option>
                                <option value="low">Low</option>
                              </select>
                            )}
                          </td>

                          <td className="px-4 py-3 text-center">
                            <span className={`font-bold text-sm ${entry.vendorCount > 1 ? "text-orange-400" : "text-muted-foreground"}`}>
                              {entry.vendorCount}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className={`font-bold text-sm ${entry.concentrationScore > 20 ? "text-red-400" : entry.concentrationScore > 10 ? "text-orange-400" : "text-muted-foreground"}`}>
                              {entry.concentrationScore}
                            </span>
                          </td>
                          <td className="px-4 py-3 max-w-xs">
                            <div className="flex flex-wrap gap-1">
                              {(entry.vendors as any[]).slice(0, 4).map((v: any) => (
                                <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
                                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted/60 hover:bg-muted cursor-pointer transition-colors flex items-center gap-0.5">
                                    {v.name}
                                    {v.grade && (
                                      <span className={`ml-0.5 font-bold ${
                                        v.grade.startsWith("A") ? "text-green-400" :
                                        v.grade.startsWith("B") ? "text-blue-400" :
                                        v.grade.startsWith("C") ? "text-yellow-400" : "text-red-400"}`}>
                                        {v.grade}
                                      </span>
                                    )}
                                  </span>
                                </Link>
                              ))}
                              {(entry.vendors as any[]).length > 4 && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted/40 text-muted-foreground">
                                  +{(entry.vendors as any[]).length - 4} more
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-4 py-3 text-right whitespace-nowrap">
                            {entry.vendorCount > 1 && (
                              <Badge variant="destructive" className="text-[10px] py-0">Shared Risk</Badge>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* ── Smart Pagination ── */}
              <SmartPagination
                page={safePage}
                totalPages={totalPages}
                totalItems={filtered.length}
                pageSize={PAGE_SIZE}
                itemLabel="providers"
                onPageChange={setPage}
                className="px-4 py-3 border-t border-border/40"
              />
            </>
          )}
        </CardContent>
      </Card>

      {/* High-Risk Shared Dependencies Alert */}
      {(data?.concentrationRisk ?? []).filter((e: any) =>
        e.vendorCount > 2 &&
        ((riskOverrides[e.domain || e.name] ?? e.riskLevel) === "high" ||
         (riskOverrides[e.domain || e.name] ?? e.riskLevel) === "critical")
      ).length > 0 && (
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="py-4 flex gap-3">
            <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-sm font-medium text-orange-300">Concentration Risk Alert</p>
              <p className="text-xs text-muted-foreground">
                {(data.concentrationRisk as any[]).filter((e: any) =>
                  e.vendorCount > 2 &&
                  ((riskOverrides[e.domain || e.name] ?? e.riskLevel) === "high" ||
                   (riskOverrides[e.domain || e.name] ?? e.riskLevel) === "critical")
                ).length} high/critical risk providers are shared across 3 or more vendors.
                A compromise of any single provider could cascade across multiple vendor relationships simultaneously.
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {(data.concentrationRisk as any[])
                  .filter((e: any) =>
                    e.vendorCount > 2 &&
                    ((riskOverrides[e.domain || e.name] ?? e.riskLevel) === "high" ||
                     (riskOverrides[e.domain || e.name] ?? e.riskLevel) === "critical")
                  )
                  .slice(0, 5)
                  .map((e: any, i: number) => (
                    <span key={i} className="text-xs px-2 py-0.5 rounded border border-orange-500/30 bg-orange-500/10 text-orange-300">
                      {e.name} ({e.vendorCount} vendors)
                    </span>
                  ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
