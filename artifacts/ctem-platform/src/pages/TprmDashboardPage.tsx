import { useEffect, useState } from "react";
import { Link } from "wouter";
import { apiFetch } from "@/lib/apiFetch";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Building2, Shield, AlertTriangle, CheckCircle2, ArrowRight,
  TrendingDown, TrendingUp, Globe, Package, RefreshCw, Plus,
} from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, PieChart, Pie, Cell, Legend } from "recharts";

interface DashboardData {
  totalVendors: number;
  serviceProviders: number;
  prospecting: number;
  subsidiaries: number;
  avgRiskScore: number;
  gradeMap: Record<string, number>;
  poor: number;
  average: number;
  good: number;
  topCritical: any[];
  assetCounts: { domains: number; subdomains: number; ipAddresses: number; webApps: number };
  infraCoverage: { misconfiguredCloud: number; secretsInApps: number; misconfiguredDns: number; sslIssues: number; exposedServices: number };
  recentScans: any[];
  vendorSummary: any[];
}

const GRADE_COLORS: Record<string, string> = { "A+": "#22c55e", "A": "#4ade80", "B": "#86efac", "C": "#fbbf24", "D": "#f97316", "F": "#ef4444" };
const RISK_COLORS = ["#22c55e", "#fbbf24", "#ef4444"];

function scoreToGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

function gradeColor(grade: string) {
  return GRADE_COLORS[grade] ?? "#6b7280";
}

function riskBadge(grade: string) {
  const c = grade === "A+" || grade === "A" ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${c}`}>{grade}</span>;
}

export default function TprmDashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    apiFetch<DashboardData>("/api/tprm/dashboard")
      .then(setData)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const gradeData = data ? Object.entries(data.gradeMap).map(([grade, count]) => ({ grade, count, fill: gradeColor(grade) })) : [];
  const distData = data ? [
    { name: "Poor (<50)", value: data.poor, fill: "#ef4444" },
    { name: "Average (50–69)", value: data.average, fill: "#fbbf24" },
    { name: "Good (≥70)", value: data.good, fill: "#22c55e" },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Third Party Risk Management</h1>
          <p className="text-muted-foreground text-sm mt-1">Continuous monitoring of your vendor ecosystem</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={load}><RefreshCw className="w-4 h-4 mr-1.5" />Refresh</Button>
          <Button size="sm" asChild><Link href="/tprm/vendors/new"><Plus className="w-4 h-4 mr-1.5" />Add Vendor</Link></Button>
        </div>
      </div>

      {/* KPI row — Overall Security Rating + sub-metrics */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Overall Security Rating */}
        <Card className="bg-card/80 col-span-2 md:col-span-1">
          <CardContent className="pt-4 pb-3 flex flex-col items-center justify-center gap-0.5 h-full">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">Security Rating</span>
            {loading ? <Skeleton className="h-12 w-12 mt-2" /> : (
              <>
                <p className={`text-5xl font-black mt-1 ${GRADE_COLORS[data ? scoreToGrade(data.avgRiskScore) : "F"] ? "" : ""}`}
                   style={{ color: GRADE_COLORS[data ? scoreToGrade(data.avgRiskScore) : "F"] }}>
                  {data ? scoreToGrade(data.avgRiskScore) : "—"}
                </p>
                <p className="text-xs text-muted-foreground">{data?.avgRiskScore ?? 0}/100</p>
              </>
            )}
          </CardContent>
        </Card>
        {[
          { label: "Total Vendors",    value: data?.totalVendors,       icon: Building2,    color: "text-blue-400" },
          { label: "High/Critical Risk", value: data?.poor,             icon: AlertTriangle, color: "text-red-400" },
          { label: "Good Standing",    value: data?.good,               icon: CheckCircle2, color: "text-green-400" },
          { label: "Service Providers", value: data?.serviceProviders,  icon: Globe,        color: "text-purple-400" },
        ].map(k => (
          <Card key={k.label} className="bg-card/60">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground uppercase tracking-wider">{k.label}</span>
                <k.icon className={`w-4 h-4 ${k.color}`} />
              </div>
              {loading ? <Skeleton className="h-8 w-16 mt-2" /> : (
                <p className={`text-2xl font-bold mt-1 ${k.color}`}>{k.value ?? "—"}</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Digital Exposure Coverage */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Digital Exposure Coverage</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: "Domains",      value: data?.assetCounts.domains },
            { label: "Subdomains",   value: data?.assetCounts.subdomains },
            { label: "IP Addresses", value: data?.assetCounts.ipAddresses },
            { label: "Web Apps",     value: data?.assetCounts.webApps },
          ].map(k => (
            <Card key={k.label} className="bg-card/50 border-dashed">
              <CardContent className="pt-3 pb-3">
                <span className="text-xs text-muted-foreground">{k.label}</span>
                {loading ? <Skeleton className="h-6 w-12 mt-1" /> : <p className="text-lg font-semibold mt-0.5">{k.value ?? 0}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Infrastructure Attack Vector Coverage */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Infrastructure Attack Vector Coverage</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "SSL/TLS Issues",       value: data?.infraCoverage.sslIssues,           color: "text-red-400" },
            { label: "Exposed Services",     value: data?.infraCoverage.exposedServices,      color: "text-orange-400" },
            { label: "DNS Misconfigs",        value: data?.infraCoverage.misconfiguredDns,    color: "text-yellow-400" },
            { label: "Secrets in Apps",      value: data?.infraCoverage.secretsInApps,        color: "text-purple-400" },
            { label: "Cloud Misconfigs",     value: data?.infraCoverage.misconfiguredCloud,   color: "text-blue-400" },
          ].map(k => (
            <Card key={k.label} className="bg-card/50 border-dashed">
              <CardContent className="pt-3 pb-3">
                <span className="text-xs text-muted-foreground">{k.label}</span>
                {loading ? <Skeleton className="h-6 w-12 mt-1" /> : <p className={`text-lg font-semibold mt-0.5 ${k.color}`}>{k.value ?? 0}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {/* Grade distribution bar chart */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Risk Grade Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-40" /> : gradeData.length === 0 ? (
              <p className="text-muted-foreground text-sm py-6 text-center">No vendor data yet</p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={gradeData} barSize={32}>
                  <XAxis dataKey="grade" tick={{ fontSize: 12 }} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} width={28} />
                  <Tooltip cursor={{ fill: "rgba(255,255,255,0.05)" }} />
                  <Bar dataKey="count" name="Vendors">
                    {gradeData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        {/* Risk distribution pie */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Portfolio Risk Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-40" /> : distData.length === 0 ? (
              <p className="text-muted-foreground text-sm py-6 text-center">No vendor data yet</p>
            ) : (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={distData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={60} label={({ name, percent }) => `${(percent * 100).toFixed(0)}%`}>
                    {distData.map((d, i) => <Cell key={i} fill={d.fill} />)}
                  </Pie>
                  <Legend iconSize={10} wrapperStyle={{ fontSize: 11 }} />
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Critical vendors */}
      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Highest Risk Vendors</CardTitle>
          <Button variant="ghost" size="sm" asChild><Link href="/tprm/vendors">View All <ArrowRight className="w-3.5 h-3.5 ml-1" /></Link></Button>
        </CardHeader>
        <CardContent>
          {loading ? <Skeleton className="h-32" /> : (data?.topCritical.length ?? 0) === 0 ? (
            <p className="text-muted-foreground text-sm py-4 text-center">No vendors yet — <Link href="/tprm/vendors/new" className="text-primary underline">add your first vendor</Link></p>
          ) : (
            <div className="space-y-2">
              {data!.topCritical.map(v => (
                <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
                  <div className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-accent/50 cursor-pointer transition-colors">
                    {v.logoUrl ? <img src={v.logoUrl} alt={v.companyName} className="w-7 h-7 rounded object-contain bg-white/10 p-0.5" /> : <div className="w-7 h-7 rounded bg-muted flex items-center justify-center text-xs font-bold">{v.companyName[0]}</div>}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{v.companyName}</p>
                      <p className="text-xs text-muted-foreground truncate">{v.domain}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="text-right">
                        <p className="text-sm font-semibold">{v.riskScore}/100</p>
                        <Progress value={v.riskScore} className="h-1 w-20" />
                      </div>
                      {riskBadge(v.riskGrade)}
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Recent scans */}
      {data && data.recentScans.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Recently Scanned</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {data.recentScans.map(v => (
                <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
                  <Badge variant="outline" className="cursor-pointer hover:bg-accent gap-1.5 py-1">
                    {v.logoUrl && <img src={v.logoUrl} alt="" className="w-3.5 h-3.5 rounded-sm" />}
                    {v.companyName}
                    {riskBadge(v.riskGrade)}
                  </Badge>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
