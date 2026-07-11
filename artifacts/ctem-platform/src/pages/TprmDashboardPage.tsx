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
  Globe, RefreshCw, Plus, TrendingUp, TrendingDown, Minus,
  Eye, Activity, Users, Lock,
} from "lucide-react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
  PieChart, Pie, Cell, Legend,
} from "recharts";

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
  continuousBreakdown: { poor: number; average: number; good: number };
  oneTimeBreakdown:    { poor: number; average: number; good: number };
  topCritical: any[];
  assetCounts: { domains: number; subdomains: number; ipAddresses: number; webApps: number; mobileApps: number };
  infraCoverage: { misconfiguredCloud: number; secretsInApps: number; misconfiguredDns: number; sslIssues: number; exposedServices: number };
  digitalExposure: { credentialLeaks: number; docsExposed: number; darkWebMentions: number; brandMentions: number; employeeDataExposed: number; credentialOnForum: number };
  activeDataLeaks: number;
  activeSecurityRisks: number;
  recentScans: any[];
  vendorSummary: any[];
}

const GRADE_COLORS: Record<string, string> = { "A+": "#22c55e", "A": "#4ade80", "B": "#86efac", "C": "#fbbf24", "D": "#f97316", "F": "#ef4444" };

function scoreToGrade(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  return "F";
}

function gradeColor(grade: string) { return GRADE_COLORS[grade] ?? "#6b7280"; }

function gradeBadgeSm(grade: string) {
  const c = grade === "A+" || grade === "A" ? "bg-green-500/20 text-green-400 border-green-500/30"
    : grade === "B" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
    : grade === "C" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
    : grade === "D" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
    : "bg-red-500/20 text-red-400 border-red-500/30";
  return <span className={`inline-flex items-center px-1.5 py-0.5 rounded border text-xs font-bold ${c}`}>{grade}</span>;
}

function AssessmentBreakdown({ label, data, total }: { label: string; data: { poor: number; average: number; good: number }; total: number }) {
  return (
    <div className="space-y-1.5">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label} <span className="text-foreground/50">({total})</span></p>
      <div className="flex gap-2">
        {[
          { key: "poor",    label: "Poor",    color: "bg-red-500/80",    text: "text-red-400",    val: data.poor },
          { key: "average", label: "Average", color: "bg-yellow-500/80", text: "text-yellow-400", val: data.average },
          { key: "good",    label: "Good",    color: "bg-green-500/80",  text: "text-green-400",  val: data.good },
        ].map(b => (
          <div key={b.key} className="flex-1 rounded p-2 bg-card/60 border border-border/40 text-center">
            <p className={`text-lg font-bold ${b.text}`}>{b.val}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{b.label}</p>
          </div>
        ))}
      </div>
    </div>
  );
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
  const distData  = data ? [
    { name: "Poor",    value: data.poor,    fill: "#ef4444" },
    { name: "Average", value: data.average, fill: "#fbbf24" },
    { name: "Good",    value: data.good,    fill: "#22c55e" },
  ].filter(d => d.value > 0) : [];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">

      {/* Page header */}
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

      {/* Attack Surface Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="py-3 flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <p className="text-xs text-muted-foreground">Attack Surface Status</p>
              {loading ? <Skeleton className="h-5 w-20 mt-0.5" /> : (
                <p className="text-sm font-bold text-red-400">{(data?.activeSecurityRisks ?? 0) > 0 ? "CRITICAL" : "CLEAR"} · {data?.activeSecurityRisks ?? 0} open risks</p>
              )}
            </div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="py-3 flex items-center gap-3">
            <Activity className="w-5 h-5 text-orange-400 shrink-0" />
            <div>
              <p className="text-xs text-muted-foreground">Active Data Leaks · Last 7 Days</p>
              {loading ? <Skeleton className="h-5 w-12 mt-0.5" /> : (
                <p className="text-sm font-bold text-orange-400">{data?.activeDataLeaks ?? 0} new high/critical findings</p>
              )}
            </div>
          </CardContent>
        </Card>
        <Card className="border-yellow-500/30 bg-yellow-500/5">
          <CardContent className="py-3 flex items-center gap-3">
            <Shield className="w-5 h-5 text-yellow-400 shrink-0" />
            <div>
              <p className="text-xs text-muted-foreground">Active Security Risk · Last 7 Days</p>
              {loading ? <Skeleton className="h-5 w-12 mt-0.5" /> : (
                <p className="text-sm font-bold text-yellow-400">{data?.activeDataLeaks ?? 0} issues · {data?.digitalExposure.brandMentions ?? 0} brand mentions</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Overall Rating + KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card/80 col-span-2 md:col-span-1">
          <CardContent className="pt-4 pb-3 flex flex-col items-center justify-center gap-0.5 h-full">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">Overall Rating</span>
            {loading ? <Skeleton className="h-12 w-12 mt-2" /> : (
              <>
                <p className="text-5xl font-black mt-1" style={{ color: GRADE_COLORS[data ? scoreToGrade(data.avgRiskScore) : "F"] }}>
                  {data ? scoreToGrade(data.avgRiskScore) : "—"}
                </p>
                <p className="text-xs text-muted-foreground">{data?.avgRiskScore ?? 0}/100</p>
              </>
            )}
          </CardContent>
        </Card>
        {[
          { label: "Total Vendors",      value: data?.totalVendors,      icon: Building2,     color: "text-blue-400" },
          { label: "Service Providers",  value: data?.serviceProviders,  icon: Globe,         color: "text-purple-400" },
          { label: "Prospecting",        value: data?.prospecting,       icon: Users,         color: "text-cyan-400" },
          { label: "Subsidiaries",       value: data?.subsidiaries,      icon: Lock,          color: "text-indigo-400" },
        ].map(k => (
          <Card key={k.label} className="bg-card/60">
            <CardContent className="pt-4 pb-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground uppercase tracking-wider">{k.label}</span>
                <k.icon className={`w-4 h-4 ${k.color}`} />
              </div>
              {loading ? <Skeleton className="h-8 w-16 mt-2" /> : (
                <p className={`text-2xl font-bold mt-1 ${k.color}`}>{k.value ?? 0}</p>
              )}
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Assessment Type Breakdown */}
      <div className="grid md:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Continuous Assessment Vendors</CardTitle></CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-16" /> : (
              <AssessmentBreakdown label="Continuous" data={data?.continuousBreakdown ?? { poor:0, average:0, good:0 }} total={(data?.continuousBreakdown.poor ?? 0) + (data?.continuousBreakdown.average ?? 0) + (data?.continuousBreakdown.good ?? 0)} />
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">One-Time Assessment Vendors</CardTitle></CardHeader>
          <CardContent>
            {loading ? <Skeleton className="h-16" /> : (
              <AssessmentBreakdown label="One-Time" data={data?.oneTimeBreakdown ?? { poor:0, average:0, good:0 }} total={(data?.oneTimeBreakdown.poor ?? 0) + (data?.oneTimeBreakdown.average ?? 0) + (data?.oneTimeBreakdown.good ?? 0)} />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Digital Exposure Risk Coverage */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Digital Exposure Risk Coverage</p>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: "Credential Leaks",           value: data?.digitalExposure.credentialLeaks,     color: "text-red-400" },
            { label: "Docs Exposed",               value: data?.digitalExposure.docsExposed,         color: "text-orange-400" },
            { label: "Brand on Hacker Forums",     value: data?.digitalExposure.brandMentions,       color: "text-yellow-400" },
            { label: "Employee Data Exposed",      value: data?.digitalExposure.employeeDataExposed, color: "text-purple-400" },
            { label: "Credentials on Dark Forums", value: data?.digitalExposure.credentialOnForum,   color: "text-pink-400" },
            { label: "Dark Web Mentions",          value: data?.digitalExposure.darkWebMentions,     color: "text-red-300" },
          ].map(k => (
            <Card key={k.label} className="bg-card/50 border-dashed">
              <CardContent className="pt-3 pb-3">
                <span className="text-[10px] text-muted-foreground leading-tight block">{k.label}</span>
                {loading ? <Skeleton className="h-6 w-8 mt-1" /> : <p className={`text-xl font-semibold mt-0.5 ${k.color}`}>{k.value ?? 0}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Infrastructure Attack Vector Coverage */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Infrastructure Initial Attack Vector Coverage</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Misconfigured Cloud Services",           value: data?.infraCoverage.misconfiguredCloud,  color: "text-blue-400" },
            { label: "Secrets & Mobile Vulnerabilities",       value: data?.infraCoverage.secretsInApps,       color: "text-purple-400" },
            { label: "Misconfigured DNS",                      value: data?.infraCoverage.misconfiguredDns,    color: "text-yellow-400" },
            { label: "Improper SSL Implementation",            value: data?.infraCoverage.sslIssues,           color: "text-red-400" },
            { label: "Exposed Services",                       value: data?.infraCoverage.exposedServices,     color: "text-orange-400" },
          ].map(k => (
            <Card key={k.label} className="bg-card/50 border-dashed">
              <CardContent className="pt-3 pb-3">
                <span className="text-[10px] text-muted-foreground leading-tight block">{k.label}</span>
                {loading ? <Skeleton className="h-6 w-8 mt-1" /> : <p className={`text-xl font-semibold mt-0.5 ${k.color}`}>{k.value ?? 0}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Digital Assets Count */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Digital Assets Count of Your Organization</p>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: "Domains",      value: data?.assetCounts.domains      },
            { label: "Subdomains",   value: data?.assetCounts.subdomains   },
            { label: "IP Addresses", value: data?.assetCounts.ipAddresses  },
            { label: "Mobile Apps",  value: data?.assetCounts.mobileApps   },
            { label: "Web Apps",     value: data?.assetCounts.webApps      },
          ].map(k => (
            <Card key={k.label} className="bg-card/50">
              <CardContent className="pt-3 pb-3 text-center">
                <p className="text-xs text-muted-foreground">{k.label}</p>
                {loading ? <Skeleton className="h-7 w-12 mt-1 mx-auto" /> : <p className="text-2xl font-bold mt-0.5">{k.value ?? 0}</p>}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Vendor Risk Summary table */}
      <Card>
        <CardHeader className="pb-2 flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Vendor Risk Summary</CardTitle>
          <Button variant="ghost" size="sm" asChild><Link href="/tprm/vendors">View All <ArrowRight className="w-3.5 h-3.5 ml-1" /></Link></Button>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? <div className="p-4"><Skeleton className="h-32" /></div> : (data?.vendorSummary.length ?? 0) === 0 ? (
            <p className="text-muted-foreground text-sm py-8 text-center">No vendors yet — <Link href="/tprm/vendors/new" className="text-primary underline">add your first vendor</Link></p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Vendor Name</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Rating</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Assessment Type</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Incidents</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">New Issues</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Total Issues</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Assets</th>
                    <th className="text-left text-xs text-muted-foreground font-medium px-4 py-2.5">Status Break-up</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {data!.vendorSummary.slice(0, 10).map((v: any) => (
                    <tr key={v.id} className="border-b border-border/30 hover:bg-accent/20 transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          {v.logoUrl ? <img src={v.logoUrl} alt="" className="w-5 h-5 rounded object-contain bg-white/10" /> : <div className="w-5 h-5 rounded bg-muted flex items-center justify-center text-[10px] font-bold">{v.companyName[0]}</div>}
                          <span className="font-medium truncate max-w-[140px]">{v.companyName}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5">{gradeBadgeSm(v.riskGrade)} <span className="text-xs text-muted-foreground ml-1">{v.riskScore}</span></td>
                      <td className="px-4 py-2.5"><Badge variant="outline" className="text-[10px]">{v.assessmentType === "continuous" ? "Continuous" : "One-Time"}</Badge></td>
                      <td className="px-4 py-2.5 text-xs font-semibold">{v.incidents > 0 ? <span className="text-red-400">{v.incidents}</span> : <span className="text-muted-foreground">0</span>}</td>
                      <td className="px-4 py-2.5 text-xs">{v.newIssues > 0 ? <span className="text-orange-400 flex items-center gap-1"><TrendingUp className="w-3 h-3" />{v.newIssues}</span> : <span className="text-muted-foreground">0</span>}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{v.totalIssues}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{v.totalAssets}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-1 text-[10px]">
                          {v.statusBreakup.open > 0 && <span className="bg-red-500/15 text-red-400 px-1.5 py-0.5 rounded">{v.statusBreakup.open} open</span>}
                          {v.statusBreakup.mitigated > 0 && <span className="bg-green-500/15 text-green-400 px-1.5 py-0.5 rounded">{v.statusBreakup.mitigated} mitigated</span>}
                          {v.statusBreakup.open === 0 && v.statusBreakup.mitigated === 0 && <span className="text-muted-foreground">—</span>}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        <Button size="sm" variant="ghost" className="h-6 text-xs" asChild>
                          <Link href={`/tprm/vendors/${v.id}`}><Eye className="w-3 h-3 mr-1" />View</Link>
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Charts row */}
      <div className="grid md:grid-cols-2 gap-6">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Security Rating Distribution</CardTitle></CardHeader>
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
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Portfolio Risk Distribution</CardTitle></CardHeader>
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

      {/* Recently scanned */}
      {data && data.recentScans.length > 0 && (
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">Recently Scanned</CardTitle></CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {data.recentScans.map(v => (
                <Link key={v.id} href={`/tprm/vendors/${v.id}`}>
                  <Badge variant="outline" className="cursor-pointer hover:bg-accent gap-1.5 py-1">
                    {v.logoUrl && <img src={v.logoUrl} alt="" className="w-3.5 h-3.5 rounded-sm" />}
                    {v.companyName}
                    {gradeBadgeSm(v.riskGrade)}
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
