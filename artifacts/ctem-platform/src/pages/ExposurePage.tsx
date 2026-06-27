import { useState, useMemo } from "react";
import {
  useListFindings, getListFindingsQueryKey,
  useGetExposureBreakdown, getGetExposureBreakdownQueryKey,
} from "@workspace/api-client-react";
import {
  ShieldAlert, Globe, Database, Wifi, Cloud, Key, AlertTriangle,
  TrendingUp, Filter, ExternalLink, Bug, ChevronRight, Activity,
  Server, Lock, Zap,
} from "lucide-react";
import { Link } from "wouter";
import { cn, formatDate } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

// ── Dangerous port registry ───────────────────────────────────────────────────

interface PortInfo {
  service: string;
  risk: "critical" | "high" | "medium";
  icon: React.ElementType;
  reason: string;
}

const DANGEROUS_PORTS: Record<number, PortInfo> = {
  21:    { service: "FTP",                 risk: "high",     icon: Globe,      reason: "Unencrypted file transfer" },
  23:    { service: "Telnet",              risk: "critical", icon: Globe,      reason: "Plaintext remote access" },
  135:   { service: "RPC",                 risk: "high",     icon: Server,     reason: "Windows RPC exposed" },
  139:   { service: "NetBIOS",             risk: "critical", icon: Wifi,       reason: "Windows NetBIOS file sharing" },
  161:   { service: "SNMP",                risk: "high",     icon: Activity,   reason: "Network management exposed" },
  389:   { service: "LDAP",                risk: "high",     icon: Key,        reason: "Directory service exposed" },
  445:   { service: "SMB",                 risk: "critical", icon: Wifi,       reason: "EternalBlue / ransomware target" },
  1433:  { service: "MSSQL",               risk: "critical", icon: Database,   reason: "Database directly exposed" },
  1521:  { service: "Oracle DB",           risk: "critical", icon: Database,   reason: "Database directly exposed" },
  2379:  { service: "etcd",                risk: "critical", icon: Key,        reason: "Kubernetes config store" },
  3306:  { service: "MySQL",               risk: "critical", icon: Database,   reason: "Database directly exposed" },
  3389:  { service: "RDP",                 risk: "critical", icon: Server,     reason: "Remote Desktop — brute-force target" },
  4243:  { service: "Docker API",          risk: "critical", icon: Activity,   reason: "Container escape risk" },
  5432:  { service: "PostgreSQL",          risk: "critical", icon: Database,   reason: "Database directly exposed" },
  5900:  { service: "VNC",                 risk: "critical", icon: Server,     reason: "Remote desktop unencrypted" },
  5984:  { service: "CouchDB",             risk: "high",     icon: Database,   reason: "Database publicly accessible" },
  6379:  { service: "Redis",               risk: "critical", icon: Database,   reason: "No auth by default — RCE risk" },
  6443:  { service: "Kubernetes API",      risk: "critical", icon: Activity,   reason: "K8s API server exposed" },
  8080:  { service: "HTTP-Alt",            risk: "medium",   icon: Globe,      reason: "Dev server exposed" },
  9200:  { service: "Elasticsearch",       risk: "critical", icon: Database,   reason: "No auth by default — data exposed" },
  9300:  { service: "Elasticsearch Peer",  risk: "critical", icon: Database,   reason: "ES cluster communication exposed" },
  11211: { service: "Memcached",           risk: "high",     icon: Database,   reason: "Cache exposed — DDoS amplifier" },
  27017: { service: "MongoDB",             risk: "critical", icon: Database,   reason: "No auth by default — data exposed" },
  27018: { service: "MongoDB",             risk: "critical", icon: Database,   reason: "MongoDB shard exposed" },
  50070: { service: "HDFS NameNode",       risk: "high",     icon: Database,   reason: "Hadoop UI exposed" },
};

// Match findings from the pipeline that were created for exposed ports
function extractPortFromTitle(title: string): number | null {
  const m = title.match(/Port\s+(\d+)/i);
  return m ? parseInt(m[1]) : null;
}

function isExposedServiceFinding(f: any) {
  return (
    f.title?.startsWith("Exposed ") &&
    (f.cve?.startsWith("EXP-PORT-") || extractPortFromTitle(f.title) !== null)
  );
}

function isCloudFinding(f: any) {
  return (
    f.cve?.startsWith("CLOUD-") ||
    f.title?.toLowerCase().includes("bucket") ||
    f.title?.toLowerCase().includes("storage") ||
    f.title?.toLowerCase().includes("blob")
  );
}

// ── Colors ───────────────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
};

const RISK_DOT: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

const CHART_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6", "#06b6d4"];

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  info:     "bg-muted text-muted-foreground border-border",
};

// ── Stat card ─────────────────────────────────────────────────────────────────

function StatCard({
  icon: Icon, label, value, sub, color = "text-primary",
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-xl p-5 flex items-start gap-4">
      <div className={cn("p-2.5 rounded-lg bg-muted/50", color)}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-2xl font-bold tabular-nums">{value}</p>
        <p className="text-sm font-medium">{label}</p>
        {sub && <p className="text-xs text-muted-foreground mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ── Exposed service row ───────────────────────────────────────────────────────

function ExposedServiceRow({ finding }: { finding: any }) {
  const port   = extractPortFromTitle(finding.title);
  const info   = port ? DANGEROUS_PORTS[port] : undefined;
  const Icon   = info?.icon ?? Server;
  const risk   = (info?.risk ?? finding.severity ?? "medium") as string;

  return (
    <div className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors border-b border-border/50 last:border-0 text-sm">
      <div className="p-1.5 rounded-md bg-muted/60">
        <Icon className="w-3.5 h-3.5 text-muted-foreground" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium truncate">{finding.title}</p>
        <p className="text-xs text-muted-foreground truncate">
          {finding.assetName ?? "—"} · {finding.assetValue ?? "—"}
        </p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {port && (
          <span className="text-xs font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
            :{port}
          </span>
        )}
        <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-bold uppercase border", RISK_COLOR[risk] ?? RISK_COLOR.medium)}>
          {risk}
        </span>
        {port ? (
          <Link href={`/findings?search=%3A${port}`} onClick={(e) => e.stopPropagation()} title={`Filter findings for port ${port}`}>
            <ExternalLink className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground transition-colors" />
          </Link>
        ) : (
          <Link href={`/findings/${finding.id}`} onClick={(e) => e.stopPropagation()}>
            <ExternalLink className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground transition-colors" />
          </Link>
        )}
      </div>
    </div>
  );
}

// ── Cloud finding row ─────────────────────────────────────────────────────────

function CloudFindingRow({ finding }: { finding: any }) {
  return (
    <div className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors border-b border-border/50 last:border-0 text-sm">
      <div className="p-1.5 rounded-md bg-sky-500/10">
        <Cloud className="w-3.5 h-3.5 text-sky-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium truncate">{finding.title}</p>
        <p className="text-xs text-muted-foreground truncate">
          {finding.assetName ?? "—"} · {formatDate(finding.createdAt)}
        </p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className={cn("text-[10px] px-2 py-0.5 rounded-md font-bold uppercase border", SEV_COLOR[finding.severity] ?? SEV_COLOR.info)}>
          {finding.severity}
        </span>
        <Link href={`/findings/${finding.id}`} onClick={(e) => e.stopPropagation()}>
          <ExternalLink className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground transition-colors" />
        </Link>
      </div>
    </div>
  );
}

// ── KEV finding row ───────────────────────────────────────────────────────────

function KevFindingRow({ finding }: { finding: any }) {
  const epssPercent = finding.epss != null ? `${(finding.epss * 100).toFixed(1)}%` : null;
  return (
    <div className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors border-b border-border/50 last:border-0 text-sm">
      <div className="p-1.5 rounded-md bg-red-500/10">
        <Zap className="w-3.5 h-3.5 text-red-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="font-medium truncate">{finding.title}</p>
        <p className="text-xs text-muted-foreground truncate">
          {finding.cve ?? "—"} · {finding.assetName ?? "—"}
        </p>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {epssPercent && (
          <span className="text-xs font-mono font-bold text-orange-400" title="EPSS — exploit probability">
            {epssPercent}
          </span>
        )}
        <span className="text-[10px] px-2 py-0.5 rounded-md font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30">
          KEV
        </span>
        <Link href={`/findings/${finding.id}`} onClick={(e) => e.stopPropagation()}>
          <ExternalLink className="w-3.5 h-3.5 text-muted-foreground hover:text-foreground transition-colors" />
        </Link>
      </div>
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState({ icon: Icon, title, sub }: { icon: React.ElementType; title: string; sub: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      <Icon className="w-10 h-10 text-muted-foreground/20 mb-3" />
      <p className="text-sm font-medium text-muted-foreground">{title}</p>
      <p className="text-xs text-muted-foreground/60 mt-1 max-w-xs">{sub}</p>
    </div>
  );
}

// ── Section wrapper ───────────────────────────────────────────────────────────

function Section({
  title, icon: Icon, count, children, accentColor = "text-primary",
}: {
  title: string;
  icon: React.ElementType;
  count?: number;
  children: React.ReactNode;
  accentColor?: string;
}) {
  return (
    <div className="bg-card border border-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-4 py-3 border-b border-border bg-muted/30">
        <Icon className={cn("w-4 h-4", accentColor)} />
        <h3 className="text-sm font-semibold">{title}</h3>
        {count !== undefined && (
          <span className="ml-auto text-xs font-bold tabular-nums text-muted-foreground">
            {count}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

// ── Risk filter tabs ──────────────────────────────────────────────────────────

type RiskFilter = "all" | "critical" | "high" | "medium";

function RiskFilterBar({ active, onChange, counts }: {
  active: RiskFilter;
  onChange: (v: RiskFilter) => void;
  counts: Record<RiskFilter, number>;
}) {
  const tabs: { key: RiskFilter; label: string }[] = [
    { key: "all",      label: "All" },
    { key: "critical", label: "Critical" },
    { key: "high",     label: "High" },
    { key: "medium",   label: "Medium" },
  ];
  return (
    <div className="flex items-center gap-1 px-4 py-2 border-b border-border/50 bg-muted/10">
      {tabs.map(({ key, label }) => (
        <button
          key={key}
          onClick={() => onChange(key)}
          className={cn(
            "text-xs px-2.5 py-1 rounded-md font-medium transition-colors",
            active === key
              ? "bg-primary/15 text-primary"
              : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
          )}
        >
          {label}
          {counts[key] > 0 && (
            <span className="ml-1.5 text-[10px] font-bold opacity-70">{counts[key]}</span>
          )}
        </button>
      ))}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ExposurePage() {
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");

  const { data: findings = [], isLoading: findingsLoading } = useListFindings(
    undefined,
    { query: { queryKey: getListFindingsQueryKey(), staleTime: 60_000 } },
  );
  const { data: breakdown = [], isLoading: breakdownLoading } = useGetExposureBreakdown({
    query: { queryKey: getGetExposureBreakdownQueryKey(), staleTime: 60_000 },
  });

  const exposedServices = useMemo(
    () => findings.filter(isExposedServiceFinding),
    [findings],
  );
  const cloudFindings = useMemo(
    () => findings.filter(isCloudFinding),
    [findings],
  );
  const kevFindings = useMemo(
    () => findings.filter((f: any) => f.isKev),
    [findings],
  );
  const criticalCount = useMemo(
    () => findings.filter((f: any) => f.severity === "critical" && f.status === "open").length,
    [findings],
  );

  // Risk counts for filter bar
  const riskCounts: Record<RiskFilter, number> = useMemo(() => {
    const counts = { all: 0, critical: 0, high: 0, medium: 0 };
    for (const f of exposedServices) {
      const port  = extractPortFromTitle(f.title);
      const info  = port ? DANGEROUS_PORTS[port] : undefined;
      const risk  = (info?.risk ?? f.severity ?? "medium") as RiskFilter;
      counts.all++;
      if (risk === "critical") counts.critical++;
      else if (risk === "high") counts.high++;
      else if (risk === "medium") counts.medium++;
    }
    return counts;
  }, [exposedServices]);

  const filteredExposed = useMemo(() => {
    if (riskFilter === "all") return exposedServices;
    return exposedServices.filter((f: any) => {
      const port = extractPortFromTitle(f.title);
      const info = port ? DANGEROUS_PORTS[port] : undefined;
      const risk = info?.risk ?? f.severity ?? "medium";
      return risk === riskFilter;
    });
  }, [exposedServices, riskFilter]);

  const isLoading = findingsLoading || breakdownLoading;

  // Service type breakdown for mini chart
  const serviceBreakdown = useMemo(() => {
    const map = new Map<string, number>();
    for (const f of exposedServices) {
      const port = extractPortFromTitle(f.title);
      const label = port ? (DANGEROUS_PORTS[port]?.service ?? `Port ${port}`) : "Unknown";
      map.set(label, (map.get(label) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [exposedServices]);

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Page header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h1 className="text-xl font-bold">Exposure Management</h1>
          </div>
          <p className="text-sm text-muted-foreground">
            Exposed services, cloud misconfigurations, and actively exploited vulnerabilities across your attack surface.
          </p>
        </div>
        <Link href="/findings">
          <button className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors border border-border rounded-lg px-3 py-2">
            <Bug className="w-3.5 h-3.5" /> All Findings <ChevronRight className="w-3 h-3" />
          </button>
        </Link>
      </div>

      {/* Summary stats */}
      {isLoading ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <Skeleton key={i} className="h-24 rounded-xl" />)}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            icon={ShieldAlert}
            label="Critical Open Findings"
            value={criticalCount}
            sub="Requires immediate action"
            color="text-red-400"
          />
          <StatCard
            icon={Server}
            label="Exposed Services"
            value={exposedServices.length}
            sub={`${riskCounts.critical} critical, ${riskCounts.high} high`}
            color="text-orange-400"
          />
          <StatCard
            icon={Cloud}
            label="Cloud Exposures"
            value={cloudFindings.length}
            sub="Public buckets & storage"
            color="text-sky-400"
          />
          <StatCard
            icon={Zap}
            label="KEV (Actively Exploited)"
            value={kevFindings.length}
            sub="CISA known exploited"
            color="text-purple-400"
          />
        </div>
      )}

      {/* Main content grid */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* Left column (2/3 width) */}
        <div className="xl:col-span-2 space-y-6">

          {/* Exposed Services */}
          <Section
            title="Exposed Dangerous Services"
            icon={Server}
            count={exposedServices.length}
            accentColor="text-orange-400"
          >
            <RiskFilterBar active={riskFilter} onChange={setRiskFilter} counts={riskCounts} />
            {isLoading ? (
              <div className="p-4 space-y-3">
                {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}
              </div>
            ) : filteredExposed.length > 0 ? (
              <div className="divide-y divide-border/40">
                {filteredExposed.slice(0, 20).map((f: any) => (
                  <ExposedServiceRow key={f.id} finding={f} />
                ))}
                {filteredExposed.length > 20 && (
                  <div className="px-4 py-3 text-center text-xs text-muted-foreground">
                    +{filteredExposed.length - 20} more ·{" "}
                    <Link href="/findings?severity=critical" className="text-primary hover:underline">View all findings</Link>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState
                icon={Server}
                title={riskFilter === "all" ? "No exposed services detected" : `No ${riskFilter} exposed services`}
                sub="Run a full scan with port scanning enabled to detect exposed dangerous services across your assets."
              />
            )}
          </Section>

          {/* Cloud Exposure */}
          <Section
            title="Cloud Exposure"
            icon={Cloud}
            count={cloudFindings.length}
            accentColor="text-sky-400"
          >
            {isLoading ? (
              <div className="p-4 space-y-3">
                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}
              </div>
            ) : cloudFindings.length > 0 ? (
              <div className="divide-y divide-border/40">
                {cloudFindings.slice(0, 15).map((f: any) => (
                  <CloudFindingRow key={f.id} finding={f} />
                ))}
                {cloudFindings.length > 15 && (
                  <div className="px-4 py-3 text-center text-xs text-muted-foreground">
                    +{cloudFindings.length - 15} more ·{" "}
                    <Link href="/findings?severity=critical" className="text-primary hover:underline">View all findings</Link>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState
                icon={Cloud}
                title="No cloud misconfigurations detected"
                sub="Cloud recon runs automatically during scans to detect public S3 buckets, Azure Blob, and GCP Storage exposures."
              />
            )}
          </Section>
        </div>

        {/* Right column (1/3 width) */}
        <div className="space-y-6">

          {/* Exposure breakdown chart */}
          <Section title="Exposure Breakdown" icon={TrendingUp} accentColor="text-primary">
            {breakdownLoading ? (
              <div className="p-4 space-y-2">
                {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-8 rounded" />)}
              </div>
            ) : breakdown.length > 0 ? (
              <div className="p-4">
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={breakdown} layout="vertical" margin={{ left: 0, right: 16 }}>
                    <XAxis type="number" tick={{ fontSize: 10 }} tickLine={false} axisLine={false} />
                    <YAxis
                      type="category"
                      dataKey="exposureType"
                      tick={{ fontSize: 10 }}
                      tickLine={false}
                      axisLine={false}
                      width={110}
                    />
                    <Tooltip
                      contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", borderRadius: "8px", fontSize: "11px" }}
                      cursor={{ fill: "var(--muted)" }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {breakdown.map((_: any, idx: number) => (
                        <Cell key={idx} fill={CHART_COLORS[idx % CHART_COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState icon={TrendingUp} title="No exposure data yet" sub="Run scans to populate exposure breakdown." />
            )}
          </Section>

          {/* Service type mini breakdown */}
          {serviceBreakdown.length > 0 && (
            <Section title="Service Types Exposed" icon={Filter} accentColor="text-orange-400">
              <div className="p-3 space-y-2">
                {serviceBreakdown.map(({ name, count }, i) => {
                  const max = serviceBreakdown[0].count;
                  return (
                    <div key={name} className="flex items-center gap-2 text-xs">
                      <span className="w-3 h-3 rounded-sm shrink-0" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                      <span className="flex-1 truncate text-muted-foreground">{name}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{ width: `${(count / max) * 100}%`, background: CHART_COLORS[i % CHART_COLORS.length] }}
                          />
                        </div>
                        <span className="font-bold tabular-nums w-4 text-right">{count}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Section>
          )}

          {/* KEV findings */}
          <Section
            title="Known Exploited (KEV)"
            icon={Zap}
            count={kevFindings.length}
            accentColor="text-red-400"
          >
            {isLoading ? (
              <div className="p-4 space-y-3">
                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-12 rounded-lg" />)}
              </div>
            ) : kevFindings.length > 0 ? (
              <div className="divide-y divide-border/40">
                {kevFindings.slice(0, 10).map((f: any) => (
                  <KevFindingRow key={f.id} finding={f} />
                ))}
                {kevFindings.length > 10 && (
                  <div className="px-4 py-3 text-center text-xs text-muted-foreground">
                    +{kevFindings.length - 10} more ·{" "}
                    <Link href="/findings?severity=critical" className="text-primary hover:underline">View all findings</Link>
                  </div>
                )}
              </div>
            ) : (
              <EmptyState
                icon={Zap}
                title="No KEV findings"
                sub="CISA KEV enrichment runs automatically during scans. CVEs matching the KEV catalog will appear here."
              />
            )}
          </Section>

          {/* Legend / info */}
          <div className="bg-card border border-border rounded-xl p-4 space-y-3">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Risk Level Guide</p>
            {(["critical", "high", "medium"] as const).map(r => (
              <div key={r} className="flex items-center gap-2.5 text-xs">
                <span className={cn("w-2 h-2 rounded-full shrink-0", RISK_DOT[r])} />
                <span className="capitalize font-medium">{r}</span>
                <span className="text-muted-foreground">
                  {r === "critical" && "— Direct exploitation likely, immediate action required"}
                  {r === "high"     && "— Significant risk, prioritize remediation"}
                  {r === "medium"   && "— Elevated risk, schedule remediation"}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
