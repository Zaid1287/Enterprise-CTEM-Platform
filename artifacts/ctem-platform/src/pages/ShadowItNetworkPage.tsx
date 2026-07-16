import { useState, useMemo } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import type { ReactElement } from "react";
import {
  Wifi, Printer, Router, Server, Monitor, Database, Cpu, HelpCircle,
  RefreshCw, Play, CheckCircle2, AlertTriangle, Trash2, Network,
  Search, ShieldAlert, Activity, Plus, Info, Eye,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────────

interface NetworkDevice {
  id: number; ipAddress: string; macAddress: string | null; macVendor: string | null;
  hostname: string | null; netbiosName: string | null; mdnsName: string | null;
  mdnsServices: string[] | null; deviceType: string; vendor: string | null;
  osGuess: string | null; snmpSysDescr: string | null; snmpSysName: string | null;
  snmpSysLocation: string | null; openPorts: number[] | null;
  discoveryMethods: string[] | null; subnet: string | null; isManaged: boolean;
  riskLevel: string; status: string; firstSeenAt: string; lastSeenAt: string;
}

// ── Constants ──────────────────────────────────────────────────────────────────

const DEVICE_ICONS: Record<string, ReactElement> = {
  printer:     <Printer className="h-5 w-5" />,
  router:      <Router className="h-5 w-5" />,
  switch:      <Network className="h-5 w-5" />,
  server:      <Server className="h-5 w-5" />,
  workstation: <Monitor className="h-5 w-5" />,
  nas:         <Database className="h-5 w-5" />,
  iot:         <Cpu className="h-5 w-5" />,
  unknown:     <HelpCircle className="h-5 w-5" />,
};

const DEVICE_COLORS: Record<string, string> = {
  printer: "#3b82f6", router: "#f97316", switch: "#8b5cf6",
  server: "#ef4444", workstation: "#6b7280", nas: "#06b6d4",
  iot: "#eab308", unknown: "#9ca3af",
};

const METHOD_META: Record<string, { label: string; bg: string; text: string }> = {
  nmap:     { label: "nmap",    bg: "bg-green-500/15",  text: "text-green-400" },
  nmap_arp: { label: "ARP",     bg: "bg-blue-500/15",   text: "text-blue-400" },
  mdns:     { label: "mDNS",    bg: "bg-purple-500/15", text: "text-purple-400" },
  snmp:     { label: "SNMP",    bg: "bg-orange-500/15", text: "text-orange-400" },
  netbios:  { label: "NetBIOS", bg: "bg-pink-500/15",   text: "text-pink-400" },
};

const RISK_CFG: Record<string, { bg: string; text: string; border: string; dot: string }> = {
  critical: { bg: "bg-red-500/10",    text: "text-red-400",    border: "border-red-500/25",    dot: "bg-red-500" },
  high:     { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/25", dot: "bg-orange-500" },
  medium:   { bg: "bg-yellow-500/10", text: "text-yellow-400", border: "border-yellow-500/25", dot: "bg-yellow-500" },
  low:      { bg: "bg-green-500/10",  text: "text-green-400",  border: "border-green-500/25",  dot: "bg-green-500" },
  info:     { bg: "bg-muted/50",      text: "text-muted-foreground", border: "border-border", dot: "bg-muted-foreground" },
};

const STATUS_CFG: Record<string, { label: string; bg: string; text: string }> = {
  new:           { label: "New",           bg: "bg-blue-500/15",   text: "text-blue-400" },
  under_review:  { label: "Under Review",  bg: "bg-yellow-500/15", text: "text-yellow-400" },
  approved:      { label: "Approved",      bg: "bg-green-500/15",  text: "text-green-400" },
  false_positive:{ label: "False Positive",bg: "bg-muted/50",      text: "text-muted-foreground" },
};

const DEVICE_TYPES = ["workstation", "server", "printer", "router", "switch", "nas", "iot", "unknown"];

// ── Helpers ────────────────────────────────────────────────────────────────────

function displayName(d: NetworkDevice) {
  return d.netbiosName ?? d.mdnsName ?? d.hostname ?? d.snmpSysName ?? d.ipAddress;
}

function formatRelTime(dt: string): string {
  const mins = Math.floor((Date.now() - new Date(dt).getTime()) / 60000);
  if (mins < 2) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function RiskBadge({ level }: { level: string }) {
  const cfg = RISK_CFG[level] ?? RISK_CFG.info;
  return (
    <span className={cn("inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold border capitalize", cfg.bg, cfg.text, cfg.border)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", cfg.dot)} />
      {level}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CFG[status] ?? { label: status, bg: "bg-muted/50", text: "text-muted-foreground" };
  return (
    <span className={cn("inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold", cfg.bg, cfg.text)}>
      {cfg.label}
    </span>
  );
}

function KpiCard({ label, value, icon, accent, sub }: { label: string; value: number | string; icon: ReactElement; accent: string; sub?: string }) {
  return (
    <div className="rounded-xl border bg-card p-4 flex items-center gap-3">
      <div className={cn("p-2.5 rounded-lg flex-shrink-0", accent)}>{icon}</div>
      <div className="min-w-0">
        <p className="text-2xl font-bold leading-none">{value}</p>
        <p className="text-xs text-muted-foreground mt-1 truncate">{label}</p>
        {sub && <p className="text-xs text-muted-foreground/70 mt-0.5 truncate">{sub}</p>}
      </div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function ShadowItNetworkPage() {
  const qc = useQueryClient();
  const { toast } = useToast();

  const [scanning, setScanning] = useState(false);
  const [scanSubnet, setScanSubnet] = useState("");
  const [showScanDialog, setShowScanDialog] = useState(false);

  // Filters — server-side (queryKey drives API refetch)
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterManaged, setFilterManaged] = useState("all");
  const [filterRisk, setFilterRisk] = useState("all");

  // Client-side search (fast, no API call needed)
  const [search, setSearch] = useState("");

  const [selected, setSelected] = useState<NetworkDevice | null>(null);

  // ── Queries ────────────────────────────────────────────────────────────────

  const subnetsQ = useQuery<{ subnets: string[] }>({
    queryKey: ["shadow-it-subnets"],
    queryFn: () => apiFetch("/api/shadow-it/network-scan/subnets"),
    staleTime: 60_000,
  });

  // Server-side filter query — queryKey includes ALL filter values so ANY change
  // triggers a fresh API call. staleTime:0 guarantees fresh data, no stale cache.
  const devicesQ = useQuery<{ items: NetworkDevice[]; total: number }>({
    queryKey: ["shadow-it-network", filterType, filterStatus, filterManaged, filterRisk],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "200" });
      if (filterType !== "all")    p.set("deviceType", filterType);
      if (filterStatus !== "all")  p.set("status", filterStatus);
      if (filterRisk !== "all")    p.set("riskLevel", filterRisk);
      if (filterManaged === "true")  p.set("isManaged", "true");
      if (filterManaged === "false") p.set("isManaged", "false");
      return apiFetch(`/api/shadow-it/network-devices?${p}`);
    },
    staleTime: 0,           // never serve cached data — always fetch fresh on key change
    refetchInterval: scanning ? 4000 : 30_000,
  });

  // ── Mutations ─────────────────────────────────────────────────────────────

  const updateDeviceMut = useMutation({
    mutationFn: ({ id, ...data }: { id: number; status?: string; isManaged?: boolean; riskLevel?: string }) =>
      apiFetch(`/api/shadow-it/network-devices/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    onSuccess: (updated: NetworkDevice) => {
      qc.invalidateQueries({ queryKey: ["shadow-it-network"] });
      setSelected(prev => prev?.id === updated.id ? updated : prev);
    },
  });

  const deleteDeviceMut = useMutation({
    mutationFn: (id: number) =>
      apiFetch(`/api/shadow-it/network-devices/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["shadow-it-network"] });
      setSelected(null);
    },
  });

  // ── Scan ──────────────────────────────────────────────────────────────────

  const startScan = async () => {
    setScanning(true);
    setShowScanDialog(false);
    try {
      await apiFetch("/api/shadow-it/network-scan", {
        method: "POST",
        body: JSON.stringify({ subnet: scanSubnet || undefined }),
      });
      toast({ title: "Scan started", description: "Discovering devices on the local network. Results will appear shortly." });
      // Poll-driven by refetchInterval while scanning=true
      await new Promise(r => setTimeout(r, 8000));
      await devicesQ.refetch();
    } catch (err: any) {
      toast({ title: "Scan failed", description: err?.message ?? "Could not start network scan", variant: "destructive" });
    } finally {
      setScanning(false);
    }
  };

  // ── Derived data ──────────────────────────────────────────────────────────

  const allDevices = devicesQ.data?.items ?? [];
  const serverTotal = devicesQ.data?.total ?? 0;

  // Client-side search on top of server-side filter results
  const devices = useMemo(() => {
    if (!search.trim()) return allDevices;
    const q = search.toLowerCase();
    return allDevices.filter(d =>
      displayName(d).toLowerCase().includes(q) ||
      d.ipAddress.includes(q) ||
      (d.macAddress ?? "").toLowerCase().includes(q) ||
      (d.macVendor ?? "").toLowerCase().includes(q) ||
      (d.osGuess ?? "").toLowerCase().includes(q) ||
      (d.subnet ?? "").includes(q)
    );
  }, [allDevices, search]);

  // KPI stats from the FULL unfiltered count (use total from server for filtered, fetch total separately)
  const managedCount = allDevices.filter(d => d.isManaged).length;
  const unmanagedCount = allDevices.filter(d => !d.isManaged).length;
  const highRiskCount = allDevices.filter(d => d.riskLevel === "critical" || d.riskLevel === "high").length;

  // Type breakdown from current result set (for quick-filter chips)
  const byType = useMemo(() => {
    const map: Record<string, number> = {};
    for (const d of allDevices) map[d.deviceType] = (map[d.deviceType] ?? 0) + 1;
    return map;
  }, [allDevices]);

  const hasActiveFilters = filterType !== "all" || filterStatus !== "all" || filterManaged !== "all" || filterRisk !== "all" || !!search;
  const clearFilters = () => { setFilterType("all"); setFilterStatus("all"); setFilterManaged("all"); setFilterRisk("all"); setSearch(""); };

  return (
    <div className="p-6 space-y-5">

      {/* ── Hero ──────────────────────────────────────────────────────────── */}
      <div className="rounded-xl bg-card border border-border/50 overflow-hidden">
        <div className="h-1 bg-gradient-to-r from-teal-500 via-cyan-500 to-blue-500" />
        <div className="px-6 py-5 flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-teal-500/10 border border-teal-500/20">
              <Wifi className="h-6 w-6 text-teal-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">Internal Network Discovery</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                ARP sweep · mDNS/Bonjour · SNMP · NetBIOS — real-time LAN device enumeration
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={devicesQ.isFetching}
              onClick={() => devicesQ.refetch()}
              className="h-9 gap-1.5"
            >
              <RefreshCw className={cn("h-4 w-4", devicesQ.isFetching && "animate-spin")} />
              Refresh
            </Button>
            <Button
              onClick={() => setShowScanDialog(true)}
              disabled={scanning}
              className="h-9 bg-teal-600 hover:bg-teal-700 text-white gap-2"
            >
              {scanning
                ? <><RefreshCw className="h-4 w-4 animate-spin" /> Scanning…</>
                : <><Play className="h-4 w-4" /> Run Scan</>
              }
            </Button>
          </div>
        </div>
      </div>

      {/* ── KPI Strip ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          label="Devices Discovered"
          value={serverTotal}
          accent="bg-teal-500/10"
          icon={<Network className="h-4 w-4 text-teal-400" />}
          sub={filterType !== "all" || filterStatus !== "all" ? `filtered from total` : undefined}
        />
        <KpiCard
          label="Managed"
          value={managedCount}
          accent="bg-green-500/10"
          icon={<CheckCircle2 className="h-4 w-4 text-green-400" />}
        />
        <KpiCard
          label="Unmanaged"
          value={unmanagedCount}
          accent="bg-orange-500/10"
          icon={<AlertTriangle className="h-4 w-4 text-orange-400" />}
        />
        <KpiCard
          label="High / Critical Risk"
          value={highRiskCount}
          accent="bg-red-500/10"
          icon={<ShieldAlert className="h-4 w-4 text-red-400" />}
        />
      </div>

      {/* ── Deployment Note ───────────────────────────────────────────────── */}
      <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 px-4 py-3 flex items-start gap-3">
        <Info className="h-4 w-4 text-yellow-500 flex-shrink-0 mt-0.5" />
        <p className="text-sm text-yellow-600 dark:text-yellow-400">
          <strong>Deployment note:</strong> The scanner discovers devices on the <em>server's</em> local network (the Replit container's LAN). For customer LAN discovery, deploy Sentinelware on a machine physically on that network, or install a network agent.
        </p>
      </div>

      {/* ── Device Type Quick-Filter Chips ────────────────────────────────── */}
      {Object.keys(byType).length > 0 && (
        <div className="flex flex-wrap gap-2">
          <button
            className={cn(
              "flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium transition-all",
              filterType === "all"
                ? "bg-teal-600 text-white border-teal-600 shadow-sm"
                : "bg-card hover:bg-muted border-border text-muted-foreground"
            )}
            onClick={() => setFilterType("all")}
          >
            All
            <span className={cn("text-xs px-1.5 py-0.5 rounded-full font-bold",
              filterType === "all" ? "bg-white/20 text-white" : "bg-muted text-muted-foreground"
            )}>
              {serverTotal}
            </span>
          </button>
          {Object.entries(byType).map(([type, cnt]) => (
            <button
              key={type}
              className={cn(
                "flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium transition-all capitalize",
                filterType === type
                  ? "border-teal-500 bg-teal-500/10 text-teal-400 shadow-sm"
                  : "bg-card hover:bg-muted border-border text-muted-foreground"
              )}
              onClick={() => setFilterType(prev => prev === type ? "all" : type)}
            >
              <span style={{ color: filterType === type ? undefined : (DEVICE_COLORS[type] ?? "#888") }}>
                {DEVICE_ICONS[type] ?? DEVICE_ICONS.unknown}
              </span>
              {type}
              <span className={cn("text-xs px-1.5 py-0.5 rounded-full font-bold",
                filterType === type ? "bg-teal-500/20 text-teal-400" : "bg-muted text-muted-foreground"
              )}>
                {cnt}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* ── Filter Bar ────────────────────────────────────────────────────── */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search IP, hostname, MAC…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="pl-9 h-9"
          />
        </div>

        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-[155px] h-9"><SelectValue placeholder="All types" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {DEVICE_TYPES.map(t => (
              <SelectItem key={t} value={t} className="capitalize">{t}</SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-[160px] h-9"><SelectValue placeholder="All statuses" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="under_review">Under Review</SelectItem>
            <SelectItem value="approved">Approved</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterRisk} onValueChange={setFilterRisk}>
          <SelectTrigger className="w-[155px] h-9"><SelectValue placeholder="All risk" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All risk levels</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>

        <Select value={filterManaged} onValueChange={setFilterManaged}>
          <SelectTrigger className="w-[155px] h-9"><SelectValue placeholder="All devices" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All devices</SelectItem>
            <SelectItem value="true">Managed only</SelectItem>
            <SelectItem value="false">Unmanaged only</SelectItem>
          </SelectContent>
        </Select>

        {hasActiveFilters && (
          <Button size="sm" variant="ghost" className="h-9 text-xs text-muted-foreground" onClick={clearFilters}>
            Clear filters
          </Button>
        )}

        <span className="text-xs text-muted-foreground ml-auto">
          {devicesQ.isFetching ? "Loading…" : `${devices.length} device${devices.length !== 1 ? "s" : ""}`}
        </span>
      </div>

      {/* ── Device Grid ───────────────────────────────────────────────────── */}
      {devicesQ.isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="rounded-xl border bg-card h-48 animate-pulse" />
          ))}
        </div>
      )}

      {!devicesQ.isLoading && devices.length === 0 && (
        <div className="rounded-xl border-2 border-dashed border-border bg-card/50 py-16 text-center">
          <div className="mx-auto w-14 h-14 rounded-full bg-teal-500/10 flex items-center justify-center mb-4">
            <Wifi className="h-7 w-7 text-teal-400 opacity-60" />
          </div>
          <h3 className="font-semibold text-base mb-1">
            {hasActiveFilters ? "No devices match your filters" : "No network devices discovered yet"}
          </h3>
          <p className="text-sm text-muted-foreground max-w-sm mx-auto mb-5">
            {hasActiveFilters
              ? "Try adjusting your filters or clearing all to see all discovered devices."
              : "Run a network scan to discover devices on the local subnet using ARP, mDNS, SNMP, and NetBIOS."}
          </p>
          {hasActiveFilters
            ? <Button variant="outline" size="sm" onClick={clearFilters}>Clear all filters</Button>
            : <Button onClick={() => setShowScanDialog(true)} className="bg-teal-600 hover:bg-teal-700 text-white">
                <Play className="h-4 w-4 mr-2" /> Run First Scan
              </Button>
          }
        </div>
      )}

      {!devicesQ.isLoading && devices.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {devices.map(d => {
            const color = DEVICE_COLORS[d.deviceType] ?? "#9ca3af";
            const riskCfg = RISK_CFG[d.riskLevel] ?? RISK_CFG.info;
            const name = displayName(d);
            const isHighRisk = d.riskLevel === "critical" || d.riskLevel === "high";

            return (
              <div
                key={d.id}
                onClick={() => setSelected(d)}
                className={cn(
                  "rounded-xl border bg-card overflow-hidden flex flex-col cursor-pointer transition-all hover:shadow-md hover:border-border/80 group",
                  isHighRisk && "border-red-500/20",
                  !d.isManaged && !isHighRisk && "border-orange-500/15",
                )}
              >
                {/* Device type color accent strip */}
                <div className="h-1" style={{ background: color }} />

                <div className="p-4 flex-1 flex flex-col gap-3">
                  {/* Header: icon + IP */}
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <div
                        className="h-10 w-10 rounded-lg flex items-center justify-center flex-shrink-0"
                        style={{ background: `${color}1a`, color }}
                      >
                        {DEVICE_ICONS[d.deviceType] ?? DEVICE_ICONS.unknown}
                      </div>
                      <div className="min-w-0">
                        <p className="font-mono text-sm font-bold leading-tight">{d.ipAddress}</p>
                        {name !== d.ipAddress && (
                          <p className="text-xs text-muted-foreground truncate max-w-[120px]" title={name}>{name}</p>
                        )}
                      </div>
                    </div>
                    <RiskBadge level={d.riskLevel} />
                  </div>

                  {/* Device type + OS */}
                  <div className="flex flex-wrap gap-1.5">
                    <span
                      className="inline-flex items-center text-xs px-2 py-0.5 rounded-full font-medium capitalize"
                      style={{ background: `${color}1a`, color }}
                    >
                      {d.deviceType}
                    </span>
                    {d.osGuess && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
                        {d.osGuess.slice(0, 20)}{d.osGuess.length > 20 ? "…" : ""}
                      </span>
                    )}
                  </div>

                  {/* MAC + vendor */}
                  {(d.macAddress || d.macVendor) && (
                    <div className="text-xs text-muted-foreground">
                      {d.macAddress && <span className="font-mono">{d.macAddress}</span>}
                      {d.macVendor && <span className="text-muted-foreground/70"> · {d.macVendor}</span>}
                    </div>
                  )}

                  {/* Discovery methods */}
                  {(d.discoveryMethods ?? []).length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {(d.discoveryMethods ?? []).map(m => {
                        const meta = METHOD_META[m] ?? { label: m, bg: "bg-muted/50", text: "text-muted-foreground" };
                        return (
                          <span key={m} className={cn("text-xs px-1.5 py-0.5 rounded-md font-medium", meta.bg, meta.text)}>
                            {meta.label}
                          </span>
                        );
                      })}
                    </div>
                  )}

                  {/* Open ports count */}
                  {d.openPorts && d.openPorts.length > 0 && (
                    <p className="text-xs text-muted-foreground">
                      <span className="font-semibold text-foreground">{d.openPorts.length}</span> open port{d.openPorts.length !== 1 ? "s" : ""}
                      {d.openPorts.length <= 5 && (
                        <span className="font-mono ml-1">({d.openPorts.slice(0, 5).join(", ")})</span>
                      )}
                    </p>
                  )}
                </div>

                {/* Card footer */}
                <div className="px-4 py-2.5 border-t border-border/50 bg-muted/20 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <StatusBadge status={d.status} />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      className={cn(
                        "text-xs font-medium px-2 py-1 rounded-lg transition-colors flex items-center gap-1",
                        d.isManaged
                          ? "bg-green-500/10 text-green-400 hover:bg-green-500/20"
                          : "bg-muted text-muted-foreground hover:bg-muted/70"
                      )}
                      onClick={e => {
                        e.stopPropagation();
                        updateDeviceMut.mutate({ id: d.id, isManaged: !d.isManaged });
                      }}
                    >
                      {d.isManaged
                        ? <><CheckCircle2 className="h-3 w-3" /> Managed</>
                        : "Unmanaged"
                      }
                    </button>
                    <span className="text-xs text-muted-foreground/60">{formatRelTime(d.lastSeenAt)}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Scan Dialog ───────────────────────────────────────────────────── */}
      <Dialog open={showScanDialog} onOpenChange={setShowScanDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Wifi className="h-5 w-5 text-teal-400" />
              Start Network Scan
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4 pt-1">
            <div>
              <Label className="text-sm font-medium">Target Subnet</Label>
              <Input
                className="mt-1.5"
                placeholder={subnetsQ.data?.subnets[0] ?? "192.168.1.0/24"}
                value={scanSubnet}
                onChange={e => setScanSubnet(e.target.value)}
              />
              <p className="text-xs text-muted-foreground mt-1.5">
                Leave blank to auto-detect. Detected subnets:{" "}
                {subnetsQ.data?.subnets.length
                  ? <span className="font-mono text-teal-400">{subnetsQ.data.subnets.join(", ")}</span>
                  : <span className="text-muted-foreground/60">detecting…</span>
                }
              </p>
            </div>

            {/* Discovery methods */}
            <div className="rounded-xl border border-border/50 bg-muted/20 p-4 space-y-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Discovery Methods</p>
              <div className="grid grid-cols-2 gap-2">
                {[
                  { color: "bg-green-500",  label: "ARP / Ping sweep", sub: "via nmap -sn" },
                  { color: "bg-purple-500", label: "mDNS / Bonjour",   sub: "UDP 5353" },
                  { color: "bg-orange-500", label: "SNMP v1 sysDescr", sub: "UDP 161" },
                  { color: "bg-pink-500",   label: "NetBIOS NS",       sub: "UDP 137" },
                ].map(m => (
                  <div key={m.label} className="flex items-start gap-2 text-xs">
                    <span className={cn("h-2 w-2 rounded-full mt-1 flex-shrink-0", m.color)} />
                    <div>
                      <p className="font-medium">{m.label}</p>
                      <p className="text-muted-foreground">{m.sub}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 px-3 py-2.5 flex items-start gap-2 text-xs text-yellow-600 dark:text-yellow-400">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5 flex-shrink-0" />
              Scanner runs on the server's network. Ensure you have permission to scan the target subnet.
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScanDialog(false)}>Cancel</Button>
            <Button onClick={startScan} className="bg-teal-600 hover:bg-teal-700 text-white gap-2">
              <Play className="h-4 w-4" /> Start Scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* ── Device Detail Sheet ───────────────────────────────────────────── */}
      <Sheet open={!!selected} onOpenChange={open => !open && setSelected(null)}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
          {selected && (
            <>
              <SheetHeader className="pb-5">
                <SheetTitle className="flex items-center gap-3">
                  <div
                    className="h-10 w-10 rounded-xl flex items-center justify-center flex-shrink-0"
                    style={{ background: `${DEVICE_COLORS[selected.deviceType] ?? "#888"}1a`, color: DEVICE_COLORS[selected.deviceType] ?? "#888" }}
                  >
                    {DEVICE_ICONS[selected.deviceType] ?? DEVICE_ICONS.unknown}
                  </div>
                  <div className="min-w-0">
                    <p className="font-semibold truncate">{displayName(selected)}</p>
                    <p className="text-sm text-muted-foreground font-normal font-mono">{selected.ipAddress}</p>
                  </div>
                </SheetTitle>
              </SheetHeader>

              <div className="space-y-6">
                {/* KPI row */}
                <div className="grid grid-cols-3 gap-3">
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1.5">Risk</p>
                    <RiskBadge level={selected.riskLevel} />
                  </div>
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1.5">Status</p>
                    <StatusBadge status={selected.status} />
                  </div>
                  <div className="rounded-xl border bg-card p-3 text-center">
                    <p className="text-xs text-muted-foreground mb-1">Managed</p>
                    <p className={cn("text-sm font-semibold", selected.isManaged ? "text-green-400" : "text-muted-foreground")}>
                      {selected.isManaged ? "Yes" : "No"}
                    </p>
                  </div>
                </div>

                {/* Identity section */}
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Identity</p>
                  <div className="rounded-xl border bg-card p-4 grid grid-cols-2 gap-3 text-sm">
                    <div><p className="text-xs text-muted-foreground">IP Address</p><p className="font-mono font-semibold">{selected.ipAddress}</p></div>
                    {selected.subnet && <div><p className="text-xs text-muted-foreground">Subnet</p><p className="font-mono">{selected.subnet}</p></div>}
                    {selected.macAddress && <div><p className="text-xs text-muted-foreground">MAC Address</p><p className="font-mono text-xs">{selected.macAddress}</p></div>}
                    {selected.macVendor && <div><p className="text-xs text-muted-foreground">MAC Vendor</p><p>{selected.macVendor}</p></div>}
                    {selected.hostname && <div><p className="text-xs text-muted-foreground">Hostname</p><p>{selected.hostname}</p></div>}
                    {selected.netbiosName && <div><p className="text-xs text-muted-foreground">NetBIOS Name</p><p>{selected.netbiosName}</p></div>}
                    {selected.mdnsName && <div><p className="text-xs text-muted-foreground">mDNS Name</p><p>{selected.mdnsName}</p></div>}
                    {selected.osGuess && <div className="col-span-2"><p className="text-xs text-muted-foreground">OS Guess</p><p>{selected.osGuess}</p></div>}
                    <div><p className="text-xs text-muted-foreground">First Seen</p><p>{new Date(selected.firstSeenAt).toLocaleString()}</p></div>
                    <div><p className="text-xs text-muted-foreground">Last Seen</p><p>{new Date(selected.lastSeenAt).toLocaleString()}</p></div>
                  </div>
                </div>

                {/* Open ports */}
                {selected.openPorts && selected.openPorts.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">
                      Open Ports ({selected.openPorts.length})
                    </p>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.openPorts.map(p => (
                        <span key={p} className="font-mono text-xs px-2 py-1 rounded-lg bg-card border border-border">{p}</span>
                      ))}
                    </div>
                  </div>
                )}

                {/* SNMP info */}
                {(selected.snmpSysDescr || selected.snmpSysName || selected.snmpSysLocation) && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">SNMP</p>
                    <div className="rounded-xl border bg-card p-4 space-y-2 text-sm">
                      {selected.snmpSysName && <div><p className="text-xs text-muted-foreground">sysName</p><p>{selected.snmpSysName}</p></div>}
                      {selected.snmpSysLocation && <div><p className="text-xs text-muted-foreground">sysLocation</p><p>{selected.snmpSysLocation}</p></div>}
                      {selected.snmpSysDescr && (
                        <div><p className="text-xs text-muted-foreground">sysDescr</p>
                          <p className="text-xs bg-muted p-2 rounded font-mono whitespace-pre-wrap mt-1">{selected.snmpSysDescr}</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* mDNS services */}
                {selected.mdnsServices && selected.mdnsServices.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">mDNS Services</p>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.mdnsServices.map((s, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Discovery methods */}
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-3">Discovered Via</p>
                  <div className="flex flex-wrap gap-2">
                    {(selected.discoveryMethods ?? []).map(m => {
                      const meta = METHOD_META[m] ?? { label: m, bg: "bg-muted/50", text: "text-muted-foreground" };
                      return (
                        <span key={m} className={cn("text-sm px-3 py-1.5 rounded-lg font-medium", meta.bg, meta.text)}>
                          {meta.label}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {/* Actions */}
                <div className="space-y-3 pt-1">
                  <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Update Status</p>
                  <div className="flex flex-wrap gap-3">
                    <Select
                      value={selected.status}
                      onValueChange={v => updateDeviceMut.mutate({ id: selected.id, status: v })}
                    >
                      <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="new">New</SelectItem>
                        <SelectItem value="under_review">Under Review</SelectItem>
                        <SelectItem value="approved">Approved</SelectItem>
                        <SelectItem value="false_positive">False Positive</SelectItem>
                      </SelectContent>
                    </Select>

                    <Button
                      size="sm"
                      variant={selected.isManaged ? "outline" : "default"}
                      className={selected.isManaged
                        ? "border-orange-400/30 text-orange-400"
                        : "bg-green-600 hover:bg-green-700 text-white"
                      }
                      onClick={() => updateDeviceMut.mutate({ id: selected.id, isManaged: !selected.isManaged })}
                      disabled={updateDeviceMut.isPending}
                    >
                      {selected.isManaged
                        ? <><Eye className="h-4 w-4 mr-2" /> Mark Unmanaged</>
                        : <><CheckCircle2 className="h-4 w-4 mr-2" /> Mark as Managed</>
                      }
                    </Button>
                  </div>

                  <Button
                    size="sm" variant="destructive" className="mt-2"
                    onClick={() => {
                      if (confirm(`Delete device record for ${displayName(selected)} (${selected.ipAddress})?`)) {
                        deleteDeviceMut.mutate(selected.id);
                      }
                    }}
                    disabled={deleteDeviceMut.isPending}
                  >
                    <Trash2 className="h-4 w-4 mr-2" /> Delete Device Record
                  </Button>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
