import { useState } from "react";
import { apiFetch } from "@/lib/apiFetch";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { AppLayout } from "@/components/layout/AppLayout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Sheet, SheetContent, SheetHeader, SheetTitle,
} from "@/components/ui/sheet";
import type { ReactElement } from "react";
import {
  Wifi, Printer, Router, Server, Monitor, Database, Cpu, HelpCircle,
  RefreshCw, Play, CheckCircle2, AlertTriangle, Trash2, Network,
} from "lucide-react";

interface NetworkDevice {
  id: number; ipAddress: string; macAddress: string | null; macVendor: string | null;
  hostname: string | null; netbiosName: string | null; mdnsName: string | null;
  mdnsServices: string[] | null; deviceType: string; vendor: string | null;
  osGuess: string | null; snmpSysDescr: string | null; snmpSysName: string | null;
  snmpSysLocation: string | null; openPorts: number[] | null;
  discoveryMethods: string[] | null; subnet: string | null; isManaged: boolean;
  riskLevel: string; status: string; firstSeenAt: string; lastSeenAt: string;
}

const DEVICE_ICONS: Record<string, ReactElement> = {
  printer:     <Printer className="h-4 w-4" />,
  router:      <Router className="h-4 w-4" />,
  switch:      <Network className="h-4 w-4" />,
  server:      <Server className="h-4 w-4" />,
  workstation: <Monitor className="h-4 w-4" />,
  nas:         <Database className="h-4 w-4" />,
  iot:         <Cpu className="h-4 w-4" />,
  unknown:     <HelpCircle className="h-4 w-4" />,
};

const DEVICE_COLORS: Record<string, string> = {
  printer: "#3b82f6", router: "#f97316", switch: "#8b5cf6",
  server: "#ef4444", workstation: "#6b7280", nas: "#06b6d4",
  iot: "#eab308", unknown: "#9ca3af",
};

const METHOD_LABELS: Record<string, { label: string; color: string }> = {
  nmap:        { label: "nmap", color: "#22c55e" },
  nmap_arp:    { label: "ARP", color: "#3b82f6" },
  mdns:        { label: "mDNS", color: "#8b5cf6" },
  snmp:        { label: "SNMP", color: "#f97316" },
  netbios:     { label: "NetBIOS", color: "#ec4899" },
};

const RISK_COLORS: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#eab308",
  low: "#22c55e", info: "#6b7280",
};

export default function ShadowItNetworkPage() {
  const qc = useQueryClient();
  const [scanning, setScanning] = useState(false);
  const [scanSubnet, setScanSubnet] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [selected, setSelected] = useState<NetworkDevice | null>(null);

  const subnetsQ = useQuery<{ subnets: string[] }>({
    queryKey: ["shadow-it-subnets"],
    queryFn: () => apiFetch("/api/shadow-it/network-scan/subnets"),
  });

  const devicesQ = useQuery<{ items: NetworkDevice[]; total: number }>({
    queryKey: ["shadow-it-network", filterType, filterStatus],
    queryFn: () => {
      const p = new URLSearchParams({ limit: "200" });
      if (filterType !== "all") p.set("deviceType", filterType);
      if (filterStatus !== "all") p.set("status", filterStatus);
      return apiFetch(`/api/shadow-it/network-devices?${p}`);
    },
    refetchInterval: scanning ? 5000 : false,
  });

  const updateDeviceMut = useMutation({
    mutationFn: ({ id, ...data }: { id: number; status?: string; isManaged?: boolean }) =>
      apiFetch(`/api/shadow-it/network-devices/${id}`, { method: "PATCH", body: JSON.stringify(data) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["shadow-it-network"] }); },
  });

  const deleteDeviceMut = useMutation({
    mutationFn: (id: number) => apiFetch(`/api/shadow-it/network-devices/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["shadow-it-network"] }); setSelected(null); },
  });

  const startScan = async () => {
    setScanning(true);
    try {
      await apiFetch("/api/shadow-it/network-scan", {
        method: "POST",
        body: JSON.stringify({ subnet: scanSubnet || undefined }),
      });
      // Poll for results
      await new Promise(r => setTimeout(r, 5000));
      await devicesQ.refetch();
    } catch { /* ignore */ } finally {
      setScanning(false);
    }
  };

  const devices = devicesQ.data?.items ?? [];

  // Type distribution for summary
  const byType: Record<string, number> = {};
  for (const d of devices) byType[d.deviceType] = (byType[d.deviceType] ?? 0) + 1;

  const displayName = (d: NetworkDevice) =>
    d.netbiosName ?? d.mdnsName ?? d.hostname ?? d.snmpSysName ?? d.ipAddress;

  return (
    <AppLayout>
      <div className="p-6 space-y-6 max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Wifi className="h-6 w-6 text-blue-500" />
              Internal Network Discovery
            </h1>
            <p className="text-muted-foreground text-sm mt-1">
              ARP sweep · mDNS/Bonjour · SNMP · NetBIOS — real-time LAN device enumeration
            </p>
          </div>
        </div>

        {/* Scan Card */}
        <Card className="border-blue-200 bg-blue-50/30 dark:bg-blue-950/20">
          <CardContent className="p-4">
            <div className="flex items-end gap-3 flex-wrap">
              <div className="flex-1 min-w-48">
                <Label className="text-sm">Target Subnet (leave blank to auto-detect)</Label>
                <Input
                  className="mt-1"
                  placeholder={subnetsQ.data?.subnets[0] ?? "192.168.1.0/24"}
                  value={scanSubnet}
                  onChange={e => setScanSubnet(e.target.value)}
                />
                {subnetsQ.data?.subnets.length ? (
                  <p className="text-xs text-muted-foreground mt-1">
                    Detected: {subnetsQ.data.subnets.join(", ")}
                  </p>
                ) : null}
              </div>
              <Button onClick={startScan} disabled={scanning} className="min-w-32">
                {scanning ? (
                  <><RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Scanning…</>
                ) : (
                  <><Play className="h-4 w-4 mr-2" /> Start Scan</>
                )}
              </Button>
            </div>

            <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-muted-foreground">
              <div className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-green-500 inline-block" />ARP / Ping sweep via nmap</div>
              <div className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-purple-500 inline-block" />mDNS / Bonjour (UDP 5353)</div>
              <div className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-orange-500 inline-block" />SNMP v1 sysDescr (UDP 161)</div>
              <div className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-pink-500 inline-block" />NetBIOS NS (UDP 137)</div>
            </div>

            <div className="mt-2 p-2 rounded bg-yellow-50 dark:bg-yellow-950/30 text-xs text-yellow-700 dark:text-yellow-400">
              <AlertTriangle className="h-3 w-3 inline mr-1" />
              <strong>Deployment note:</strong> Scanner discovers devices on the server's local network. For customer LAN discovery, deploy Sentinelware on a machine physically on that network or run a network agent.
            </div>
          </CardContent>
        </Card>

        {/* Summary by type */}
        {Object.keys(byType).length > 0 && (
          <div className="flex gap-3 flex-wrap">
            {Object.entries(byType).map(([type, count]) => (
              <button
                key={type}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${filterType === type ? "bg-primary text-primary-foreground" : "bg-card hover:bg-muted"}`}
                onClick={() => setFilterType(filterType === type ? "all" : type)}
              >
                <span style={{ color: DEVICE_COLORS[type] ?? "#888" }}>{DEVICE_ICONS[type] ?? DEVICE_ICONS.unknown}</span>
                <span className="capitalize">{type}</span>
                <Badge variant="secondary" className="ml-1">{count}</Badge>
              </button>
            ))}
          </div>
        )}

        {/* Filters */}
        <div className="flex gap-3">
          <Select value={filterType} onValueChange={setFilterType}>
            <SelectTrigger className="w-40"><SelectValue placeholder="All types" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              {["workstation", "server", "printer", "router", "switch", "nas", "iot", "unknown"].map(t => (
                <SelectItem key={t} value={t} className="capitalize">{t}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={filterStatus} onValueChange={setFilterStatus}>
            <SelectTrigger className="w-40"><SelectValue placeholder="All statuses" /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="new">New</SelectItem>
              <SelectItem value="under_review">Under Review</SelectItem>
              <SelectItem value="approved">Approved</SelectItem>
              <SelectItem value="false_positive">False Positive</SelectItem>
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={() => devicesQ.refetch()}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>

        {/* Device Table */}
        {devices.length === 0 ? (
          <Card>
            <CardContent className="py-12 text-center">
              <Wifi className="h-10 w-10 text-muted-foreground mx-auto mb-3" />
              <p className="font-medium">No network devices found yet</p>
              <p className="text-sm text-muted-foreground mt-1">Run a network scan to discover devices on the local subnet.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead>
                  <TableHead>IP Address</TableHead>
                  <TableHead>MAC / Vendor</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Discovered by</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Managed</TableHead>
                  <TableHead>Last Seen</TableHead>
                  <TableHead></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.map(d => (
                  <TableRow key={d.id} className="cursor-pointer hover:bg-muted/50" onClick={() => setSelected(d)}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span style={{ color: DEVICE_COLORS[d.deviceType] ?? "#888" }}>
                          {DEVICE_ICONS[d.deviceType] ?? DEVICE_ICONS.unknown}
                        </span>
                        <div>
                          <p className="font-medium text-sm">{displayName(d)}</p>
                          {d.snmpSysDescr && (
                            <p className="text-xs text-muted-foreground max-w-48 truncate" title={d.snmpSysDescr}>
                              {d.snmpSysDescr}
                            </p>
                          )}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-sm">{d.ipAddress}</TableCell>
                    <TableCell>
                      <div>
                        {d.macAddress && <p className="font-mono text-xs">{d.macAddress}</p>}
                        {d.macVendor && <p className="text-xs text-muted-foreground">{d.macVendor}</p>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="capitalize text-xs">{d.deviceType}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {(d.discoveryMethods ?? []).map(m => (
                          <span key={m} className="text-xs px-1.5 py-0.5 rounded text-white"
                            style={{ background: METHOD_LABELS[m]?.color ?? "#888" }}>
                            {METHOD_LABELS[m]?.label ?? m}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={d.status === "approved" ? "default" : "secondary"} className="capitalize text-xs">
                        {d.status.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell onClick={e => e.stopPropagation()}>
                      <Button
                        size="sm"
                        variant={d.isManaged ? "default" : "outline"}
                        className={`text-xs h-7 ${d.isManaged ? "bg-green-600 hover:bg-green-700" : ""}`}
                        onClick={() => updateDeviceMut.mutate({ id: d.id, isManaged: !d.isManaged })}
                      >
                        {d.isManaged ? <><CheckCircle2 className="h-3 w-3 mr-1" />Managed</> : "Unmanaged"}
                      </Button>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(d.lastSeenAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell onClick={e => e.stopPropagation()}>
                      <Button size="sm" variant="ghost" className="text-red-500 h-7 w-7 p-0"
                        onClick={() => { if (confirm("Delete this device?")) deleteDeviceMut.mutate(d.id); }}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      {/* ── Device Detail Drawer ── */}
      <Sheet open={!!selected} onOpenChange={open => !open && setSelected(null)}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2">
                  <span style={{ color: DEVICE_COLORS[selected.deviceType] ?? "#888" }}>
                    {DEVICE_ICONS[selected.deviceType] ?? DEVICE_ICONS.unknown}
                  </span>
                  {displayName(selected)}
                </SheetTitle>
              </SheetHeader>

              <div className="mt-6 space-y-5">
                {/* Identity */}
                <section>
                  <p className="font-medium text-sm mb-2 text-muted-foreground uppercase tracking-wide">Identity</p>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div><p className="text-xs text-muted-foreground">IP Address</p><p className="font-mono">{selected.ipAddress}</p></div>
                    {selected.macAddress && <div><p className="text-xs text-muted-foreground">MAC Address</p><p className="font-mono">{selected.macAddress}</p></div>}
                    {selected.macVendor && <div><p className="text-xs text-muted-foreground">Vendor</p><p>{selected.macVendor}</p></div>}
                    {selected.hostname && <div><p className="text-xs text-muted-foreground">Hostname</p><p>{selected.hostname}</p></div>}
                    {selected.netbiosName && <div><p className="text-xs text-muted-foreground">NetBIOS Name</p><p>{selected.netbiosName}</p></div>}
                    {selected.mdnsName && <div><p className="text-xs text-muted-foreground">mDNS Name</p><p>{selected.mdnsName}</p></div>}
                    {selected.osGuess && <div><p className="text-xs text-muted-foreground">OS Guess</p><p>{selected.osGuess}</p></div>}
                    {selected.subnet && <div><p className="text-xs text-muted-foreground">Subnet</p><p className="font-mono">{selected.subnet}</p></div>}
                  </div>
                </section>

                {/* SNMP info */}
                {(selected.snmpSysDescr || selected.snmpSysName || selected.snmpSysLocation) && (
                  <section>
                    <p className="font-medium text-sm mb-2 text-muted-foreground uppercase tracking-wide">SNMP</p>
                    <div className="space-y-1 text-sm">
                      {selected.snmpSysName && <div><p className="text-xs text-muted-foreground">sysName</p><p>{selected.snmpSysName}</p></div>}
                      {selected.snmpSysLocation && <div><p className="text-xs text-muted-foreground">sysLocation</p><p>{selected.snmpSysLocation}</p></div>}
                      {selected.snmpSysDescr && <div><p className="text-xs text-muted-foreground">sysDescr</p><p className="text-xs bg-muted p-2 rounded font-mono whitespace-pre-wrap">{selected.snmpSysDescr}</p></div>}
                    </div>
                  </section>
                )}

                {/* mDNS services */}
                {selected.mdnsServices && selected.mdnsServices.length > 0 && (
                  <section>
                    <p className="font-medium text-sm mb-2 text-muted-foreground uppercase tracking-wide">mDNS Services</p>
                    <div className="flex flex-wrap gap-1">
                      {selected.mdnsServices.map((s, i) => (
                        <Badge key={i} variant="outline" className="text-xs">{s}</Badge>
                      ))}
                    </div>
                  </section>
                )}

                {/* Discovery methods */}
                <section>
                  <p className="font-medium text-sm mb-2 text-muted-foreground uppercase tracking-wide">Discovered Via</p>
                  <div className="flex gap-2">
                    {(selected.discoveryMethods ?? []).map(m => (
                      <span key={m} className="text-xs px-2 py-1 rounded text-white"
                        style={{ background: METHOD_LABELS[m]?.color ?? "#888" }}>
                        {METHOD_LABELS[m]?.label ?? m}
                      </span>
                    ))}
                  </div>
                </section>

                {/* Actions */}
                <section className="flex gap-2 flex-wrap">
                  <Select
                    value={selected.status}
                    onValueChange={v => {
                      updateDeviceMut.mutate({ id: selected.id, status: v });
                      setSelected(s => s ? { ...s, status: v } : null);
                    }}
                  >
                    <SelectTrigger className="w-44"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="new">New</SelectItem>
                      <SelectItem value="under_review">Under Review</SelectItem>
                      <SelectItem value="approved">Approved</SelectItem>
                      <SelectItem value="false_positive">False Positive</SelectItem>
                    </SelectContent>
                  </Select>

                  <Button
                    size="sm"
                    variant={selected.isManaged ? "default" : "outline"}
                    onClick={() => {
                      updateDeviceMut.mutate({ id: selected.id, isManaged: !selected.isManaged });
                      setSelected(s => s ? { ...s, isManaged: !s.isManaged } : null);
                    }}
                  >
                    {selected.isManaged ? "✓ Managed" : "Mark as Managed"}
                  </Button>

                  <Button
                    size="sm" variant="destructive"
                    onClick={() => { if (confirm("Delete this device record?")) deleteDeviceMut.mutate(selected.id); }}
                  >
                    <Trash2 className="h-4 w-4 mr-1" /> Delete
                  </Button>
                </section>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </AppLayout>
  );
}
