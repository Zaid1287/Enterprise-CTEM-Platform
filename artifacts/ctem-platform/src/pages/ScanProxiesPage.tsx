import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Plus, Trash2, Pencil, Wifi, WifiOff, Clock, RefreshCw,
  Loader2, TestTube2, CheckCircle2, XCircle, Activity,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { getToken } from "@/lib/auth";
import { useAuth } from "@/hooks/useAuth";

/* ─── Types ─────────────────────────────────────────────────────────── */
interface Proxy {
  id: number; ip: string; label: string | null; type: string;
  country: string | null; asn: string | null;
  healthScore: number; successCount: number; failCount: number;
  count429: number; count403: number; avgLatencyMs: number | null;
  status: "active" | "cooldown" | "inactive"; lastTestedAt: string | null;
}

/* ─── API ────────────────────────────────────────────────────────────── */
const BASE = () => import.meta.env.BASE_URL.replace(/\/$/, "");
const hdrs = () => ({ Authorization: `Bearer ${getToken()}`, "Content-Type": "application/json" });
async function api<T>(path: string, opts?: RequestInit): Promise<T> {
  const r = await fetch(`${BASE()}${path}`, { headers: hdrs(), ...opts });
  if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error((e as any).error ?? "Request failed"); }
  return r.json();
}

/* ─── StatusBadge ─────────────────────────────────────────────────────── */
function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { label: string; icon: React.ElementType; cls: string }> = {
    active:   { label: "Healthy",      icon: Wifi,    cls: "bg-green-500/15 text-green-600 border-green-500/30" },
    cooldown: { label: "Cooling Down", icon: Clock,   cls: "bg-amber-500/15 text-amber-600 border-amber-500/30" },
    inactive: { label: "Inactive",     icon: WifiOff, cls: "bg-red-500/15 text-red-600 border-red-500/30"   },
  };
  const s = map[status] ?? { label: status, icon: Activity, cls: "bg-muted text-muted-foreground" };
  const Icon = s.icon;
  return (
    <Badge variant="outline" className={cn("text-xs font-medium gap-1", s.cls)}>
      <Icon className="w-3 h-3" />{s.label}
    </Badge>
  );
}

/* ─── Add/Edit Dialog ─────────────────────────────────────────────────── */
function ProxyDialog({
  open, onClose, initial,
}: {
  open: boolean; onClose: () => void;
  initial?: Proxy;
}) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const [ip, setIp]         = useState(initial?.ip ?? "");
  const [port, setPort]     = useState(String(initial?.id ?? "3128"));
  const [label, setLabel]   = useState(initial?.label ?? "");
  const [type, setType]     = useState(initial?.type ?? "http");
  const [country, setCountry] = useState(initial?.country ?? "");
  const [asn, setAsn]       = useState(initial?.asn ?? "");

  const isEdit = !!initial;

  const saveMut = useMutation({
    mutationFn: (body: object) =>
      isEdit
        ? api(`/api/scan-proxies/${initial!.id}`, { method: "PATCH", body: JSON.stringify(body) })
        : api("/api/scan-proxies", { method: "POST", body: JSON.stringify(body) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      toast({ title: isEdit ? "Proxy updated" : "Proxy added", description: isEdit ? "Changes saved." : "Live TCP ping test complete." });
      onClose();
    },
    onError: (e: Error) => toast({ title: "Failed", description: e.message, variant: "destructive" }),
  });

  const handleSubmit = () => {
    if (!ip.trim()) { toast({ title: "IP required", variant: "destructive" }); return; }
    saveMut.mutate({ ip: ip.trim(), port: parseInt(port, 10), label: label || undefined, type, country: country || undefined, asn: asn || undefined });
  };

  return (
    <Dialog open={open} onOpenChange={v => { if (!v) onClose(); }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit Proxy" : "Add Proxy"}</DialogTitle>
        </DialogHeader>
        <div className="grid gap-4 py-2">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>IP Address *</Label>
              <Input placeholder="1.2.3.4" value={ip} onChange={e => setIp(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label>Port</Label>
              <Input placeholder="3128" value={port} onChange={e => setPort(e.target.value)} type="number" />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>Label</Label>
            <Input placeholder="e.g. DE Datacenter 1" value={label} onChange={e => setLabel(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label>Proxy Class</Label>
              <Select value={type} onValueChange={setType}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="datacenter">Datacenter</SelectItem>
                  <SelectItem value="residential">Residential</SelectItem>
                  <SelectItem value="isp">ISP</SelectItem>
                  <SelectItem value="mobile">Mobile</SelectItem>
                  <SelectItem value="socks5">SOCKS5</SelectItem>
                  <SelectItem value="http">HTTP (Generic)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label>Country</Label>
              <Input placeholder="DE" maxLength={3} value={country} onChange={e => setCountry(e.target.value)} />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label>ASN / Provider</Label>
            <Input placeholder="e.g. Hetzner" value={asn} onChange={e => setAsn(e.target.value)} />
          </div>
          {!isEdit && (
            <p className="text-xs text-muted-foreground bg-blue-500/10 border border-blue-500/20 rounded-lg px-3 py-2">
              A live TCP ping test will run on save. Status will reflect the result immediately.
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={saveMut.isPending}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={saveMut.isPending}>
            {saveMut.isPending && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
            {isEdit ? "Save Changes" : "Add & Test"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ─── Main Page ───────────────────────────────────────────────────────── */
export default function ScanProxiesPage() {
  const { user } = useAuth();
  const isSuperAdmin = user?.role === "super_admin";
  const { toast } = useToast();
  const qc = useQueryClient();
  const [showAdd, setShowAdd] = useState(false);
  const [editProxy, setEditProxy] = useState<Proxy | null>(null);
  const [testingId, setTestingId] = useState<number | null>(null);

  const { data: proxies = [], isLoading } = useQuery<Proxy[]>({
    queryKey: ["scan-proxies"],
    queryFn: () => api("/api/scan-proxies"),
    refetchInterval: 30_000,
  });

  const deleteMut = useMutation({
    mutationFn: (id: number) => api(`/api/scan-proxies/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["scan-proxies"] }); toast({ title: "Proxy removed" }); },
    onError: () => toast({ title: "Delete failed", variant: "destructive" }),
  });

  const testProxy = async (proxy: Proxy) => {
    setTestingId(proxy.id);
    try {
      const result = await api<{ reachable: boolean; latencyMs?: number }>(`/api/scan-proxies/${proxy.id}/health`);
      qc.invalidateQueries({ queryKey: ["scan-proxies"] });
      if (result.reachable) {
        toast({ title: "Proxy reachable", description: `Latency: ${result.latencyMs ?? "?"}ms` });
      } else {
        toast({ title: "Proxy unreachable", description: "TCP connection failed.", variant: "destructive" });
      }
    } catch {
      toast({ title: "Health check failed", variant: "destructive" });
    } finally {
      setTestingId(null);
    }
  };

  const activeCount   = proxies.filter(p => p.status === "active").length;
  const cooldownCount = proxies.filter(p => p.status === "cooldown").length;
  const inactiveCount = proxies.filter(p => p.status === "inactive").length;

  return (
    <div className="p-6 space-y-6 max-w-screen-xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Proxy / IP Pool Management</h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Configure and test outbound proxies used by the scan orchestration engine
          </p>
        </div>
        {isSuperAdmin && (
          <Button onClick={() => setShowAdd(true)} className="gap-1.5">
            <Plus className="w-4 h-4" /> Add Proxy
          </Button>
        )}
      </div>

      {/* Summary chips */}
      <div className="flex gap-3 flex-wrap">
        <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/25 gap-1.5 px-3 py-1 text-sm">
          <Wifi className="w-3.5 h-3.5" /> {activeCount} Healthy
        </Badge>
        <Badge variant="outline" className="bg-amber-500/10 text-amber-600 border-amber-500/25 gap-1.5 px-3 py-1 text-sm">
          <Clock className="w-3.5 h-3.5" /> {cooldownCount} Cooling
        </Badge>
        <Badge variant="outline" className="bg-red-500/10 text-red-600 border-red-500/25 gap-1.5 px-3 py-1 text-sm">
          <WifiOff className="w-3.5 h-3.5" /> {inactiveCount} Inactive
        </Badge>
      </div>

      {/* Proxy Table */}
      <div className="rounded-xl border bg-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th className="px-4 py-3 text-left font-medium">IP Address</th>
                <th className="px-4 py-3 text-left font-medium">Label</th>
                <th className="px-4 py-3 text-left font-medium">Class</th>
                <th className="px-4 py-3 text-left font-medium">Country</th>
                <th className="px-4 py-3 text-left font-medium">ASN</th>
                <th className="px-4 py-3 text-right font-medium">Health</th>
                <th className="px-4 py-3 text-right font-medium">Success %</th>
                <th className="px-4 py-3 text-right font-medium">429s</th>
                <th className="px-4 py-3 text-right font-medium">403s</th>
                <th className="px-4 py-3 text-right font-medium">Avg Latency</th>
                <th className="px-4 py-3 text-left font-medium">Status</th>
                <th className="px-4 py-3 text-left font-medium">Last Tested</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b">
                    {Array.from({ length: 13 }).map((__, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-full" /></td>
                    ))}
                  </tr>
                ))
              ) : proxies.length === 0 ? (
                <tr><td colSpan={13} className="px-4 py-12 text-center">
                  <p className="text-muted-foreground text-sm">No proxies configured yet.</p>
                  <p className="text-xs text-muted-foreground mt-1">Add a proxy IP to start routing scan traffic through it.</p>
                </td></tr>
              ) : proxies.map(proxy => {
                const total = (proxy.successCount ?? 0) + (proxy.failCount ?? 0);
                const successPct = total > 0 ? Math.round(proxy.successCount / total * 100) : null;
                return (
                <tr key={proxy.id} className="border-b last:border-0 hover:bg-muted/30 transition-colors">
                  <td className="px-4 py-2.5 font-mono text-xs">{proxy.ip}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{proxy.label ?? "—"}</td>
                  <td className="px-4 py-2.5"><Badge variant="outline" className="text-xs capitalize">{proxy.type}</Badge></td>
                  <td className="px-4 py-2.5 text-xs">{proxy.country ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{proxy.asn ?? "—"}</td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={cn("font-bold text-sm", proxy.healthScore >= 70 ? "text-green-600" : proxy.healthScore >= 30 ? "text-amber-500" : "text-red-500")}>
                      {proxy.healthScore}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs">
                    {successPct != null ? (
                      <span className={successPct >= 80 ? "text-green-600" : successPct >= 50 ? "text-amber-500" : "text-red-500"}>
                        {successPct}%
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs">{proxy.count429 ?? 0}</td>
                  <td className="px-4 py-2.5 text-right text-xs">{proxy.count403 ?? 0}</td>
                  <td className="px-4 py-2.5 text-right text-xs text-muted-foreground">
                    {proxy.avgLatencyMs != null ? `${proxy.avgLatencyMs}ms` : "—"}
                  </td>
                  <td className="px-4 py-2.5"><StatusBadge status={proxy.status} /></td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {proxy.lastTestedAt ? new Date(proxy.lastTestedAt).toLocaleString() : "Never"}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost" size="icon"
                        className="w-7 h-7"
                        title="Test health"
                        disabled={testingId === proxy.id}
                        onClick={() => testProxy(proxy)}
                      >
                        {testingId === proxy.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TestTube2 className="w-3.5 h-3.5" />}
                      </Button>
                      {isSuperAdmin && (
                        <>
                          <Button variant="ghost" size="icon" className="w-7 h-7" title="Edit" onClick={() => setEditProxy(proxy)}>
                            <Pencil className="w-3.5 h-3.5" />
                          </Button>
                          <Button
                            variant="ghost" size="icon" className="w-7 h-7 text-destructive hover:text-destructive"
                            title="Delete"
                            disabled={deleteMut.isPending}
                            onClick={() => { if (confirm(`Remove proxy ${proxy.ip}?`)) deleteMut.mutate(proxy.id); }}
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </Button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ); })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dialogs */}
      {showAdd && <ProxyDialog open onClose={() => setShowAdd(false)} />}
      {editProxy && <ProxyDialog open onClose={() => setEditProxy(null)} initial={editProxy} />}
    </div>
  );
}
